// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Dario Casalinuovo
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/xattr.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/dirent.h>
#include <linux/mutex.h>
#include <linux/mnt_idmapping.h>

#include "attribute.h"
#include "node_monitor.h"
#include "nexus.h"
#include "volume.h"

#ifndef NEXUS_ATTR_DEBUG
#define NEXUS_ATTR_DEBUG 0
#endif

#if NEXUS_ATTR_DEBUG
#define attr_dbg(fmt, ...) pr_info("nexus_attr: DBG: " fmt, ##__VA_ARGS__)
#else
#define attr_dbg(fmt, ...) do {} while (0)
#endif

#define attr_err(fmt, ...)  pr_err("nexus_attr: ERROR: " fmt, ##__VA_ARGS__)
#define attr_warn(fmt, ...) pr_warn("nexus_attr: WARN: "  fmt, ##__VA_ARGS__)

#define ATTR_PREFIX     "user.beos."
#define ATTR_PREFIX_LEN 10
#define ATTR_LOCK_HASH_BITS 6

struct attr_lock {
	struct hlist_node  node;
	/* not refcounted — valid only while held */
	struct inode      *inode;
	char               name[XATTR_NAME_MAX + 1];
	struct mutex       mutex;
	int                refcount;
};

static DEFINE_HASHTABLE(attr_lock_table, ATTR_LOCK_HASH_BITS);
static DEFINE_SPINLOCK(attr_lock_table_lock);

static uint32_t attr_lock_hash(struct inode *inode, const char *name)
{
	uint32_t h = hash_ptr(inode, ATTR_LOCK_HASH_BITS);
	h ^= full_name_hash(NULL, name, strlen(name));
	return h;
}

static struct attr_lock *nexus_attr_lock_acquire(struct inode *inode,
	const char *name)
{
	struct attr_lock *lk, *new_lk = NULL;
	unsigned long flags;
	uint32_t h;

retry:
	h = attr_lock_hash(inode, name);

	spin_lock_irqsave(&attr_lock_table_lock, flags);
	hash_for_each_possible(attr_lock_table, lk, node, h) {
		if (lk->inode == inode && strcmp(lk->name, name) == 0) {
			lk->refcount++;
			spin_unlock_irqrestore(&attr_lock_table_lock, flags);
			kfree(new_lk);
			mutex_lock(&lk->mutex);
			return lk;
		}
	}

	if (new_lk) {
		hash_add(attr_lock_table, &new_lk->node, h);
		spin_unlock_irqrestore(&attr_lock_table_lock, flags);
		mutex_lock(&new_lk->mutex);
		return new_lk;
	}
	spin_unlock_irqrestore(&attr_lock_table_lock, flags);

	new_lk = kmalloc(sizeof(*new_lk), GFP_KERNEL);
	if (!new_lk)
		return NULL;
	new_lk->inode = inode;
	strscpy(new_lk->name, name, sizeof(new_lk->name));
	mutex_init(&new_lk->mutex);
	new_lk->refcount = 1;
	goto retry;
}

static void nexus_attr_lock_release(struct attr_lock *lk)
{
	unsigned long flags;

	mutex_unlock(&lk->mutex);

	spin_lock_irqsave(&attr_lock_table_lock, flags);
	lk->refcount--;
	if (lk->refcount == 0) {
		hash_del(&lk->node);
		spin_unlock_irqrestore(&attr_lock_table_lock, flags);
		kfree(lk);
		return;
	}
	spin_unlock_irqrestore(&attr_lock_table_lock, flags);
}


static int check_attr_caps(struct inode *inode, bool need_write)
{
	uint32_t caps = nexus_caps_for_inode(inode);

	if (!(caps & NX_FS_HAS_ATTR))
		return -EOPNOTSUPP;
	if (need_write && (caps & NX_FS_IS_READONLY))
		return -EROFS;
	return 0;
}


static int build_xattr_name(const char *attr_name, char *out,
	size_t out_size)
{
	size_t nlen = strnlen(attr_name, NEXUS_ATTR_NAME_MAX + 1);

	if (nlen == 0)
		return -EINVAL;
	if (nlen > NEXUS_ATTR_NAME_MAX)
		return -ENAMETOOLONG;

	if (ATTR_PREFIX_LEN + nlen + 1 > out_size)
		return -ENAMETOOLONG;

	memcpy(out, ATTR_PREFIX, ATTR_PREFIX_LEN);
	memcpy(out + ATTR_PREFIX_LEN, attr_name, nlen);
	out[ATTR_PREFIX_LEN + nlen] = '\0';
	return 0;
}


struct attr_dir_ctx {
	char  **names;
	size_t  count;
};

static int attr_dir_iterate(struct file *file, struct dir_context *ctx)
{
	struct attr_dir_ctx *adctx = file->private_data;
	loff_t pos = ctx->pos;

	while ((size_t)pos < adctx->count) {
		const char *name = adctx->names[pos];
		unsigned int type = DT_REG;

		if (!dir_emit(ctx, name, strlen(name),
			      (ino_t)(pos + 1), type))
			return 0;

		pos++;
		ctx->pos = pos;
	}

	return 0;
}

static int attr_dir_release(struct inode *inode, struct file *file)
{
	struct attr_dir_ctx *adctx = file->private_data;
	size_t i;

	if (adctx) {
		for (i = 0; i < adctx->count; i++)
			kfree(adctx->names[i]);
		kfree(adctx->names);
		kfree(adctx);
		file->private_data = NULL;
	}
	return 0;
}

static const struct file_operations attr_dir_fops = {
	.owner          = THIS_MODULE,
	.iterate_shared = attr_dir_iterate,
	.release        = attr_dir_release,
	.llseek         = default_llseek,
};


long nexus_attr_ioctl_dir_open(unsigned long arg)
{
	struct nexus_attr_dir_open req;
	struct file *target_file;
	struct inode *inode;
	struct attr_dir_ctx *adctx;
	ssize_t list_size;
	char *list_buf = NULL;
	char **names = NULL;
	size_t count = 0;
	char *entry, *end;
	int ret, fd;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	target_file = fget(req.target_fd);
	if (!target_file)
		return -EBADF;

	inode = file_inode(target_file);

	ret = check_attr_caps(inode, false);
	if (ret) {
		fput(target_file);
		return ret;
	}

	list_size = vfs_listxattr(target_file->f_path.dentry, NULL, 0); /* idmap not needed for listxattr */
	if (list_size < 0) {
		fput(target_file);
		return list_size;
	}

	if (list_size == 0) {
		goto build_ctx;
	}

	list_buf = kmalloc(list_size, GFP_KERNEL);
	if (!list_buf) {
		fput(target_file);
		return -ENOMEM;
	}

	list_size = vfs_listxattr(target_file->f_path.dentry, list_buf, list_size);
	if (list_size < 0) {
		ret = list_size;
		goto err_list;
	}

	entry = list_buf;
	end   = list_buf + list_size;
	while (entry < end) {
		size_t len = strnlen(entry, end - entry);
		if (len >= ATTR_PREFIX_LEN &&
		    memcmp(entry, ATTR_PREFIX, ATTR_PREFIX_LEN) == 0)
			count++;
		entry += len + 1;
	}

	if (count > 0) {
		names = kcalloc(count, sizeof(char *), GFP_KERNEL);
		if (!names) {
			ret = -ENOMEM;
			goto err_list;
		}

		entry = list_buf;
		count = 0;
		while (entry < end) {
			size_t len = strnlen(entry, end - entry);
			if (len >= ATTR_PREFIX_LEN &&
			    memcmp(entry, ATTR_PREFIX, ATTR_PREFIX_LEN) == 0) {
				names[count] = kstrdup(entry + ATTR_PREFIX_LEN,
						       GFP_KERNEL);
				if (!names[count]) {
					size_t i;
					for (i = 0; i < count; i++)
						kfree(names[i]);
					kfree(names);
					ret = -ENOMEM;
					goto err_list;
				}
				count++;
			}
			entry += len + 1;
		}
	}

build_ctx:
	adctx = kzalloc(sizeof(*adctx), GFP_KERNEL);
	if (!adctx) {
		size_t i;
		for (i = 0; i < count; i++)
			kfree(names[i]);
		kfree(names);
		ret = -ENOMEM;
		goto err_list;
	}

	adctx->names = names;
	adctx->count = count;

	fd = anon_inode_getfd("[nexus-attr-dir]", &attr_dir_fops, adctx,
			      O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		size_t i;
		for (i = 0; i < count; i++)
			kfree(names[i]);
		kfree(names);
		kfree(adctx);
		ret = fd;
		goto err_list;
	}

	kfree(list_buf);
	fput(target_file);
	return fd;

err_list:
	kfree(list_buf);
	fput(target_file);
	return ret;
}


long nexus_attr_ioctl_read(unsigned long arg)
{
	struct nexus_attr_io req;
	struct file *target_file;
	struct inode *inode;
	char xattr_name[XATTR_NAME_MAX + 1];
	char *kbuf = NULL;
	ssize_t xattr_len;
	__u32 type;
	__s64 data_len;
	__s64 copy_len = 0;
	int ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	/* NUL-terminate the user-supplied name defensively. */
	req.name[sizeof(req.name) - 1] = '\0';

	target_file = fget(req.target_fd);
	if (!target_file)
		return -EBADF;

	inode = file_inode(target_file);

	ret = check_attr_caps(inode, false);
	if (ret) {
		fput(target_file);
		return ret;
	}

	ret = build_xattr_name(req.name, xattr_name, sizeof(xattr_name));
	if (ret) {
		fput(target_file);
		return ret;
	}

	xattr_len = vfs_getxattr(&nop_mnt_idmap, target_file->f_path.dentry,
				 xattr_name, NULL, 0);
	if (xattr_len < 0) {
		ret = xattr_len;
		goto out;
	}
	if (xattr_len < 4) {
		ret = -ENODATA;
		goto out;
	}

	kbuf = kvmalloc(xattr_len, GFP_KERNEL);
	if (!kbuf) {
		fput(target_file);
		return -ENOMEM;
	}

	for (;;) {
		xattr_len = vfs_getxattr(&nop_mnt_idmap,
					 target_file->f_path.dentry,
					 xattr_name, kbuf, xattr_len);
		if (xattr_len != -ERANGE)
			break;

		xattr_len = vfs_getxattr(&nop_mnt_idmap,
					 target_file->f_path.dentry,
					 xattr_name, NULL, 0);
		if (xattr_len < 0) {
			ret = (int)xattr_len;
			goto out;
		}
		kvfree(kbuf);
		kbuf = kvmalloc(xattr_len, GFP_KERNEL);
		if (!kbuf) {
			fput(target_file);
			return -ENOMEM;
		}
	}
	if (xattr_len < 4) {
		ret = (int)(xattr_len < 0 ? xattr_len : -ENODATA);
		goto out;
	}

	memcpy(&type, kbuf, 4);
	req.type = le32_to_cpu(type);

	data_len = (ssize_t)xattr_len - 4;

	if (req.pos < 0 || req.pos > data_len) {
		ret = 0;
		goto write_type_back;
	}

	copy_len = data_len - req.pos;
	if (copy_len > (__s64)req.buf_len)
		copy_len = (__s64)req.buf_len;

	if (copy_len > 0) {
		if (copy_to_user((void __user *)(uintptr_t)req.buf_addr,
				 kbuf + 4 + req.pos, copy_len)) {
			ret = -EFAULT;
			goto out;
		}
	}

write_type_back:
	if (copy_to_user(&((struct nexus_attr_io __user *)arg)->type,
			 &req.type, sizeof(req.type))) {
		ret = -EFAULT;
		goto out;
	}

	ret = (copy_len > 0) ? (int)copy_len : 0;

out:
	kvfree(kbuf);
	fput(target_file);
	return ret;
}


long nexus_attr_ioctl_write(unsigned long arg)
{
	struct nexus_attr_io req;
	struct file *target_file;
	struct inode *inode;
	char xattr_name[XATTR_NAME_MAX + 1];
	struct attr_lock *lk = NULL;
	char *new_payload = NULL;
	size_t new_payload_len;
	char *user_buf = NULL;
	bool attr_existed = false;
	int ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	req.name[sizeof(req.name) - 1] = '\0';

	target_file = fget(req.target_fd);
	if (!target_file)
		return -EBADF;

	inode = file_inode(target_file);

	ret = check_attr_caps(inode, true);
	if (ret)
		goto out_fput;

	ret = build_xattr_name(req.name, xattr_name, sizeof(xattr_name));
	if (ret)
		goto out_fput;

	if (req.buf_len > (64ULL * 1024 * 1024)) {
		ret = -EINVAL;
		goto out_fput;
	}

	user_buf = kvmalloc(req.buf_len ? req.buf_len : 1, GFP_KERNEL);
	if (!user_buf) {
		ret = -ENOMEM;
		goto out_fput;
	}
	if (req.buf_len && copy_from_user(user_buf,
				(void __user *)(uintptr_t)req.buf_addr,
				req.buf_len)) {
		ret = -EFAULT;
		goto out_user_buf;
	}

	lk = nexus_attr_lock_acquire(inode, xattr_name);
	if (!lk) {
		ret = -ENOMEM;
		goto out_user_buf;
	}

	ssize_t probe = vfs_getxattr(&nop_mnt_idmap, target_file->f_path.dentry,
				     xattr_name, NULL, 0);
	attr_existed = (probe >= 0);

	if (req.pos == 0) {
		new_payload_len = 4 + req.buf_len;
		new_payload = kvmalloc(new_payload_len, GFP_KERNEL);
		if (!new_payload) {
			ret = -ENOMEM;
			goto out_unlock;
		}
		__u32 le_type = cpu_to_le32(req.type);
		memcpy(new_payload, &le_type, 4);
		if (req.buf_len)
			memcpy(new_payload + 4, user_buf, req.buf_len);
	} else {
		ssize_t old_len;
		size_t old_data_len;
		size_t new_data_len;

		old_len = vfs_getxattr(&nop_mnt_idmap,
				       target_file->f_path.dentry, xattr_name,
				       NULL, 0);
		if (old_len < 0) {
			old_len = 4;
		}

		if (old_len < 4)
			old_len = 4;

		old_data_len = (size_t)(old_len - 4);

		new_data_len = (size_t)req.pos + req.buf_len;
		if (new_data_len < old_data_len)
			new_data_len = old_data_len;

		new_payload_len = 4 + new_data_len;
		new_payload = kvzalloc(new_payload_len, GFP_KERNEL);
		if (!new_payload) {
			ret = -ENOMEM;
			goto out_unlock;
		}

		if (old_len > 4) {
			ssize_t got = vfs_getxattr(&nop_mnt_idmap,
						   target_file->f_path.dentry,
						   xattr_name,
						   new_payload, old_len);
			if (got < 0) {
				__u32 le_type = cpu_to_le32(req.type);
				memcpy(new_payload, &le_type, 4);
				memset(new_payload + 4, 0, new_data_len);
			}
		} else {
			__u32 le_type = cpu_to_le32(req.type);
			memcpy(new_payload, &le_type, 4);
		}

		if (req.buf_len)
			memcpy(new_payload + 4 + req.pos, user_buf, req.buf_len);
	}

	ret = vfs_setxattr(&nop_mnt_idmap, target_file->f_path.dentry,
			   xattr_name, new_payload, new_payload_len, 0);

	if (ret == 0) {
		nexus_nm_notify_xattr(inode, xattr_name,
			attr_existed ? B_ATTR_CAUSE_CHANGED
				     : B_ATTR_CAUSE_CREATED);
		ret = (int)req.buf_len;
	}

out_unlock:
	nexus_attr_lock_release(lk);
out_user_buf:
	kvfree(user_buf);
	kvfree(new_payload);
out_fput:
	fput(target_file);
	return ret;
}


long nexus_attr_ioctl_stat(unsigned long arg)
{
	struct nexus_attr_stat req;
	struct file *target_file;
	struct inode *inode;
	char xattr_name[XATTR_NAME_MAX + 1];
	ssize_t xattr_len;
	__u32 type;
	int ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	req.name[sizeof(req.name) - 1] = '\0';

	target_file = fget(req.target_fd);
	if (!target_file)
		return -EBADF;

	inode = file_inode(target_file);

	ret = check_attr_caps(inode, false);
	if (ret) {
		fput(target_file);
		return ret;
	}

	ret = build_xattr_name(req.name, xattr_name, sizeof(xattr_name));
	if (ret) {
		fput(target_file);
		return ret;
	}

	xattr_len = vfs_getxattr(&nop_mnt_idmap, target_file->f_path.dentry,
				 xattr_name, NULL, 0);
	if (xattr_len < 0) {
		fput(target_file);
		return xattr_len;
	}
	if (xattr_len < 4) {
		fput(target_file);
		return -ENODATA;
	}

	char *full = kvmalloc(xattr_len, GFP_KERNEL);
	if (!full) {
		fput(target_file);
		return -ENOMEM;
	}
	ret = vfs_getxattr(&nop_mnt_idmap, target_file->f_path.dentry,
			   xattr_name, full, xattr_len);
	if (ret < 4) {
		kvfree(full);
		fput(target_file);
		return ret < 0 ? ret : -ENODATA;
	}
	memcpy(&type, full, 4);
	kvfree(full);

	req.type_out = le32_to_cpu(type);
	req.size_out = (__u64)(xattr_len - 4);

	if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
		fput(target_file);
		return -EFAULT;
	}

	fput(target_file);
	return 0;
}


long nexus_attr_ioctl_remove(unsigned long arg)
{
	struct nexus_attr_remove req;
	struct file *target_file;
	struct inode *inode;
	char xattr_name[XATTR_NAME_MAX + 1];
	struct attr_lock *lk;
	int ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	req.name[sizeof(req.name) - 1] = '\0';

	target_file = fget(req.target_fd);
	if (!target_file)
		return -EBADF;

	inode = file_inode(target_file);

	ret = check_attr_caps(inode, true);
	if (ret) {
		fput(target_file);
		return ret;
	}

	ret = build_xattr_name(req.name, xattr_name, sizeof(xattr_name));
	if (ret) {
		fput(target_file);
		return ret;
	}

	lk = nexus_attr_lock_acquire(inode, xattr_name);
	if (!lk) {
		fput(target_file);
		return -ENOMEM;
	}

	ret = vfs_removexattr(&nop_mnt_idmap, target_file->f_path.dentry,
			      xattr_name);

	if (ret == 0)
		nexus_nm_notify_xattr(inode, xattr_name, B_ATTR_CAUSE_REMOVED);

	nexus_attr_lock_release(lk);
	fput(target_file);
	return ret;
}


long nexus_attr_ioctl_rename(unsigned long arg)
{
	struct nexus_attr_rename req;
	struct file *from_file, *to_file;
	struct inode *from_inode, *to_inode;
	char from_xattr[XATTR_NAME_MAX + 1];
	char to_xattr[XATTR_NAME_MAX + 1];
	struct attr_lock *lk_first = NULL, *lk_second = NULL;
	char *payload = NULL;
	ssize_t payload_len;
	int ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	req.from_name[sizeof(req.from_name) - 1] = '\0';
	req.to_name[sizeof(req.to_name) - 1]     = '\0';

	from_file = fget(req.from_fd);
	if (!from_file)
		return -EBADF;

	to_file = fget(req.to_fd);
	if (!to_file) {
		fput(from_file);
		return -EBADF;
	}

	from_inode = file_inode(from_file);
	to_inode   = file_inode(to_file);

	ret = check_attr_caps(from_inode, true);
	if (ret)
		goto out_fput;

	if (from_inode != to_inode) {
		ret = check_attr_caps(to_inode, true);
		if (ret)
			goto out_fput;
	}

	ret = build_xattr_name(req.from_name, from_xattr, sizeof(from_xattr));
	if (ret)
		goto out_fput;
	ret = build_xattr_name(req.to_name, to_xattr, sizeof(to_xattr));
	if (ret)
		goto out_fput;

	/* Canonical lock order: inode ptr asc, then xattr name. */
	bool first_is_from;
	if (from_inode != to_inode)
		first_is_from = (from_inode < to_inode);
	else
		first_is_from = (strcmp(from_xattr, to_xattr) <= 0);

	if (first_is_from) {
		lk_first  = nexus_attr_lock_acquire(from_inode, from_xattr);
		if (!lk_first) {
			ret = -ENOMEM;
			goto out_fput;
		}
		lk_second = nexus_attr_lock_acquire(to_inode, to_xattr);
		if (!lk_second) {
			ret = -ENOMEM;
			goto out_unlock_first;
		}
	} else {
		lk_first  = nexus_attr_lock_acquire(to_inode, to_xattr);
		if (!lk_first) {
			ret = -ENOMEM;
			goto out_fput;
		}
		lk_second = nexus_attr_lock_acquire(from_inode, from_xattr);
		if (!lk_second) {
			ret = -ENOMEM;
			goto out_unlock_first;
		}
	}

	payload_len = vfs_getxattr(&nop_mnt_idmap, from_file->f_path.dentry,
				   from_xattr, NULL, 0);
	if (payload_len < 0) {
		ret = payload_len;
		goto out_unlock_both;
	}

	payload = kvmalloc(payload_len, GFP_KERNEL);
	if (!payload) {
		ret = -ENOMEM;
		goto out_unlock_both;
	}

	ret = vfs_getxattr(&nop_mnt_idmap, from_file->f_path.dentry,
			   from_xattr, payload, payload_len);
	if (ret < 0)
		goto out_payload;

	ret = vfs_setxattr(&nop_mnt_idmap, to_file->f_path.dentry,
			   to_xattr, payload, payload_len, 0);

	if (ret)
		goto out_payload;

	ret = vfs_removexattr(&nop_mnt_idmap, from_file->f_path.dentry,
			      from_xattr);

	if (ret) {
		vfs_removexattr(&nop_mnt_idmap, to_file->f_path.dentry,
				to_xattr);
		goto out_payload;
	}

	nexus_nm_notify_xattr(to_inode,   to_xattr,   B_ATTR_CAUSE_CREATED);
	nexus_nm_notify_xattr(from_inode, from_xattr, B_ATTR_CAUSE_REMOVED);

out_payload:
	kvfree(payload);
out_unlock_both:
	nexus_attr_lock_release(lk_second);
out_unlock_first:
	nexus_attr_lock_release(lk_first);
out_fput:
	fput(to_file);
	fput(from_file);
	return ret;
}


int nexus_attr_init(void)
{
	hash_init(attr_lock_table);
	pr_info("nexus_attr: initialized\n");
	return 0;
}

void nexus_attr_exit(void)
{
	struct attr_lock *lk;
	struct hlist_node *tmp;
	unsigned long flags;
	int bkt;

	spin_lock_irqsave(&attr_lock_table_lock, flags);
	hash_for_each_safe(attr_lock_table, bkt, tmp, lk, node) {
		attr_warn("attr_lock for inode %p name '%s' still alive at exit "
			  "(refcount=%d)\n", lk->inode, lk->name, lk->refcount);
		hash_del(&lk->node);
		kfree(lk);
	}
	spin_unlock_irqrestore(&attr_lock_table_lock, flags);

	pr_info("nexus_attr: exited\n");
}
