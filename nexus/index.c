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
#include <linux/xattr.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/dirent.h>
#include <linux/namei.h>
#include <linux/stat.h>
#include <linux/mnt_idmapping.h>

#include "index.h"
#include "nexus.h"
#include "volume.h"

#define idx_err(fmt, ...)  pr_err("nexus_idx: ERROR: " fmt, ##__VA_ARGS__)
#define idx_warn(fmt, ...) pr_warn("nexus_idx: WARN: "  fmt, ##__VA_ARGS__)

/* xattr key names for index metadata (stored on the marker file) */
#define IDX_XATTR_TYPE  "user.beos.index_type"
#define IDX_XATTR_FLAGS "user.beos.index_flags"

#define INDEXES_ROOT      "/system/indexes"
#define INDEXES_ROOT_LEN  16

#define UUID_STR_LEN 37
#define IDX_PATH_MAX 320

static int resolve_target(int target_fd, struct file **filep,
			  struct inode **inodep, char uuid[UUID_STR_LEN])
{
	struct file *f;
	struct inode *inode;
	int ret;

	f = fget(target_fd);
	if (!f)
		return -EBADF;

	inode = file_inode(f);

	ret = nexus_uuid_for_inode(inode, uuid);
	if (ret) {
		fput(f);
		return (ret == -ENODATA) ? -EOPNOTSUPP : ret;
	}

	*filep  = f;
	*inodep = inode;
	return 0;
}

static int check_index_caps(struct inode *inode, bool need_write)
{
	uint32_t caps = nexus_caps_for_inode(inode);

	if (!(caps & NX_FS_HAS_QUERY))
		return -EOPNOTSUPP;
	if (need_write && (caps & NX_FS_IS_READONLY))
		return -EROFS;
	return 0;
}

static int validate_index_name(const char name[256])
{
	size_t len = strnlen(name, 256);

	if (len == 0 || len == 256)
		return -EINVAL;

	if (memchr(name, '/', len))
		return -EINVAL;

	return (int)len;
}

static int build_index_path(const char *uuid, const char *name,
			    char *buf, size_t bufsz)
{
	int n = snprintf(buf, bufsz, "%s/%s/%s", INDEXES_ROOT, uuid, name);

	if (n < 0 || (size_t)n >= bufsz)
		return -ENAMETOOLONG;
	return 0;
}

static int build_uuid_dir_path(const char *uuid, char *buf, size_t bufsz)
{
	int n = snprintf(buf, bufsz, "%s/%s", INDEXES_ROOT, uuid);

	if (n < 0 || (size_t)n >= bufsz)
		return -ENAMETOOLONG;
	return 0;
}

static int ensure_dir(const char *path)
{
	struct path parent_path;
	struct dentry *child;
	const char *slash;
	char parent_buf[IDX_PATH_MAX];
	const char *basename;
	int ret;
	size_t parent_len;

	slash = strrchr(path, '/');
	if (!slash || slash == path)
		return -EINVAL;

	basename = slash + 1;
	parent_len = (size_t)(slash - path);
	if (parent_len == 0 || parent_len >= sizeof(parent_buf))
		return -EINVAL;

	memcpy(parent_buf, path, parent_len);
	parent_buf[parent_len] = '\0';

	ret = kern_path(parent_buf, LOOKUP_DIRECTORY, &parent_path);
	if (ret)
		return ret;

	inode_lock(d_inode(parent_path.dentry));
	child = lookup_one_len(basename, parent_path.dentry, strlen(basename));
	if (IS_ERR(child)) {
		ret = PTR_ERR(child);
		goto out_unlock;
	}

	if (d_is_positive(child)) {
		ret = 0;
		dput(child);
		goto out_unlock;
	}

	ret = vfs_mkdir(&nop_mnt_idmap, d_inode(parent_path.dentry),
			child, 0755);
	dput(child);

out_unlock:
	inode_unlock(d_inode(parent_path.dentry));
	path_put(&parent_path);
	return ret;
}

static int ensure_indexes_tree(const char *uuid)
{
	char path[IDX_PATH_MAX];
	int ret;

	ret = ensure_dir(INDEXES_ROOT);
	if (ret && ret != -EEXIST)
		return ret;

	ret = build_uuid_dir_path(uuid, path, sizeof(path));
	if (ret)
		return ret;

	ret = ensure_dir(path);
	if (ret && ret != -EEXIST)
		return ret;

	return 0;
}


struct idx_dir_ctx {
	struct file *backing;
};

static int idx_dir_iterate(struct file *file, struct dir_context *ctx)
{
	struct idx_dir_ctx *idctx = file->private_data;

	if (!idctx || !idctx->backing)
		return 0;

	return idctx->backing->f_op->iterate_shared(idctx->backing, ctx);
}

static int idx_dir_release(struct inode *inode, struct file *file)
{
	struct idx_dir_ctx *idctx = file->private_data;

	if (idctx) {
		if (idctx->backing)
			fput(idctx->backing);
		kfree(idctx);
		file->private_data = NULL;
	}
	return 0;
}

static const struct file_operations idx_dir_fops = {
	.owner          = THIS_MODULE,
	.iterate_shared = idx_dir_iterate,
	.release        = idx_dir_release,
	.llseek         = default_llseek,
};


long nexus_index_ioctl_dir_open(unsigned long arg)
{
	struct nexus_index_dir_open req;
	struct file *target_file;
	struct inode *inode;
	char uuid[UUID_STR_LEN];
	char uuid_dir[IDX_PATH_MAX];
	struct path dir_path;
	struct file *backing = NULL;
	struct idx_dir_ctx *idctx;
	int fd, ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	ret = resolve_target(req.target_fd, &target_file, &inode, uuid);
	if (ret)
		return ret;

	ret = check_index_caps(inode, false);
	if (ret)
		goto out_fput;

	ret = build_uuid_dir_path(uuid, uuid_dir, sizeof(uuid_dir));
	if (ret)
		goto out_fput;

	ret = kern_path(uuid_dir, LOOKUP_DIRECTORY, &dir_path);
	if (ret == 0) {
		backing = dentry_open(&dir_path, O_RDONLY | O_DIRECTORY,
				      current_cred());
		path_put(&dir_path);
		if (IS_ERR(backing)) {
			ret = PTR_ERR(backing);
			goto out_fput;
		}
	} else if (ret != -ENOENT) {
		goto out_fput;
	}
	ret = 0;

	idctx = kzalloc(sizeof(*idctx), GFP_KERNEL);
	if (!idctx) {
		if (backing)
			fput(backing);
		ret = -ENOMEM;
		goto out_fput;
	}
	idctx->backing = backing;

	fd = anon_inode_getfd("[nexus-index-dir]", &idx_dir_fops, idctx,
			      O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (backing)
			fput(backing);
		kfree(idctx);
		ret = fd;
		goto out_fput;
	}

	fput(target_file);
	return fd;

out_fput:
	fput(target_file);
	return ret;
}


long nexus_index_ioctl_create(unsigned long arg)
{
	struct nexus_index_create req;
	struct file *target_file;
	struct inode *inode;
	char uuid[UUID_STR_LEN];
	char marker_path[IDX_PATH_MAX];
	char uuid_dir[IDX_PATH_MAX];
	struct path parent_path;
	struct dentry *marker_dentry;
	__u32 le_val;
	int ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	req.name[sizeof(req.name) - 1] = '\0';

	ret = validate_index_name(req.name);
	if (ret < 0)
		return ret;

	ret = resolve_target(req.target_fd, &target_file, &inode, uuid);
	if (ret)
		return ret;

	ret = check_index_caps(inode, true);
	if (ret)
		goto out_fput;

	ret = ensure_indexes_tree(uuid);
	if (ret)
		goto out_fput;

	ret = build_index_path(uuid, req.name, marker_path, sizeof(marker_path));
	if (ret)
		goto out_fput;

	ret = build_uuid_dir_path(uuid, uuid_dir, sizeof(uuid_dir));
	if (ret)
		goto out_fput;

	ret = kern_path(uuid_dir, LOOKUP_DIRECTORY, &parent_path);
	if (ret)
		goto out_fput;

	inode_lock(d_inode(parent_path.dentry));

	marker_dentry = lookup_one_len(req.name, parent_path.dentry,
				       strlen(req.name));
	if (IS_ERR(marker_dentry)) {
		ret = PTR_ERR(marker_dentry);
		goto out_parent_unlock;
	}

	if (d_is_positive(marker_dentry)) {
		ret = -EEXIST;
		goto out_dput;
	}

	ret = vfs_create(&nop_mnt_idmap, d_inode(parent_path.dentry),
			 marker_dentry, 0644, false);
	if (ret)
		goto out_dput;

	le_val = cpu_to_le32(req.type);
	ret = vfs_setxattr(&nop_mnt_idmap, marker_dentry, IDX_XATTR_TYPE,
			   &le_val, sizeof(le_val), 0);
	if (ret)
		goto out_dput;

	le_val = cpu_to_le32(req.flags);
	ret = vfs_setxattr(&nop_mnt_idmap, marker_dentry, IDX_XATTR_FLAGS,
			   &le_val, sizeof(le_val), 0);

out_dput:
	dput(marker_dentry);
out_parent_unlock:
	inode_unlock(d_inode(parent_path.dentry));
	path_put(&parent_path);
out_fput:
	fput(target_file);
	return ret;
}


long nexus_index_ioctl_remove(unsigned long arg)
{
	struct nexus_index_remove req;
	struct file *target_file;
	struct inode *inode;
	char uuid[UUID_STR_LEN];
	char uuid_dir[IDX_PATH_MAX];
	struct path parent_path;
	struct dentry *marker_dentry;
	int ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	req.name[sizeof(req.name) - 1] = '\0';

	ret = validate_index_name(req.name);
	if (ret < 0)
		return ret;

	ret = resolve_target(req.target_fd, &target_file, &inode, uuid);
	if (ret)
		return ret;

	ret = check_index_caps(inode, true);
	if (ret)
		goto out_fput;

	ret = build_uuid_dir_path(uuid, uuid_dir, sizeof(uuid_dir));
	if (ret)
		goto out_fput;

	ret = kern_path(uuid_dir, LOOKUP_DIRECTORY, &parent_path);
	if (ret) {
		if (ret == -ENOENT)
			ret = -ENOENT;
		goto out_fput;
	}

	inode_lock(d_inode(parent_path.dentry));

	marker_dentry = lookup_one_len(req.name, parent_path.dentry,
				       strlen(req.name));
	if (IS_ERR(marker_dentry)) {
		ret = PTR_ERR(marker_dentry);
		goto out_parent_unlock;
	}

	if (!d_is_positive(marker_dentry)) {
		ret = -ENOENT;
		goto out_dput;
	}

	ret = vfs_unlink(&nop_mnt_idmap, d_inode(parent_path.dentry),
			 marker_dentry, NULL);

out_dput:
	dput(marker_dentry);
out_parent_unlock:
	inode_unlock(d_inode(parent_path.dentry));
	path_put(&parent_path);
out_fput:
	fput(target_file);
	return ret;
}


long nexus_index_ioctl_stat(unsigned long arg)
{
	struct nexus_index_stat req;
	struct file *target_file;
	struct inode *inode;
	char uuid[UUID_STR_LEN];
	char marker_path[IDX_PATH_MAX];
	struct path mpath;
	struct kstat kst;
	__u32 le_val;
	ssize_t xret;
	int ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	req.name[sizeof(req.name) - 1] = '\0';

	ret = validate_index_name(req.name);
	if (ret < 0)
		return ret;

	ret = resolve_target(req.target_fd, &target_file, &inode, uuid);
	if (ret)
		return ret;

	ret = check_index_caps(inode, false);
	if (ret)
		goto out_fput;

	ret = build_index_path(uuid, req.name, marker_path, sizeof(marker_path));
	if (ret)
		goto out_fput;

	ret = kern_path(marker_path, 0, &mpath);
	if (ret)
		goto out_fput;

	xret = vfs_getxattr(&nop_mnt_idmap, mpath.dentry, IDX_XATTR_TYPE,
			    &le_val, sizeof(le_val));
	if (xret < 0) {
		ret = (int)xret;
		goto out_path;
	}
	req.type = le32_to_cpu(le_val);

	xret = vfs_getxattr(&nop_mnt_idmap, mpath.dentry, IDX_XATTR_FLAGS,
			    &le_val, sizeof(le_val));
	if (xret < 0) {
		req.flags = 0;
	} else {
		req.flags = le32_to_cpu(le_val);
	}

	ret = vfs_getattr(&mpath, &kst, STATX_MTIME | STATX_CTIME,
			  AT_STATX_SYNC_AS_STAT);
	if (ret)
		goto out_path;

	req.size              = 0;
	req.modification_time = (__s64)kst.mtime.tv_sec;
	req.creation_time     = (__s64)kst.ctime.tv_sec;
	req.uid               = 0;
	req.gid               = 0;

	if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
		ret = -EFAULT;
		goto out_path;
	}
	ret = 0;

out_path:
	path_put(&mpath);
out_fput:
	fput(target_file);
	return ret;
}


int nexus_index_init(void)
{
	pr_info("nexus_idx: initialized\n");
	return 0;
}

void nexus_index_exit(void)
{
	pr_info("nexus_idx: exited\n");
}
