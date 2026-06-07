// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026. Dario Casalinuovo
 *
 * vref: virtual reference handle for an inode-identity token.
 *
 * Two arms:
 *   VREF_FH   — exportfs file handle + vfsmount. Used for any filesystem
 *               with export_ops. No struct file or inode pin: rename and
 *               unlink-with-other-link semantics match BeOS node_ref.
 *               Re-open uses exportfs_decode_fh(); returns ESTALE → mapped
 *               to B_ENTRY_NOT_FOUND when the inode is gone.
 *
 *   VREF_PATH — pinned struct path. Fallback for synthetic filesystems
 *               (proc, sys, debugfs, cgroup) that lack export_ops. The
 *               pin is harmless on RAM-only fs.
 *
 * Sockets, anon_inodes, pipes are rejected at create: they have no useful
 * inode identity and are outside the entry_ref/node_ref API surface.
 */

#include <linux/dcache.h>
#include <linux/exportfs.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "errors.h"
#include "nexus.h"
#include "nexus_private.h"
#include "vref.h"

static DEFINE_HASHTABLE(fd_hashmap, 10);
static DEFINE_MUTEX(fd_map_lock);
static DEFINE_IDA(vref_ida);


static bool
is_rejected_fs(unsigned long magic)
{
	switch (magic) {
		case SOCKFS_MAGIC:
		case ANON_INODE_FS_MAGIC:
		case PIPEFS_MAGIC:
			return true;
		default:
			return false;
	}
}


static void
nexus_vref_destroy(struct kref *kref)
{
	struct nexus_vref *entry
		= container_of(kref, struct nexus_vref, ref_count);

	hash_del(&entry->node);
	if (entry->kind == VREF_FH)
		mntput(entry->fh.mnt);
	else
		path_put(&entry->pth.path);
	ida_free(&vref_ida, entry->id);
	kfree(entry);
}


int32_t
nexus_vref_create_from_file(struct file *file)
{
	struct nexus_vref *entry;
	struct dentry *dentry;
	struct super_block *sb;
	int id;

	if (!file || !file->f_path.dentry || !file->f_path.dentry->d_inode)
		return -ENOENT;

	dentry = file->f_path.dentry;
	sb = dentry->d_sb;
	if (is_rejected_fs(sb->s_magic))
		return -ENOTSUPP;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	if (sb->s_export_op != NULL) {
		int max_len = NEXUS_FH_MAX / 4;
		int type = exportfs_encode_fh(dentry,
			(struct fid *)entry->fh.fh, &max_len, 0);

		if (type > 0 && type != FILEID_INVALID
				&& max_len * 4 <= NEXUS_FH_MAX) {
			entry->kind     = VREF_FH;
			entry->fh.mnt   = mntget(file->f_path.mnt);
			entry->fh.fh_len  = (u8)(max_len * 4);
			entry->fh.fh_type = type;
			entry->fh.mode    = file->f_mode;
		} else {
			/* fall through to PATH arm */
			entry->kind = VREF_PATH;
		}
	} else {
		entry->kind = VREF_PATH;
	}

	if (entry->kind == VREF_PATH) {
		entry->pth.path = file->f_path;
		path_get(&entry->pth.path);
		entry->pth.mode = file->f_mode;
	}

	id = ida_alloc_min(&vref_ida, 1, GFP_KERNEL);
	if (id < 0) {
		if (entry->kind == VREF_FH)
			mntput(entry->fh.mnt);
		else
			path_put(&entry->pth.path);
		kfree(entry);
		return -ENOMEM;
	}

	mutex_lock(&fd_map_lock);
	kref_init(&entry->ref_count);
	entry->id = id;
	entry->team = current->tgid;
	hash_add(fd_hashmap, &entry->node, entry->id);
	mutex_unlock(&fd_map_lock);

	return entry->id;
}


static int32_t
nexus_vref_create_from_user_fd(int fd)
{
	struct file *file = fget(fd);
	int32_t id;

	if (!file)
		return -EBADF;

	id = nexus_vref_create_from_file(file);
	fput(file);
	return id;
}


static int
nexus_vref_acquire(int32_t id)
{
	struct nexus_vref *entry = NULL;

	mutex_lock(&fd_map_lock);
	hash_for_each_possible(fd_hashmap, entry, node, id) {
		if (entry->id == id) {
			kref_get(&entry->ref_count);
			entry->team = current->tgid;
			mutex_unlock(&fd_map_lock);
			return B_OK;
		}
	}
	mutex_unlock(&fd_map_lock);
	return -EINVAL;
}


/* Re-open the inode identified by the vref. Returns a new fd or a Haiku
 * status code. Caller takes ownership of the fd.
 */
static int
nexus_vref_reopen(struct nexus_vref *entry)
{
	struct file *file;
	int fd;

	if (entry->kind == VREF_FH) {
		struct dentry *dec = exportfs_decode_fh(entry->fh.mnt,
			(struct fid *)entry->fh.fh,
			entry->fh.fh_len / 4,
			entry->fh.fh_type,
			NULL, NULL);
		struct path p;

		if (IS_ERR(dec)) {
			long err = PTR_ERR(dec);
			return (err == -ESTALE) ? B_ENTRY_NOT_FOUND : B_ERROR;
		}
		p.mnt = entry->fh.mnt;
		p.dentry = dec;
		file = dentry_open(&p, entry->fh.mode, current_cred());
		dput(dec);
	} else {
		file = dentry_open(&entry->pth.path, entry->pth.mode,
			current_cred());
	}

	if (IS_ERR(file))
		return B_NOT_ALLOWED;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		fput(file);
		return B_NO_MEMORY;
	}
	fd_install(fd, file);
	return fd;
}


static int
nexus_vref_acquire_fd(int32_t id)
{
	struct nexus_vref *entry = NULL;
	int fd = -EINVAL;

	mutex_lock(&fd_map_lock);
	hash_for_each_possible(fd_hashmap, entry, node, id) {
		if (entry->id == id) {
			fd = nexus_vref_reopen(entry);
			break;
		}
	}
	mutex_unlock(&fd_map_lock);
	return fd;
}


static int
nexus_vref_open(int32_t id)
{
	struct nexus_vref *entry = NULL;
	int fd = B_ENTRY_NOT_FOUND;

	mutex_lock(&fd_map_lock);
	hash_for_each_possible(fd_hashmap, entry, node, id) {
		if (entry->id == id) {
			fd = nexus_vref_reopen(entry);
			break;
		}
	}
	mutex_unlock(&fd_map_lock);
	return fd;
}


void
nexus_vref_drop_kernel_ref(int32_t id)
{
	struct nexus_vref *entry = NULL;
	struct hlist_node *tmp = NULL;

	mutex_lock(&fd_map_lock);
	hash_for_each_possible_safe(fd_hashmap, entry, tmp, node, id) {
		if (entry->id == id) {
			kref_put(&entry->ref_count, nexus_vref_destroy);
			break;
		}
	}
	mutex_unlock(&fd_map_lock);
}


static long
nexus_vref_release(int32_t id)
{
	struct nexus_vref *entry = NULL;
	struct hlist_node *tmp = NULL;
	long ret = -EINVAL;

	mutex_lock(&fd_map_lock);
	hash_for_each_possible_safe(fd_hashmap, entry, tmp, node, id) {
		if (entry->id == id) {
			if (entry->team != current->tgid) {
				ret = 0;
			} else {
				kref_put(&entry->ref_count, nexus_vref_destroy);
				ret = 0;
			}
			break;
		}
	}
	mutex_unlock(&fd_map_lock);
	return ret;
}


long
nexus_vref_ioctl(unsigned int cmd, unsigned long arg)
{
	int fd = -1;
	int32_t id = -1;

	switch (cmd) {
		case NEXUS_VREF_CREATE:
			if (copy_from_user(&fd, (int __user *)arg, sizeof(fd)))
				return -EFAULT;
			return nexus_vref_create_from_user_fd(fd);

		case NEXUS_VREF_ACQUIRE_FD:
			if (copy_from_user(&id, (int __user *)arg, sizeof(id)))
				return -EFAULT;
			return nexus_vref_acquire_fd(id);

		case NEXUS_VREF_ACQUIRE:
			if (copy_from_user(&id, (int __user *)arg, sizeof(id)))
				return -EFAULT;
			return nexus_vref_acquire(id);

		case NEXUS_VREF_OPEN:
			if (copy_from_user(&id, (int __user *)arg, sizeof(id)))
				return -EFAULT;
			return nexus_vref_open(id);

		case NEXUS_VREF_RELEASE:
			if (copy_from_user(&id, (int __user *)arg, sizeof(id)))
				return -EFAULT;
			return nexus_vref_release(id);

		default:
			return -ENOTTY;
	}
}


int
nexus_vref_init(void)
{
	pr_info("nexus_vref: initialized (fh+path)\n");
	return 0;
}


void
nexus_vref_exit(void)
{
	ida_destroy(&vref_ida);
	pr_info("nexus_vref: cleaned up\n");
}


void
nexus_vref_team_exit(pid_t team)
{
	struct nexus_vref *entry;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&fd_map_lock);
	hash_for_each_safe(fd_hashmap, bkt, tmp, entry, node) {
		if (entry->team == (int)team) {
			pr_debug("nexus_vref: releasing vref %d for exiting team %d\n",
				entry->id, team);
			kref_put(&entry->ref_count, nexus_vref_destroy);
		}
	}
	mutex_unlock(&fd_map_lock);
}
