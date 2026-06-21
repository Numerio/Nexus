// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026. Dario Casalinuovo
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
#include <linux/random.h>
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


/* Caller must hold fd_map_lock. Returns NULL if no entry matches. */
static struct nexus_vref *
find_entry_locked(int32_t id)
{
	struct nexus_vref *entry;

	hash_for_each_possible(fd_hashmap, entry, node, id) {
		if (entry->id == id)
			return entry;
	}
	return NULL;
}


static void
nexus_vref_destroy(struct kref *kref)
{
	struct nexus_vref *entry
		= container_of(kref, struct nexus_vref, ref_count);
	struct nexus_vref_slot *slot, *tmp;

	hash_del(&entry->node);

	list_for_each_entry_safe(slot, tmp, &entry->slots, node) {
		list_del(&slot->node);
		kfree(slot);
	}

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
	INIT_LIST_HEAD(&entry->slots);
	mutex_init(&entry->slots_lock);
	hash_add(fd_hashmap, &entry->node, entry->id);
	mutex_unlock(&fd_map_lock);

	return entry->id;
}

static fmode_t
nexus_vref_backing_mode(const struct nexus_vref *entry)
{
	return entry->kind == VREF_FH ? entry->fh.mode : entry->pth.mode;
}

static int
nexus_vref_add_slot_for(struct nexus_vref *entry, pid_t target_team,
	fmode_t allowed_mode, vref_key *out_key)
{
	struct nexus_vref_slot *slot;
	uint64_t key;

	slot = kzalloc(sizeof(*slot), GFP_KERNEL);
	if (!slot)
		return -ENOMEM;

	do {
		key = get_random_u64();
	} while (key == 0);

	slot->key = key;
	slot->owner_team = target_team;
	slot->allowed_mode = allowed_mode;

	mutex_lock(&entry->slots_lock);
	list_add(&slot->node, &entry->slots);
	mutex_unlock(&entry->slots_lock);

	kref_get(&entry->ref_count);
	*out_key = key;
	return B_OK;
}

static int
nexus_vref_add_slot(struct nexus_vref *entry, vref_key *out_key)
{
	return nexus_vref_add_slot_for(entry, current->tgid,
		nexus_vref_backing_mode(entry), out_key);
}

static bool
nexus_vref_caller_owns(struct nexus_vref *entry)
{
	struct nexus_vref_slot *s;
	bool owns = false;
	mutex_lock(&entry->slots_lock);
	list_for_each_entry(s, &entry->slots, node) {
		if (s->owner_team == current->tgid) {
			owns = true;
			break;
		}
	}
	mutex_unlock(&entry->slots_lock);
	return owns;
}

static int
nexus_vref_drop_slot(struct nexus_vref *entry, vref_key key)
{
	struct nexus_vref_slot *slot, *tmp;
	int ret = -EINVAL;

	mutex_lock(&entry->slots_lock);
	list_for_each_entry_safe(slot, tmp, &entry->slots, node) {
		if (slot->key != key || slot->owner_team != current->tgid)
			continue;
		list_del(&slot->node);
		kfree(slot);
		ret = B_OK;
		break;
	}
	mutex_unlock(&entry->slots_lock);

	if (ret == B_OK)
		kref_put(&entry->ref_count, nexus_vref_destroy);
	return ret;
}


static long
nexus_vref_create(struct nexus_vref_create __user *uarg)
{
	struct nexus_vref_create k;
	struct file *file;
	struct nexus_vref *entry = NULL;
	int32_t id;
	int ret;

	if (copy_from_user(&k, uarg, sizeof(k)))
		return -EFAULT;

	file = fget(k.fd);
	if (!file)
		return -EBADF;

	id = nexus_vref_create_from_file(file);
	fput(file);
	if (id < 0)
		return id;

	mutex_lock(&fd_map_lock);
	entry = find_entry_locked(id);
	if (entry == NULL) {
		mutex_unlock(&fd_map_lock);
		return -ENOENT;
	}
	ret = nexus_vref_add_slot(entry, &k.key);
	mutex_unlock(&fd_map_lock);
	if (ret != B_OK)
		return ret;

	k.id = id;
	if (copy_to_user(uarg, &k, sizeof(k)))
		return -EFAULT;
	return 0;
}


static long
nexus_vref_acquire(struct nexus_vref_op __user *uarg)
{
	struct nexus_vref_op k;
	struct nexus_vref *entry;
	int ret;

	if (copy_from_user(&k, uarg, sizeof(k)))
		return -EFAULT;

	mutex_lock(&fd_map_lock);
	entry = find_entry_locked(k.id);
	if (entry == NULL) {
		mutex_unlock(&fd_map_lock);
		return -EINVAL;
	}

	if (!nexus_vref_caller_owns(entry)) {
		struct nexus_vref_slot *s;
		pid_t first_owner = -1;

		mutex_lock(&entry->slots_lock);
		s = list_first_entry_or_null(&entry->slots,
			struct nexus_vref_slot, node);
		if (s != NULL)
			first_owner = s->owner_team;
		mutex_unlock(&entry->slots_lock);

		mutex_unlock(&fd_map_lock);
		pr_warn_ratelimited("nexus_vref: ACQUIRE EPERM "
			"id=%d caller=%d(%s) owner=%d\n",
			k.id, current->tgid, current->comm, first_owner);
		return -EPERM;
	}

	ret = nexus_vref_add_slot(entry, &k.key);
	mutex_unlock(&fd_map_lock);
	if (ret != B_OK)
		return ret;

	if (copy_to_user(uarg, &k, sizeof(k)))
		return -EFAULT;
	return 0;
}

static long
nexus_vref_open(struct nexus_vref_open __user *uarg)
{
	struct nexus_vref_open k;
	struct nexus_vref *entry;
	struct nexus_vref_slot *slot;
	struct file *file;
	int fd, ret = -EINVAL;

	enum nexus_vref_kind kind;
	struct vfsmount *mnt = NULL;
	struct path path = { .mnt = NULL, .dentry = NULL };
	u8 fh[NEXUS_FH_MAX];
	u8 fh_len = 0;
	int fh_type = 0;
	fmode_t open_mode = 0;
	bool held_kref = false;

	if (copy_from_user(&k, uarg, sizeof(k)))
		return -EFAULT;

	mutex_lock(&fd_map_lock);
	entry = find_entry_locked(k.id);
	if (entry == NULL) {
		mutex_unlock(&fd_map_lock);
		return -EINVAL;
	}

	mutex_lock(&entry->slots_lock);
	list_for_each_entry(slot, &entry->slots, node) {
		if (slot->key != k.key || slot->owner_team != current->tgid)
			continue;
		open_mode = k.requested_mode == 0
			? slot->allowed_mode
			: ((fmode_t)k.requested_mode & slot->allowed_mode);
		ret = open_mode == 0 ? -EACCES : B_OK;
		break;
	}
	mutex_unlock(&entry->slots_lock);

	if (ret == B_OK) {
		kind = entry->kind;
		if (kind == VREF_FH) {
			mnt = mntget(entry->fh.mnt);
			fh_len = entry->fh.fh_len;
			fh_type = entry->fh.fh_type;
			memcpy(fh, entry->fh.fh, fh_len);
		} else {
			path = entry->pth.path;
			path_get(&path);
		}
		kref_get(&entry->ref_count);
		held_kref = true;
	}
	mutex_unlock(&fd_map_lock);

	if (ret != B_OK)
		return ret;

	if (kind == VREF_FH) {
		struct dentry *dec = exportfs_decode_fh(mnt,
			(struct fid *)fh, fh_len / 4, fh_type, NULL, NULL);
		struct path p;
		if (IS_ERR(dec)) {
			ret = PTR_ERR(dec) == -ESTALE
				? B_ENTRY_NOT_FOUND : B_ERROR;
			goto out;
		}
		p.mnt = mnt;
		p.dentry = dec;
		file = dentry_open(&p, open_mode, current_cred());
		dput(dec);
	} else
		file = dentry_open(&path, open_mode, current_cred());

	if (IS_ERR(file)) {
		ret = B_NOT_ALLOWED;
		goto out;
	}
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		fput(file);
		ret = B_NO_MEMORY;
		goto out;
	}
	fd_install(fd, file);
	k.fd_out = fd;
	ret = B_OK;

out:
	if (kind == VREF_FH)
		mntput(mnt);
	else
		path_put(&path);
	if (held_kref) {
		mutex_lock(&fd_map_lock);
		kref_put(&entry->ref_count, nexus_vref_destroy);
		mutex_unlock(&fd_map_lock);
	}
	if (ret != B_OK)
		return ret;
	if (copy_to_user(uarg, &k, sizeof(k)))
		return -EFAULT;
	return 0;
}


static long
nexus_vref_release(struct nexus_vref_op __user *uarg)
{
	struct nexus_vref_op k;
	struct nexus_vref *entry;
	int ret = -EINVAL;

	if (copy_from_user(&k, uarg, sizeof(k)))
		return -EFAULT;

	mutex_lock(&fd_map_lock);
	entry = find_entry_locked(k.id);
	if (entry != NULL)
		ret = nexus_vref_drop_slot(entry, k.key);
	mutex_unlock(&fd_map_lock);

	return ret;
}


struct nexus_vref *
nexus_vref_kref_acquire(int32_t id)
{
	struct nexus_vref *entry;

	mutex_lock(&fd_map_lock);
	entry = find_entry_locked(id);
	if (entry != NULL)
		kref_get(&entry->ref_count);
	mutex_unlock(&fd_map_lock);
	return entry;
}

void
nexus_vref_kref_release(struct nexus_vref *entry)
{
	if (entry == NULL)
		return;
	mutex_lock(&fd_map_lock);
	kref_put(&entry->ref_count, nexus_vref_destroy);
	mutex_unlock(&fd_map_lock);
}

int
nexus_vref_mint_slot_for(struct nexus_vref *entry, pid_t target_team,
	uint64_t *out_key)
{
	if (entry == NULL || out_key == NULL)
		return -EINVAL;
	return nexus_vref_add_slot_for(entry, target_team,
		nexus_vref_backing_mode(entry), out_key);
}

int
nexus_vref_grant_slot_for_id(int32_t id, pid_t target_team)
{
	struct nexus_vref *entry;
	struct nexus_vref_slot *s;
	bool already_owns = false;
	uint64_t key;
	int ret;

	if (target_team <= 0)
		return -EINVAL;

	entry = nexus_vref_kref_acquire(id);
	if (entry == NULL)
		return -ENOENT;

	mutex_lock(&entry->slots_lock);
	list_for_each_entry(s, &entry->slots, node) {
		if (s->owner_team == target_team) {
			already_owns = true;
			break;
		}
	}
	mutex_unlock(&entry->slots_lock);

	if (already_owns) {
		nexus_vref_kref_release(entry);
		return B_OK;
	}

	ret = nexus_vref_add_slot_for(entry, target_team,
		nexus_vref_backing_mode(entry), &key);
	nexus_vref_kref_release(entry);
	return ret;
}


EXPORT_SYMBOL(nexus_vref_kref_acquire);
EXPORT_SYMBOL(nexus_vref_kref_release);
EXPORT_SYMBOL(nexus_vref_mint_slot_for);
EXPORT_SYMBOL(nexus_vref_grant_slot_for_id);
EXPORT_SYMBOL(nexus_vref_ioctl);
EXPORT_SYMBOL(nexus_vref_create_from_file);
EXPORT_SYMBOL(nexus_vref_drop_kernel_ref);
EXPORT_SYMBOL(nexus_vref_acquire_kernel_ref);


void
nexus_vref_drop_kernel_ref(int32_t id)
{
	struct nexus_vref *entry;

	mutex_lock(&fd_map_lock);
	entry = find_entry_locked(id);
	if (entry != NULL)
		kref_put(&entry->ref_count, nexus_vref_destroy);
	mutex_unlock(&fd_map_lock);
}


bool
nexus_vref_acquire_kernel_ref(int32_t id)
{
	struct nexus_vref *entry;

	mutex_lock(&fd_map_lock);
	entry = find_entry_locked(id);
	if (entry != NULL)
		kref_get(&entry->ref_count);
	mutex_unlock(&fd_map_lock);
	return entry != NULL;
}


long
nexus_vref_ioctl(unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
		case NEXUS_VREF_CREATE:
			return nexus_vref_create(
				(struct nexus_vref_create __user *)arg);

		case NEXUS_VREF_ACQUIRE:
			return nexus_vref_acquire(
				(struct nexus_vref_op __user *)arg);

		case NEXUS_VREF_RELEASE:
			return nexus_vref_release(
				(struct nexus_vref_op __user *)arg);

		case NEXUS_VREF_OPEN:
			return nexus_vref_open(
				(struct nexus_vref_open __user *)arg);

		default:
			return -ENOTTY;
	}
}


int
nexus_vref_init(void)
{
	nexus_register_team_exit(nexus_vref_team_exit);
	return 0;
}


void
nexus_vref_exit(void)
{
	nexus_unregister_team_exit(nexus_vref_team_exit);
	ida_destroy(&vref_ida);
}


void
nexus_vref_team_exit(pid_t team)
{
	struct nexus_vref *entry;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&fd_map_lock);
	hash_for_each_safe(fd_hashmap, bkt, tmp, entry, node) {
		struct nexus_vref_slot *slot, *stmp;
		int reaped = 0;

		mutex_lock(&entry->slots_lock);
		list_for_each_entry_safe(slot, stmp, &entry->slots, node) {
			if (slot->owner_team == (int)team) {
				list_del(&slot->node);
				kfree(slot);
				reaped++;
			}
		}
		mutex_unlock(&entry->slots_lock);
		while (reaped--)
			kref_put(&entry->ref_count, nexus_vref_destroy);
	}
	mutex_unlock(&fd_map_lock);
}
