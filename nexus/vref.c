// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026. Dario Casalinuovo
 */

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/hashtable.h>
#include <linux/kref.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "errors.h"
#include "nexus.h"
#include "nexus_private.h"
#include "vref.h"

static DEFINE_HASHTABLE(fd_hashmap, 10);
static DEFINE_MUTEX(fd_map_lock);
static DEFINE_IDA(vref_ida);

static void nexus_vref_destroy(struct kref *kref) {
	struct nexus_vref *entry = container_of(kref, struct nexus_vref, ref_count);


	ida_free(&vref_ida, entry->id);
	fput(entry->file);
	hash_del(&entry->node);
	kfree(entry);
}

int32_t nexus_vref_create_from_file(struct file *file) {
	struct nexus_vref *entry = kzalloc(sizeof(struct nexus_vref), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	int id = ida_alloc_min(&vref_ida, 1, GFP_KERNEL);
	if (id < 0) {
		kfree(entry);
		return -ENOMEM;
	}

	mutex_lock(&fd_map_lock);
	kref_init(&entry->ref_count);
	entry->id = id;
	entry->file = get_file(file);
	entry->team = current->tgid;
	hash_add(fd_hashmap, &entry->node, entry->id);
	mutex_unlock(&fd_map_lock);

	return entry->id;
}

static int32_t nexus_vref_create_from_user_fd(int fd) {
	struct file *file = fget(fd);
	if (!file)
		return -EBADF;

	int32_t id = nexus_vref_create_from_file(file);
	fput(file);
	return id;
}

static int nexus_vref_acquire(int32_t id) {
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

static int nexus_vref_acquire_fd(int32_t id) {
	struct nexus_vref *entry = NULL;
	struct hlist_node *tmp;

	mutex_lock(&fd_map_lock);
	hash_for_each_possible_safe(fd_hashmap, entry, tmp, node, id) {
		if (entry->id == id) {
			struct file* file = get_file(entry->file);
			int fd = get_unused_fd_flags(entry->file->f_flags & O_CLOEXEC);
			if (fd < 0) {
				fput(file);
				mutex_unlock(&fd_map_lock);
				return -1;
			}
			fd_install(fd, file);
			mutex_unlock(&fd_map_lock);
			return fd;
		}
	}
	mutex_unlock(&fd_map_lock);
	return -EINVAL;
}

static int nexus_vref_open(int32_t id) {
	struct nexus_vref *entry = NULL;

	mutex_lock(&fd_map_lock);
	hash_for_each_possible(fd_hashmap, entry, node, id) {
		if (entry->id == id) {
			struct file* file = get_file(entry->file);
			int fd = get_unused_fd_flags(entry->file->f_flags & O_CLOEXEC);
			if (fd < 0) {
				fput(file);
				mutex_unlock(&fd_map_lock);
				return B_ENTRY_NOT_FOUND;
			}
			fd_install(fd, file);
			mutex_unlock(&fd_map_lock);
			return fd;
		}
	}
	mutex_unlock(&fd_map_lock);
	return B_ENTRY_NOT_FOUND;
}

void nexus_vref_drop_kernel_ref(int32_t id) {
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

static long nexus_vref_release(int32_t id) {
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

long nexus_vref_ioctl(unsigned int cmd, unsigned long arg) {
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

int nexus_vref_init(void)
{
	pr_info("nexus_vref: initialized\n");
	return 0;
}

void nexus_vref_exit(void)
{
	ida_destroy(&vref_ida);
	pr_info("nexus_vref: cleaned up\n");
}

void nexus_vref_team_exit(pid_t team)
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


