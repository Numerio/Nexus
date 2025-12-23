// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025 Dario Casalinuovo
 */

#include <linux/cdev.h>
#include <linux/file.h>
#include <linux/mutex.h>
#include <linux/hashtable.h>
#include <linux/kref.h>

#include "errors.h"
#include "nexus.h"
#include "nexus_private.h"

#define DEV_NAME "nexus_vref"

static int major = -1;
static struct cdev nexus_cdev;
static struct class *nexus_class = NULL;

static DEFINE_HASHTABLE(fd_hashmap, 10);
static DEFINE_MUTEX(fd_map_lock);
static int32_t id_counter = 1;

static void nexus_vref_destroy(struct kref *kref) {
	struct nexus_vref *entry = container_of(kref, struct nexus_vref, ref_count);

	printk("nexus_vref_destroy vref %d", entry->id);

	fput(entry->file);
	hash_del(&entry->node);
	kfree(entry);
}

int32_t nexus_vref_create(int fd) {
	struct file *file = fget(fd);
	if (!file) {
		return -EBADF;
	}

	struct nexus_vref *entry = kzalloc(sizeof(struct nexus_vref), GFP_KERNEL);
	if (!entry) {
		fput(file);
		return -ENOMEM;
	}

	mutex_lock(&fd_map_lock);
	kref_init(&entry->ref_count);
	entry->id = id_counter++;
	entry->file = get_file(file);
	printk( KERN_INFO "create vref %d %d", entry->id, kref_read(&entry->ref_count));
	hash_add(fd_hashmap, &entry->node, entry->id);
	fput(file);
	mutex_unlock(&fd_map_lock);

	return entry->id;
}

int nexus_vref_acquire(int32_t id) {
	struct nexus_vref *entry = NULL;

	mutex_lock(&fd_map_lock);
	hash_for_each_possible(fd_hashmap, entry, node, id) {
		if (entry->id == id) {
			kref_get(&entry->ref_count);
			mutex_unlock(&fd_map_lock);
			return B_OK;
		}
	}
	mutex_unlock(&fd_map_lock);
	return -EINVAL;
}

int nexus_vref_acquire_fd(int32_t id) {
	struct nexus_vref *entry = NULL;
	struct hlist_node *tmp;

	mutex_lock(&fd_map_lock);
	hash_for_each_possible_safe(fd_hashmap, entry, tmp, node, id) {
		if (entry->id == id) {
			kref_get(&entry->ref_count);
			struct file* file = get_file(entry->file);
			int fd = get_unused_fd_flags(O_RDWR);
			if (fd < 0) {
				kref_put(&entry->ref_count, nexus_vref_destroy);
				fput(file);
				mutex_unlock(&fd_map_lock);
				return -1;
			}
			fd_install(fd, file);
			printk( KERN_INFO "acquire kref %d", kref_read(&entry->ref_count));
			mutex_unlock(&fd_map_lock);
			return fd;
		}
	}
	mutex_unlock(&fd_map_lock);
	return -EINVAL;
}

int nexus_vref_open(int32_t id) {
	struct nexus_vref *entry = NULL;

	mutex_lock(&fd_map_lock);
	hash_for_each_possible(fd_hashmap, entry, node, id) {
		if (entry->id == id) {
			struct file* file = get_file(entry->file);
			int fd = get_unused_fd_flags(O_RDWR);
			if (fd < 0) {
				fput(file);
				mutex_unlock(&fd_map_lock);
				return -1;
			}
			fd_install(fd, file);
			printk( KERN_INFO "acquire kref %d", kref_read(&entry->ref_count));
			mutex_unlock(&fd_map_lock);
			return fd;
		}
	}
	mutex_unlock(&fd_map_lock);
	return -EINVAL;
}

long nexus_vref_release(int32_t id) {
	printk(KERN_INFO "release called %d", current->pid);

	struct nexus_vref *entry = NULL;
	struct hlist_node *tmp = NULL;

	mutex_lock(&fd_map_lock);
	hash_for_each_possible_safe(fd_hashmap, entry, tmp, node, id) {
		if (entry->id == id) {
			printk( KERN_INFO "release vref %d count %d", id, kref_read(&entry->ref_count));
			kref_put(&entry->ref_count, nexus_vref_destroy);
			mutex_unlock(&fd_map_lock);
			return 0;
		}
	}
	mutex_unlock(&fd_map_lock);
	return -EINVAL;
}

static long vref_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	int fd = -1;
	int32_t id = -1;

	switch (cmd) {
		case NEXUS_VREF_CREATE:
			if (copy_from_user(&fd, (int __user *)arg, sizeof(fd)))
				return -EFAULT;
			return nexus_vref_create(fd);

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
			return -EINVAL;
	}
}

static int vref_open(struct inode *inode, struct file *file) {
	return 0;
}

static int vref_release(struct inode *inode, struct file *file) {
	return 0;
}

static const struct file_operations vref_fops = {
	.owner = THIS_MODULE,
	.open = vref_open,
	.release = vref_release,
	.unlocked_ioctl = vref_ioctl,
};

static void nexus_cleanup_dev(int device_created)
{
	if (device_created) {
		device_destroy(nexus_class, major);
		cdev_del(&nexus_cdev);
	}
	if (nexus_class)
		class_destroy(nexus_class);
	if (major != -1)
		unregister_chrdev_region(major, 1);
}

static int __init vref_init(void) {
	int device_created = 0;

	if (alloc_chrdev_region(&major, 0, 1, DEV_NAME "_proc") < 0)
		goto error;

	nexus_class = class_create(DEV_NAME "_sys");

	if (nexus_class == NULL)
		goto error;

	if (device_create(nexus_class, NULL, major, NULL, DEV_NAME) == NULL)
		goto error;

	device_created = 1;
	cdev_init(&nexus_cdev, &vref_fops);
	if (cdev_add(&nexus_cdev, major, 1) == -1)
		goto error;

	printk(KERN_INFO "nexus_vref loaded\n");
	return 0;

error:
	nexus_cleanup_dev(device_created);
	return -1;
}

static void __exit vref_exit(void) {
	nexus_cleanup_dev(1);
	printk(KERN_INFO "nexus_vref module unloaded\n");
}

module_init(vref_init);
module_exit(vref_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dario Casalinuovo");
MODULE_DESCRIPTION("Nexus IPC reference counted file descriptors handles.");
