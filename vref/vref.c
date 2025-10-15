// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025 Dario Casalinuovo
 */

#include <linux/cdev.h>
#include <linux/file.h>
#include <linux/mutex.h>
#include <linux/hashtable.h>
#include <linux/kref.h>

#include "../nexus/errors.h"
#include "../nexus/nexus.h"
#include "../nexus/nexus_private.h"

#define DEV_NAME "nexus_vref"

static int major = -1;
static struct cdev nexus_cdev;
static struct class *nexus_class = NULL;

static DEFINE_HASHTABLE(fd_hashmap, 10);
static DEFINE_MUTEX(fd_map_lock);
static int32_t id_counter = 0;

struct fd_entry {
	pid_t pid;
	int fd;
	struct list_head list;
};


static void fd_entry_release(struct kref *kref) {
	printk(KERN_INFO "fd_entry_release");
	struct nexus_vref *entry = container_of(kref, struct nexus_vref, ref_count);
	struct fd_entry *entry_fd, *tmp;

	list_for_each_entry_safe(entry_fd, tmp, &entry->fd_list, list) {
		list_del(&entry_fd->list);
		kfree(entry_fd);
	}

	hash_del(&entry->node);
	kfree(entry);
}

static struct nexus_vref *find_or_create_entry(int fd) {
	printk(KERN_INFO "find_or_create_entry");
	struct file *f = fget(fd);
	if (!f) {
		return ERR_PTR(-EBADF);
	}

	dev_t dev = f->f_inode->i_sb->s_dev;
	ino_t ino = f->f_inode->i_ino;
	struct nexus_vref *entry = NULL;
	int32_t id;

	mutex_lock(&fd_map_lock);

	hash_for_each(fd_hashmap, id, entry, node) {
		if (entry->dev == dev && entry->ino == ino) {
			kref_get(&entry->ref_count);
			mutex_unlock(&fd_map_lock);
			fput(f);
			return entry;
		}
	}

	entry = kmalloc(sizeof(struct nexus_vref), GFP_KERNEL);
	if (!entry) {
		mutex_unlock(&fd_map_lock);
		fput(f);
		return ERR_PTR(-ENOMEM);
	}

	kref_init(&entry->ref_count);
	//kref_get
	INIT_LIST_HEAD(&entry->fd_list);
	entry->id = id_counter++;

	entry->file = f;
	entry->dev = dev;
	entry->ino = ino;

	hash_add(fd_hashmap, &entry->node, entry->id);

	mutex_unlock(&fd_map_lock);
	printk(KERN_INFO "entry added %d", entry->id);
	return entry;
}

int32_t nexus_vref_create(int fd) {
	printk(KERN_INFO "nexus_vref_create");
	struct nexus_vref *entry = find_or_create_entry(fd);
	if (IS_ERR(entry)) {
		return PTR_ERR(entry);
	}

	struct fd_entry *entry_fd = kmalloc(sizeof(struct fd_entry), GFP_KERNEL);
	if (!entry_fd) {
		fput(entry->file);
		kref_put(&entry->ref_count, fd_entry_release);
		return -ENOMEM;
	}
	
	entry_fd->pid = current->pid;
	entry_fd->fd = fd;
	list_add(&entry_fd->list, &entry->fd_list);
	printk(KERN_INFO "nexus_vref_create add %d %d", fd, entry->id);
	return entry->id;
}

int nexus_vref_acquire(int32_t id) {
	printk(KERN_INFO "nexus_vref_acquire %d", id);
	struct nexus_vref *entry = NULL;

	mutex_lock(&fd_map_lock);

	int32_t _id;
	hash_for_each(fd_hashmap, _id, entry, node) {
		printk(KERN_INFO "a %d %d", id, entry->id);

		if (entry->id == id) {
			printk(KERN_INFO "---------------found");

			struct fd_entry *entry_fd;
			list_for_each_entry(entry_fd, &entry->fd_list, list) {
				if (entry_fd->pid == current->pid) {
					kref_get(&entry->ref_count);
					mutex_unlock(&fd_map_lock);
					return entry_fd->fd;
				}
			}

			int fd = get_unused_fd_flags(O_RDONLY);
			if (fd < 0) {
				printk(KERN_INFO "failed to get fd");
				mutex_unlock(&fd_map_lock);
				return -1;
			}

			fd_install(fd, entry->file);

			struct fd_entry *ret = kmalloc(sizeof(struct fd_entry), GFP_KERNEL);
			if (!ret) {
				fput(entry->file);
				mutex_unlock(&fd_map_lock);
				return -ENOMEM;
			}

			ret->pid = current->pid;
			ret->fd = fd;
			list_add(&ret->list, &entry->fd_list);
			mutex_unlock(&fd_map_lock);
			return fd;
		}
	}

	printk(KERN_INFO "******************* einval2\n");
	mutex_unlock(&fd_map_lock);
	return -EINVAL;
}

long nexus_vref_release(int32_t id) {
	printk(KERN_INFO "nexus_vref_release");
	struct nexus_vref *entry = NULL;

	mutex_lock(&fd_map_lock);

	int32_t _id;
	hash_for_each(fd_hashmap, _id, entry, node) {
		if (entry->id == id) {
			printk(KERN_INFO "nexus_vref_release id %d", id);
			kref_put(&entry->ref_count, fd_entry_release);
			mutex_unlock(&fd_map_lock);
			return 0;
		}
	}

	printk(KERN_INFO "einval\n");
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
		
		case NEXUS_VREF_ACQUIRE:
			if (copy_from_user(&id, (int __user *)arg, sizeof(id)))
				return -EFAULT;

			return nexus_vref_acquire(id);
		
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
