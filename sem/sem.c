// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025 Dario Casalinuovo
 */

#include <linux/cdev.h>
#include <linux/jiffies.h>
#include <linux/semaphore.h>

#include "../nexus/errors.h"
#include "../nexus/nexus.h"
#include "../nexus/nexus_private.h"

#define DEV_NAME "nexus_sem"

static int major = -1;
static struct cdev nexus_cdev;
static struct class *nexus_class = NULL;

typedef int32_t sem_id;

static struct nexus_sem *nexus_sems[1000];
static DEFINE_MUTEX(nexus_sem_lock);

int last_sem_id = 1;


long nexus_sem_create(struct nexus_sem_exchange *exchange) {
	struct nexus_sem* sem
		= kzalloc(sizeof(struct nexus_port), GFP_KERNEL);

	if (sem == NULL)
		return -ENOMEM;

	// TODO B_NO_MORE_SEMS

	mutex_lock(&nexus_sem_lock);
	last_sem_id++;

	printk(KERN_INFO "create sem id %d\n", last_sem_id);

	nexus_sems[last_sem_id] = sem;

	printk(KERN_INFO "create sem id %d ok\n", last_sem_id);

	sema_init(&nexus_sems[last_sem_id]->sem, exchange->count);
	kref_init(&sem->ref_count);
	kref_get(&sem->ref_count);
	exchange->id = last_sem_id;
	sem->deleted = false;
	mutex_unlock(&nexus_sem_lock);

	return 0;
}

long nexus_sem_acquire(struct nexus_sem_exchange *exchange) {

	mutex_lock(&nexus_sem_lock);
	struct nexus_sem* sem = nexus_sems[exchange->id];
	if (exchange->id < 0 || sem == NULL)
		return B_BAD_VALUE;

	printk(KERN_INFO "acquire sem id %d\n", exchange->id);

	kref_get(&sem->ref_count);
	mutex_unlock(&nexus_sem_lock);

	// TODO B_DO_NOT_RESCHEDULE
	int ret = B_ERROR;
	// B_ABSOLUTE_TIMEOUT
	if (exchange->flags & B_TIMEOUT || exchange->flags & B_ABSOLUTE_TIMEOUT && exchange->timeout != B_INFINITE_TIMEOUT) {
		printk(KERN_INFO "timeout %d", exchange->id);

		unsigned long timeout_jiffies
			= (unsigned long)(exchange->timeout * HZ / 1000000);

		if (exchange->flags & B_ABSOLUTE_TIMEOUT)
			timeout_jiffies -= jiffies;

		printk(KERN_INFO "timeout %d\n", timeout_jiffies);
		ret = down_timeout(&sem->sem, timeout_jiffies);
		exchange->count--;
		while (ret == 0 && exchange->count != 0) {
			ret = down_interruptible(&sem->sem);
			exchange->count--;
		}
		if (ret < 0) {
			if (ret == -EAGAIN || (ret == -ETIME && exchange->timeout == 0))
				ret = B_WOULD_BLOCK;

			if (ret == -ETIME)
				ret = B_TIMED_OUT;
		}
	} else {
		while (exchange->count != 0) {
			ret = down_interruptible(&sem->sem);
			if (ret < 0)
				break;
			exchange->count--;
		}
	}

	if (ret == -EINTR)
		ret = B_INTERRUPTED;

	mutex_lock(&nexus_sem_lock);
	if (sem->deleted) {
		kref_put(&sem->ref_count, nexus_sem_delete);
		mutex_unlock(&nexus_sem_lock);
		return B_BAD_SEM_ID;
	}

	kref_put(&sem->ref_count, nexus_sem_delete);
	mutex_unlock(&nexus_sem_lock);

	printk(KERN_INFO "acquire sem id %d exit\n", exchange->id);

	return ret;
}

long nexus_sem_release(struct nexus_sem_exchange *exchange) {
	printk(KERN_INFO "release sem id %d\n", exchange->id);

	// TODO B_RELEASE_ALL

	mutex_lock(&nexus_sem_lock);
	struct nexus_sem* sem = nexus_sems[exchange->id];
	if (exchange->id < 0 || !sem) {
		mutex_unlock(&nexus_sem_lock);
		return B_BAD_VALUE;
	}
	kref_get(&sem->ref_count);
	mutex_unlock(&nexus_sem_lock);

	while(exchange->count != 0) {
		up(&sem->sem);
		exchange->count--;
	}

	mutex_lock(&nexus_sem_lock);
	kref_put(&sem->ref_count, nexus_sem_delete);
	mutex_unlock(&nexus_sem_lock);

	return 0;
}

void nexus_sem_delete(struct kref* ref) {
	struct nexus_sem* sem = container_of(ref, struct nexus_sem, ref_count);

	printk(KERN_INFO "delete sem id %d\n", sem->id);

	nexus_sems[sem->id] = NULL;
	kfree(sem);
}

long nexus_sem_count(struct nexus_sem_exchange *exchange) {
	mutex_lock(&nexus_sem_lock);
	if (exchange->id < 0 || !nexus_sems[exchange->id])
		return B_BAD_VALUE;

	exchange->count = nexus_sems[exchange->id]->sem.count;
	printk(KERN_INFO "count sem id %d %d\n", exchange->id, exchange->count);

	mutex_unlock(&nexus_sem_lock);
	return 0;
}

static long sem_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	struct nexus_sem_exchange exchange;
	long ret;

	if (copy_from_user(&exchange, (struct nexus_sem_exchange __user *)arg,
			sizeof(exchange))) {
		return -EFAULT;
	}

	switch (cmd) {
		case NEXUS_SEM_CREATE:
			ret = nexus_sem_create(&exchange);
			if (ret < 0)
				return ret;
	
			if (copy_to_user((struct nexus_sem_exchange __user *)arg,
					&exchange, sizeof(exchange))) {
				return -EFAULT;
			}
			return 0;

		case NEXUS_SEM_DELETE:
			mutex_lock(&nexus_sem_lock);
			struct nexus_sem* sem = nexus_sems[exchange.id];
			if (!sem || sem->deleted) {
				mutex_unlock(&nexus_sem_lock);
				// B_BAD_SEM_ID
				return B_ERROR;
			}

			sem->deleted = true;
			nexus_sems[exchange.id] = NULL;

			int32_t count = kref_read(&sem->ref_count);
			while(count != 1) {
				up(&sem->sem);
				count--;
			}

			kref_put(&sem->ref_count, nexus_sem_delete);
			mutex_unlock(&nexus_sem_lock);
			return 0;

		case NEXUS_SEM_ACQUIRE:
			return nexus_sem_acquire(&exchange);

		case NEXUS_SEM_RELEASE:
			return nexus_sem_release(&exchange);

		case NEXUS_SEM_COUNT:
			ret = nexus_sem_count(&exchange);
			if (ret < 0)
				return ret;

			if (copy_to_user((struct nexus_sem_exchange __user *)arg,
					&exchange, sizeof(exchange))) {
				// B_BAD_VALUE?
				return -EFAULT;
			}
			return 0;

		default:
			return B_ERROR;
	}
}

static int nexus_semaphore_open(struct inode *inode, struct file *file) {
	return 0;
}

static int nexus_semaphore_release(struct inode *inode, struct file *file) {
	return 0;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = nexus_semaphore_open,
	.release = nexus_semaphore_release,
	.unlocked_ioctl = sem_ioctl
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

static int __init nexus_semaphore_init(void) {

	int device_created = 0;

	if (alloc_chrdev_region(&major, 0, 1, DEV_NAME "_proc") < 0)
		goto error;

	nexus_class = class_create(DEV_NAME "_sys");

	if (nexus_class == NULL)
		goto error;

	if (device_create(nexus_class, NULL, major, NULL, DEV_NAME) == NULL)
		goto error;

	device_created = 1;
	cdev_init(&nexus_cdev, &fops);
	if (cdev_add(&nexus_cdev, major, 1) == -1)
		goto error;

	memset(&nexus_sems, 0, sizeof(nexus_sems));

	printk(KERN_INFO "nexus_sem module loaded\n");
	return 0;

error:
	nexus_cleanup_dev(device_created);
	return -1;
}

static void __exit nexus_semaphore_exit(void) {
	device_destroy(nexus_class, major);
	cdev_del(&nexus_cdev);

	if (nexus_class)
		class_destroy(nexus_class);
	if (major != -1)
		unregister_chrdev_region(major, 1);

	nexus_cleanup_dev(1);

	printk(KERN_INFO "nexus_sem module unloaded\n");
}

module_init(nexus_semaphore_init);
module_exit(nexus_semaphore_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dario Casalinuovo");
MODULE_DESCRIPTION("Nexus IPC Semaphore");
