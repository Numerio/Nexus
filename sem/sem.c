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

	// TODO B_NO_MORE_SEMS
	if (exchange->count < 0)
		return B_BAD_VALUE;

	struct nexus_sem* sem
		= kzalloc(sizeof(struct nexus_port), GFP_KERNEL);

	if (sem == NULL)
		return -ENOMEM;

	mutex_lock(&nexus_sem_lock);
	last_sem_id++;

	printk(KERN_INFO "create sem id %d\n", last_sem_id);

	nexus_sems[last_sem_id] = sem;

	init_waitqueue_head(&sem->wait_queue);
	atomic_set(&sem->count, exchange->count);

	kref_init(&sem->ref_count);
	kref_get(&sem->ref_count);

	sem->id = last_sem_id;
	sem->team = get_task_struct(current);
	sem->deleted = false;

	exchange->id = last_sem_id;
	mutex_unlock(&nexus_sem_lock);

	return 0;
}

long nexus_sem_acquire(struct nexus_sem_exchange *exchange) {

	mutex_lock(&nexus_sem_lock);
	struct nexus_sem* sem = nexus_sems[exchange->id];
	if (exchange->id < 0 || sem == NULL || exchange->count < 1) {
		mutex_unlock(&nexus_sem_lock);
		return B_BAD_VALUE;
	}

	if (sem->deleted) {
		mutex_unlock(&nexus_sem_lock);
		return B_BAD_SEM_ID;
	}

	if ((exchange->flags & (B_ABSOLUTE_TIMEOUT | B_RELATIVE_TIMEOUT))
			== (B_ABSOLUTE_TIMEOUT | B_RELATIVE_TIMEOUT)) {
		mutex_unlock(&nexus_sem_lock);
		return B_BAD_VALUE;
	}

	printk(KERN_INFO "acquire sem idd %d\n", exchange->id);

	kref_get(&sem->ref_count);

	uint32_t flags = exchange->flags;
	int64_t timeout = exchange->timeout;
	uint64_t count = exchange->count;

	int ret = B_ERROR;

	int current_count = atomic_read(&sem->count);
	if (current_count - exchange->count < 0) {
		if ((flags & B_RELATIVE_TIMEOUT) != 0 && timeout <= 0) {
			printk(KERN_INFO "would block 1");
			ret = B_WOULD_BLOCK;
			goto exit;
		} else if ((flags & B_ABSOLUTE_TIMEOUT) != 0 && timeout < 0) {
			printk(KERN_INFO "timeout 1");
			ret = B_TIMED_OUT;
			goto exit;
		}
	}

	if (timeout > 0 && flags & B_ABSOLUTE_TIMEOUT) {
		ktime_t now = ktime_get();
		timeout -= ktime_to_us(now);
		if (timeout <= 0) {
			printk(KERN_INFO "absoluted timeout");
			ret = B_TIMED_OUT;
			goto exit;
		}
	}

	current_count = atomic_sub_return(count, &sem->count);
	if (current_count >= 0)	{
		printk(KERN_INFO "current count %d", current_count);
		ret = B_OK;
		goto exit;
	}

	mutex_unlock(&nexus_sem_lock);
	printk(KERN_INFO "going to wait");
	// TODO B_DO_NOT_RESCHEDULE
	if (timeout >= 0 && exchange->timeout != B_INFINITE_TIMEOUT) {
		ret = wait_event_interruptible_hrtimeout(sem->wait_queue,
			atomic_read(&sem->count) >= 0
				|| sem->deleted,
			ns_to_ktime(timeout*1000));

		if (ret == -ETIME) {
			if (timeout == 0)
				ret = B_WOULD_BLOCK;
			else
				ret = B_TIMED_OUT;
		}

	} else {
		ret = wait_event_interruptible(sem->wait_queue,
			atomic_read(&sem->count) >= 0
				|| sem->deleted);
	}
	mutex_lock(&nexus_sem_lock);

	if (sem->deleted)
		ret = B_BAD_SEM_ID;
	else if (ret == -ERESTARTSYS) {
		current_count = atomic_add_return(count, &sem->count);
		ret = B_INTERRUPTED;
	}

exit:
	kref_put(&sem->ref_count, nexus_sem_delete);
	mutex_unlock(&nexus_sem_lock);

	printk(KERN_INFO "acquire sem id %d exit\n", exchange->id);

	return ret;
}

long nexus_sem_release(struct nexus_sem_exchange *exchange) {
	printk(KERN_INFO "release sem id %d\n", exchange->id);

	mutex_lock(&nexus_sem_lock);
	struct nexus_sem* sem = nexus_sems[exchange->id];
	if (exchange->id < 0 || !sem || exchange->count < 0) {
		mutex_unlock(&nexus_sem_lock);
		return B_BAD_VALUE;
	}

	if (sem->deleted) {
		mutex_unlock(&nexus_sem_lock);
		return B_BAD_SEM_ID;
	}

	atomic_add_return(exchange->count, &sem->count);
	wake_up_all(&sem->wait_queue);
	mutex_unlock(&nexus_sem_lock);
	return 0;
}

void nexus_sem_delete(struct kref* ref) {
	struct nexus_sem* sem = container_of(ref, struct nexus_sem, ref_count);

	printk(KERN_INFO "delete sem id %d\n", sem->id);

	nexus_sems[sem->id] = NULL;
	put_task_struct(sem->team);
	kfree(sem);
}

long nexus_sem_count(struct nexus_sem_exchange *exchange) {
	mutex_lock(&nexus_sem_lock);
	if (exchange->id < 0 || !nexus_sems[exchange->id])
		return B_BAD_VALUE;

	exchange->count = atomic_read(&nexus_sems[exchange->id]->count);
	printk(KERN_INFO "count sem id %d %d\n", exchange->id, exchange->count);

	mutex_unlock(&nexus_sem_lock);
	return 0;
}

static long nexus_semaphore_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
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
				return B_BAD_SEM_ID;
			}

			//sem->status = NEXUS_SEM_DELETED;
			sem->deleted = true;
			nexus_sems[exchange.id] = NULL;

			wake_up(&sem->wait_queue);

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
	.unlocked_ioctl = nexus_semaphore_ioctl
};

static void nexus_semaphore_cleanup_dev(int device_created)
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
	nexus_semaphore_cleanup_dev(device_created);
	return -1;
}

static void __exit nexus_semaphore_exit(void) {
	device_destroy(nexus_class, major);
	cdev_del(&nexus_cdev);

	if (nexus_class)
		class_destroy(nexus_class);
	if (major != -1)
		unregister_chrdev_region(major, 1);

	nexus_semaphore_cleanup_dev(1);

	printk(KERN_INFO "nexus_sem module unloaded\n");
}

module_init(nexus_semaphore_init);
module_exit(nexus_semaphore_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dario Casalinuovo");
MODULE_DESCRIPTION("Nexus IPC Semaphore");
