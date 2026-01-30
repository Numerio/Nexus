// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026 Dario Casalinuovo
 */

#include <linux/cdev.h>
#include <linux/idr.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>

#include "errors.h"
#include "nexus.h"
#include "nexus_private.h"
#include "util.h"

#define DEVICE_NAME "nexus_sem"
#define CLASS_NAME  "nexus"

#define TEAM_HASH_BITS 8

static dev_t dev_num;
static struct cdev nexus_cdev;
static struct class *nexus_class;
static struct device *nexus_device;

static DEFINE_IDR(sem_idr);
static DEFINE_SPINLOCK(sem_idr_lock);
static DEFINE_HASHTABLE(team_hash, TEAM_HASH_BITS);
static DEFINE_SPINLOCK(team_hash_lock);

static struct nexus_sem *sem_get(sem_id id)
{
	struct nexus_sem *sem;
	unsigned long flags;

	spin_lock_irqsave(&sem_idr_lock, flags);
	sem = idr_find(&sem_idr, id);
	// TODO maybe use kref_get/kref_put
	if (sem && !sem->deleted)
		atomic_inc(&sem->ref_count);
	else
		sem = NULL;
	spin_unlock_irqrestore(&sem_idr_lock, flags);

	return sem;
}

static void sem_put(struct nexus_sem *sem)
{
	if (atomic_dec_and_test(&sem->ref_count))
		kfree(sem);
}

static struct team_sem_list *get_or_create_team_list(team_id team)
{
	struct team_sem_list *list;
	unsigned long flags;

	spin_lock_irqsave(&team_hash_lock, flags);
	hash_for_each_possible(team_hash, list, hash_node, team) {
		if (list->team == team) {
			spin_unlock_irqrestore(&team_hash_lock, flags);
			return list;
		}
	}
	spin_unlock_irqrestore(&team_hash_lock, flags);

	list = kzalloc(sizeof(*list), GFP_KERNEL);
	if (!list)
		return NULL;

	list->team = team;
	INIT_HLIST_HEAD(&list->sems);
	spin_lock_init(&list->lock);

	spin_lock_irqsave(&team_hash_lock, flags);
	hash_add(team_hash, &list->hash_node, team);
	spin_unlock_irqrestore(&team_hash_lock, flags);

	return list;
}

static status_t nexus_create_sem(int32_t count, const char __user *name, sem_id *out_id)
{
	struct nexus_sem *sem;
	struct team_sem_list *team_list;
	int id;
	unsigned long flags;
	team_id owner;

	if (count < 0)
		return B_BAD_VALUE;

	sem = kzalloc(sizeof(*sem), GFP_KERNEL);
	if (!sem)
		return B_NO_MORE_SEMS;

	owner = task_tgid_nr(current);

	spin_lock_init(&sem->lock);
	INIT_LIST_HEAD(&sem->waiters);
	INIT_HLIST_NODE(&sem->team_node);
	sem->count = count;
	sem->owner = owner;
	sem->latest_holder = 0;
	sem->deleted = false;
	atomic_set(&sem->ref_count, 1);

	if (name) {
		if (strncpy_from_user(sem->name, name, B_OS_NAME_LENGTH - 1) < 0)
			return B_BAD_VALUE;
		sem->name[B_OS_NAME_LENGTH - 1] = '\0';
	} else {
		strcpy(sem->name, "Anonymous Sem");
	}

	spin_lock_irqsave(&sem_idr_lock, flags);
	id = idr_alloc(&sem_idr, sem, 1, MAX_SEMS, GFP_ATOMIC);
	spin_unlock_irqrestore(&sem_idr_lock, flags);

	if (id < 0) {
		kfree(sem);
		return B_NO_MORE_SEMS;
	}

	sem->id = id;

	team_list = get_or_create_team_list(owner);
	if (team_list) {
		spin_lock_irqsave(&team_list->lock, flags);
		hlist_add_head(&sem->team_node, &team_list->sems);
		spin_unlock_irqrestore(&team_list->lock, flags);
	}

	*out_id = id;
	return B_OK;
}

static void wake_waiters(struct nexus_sem *sem)
{
	struct nexus_sem_waiter *waiter, *tmp;

	list_for_each_entry_safe(waiter, tmp, &sem->waiters, list) {
		waiter->status = B_OK;
		waiter->woken = true;
		list_del(&waiter->list);
		wake_up_process(waiter->task);

		if (sem->count < 0)
			break;
	}
}

static void wake_all_waiters_error(struct nexus_sem *sem, status_t error)
{
	struct nexus_sem_waiter *waiter, *tmp;

	list_for_each_entry_safe(waiter, tmp, &sem->waiters, list) {
		waiter->status = error;
		waiter->woken = true;
		list_del(&waiter->list);
		wake_up_process(waiter->task);
	}
}

static struct team_sem_list *get_team_list(team_id team)
{
	struct team_sem_list *list;
	unsigned long flags;

	spin_lock_irqsave(&team_hash_lock, flags);
	hash_for_each_possible(team_hash, list, hash_node, team) {
		if (list->team == team) {
			spin_unlock_irqrestore(&team_hash_lock, flags);
			return list;
		}
	}
	spin_unlock_irqrestore(&team_hash_lock, flags);

	return NULL;
}

static status_t nexus_delete_sem(sem_id id)
{
	struct nexus_sem *sem;
	struct team_sem_list *team_list;
	unsigned long flags;

	spin_lock_irqsave(&sem_idr_lock, flags);
	sem = idr_find(&sem_idr, id);
	if (!sem || sem->deleted) {
		spin_unlock_irqrestore(&sem_idr_lock, flags);
		return B_BAD_SEM_ID;
	}

	idr_remove(&sem_idr, id);
	spin_unlock_irqrestore(&sem_idr_lock, flags);

	spin_lock_irqsave(&sem->lock, flags);
	sem->deleted = true;

	wake_all_waiters_error(sem, B_BAD_SEM_ID);
	spin_unlock_irqrestore(&sem->lock, flags);

	team_list = get_team_list(sem->owner);
	if (team_list) {
		spin_lock_irqsave(&team_list->lock, flags);
		hlist_del(&sem->team_node);
		spin_unlock_irqrestore(&team_list->lock, flags);
	}

	sem_put(sem);

	return B_OK;
}

static status_t nexus_acquire_sem(sem_id id, int32_t count, uint32_t flags, bigtime_t timeout)
{
	struct nexus_sem *sem;
	struct nexus_sem_waiter waiter;
	unsigned long irq_flags;
	long jiffies_timeout;
	status_t result = B_OK;
	bool need_wait;

	if (count < 1)
		return B_BAD_VALUE;

	sem = sem_get(id);
	if (!sem)
		return B_BAD_SEM_ID;

	spin_lock_irqsave(&sem->lock, irq_flags);

	if (sem->deleted) {
		spin_unlock_irqrestore(&sem->lock, irq_flags);
		sem_put(sem);
		return B_BAD_SEM_ID;
	}

	if (sem->count >= count && list_empty(&sem->waiters)) {
		sem->count -= count;
		sem->latest_holder = task_pid_nr(current);
		spin_unlock_irqrestore(&sem->lock, irq_flags);
		sem_put(sem);
		return B_OK;
	}

	jiffies_timeout = calculate_timeout(timeout, flags);
	if (jiffies_timeout == 0) {
		spin_unlock_irqrestore(&sem->lock, irq_flags);
		sem_put(sem);
		return B_WOULD_BLOCK;
	}

	waiter.task = current;
	waiter.count = count;
	waiter.status = B_TIMED_OUT;
	waiter.woken = false;

	list_add_tail(&waiter.list, &sem->waiters);

	sem->count -= count;

	do {
		set_current_state(TASK_INTERRUPTIBLE);
		spin_unlock_irqrestore(&sem->lock, irq_flags);

		if (jiffies_timeout == MAX_SCHEDULE_TIMEOUT)
			schedule();
		else {
			// TODO use hrtimeout
			jiffies_timeout = schedule_timeout(jiffies_timeout);
		}

		spin_lock_irqsave(&sem->lock, irq_flags);

		if (waiter.woken) {
			result = waiter.status;
			break;
		}

		if ((flags & B_CAN_INTERRUPT) && signal_pending(current)) {
			list_del(&waiter.list);
			sem->count += count;
			result = B_INTERRUPTED;
			break;
		}

		if (jiffies_timeout == 0 && !waiter.woken) {
			list_del(&waiter.list);
			sem->count += count;
			result = B_TIMED_OUT;
			break;
		}

		need_wait = !waiter.woken && (jiffies_timeout > 0 || jiffies_timeout == MAX_SCHEDULE_TIMEOUT);

	} while (need_wait);
	
	if (result == B_OK)
		sem->latest_holder = task_pid_nr(current);

	spin_unlock_irqrestore(&sem->lock, irq_flags);
	set_current_state(TASK_RUNNING);
	sem_put(sem);

	return result;
}

static status_t nexus_release_sem(sem_id id, int32_t count, uint32_t flags)
{
	struct nexus_sem *sem;
	unsigned long irq_flags;

	if (count < 1)
		return B_BAD_VALUE;

	sem = sem_get(id);
	if (!sem)
		return B_BAD_SEM_ID;

	spin_lock_irqsave(&sem->lock, irq_flags);

	if (sem->deleted) {
		spin_unlock_irqrestore(&sem->lock, irq_flags);
		sem_put(sem);
		return B_BAD_SEM_ID;
	}

	sem->count += count;

	// wake order is FIFO
	wake_waiters(sem);

	spin_unlock_irqrestore(&sem->lock, irq_flags);

	if (!(flags & B_DO_NOT_RESCHEDULE))
		cond_resched();

	sem_put(sem);
	return B_OK;
}

static status_t nexus_get_sem_count(sem_id id, int32_t *out_count)
{
	struct nexus_sem *sem;
	unsigned long flags;

	sem = sem_get(id);
	if (!sem)
		return B_BAD_SEM_ID;

	spin_lock_irqsave(&sem->lock, flags);
	*out_count = sem->count;
	spin_unlock_irqrestore(&sem->lock, flags);

	sem_put(sem);
	return B_OK;
}

static status_t nexus_get_sem_info(sem_id id, struct nexus_sem_info *info)
{
	struct nexus_sem *sem;
	unsigned long flags;

	sem = sem_get(id);
	if (!sem)
		return B_BAD_SEM_ID;

	spin_lock_irqsave(&sem->lock, flags);
	info->sem = sem->id;
	info->team = sem->owner;
	info->count = sem->count;
	strncpy(info->name, sem->name, B_OS_NAME_LENGTH);
	info->name[B_OS_NAME_LENGTH - 1] = '\0';
	info->latest_holder = sem->latest_holder;
	spin_unlock_irqrestore(&sem->lock, flags);

	sem_put(sem);
	return B_OK;
}

static status_t nexus_get_next_sem_info(team_id team, int32_t *cookie, 
	struct nexus_sem_info *info)
{
	struct team_sem_list *team_list;
	struct nexus_sem *sem = NULL;
	unsigned long flags;
	int count = 0;
	pid_t target_team;

	if (team == 0) {
		target_team = task_tgid_nr(current);
	} else if (team < 0) {
		return B_BAD_TEAM_ID;
	} else {
		target_team = team;
		struct pid *pid_struct = find_get_pid(target_team);
		if (!pid_struct)
			return B_BAD_TEAM_ID;
		put_pid(pid_struct);
	}

	team_list = get_team_list(target_team);
	if (!team_list)
		return B_BAD_VALUE;

	spin_lock_irqsave(&team_list->lock, flags);

	hlist_for_each_entry(sem, &team_list->sems, team_node) {
		if (count == *cookie) {
			info->sem = sem->id;
			info->team = sem->owner;
			strncpy(info->name, sem->name, B_OS_NAME_LENGTH);
			info->name[B_OS_NAME_LENGTH - 1] = '\0';

			spin_lock(&sem->lock);
			info->count = sem->count;
			info->latest_holder = sem->latest_holder;
			spin_unlock(&sem->lock);

			(*cookie)++;
			spin_unlock_irqrestore(&team_list->lock, flags);
			return B_OK;
		}
		count++;
	}

	spin_unlock_irqrestore(&team_list->lock, flags);
	return B_BAD_VALUE;
}

static long nexus_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	// TODO we should expect reinit on fork otherwise kill the team?
	struct nexus_sem_exchange ex;
	struct nexus_sem_info info;
	struct nexus_sem_next_info next_info;
	status_t result;

	switch (cmd) {
	case NEXUS_SEM_CREATE:
		if (copy_from_user(&ex, (void __user *)arg, sizeof(ex)))
			return -EFAULT;
		result = nexus_create_sem(ex.count, ex.name, &ex.id);
		if (result == B_OK) {
			if (copy_to_user((void __user *)arg, &ex, sizeof(ex)))
				return -EFAULT;
		}
		return ex.id;

	case NEXUS_SEM_DELETE:
		if (copy_from_user(&ex, (void __user *)arg, sizeof(ex)))
			return -EFAULT;
		return nexus_delete_sem(ex.id);

	case NEXUS_SEM_ACQUIRE:
		if (copy_from_user(&ex, (void __user *)arg, sizeof(ex)))
			return -EFAULT;
		return nexus_acquire_sem(ex.id, ex.count, ex.flags, ex.timeout);

	case NEXUS_SEM_RELEASE:
		if (copy_from_user(&ex, (void __user *)arg, sizeof(ex)))
			return -EFAULT;
		return nexus_release_sem(ex.id, ex.count, ex.flags);

	case NEXUS_SEM_COUNT:
		if (copy_from_user(&ex, (void __user *)arg, sizeof(ex)))
			return -EFAULT;
		result = nexus_get_sem_count(ex.id, &ex.count);
		if (result == B_OK) {
			if (copy_to_user((void __user *)arg, &ex, sizeof(ex)))
				return -EFAULT;
		}
		return result;

	case NEXUS_SEM_INFO:
		if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
			return -EFAULT;
		result = nexus_get_sem_info(info.sem, &info);
		if (result == B_OK) {
			if (copy_to_user((void __user *)arg, &info, sizeof(info)))
				return -EFAULT;
		}
		return result;

	case NEXUS_SEM_NEXT_INFO:
		if (copy_from_user(&next_info, (void __user *)arg, sizeof(next_info)))
			return -EFAULT;
		result = nexus_get_next_sem_info(next_info.team, &next_info.cookie, 
									   &next_info.info);
		if (result == B_OK) {
			if (copy_to_user((void __user *)arg, &next_info, sizeof(next_info)))
				return -EFAULT;
		}
		return result;

	default:
		return -ENOTTY;
	}
}

static int nexus_sem_open(struct inode *inode, struct file *file)
{
	// TODO
	return 0;
}

static int nexus_sem_release(struct inode *inode, struct file *file)
{
	// TODO
	return 0;
}

static const struct file_operations nexus_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = nexus_ioctl,
	.compat_ioctl   = nexus_ioctl,
	.open           = nexus_sem_open,
	.release        = nexus_sem_release,
};

static int __init nexus_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
	if (ret < 0) {
		pr_err("nexus: Failed to allocate device number\n");
		return ret;
	}

	nexus_class = class_create(CLASS_NAME);
	if (IS_ERR(nexus_class)) {
		pr_err("nexus: Failed to create device class\n");
		unregister_chrdev_region(dev_num, 1);
		return PTR_ERR(nexus_class);
	}

	nexus_device = device_create(nexus_class, NULL, dev_num, NULL, DEVICE_NAME);
	if (IS_ERR(nexus_device)) {
		pr_err("nexus: Failed to create device\n");
		class_destroy(nexus_class);
		unregister_chrdev_region(dev_num, 1);
		return PTR_ERR(nexus_device);
	}

	cdev_init(&nexus_cdev, &nexus_fops);
	nexus_cdev.owner = THIS_MODULE;
	ret = cdev_add(&nexus_cdev, dev_num, 1);
	if (ret < 0) {
		pr_err("nexus: Failed to add cdev\n");
		device_destroy(nexus_class, dev_num);
		class_destroy(nexus_class);
		unregister_chrdev_region(dev_num, 1);
		return ret;
	}

	pr_info("nexus_sem: module loaded (major=%d)\n", MAJOR(dev_num));
	return 0;
}

static void __exit nexus_exit(void)
{
	struct nexus_sem *sem;
	int id;
	unsigned long flags;

	spin_lock_irqsave(&sem_idr_lock, flags);
	idr_for_each_entry(&sem_idr, sem, id) {
		sem->deleted = true;
		spin_lock(&sem->lock);
		wake_all_waiters_error(sem, B_BAD_SEM_ID);
		spin_unlock(&sem->lock);
	}
	spin_unlock_irqrestore(&sem_idr_lock, flags);

	idr_destroy(&sem_idr);

	cdev_del(&nexus_cdev);
	device_destroy(nexus_class, dev_num);
	class_destroy(nexus_class);
	unregister_chrdev_region(dev_num, 1);

	pr_info("nexus_sem: module unloaded\n");
}

module_init(nexus_init);
module_exit(nexus_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dario Casalinuovo");
MODULE_DESCRIPTION("Nexus semaphore.");
MODULE_VERSION("1.0");
