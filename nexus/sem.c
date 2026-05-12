// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026 Dario Casalinuovo
 */

#include "nexus.h"

#include <linux/hrtimer.h>
#include <linux/idr.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

#include "errors.h"
#include "nexus_private.h"

static DEFINE_IDR(nexus_sem_idr);
static DEFINE_SPINLOCK(sem_idr_lock);

/* Wake all waiters with an error status (sem deleted or team exit). */
static void wake_all_waiters_error(struct nexus_sem *sem, status_t err)
{
	struct nexus_sem_waiter *w, *tmp;

	/* sem->lock must be held by caller */
	list_for_each_entry_safe(w, tmp, &sem->waiters, list) {
		w->status = err;
		w->woken = true;
		list_del_init(&w->list);
		wake_up_process(w->task);
	}
}

static void nexus_sem_put(struct nexus_sem *sem)
{
	if (atomic_dec_and_test(&sem->ref_count))
		kfree(sem);
}

static void nexus_sem_get(struct nexus_sem *sem)
{
	atomic_inc(&sem->ref_count);
}

static int nexus_create_sem(int32_t count, const char __user *uname, sem_id *out_id)
{
	struct nexus_sem *sem;
	int id;

	if (count < 0)
		return B_BAD_VALUE;

	sem = kzalloc(sizeof(*sem), GFP_KERNEL);
	if (!sem)
		return B_NO_MEMORY;

	if (strncpy_from_user(sem->name, uname, B_OS_NAME_LENGTH) < 0) {
		kfree(sem);
		return B_BAD_VALUE;
	}
	sem->name[B_OS_NAME_LENGTH - 1] = '\0';

	sem->count = count;
	sem->owner = current->tgid;
	sem->deleted = false;
	spin_lock_init(&sem->lock);
	INIT_LIST_HEAD(&sem->waiters);
	atomic_set(&sem->ref_count, 1);

	spin_lock(&sem_idr_lock);
	id = idr_alloc(&nexus_sem_idr, sem, 1, 0, GFP_ATOMIC);
	spin_unlock(&sem_idr_lock);

	if (id < 0) {
		kfree(sem);
		return B_NO_MORE_SEMS;
	}
	sem->id = id;
	*out_id = id;
	return B_OK;
}

static int nexus_delete_sem(sem_id id)
{
	struct nexus_sem *sem;
	unsigned long flags;

	spin_lock_irqsave(&sem_idr_lock, flags);
	sem = idr_find(&nexus_sem_idr, id);
	if (!sem) {
		spin_unlock_irqrestore(&sem_idr_lock, flags);
		return B_BAD_SEM_ID;
	}
	idr_remove(&nexus_sem_idr, id);
	spin_unlock_irqrestore(&sem_idr_lock, flags);

	spin_lock_irqsave(&sem->lock, flags);
	if (!sem->deleted) {
		sem->deleted = true;
		wake_all_waiters_error(sem, B_BAD_SEM_ID);
	}
	spin_unlock_irqrestore(&sem->lock, flags);

	nexus_sem_put(sem);
	return B_OK;
}

static int nexus_acquire_sem(sem_id id, int32_t count, uint32_t flags,
			     bigtime_t timeout)
{
	struct nexus_sem *sem;
	struct nexus_sem_waiter waiter;
	unsigned long iflags;
	int ret = B_OK;
	bool has_deadline = false;
	u64 deadline_ns = 0;

	if (count <= 0)
		return B_BAD_VALUE;

	spin_lock_irqsave(&sem_idr_lock, iflags);
	sem = idr_find(&nexus_sem_idr, id);
	if (!sem) {
		spin_unlock_irqrestore(&sem_idr_lock, iflags);
		return B_BAD_SEM_ID;
	}
	nexus_sem_get(sem);
	spin_unlock_irqrestore(&sem_idr_lock, iflags);

	spin_lock_irqsave(&sem->lock, iflags);

	if (sem->deleted) {
		ret = B_BAD_SEM_ID;
		goto out_unlock;
	}

	if (sem->count >= count) {
		sem->count -= count;
		sem->latest_holder = current->pid;
		spin_unlock_irqrestore(&sem->lock, iflags);
		nexus_sem_put(sem);
		return B_OK;
	}

	if ((flags & B_RELATIVE_TIMEOUT) && timeout == 0) {
		ret = B_WOULD_BLOCK;
		goto out_unlock;
	}

	if (flags & B_ABSOLUTE_TIMEOUT) {
		has_deadline = true;
		deadline_ns = (u64)timeout * 1000ULL;
		if (ktime_get_ns() >= deadline_ns) {
			ret = B_TIMED_OUT;
			goto out_unlock;
		}
	} else if ((flags & B_RELATIVE_TIMEOUT) && timeout > 0 &&
			timeout != B_INFINITE_TIMEOUT) {
		has_deadline = true;
		deadline_ns = ktime_get_ns() + (u64)timeout * 1000ULL;
	}

	/* Enqueue waiter */
	waiter.task = current;
	waiter.count = count;
	waiter.status = B_OK;
	waiter.woken = false;
	list_add_tail(&waiter.list, &sem->waiters);

	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		spin_unlock_irqrestore(&sem->lock, iflags);

		if (has_deadline) {
			ktime_t deadline = ns_to_ktime((s64)deadline_ns);
			schedule_hrtimeout_range(&deadline, 0, HRTIMER_MODE_ABS);
		} else {
			schedule();
		}

		spin_lock_irqsave(&sem->lock, iflags);

		if (waiter.woken) {
			ret = waiter.status;
			break;
		}

		if (signal_pending(current)) {
			ret = B_INTERRUPTED;
			break;
		}

		if (sem->count >= count) {
			sem->count -= count;
			sem->latest_holder = current->pid;
			ret = B_OK;
			break;
		}

		if (has_deadline && ktime_get_ns() >= deadline_ns) {
			ret = B_TIMED_OUT;
			break;
		}
	}

	set_current_state(TASK_RUNNING);
	if (!list_empty(&waiter.list))
		list_del(&waiter.list);

out_unlock:
	spin_unlock_irqrestore(&sem->lock, iflags);
	nexus_sem_put(sem);
	return ret;
}

static int nexus_release_sem(sem_id id, int32_t count, uint32_t flags)
{
	struct nexus_sem *sem;
	struct nexus_sem_waiter *w, *tmp;
	unsigned long iflags;
	int ret = B_OK;

	if (count <= 0 && (flags & B_RELEASE_ALL) == 0)
		return B_BAD_VALUE;

	spin_lock_irqsave(&sem_idr_lock, iflags);
	sem = idr_find(&nexus_sem_idr, id);
	if (!sem) {
		spin_unlock_irqrestore(&sem_idr_lock, iflags);
		return B_BAD_SEM_ID;
	}
	nexus_sem_get(sem);
	spin_unlock_irqrestore(&sem_idr_lock, iflags);

	spin_lock_irqsave(&sem->lock, iflags);

	if (sem->deleted) {
		ret = B_BAD_SEM_ID;
		goto out;
	}

	if (flags & B_RELEASE_ALL) {
		/* Wake every waiter regardless of count. Haiku passes a
		 * negative `count` as the unblock status so callers can
		 * broadcast errors (e.g. B_INTERRUPTED on teardown). */
		status_t unblock_status = (count < 0) ? count : B_OK;

		sem->count = 0;
		list_for_each_entry_safe(w, tmp, &sem->waiters, list) {
			sem->latest_holder = w->task->pid;
			w->status = unblock_status;
			w->woken = true;
			list_del_init(&w->list);
			wake_up_process(w->task);
		}
	} else {
		int32_t initial_count = sem->count;
		sem->count += count;

		/* FIFO; stop at the first waiter we can't satisfy so a
		 * large-count acquirer isn't starved by smaller ones behind it. */
		list_for_each_entry_safe(w, tmp, &sem->waiters, list) {
			if (sem->count < w->count)
				break;
			sem->count -= w->count;
			sem->latest_holder = w->task->pid;
			w->status = B_OK;
			w->woken = true;
			list_del_init(&w->list);
			wake_up_process(w->task);
		}

		/* B_RELEASE_IF_WAITING_ONLY: discard any portion of `count`
		 * that wasn't consumed by waking waiters. */
		if ((flags & B_RELEASE_IF_WAITING_ONLY) && sem->count > initial_count)
			sem->count = initial_count;
	}

out:
	spin_unlock_irqrestore(&sem->lock, iflags);
	nexus_sem_put(sem);
	return ret;
}

static int nexus_get_sem_count(sem_id id, int32_t *count)
{
	struct nexus_sem *sem;
	unsigned long flags;
	int ret = B_OK;

	spin_lock_irqsave(&sem_idr_lock, flags);
	sem = idr_find(&nexus_sem_idr, id);
	if (!sem) {
		ret = B_BAD_SEM_ID;
		goto out;
	}
	*count = sem->count;
out:
	spin_unlock_irqrestore(&sem_idr_lock, flags);
	return ret;
}

static int nexus_get_sem_info(sem_id id, struct nexus_sem_info *info)
{
	struct nexus_sem *sem;
	unsigned long flags;
	int ret = B_OK;

	spin_lock_irqsave(&sem_idr_lock, flags);
	sem = idr_find(&nexus_sem_idr, id);
	if (!sem) {
		ret = B_BAD_SEM_ID;
		goto out;
	}

	info->sem = sem->id;
	strncpy(info->name, sem->name, B_OS_NAME_LENGTH);
	info->name[B_OS_NAME_LENGTH - 1] = '\0';
	info->count = sem->count;
	info->team = sem->owner;
	info->latest_holder = sem->latest_holder;
out:
	spin_unlock_irqrestore(&sem_idr_lock, flags);
	return ret;
}

static int nexus_get_next_sem_info(team_id team, int32_t cookie,
				   struct nexus_sem_next_info *out)
{
	struct nexus_sem *sem;
	unsigned long flags;
	int id;

	spin_lock_irqsave(&sem_idr_lock, flags);
	idr_for_each_entry(&nexus_sem_idr, sem, id) {
		if (id <= cookie)
			continue;
		if (team != 0 && sem->owner != team)
			continue;

		out->info.sem = sem->id;
		strncpy(out->info.name, sem->name, B_OS_NAME_LENGTH);
		out->info.name[B_OS_NAME_LENGTH - 1] = '\0';
		out->info.count = sem->count;
		out->info.team = sem->owner;
		out->info.latest_holder = sem->latest_holder;
		out->cookie = id;
		spin_unlock_irqrestore(&sem_idr_lock, flags);
		return B_OK;
	}
	spin_unlock_irqrestore(&sem_idr_lock, flags);
	return B_BAD_SEM_ID;
}

void nexus_sem_team_exit(pid_t team)
{
	struct nexus_sem *sem;
	unsigned long flags;
	int id;

	spin_lock_irqsave(&sem_idr_lock, flags);
	idr_for_each_entry(&nexus_sem_idr, sem, id) {
		if (sem->owner != (team_id)team)
			continue;
		spin_lock(&sem->lock);
		if (!sem->deleted) {
			sem->deleted = true;
			wake_all_waiters_error(sem, B_BAD_SEM_ID);
		}
		spin_unlock(&sem->lock);
	}
	spin_unlock_irqrestore(&sem_idr_lock, flags);
}

int nexus_sem_init(void)
{
	pr_info("nexus_sem: initialized\n");
	return 0;
}

void nexus_sem_exit(void)
{
	struct nexus_sem *sem;
	int id;

	spin_lock(&sem_idr_lock);
	idr_for_each_entry(&nexus_sem_idr, sem, id) {
		spin_lock(&sem->lock);
		sem->deleted = true;
		wake_all_waiters_error(sem, B_BAD_SEM_ID);
		spin_unlock(&sem->lock);
		idr_remove(&nexus_sem_idr, id);
		kfree(sem);
	}
	idr_destroy(&nexus_sem_idr);
	spin_unlock(&sem_idr_lock);
}

/* ioctl wrappers */

static long nexus_sem_ioctl_create(unsigned long arg)
{
	struct nexus_sem_create ex;
	sem_id id;
	long ret;

	if (copy_from_user(&ex, (void __user *)arg, sizeof(ex)))
		return B_BAD_VALUE;

	ret = nexus_create_sem(ex.count, ex.name, &id);
	if (ret != B_OK)
		return ret;

	ex.id = id;
	if (copy_to_user((void __user *)arg, &ex, sizeof(ex)))
		return B_BAD_VALUE;

	return B_OK;
}

static long nexus_sem_ioctl_delete(unsigned long arg)
{
	struct nexus_sem_delete_req ex;

	if (copy_from_user(&ex, (void __user *)arg, sizeof(ex)))
		return B_BAD_VALUE;

	return nexus_delete_sem(ex.id);
}

static long nexus_sem_ioctl_acquire(unsigned long arg)
{
	struct nexus_sem_op ex;

	if (copy_from_user(&ex, (void __user *)arg, sizeof(ex)))
		return B_BAD_VALUE;

	return nexus_acquire_sem(ex.id, ex.count, ex.flags, ex.timeout);
}

static long nexus_sem_ioctl_release(unsigned long arg)
{
	struct nexus_sem_op ex;

	if (copy_from_user(&ex, (void __user *)arg, sizeof(ex)))
		return B_BAD_VALUE;

	return nexus_release_sem(ex.id, ex.count, ex.flags);
}

static long nexus_sem_ioctl_count(unsigned long arg)
{
	struct nexus_sem_count_req ex;
	long ret;

	if (copy_from_user(&ex, (void __user *)arg, sizeof(ex)))
		return B_BAD_VALUE;

	ret = nexus_get_sem_count(ex.id, &ex.count);
	if (ret != B_OK)
		return ret;

	if (copy_to_user((void __user *)arg, &ex, sizeof(ex)))
		return B_BAD_VALUE;

	return B_OK;
}

static long nexus_sem_ioctl_info(unsigned long arg)
{
	struct nexus_sem_info_req ex;
	long ret;

	if (copy_from_user(&ex, (void __user *)arg, sizeof(ex)))
		return B_BAD_VALUE;

	ret = nexus_get_sem_info(ex.id, &ex.info);
	if (ret != B_OK)
		return ret;

	if (copy_to_user((void __user *)arg, &ex, sizeof(ex)))
		return B_BAD_VALUE;

	return B_OK;
}

static long nexus_sem_ioctl_next_info(unsigned long arg)
{
	struct nexus_sem_next_info ex;
	long ret;

	if (copy_from_user(&ex, (void __user *)arg, sizeof(ex)))
		return B_BAD_VALUE;

	ret = nexus_get_next_sem_info(ex.team, ex.cookie, &ex);
	if (ret != B_OK)
		return ret;

	if (copy_to_user((void __user *)arg, &ex, sizeof(ex)))
		return B_BAD_VALUE;

	return B_OK;
}

long nexus_sem_ioctl(unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case NEXUS_SEM_CREATE:
		return nexus_sem_ioctl_create(arg);
	case NEXUS_SEM_DELETE:
		return nexus_sem_ioctl_delete(arg);
	case NEXUS_SEM_ACQUIRE:
		return nexus_sem_ioctl_acquire(arg);
	case NEXUS_SEM_RELEASE:
		return nexus_sem_ioctl_release(arg);
	case NEXUS_SEM_COUNT:
		return nexus_sem_ioctl_count(arg);
	case NEXUS_SEM_INFO:
		return nexus_sem_ioctl_info(arg);
	case NEXUS_SEM_NEXT_INFO:
		return nexus_sem_ioctl_next_info(arg);
	default:
		return -ENOTTY;
	}
}
