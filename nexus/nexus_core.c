// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026 Dario Casalinuovo
 */

#include "nexus.h"
#include "vref.h"

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/signal.h>
#include <linux/task_work.h>
#include <linux/tracepoint.h>
#include <linux/hashtable.h>
#include <linux/wait.h>

#include "errors.h"
#include "nexus_private.h"

#define DEV_NAME "nexus"

static dev_t major = 0;

uint64_t nexus_core_dev(void)
{
	return (uint64_t)new_encode_dev(major);
}
EXPORT_SYMBOL(nexus_core_dev);
static struct cdev nexus_cdev;
static struct class *nexus_class = NULL;

DEFINE_MUTEX(nexus_main_lock);
HLIST_HEAD(nexus_teams);
EXPORT_SYMBOL(nexus_teams);

DEFINE_IDR(nexus_port_idr);
static DEFINE_IDR(nexus_teams_idr);

/* Global tid -> struct nexus_thread index of every registered record.
 * WAITFOR and GET_GENERATION resolve through it: a tid is either registered
 * (known, resolvable) or unknown -- there is no third state to guess about.
 * Occupancy rule: a tid maps to its OLDEST still-retained record; a later
 * nexus_thread_init() for an already-mapped tid (e.g. a fork child opening
 * its own team while the creator-registered record lives in the parent's
 * team) stays unindexed and is reachable through its team only. */
static DEFINE_IDR(nexus_threads_idr);

/* Global incarnation counter for generation stamps. */
static atomic64_t nexus_thread_generation_ctr = ATOMIC64_INIT(0);

/* Always in [1, 2^31-1]: never 0 (0 would read as "no record"), never
 * negative (a signed-int consumer checking "< 0" must only ever see real
 * errors there). Wraps after 2^31 incarnations, which only aliases two
 * incarnations 2^31 apart -- the recycling window itself is far shorter. */
static int32_t nexus_thread_next_generation(void)
{
	int64_t gen = atomic64_inc_return(&nexus_thread_generation_ctr)
		& 0x7fffffff;
	return (gen == 0) ? 1 : (int32_t)gen;
}

/* All callers hold nexus_main_lock: registration, retirement and lookup are
 * serialized against each other, so the indexed pointer is always the live
 * record for the tid while the lock is held. */
static struct nexus_thread* nexus_thread_lookup(int32_t tid)
{
	return idr_find(&nexus_threads_idr, tid);
}

/* The index entry holds a reference: nexus_thread_retire() drops it along
 * with the tree's. Without it, retire over-put and freed a record whose exit
 * hook was still pending (refcount underflow in nexus_thread_exit_work). */
static int nexus_thread_index(struct nexus_thread *thread)
{
	int ret = idr_alloc(&nexus_threads_idr, thread,
		thread->id, thread->id + 1, GFP_KERNEL);
	if (ret >= 0) {
		kref_get(&thread->ref_count);
		return 0;
	}
	if (idr_find(&nexus_threads_idr, thread->id) != NULL) {
		/* Slot occupied by an older retained record for the same tid
		 * (see occupancy rule above): keep the older one indexed. */
		return 0;
	}
	return ret;
}

/* Drop a record's index entry. Called ONLY at retirement sites (where the
 * record leaves its team's rbtree, or the team itself dies), never from
 * nexus_thread_destroy: retirement is serialized under nexus_main_lock, so
 * an erased entry can never belong to a newer record for the same tid.
 * Returns true if this record was the indexed one. */
static bool nexus_thread_unindex(struct nexus_thread *thread)
{
	if (idr_find(&nexus_threads_idr, thread->id) != thread)
		return false;
	idr_remove(&nexus_threads_idr, thread->id);
	return true;
}

/* Retire a record leaving its team (recycle or team teardown): drop the
 * index entry plus the tree-membership and index references. Safe for
 * never-indexed records (e.g. a fork child's own-team main record whose tid
 * slot is held by the creator-registered record). */
static void nexus_thread_retire(struct nexus_thread *thread)
{
	bool indexed = nexus_thread_unindex(thread);
	kref_put(&thread->ref_count, nexus_thread_destroy);
	if (indexed)
		kref_put(&thread->ref_count, nexus_thread_destroy);
}

struct nexus_team* nexus_find_team(int32_t id)
{
	return idr_find(&nexus_teams_idr, id);
}

// TODO make non-exported functions static
// TODO fine-grained locking through spinlocks
// TODO per-team lock


static void nexus_thread_exit_work(struct callback_head *head)
{
	struct nexus_thread *thread = container_of(head, struct nexus_thread, exit_work);
	struct nexus_team *orphan_team = NULL;

	mutex_lock(&nexus_main_lock);

	if (!thread->has_thread_exited) {
		if (!thread->has_return_code) {
			int sig = current->exit_code & 0x7f;
			switch (sig) {
			case 0:
				thread->exit_status = B_OK;
				break;
			case SIGSEGV:
			case SIGBUS:
			case SIGILL:
			case SIGFPE:
				thread->exit_status = B_BAD_ADDRESS;
				break;
			case SIGABRT:
				thread->exit_status = B_ERROR;
				break;
			default:
				thread->exit_status = B_INTERRUPTED;
				break;
			}
		}
		thread->has_thread_exited = true;
	}

	wake_up_all(&thread->thread_exit);
	wake_up_all(&thread->thread_suspended);
	wake_up_all(&thread->thread_has_newborn);
	wake_up_all(&thread->buffer_read);

	if (thread->team != NULL && thread->team->main_thread == thread
			&& thread->team->open_count == 0) {
		orphan_team = thread->team;
		pr_warn_ratelimited("nexus: team=%d destroyed before its first open()\n",
			orphan_team->id);
	}

	kref_put(&thread->ref_count, nexus_thread_destroy);

	if (orphan_team != NULL)
		nexus_team_destroy(orphan_team);

	mutex_unlock(&nexus_main_lock);
}

/* Exit detection. The record is parked in a pid-keyed table (holding a
 * ref) and the sched_process_exit probe, which runs in do_exit() before
 * exit_task_work(), hands it to task_work there. nexus_thread_exit_work()
 * therefore only ever runs at real exit, in sleepable context, with the
 * real exit_code. Queuing the task_work directly at arm time is wrong:
 * TWA_NONE work also runs on the task's next return to user mode (rseq sets
 * TIF_NOTIFY_RESUME on every reschedule) and marked live threads exited --
 * wait_for_thread() returning at once with status 0 (Nexus #12). */
static DEFINE_HASHTABLE(nexus_exit_hash, 8);
static DEFINE_SPINLOCK(nexus_exit_lock);
static struct tracepoint *nexus_exit_tp;

/* Only the task argument is used; kernels that also pass group_dead call
 * this with an extra argument, which the calling convention ignores. */
static void nexus_exit_probe(void *data, struct task_struct *task)
{
	struct nexus_thread *thread;
	struct hlist_node *tmp;
	pid_t pid = task->pid;

	/* Pairs with the barrier in nexus_thread_arm_exit_hook(): PF_EXITING
	 * is set before this runs. */
	smp_mb();
	if (hlist_empty(&nexus_exit_hash[hash_min(pid, HASH_BITS(nexus_exit_hash))]))
		return;

	spin_lock(&nexus_exit_lock);
	hash_for_each_possible_safe(nexus_exit_hash, thread, tmp, exit_node, pid) {
		if (thread->exit_pid != pid)
			continue;
		hash_del(&thread->exit_node);
		WARN_ON_ONCE(task_work_add(task, &thread->exit_work, TWA_NONE));
	}
	spin_unlock(&nexus_exit_lock);
}

static void nexus_find_exit_tp(struct tracepoint *tp, void *priv)
{
	if (strcmp(tp->name, "sched_process_exit") == 0)
		*(struct tracepoint **)priv = tp;
}

/* Arm exit detection for a thread on the given task. Idempotent via
 * exit_hook_installed. Returns false if the task is already exiting and
 * the probe may have been missed -- the caller must then finish the record
 * itself (see nexus_thread_arm_exit_or_finish) so waiters can never hang. */
static bool nexus_thread_arm_exit_hook(struct nexus_thread *thread,
	struct task_struct *task)
{
	bool reclaimed = false;

	if (thread->exit_hook_installed)
		return true;
	if (READ_ONCE(task->flags) & PF_EXITING)
		return false;

	thread->exit_hook_installed = true;
	thread->exit_pid = task->pid;
	kref_get(&thread->ref_count);
	init_task_work(&thread->exit_work, nexus_thread_exit_work);

	spin_lock(&nexus_exit_lock);
	hash_add(nexus_exit_hash, &thread->exit_node, thread->exit_pid);
	spin_unlock(&nexus_exit_lock);

	/* If the task started exiting meanwhile the probe may already have
	 * run; whoever unhashes the record owns it. */
	smp_mb();
	if (!(READ_ONCE(task->flags) & PF_EXITING))
		return true;

	spin_lock(&nexus_exit_lock);
	if (hash_hashed(&thread->exit_node)) {
		hash_del(&thread->exit_node);
		reclaimed = true;
	}
	spin_unlock(&nexus_exit_lock);

	if (!reclaimed)
		return true;

	thread->exit_hook_installed = false;
	kref_put(&thread->ref_count, nexus_thread_destroy);
	return false;
}

/* Arm the exit hook; if the task is already exiting, finish the record right
 * away with a synthesized status instead. A thread that died before the hook
 * could be armed then still resolves cleanly through WAITFOR (immediate
 * B_ERROR, not a hang and not B_BAD_THREAD_ID). Caller holds nexus_main_lock. */
static void nexus_thread_arm_exit_or_finish(struct nexus_thread *thread,
	struct task_struct *task)
{
	if (nexus_thread_arm_exit_hook(thread, task))
		return;

	if (!thread->has_thread_exited) {
		if (!thread->has_return_code)
			thread->exit_status = B_ERROR;
		thread->has_thread_exited = true;
		wake_up_all(&thread->thread_exit);
		wake_up_all(&thread->thread_suspended);
		wake_up_all(&thread->thread_has_newborn);
		wake_up_all(&thread->buffer_read);
	}
}

/* Team-exit callback list */
#define NEXUS_MAX_TEAM_EXIT_CBS 8

static nexus_team_notify_fn team_exit_callbacks[NEXUS_MAX_TEAM_EXIT_CBS];
static int team_exit_cb_count = 0;
static DEFINE_SPINLOCK(team_exit_cb_lock);

int nexus_register_team_exit(nexus_team_notify_fn fn)
{
	unsigned long flags;
	spin_lock_irqsave(&team_exit_cb_lock, flags);
	if (team_exit_cb_count >= NEXUS_MAX_TEAM_EXIT_CBS) {
		spin_unlock_irqrestore(&team_exit_cb_lock, flags);
		return -ENOMEM;
	}
	team_exit_callbacks[team_exit_cb_count++] = fn;
	spin_unlock_irqrestore(&team_exit_cb_lock, flags);
	return 0;
}
EXPORT_SYMBOL(nexus_register_team_exit);

void nexus_unregister_team_exit(nexus_team_notify_fn fn)
{
	unsigned long flags;
	int i;
	spin_lock_irqsave(&team_exit_cb_lock, flags);
	for (i = 0; i < team_exit_cb_count; i++) {
		if (team_exit_callbacks[i] == fn) {
			team_exit_callbacks[i] = team_exit_callbacks[--team_exit_cb_count];
			break;
		}
	}
	spin_unlock_irqrestore(&team_exit_cb_lock, flags);
}
EXPORT_SYMBOL(nexus_unregister_team_exit);

static struct nexus_team* nexus_team_init_for(pid_t tgid)
{
	struct nexus_team *t = idr_find(&nexus_teams_idr, tgid);
	if (t != NULL) {
		t->open_count++;
		pr_debug("nexus: tgid=%d open_count=%d (reuse)\n",
			tgid, t->open_count);
		return t;
	}

	struct nexus_team* team = kzalloc(sizeof(struct nexus_team), GFP_KERNEL);
	if (team != NULL) {
		team->id = tgid;
		team->open_count = 1;
		team->main_thread = nexus_thread_init(team, team->id, NULL);

		if (team->main_thread == NULL) {
			kfree(team);
			return NULL;
		}

		strscpy(team->main_thread->name, "main",
			sizeof(team->main_thread->name));
		team->ports = RB_ROOT;
		team->threads = RB_ROOT;

		hlist_add_head(&team->node, &nexus_teams);
		if (idr_alloc(&nexus_teams_idr, team, team->id, team->id + 1,
				GFP_KERNEL) < 0) {
			pr_warn("nexus: idr_alloc failed for team %d\n", team->id);
		}
		pr_debug("nexus: tgid=%d new team\n", tgid);
	}
	return team;
}

struct nexus_team* nexus_team_init()
{
	return nexus_team_init_for(current->tgid);
}

void nexus_team_destroy(struct nexus_team *team)
{
	if (--team->open_count > 0) {
		pr_debug("nexus: team %d release, open_count=%d (still alive)\n",
			team->id, team->open_count);
		return;
	}

	hlist_del(&team->node);
	idr_remove(&nexus_teams_idr, team->id);

	nexus_sem_team_exit(team->id);

	int _i;
	unsigned long _flags;
	spin_lock_irqsave(&team_exit_cb_lock, _flags);
	for (_i = 0; _i < team_exit_cb_count; _i++) {
		nexus_team_notify_fn _fn = team_exit_callbacks[_i];
		spin_unlock_irqrestore(&team_exit_cb_lock, _flags);
		_fn(team->id);
		spin_lock_irqsave(&team_exit_cb_lock, _flags);
	}
	spin_unlock_irqrestore(&team_exit_cb_lock, _flags);

	/* Runs last so vref_team_exit can warn on orphan pinned refs. Registered
	 * directly (not via nexus_register_team_exit) to pin ordering. */
	nexus_vref_team_exit(team->id);

	pr_debug("nexus: team %d destroyed\n", team->id);

	struct rb_node *node;
	struct nexus_port *port;
	struct nexus_thread *thread;

	node = rb_first(&team->ports);
	while (node) {
		port = rb_entry(node, struct nexus_port, node);
		node = rb_next(node);
		rb_erase(&port->node, &team->ports);
		RB_CLEAR_NODE(&port->node);
		port->team = NULL;
		nexus_port_close(port);
		kref_put(&port->ref_count, nexus_port_destroy);
	}

	node = rb_first(&team->threads);
	while (node) {
		thread = rb_entry(node, struct nexus_thread, node);
		node = rb_next(node);
		rb_erase(&thread->node, &team->threads);
		RB_CLEAR_NODE(&thread->node);
		thread->team = NULL;
		nexus_thread_retire(thread);
	}

	team->main_thread->team = NULL;
	nexus_thread_retire(team->main_thread);
	team->main_thread = NULL;
	kfree(team);
}

struct nexus_thread* nexus_thread_init(struct nexus_team *team, pid_t id, const char *name)
{
	struct nexus_thread* thread = kzalloc(sizeof(struct nexus_thread), GFP_KERNEL);

	if (thread != NULL) {
		thread->id = id;

		if (name != NULL) {
			if (strncpy_from_user(
					thread->name, name, B_OS_NAME_LENGTH) < 0) {
				kfree(thread);
				return NULL;
			}
		}

		kref_init(&thread->ref_count);

		sema_init(&thread->sem_read, 1);
		sema_init(&thread->sem_write, 1);

		init_waitqueue_head(&thread->buffer_read);
		init_waitqueue_head(&thread->thread_suspended);
		init_waitqueue_head(&thread->thread_has_newborn);
		init_waitqueue_head(&thread->thread_exit);

		thread->buffer_ready = 0;
		thread->buffer = NULL;
		thread->team = team;
		thread->exit_status = 0;
		thread->has_thread_exited = false;
		thread->has_return_code = false;
		thread->return_code = B_ERROR;
		thread->thread_wait_newborn = false;
		thread->newborn_src = NEXUS_NEWBORN_SRC_NONE;
		thread->thread_resumed = false;
		thread->exit_hook_installed = false;
		thread->generation = nexus_thread_next_generation();

		/* A record that cannot be resolved through the global index
		 * must not exist: WAITFOR's strictness depends on it. */
		if (nexus_thread_index(thread) < 0) {
			kfree(thread);
			return NULL;
		}
	}
	return thread;
}

void nexus_thread_destroy(struct kref* ref)
{
	struct nexus_thread* thread = container_of(ref, struct nexus_thread, ref_count);
	struct nexus_team* team = thread->team;

	// Just in case thread was allocated and never spawned.
	if (!thread->has_thread_exited) {
		thread->has_thread_exited = true;
		if (!thread->has_return_code)
			thread->exit_status = B_ERROR;
		wake_up_all(&thread->thread_exit);
		wake_up_all(&thread->thread_suspended);
		wake_up_all(&thread->thread_has_newborn);
		wake_up_all(&thread->buffer_read);
	}

	if (team != NULL && thread->id != team->id)
		rb_erase(&thread->node, &team->threads);
	kfree(thread->buffer);
	kfree(thread);
}

static struct nexus_thread* find_thread(struct nexus_team *team, const char *name) {
	struct nexus_thread *thread = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = &team->threads.rb_node;

	while (*p) {
		parent = *p;
		thread = rb_entry(parent, struct nexus_thread, node);

		if (current->pid > thread->id)
			p = &(*p)->rb_right;
		else if (current->pid < thread->id)
			p = &(*p)->rb_left;
		else
			break;
	}

	if (*p == NULL) {
		if (name != NULL) {
			pid_t pid = pid_nr(get_task_pid(current, PIDTYPE_PID));
			thread = nexus_thread_init(team, pid, name);
			if (thread == NULL)
				return NULL;
			rb_link_node(&thread->node, parent, p);
			rb_insert_color(&thread->node, &team->threads);
		} else {
			return NULL;
		}
    } else if (name != NULL && thread->has_thread_exited) {
        thread->has_thread_exited = false;
        thread->has_return_code = false;
        thread->thread_wait_newborn = false;
        thread->child_thread = 0;
        thread->newborn_src = NEXUS_NEWBORN_SRC_NONE;
        thread->thread_resumed = false;
        /* Re-arming a record is a new incarnation: stamp it as such so a
         * generation consumer can never confuse it with the old one. */
        thread->generation = nexus_thread_next_generation();
    }
    return thread;
}

static struct nexus_thread* register_thread(struct nexus_team *team, pid_t pid) {
	struct nexus_thread *thread = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = &team->threads.rb_node;

	if (team->main_thread && team->main_thread->id == pid)
		return team->main_thread;

	while (*p) {
		parent = *p;
		thread = rb_entry(parent, struct nexus_thread, node);

		if (pid > thread->id)
			p = &(*p)->rb_right;
		else if (pid < thread->id)
			p = &(*p)->rb_left;
		else {
			if (!thread->has_thread_exited)
				return thread;

			/* The record under this tid has exited; a live task
			 * cannot still own it (the exit work runs before the
			 * pid is released), so this is a recycled tid.
			 * Retire the stale incarnation -- its waiters were
			 * woken at its exit and its state is frozen -- and
			 * register a fresh one that inherits nothing. */
			pr_warn_ratelimited("nexus: recycled tid=%d in team=%d: stale record (gen=%d) retired\n",
				(int)pid, (int)team->id, thread->generation);
			rb_erase(&thread->node, &team->threads);
			RB_CLEAR_NODE(&thread->node);
			nexus_thread_retire(thread);
			return register_thread(team, pid);
		}
	}

	thread = nexus_thread_init(team, pid, NULL);
	if (thread == NULL)
		return NULL;

	rb_link_node(&thread->node, parent, p);
	rb_insert_color(&thread->node, &team->threads);

	if (pid == current->pid)
		nexus_thread_arm_exit_or_finish(thread, current);

	return thread;
}

static struct nexus_thread* find_thread_by_id(struct nexus_team *team, int32_t pid) {
	if (team->main_thread && team->main_thread->id == pid) {
		return team->main_thread;
	}

	struct nexus_thread *thread = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = &team->threads.rb_node;

	while (*p) {
		parent = *p;
		thread = rb_entry(parent, struct nexus_thread, node);

		if (pid > thread->id)
			p = &(*p)->rb_right;
		else if (pid < thread->id)
			p = &(*p)->rb_left;
		else {
			return thread;
		}
	}
	return NULL;
}

static struct nexus_thread* nexus_thread_spawn(struct nexus_team *team,
	const char* name)
{
	return find_thread(team, name);
}

static long nexus_wait_newborn_sync(pid_t child_pid)
{
	struct pid *child_pid_struct;
	struct task_struct *child_task;
	struct task_struct *parent;
	struct nexus_team *child_team;
	bool is_child;
	long ret;

	if (child_pid <= 0 || child_pid == current->pid) {
		pr_warn_ratelimited("nexus: WAIT_NEWBORN(sync): bogus pid=%d from tgid=%d\n",
			child_pid, current->tgid);
		return B_BAD_THREAD_ID;
	}

	child_pid_struct = find_get_pid(child_pid);
	child_task = get_pid_task(child_pid_struct, PIDTYPE_PID);
	put_pid(child_pid_struct);

	if (child_task == NULL) {
		pr_warn_ratelimited("nexus: WAIT_NEWBORN(sync): pid=%d gone before registration\n",
			child_pid);
		return B_BAD_THREAD_ID;
	}

	rcu_read_lock();
	parent = rcu_dereference(child_task->real_parent);
	is_child = (parent != NULL) && (parent->tgid == current->tgid);
	rcu_read_unlock();

	if (!is_child) {
		pr_warn_ratelimited("nexus: WAIT_NEWBORN(sync): pid=%d is not a child of tgid=%d\n",
			child_pid, current->tgid);
		put_task_struct(child_task);
		return B_BAD_THREAD_ID;
	}

	if (idr_find(&nexus_teams_idr, child_task->tgid) != NULL) {
		put_task_struct(child_task);
		return child_pid;
	}

	child_team = nexus_team_init_for(child_task->tgid);
	if (child_team == NULL) {
		put_task_struct(child_task);
		return B_NO_MEMORY;
	}

	child_team->open_count = 0;

	/* The pre-created team holds no fd of its own: without an exit hook
	 * its orphan cleanup (nexus_thread_exit_work) can never run, and a
	 * child that dies before its first open() leaves a stale
	 * pre-registration behind (the PR #47 hang). Arming the hook ties the
	 * team's lifetime to the child's lifetime. */
	if (child_team->main_thread != NULL
			&& child_task->pid == child_task->tgid)
		nexus_thread_arm_exit_or_finish(child_team->main_thread,
			child_task);

	ret = child_pid;
	put_task_struct(child_task);
	return ret;
}

static long nexus_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct nexus_team *team = filp->private_data;
	struct nexus_thread *thread = NULL;
	struct nexus_team *iter_team = NULL;
	struct nexus_thread *dest_thread = NULL;
	struct task_struct *task = NULL;
	long ret = -1;

	mutex_lock(&nexus_main_lock);

	if (team->id != current->tgid) {
		mutex_unlock(&nexus_main_lock);
		return -EPERM;
	}

	switch (cmd) {
	case NEXUS_SEM_CREATE:
	case NEXUS_SEM_ACQUIRE:
	case NEXUS_SEM_RELEASE:
	case NEXUS_SEM_DELETE:
	case NEXUS_SEM_COUNT:
	case NEXUS_SEM_INFO:
	case NEXUS_SEM_NEXT_INFO:
		mutex_unlock(&nexus_main_lock);
		ret = nexus_sem_ioctl(cmd, arg);
		return ret;
	default:
		break;
	}

	if (team->id == current->pid) {
		thread = team->main_thread;
	} else {
		thread = find_thread(team, NULL);
		if (thread != NULL && thread->id == current->pid
				&& thread->has_thread_exited && cmd == NEXUS_THREAD_SPAWN) {
			/* SPAWN on a recycled tid: retire the stale incarnation
			 * (its waiters were woken at its exit) and register a
			 * fresh one below. */
			pr_warn_ratelimited("nexus: SPAWN on recycled tid=%d in team=%d, stale record (gen=%d) retired\n",
				current->pid, team->id, thread->generation);
			rb_erase(&thread->node, &team->threads);
			RB_CLEAR_NODE(&thread->node);
			nexus_thread_retire(thread);
			thread = NULL;
		}
		if (thread == NULL || thread->id != current->pid
				|| cmd == NEXUS_THREAD_SPAWN) {
			if (cmd == NEXUS_THREAD_SPAWN) {
				struct nexus_thread_spawn spawn_data;
				if (copy_from_user(&spawn_data,
					(struct __user nexus_thread_spawn *)arg,
					sizeof(spawn_data)) != 0) {
					mutex_unlock(&nexus_main_lock);
					return -EFAULT;
				}

				/* Register ourselves unless the creator already
				 * did it in the same operation that created us
				 * (creator-side registration): then this is a
				 * no-op and we only announce + gate below. */
				if (thread == NULL || thread->id != current->pid) {
					struct nexus_thread *self_new =
						nexus_thread_spawn(team, spawn_data.name);
					ret = (self_new != NULL) ? 0 : -ENOMEM;
					if (self_new != NULL)
						nexus_thread_arm_exit_or_finish(
							self_new, current);
				} else {
					ret = B_OK;
				}

				task = get_pid_task(
					find_get_pid((pid_t)spawn_data.father),
					PIDTYPE_PID);

				if (task == NULL) {
					mutex_unlock(&nexus_main_lock);
					return B_BAD_THREAD_ID;
				}

				iter_team = idr_find(&nexus_teams_idr, task->tgid);
				if (iter_team != NULL) {
					if (task->pid == iter_team->id) {
						dest_thread = iter_team->main_thread;
					} else {
						dest_thread = register_thread(iter_team,
							 spawn_data.father);
						if (dest_thread == NULL) {
							put_task_struct(task);
							mutex_unlock(&nexus_main_lock);
							return B_BAD_THREAD_ID;
						}
					}
				}

				if (dest_thread == NULL) {
					put_task_struct(task);
					mutex_unlock(&nexus_main_lock);
					return B_BAD_THREAD_ID;
				}

				if (dest_thread->thread_wait_newborn) {
					pr_warn_ratelimited("nexus: SPAWN announce: stale latch on thread=%d (team=%d), previous child_thread=%d src=%d overwritten by %d src=SPAWN\n",
						(int)dest_thread->id, (int)iter_team->id,
						(int)dest_thread->child_thread,
						(int)dest_thread->newborn_src, current->pid);
				}

				dest_thread->child_thread = current->pid;
				dest_thread->thread_wait_newborn = true;
				dest_thread->newborn_src = NEXUS_NEWBORN_SRC_SPAWN;

				kref_get(&dest_thread->ref_count);
				mutex_unlock(&nexus_main_lock);
				wake_up(&dest_thread->thread_has_newborn);
				mutex_lock(&nexus_main_lock);
				kref_put(&dest_thread->ref_count, nexus_thread_destroy);

				put_task_struct(task);

				struct nexus_thread *self = find_thread_by_id(team,
					   current->pid);
				if (self != NULL && !self->thread_resumed) {
					kref_get(&self->ref_count);
					mutex_unlock(&nexus_main_lock);
					wait_event_interruptible(self->thread_suspended,
						 self->thread_resumed);
					mutex_lock(&nexus_main_lock);
					kref_put(&self->ref_count, nexus_thread_destroy);
				}

				mutex_unlock(&nexus_main_lock);
				return ret;
			}

			thread = register_thread(team, current->pid);
			if (thread == NULL) {
				mutex_unlock(&nexus_main_lock);
				return -ENOMEM;
			}
		}
	}

	switch (cmd) {
			case NEXUS_THREAD_SET_NAME: {
			struct nexus_thread_set_name_req user_data;
			if (copy_from_user(&user_data, (struct __user nexus_thread_set_name_req*)arg,
					sizeof(user_data))) {
				ret = B_BAD_VALUE;
				break;
			}
			if (strncpy_from_user(thread->name, user_data.name,
					min(B_OS_NAME_LENGTH, user_data.size)) < 0)
				ret = B_BAD_VALUE;
			else
				ret = B_OK;
			break;
		}

		case NEXUS_THREAD_READ: {
			struct nexus_thread_rw user_data;
			int32_t status;

			if (copy_from_user(&user_data, (struct __user nexus_thread_rw*)arg,
					sizeof(user_data))) {
				ret = -EFAULT;
				break;
			}
			do {
				if (thread->id != current->pid) {
					status = B_BAD_THREAD_ID;
					break;
				}
				if (down_interruptible(&thread->sem_read)) {
					status = B_INTERRUPTED;
					break;
				}
				mutex_unlock(&nexus_main_lock);
				wait_event_interruptible(thread->buffer_read,
					thread->buffer_ready != 0);
				mutex_lock(&nexus_main_lock);
				if (copy_to_user(user_data.buffer, thread->buffer,
						min(user_data.size, thread->buffer_size))) {
					status = B_BAD_VALUE;
					break;
				}
				user_data.sender = thread->sender;
				user_data.return_code = thread->unblock_code;
				kfree(thread->buffer);
				thread->buffer = NULL;
				thread->buffer_size = 0;
				thread->buffer_ready = 0;
				thread->sender = -1;
				thread->unblock_code = -1;
				up(&thread->sem_write);
				status = B_OK;
			} while (0);
			user_data.ret = status;
			if (copy_to_user((struct __user nexus_thread_rw*)arg, &user_data,
					sizeof(user_data)))
				ret = -EFAULT;
			else
				ret = 0;
			break;
		}

		case NEXUS_THREAD_WRITE: {
			struct nexus_thread_rw user_data;
			struct nexus_team *iter_team = NULL;
			struct nexus_thread *dest_thread = NULL;
			struct pid *_pid_ref;
			struct task_struct *task = NULL;
			int sem_ret;
			int32_t status;

			if (copy_from_user(&user_data, (struct __user nexus_thread_rw*)arg,
					sizeof(user_data))) {
				ret = -EFAULT;
				break;
			}
			do {
				_pid_ref = find_get_pid((pid_t)user_data.receiver);
				task = get_pid_task(_pid_ref, PIDTYPE_PID);
				put_pid(_pid_ref);
				if (task == NULL) { status = B_BAD_THREAD_ID; break; }
				iter_team = idr_find(&nexus_teams_idr, task->tgid);
				if (iter_team != NULL) {
					if (task->pid == iter_team->id)
						dest_thread = iter_team->main_thread;
					else
						dest_thread = find_thread_by_id(iter_team,
							user_data.receiver);
				}
				if (dest_thread == NULL) {
					put_task_struct(task);
					status = B_BAD_THREAD_ID;
					break;
				}
				kref_get(&dest_thread->ref_count);
				mutex_unlock(&nexus_main_lock);
				sem_ret = down_interruptible(&dest_thread->sem_write);
				mutex_lock(&nexus_main_lock);
				if (kref_put(&dest_thread->ref_count, nexus_thread_destroy)) {
					put_task_struct(task);
					status = B_BAD_THREAD_ID;
					break;
				}
				if (sem_ret) {
					put_task_struct(task);
					status = B_INTERRUPTED;
					break;
				}
				dest_thread->buffer = kzalloc(user_data.size, GFP_KERNEL);
				if (dest_thread->buffer == NULL) {
					put_task_struct(task);
					status = B_NO_MEMORY;
					break;
				}
				if (copy_from_user(dest_thread->buffer, user_data.buffer,
						user_data.size)) {
					kfree(dest_thread->buffer);
					dest_thread->buffer = NULL;
					put_task_struct(task);
					status = B_BAD_VALUE;
					break;
				}
				dest_thread->sender = current->pid;
				dest_thread->buffer_size = user_data.size;
				dest_thread->buffer_ready = 1;
				dest_thread->unblock_code = user_data.return_code;
				wake_up_interruptible(&dest_thread->buffer_read);
				up(&dest_thread->sem_read);
				put_task_struct(task);
				status = B_OK;
			} while (0);
			user_data.ret = status;
			if (copy_to_user((struct __user nexus_thread_rw*)arg, &user_data,
					sizeof(user_data)))
				ret = -EFAULT;
			else
				ret = 0;
			break;
		}

		case NEXUS_THREAD_HAS_DATA: {
			struct nexus_thread_rw user_data;
			struct nexus_team *iter_team = NULL;
			struct nexus_thread *dest_thread = NULL;
			struct pid *_pid_ref;
			struct task_struct *task;
			int32_t status;

			if (copy_from_user(&user_data, (struct __user nexus_thread_rw*)arg,
					sizeof(user_data))) {
				ret = -EFAULT;
				break;
			}
			do {
				_pid_ref = find_get_pid((pid_t)user_data.receiver);
				task = get_pid_task(_pid_ref, PIDTYPE_PID);
				put_pid(_pid_ref);
				if (task == NULL) { status = B_BAD_THREAD_ID; break; }
				iter_team = idr_find(&nexus_teams_idr, task->tgid);
				if (iter_team != NULL) {
					if (task->pid == iter_team->id)
						dest_thread = iter_team->main_thread;
					else
						dest_thread = find_thread_by_id(iter_team,
							user_data.receiver);
				}
				put_task_struct(task);
				if (dest_thread == NULL) {
					status = B_BAD_THREAD_ID;
					break;
				}
				status = (dest_thread->buffer_ready == 1)
					? B_OK : B_WOULD_BLOCK;
			} while (0);
			user_data.ret = status;
			if (copy_to_user((struct __user nexus_thread_rw*)arg, &user_data,
					sizeof(user_data)))
				ret = -EFAULT;
			else
				ret = 0;
			break;
		}

		case NEXUS_THREAD_WAITFOR: {
			struct nexus_thread_waitfor_req user_data;
			struct nexus_thread *dest_thread = NULL;
			struct pid *_pid_ref;
			struct task_struct *task;
			int wret;
			int32_t status;

			if (copy_from_user(&user_data,
					(struct __user nexus_thread_waitfor_req*)arg,
					sizeof(user_data))) {
				ret = -EFAULT;
				break;
			}
			do {
				if ((pid_t)user_data.receiver == current->pid) {
					status = B_BAD_THREAD_ID;
					break;
				}
				/* Strict resolution: a tid is either registered
				 * with nexus (creator-side registration or the
				 * thread's own first ioctl) or unknown. Unknown
				 * means "never created or fully retired": fail
				 * immediately, no guessing, no retries. */
				dest_thread = nexus_thread_lookup(
						(int32_t)user_data.receiver);
				if (dest_thread == NULL
						|| dest_thread->team != team) {
					/* Unknown tid, or a record of another
					 * team: not ours to wait on. */
					status = B_BAD_THREAD_ID;
					break;
				}
				/* When the target task is still alive it must
				 * share our address space. A NULL mm means the
				 * task is a zombie (already exited): the exit
				 * status is then served from its record. */
				_pid_ref = find_get_pid((pid_t)user_data.receiver);
				task = get_pid_task(_pid_ref, PIDTYPE_PID);
				put_pid(_pid_ref);
				if (task != NULL) {
					if (task->mm != NULL
							&& task->mm != current->mm) {
						put_task_struct(task);
						status = B_BAD_THREAD_ID;
						break;
					}
					put_task_struct(task);
				}
				kref_get(&dest_thread->ref_count);
				mutex_unlock(&nexus_main_lock);
				wret = wait_event_interruptible(dest_thread->thread_exit,
					dest_thread->has_thread_exited);
				mutex_lock(&nexus_main_lock);
				if (wret == -ERESTARTSYS) {
					kref_put(&dest_thread->ref_count, nexus_thread_destroy);
					status = B_INTERRUPTED;
					break;
				}
				user_data.return_code = dest_thread->exit_status;
				kref_put(&dest_thread->ref_count, nexus_thread_destroy);
				status = B_OK;
			} while (0);
			user_data.ret = status;
			if (copy_to_user((struct __user nexus_thread_waitfor_req*)arg,
					&user_data, sizeof(user_data)))
				ret = -EFAULT;
			else
				ret = 0;
			break;
		}

		case NEXUS_THREAD_WAIT_NEWBORN:
			if (arg != 0) {
				ret = nexus_wait_newborn_sync((pid_t)arg);
				goto exit;
			}

			if (!thread->thread_wait_newborn) {
				long nb_left;
				bool nb_reported = false;

				kref_get(&thread->ref_count);
				mutex_unlock(&nexus_main_lock);
				do {
					nb_left = wait_event_interruptible_timeout(
						thread->thread_has_newborn,
						thread->thread_wait_newborn,
						msecs_to_jiffies(10000));
					if (nb_left == 0 && !nb_reported) {
						nb_reported = true;
						pr_warn("nexus: WAIT_NEWBORN stuck >10s: waiter tid=%d tgid=%d nexus_thread=%d team=%d main_thread=%d\n",
							task_pid_vnr(current), task_tgid_vnr(current),
							(int)thread->id, (int)team->id,
							team->main_thread ? (int)team->main_thread->id : -1);
					}
				} while (nb_left == 0);
				ret = (nb_left < 0) ? nb_left : 0;
				mutex_lock(&nexus_main_lock);

				if (ret == -ERESTARTSYS) {
					kref_put(&thread->ref_count, nexus_thread_destroy);
					ret = B_INTERRUPTED;
					break;
				}
				kref_put(&thread->ref_count, nexus_thread_destroy);
			}

			thread->thread_wait_newborn = false;
			thread->newborn_src = NEXUS_NEWBORN_SRC_NONE;
			ret = thread->child_thread;
			thread->child_thread = 0;
			goto exit;

		case NEXUS_THREAD_CLONE_EXECUTED:
			if (arg != 2) {
			rcu_read_lock();
			task = rcu_dereference(current->real_parent);
			if (!task) {
				rcu_read_unlock();
				mutex_unlock(&nexus_main_lock);
				return B_BAD_THREAD_ID;
			}
			pid_t parent_tid = task_pid_vnr(task);
			pid_t parent_tgid = task_tgid_vnr(task);
			rcu_read_unlock();

			iter_team = idr_find(&nexus_teams_idr, parent_tgid);
			if (iter_team == NULL) {
				pr_warn_ratelimited("nexus: CLONE_EXECUTED: no team for parent tgid=%d (child tid=%d)\n",
					parent_tgid, task_pid_vnr(current));
			} else {
				dest_thread = register_thread(iter_team, parent_tid);
				if (dest_thread == NULL) {
					pr_warn_ratelimited("nexus: CLONE_EXECUTED: cannot register father tid=%d in team=%d (child tid=%d)\n",
						parent_tid, (int)iter_team->id,
						task_pid_vnr(current));
				}
			}

			if (dest_thread == NULL) {
				pr_warn_ratelimited("nexus: CLONE_EXECUTED: no dest_thread for parent tid=%d tgid=%d, returning B_BAD_THREAD_ID (child tid=%d will abort)\n",
					parent_tid, parent_tgid, task_pid_vnr(current));
				mutex_unlock(&nexus_main_lock);
				return B_BAD_THREAD_ID;
			}

			if (dest_thread->thread_wait_newborn) {
				pr_warn_ratelimited("nexus: CLONE_EXECUTED: stale latch on thread=%d (team=%d), previous child_thread=%d src=%d overwritten by %d src=CLONE (arg=%ld)\n",
					(int)dest_thread->id, (int)iter_team->id,
					(int)dest_thread->child_thread,
					(int)dest_thread->newborn_src, current->pid, (long)arg);
			}

			dest_thread->child_thread = current->pid;
			dest_thread->thread_wait_newborn = true;
			dest_thread->newborn_src = NEXUS_NEWBORN_SRC_CLONE;

			kref_get(&dest_thread->ref_count);
			mutex_unlock(&nexus_main_lock);
			wake_up(&dest_thread->thread_has_newborn);
			mutex_lock(&nexus_main_lock);
			kref_put(&dest_thread->ref_count, nexus_thread_destroy);
			}

			if ((arg == 0 || arg == 2) && !thread->thread_resumed) {
				kref_get(&thread->ref_count);
				mutex_unlock(&nexus_main_lock);
				wait_event_interruptible(thread->thread_suspended,
					 thread->thread_resumed);
				mutex_lock(&nexus_main_lock);
				kref_put(&thread->ref_count, nexus_thread_destroy);
			}

			mutex_unlock(&nexus_main_lock);
			return current->pid;
			break;

		case NEXUS_THREAD_RESUME:
			thread_id tid = (thread_id)arg;
			if (tid < 0) {
				ret = B_BAD_THREAD_ID;
				break;
			}

			{
			struct pid *_pid_ref = find_get_pid((pid_t)tid);
			task = get_pid_task(_pid_ref, PIDTYPE_PID);
			put_pid(_pid_ref);
			}

			if (task == NULL) {
				ret = B_BAD_THREAD_ID;
				break;
			}

			iter_team = idr_find(&nexus_teams_idr, task->tgid);
			if (iter_team == NULL) {
				pr_warn_ratelimited("nexus: RESUME tid=%d: no team for tgid=%d\n",
					(int)tid, task->tgid);
				ret = B_BAD_TEAM_ID;
			}
			if (iter_team != NULL) {
				if (task->pid == iter_team->id) {
					dest_thread = iter_team->main_thread;
				} else {
					dest_thread = find_thread_by_id(iter_team, tid);
					if (dest_thread == NULL)
						ret = B_BAD_THREAD_ID;
				}
			}

			if (dest_thread == NULL) {
				ret = B_BAD_THREAD_ID;
				break;
			}

			if (!dest_thread->thread_resumed) {
				dest_thread->thread_resumed = true;
				kref_get(&dest_thread->ref_count);
				mutex_unlock(&nexus_main_lock);
				wake_up(&dest_thread->thread_suspended);
				mutex_lock(&nexus_main_lock);
				kref_put(&dest_thread->ref_count, nexus_thread_destroy);
			}
			put_task_struct(task);
			ret = B_OK;
			break;

		case NEXUS_THREAD_REGISTER: {
			/* Creator-side registration: the creator hands nexus
			 * the tid it received from clone(), in the same
			 * operation that created the thread. From here on a
			 * thread that exists is a thread nexus knows: WAITFOR
			 * resolves it strictly, without retries or /proc. */
			thread_id child_tid = (thread_id)arg;
			struct pid *_pid_ref;
			struct task_struct *child_task;
			struct nexus_thread *child_record;
			struct task_struct *parent;
			bool same_mm, is_child;

			if (child_tid <= 0 || child_tid == current->pid) {
				ret = B_BAD_THREAD_ID;
				break;
			}

			_pid_ref = find_get_pid((pid_t)child_tid);
			child_task = get_pid_task(_pid_ref, PIDTYPE_PID);
			put_pid(_pid_ref);
			if (child_task == NULL) {
				/* Never created, or created, exited and fully
				 * reaped: unknown, and honestly reported. */
				ret = B_BAD_THREAD_ID;
				break;
			}

			/* Only the creator may register: the target must
			 * share our address space (spawn_thread-style
			 * threads) or be our direct child (fork-style). */
			rcu_read_lock();
			parent = rcu_dereference(child_task->real_parent);
			is_child = (parent != NULL)
				&& (parent->tgid == current->tgid);
			rcu_read_unlock();
			same_mm = (child_task->mm != NULL)
				&& (child_task->mm == current->mm);

			if (!same_mm && !is_child) {
				put_task_struct(child_task);
				ret = B_BAD_THREAD_ID;
				break;
			}

			/* Register in the caller's team, keyed by the child
			 * tid: the record outlives the child's exit (so
			 * post-mortem WAITFOR serves the real status) and no
			 * pre-created child team is needed, so nothing can go
			 * stale (the PR #47 hang is structurally absent). */
			child_record = register_thread(team, (pid_t)child_tid);
			if (child_record == NULL) {
				put_task_struct(child_task);
				ret = B_NO_MEMORY;
				break;
			}

			/* If the child is already exiting, the record is
			 * finished right away with a synthesized status:
			 * WAITFOR then returns cleanly instead of hanging or
			 * lying with B_BAD_THREAD_ID. */
			nexus_thread_arm_exit_or_finish(child_record, child_task);
			put_task_struct(child_task);

			ret = child_tid;
			break;
		}

		case NEXUS_THREAD_GET_GENERATION: {
			/* Incarnation stamp of a registered tid: changes on
			 * every recycle. Always in [1, 2^31-1], so a caller
			 * checking "< 0" sees real errors only. */
			thread_id gen_tid = (thread_id)arg;
			struct nexus_thread *gen_thread;

			if (gen_tid <= 0) {
				ret = B_BAD_THREAD_ID;
				break;
			}

			gen_thread = nexus_thread_lookup((int32_t)gen_tid);
			if (gen_thread == NULL || gen_thread->team != team) {
				ret = B_BAD_THREAD_ID;
				break;
			}

			ret = gen_thread->generation;
			break;
		}

		case NEXUS_THREAD_SET_RETURN_CODE:
			thread->exit_status = (int32_t)(long)arg;
			thread->has_return_code = true;
			ret = B_OK;
			break;

		case NEXUS_PORT_CREATE:
			ret = nexus_port_create(team, arg);
			break;

			case NEXUS_PORT_CLOSE:
			ret = nexus_port_io_close(team, arg);
			break;
		case NEXUS_PORT_DELETE:
			ret = nexus_port_io_delete(team, arg);
			break;
		case NEXUS_PORT_READ:
			ret = nexus_port_io_read(team, arg);
			break;
		case NEXUS_PORT_WRITE:
			ret = nexus_port_io_write(team, arg);
			break;
		case NEXUS_PORT_INFO:
			ret = nexus_port_io_info(team, arg);
			break;
		case NEXUS_PORT_MESSAGE_INFO:
			ret = nexus_port_io_message_info(team, arg);
			break;
		case NEXUS_SET_PORT_OWNER:
			ret = nexus_port_io_set_owner(team, arg);
			break;
		case NEXUS_PORT_WRITE_CAPS:
			ret = nexus_port_io_write_caps(team, arg);
			break;
		case NEXUS_PORT_READ_CAPS:
			ret = nexus_port_io_read_caps(team, arg);
			break;

		case NEXUS_PORT_FIND:
			ret = nexus_port_find(arg);
			break;

		case NEXUS_GET_NEXT_PORT_FOR_TEAM:
			ret = nexus_get_next_port_for_team(arg);
			break;

		default:
			break;
	}

exit:
	mutex_unlock(&nexus_main_lock);
	return ret;
}

static int nexus_open(struct inode *nodp, struct file *filp)
{
	struct nexus_team* team = NULL;

	mutex_lock(&nexus_main_lock);
	team = nexus_team_init();
	if (team == NULL) {
		mutex_unlock(&nexus_main_lock);
		return -ENOMEM;
	}

	if (current->pid == team->id)
		nexus_thread_arm_exit_or_finish(team->main_thread, current);
	mutex_unlock(&nexus_main_lock);

	filp->private_data = (void*)team;

	pr_debug("nexus: open team=%d by tgid=%d pid=%d\n",
		team->id, current->tgid, current->pid);

	return 0;
}

static int nexus_release(struct inode *nodp, struct file *filp)
{
	struct nexus_team *team = (struct nexus_team *)filp->private_data;

	pr_debug("nexus: release team=%d by tgid=%d pid=%d\n",
		team->id, current->tgid, current->pid);

	mutex_lock(&nexus_main_lock);
	nexus_team_destroy(team);
	mutex_unlock(&nexus_main_lock);

	filp->private_data = NULL;

	return 0;
}

struct file_operations nexus_interface_fops = {
	.owner = THIS_MODULE,
	.read = NULL,
	.write = NULL,
	.open = nexus_open,
	.unlocked_ioctl = nexus_ioctl,
	.release = nexus_release
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

static int nexus_init(void)
{
	int device_created = 0;

	if (alloc_chrdev_region(&major, 0, 1, DEV_NAME "_proc") < 0)
		goto error;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	nexus_class = class_create(THIS_MODULE, DEV_NAME "_sys");
#else
	nexus_class = class_create(DEV_NAME "_sys");
#endif

	if (nexus_class == NULL)
		goto error;

	if (device_create(nexus_class, NULL, major, NULL, DEV_NAME) == NULL)
		goto error;

	device_created = 1;
	cdev_init(&nexus_cdev, &nexus_interface_fops);
	if (cdev_add(&nexus_cdev, major, 1) == -1)
		goto error;

	int ret = nexus_sem_init();
	if (ret < 0) {
		pr_err("nexus: failed to init sem: %d\n", ret);
		goto error;
	}

	ret = nexus_vref_init();
	if (ret < 0) {
		pr_err("nexus: failed to init vref: %d\n", ret);
		nexus_sem_exit();
		goto error;
	}

	for_each_kernel_tracepoint(nexus_find_exit_tp, &nexus_exit_tp);
	ret = nexus_exit_tp != NULL
		? tracepoint_probe_register(nexus_exit_tp, nexus_exit_probe, NULL)
		: -ENOENT;
	if (ret < 0) {
		pr_err("nexus: cannot hook sched_process_exit: %d\n", ret);
		nexus_vref_exit();
		nexus_sem_exit();
		goto error;
	}

	printk(KERN_INFO "nexus: loaded (sync-newborn+tid-recycle)\n");
	return 0;

error:
	nexus_cleanup_dev(device_created);
	return ret < 0 ? ret : -ENOMEM;
}

static void nexus_exit(void)
{
	struct nexus_thread *thread;
	struct hlist_node *tmp;
	int bkt;

	tracepoint_probe_unregister(nexus_exit_tp, nexus_exit_probe, NULL);
	tracepoint_synchronize_unregister();

	/* No opener can be left, so nothing waits on these records. */
	mutex_lock(&nexus_main_lock);
	hash_for_each_safe(nexus_exit_hash, bkt, tmp, thread, exit_node) {
		hash_del(&thread->exit_node);
		kref_put(&thread->ref_count, nexus_thread_destroy);
	}
	mutex_unlock(&nexus_main_lock);

	nexus_vref_exit();
	nexus_sem_exit();
	nexus_cleanup_dev(1);
	printk(KERN_INFO "nexus: unloaded\n");
}



module_init(nexus_init);
module_exit(nexus_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dario Casalinuovo");
MODULE_DESCRIPTION("Nexus IPC");
MODULE_VERSION("0.7");
