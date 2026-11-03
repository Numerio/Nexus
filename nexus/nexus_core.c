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
#include <linux/ktime.h>
#include <linux/semaphore.h>
#include <linux/minmax.h>

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

/* Lock order and the meaning of each lock: see nexus_private.h. */
static DEFINE_MUTEX(nexus_main_lock);

HLIST_HEAD(nexus_teams);
EXPORT_SYMBOL(nexus_teams);

/* Team table: nexus_teams and nexus_teams_idr change together, under
 * nexus_main_lock and this spinlock. Lookups need only the spinlock. */
static DEFINE_IDR(nexus_teams_idr);
static DEFINE_SPINLOCK(nexus_teams_lock);

/* Global tid -> struct nexus_thread index of every registered record.
 * WAITFOR resolves through it: a tid is either registered
 * (known, resolvable) or unknown -- there is no third state to guess about.
 * Occupancy rule: a tid maps to its OLDEST still-retained record; a later
 * nexus_thread_init() for an already-mapped tid (e.g. a fork child opening
 * its own team while the creator-registered record lives in the parent's
 * team) stays unindexed and is reachable through its team only. Leaf
 * spinlock. */
static DEFINE_IDR(nexus_threads_idr);
static DEFINE_SPINLOCK(nexus_threads_idr_lock);

/* Global incarnation counter for generation stamps. */
static atomic64_t nexus_thread_generation_ctr = ATOMIC64_INIT(0);

static void nexus_team_destroy(struct nexus_team *team);
static struct nexus_thread* nexus_thread_init(struct nexus_team *team,
	pid_t id, const char *name);
static void nexus_thread_destroy(struct kref* ref);
static void nexus_team_free(struct kref *ref);

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

/* Returns the record indexed for the tid with a reference, or NULL. The
 * index entry itself holds a reference, so an entry found under the lock
 * cannot be at zero. Pair with kref_put(..., nexus_thread_destroy). */
static struct nexus_thread* nexus_thread_lookup(int32_t tid)
{
	struct nexus_thread *t;
	unsigned long flags;

	spin_lock_irqsave(&nexus_threads_idr_lock, flags);
	t = idr_find(&nexus_threads_idr, tid);
	if (t != NULL && !kref_get_unless_zero(&t->ref_count))
		t = NULL;
	spin_unlock_irqrestore(&nexus_threads_idr_lock, flags);
	return t;
}

static struct nexus_thread* nexus_thread_lookup_rcu(int32_t tid)
{
	struct nexus_thread *t;

	rcu_read_lock();
	t = idr_find(&nexus_threads_idr, tid);
	if (t != NULL && !kref_get_unless_zero(&t->ref_count))
		t = NULL;
	rcu_read_unlock();
	return t;
}

/* The index entry holds a reference: nexus_thread_retire() drops it along
 * with the tree's. Without it, retire over-put and freed a record whose exit
 * hook was still pending (refcount underflow in nexus_thread_exit_work). */
static int nexus_thread_index(struct nexus_thread *thread)
{
	unsigned long flags;
	int ret;

	idr_preload(GFP_KERNEL);
	spin_lock_irqsave(&nexus_threads_idr_lock, flags);
	ret = idr_alloc(&nexus_threads_idr, thread,
		thread->id, thread->id + 1, GFP_NOWAIT);
	if (ret >= 0) {
		kref_get(&thread->ref_count);
		ret = 0;
	} else if (idr_find(&nexus_threads_idr, thread->id) != NULL) {
		/* Slot occupied by an older retained record for the same tid
		 * (see occupancy rule above): keep the older one indexed. */
		ret = 0;
	}
	spin_unlock_irqrestore(&nexus_threads_idr_lock, flags);
	idr_preload_end();
	return ret;
}

/* Drop a record's index entry. Called ONLY at retirement sites (where the
 * record leaves its team's rbtree, or the team itself dies), never from
 * nexus_thread_destroy: retirement is serialized under the home team's
 * lock, so an erased entry can never belong to a newer record for the same
 * tid. Returns true if this record was the indexed one. */
static bool nexus_thread_unindex(struct nexus_thread *thread)
{
	unsigned long flags;
	bool indexed = false;

	spin_lock_irqsave(&nexus_threads_idr_lock, flags);
	if (idr_find(&nexus_threads_idr, thread->id) == thread) {
		idr_remove(&nexus_threads_idr, thread->id);
		indexed = true;
	}
	spin_unlock_irqrestore(&nexus_threads_idr_lock, flags);
	return indexed;
}

/* Retire a record leaving its team (recycle or team teardown): drop the
 * index entry plus the tree-membership and index references. Safe for
 * never-indexed records (e.g. a fork child's own-team main record whose tid
 * slot is held by the creator-registered record). Caller holds
 * thread->home->lock and has already erased the record from the tree. */
static void nexus_thread_retire(struct nexus_thread *thread)
{
	bool indexed = nexus_thread_unindex(thread);

	thread->team = NULL;
	kref_put(&thread->ref_count, nexus_thread_destroy);
	if (indexed)
		kref_put(&thread->ref_count, nexus_thread_destroy);
}

/* Returns the team with a reference, or NULL. A team in the table holds
 * its lifetime reference, so the count cannot be zero here. */
struct nexus_team* nexus_find_team(int32_t id)
{
	struct nexus_team *t;
	unsigned long flags;

	spin_lock_irqsave(&nexus_teams_lock, flags);
	t = idr_find(&nexus_teams_idr, id);
	if (t != NULL && !kref_get_unless_zero(&t->ref_count))
		t = NULL;
	spin_unlock_irqrestore(&nexus_teams_lock, flags);
	return t;
}

/* Lookup for callers that hold nexus_main_lock: no reference needed, the
 * team cannot be destroyed under them. */
static struct nexus_team* nexus_team_peek(int32_t id)
{
	return idr_find(&nexus_teams_idr, id);
}

void nexus_team_put(struct nexus_team *team)
{
	if (team != NULL)
		kref_put(&team->ref_count, nexus_team_free);
}

static void nexus_team_free(struct kref *ref)
{
	kfree(container_of(ref, struct nexus_team, ref_count));
}

/* Lock two team mutexes in ascending team id order. a and b must differ. */
void nexus_lock_two_teams(struct nexus_team *a, struct nexus_team *b)
{
	if (a->id < b->id) {
		mutex_lock(&a->lock);
		mutex_lock(&b->lock);
	} else {
		mutex_lock(&b->lock);
		mutex_lock(&a->lock);
	}
}

void nexus_unlock_two_teams(struct nexus_team *a, struct nexus_team *b)
{
	if (a->id < b->id) {
		mutex_unlock(&b->lock);
		mutex_unlock(&a->lock);
	} else {
		mutex_unlock(&a->lock);
		mutex_unlock(&b->lock);
	}
}

/* Channel semaphores start at 1. Exit wakes peers, which return any count
 * they hold; re-arm restores the creation values. */
static void nexus_thread_rearm_channels(struct nexus_thread *thread)
{
	sema_init(&thread->sem_read, 1);
	sema_init(&thread->sem_write, 1);
}

static void nexus_thread_release_channels(struct nexus_thread *thread)
{
	/* Wake peers parked on this record; each re-checks has_thread_exited
	 * and ups again to return the count, so semaphores are not inflated. */
	up(&thread->sem_read);
	up(&thread->sem_write);
}

static void nexus_thread_exit_work(struct callback_head *head)
{
	struct nexus_thread *thread = container_of(head, struct nexus_thread, exit_work);
	struct nexus_team *team = thread->home;
	bool main_thread;

	mutex_lock(&team->lock);

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
	wake_up_all(&thread->buffer_read);
	nexus_thread_release_channels(thread);

	/* Only a team nobody holds open can be an orphan: an open fd's release
	 * destroys the team itself. */
	main_thread = team->main_thread == thread
		&& READ_ONCE(team->open_count) == 0;
	mutex_unlock(&team->lock);

	/* A pre-created team nobody opened is torn down with its main thread.
	 * open_count belongs to nexus_main_lock, so the verdict is taken
	 * there; team->lock cannot be held across it. */
	if (main_thread) {
		mutex_lock(&nexus_main_lock);
		if (team->main_thread == thread && team->open_count == 0) {
			pr_warn_ratelimited("nexus: team=%d destroyed before its first open()\n",
				team->id);
			nexus_team_destroy(team);
		}
		mutex_unlock(&nexus_main_lock);
	}

	kref_put(&thread->ref_count, nexus_thread_destroy);
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
/* raw_spinlock_t: the probe runs with preemption disabled, where on
 * PREEMPT_RT spinlock_t is a sleeping lock (scheduling while atomic). */
static DEFINE_RAW_SPINLOCK(nexus_exit_lock);
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

	raw_spin_lock(&nexus_exit_lock);
	hash_for_each_possible_safe(nexus_exit_hash, thread, tmp, exit_node, pid) {
		if (thread->exit_pid != pid)
			continue;
		hash_del(&thread->exit_node);
		WARN_ON_ONCE(task_work_add(task, &thread->exit_work, TWA_NONE));
	}
	raw_spin_unlock(&nexus_exit_lock);
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

	raw_spin_lock(&nexus_exit_lock);
	hash_add(nexus_exit_hash, &thread->exit_node, thread->exit_pid);
	raw_spin_unlock(&nexus_exit_lock);

	/* If the task started exiting meanwhile the probe may already have
	 * run; whoever unhashes the record owns it. */
	smp_mb();
	if (!(READ_ONCE(task->flags) & PF_EXITING))
		return true;

	raw_spin_lock(&nexus_exit_lock);
	if (hash_hashed(&thread->exit_node)) {
		hash_del(&thread->exit_node);
		reclaimed = true;
	}
	raw_spin_unlock(&nexus_exit_lock);

	if (!reclaimed)
		return true;

	thread->exit_hook_installed = false;
	kref_put(&thread->ref_count, nexus_thread_destroy);
	return false;
}

/* Arm the exit hook; if the task is already exiting, finish the record right
 * away with a synthesized status instead. A thread that died before the hook
 * could be armed then still resolves cleanly through WAITFOR (immediate
 * B_ERROR, not a hang and not B_BAD_THREAD_ID). Caller holds thread->home->lock. */
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
		wake_up_all(&thread->buffer_read);
		nexus_thread_release_channels(thread);
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

/* Caller holds nexus_main_lock. */
static struct nexus_team* nexus_team_init_for(pid_t tgid)
{
	struct nexus_team *team = nexus_team_peek(tgid);
	unsigned long flags;
	int ret;

	if (team != NULL) {
		team->open_count++;
		pr_debug("nexus: tgid=%d open_count=%d (reuse)\n",
			tgid, team->open_count);
		return team;
	}

	team = kzalloc(sizeof(struct nexus_team), GFP_KERNEL);
	if (team == NULL)
		return NULL;

	team->id = tgid;
	team->open_count = 1;
	kref_init(&team->ref_count);
	mutex_init(&team->lock);
	team->ports = RB_ROOT;
	team->threads = RB_ROOT;

	team->main_thread = nexus_thread_init(team, team->id, NULL);
	if (team->main_thread == NULL) {
		kfree(team);
		return NULL;
	}

	strscpy(team->main_thread->name, "main",
		sizeof(team->main_thread->name));

	idr_preload(GFP_KERNEL);
	spin_lock_irqsave(&nexus_teams_lock, flags);
	hlist_add_head(&team->node, &nexus_teams);
	ret = idr_alloc(&nexus_teams_idr, team, team->id, team->id + 1,
		GFP_NOWAIT);
	spin_unlock_irqrestore(&nexus_teams_lock, flags);
	idr_preload_end();
	if (ret < 0)
		pr_warn("nexus: idr_alloc failed for team %d\n", team->id);

	pr_debug("nexus: tgid=%d new team\n", tgid);
	return team;
}

/* Caller holds nexus_main_lock. */
static struct nexus_team* nexus_team_init(void)
{
	return nexus_team_init_for(current->tgid);
}

/* Caller holds nexus_main_lock. */
static void nexus_team_destroy(struct nexus_team *team)
{
	struct nexus_thread *thread;
	struct rb_node *node;
	unsigned long flags;

	if (--team->open_count > 0) {
		pr_debug("nexus: team %d release, open_count=%d (still alive)\n",
			team->id, team->open_count);
		return;
	}

	spin_lock_irqsave(&nexus_teams_lock, flags);
	hlist_del(&team->node);
	idr_remove(&nexus_teams_idr, team->id);
	spin_unlock_irqrestore(&nexus_teams_lock, flags);

	mutex_lock(&team->lock);
	team->dead = true;
	mutex_unlock(&team->lock);

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

	/* The callbacks above resolve port owners through the ports, so the
	 * ports go only now. Queued messages hold vref references; they must
	 * be released before vref_team_exit reaps the team's slots, or the
	 * release underflows. vref_team_exit stays after the callbacks and
	 * runs last so it can warn on orphan pinned refs. */
	nexus_port_team_teardown(team);

	nexus_vref_team_exit(team->id);

	pr_debug("nexus: team %d destroyed\n", team->id);

	mutex_lock(&team->lock);
	node = rb_first(&team->threads);
	while (node) {
		thread = rb_entry(node, struct nexus_thread, node);
		node = rb_next(node);
		rb_erase(&thread->node, &team->threads);
		RB_CLEAR_NODE(&thread->node);
		nexus_thread_retire(thread);
	}

	nexus_thread_retire(team->main_thread);
	team->main_thread = NULL;
	mutex_unlock(&team->lock);

	/* Drop the lifetime ref; threads and lookups that still hold one keep
	 * the object alive until they put. */
	nexus_team_put(team);
}

static struct nexus_thread* nexus_thread_init(struct nexus_team *team,
	pid_t id, const char *name)
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
		init_waitqueue_head(&thread->thread_exit);

		thread->buffer_ready = 0;
		thread->buffer = NULL;
		thread->team = team;
		thread->home = team;
		thread->exit_status = 0;
		thread->has_thread_exited = false;
		thread->has_return_code = false;
		thread->return_code = B_ERROR;
		thread->thread_resumed = false;
		thread->spawn_pending = false;
		thread->exit_hook_installed = false;
		thread->generation = nexus_thread_next_generation();
		RB_CLEAR_NODE(&thread->node);

		/* A record that cannot be resolved through the global index
		 * must not exist: WAITFOR's strictness depends on it. */
		if (nexus_thread_index(thread) < 0) {
			kfree(thread);
			return NULL;
		}

		/* The record pins its home team so the team lock stays
		 * usable for as long as the record lives. */
		kref_get(&team->ref_count);
	}
	return thread;
}

/* Last reference gone. Takes no locks: it runs with or without the home
 * team lock held, and the record is no longer reachable. */
static void nexus_thread_destroy(struct kref* ref)
{
	struct nexus_thread* thread = container_of(ref, struct nexus_thread, ref_count);
	struct nexus_team* team = thread->team;
	struct nexus_team* home = thread->home;

	// Just in case thread was allocated and never spawned.
	if (!thread->has_thread_exited) {
		thread->has_thread_exited = true;
		if (!thread->has_return_code)
			thread->exit_status = B_ERROR;
		wake_up_all(&thread->thread_exit);
		wake_up_all(&thread->thread_suspended);
		wake_up_all(&thread->buffer_read);
		nexus_thread_release_channels(thread);
	}

	/* Retirement already erased and cleared the node; rb_erase on a
	 * cleared node corrupts the team tree. The tree holds a reference,
	 * so a linked record should never get here. */
	if (team != NULL && thread->id != team->id
			&& !RB_EMPTY_NODE(&thread->node)) {
		WARN_ON_ONCE(1);
		rb_erase(&thread->node, &team->threads);
		RB_CLEAR_NODE(&thread->node);
	}
	thread->team = NULL;
	kfree(thread->buffer);
	kfree_rcu(thread, rcu);
	nexus_team_put(home);
}

/* The tree helpers below need team->lock held by the caller. */
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
			pid_t pid = task_pid_nr(current);
			thread = nexus_thread_init(team, pid, name);
			if (thread == NULL)
				return NULL;
			rb_link_node(&thread->node, parent, p);
			rb_insert_color(&thread->node, &team->threads);
		} else {
			return NULL;
		}
    } else if (name != NULL && thread->has_thread_exited) {
        /* Re-arm is a new incarnation: a half-rearmed record keeps the old
         * exit hook and never detects the new task's exit. */
        thread->has_thread_exited = false;
        thread->has_return_code = false;
        thread->thread_resumed = false;
        thread->spawn_pending = false;
        thread->return_code = B_ERROR;
        thread->exit_status = 0;
        thread->exit_hook_installed = false;
        kfree(thread->buffer);
        thread->buffer = NULL;
        thread->buffer_ready = 0;
        thread->buffer_size = 0;
        thread->sender = -1;
        thread->unblock_code = -1;
        nexus_thread_rearm_channels(thread);
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

/* Caller holds nexus_main_lock. */
static long nexus_precreate_child_team(pid_t child_pid)
{
	struct pid *child_pid_struct;
	struct task_struct *child_task;
	struct task_struct *parent;
	struct nexus_team *child_team;
	bool is_child;
	long ret;

	if (child_pid <= 0 || child_pid == current->pid) {
		pr_warn_ratelimited("nexus: REGISTER: bogus pid=%d from tgid=%d\n",
			child_pid, current->tgid);
		return B_BAD_THREAD_ID;
	}

	child_pid_struct = find_get_pid(child_pid);
	child_task = get_pid_task(child_pid_struct, PIDTYPE_PID);
	put_pid(child_pid_struct);

	if (child_task == NULL) {
		pr_warn_ratelimited("nexus: REGISTER: pid=%d gone before registration\n",
			child_pid);
		return B_BAD_THREAD_ID;
	}

	rcu_read_lock();
	parent = rcu_dereference(child_task->real_parent);
	is_child = (parent != NULL) && (parent->tgid == current->tgid);
	rcu_read_unlock();

	if (!is_child) {
		pr_warn_ratelimited("nexus: REGISTER: pid=%d is not a child of tgid=%d\n",
			child_pid, current->tgid);
		put_task_struct(child_task);
		return B_BAD_THREAD_ID;
	}

	child_team = nexus_team_peek(child_task->tgid);
	if (child_team != NULL) {
		/* REGISTER of a load_image child whose team was already
		 * created (child opened nexus first): still park it. */
		mutex_lock(&child_team->lock);
		if (child_team->main_thread != NULL)
			child_team->main_thread->spawn_pending = true;
		mutex_unlock(&child_team->lock);
		put_task_struct(child_task);
		return child_pid;
	}

	child_team = nexus_team_init_for(child_task->tgid);
	if (child_team == NULL) {
		put_task_struct(child_task);
		return B_NO_MEMORY;
	}

	child_team->open_count = 0;

	mutex_lock(&child_team->lock);

	/* load_image children park in CLONE_EXECUTED until resume_thread();
	 * mark the pre-created main record so the park still happens. */
	if (child_team->main_thread != NULL)
		child_team->main_thread->spawn_pending = true;

	/* The pre-created team holds no fd of its own: without an exit hook
	 * its orphan cleanup (nexus_thread_exit_work) can never run, and a
	 * child that dies before its first open() leaves a stale
	 * pre-registration behind (the PR #47 hang). Arming the hook ties the
	 * team's lifetime to the child's lifetime. */
	if (child_team->main_thread != NULL
			&& child_task->pid == child_task->tgid)
		nexus_thread_arm_exit_or_finish(child_team->main_thread,
			child_task);

	mutex_unlock(&child_team->lock);

	ret = child_pid;
	put_task_struct(child_task);
	return ret;
}

/* Resolve a target tid to its record, with a reference. Native threads are
 * registered before their id can be known (REGISTER, or the thread's own
 * first call), so the index lookup hits and nothing below runs for them. A
 * thread nexus has not met yet (created outside libroot2, or a fork child
 * before its first open()) is registered on first contact, if it is alive
 * and nexus-aware: a thread of a process that opened nexus, or a child
 * process of the caller, whose team is then pre-created unless
 * own_team_only is set. Anything else is unknown. The first-contact path
 * spans the team table, the thread index and a team tree, so it runs under
 * nexus_main_lock. The caller must hold no team lock. */
static struct nexus_thread *nexus_resolve_thread(pid_t tid, bool own_team_only)
{
	struct nexus_thread *thread;
	struct nexus_team *owner;
	struct task_struct *task;
	struct pid *pid_ref;

	if (tid <= 0)
		return NULL;

	thread = nexus_thread_lookup(tid);
	if (thread != NULL)
		return thread;

	pid_ref = find_get_pid(tid);
	task = get_pid_task(pid_ref, PIDTYPE_PID);
	put_pid(pid_ref);
	if (task == NULL)
		return NULL;

	if (own_team_only && task->tgid != current->tgid) {
		put_task_struct(task);
		return NULL;
	}

	mutex_lock(&nexus_main_lock);

	owner = nexus_team_peek(task->tgid);
	if (owner == NULL && task->pid == task->tgid
			&& nexus_precreate_child_team(tid) == tid)
		owner = nexus_team_peek(task->tgid);

	if (owner != NULL) {
		mutex_lock(&owner->lock);
		if (task->pid == owner->id) {
			thread = owner->main_thread;
		} else {
			thread = register_thread(owner, tid);
			if (thread != NULL)
				nexus_thread_arm_exit_or_finish(thread, task);
		}
		if (thread != NULL)
			kref_get(&thread->ref_count);
		mutex_unlock(&owner->lock);
	}

	mutex_unlock(&nexus_main_lock);

	put_task_struct(task);
	return thread;
}

/* Find the record of a live task: through its team first, then through
 * first contact. Returns a reference. The caller holds no team lock. */
static struct nexus_thread *nexus_thread_get_for_task(struct task_struct *task,
	pid_t tid)
{
	struct nexus_thread *thread = NULL;
	struct nexus_team *team;

	team = nexus_find_team(task->tgid);
	if (team != NULL) {
		mutex_lock(&team->lock);
		if (task->pid == team->id)
			thread = team->main_thread;
		else
			thread = find_thread_by_id(team, tid);
		if (thread != NULL)
			kref_get(&thread->ref_count);
		mutex_unlock(&team->lock);
		nexus_team_put(team);
	}
	if (thread == NULL)
		thread = nexus_resolve_thread(tid, false);
	return thread;
}

/* The cross-thread commands below run with no team lock held: they look
 * up another thread's record (possibly in another team), pin it with a
 * reference and take that record's home team lock only while touching it. */

static long nexus_thread_do_write(unsigned long arg)
{
	struct nexus_thread_rw user_data;
	struct nexus_thread *dest = NULL;
	struct nexus_team *dteam;
	struct pid *pid_ref;
	struct task_struct *task;
	void *kbuf;
	int sem_ret;
	int32_t status;

	if (copy_from_user(&user_data, (struct __user nexus_thread_rw*)arg,
			sizeof(user_data)))
		return -EFAULT;

	do {
		pid_ref = find_get_pid((pid_t)user_data.receiver);
		task = get_pid_task(pid_ref, PIDTYPE_PID);
		put_pid(pid_ref);
		if (task == NULL) { status = B_BAD_THREAD_ID; break; }
		dest = nexus_thread_get_for_task(task, (pid_t)user_data.receiver);
		put_task_struct(task);
		if (dest == NULL) { status = B_BAD_THREAD_ID; break; }

		dteam = dest->home;

		if (user_data.size > PORT_MAX_MESSAGE_SIZE)
			kbuf = NULL;
		else
			kbuf = kmalloc(user_data.size, GFP_KERNEL);
		if (kbuf == NULL) {
			status = B_NO_MEMORY;
			kref_put(&dest->ref_count, nexus_thread_destroy);
			break;
		}
		if (copy_from_user(kbuf, user_data.buffer, user_data.size)) {
			kfree(kbuf);
			status = B_BAD_VALUE;
			kref_put(&dest->ref_count, nexus_thread_destroy);
			break;
		}

		sem_ret = down_interruptible(&dest->sem_write);

		mutex_lock(&dteam->lock);
		if (dest->team == NULL) {
			/* Retired while we slept. */
			if (!sem_ret)
				up(&dest->sem_write);
			kfree(kbuf);
			status = B_BAD_THREAD_ID;
		} else if (sem_ret) {
			kfree(kbuf);
			status = B_INTERRUPTED;
		} else if (dest->has_thread_exited) {
			/* Dead target: exit's up() let us in, but nobody will
			 * read, and a pending slot must not be overwritten. */
			up(&dest->sem_write);
			kfree(kbuf);
			status = B_BAD_THREAD_ID;
		} else {
			dest->buffer = kbuf;
			dest->sender = current->pid;
			dest->buffer_size = user_data.size;
			dest->buffer_ready = 1;
			dest->unblock_code = user_data.return_code;
			wake_up_interruptible(&dest->buffer_read);
			up(&dest->sem_read);
			status = B_OK;
		}
		mutex_unlock(&dteam->lock);
		kref_put(&dest->ref_count, nexus_thread_destroy);
	} while (0);

	user_data.ret = status;
	if (copy_to_user((struct __user nexus_thread_rw*)arg, &user_data,
			sizeof(user_data)))
		return -EFAULT;
	return 0;
}

static long nexus_thread_do_has_data(unsigned long arg)
{
	struct nexus_thread_rw user_data;
	struct nexus_thread *dest = NULL;
	struct pid *pid_ref;
	struct task_struct *task;
	int32_t status;

	if (copy_from_user(&user_data, (struct __user nexus_thread_rw*)arg,
			sizeof(user_data)))
		return -EFAULT;

	do {
		pid_ref = find_get_pid((pid_t)user_data.receiver);
		task = get_pid_task(pid_ref, PIDTYPE_PID);
		put_pid(pid_ref);
		if (task == NULL) { status = B_BAD_THREAD_ID; break; }
		dest = nexus_thread_get_for_task(task, (pid_t)user_data.receiver);
		put_task_struct(task);
		if (dest == NULL) { status = B_BAD_THREAD_ID; break; }

		mutex_lock(&dest->home->lock);
		status = (dest->buffer_ready == 1) ? B_OK : B_WOULD_BLOCK;
		mutex_unlock(&dest->home->lock);
		kref_put(&dest->ref_count, nexus_thread_destroy);
	} while (0);

	user_data.ret = status;
	if (copy_to_user((struct __user nexus_thread_rw*)arg, &user_data,
			sizeof(user_data)))
		return -EFAULT;
	return 0;
}

static long nexus_thread_do_waitfor(struct nexus_team *team,
	unsigned long arg)
{
	struct nexus_thread_waitfor_req user_data;
	struct nexus_thread *dest = NULL;
	struct pid *pid_ref;
	struct task_struct *task;
	int wret;
	int32_t status;

	if (copy_from_user(&user_data,
			(struct __user nexus_thread_waitfor_req*)arg,
			sizeof(user_data)))
		return -EFAULT;

	do {
		if ((pid_t)user_data.receiver == current->pid) {
			status = B_BAD_THREAD_ID;
			break;
		}
		/* Registered, or registered now on first contact
		 * (nexus_resolve_thread); a tid with no record and no live
		 * task fails immediately. */
		dest = nexus_resolve_thread((pid_t)user_data.receiver, true);
		if (dest == NULL) {
			status = B_BAD_THREAD_ID;
			break;
		}

		mutex_lock(&dest->home->lock);
		if (dest->team != team) {
			/* A record of another team, or one already retired:
			 * not ours to wait on. */
			mutex_unlock(&dest->home->lock);
			kref_put(&dest->ref_count, nexus_thread_destroy);
			status = B_BAD_THREAD_ID;
			break;
		}

		/* When the target task is still alive it must share our
		 * address space. A NULL mm means the task is a zombie
		 * (already exited): the exit status is then served from its
		 * record. */
		pid_ref = find_get_pid((pid_t)user_data.receiver);
		task = get_pid_task(pid_ref, PIDTYPE_PID);
		put_pid(pid_ref);
		if (task != NULL) {
			if (task->mm != NULL && task->mm != current->mm) {
				put_task_struct(task);
				mutex_unlock(&dest->home->lock);
				kref_put(&dest->ref_count, nexus_thread_destroy);
				status = B_BAD_THREAD_ID;
				break;
			}
			put_task_struct(task);
		}

		/* Waiting on a never-resumed thread resumes it. */
		if (!dest->thread_resumed) {
			dest->thread_resumed = true;
			dest->spawn_pending = false;
			wake_up(&dest->thread_suspended);
		}
		mutex_unlock(&dest->home->lock);

		wret = wait_event_interruptible(dest->thread_exit,
			dest->has_thread_exited);

		if (wret == -ERESTARTSYS) {
			kref_put(&dest->ref_count, nexus_thread_destroy);
			status = B_INTERRUPTED;
			break;
		}
		mutex_lock(&dest->home->lock);
		user_data.return_code = dest->exit_status;
		mutex_unlock(&dest->home->lock);
		kref_put(&dest->ref_count, nexus_thread_destroy);
		status = B_OK;
	} while (0);

	user_data.ret = status;
	if (copy_to_user((struct __user nexus_thread_waitfor_req*)arg,
			&user_data, sizeof(user_data)))
		return -EFAULT;
	return 0;
}

static long nexus_thread_do_resume(unsigned long arg)
{
	thread_id tid = (thread_id)arg;
	struct nexus_thread *dest;
	struct pid *pid_ref;
	struct task_struct *task;

	if (tid < 0)
		return B_BAD_THREAD_ID;

	pid_ref = find_get_pid((pid_t)tid);
	task = get_pid_task(pid_ref, PIDTYPE_PID);
	put_pid(pid_ref);
	if (task == NULL)
		return B_BAD_THREAD_ID;

	dest = nexus_thread_get_for_task(task, (pid_t)tid);
	put_task_struct(task);
	if (dest == NULL)
		return B_BAD_THREAD_ID;

	mutex_lock(&dest->home->lock);
	if (!dest->thread_resumed) {
		dest->thread_resumed = true;
		dest->spawn_pending = false;
		wake_up(&dest->thread_suspended);
	}
	mutex_unlock(&dest->home->lock);
	kref_put(&dest->ref_count, nexus_thread_destroy);
	return B_OK;
}

/* Creator-side registration: the creator hands nexus the tid it received
 * from clone(), in the same operation that created the thread, so the
 * thread is known before its id is handed out. */
static long nexus_thread_do_register(struct nexus_team *team,
	unsigned long arg)
{
	thread_id child_tid = (thread_id)arg;
	struct pid *_pid_ref;
	struct task_struct *child_task;
	struct nexus_thread *child_record;
	struct task_struct *parent;
	bool same_mm, is_child;
	long ret;

	if (child_tid <= 0 || child_tid == current->pid)
		return B_BAD_THREAD_ID;

	_pid_ref = find_get_pid((pid_t)child_tid);
	child_task = get_pid_task(_pid_ref, PIDTYPE_PID);
	put_pid(_pid_ref);
	if (child_task == NULL) {
		/* Never created, or created, exited and fully reaped:
		 * unknown, and honestly reported. */
		return B_BAD_THREAD_ID;
	}

	/* Only the creator may register: the target must share our address
	 * space (spawn_thread-style threads) or be our direct child
	 * (fork-style). */
	rcu_read_lock();
	parent = rcu_dereference(child_task->real_parent);
	is_child = (parent != NULL) && (parent->tgid == current->tgid);
	rcu_read_unlock();
	same_mm = (child_task->mm != NULL) && (child_task->mm == current->mm);

	if (!same_mm && !is_child) {
		put_task_struct(child_task);
		return B_BAD_THREAD_ID;
	}

	/* Pre-create the child team so an early resume_thread() is not lost;
	 * its main thread is spawn_pending. Creating a team is lifecycle. */
	if (!same_mm) {
		put_task_struct(child_task);
		mutex_lock(&nexus_main_lock);
		ret = nexus_precreate_child_team((pid_t)child_tid);
		mutex_unlock(&nexus_main_lock);
		return ret;
	}

	/* Register in the caller's team, keyed by the child tid: the record
	 * outlives the child's exit (so post-mortem WAITFOR serves the real
	 * status) and no pre-created child team is needed, so nothing can go
	 * stale (the PR #47 hang is structurally absent). */
	mutex_lock(&team->lock);
	child_record = register_thread(team, (pid_t)child_tid);
	if (child_record == NULL) {
		mutex_unlock(&team->lock);
		put_task_struct(child_task);
		return B_NO_MEMORY;
	}

	/* Same-mm child is a spawn/load_image thread: park it until
	 * resume_thread(). */
	child_record->spawn_pending = true;

	/* Armed here too, so a thread killed before its SPAWN still gets its
	 * record finished. */
	nexus_thread_arm_exit_or_finish(child_record, child_task);
	mutex_unlock(&team->lock);
	put_task_struct(child_task);

	return child_tid;
}

static bool nexus_is_port_cmd(unsigned int cmd)
{
	switch (cmd) {
	case NEXUS_PORT_CREATE:
	case NEXUS_PORT_CLOSE:
	case NEXUS_PORT_DELETE:
	case NEXUS_PORT_READ:
	case NEXUS_PORT_WRITE:
	case NEXUS_PORT_INFO:
	case NEXUS_PORT_MESSAGE_INFO:
	case NEXUS_SET_PORT_OWNER:
	case NEXUS_PORT_WRITE_CAPS:
	case NEXUS_PORT_READ_CAPS:
	case NEXUS_PORT_FIND:
	case NEXUS_GET_NEXT_PORT_FOR_TEAM:
		return true;
	default:
		return false;
	}
}


static bool nexus_caller_known_in_team(struct nexus_team *team)
{
	struct nexus_thread *t;
	bool known;

	if (team->id == current->pid)
		return true;

	t = nexus_thread_lookup_rcu(current->pid);
	if (t == NULL)
		return false;

	known = READ_ONCE(t->team) == team && t->id == current->pid
		&& !READ_ONCE(t->has_thread_exited);
	kref_put(&t->ref_count, nexus_thread_destroy);
	return known;
}


static long nexus_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct nexus_team *team = filp->private_data;
	struct nexus_thread *thread = NULL;
	long ret = -1;

	if (team->id != current->tgid)
		return -EPERM;

	if (nexus_is_port_cmd(cmd) && nexus_caller_known_in_team(team))
		return nexus_port_dispatch(team, cmd, arg);

	/* Everything below first resolves the caller's own record, under the
	 * team lock; this is where a thread nexus has not met yet registers
	 * itself. */
	mutex_lock(&team->lock);

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
					mutex_unlock(&team->lock);
					return -EFAULT;
				}

				/* The creator normally registered us already
				 * (NEXUS_THREAD_REGISTER); a thread spawned
				 * outside libroot2 registers itself here. */
				if (thread == NULL || thread->id != current->pid) {
					thread = find_thread(team, spawn_data.name);
					if (thread == NULL) {
						mutex_unlock(&team->lock);
						return -ENOMEM;
					}
				} else if (spawn_data.name != NULL
						&& strncpy_from_user(thread->name,
							spawn_data.name, B_OS_NAME_LENGTH) < 0) {
					thread->name[0] = '\0';
				}
				nexus_thread_arm_exit_or_finish(thread, current);

				/* Spawned threads start suspended. */
				thread->spawn_pending = true;
				if (!thread->thread_resumed) {
					int wret;

					kref_get(&thread->ref_count);
					mutex_unlock(&team->lock);
					wret = wait_event_state(thread->thread_suspended,
						thread->thread_resumed, NEXUS_WAIT_PARK);
					mutex_lock(&team->lock);
					kref_put(&thread->ref_count, nexus_thread_destroy);
					if (wret != 0) {
						mutex_unlock(&team->lock);
						return -ERESTARTNOINTR;
					}
				}

				mutex_unlock(&team->lock);
				return B_OK;
			}

			thread = register_thread(team, current->pid);
			if (thread == NULL) {
				mutex_unlock(&team->lock);
				return -ENOMEM;
			}
		}
	}

	/* Commands that touch other threads or ports hold no team lock. */
	switch (cmd) {
	case NEXUS_THREAD_WRITE:
		mutex_unlock(&team->lock);
		return nexus_thread_do_write(arg);

	case NEXUS_THREAD_HAS_DATA:
		mutex_unlock(&team->lock);
		return nexus_thread_do_has_data(arg);

	case NEXUS_THREAD_WAITFOR:
		mutex_unlock(&team->lock);
		return nexus_thread_do_waitfor(team, arg);

	case NEXUS_THREAD_RESUME:
		mutex_unlock(&team->lock);
		return nexus_thread_do_resume(arg);

	case NEXUS_THREAD_REGISTER:
		mutex_unlock(&team->lock);
		return nexus_thread_do_register(team, arg);

	case NEXUS_PORT_CREATE:
	case NEXUS_PORT_CLOSE:
	case NEXUS_PORT_DELETE:
	case NEXUS_PORT_READ:
	case NEXUS_PORT_WRITE:
	case NEXUS_PORT_INFO:
	case NEXUS_PORT_MESSAGE_INFO:
	case NEXUS_SET_PORT_OWNER:
	case NEXUS_PORT_WRITE_CAPS:
	case NEXUS_PORT_READ_CAPS:
	case NEXUS_PORT_FIND:
	case NEXUS_GET_NEXT_PORT_FOR_TEAM:
		mutex_unlock(&team->lock);
		return nexus_port_dispatch(team, cmd, arg);

	default:
		break;
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
		struct nexus_thread *self;
		int32_t status;
		int sem_ret, wret;
		bool has_deadline = false;
		u64 deadline_ns = 0;

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
			if (user_data.buffer == NULL && user_data.size > 0) {
				status = B_BAD_VALUE;
				break;
			}
			/* Never sleep holding the team lock, or every other
			 * ioctl of the team blocks on it. */
			if ((user_data.flags & B_RELATIVE_TIMEOUT) &&
			    user_data.timeout == 0) {
				status = B_WOULD_BLOCK;
				break;
			}
			if ((user_data.flags & B_ABSOLUTE_TIMEOUT) ||
			    ((user_data.flags & B_RELATIVE_TIMEOUT) &&
			     user_data.timeout > 0 &&
			     user_data.timeout != B_INFINITE_TIMEOUT)) {
				has_deadline = true;
				if (user_data.flags & B_ABSOLUTE_TIMEOUT)
					deadline_ns = (u64)user_data.timeout * 1000ULL;
				else
					deadline_ns = ktime_get_boottime_ns() +
						(u64)user_data.timeout * 1000ULL;
			}

			/* Finished record with no pending slot: reject
			 * instead of waiting forever. */
			if (thread->has_thread_exited &&
			    thread->buffer_ready == 0) {
				status = B_BAD_THREAD_ID;
				break;
			}

			self = thread;
			kref_get(&self->ref_count);
			mutex_unlock(&team->lock);
			if (has_deadline) {
				u64 now = ktime_get_boottime_ns();

				/* down_timeout() takes relative jiffies. */
				if (now >= deadline_ns)
					sem_ret = -ETIME;
				else
					sem_ret = down_timeout(&self->sem_read,
						max_t(long, 1,
							nsecs_to_jiffies(deadline_ns - now)));
			} else {
				sem_ret = down_interruptible(&self->sem_read);
			}
			mutex_lock(&team->lock);
			if (kref_put(&self->ref_count, nexus_thread_destroy)) {
				status = B_BAD_THREAD_ID;
				break;
			}
			if (sem_ret) {
				/* Never took the count. */
				if (sem_ret == -ETIME)
					status = B_TIMED_OUT;
				else
					status = B_INTERRUPTED;
				break;
			}
			/* Took sem_read. Record may have been recycled or
			 * exited while the lock was dropped. */
			if (self->id != current->pid ||
			    (self->has_thread_exited &&
			     self->buffer_ready == 0)) {
				up(&self->sem_read);
				status = B_BAD_THREAD_ID;
				break;
			}
			mutex_unlock(&team->lock);
			if (has_deadline) {
				u64 now = ktime_get_boottime_ns();

				/* Relative, and interruptible so the freezer
				 * can still stop us. */
				if (now >= deadline_ns) {
					wret = -ETIME;
				} else {
					wret = wait_event_interruptible_hrtimeout(
						self->buffer_read,
						self->buffer_ready != 0
							|| self->has_thread_exited,
						ns_to_ktime(deadline_ns - now));
				}
			} else {
				wret = wait_event_interruptible(self->buffer_read,
					self->buffer_ready != 0
						|| self->has_thread_exited);
			}
			mutex_lock(&team->lock);
			if (self->id != current->pid) {
				up(&self->sem_read);
				status = B_BAD_THREAD_ID;
				break;
			}
			if (self->has_thread_exited &&
			    self->buffer_ready == 0) {
				up(&self->sem_read);
				status = B_BAD_THREAD_ID;
				break;
			}
			if (wret != 0 && self->buffer_ready == 0) {
				/* A signal or the freezer, before any data: give
				 * sem_read back, as the sender would have. */
				up(&self->sem_read);
				if (wret == -ETIME)
					status = B_TIMED_OUT;
				else
					status = B_INTERRUPTED;
				break;
			}
			if (self->buffer == NULL) {
				/* Flag set without a buffer: drop the slot and
				 * release the writer so the channel is not wedged. */
				self->buffer_ready = 0;
				self->sender = -1;
				self->unblock_code = -1;
				up(&self->sem_write);
				up(&self->sem_read);
				status = B_BAD_VALUE;
				break;
			}
			{
				void *kbuf = self->buffer;
				size_t kbuf_size = self->buffer_size;

				user_data.sender = self->sender;
				user_data.return_code = self->unblock_code;
				self->buffer = NULL;
				self->buffer_size = 0;
				self->buffer_ready = 0;
				self->sender = -1;
				self->unblock_code = -1;
				up(&self->sem_write);
				mutex_unlock(&team->lock);

				user_data.size = min_t(size_t, user_data.size, kbuf_size);
				if (copy_to_user(user_data.buffer, kbuf, user_data.size))
					user_data.ret = B_BAD_VALUE;
				else
					user_data.ret = B_OK;
				kfree(kbuf);

				if (copy_to_user((struct __user nexus_thread_rw*)arg,
						&user_data, sizeof(user_data)))
					return -EFAULT;
				return 0;
			}
		} while (0);
		user_data.ret = status;
		if (copy_to_user((struct __user nexus_thread_rw*)arg, &user_data,
				sizeof(user_data)))
			ret = -EFAULT;
		else
			ret = 0;
		break;
	}

	case NEXUS_THREAD_CLONE_EXECUTED:
		/* Only load_image children call this, as their team's main
		 * thread. One can get here before its creator's REGISTER (one
		 * CPU), so it marks itself pending like a spawned thread. */
		if (!thread->thread_resumed && !thread->spawn_pending) {
			if (current->pid != current->tgid) {
				ret = B_BAD_THREAD_ID;
				break;
			}
			thread->spawn_pending = true;
		}
		if (!thread->thread_resumed) {
			int wret;

			kref_get(&thread->ref_count);
			mutex_unlock(&team->lock);
			wret = wait_event_state(thread->thread_suspended,
				thread->thread_resumed, NEXUS_WAIT_PARK);
			mutex_lock(&team->lock);
			kref_put(&thread->ref_count, nexus_thread_destroy);
			if (wret != 0) {
				mutex_unlock(&team->lock);
				return -ERESTARTNOINTR;
			}
		}

		mutex_unlock(&team->lock);
		return current->pid;

	case NEXUS_THREAD_SET_RETURN_CODE:
		thread->exit_status = (int32_t)(long)arg;
		thread->has_return_code = true;
		ret = B_OK;
		break;

	default:
		break;
	}

	mutex_unlock(&team->lock);
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

	if (current->pid == team->id) {
		mutex_lock(&team->lock);
		nexus_thread_arm_exit_or_finish(team->main_thread, current);
		mutex_unlock(&team->lock);
	}
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

	int ret = nexus_port_proc_init();
	if (ret < 0) {
		pr_err("nexus: failed to init /proc/nexus: %d\n", ret);
		goto error;
	}

	ret = nexus_vref_init();
	if (ret < 0) {
		pr_err("nexus: failed to init vref: %d\n", ret);
		nexus_port_proc_exit();
		goto error;
	}

	for_each_kernel_tracepoint(nexus_find_exit_tp, &nexus_exit_tp);
	ret = nexus_exit_tp != NULL
		? tracepoint_probe_register(nexus_exit_tp, nexus_exit_probe, NULL)
		: -ENOENT;
	if (ret < 0) {
		pr_err("nexus: cannot hook sched_process_exit: %d\n", ret);
		nexus_vref_exit();
		nexus_port_proc_exit();
		goto error;
	}

	printk(KERN_INFO "nexus: loaded (creator registration, exit via sched_process_exit)\n");
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
	nexus_port_proc_exit();
	nexus_cleanup_dev(1);
	printk(KERN_INFO "nexus: unloaded\n");
}



module_init(nexus_init);
module_exit(nexus_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dario Casalinuovo");
MODULE_DESCRIPTION("Nexus IPC");
MODULE_VERSION("0.7");
