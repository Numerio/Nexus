// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026 Dario Casalinuovo
 */

#include "nexus.h"
#include "vref.h"

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/signal.h>
#include <linux/task_work.h>
#include <linux/wait.h>

#include "errors.h"
#include "nexus_private.h"

#define DEV_NAME "nexus"

static dev_t major = 0;

uint64_t nexus_core_dev(void)
{
	// Userspace stat() encodes dev_t differently from kernel MKDEV
	// (glibc: (major<<8)|minor, kernel: major<<MINORBITS|minor).
	// Convert so the value we stamp into kmsgs matches st_rdev seen
	// by libroot's get_vref_dev() (fstat of /dev/nexus).
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

struct nexus_team* nexus_find_team(int32_t id)
{
	return idr_find(&nexus_teams_idr, id);
}
EXPORT_SYMBOL(nexus_find_team);

// TODO make non-exported functions static
// TODO fine-grained locking through spinlocks
// TODO per-team lock


static void nexus_thread_exit_work(struct callback_head *head)
{
	struct nexus_thread *thread = container_of(head, struct nexus_thread, exit_work);

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

	kref_put(&thread->ref_count, nexus_thread_destroy);
	mutex_unlock(&nexus_main_lock);
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

struct nexus_team* nexus_team_init()
{
	struct nexus_team *t = idr_find(&nexus_teams_idr, current->tgid);
	if (t != NULL) {
		t->open_count++;
		pr_debug("nexus: tgid=%d open_count=%d (reuse)\n",
			current->tgid, t->open_count);
		return t;
	}

	struct nexus_team* team = kzalloc(sizeof(struct nexus_team), GFP_KERNEL);
	if (team != NULL) {
		team->id = current->group_leader->pid;
		team->open_count = 1;
		team->main_thread = nexus_thread_init(team, team->id, NULL);

		if (team->main_thread == NULL) {
			kfree(team);
			return NULL;
		}

		strncpy(team->main_thread->name, "main", 4);
		team->ports = RB_ROOT;
		team->threads = RB_ROOT;

		hlist_add_head(&team->node, &nexus_teams);
		if (idr_alloc(&nexus_teams_idr, team, team->id, team->id + 1,
				GFP_KERNEL) < 0) {
			pr_warn("nexus: idr_alloc failed for team %d\n", team->id);
		}
		pr_debug("nexus: tgid=%d new team\n", current->tgid);
	}
	return team;
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
		kref_put(&thread->ref_count, nexus_thread_destroy);
	}

	team->main_thread->team = NULL;
	kref_put(&team->main_thread->ref_count, nexus_thread_destroy);
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
		thread->thread_resumed = false;
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
	}

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

static long nexus_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct nexus_team *team = filp->private_data;
	struct nexus_thread *thread = NULL;
	struct nexus_team *iter_team = NULL;
	struct nexus_thread *dest_thread = NULL;
	struct task_struct *task = NULL;
	long ret = -1;

	mutex_lock(&nexus_main_lock);

	// Forked child didn't respect rules.
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
		if (thread == NULL || thread->id != current->pid) {
			if (cmd == NEXUS_THREAD_SPAWN) {
				struct nexus_thread_spawn spawn_data;
				if (copy_from_user(&spawn_data,
					(struct __user nexus_thread_spawn *)arg,
					sizeof(spawn_data)) != 0) {
					mutex_unlock(&nexus_main_lock);
					return -EFAULT;
				}

				struct nexus_thread *self_new =
					nexus_thread_spawn(team, spawn_data.name);
				ret = (self_new != NULL) ? 0 : -ENOMEM;
				if (self_new != NULL) {
					kref_get(&self_new->ref_count);
					init_task_work(&self_new->exit_work,
						nexus_thread_exit_work);
					if (task_work_add(current, &self_new->exit_work,
							TWA_NONE) != 0)
						kref_put(&self_new->ref_count,
							nexus_thread_destroy);
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
						dest_thread = find_thread_by_id(iter_team,
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

				dest_thread->child_thread = current->pid;
				dest_thread->thread_wait_newborn = true;

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

			mutex_unlock(&nexus_main_lock);
			return -ENOMEM;
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
			struct nexus_team *wf_team;
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
				_pid_ref = find_get_pid((pid_t)user_data.receiver);
				task = get_pid_task(_pid_ref, PIDTYPE_PID);
				put_pid(_pid_ref);
				if (task == NULL) { status = B_BAD_THREAD_ID; break; }
				if (task->mm != current->mm) {
					put_task_struct(task);
					status = B_BAD_THREAD_ID;
					break;
				}
				wf_team = idr_find(&nexus_teams_idr, task->tgid);
				if (wf_team != NULL) {
					if (task->pid == wf_team->id)
						dest_thread = wf_team->main_thread;
					else
						dest_thread = find_thread_by_id(wf_team,
							user_data.receiver);
				}
				put_task_struct(task);
				if (dest_thread == NULL) {
					status = B_BAD_THREAD_ID;
					break;
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
			if (!thread->thread_wait_newborn) {
				kref_get(&thread->ref_count);
				mutex_unlock(&nexus_main_lock);
				ret = wait_event_interruptible(thread->thread_has_newborn,
										   thread->thread_wait_newborn);
				mutex_lock(&nexus_main_lock);

				if (ret == -ERESTARTSYS) {
					kref_put(&thread->ref_count, nexus_thread_destroy);
					ret = B_INTERRUPTED;
					break;
				}
				kref_put(&thread->ref_count, nexus_thread_destroy);
			}

			thread->thread_wait_newborn = false;
			ret = thread->child_thread;
			thread->child_thread = 0;
			goto exit;

		case NEXUS_THREAD_CLONE_EXECUTED:
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
			if (iter_team != NULL) {
				dest_thread = find_thread_by_id(iter_team, parent_tid);
				if (dest_thread == NULL)
					dest_thread = iter_team->main_thread;
			}

			if (dest_thread == NULL) {
				mutex_unlock(&nexus_main_lock);
				return B_BAD_THREAD_ID;
			}

			dest_thread->child_thread = current->pid;
			dest_thread->thread_wait_newborn = true;

			kref_get(&dest_thread->ref_count);
			mutex_unlock(&nexus_main_lock);
			wake_up(&dest_thread->thread_has_newborn);
			mutex_lock(&nexus_main_lock);
			kref_put(&dest_thread->ref_count, nexus_thread_destroy);

			if (arg == 0 && !thread->thread_resumed) {
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
	mutex_unlock(&nexus_main_lock);

	if (team->open_count == 1) {
		kref_get(&team->main_thread->ref_count);
		init_task_work(&team->main_thread->exit_work, nexus_thread_exit_work);
		if (task_work_add(current, &team->main_thread->exit_work, TWA_NONE) != 0) {
			kref_put(&team->main_thread->ref_count, nexus_thread_destroy);
		}
	}

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

	printk(KERN_INFO "nexus: loaded\n");
	return 0;

error:
	nexus_cleanup_dev(device_created);
	return ret < 0 ? ret : -ENOMEM;
}

static void nexus_exit(void)
{
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
