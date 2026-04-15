// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026 Dario Casalinuovo
 */

#include "nexus.h"

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

static int major = -1;
static struct cdev nexus_cdev;
static struct class *nexus_class = NULL;

DEFINE_MUTEX(nexus_main_lock);
HLIST_HEAD(nexus_teams);

DEFINE_IDR(nexus_port_idr);

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

struct nexus_team* nexus_team_init()
{
	struct nexus_team* team = kzalloc(sizeof(struct nexus_team), GFP_KERNEL);
	if (team != NULL) {
		team->id = current->group_leader->pid;
		team->main_thread = nexus_thread_init(team, team->id, NULL);

		if (team->main_thread == NULL) {
			kfree(team);
			return NULL;
		}

		strncpy(team->main_thread->name, "main", 4);
		team->ports = RB_ROOT;
		team->threads = RB_ROOT;

		hlist_add_head(&team->node, &nexus_teams);
	}
	return team;
}

void nexus_team_destroy(struct nexus_team *team)
{
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
	hlist_del(&team->node);
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

struct nexus_thread* find_thread(struct nexus_team *team, const char *name) {
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

struct nexus_thread* find_thread_by_id(struct nexus_team *team, int32_t pid) {
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

static long nexus_thread_spawn(struct nexus_team *team, const char* name)
{
	find_thread(team, name);
	return 0;
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

				ret = nexus_thread_spawn(team, spawn_data.name);

				struct nexus_thread *self_new =
					find_thread_by_id(team, current->pid);
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

				hlist_for_each_entry(iter_team, &nexus_teams, node) {
					if (task->pid == iter_team->id) {
						dest_thread = iter_team->main_thread;
						break;
					} else if (task->tgid == iter_team->id) {
						dest_thread = find_thread_by_id(iter_team,
							 spawn_data.father);
						if (dest_thread == NULL) {
							put_task_struct(task);
							mutex_unlock(&nexus_main_lock);
							return B_BAD_THREAD_ID;
						}
						break;
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
		case NEXUS_THREAD_OP: {
			struct nexus_thread_exchange user_data;
			if (copy_from_user(&user_data, (struct __user nexus_thread_exchange*)arg,
					sizeof(user_data))) {
				ret = B_BAD_VALUE;
				break;
			}

			int32_t user_ret = B_OK;

			if (user_data.op == NEXUS_THREAD_READ) {
				if (thread->id != current->pid) {
					ret = B_BAD_THREAD_ID;
					goto exit;
				}

				down_interruptible(&thread->sem_read);

				mutex_unlock(&nexus_main_lock);
				wait_event_interruptible(thread->buffer_read, thread->buffer_ready != 0);
				mutex_lock(&nexus_main_lock);
				if (copy_to_user(user_data.buffer, thread->buffer,
						min(user_data.size, thread->buffer_size))) {
					ret = B_BAD_VALUE;
					goto exit;
				}

				user_data.sender = thread->sender;
				user_ret = thread->unblock_code;

				kfree(thread->buffer);
				thread->buffer = NULL;
				thread->buffer_size = 0;
				thread->buffer_ready = 0;
				thread->sender = -1;
				thread->unblock_code = -1;

				up(&thread->sem_write);
			} else if (user_data.op == NEXUS_THREAD_WRITE) {
				struct nexus_team *iter_team = NULL;
				struct nexus_thread *dest_thread = NULL;

				struct task_struct* task = get_pid_task(find_get_pid(
					(pid_t)user_data.receiver),PIDTYPE_PID);
				if (task == NULL) {
					ret = B_BAD_THREAD_ID;
					goto exit;
				}

				hlist_for_each_entry(iter_team, &nexus_teams, node) {
					if (task->pid == iter_team->id) {
						dest_thread = iter_team->main_thread;
						break;
					} else if (task->tgid == iter_team->id) {
						dest_thread = find_thread_by_id(iter_team, user_data.receiver);
						if (dest_thread == NULL) {
							put_task_struct(task);
							ret = B_BAD_THREAD_ID;
							goto exit;
						}
						break;
					}
				}

				if (dest_thread == NULL) {
					put_task_struct(task);
					ret = B_BAD_THREAD_ID;
					goto exit;
				}

				kref_get(&dest_thread->ref_count);
				mutex_unlock(&nexus_main_lock);
				// if -1 release the process then -ERESTARTSYS
				down_interruptible(&dest_thread->sem_write);
				mutex_lock(&nexus_main_lock);
				if (kref_put(&dest_thread->ref_count, nexus_thread_destroy)) {
					put_task_struct(task);
					ret = B_BAD_THREAD_ID;
					goto exit;
				}

				dest_thread->buffer = kzalloc(user_data.size, GFP_KERNEL);
				if (dest_thread->buffer == NULL) {
					put_task_struct(task);
					ret = B_NO_MEMORY;
					goto exit;
				}

				if (copy_from_user(dest_thread->buffer, user_data.buffer,
						user_data.size)) {
					put_task_struct(task);
					ret = B_BAD_VALUE;
					goto exit;
				}

				dest_thread->sender = current->pid;

				dest_thread->buffer_size = user_data.size;
				dest_thread->buffer_ready = 1;
				dest_thread->unblock_code = user_data.return_code;

				wake_up_interruptible(&dest_thread->buffer_read);
				up(&dest_thread->sem_read);

				put_task_struct(task);

			} else if (user_data.op == NEXUS_THREAD_HAS_DATA) {
				struct nexus_team *iter_team = NULL;
				struct nexus_thread *dest_thread = NULL;

				struct task_struct* task = get_pid_task(find_get_pid(
					(pid_t)user_data.receiver),PIDTYPE_PID);
				if (task == NULL) {
					ret = B_BAD_THREAD_ID;
					goto exit;
				}

				hlist_for_each_entry(iter_team, &nexus_teams, node) {
					if (task->pid == iter_team->id) {
						dest_thread = iter_team->main_thread;
						break;
					} else if (task->tgid == iter_team->id) {
						dest_thread = find_thread_by_id(iter_team, user_data.receiver);
						if (dest_thread == NULL) {
							put_task_struct(task);
							ret = B_BAD_THREAD_ID;
							goto exit;
						}
						break;
					}
				}

				if (dest_thread == NULL) {
					put_task_struct(task);
					ret = B_BAD_THREAD_ID;
					goto exit;
				}

				if (dest_thread->buffer_ready != 1) {
					put_task_struct(task);
					ret = B_WOULD_BLOCK;
					goto exit;
				}

				put_task_struct(task);
			} else if (user_data.op == NEXUS_THREAD_SET_NAME) {
				if (strncpy_from_user(thread->name, user_data.buffer,
						min(B_OS_NAME_LENGTH, user_data.size)) < 0) {
					ret = B_BAD_VALUE;
					goto exit;
				}
			} else if (user_data.op == NEXUS_THREAD_WAITFOR) {
				struct nexus_team *team;
				struct nexus_thread *dest_thread = NULL;
				struct task_struct* task = get_pid_task(find_get_pid(
					(pid_t)user_data.receiver), PIDTYPE_PID);

				if (task == NULL) {
					ret = B_BAD_THREAD_ID;
					goto exit;
				}
				if (task->mm != current->mm) {
					put_task_struct(task);
					ret = B_BAD_THREAD_ID;
					goto exit;
				}

				hlist_for_each_entry(team, &nexus_teams, node) {
					if (task->pid == team->id) {
						dest_thread = team->main_thread;
						break;
					} else if (task->tgid == team->id) {
						dest_thread = find_thread_by_id(team, user_data.receiver);
						break;
					}
				}

				if (dest_thread == NULL) {
					put_task_struct(task);
					ret = B_BAD_THREAD_ID;
					goto exit;
				}

				// Cache exit status while we're still alive.
				int32_t exit_status = dest_thread->exit_status;

				if (!dest_thread->has_thread_exited) {
					int wret;

					kref_get(&dest_thread->ref_count);
					mutex_unlock(&nexus_main_lock);
					wret = wait_event_interruptible(dest_thread->thread_exit,
						dest_thread->has_thread_exited);
					mutex_lock(&nexus_main_lock);

					if (wret == -ERESTARTSYS) {
						kref_put(&dest_thread->ref_count, nexus_thread_destroy);
						put_task_struct(task);
						ret = B_INTERRUPTED;
						goto exit;
					}
					exit_status = dest_thread->exit_status;
					kref_put(&dest_thread->ref_count, nexus_thread_destroy);
				}

				user_data.return_code = exit_status;
				user_ret = B_OK;

				put_task_struct(task);
			}

			if (copy_to_user((struct __user nexus_thread_exchange*)arg, &user_data,
					sizeof(user_data))) {
				ret = B_BAD_VALUE;
				break;
			}
			ret = user_ret;
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

			hlist_for_each_entry(iter_team, &nexus_teams, node) {
				if (parent_tgid == iter_team->id) {
					dest_thread = find_thread_by_id(iter_team, parent_tid);
					if (dest_thread == NULL)
						dest_thread = iter_team->main_thread;

					break;
				}
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

			task = get_pid_task(find_get_pid((pid_t)tid),
													PIDTYPE_PID);

			if (task == NULL) {
				ret = B_BAD_THREAD_ID;
				break;
			}

			hlist_for_each_entry(iter_team, &nexus_teams, node) {
				if (task->pid == iter_team->id) {
					dest_thread = iter_team->main_thread;
					break;
				} else if (task->tgid == iter_team->id) {
					dest_thread = find_thread_by_id(iter_team, tid);
					if (dest_thread == NULL) {
						ret = B_BAD_THREAD_ID;
						break;
					}
					break;
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

		case NEXUS_THREAD_EXIT:
			if (arg != 0) {
				struct nexus_thread_exchange exit_data;
				if (copy_from_user(&exit_data,
					(struct __user nexus_thread_exchange *)arg,
						sizeof(exit_data)) == 0) {
				thread->exit_status = exit_data.return_code;
				} else {
					thread->exit_status = B_OK;
				}
			} else {
				thread->exit_status = B_OK;
			}

			thread->has_thread_exited = 1;

			mutex_unlock(&nexus_main_lock);
			wake_up_interruptible(&thread->thread_exit);
			mutex_lock(&nexus_main_lock);

			kref_put(&thread->ref_count, nexus_thread_destroy);
			ret = B_OK;
			break;

		case NEXUS_PORT_CREATE:
			ret = nexus_port_init(team, arg);
			break;

		case NEXUS_PORT_OP:
			ret = nexus_port_op(team, arg);
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

	kref_get(&team->main_thread->ref_count);
	init_task_work(&team->main_thread->exit_work, nexus_thread_exit_work);
	if (task_work_add(current, &team->main_thread->exit_work, TWA_NONE) != 0) {
		kref_put(&team->main_thread->ref_count, nexus_thread_destroy);
	}

	filp->private_data = (void*)team;

	return 0;
}

static int nexus_release(struct inode *nodp, struct file *filp)
{
	struct nexus_team *team = filp->private_data;
	mutex_lock(&nexus_main_lock);
	nexus_team_destroy((struct nexus_team*)filp->private_data);
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

	printk(KERN_INFO "nexus: loaded\n");
	return 0;

error:
	nexus_cleanup_dev(device_created);
	return -1;
}

static void nexus_exit(void)
{
	nexus_cleanup_dev(1);
	printk(KERN_INFO "nexus: unloaded\n");
}

module_init(nexus_init);
module_exit(nexus_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dario Casalinuovo");
MODULE_DESCRIPTION("Nexus IPC");
MODULE_VERSION("0.7");
