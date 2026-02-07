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
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/wait.h>

#include "errors.h"
#include "nexus_private.h"

#define DEV_NAME "nexus"

static int major = -1;
static struct cdev nexus_cdev;
static struct class *nexus_class = NULL;

static DEFINE_MUTEX(nexus_main_lock);
static HLIST_HEAD(nexus_teams);

static struct nexus_port* nexus_ports[MAX_PORTS];

// TODO make non-exported functions static
// TODO use IDRs
// TODO fine-grained locking through spinlocks
// TODO per-team lock

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
	printk(KERN_INFO "team destroy");

	struct rb_node *node;
	struct nexus_port *port;
	struct nexus_thread *thread;

	node = rb_first(&team->ports);
	while (node) {
		port = rb_entry(node, struct nexus_port, node);
		node = rb_next(node);
		nexus_port_destroy(&port->ref_count);
	}

	node = rb_first(&team->threads);
	while (node) {
		thread = rb_entry(node, struct nexus_thread, node);
		node = rb_next(node);
		nexus_thread_destroy(&thread->ref_count);
	}

	nexus_thread_destroy(&team->main_thread->ref_count);
	team->main_thread = NULL;
	hlist_del(&team->node);
	kfree(team);
}

struct nexus_thread* nexus_thread_init(struct nexus_team *team, pid_t id, const char *name)
{
	printk("thread init %d", id);
	struct nexus_thread* thread = kzalloc(sizeof(struct nexus_thread), GFP_KERNEL);

	if (thread != NULL) {
		thread->id = id;

		if (name != NULL) {
			if (strncpy_from_user(
					thread->name, name, B_OS_NAME_LENGTH) < 0) {
				printk(KERN_INFO "thread_error from %d", thread->id);

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
		thread->return_code = B_ERROR;
		thread->thread_wait_newborn = false;
		thread->thread_resumed = false;
	}
	return thread;
}

void nexus_thread_destroy(struct kref* ref)
{
	struct nexus_thread* thread = container_of(ref, struct nexus_thread, ref_count);

	printk(KERN_INFO "thread_destroy %d", thread->id);

	struct nexus_team* team = thread->team;
	if (thread->id != team->id)
		rb_erase(&thread->node, &team->threads);
	kfree(thread);
	printk(KERN_INFO "thread destroy exit");
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
	if (*p == NULL && name != NULL) {
		pid_t pid = pid_nr(get_task_pid(current, PIDTYPE_PID));
		thread = nexus_thread_init(team, pid, name);
		if (thread == NULL)
			return NULL;
		rb_link_node(&thread->node, parent, p);
		rb_insert_color(&thread->node, &team->threads);
	}
	return thread;
}

struct nexus_thread* find_thread_by_id(struct nexus_team *team, int32_t pid) {
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
		else
			return thread;
	}

	return NULL;
}

static long nexus_thread_spawn(struct nexus_team *team, const char* name)
{
	find_thread(team, name);
	return 0;
}

long nexus_thread_op(struct nexus_thread *thread, unsigned long arg)
{
	struct nexus_thread_exchange user_data;
	if (copy_from_user(&user_data, (struct __user nexus_thread_exchange*)arg,
			sizeof(user_data))) {
		return B_BAD_VALUE;
	}

	int32_t user_ret = B_OK;

	if (user_data.op == NEXUS_THREAD_READ) {

		printk(KERN_INFO "thread_read %d %d %d", current->pid, thread->id, thread->unblock_code);

		if (thread->id != current->pid)
			return B_BAD_THREAD_ID;

		down_interruptible(&thread->sem_read);

		mutex_unlock(&nexus_main_lock);
		wait_event_interruptible(thread->buffer_read, thread->buffer_ready != 0);
		mutex_lock(&nexus_main_lock);

		printk(KERN_INFO "thread_read %d %d %d", current->pid, thread->id, thread->unblock_code);

		if (copy_to_user(user_data.buffer, thread->buffer,
				min(user_data.size, thread->buffer_size))) {
			return B_BAD_VALUE;
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

		printk(KERN_INFO "thread_read finish");

	} else if (user_data.op == NEXUS_THREAD_WRITE) {
		printk(KERN_INFO "thread_write from %d to %d", thread->id, user_data.receiver);

		struct nexus_team *iter_team = NULL;
		struct nexus_thread *dest_thread = NULL;

		struct task_struct* task = get_pid_task(find_get_pid(
			(pid_t)user_data.receiver),PIDTYPE_PID);
		if (task == NULL)
			return B_BAD_THREAD_ID;

		hlist_for_each_entry(iter_team, &nexus_teams, node) {
			if (task->pid == iter_team->id) {
				dest_thread = iter_team->main_thread;
				break;
			} else if (task->tgid == iter_team->id) {
				dest_thread = find_thread_by_id(iter_team, user_data.receiver);
				if (dest_thread == NULL)
					return B_BAD_THREAD_ID;
				break;
			}
		}

		if (dest_thread == NULL)
			return B_BAD_THREAD_ID;

		kref_get(&dest_thread->ref_count);
		mutex_unlock(&nexus_main_lock);
		// if -1 release the process then -ERESTARTSYS
		down_interruptible(&dest_thread->sem_write);
		mutex_lock(&nexus_main_lock);
		kref_put(&dest_thread->ref_count, nexus_thread_destroy);

		printk(KERN_INFO "thread_written from %d to %d", thread->id, dest_thread->id);

		// TODO define exact policy for retaining task structs

		if (dest_thread == NULL)
			return B_BAD_THREAD_ID;

		dest_thread->buffer = kzalloc(user_data.size, GFP_KERNEL);
		if (dest_thread->buffer == NULL)
			return B_NO_MEMORY;

		if (copy_from_user(dest_thread->buffer, user_data.buffer,
				user_data.size)) {
			return B_BAD_VALUE;
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
		if (task == NULL)
			return B_BAD_THREAD_ID;
		printk(KERN_INFO "has data %d %d\n", current->pid, user_data.return_code);

		hlist_for_each_entry(iter_team, &nexus_teams, node) {
			if (task->pid == iter_team->id) {
				dest_thread = iter_team->main_thread;
				break;
			} else if (task->tgid == iter_team->id) {
				dest_thread = find_thread_by_id(iter_team, user_data.receiver);
				if (dest_thread == NULL)
					return B_BAD_THREAD_ID;
				break;
			}
		}

		if (dest_thread == NULL) {
			put_task_struct(task);
			return B_BAD_THREAD_ID;
		}

		if (dest_thread->buffer_ready != 1) {
			put_task_struct(task);
			return B_WOULD_BLOCK;
		}

		printk(KERN_INFO "has data found %d\n", current->pid);
		put_task_struct(task);
		printk(KERN_INFO "has data exit");
	} else if (user_data.op == NEXUS_THREAD_SET_NAME) {
		if (strncpy_from_user(thread->name, user_data.buffer,
				min(B_OS_NAME_LENGTH, user_data.size)) < 0) {
			printk(KERN_INFO "set name thread_error from %d", thread->id);
			return B_BAD_VALUE;
		}
		printk(KERN_INFO "set name thread from %d set to %s", thread->id, thread->name);

	} else if (user_data.op == NEXUS_THREAD_WAITFOR) {
		struct nexus_team *team;
		struct nexus_thread *dest_thread = NULL;
		struct task_struct* task = get_pid_task(find_get_pid(
			(pid_t)user_data.receiver), PIDTYPE_PID);

		if (task == NULL || (task->mm != current->mm))
			return B_BAD_THREAD_ID;

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
			return B_BAD_THREAD_ID;
		}

		printk(KERN_INFO "thread %d waitfor %d (exited=%d)", 
			thread->id, dest_thread->id, dest_thread->has_thread_exited);

		if (!dest_thread->has_thread_exited) {
			int ret;
			
			kref_get(&dest_thread->ref_count);
			mutex_unlock(&nexus_main_lock);
			ret = wait_event_interruptible(dest_thread->thread_exit,
				dest_thread->has_thread_exited);
			mutex_lock(&nexus_main_lock);
			
			if (ret == -ERESTARTSYS) {
				kref_put(&dest_thread->ref_count, nexus_thread_destroy);
				put_task_struct(task);
				return B_INTERRUPTED;
			}
			
			kref_put(&dest_thread->ref_count, nexus_thread_destroy);
		}

		user_data.return_code = dest_thread->exit_status;
		user_ret = B_OK;
		
		put_task_struct(task);
		printk(KERN_INFO "thread %d waitfor %d complete, exit_status=%d", 
			thread->id, dest_thread->id, dest_thread->exit_status);
	}

	if (copy_to_user((struct __user nexus_thread_exchange*)arg, &user_data,
			sizeof(user_data))) {
		return B_BAD_VALUE;
	}

	printk(KERN_INFO "return %d", current->pid);
	return user_ret;
}

long nexus_port_find(unsigned long arg)
{
	char name[B_OS_NAME_LENGTH];

	struct nexus_port_exchange in_data;

	if (copy_from_user(&in_data, (struct __user nexus_port_exchange*)arg,
			sizeof(in_data))) {
		return B_BAD_VALUE;
	}

	if (in_data.buffer == NULL) {
		return B_BAD_VALUE;	
	}

	if (copy_from_user(name, in_data.buffer,
			min(in_data.size, (size_t) B_OS_NAME_LENGTH))) {
		return B_BAD_VALUE;
	}

	in_data.id = B_ERROR;

	for (int i = 0; i < MAX_PORTS; i++) {
		if (nexus_ports[i] != NULL) {
			printk(KERN_INFO "find_port %s %s\n", name, nexus_ports[i]->name);
			if (strcmp(nexus_ports[i]->name, name) == 0) {
				in_data.id = nexus_ports[i]->id;
				break;
			}
		}
	}

	if (copy_to_user((struct __user nexus_port_exchange*)arg, &in_data,
			sizeof(in_data))) {
		return B_BAD_VALUE;
	}

	return 0;
}

long nexus_port_init(struct nexus_team* team, unsigned long arg)
{
	int32_t id = 0;
	struct nexus_port *port = NULL;

	struct nexus_port *next_port = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = NULL;

	struct nexus_port_exchange in_data;
	struct nexus_port_exchange out_data;

	if (copy_from_user(&in_data, (struct __user nexus_port_exchange*)arg,
			sizeof(in_data))) {
		return B_BAD_VALUE;
	}

	if (in_data.cookie < 0 || in_data.cookie > PORT_MAX_QUEUE
			|| in_data.size > B_OS_NAME_LENGTH
				|| in_data.buffer == NULL) {
		return B_BAD_VALUE;
	}

	while (nexus_ports[id] != NULL && id < MAX_PORTS)
		id++;

	printk(KERN_INFO "Allocated port id %d\n", id);

	if (id >= MAX_PORTS) {
		return B_NO_MORE_PORTS;
	}

	port = kzalloc(sizeof(struct nexus_port), GFP_KERNEL);

	kref_init(&port->ref_count);

	init_waitqueue_head(&port->buffer_read);
	init_waitqueue_head(&port->buffer_write);

	port->write_count = in_data.cookie;
	port->is_open = true;

	port->id = id;
	port->capacity = in_data.cookie;
	port->team = team;

	INIT_LIST_HEAD(&port->queue);

	// TODO check size
	if (copy_from_user(port->name, in_data.buffer, min(in_data.size,
			(size_t)B_OS_NAME_LENGTH))) {
		return B_BAD_VALUE;
	}

	// TODO we should pubblish info about a port in /proc/
	// TODO utility functions for adding ports
	p = &team->ports.rb_node;
	while (*p) {
		parent = *p;
		next_port = rb_entry(parent, struct nexus_port, node);

		if (port->id > next_port->id)
			p = &(*p)->rb_right;
		else if (port->id < next_port->id)
			p = &(*p)->rb_left;
		else
			break;
	}
	if (*p == NULL) {
		rb_link_node(&port->node, parent, p);
		rb_insert_color(&port->node, &team->ports);
	}

	rwlock_init(&port->rw_lock);

	nexus_ports[id] = port;

	printk(KERN_INFO "initialized port id %d\n", id);

	out_data.id = id;

	if (copy_to_user((struct __user nexus_port_exchange*)arg, &out_data,
			sizeof(out_data))) {
		return B_BAD_VALUE;
	}

	return 0;
}

long nexus_port_close(struct nexus_port* port)
{
	port->is_open = false;

	mutex_unlock(&nexus_main_lock);
	wake_up_interruptible(&port->buffer_write);
	wake_up_interruptible(&port->buffer_read);
	mutex_lock(&nexus_main_lock);

	return B_OK;
}

void nexus_port_destroy(struct kref* ref)
{
	struct nexus_port* port = container_of(ref, struct nexus_port, ref_count);

	printk(KERN_INFO "Port destroy enter %d owned by %d\n", port->id, port->team->id);
	nexus_ports[port->id] = NULL;

	if (port->is_open)
		nexus_port_close(port);

	write_lock(&port->rw_lock);
	rb_erase(&port->node, &port->team->ports);
	write_unlock(&port->rw_lock);

	kfree(port);
}

long nexus_set_port_owner(struct nexus_port* port, pid_t target_team)
{
	//printk(KERN_INFO "Set port owner %d\n", port->id);

	struct nexus_team* dest_team = NULL;
	struct nexus_port *next_port = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = NULL;

	// TODO just like the port init we want to reduce code duplication here
	hlist_for_each_entry(dest_team, &nexus_teams, node) {
		if (dest_team->id == target_team) {
			rb_erase(&port->node, &port->team->ports);
			
			p = &dest_team->ports.rb_node;
			while (*p) {
				parent = *p;
				next_port = rb_entry(parent, struct nexus_port, node);

				if (port->id > next_port->id)
					p = &(*p)->rb_right;
				else if (port->id < next_port->id)
					p = &(*p)->rb_left;
				else
					break;
			}
			if (*p == NULL) {
				rb_link_node(&port->node, parent, p);
				rb_insert_color(&port->node, &dest_team->ports);
				port->team = dest_team;
				return B_OK;
			}
		}
	}

	printk(KERN_INFO "Set port owner %d exit\n", port->id);
	return B_ERROR;
}

long nexus_port_read(struct nexus_port* port, int32_t* code, void* buffer,
	size_t* size, uint32_t flags, int64_t timeout)
{
	struct nexus_buffer* buf = NULL;
	int ret = 0;

	//printk(KERN_INFO "port_read enter %d\n", port->id);

	if ((buffer == NULL && *size > 0)
			|| *size > PORT_MAX_MESSAGE_SIZE || timeout < 0) {
		return B_BAD_VALUE;
	}

	if (nexus_ports[port->id] == NULL || (!port->is_open && port->read_count == 0)) {
		return B_BAD_PORT_ID;
	}

	// TODO we are not really supporting absolute timeout
	// even if not documented it is probably required
	flags &= B_RELATIVE_TIMEOUT | B_ABSOLUTE_TIMEOUT;

	while (port->read_count == 0) {
		if ((flags & B_RELATIVE_TIMEOUT) != 0 && timeout <= 0) {
			return B_WOULD_BLOCK;
		}

		kref_get(&port->ref_count);
		int32_t port_id = port->id;
		mutex_unlock(&nexus_main_lock);
		if (flags & B_TIMEOUT && timeout != B_INFINITE_TIMEOUT) {
			ret = wait_event_interruptible_hrtimeout(port->buffer_read,
				port->read_count > 0 || port->is_open == false,
					timeout*1000);
		} else {
			ret = wait_event_interruptible(port->buffer_read,
				port->read_count > 0 || port->is_open == false);
		}
		mutex_lock(&nexus_main_lock);
		kref_put(&port->ref_count, nexus_port_destroy);

		if (nexus_ports[port_id] == NULL
				|| (!port->is_open && port->read_count == 0)
					|| ret == -ERESTARTSYS) {
			return B_BAD_PORT_ID;
		}

		if (flags & B_TIMEOUT && ret == -ETIME) {
			return B_TIMED_OUT;
		} else  if (ret == 0 || ret == -ETIME) {
			break;
		}
	}

	buf = list_first_entry_or_null(&port->queue, struct nexus_buffer, node);
	if (buf == NULL) {
		return B_BAD_VALUE;
	}

	if (buf->buffer != NULL) {
		if (copy_to_user(buffer, buf->buffer, min(buf->size, *size))) {
			return B_BAD_VALUE;
		}
		*size = buf->size;
	}

	if (code != NULL) {
		if (copy_to_user(code, &buf->code, sizeof(code))) {
			return B_BAD_VALUE;
		}
	}

	port->read_count--;
	port->write_count++;
	port->total_count++;

	wake_up_interruptible(&port->buffer_write);

	list_del(&buf->node);
	kfree(buf->buffer);
	kfree(buf);

	//printk(KERN_INFO "port_read %d: finish now write count is %d and "
	//	"read count is %d\n", port->id, port->write_count,
	//		port->read_count);

	return B_OK;
}

long nexus_port_write(struct nexus_port* port, int32_t* msg_code,
	const void* buffer, size_t size, uint32_t flags, int64_t timeout)
{
	struct nexus_buffer* buf = 0;
	int ret = 0;

	if ((buffer == NULL && size != 0) || size > PORT_MAX_MESSAGE_SIZE
			|| timeout < 0) {
		return B_BAD_VALUE;
	}

	flags &= B_RELATIVE_TIMEOUT | B_ABSOLUTE_TIMEOUT;

	if (!port->is_open) {
		return B_BAD_PORT_ID;
	}

	port->write_count--;
	
	if (port->write_count >= 0)
		goto goahead;

	while (port->write_count <= 0) {
		if ((flags & B_RELATIVE_TIMEOUT) != 0 && timeout <= 0) {
			port->write_count++;
			return B_WOULD_BLOCK;
		}

		int32_t port_id = port->id;
		kref_get(&port->ref_count);
		mutex_unlock(&nexus_main_lock);
		if (flags & B_TIMEOUT && timeout != B_INFINITE_TIMEOUT) {
			ret = wait_event_interruptible_hrtimeout(port->buffer_write,
				port->write_count >= 0 || port->is_open == false,
					timeout*1000);
		} else {
			ret = wait_event_interruptible(port->buffer_write,
				port->write_count >= 0 || port->is_open == false);
		}
		mutex_lock(&nexus_main_lock);
		kref_put(&port->ref_count, nexus_port_destroy);

		if (nexus_ports[port_id] == NULL) {
			return B_BAD_PORT_ID;
		}

		if (!port->is_open || ret == -ERESTARTSYS) {
			port->write_count++;
			return B_BAD_PORT_ID;
		}

		if (flags & B_TIMEOUT && ret == -ETIME) {
			port->write_count++;
			return B_TIMED_OUT;
		} else if (ret == 0) {
			break;
		}
	}

goahead:
	buf = kzalloc(sizeof(struct nexus_buffer), GFP_KERNEL);

	if (buffer != NULL) {
		buf->buffer = kzalloc(size, GFP_KERNEL);
		if (copy_from_user(buf->buffer, buffer, size)) {
			kfree(buf);
			kfree(buf->buffer);
			
			port->write_count++;
			return B_BAD_VALUE;
		}
		buf->size = size;
	} else 
		buf->buffer = NULL;

	if (copy_from_user(&buf->code, msg_code, sizeof(*msg_code))) {
		kfree(buf->buffer);
		kfree(buf);

		port->write_count++;
		return B_BAD_VALUE;
	}

	list_add_tail(&buf->node, &port->queue);
	port->read_count++;

	wake_up_interruptible(&port->buffer_read);

	//printk(KERN_INFO "port_write %d finish now write count is %d and "
	//	"read count is %d\n", port->id, port->write_count,
	//		port->read_count);

	return B_OK;
}

status_t nexus_write_port(uint32_t id, int32_t code, const void *buffer,
	size_t buffer_size)
{
	mutex_lock(&nexus_main_lock);

	struct nexus_port* port = nexus_ports[id];	
	if (port == NULL) {
		return B_BAD_PORT_ID;
	}

	long ret = nexus_port_write(port, &code, buffer, buffer_size, 0, B_INFINITE_TIMEOUT);
	mutex_unlock(&nexus_main_lock);
	return ret;
}

EXPORT_SYMBOL(nexus_write_port);

long nexus_port_info(struct nexus_port* port, struct nexus_port_info* info)
{
	struct nexus_port_info message_info;

	memset(&message_info, 0, sizeof(message_info));

	if (info == NULL) {
		return B_BAD_VALUE;
	}

	if (nexus_ports[port->id] == NULL
			|| (!port->is_open && port->read_count == 0)) {
		return B_BAD_PORT_ID;
	}

	message_info.port = port->id;
	message_info.team = port->team->id;
	message_info.capacity = port->capacity;
	message_info.queue_count = port->read_count;
	message_info.total_count = port->total_count;

	if (copy_to_user(info, &message_info, sizeof(*info))) {
		return B_BAD_VALUE;
	}

	return B_OK;
}


long nexus_port_message_info(struct nexus_port* port,
	struct nexus_port_message_info* info, size_t size, uint32_t flags,
		int64_t timeout)
{
	struct nexus_buffer* buf = NULL;
	struct nexus_port_message_info message_info;
	int ret = 0;

	memset(&message_info, 0, sizeof(message_info));

	if (info == NULL || timeout < 0) {
		return B_BAD_VALUE;
	}

	if (nexus_ports[port->id] == NULL
			|| (!port->is_open && port->read_count == 0)) {
		return B_BAD_PORT_ID;
	}

	flags &= B_RELATIVE_TIMEOUT | B_ABSOLUTE_TIMEOUT;

	while (port->read_count == 0) {
		if ((flags & B_RELATIVE_TIMEOUT) != 0 && timeout <= 0) {
			return B_WOULD_BLOCK;
		}

		kref_get(&port->ref_count);
		int32_t port_id = port->id;
		mutex_unlock(&nexus_main_lock);
		if ((flags & B_TIMEOUT) != 0 && timeout != B_INFINITE_TIMEOUT) {
			ret = wait_event_interruptible_hrtimeout(port->buffer_read,
				port->read_count > 0 || port->is_open == false,
					timeout*1000);
		} else {
			ret = wait_event_interruptible(port->buffer_read,
				port->read_count > 0 || port->is_open == false);
		}
		mutex_lock(&nexus_main_lock);
		kref_put(&port->ref_count, nexus_port_destroy);

		if (nexus_ports[port_id] == NULL
				|| (!port->is_open && port->read_count == 0)
					|| ret == -ERESTARTSYS) {
			return B_BAD_PORT_ID;
		}

		if (flags & B_TIMEOUT && ret == -ETIME) {
			return B_TIMED_OUT;
		} else if (ret == 0) {
			break;
		}
	}

	buf = list_first_entry_or_null(&port->queue, struct nexus_buffer, node);
	if (buf == NULL) {
		return B_BAD_VALUE;
	}

	message_info.size = buf->size;

	if (copy_to_user(info, &message_info, sizeof(*info))) {
		return B_BAD_VALUE;
	}

	return B_OK;
}

long nexus_port_op(struct nexus_team *team, unsigned long arg)
{
	struct nexus_port *port;
	struct nexus_port_exchange in_data;
	long ret;

	if (copy_from_user(&in_data, (struct __user nexus_port_exchange*)arg,
			sizeof(in_data))) {
		return B_BAD_VALUE;
	}

	if (in_data.id < 0) {
		return B_BAD_PORT_ID;
	}

	port = nexus_ports[in_data.id];
	if (port == NULL) {
		return B_BAD_PORT_ID;
	}

	switch (in_data.op) {
		case NEXUS_PORT_DELETE:
			printk(KERN_INFO "port delete %d", port->id);
			nexus_ports[port->id] = NULL;
			if (port->is_open)
				nexus_port_close(port);

			kref_put(&port->ref_count, nexus_port_destroy);
			ret = B_OK;
			break;

		case NEXUS_PORT_CLOSE:
			ret = nexus_port_close(port);
			break;

		case NEXUS_PORT_READ:
			ret = nexus_port_read(port, in_data.code, in_data.buffer,
				&in_data.size, in_data.flags, in_data.timeout);
			break;

		case NEXUS_PORT_WRITE:
			ret = nexus_port_write(port, in_data.code, in_data.buffer,
				in_data.size, in_data.flags, in_data.timeout);
			break;

		case NEXUS_PORT_MESSAGE_INFO:
			ret = nexus_port_message_info(port,
				(struct nexus_port_message_info*)in_data.buffer,
					in_data.size, in_data.flags, in_data.timeout);
			break;

		case NEXUS_PORT_INFO:
			ret = nexus_port_info(port,
				(struct nexus_port_info*)in_data.buffer);
			break;

		case NEXUS_SET_PORT_OWNER:
			// TODO check current team owns the port
			ret = nexus_set_port_owner(port, in_data.cookie);
			break;

		default:
			return B_ERROR;
	}

	if (copy_to_user((struct __user nexus_port_exchange*)arg, &in_data,
			sizeof(in_data))) {
		return B_BAD_VALUE;
	}

	return ret;
}

static long nexus_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct nexus_team *team = filp->private_data;
	struct nexus_thread *thread = NULL;
	long ret = -1;

	mutex_lock(&nexus_main_lock);

	// Someone forked let's reinit the team
	if (team->id != current->tgid) {
		team = nexus_team_init();
		filp->private_data = (void*)team;
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

				struct nexus_team *iter_team = NULL;
				struct nexus_thread *dest_thread = NULL;
				struct task_struct *task = get_pid_task(
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
		case NEXUS_THREAD_OP:
			ret = nexus_thread_op(thread, arg);
			break;

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

		case NEXUS_THREAD_RESUME:
			thread_id tid = (thread_id)arg;
			if (tid < 0) {
				ret = B_BAD_THREAD_ID;
				break;
			}

			struct nexus_team *iter_team = NULL;
			struct nexus_thread *dest_thread = NULL;
			struct task_struct *task = get_pid_task(find_get_pid((pid_t)tid),
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
			printk(KERN_INFO "nexus_thread_exit %d", thread->id);

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
	if (team == NULL)
		return -ENOMEM;
	mutex_unlock(&nexus_main_lock);

	filp->private_data = (void*)team;

	return 0;
}

static int nexus_release(struct inode *nodp, struct file *filp)
{
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

	memset(nexus_ports, 0, MAX_PORTS*sizeof(struct nexus_port*));

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
