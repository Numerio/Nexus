// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026 Dario Casalinuovo
 */

#include "nexus.h"

#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "errors.h"
#include "nexus_private.h"

extern struct mutex nexus_main_lock;
extern struct hlist_head nexus_teams;
extern struct idr nexus_port_idr;

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

	{
		struct nexus_port *p;
		int pid;
		idr_for_each_entry(&nexus_port_idr, p, pid) {
			if (strcmp(p->name, name) == 0) {
				in_data.id = p->id;
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

	port = kzalloc(sizeof(struct nexus_port), GFP_KERNEL);
	if (!port)
		return B_NO_MEMORY;

	kref_init(&port->ref_count);

	init_waitqueue_head(&port->buffer_read);
	init_waitqueue_head(&port->buffer_write);

	port->write_count = in_data.cookie;
	port->is_open = true;

	port->capacity = in_data.cookie;
	port->team = team;

	INIT_LIST_HEAD(&port->queue);

	// TODO check size
	if (copy_from_user(port->name, in_data.buffer, min(in_data.size,
			(size_t)B_OS_NAME_LENGTH))) {
		kfree(port);
		return B_BAD_VALUE;
	}

	// TODO we should publish info about a port in /proc/
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

	int id = idr_alloc(&nexus_port_idr, port, 1, 0, GFP_KERNEL);
	if (id < 0) {
		kfree(port);
		return B_NO_MORE_PORTS;
	}
	port->id = id;

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

	// id is zeroed by PORT_DELETE to avoid double removal
	if (port->id != 0)
		idr_remove(&nexus_port_idr, port->id);

	if (port->is_open)
		nexus_port_close(port);

	struct nexus_buffer *buf, *tmp;
	list_for_each_entry_safe(buf, tmp, &port->queue, node) {
		list_del(&buf->node);
		kfree(buf->buffer);
		kfree(buf);
	}

	if (port->team != NULL) {
		write_lock(&port->rw_lock);
		rb_erase(&port->node, &port->team->ports);
		write_unlock(&port->rw_lock);
	}

	kfree(port);
}

long nexus_get_next_port_for_team(unsigned long arg)
{
	struct nexus_get_next_port req;
	struct nexus_team *team;
	struct rb_node *node;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return B_BAD_VALUE;

	team = NULL;
	hlist_for_each_entry(team, &nexus_teams, node) {
		if (team->id == req.team)
			goto found;
	}
	return B_BAD_TEAM_ID;

found:
	for (node = rb_first(&team->ports); node != NULL; node = rb_next(node)) {
		struct nexus_port *p = rb_entry(node, struct nexus_port, node);
		if (p->id <= req.cookie)
			continue;

		req.info.port       = p->id;
		req.info.team       = team->id;
		req.info.capacity   = p->capacity;
		req.info.queue_count = p->read_count;
		req.info.total_count = p->total_count;
		strncpy(req.info.name, p->name, B_OS_NAME_LENGTH);
		req.info.name[B_OS_NAME_LENGTH - 1] = '\0';

		if (copy_to_user((void __user *)arg, &req, sizeof(req)))
			return B_BAD_VALUE;
		return B_OK;
	}

	return B_BAD_PORT_ID;
}


long nexus_set_port_owner(struct nexus_port* port, pid_t target_team)
{
	struct nexus_team* dest_team = NULL;
	struct nexus_port *next_port = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = NULL;

	if (port->team == NULL)
		return B_ERROR;

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
	return B_ERROR;
}

long nexus_port_read(struct nexus_port* port, int32_t* code, void* buffer,
	size_t* size, uint32_t flags, int64_t timeout)
{
	struct nexus_buffer* buf = NULL;
	int ret = 0;

	if ((buffer == NULL && *size > 0)
			|| *size > PORT_MAX_MESSAGE_SIZE || timeout < 0) {
		return B_BAD_VALUE;
	}

	if (idr_find(&nexus_port_idr, port->id) == NULL || (!port->is_open && port->read_count == 0)) {
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

		// Re-fetch via IDR: port may have been freed.
		port = idr_find(&nexus_port_idr, port_id);
		if (port == NULL) {
			return B_BAD_PORT_ID;
		}

		if (!port->is_open && port->read_count == 0) {
			return B_BAD_PORT_ID;
		}

		if (ret == -ERESTARTSYS || ret == -ERESTARTNOHAND
				|| ret == -ERESTARTNOINTR) {
			return B_INTERRUPTED;
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

	if (buf->size > *size) {
		list_del(&buf->node);
		kfree(buf->buffer);
		kfree(buf);
		port->read_count--;
		port->write_count++;
		port->total_count++;
		wake_up_interruptible(&port->buffer_write);
		return B_BAD_VALUE;
	}

	list_del(&buf->node);
	port->read_count--;
	port->write_count++;
	port->total_count++;
	wake_up_interruptible(&port->buffer_write);

	if (buf->buffer != NULL) {
		if (copy_to_user(buffer, buf->buffer, buf->size)) {
			kfree(buf->buffer);
			kfree(buf);
			return B_BAD_VALUE;
		}
		*size = buf->size;
	}

	if (code != NULL) {
		if (copy_to_user(code, &buf->code, sizeof(*code))) {
			kfree(buf->buffer);
			kfree(buf);
			return B_BAD_VALUE;
		}
	}

	kfree(buf->buffer);
	kfree(buf);

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

		// Re-fetch via IDR: kref_put may have freed port if the last ref dropped.
		port = idr_find(&nexus_port_idr, port_id);
		if (port == NULL) {
			return B_BAD_PORT_ID;
		}

		if (!port->is_open || ret == -ERESTARTSYS
				|| ret == -ERESTARTNOHAND || ret == -ERESTARTNOINTR) {
			if (ret == -ERESTARTSYS || ret == -ERESTARTNOHAND
					|| ret == -ERESTARTNOINTR) {
				port->write_count++;
				return B_INTERRUPTED;
			}
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
	if (buf == NULL) {
		port->write_count++;
		return B_NO_MEMORY;
	}

	if (buffer != NULL) {
		buf->buffer = kzalloc(size, GFP_KERNEL);
		if (buf->buffer == NULL) {
			kfree(buf);
			port->write_count++;
			return B_NO_MEMORY;
		}
		if (copy_from_user(buf->buffer, buffer, size)) {
			kfree(buf->buffer);
			kfree(buf);
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

	return B_OK;
}

status_t nexus_write_port(uint32_t id, int32_t code, const void *buffer,
	size_t buffer_size)
{
	mutex_lock(&nexus_main_lock);

	struct nexus_port* port = idr_find(&nexus_port_idr, id);
	if (port == NULL) {
		mutex_unlock(&nexus_main_lock);
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

	if (idr_find(&nexus_port_idr, port->id) == NULL
			|| (!port->is_open && port->read_count == 0)) {
		return B_BAD_PORT_ID;
	}

	if (port->team == NULL)
		return B_BAD_PORT_ID;

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

	if (idr_find(&nexus_port_idr, port->id) == NULL
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

		// Re-fetch via IDR: kref_put may have freed port if the last ref dropped.
		port = idr_find(&nexus_port_idr, port_id);
		if (port == NULL || (!port->is_open && port->read_count == 0)) {
			return B_BAD_PORT_ID;
		}

		if (ret == -ERESTARTSYS || ret == -ERESTARTNOHAND
				|| ret == -ERESTARTNOINTR) {
			return B_INTERRUPTED;
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

	port = idr_find(&nexus_port_idr, in_data.id);
	if (port == NULL) {
		return B_BAD_PORT_ID;
	}

	switch (in_data.op) {
		case NEXUS_PORT_DELETE:
			idr_remove(&nexus_port_idr, port->id);
			// Zero the id so that destroy skips idr_remove
			port->id = 0;
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
			if (port->team == NULL || port->team->id != current->tgid) {
				ret = B_NOT_ALLOWED;
				break;
			}
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
