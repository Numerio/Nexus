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
#include "vref.h"

extern struct mutex nexus_main_lock;
extern struct hlist_head nexus_teams;
extern struct idr nexus_port_idr;

long nexus_port_find(unsigned long arg)
{
	char name[B_OS_NAME_LENGTH];
	struct nexus_port_find_req in_data;

	if (copy_from_user(&in_data, (struct __user nexus_port_find_req*)arg,
			sizeof(in_data))) {
		return -EFAULT;
	}

	if (copy_from_user(name, in_data.name,
			min(in_data.size, (size_t) B_OS_NAME_LENGTH))) {
		return -EFAULT;
	}

	struct nexus_port *p;
	int pid;
	in_data.id = B_ERROR;
	in_data.ret = B_NAME_NOT_FOUND;
	idr_for_each_entry(&nexus_port_idr, p, pid) {
		if (strcmp(p->name, name) == 0) {
			in_data.id = p->id;
			in_data.ret = B_OK;
			break;
		}
	}

	if (copy_to_user((struct __user nexus_port_find_req*)arg, &in_data,
			sizeof(in_data))) {
		return -EFAULT;
	}

	return 0;
}

long nexus_port_create(struct nexus_team* team, unsigned long arg)
{
	struct nexus_port *port = NULL;
	struct nexus_port *next_port = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = NULL;
	struct nexus_port_create in_data;

	if (copy_from_user(&in_data, (struct __user nexus_port_create*)arg,
			sizeof(in_data))) {
		return -EFAULT;
	}

	if (in_data.capacity < 0 || in_data.capacity > PORT_MAX_QUEUE
			|| in_data.size > B_OS_NAME_LENGTH
				|| in_data.name == NULL) {
		in_data.ret = B_BAD_VALUE;
		goto out_copy;
	}

	port = kzalloc(sizeof(struct nexus_port), GFP_KERNEL);
	if (!port) {
		in_data.ret = B_NO_MEMORY;
		goto out_copy;
	}

	kref_init(&port->ref_count);

	init_waitqueue_head(&port->buffer_read);
	init_waitqueue_head(&port->buffer_write);

	port->write_count = in_data.capacity;
	port->is_open = true;

	port->capacity = in_data.capacity;
	port->team = team;
	port->read_count = 0;

	INIT_LIST_HEAD(&port->queue);

	// TODO check size
	if (copy_from_user(port->name, in_data.name, min(in_data.size,
			(size_t)B_OS_NAME_LENGTH))) {
		kfree(port);
		return -EFAULT;
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
		in_data.ret = B_NO_MORE_PORTS;
		goto out_copy;
	}
	port->id = id;
	in_data.id = id;
	in_data.ret = B_OK;

out_copy:
	if (copy_to_user((struct __user nexus_port_create*)arg, &in_data,
			sizeof(in_data))) {
		return -EFAULT;
	}

	return 0;
}

long nexus_port_close(struct nexus_port* port)
{
	port->is_open = false;
	wake_up_interruptible(&port->buffer_write);
	wake_up_interruptible(&port->buffer_read);

	return B_OK;
}

static void nexus_buffer_free(struct nexus_buffer *buf)
{
	int i;

	if (buf == NULL)
		return;
	// Release caps if needed
	for (i = 0; i < buf->cap_count; i++)
		nexus_vref_kref_release(buf->caps[i].vref);
	kfree(buf->caps);
	kfree(buf->buffer);
	kfree(buf);
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
		nexus_buffer_free(buf);
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
		return -EFAULT;

	req.ret = B_BAD_TEAM_ID;
	team = nexus_find_team(req.team);
	if (team == NULL)
		goto out_copy;

	req.ret = B_BAD_PORT_ID;
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
		req.ret = B_OK;
		break;
	}

out_copy:
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}


long nexus_set_port_owner(struct nexus_port* port, pid_t target_team)
{
	struct nexus_team* dest_team = NULL;
	struct nexus_port *next_port = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = NULL;

	if (port->team == NULL)
		return B_ERROR;

	dest_team = nexus_find_team(target_team);
	if (dest_team == NULL)
		return B_ERROR;

	write_lock(&port->rw_lock);
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
		write_unlock(&port->rw_lock);
		return B_OK;
	}
	write_unlock(&port->rw_lock);
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

	if (!port->is_open && port->read_count == 0)
		return B_BAD_PORT_ID;

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

		struct nexus_port *fresh = idr_find(&nexus_port_idr, port_id);
		if (fresh != port) {
			kref_put(&port->ref_count, nexus_port_destroy);
			return B_BAD_PORT_ID;
		}
		kref_put(&port->ref_count, nexus_port_destroy);

		if (!port->is_open && port->read_count == 0) {
			return B_BAD_PORT_ID;
		}

		if (ret == -ERESTARTSYS || ret == -ERESTARTNOHAND
				|| ret == -ERESTARTNOINTR) {
			return B_INTERRUPTED;
		}

		if (flags & B_TIMEOUT && ret == -ETIME) {
			return B_TIMED_OUT;
		} else if (ret == 0 || ret == -ETIME) {
			if (port->read_count > 0)
				break;
		}
	}

	buf = list_first_entry_or_null(&port->queue, struct nexus_buffer, node);
	if (buf == NULL) {
		return B_BAD_VALUE;
	}

	if (buf->cap_count > 0)
		pr_warn_ratelimited("nexus_port: LEGACY_READ_DROPS_CAPS "
			"port=%d(%s) reader=%d(%s) caps=%d size=%zu\n",
			port->id, port->name, current->tgid, current->comm,
			buf->cap_count, buf->size);

	size_t bufferSize = *size;

	list_del(&buf->node);
	port->read_count--;
	port->write_count++;
	port->total_count++;
	wake_up_interruptible(&port->buffer_write);

	size_t copySize = min(bufferSize, buf->size);

	if (buf->buffer != NULL) {
		if (copy_to_user(buffer, buf->buffer, copySize)) {
			nexus_buffer_free(buf);
			return B_BAD_VALUE;
		}
		*size = copySize;
	}

	if (code != NULL) {
		if (copy_to_user(code, &buf->code, sizeof(*code))) {
			nexus_buffer_free(buf);
			return B_BAD_VALUE;
		}
	}

	nexus_buffer_free(buf);

	return B_OK;
}

static long _nexus_port_write(struct nexus_port* port, int32_t* msg_code,
	const void* buffer, size_t size, uint32_t flags, int64_t timeout,
	bool from_user)
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

		struct nexus_port *fresh = idr_find(&nexus_port_idr, port_id);
		if (fresh != port) {
			kref_put(&port->ref_count, nexus_port_destroy);
			return B_BAD_PORT_ID;
		}
		kref_put(&port->ref_count, nexus_port_destroy);

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
		}
		if (ret == 0 && port->write_count >= 0) {
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
		if (from_user) {
			if (copy_from_user(buf->buffer, buffer, size)) {
				kfree(buf->buffer);
				kfree(buf);
				port->write_count++;
				return B_BAD_VALUE;
			}
		} else {
			memcpy(buf->buffer, buffer, size);
		}
		buf->size = size;
	} else
		buf->buffer = NULL;

	if (from_user) {
		if (copy_from_user(&buf->code, msg_code, sizeof(*msg_code))) {
			kfree(buf->buffer);
			kfree(buf);
			port->write_count++;
			return B_BAD_VALUE;
		}
	} else {
		buf->code = *msg_code;
	}

	list_add_tail(&buf->node, &port->queue);
	port->read_count++;

	wake_up_interruptible(&port->buffer_read);

	return B_OK;
}

long nexus_port_write(struct nexus_port* port, int32_t* msg_code,
	const void* buffer, size_t size, uint32_t flags, int64_t timeout)
{
	return _nexus_port_write(port, msg_code, buffer, size, flags, timeout,
		true);
}

static long nexus_port_write_kernel(struct nexus_port* port, int32_t* msg_code,
	const void* buffer, size_t size)
{
	return _nexus_port_write(port, msg_code, buffer, size,
		B_RELATIVE_TIMEOUT, 0, false);
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

	long ret = nexus_port_write_kernel(port, &code, buffer, buffer_size);
	mutex_unlock(&nexus_main_lock);
	return ret;
}

EXPORT_SYMBOL(nexus_write_port);

pid_t nexus_port_team_of(uint32_t id)
{
	struct nexus_port *port;
	pid_t team = -1;

	mutex_lock(&nexus_main_lock);
	port = idr_find(&nexus_port_idr, id);
	if (port != NULL && port->team != NULL)
		team = port->team->id;
	mutex_unlock(&nexus_main_lock);
	return team;
}
EXPORT_SYMBOL(nexus_port_team_of);

static long nexus_port_write_with_caps(struct nexus_port* port,
	int32_t* msg_code, const void __user* buffer, size_t size,
	const struct nexus_port_cap_in __user* user_caps, size_t cap_count,
	uint32_t flags, int64_t timeout)
{
	struct nexus_buffer* buf = NULL;
	struct nexus_port_cap_kref* caps_arr = NULL;
	struct nexus_port_cap_in* caps_tmp = NULL;
	int ret = 0;
	size_t i;

	if ((buffer == NULL && size != 0) || size > PORT_MAX_MESSAGE_SIZE
			|| timeout < 0) {
		return B_BAD_VALUE;
	}
	if (cap_count > 0 && user_caps == NULL)
		return B_BAD_VALUE;

	// Max caps per message
	if (cap_count > 1024)
		return B_BAD_VALUE;

	flags &= B_RELATIVE_TIMEOUT | B_ABSOLUTE_TIMEOUT;

	if (!port->is_open)
		return B_BAD_PORT_ID;

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

		struct nexus_port *fresh = idr_find(&nexus_port_idr, port_id);
		if (fresh != port) {
			kref_put(&port->ref_count, nexus_port_destroy);
			return B_BAD_PORT_ID;
		}
		kref_put(&port->ref_count, nexus_port_destroy);

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
		}
		if (ret == 0 && port->write_count >= 0)
			break;
	}

goahead:
	buf = kzalloc(sizeof(struct nexus_buffer), GFP_KERNEL);
	if (buf == NULL) {
		ret = B_NO_MEMORY;
		goto err_count;
	}

	if (buffer != NULL && size > 0) {
		buf->buffer = kzalloc(size, GFP_KERNEL);
		if (buf->buffer == NULL) {
			ret = B_NO_MEMORY;
			goto err_buf;
		}
		if (copy_from_user(buf->buffer, buffer, size)) {
			ret = B_BAD_VALUE;
			goto err_buf;
		}
		buf->size = size;
	}

	if (copy_from_user(&buf->code, msg_code, sizeof(*msg_code))) {
		ret = B_BAD_VALUE;
		goto err_buf;
	}

	if (cap_count > 0) {
		caps_tmp = kmalloc_array(cap_count, sizeof(*caps_tmp), GFP_KERNEL);
		caps_arr = kzalloc(cap_count * sizeof(*caps_arr), GFP_KERNEL);
		if (caps_tmp == NULL || caps_arr == NULL) {
			ret = B_NO_MEMORY;
			goto err_caps;
		}
		if (copy_from_user(caps_tmp, user_caps,
				cap_count * sizeof(*caps_tmp))) {
			ret = B_BAD_VALUE;
			goto err_caps;
		}
		for (i = 0; i < cap_count; i++) {
			if (caps_tmp[i].kind != NEXUS_PORT_CAP_VREF) {
				ret = B_BAD_VALUE;
				goto err_caps_acquired;
			}
			caps_arr[i].vref = nexus_vref_kref_acquire(caps_tmp[i].vref_id);
			if (caps_arr[i].vref == NULL) {
				ret = B_BAD_VALUE;
				goto err_caps_acquired;
			}
			caps_arr[i].buffer_offset = caps_tmp[i].buffer_offset;
		}
		kfree(caps_tmp);
		buf->caps = caps_arr;
		buf->cap_count = cap_count;
	}

	list_add_tail(&buf->node, &port->queue);
	port->read_count++;
	wake_up_interruptible(&port->buffer_read);

	return B_OK;

err_caps_acquired:
	while (i-- > 0)
		nexus_vref_kref_release(caps_arr[i].vref);
err_caps:
	kfree(caps_tmp);
	kfree(caps_arr);
err_buf:
	kfree(buf->buffer);
	kfree(buf);
err_count:
	port->write_count++;
	return ret;
}


static long nexus_port_read_with_caps(struct nexus_port* port, int32_t* code,
	void __user* buffer, size_t* size_inout,
	struct nexus_port_cap_out __user* user_caps, size_t* caps_count_inout,
	uint32_t flags, int64_t timeout)
{
	struct nexus_buffer* buf = NULL;
	struct nexus_port_cap_out* caps_out = NULL;
	int ret = 0;
	int i;

	if ((buffer == NULL && *size_inout > 0)
			|| *size_inout > PORT_MAX_MESSAGE_SIZE || timeout < 0) {
		return B_BAD_VALUE;
	}
	if (*caps_count_inout > 0 && user_caps == NULL)
		return B_BAD_VALUE;

	if (!port->is_open && port->read_count == 0)
		return B_BAD_PORT_ID;

	flags &= B_RELATIVE_TIMEOUT | B_ABSOLUTE_TIMEOUT;

	while (port->read_count == 0) {
		if ((flags & B_RELATIVE_TIMEOUT) != 0 && timeout <= 0)
			return B_WOULD_BLOCK;

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

		struct nexus_port *fresh = idr_find(&nexus_port_idr, port_id);
		if (fresh != port) {
			kref_put(&port->ref_count, nexus_port_destroy);
			return B_BAD_PORT_ID;
		}
		kref_put(&port->ref_count, nexus_port_destroy);

		if (!port->is_open && port->read_count == 0)
			return B_BAD_PORT_ID;
		if (ret == -ERESTARTSYS || ret == -ERESTARTNOHAND
				|| ret == -ERESTARTNOINTR)
			return B_INTERRUPTED;
		if (flags & B_TIMEOUT && ret == -ETIME)
			return B_TIMED_OUT;
		if ((ret == 0 || ret == -ETIME) && port->read_count > 0)
			break;
	}

	buf = list_first_entry_or_null(&port->queue, struct nexus_buffer, node);
	if (buf == NULL)
		return B_BAD_VALUE;

	if (*size_inout < buf->size
			|| *caps_count_inout < (size_t)buf->cap_count) {
		*size_inout = buf->size;
		*caps_count_inout = buf->cap_count;
		return B_BUFFER_OVERFLOW;
	}

	if (buf->cap_count > 0) {
		caps_out = kzalloc(buf->cap_count * sizeof(*caps_out), GFP_KERNEL);
		if (caps_out == NULL)
			return B_NO_MEMORY;
	}

	for (i = 0; i < buf->cap_count; i++) {
		uint64_t key = 0;
		ret = nexus_vref_mint_slot_for(buf->caps[i].vref,
			current->tgid, &key);
		if (ret != B_OK)
			goto out;
		caps_out[i].kind = NEXUS_PORT_CAP_VREF;
		caps_out[i].vref_id = buf->caps[i].vref->id;
		caps_out[i].buffer_offset = buf->caps[i].buffer_offset;
		caps_out[i].key = key;
	}

	if (buf->buffer != NULL && buf->size > 0
			&& copy_to_user(buffer, buf->buffer, buf->size)) {
		ret = B_BAD_VALUE;
		goto out;
	}
	if (buf->cap_count > 0 && copy_to_user(user_caps, caps_out,
			buf->cap_count * sizeof(*caps_out))) {
		ret = B_BAD_VALUE;
		goto out;
	}
	if (code != NULL && copy_to_user(code, &buf->code, sizeof(*code))) {
		ret = B_BAD_VALUE;
		goto out;
	}

	*size_inout = buf->size;
	*caps_count_inout = buf->cap_count;

	list_del(&buf->node);
	port->read_count--;
	port->write_count++;
	port->total_count++;
	wake_up_interruptible(&port->buffer_write);
	nexus_buffer_free(buf);
	ret = B_OK;

out:
	kfree(caps_out);
	return ret;
}


long nexus_port_info(struct nexus_port* port, struct nexus_port_info* info)
{
	struct nexus_port_info message_info;

	memset(&message_info, 0, sizeof(message_info));

	if (info == NULL) {
		return B_BAD_VALUE;
	}

	if (!port->is_open && port->read_count == 0)
		return B_BAD_PORT_ID;

	read_lock(&port->rw_lock);
	if (port->team == NULL) {
		read_unlock(&port->rw_lock);
		return B_BAD_PORT_ID;
	}

	message_info.port = port->id;
	message_info.team = port->team->id;
	message_info.capacity = port->capacity;
	message_info.queue_count = port->read_count;
	message_info.total_count = port->total_count;
	read_unlock(&port->rw_lock);

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

	if (!port->is_open && port->read_count == 0)
		return B_BAD_PORT_ID;

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

		struct nexus_port *fresh = idr_find(&nexus_port_idr, port_id);
		if (fresh != port) {
			kref_put(&port->ref_count, nexus_port_destroy);
			return B_BAD_PORT_ID;
		}
		kref_put(&port->ref_count, nexus_port_destroy);

		if (!port->is_open && port->read_count == 0) {
			return B_BAD_PORT_ID;
		}

		if (ret == -ERESTARTSYS || ret == -ERESTARTNOHAND
				|| ret == -ERESTARTNOINTR) {
			return B_INTERRUPTED;
		}

		if (flags & B_TIMEOUT && ret == -ETIME) {
			return B_TIMED_OUT;
		} else if (ret == 0) {
			if (port->read_count > 0)
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

long nexus_port_io_close(struct nexus_team *team, unsigned long arg)
{
	struct nexus_port_id data;
	struct nexus_port *port;

	if (copy_from_user(&data, (struct __user nexus_port_id*)arg, sizeof(data)))
		return -EFAULT;

	port = idr_find(&nexus_port_idr, data.id);
	data.ret = port ? nexus_port_close(port) : B_BAD_PORT_ID;

	if (copy_to_user((struct __user nexus_port_id*)arg, &data, sizeof(data)))
		return -EFAULT;

	return 0;
}

long nexus_port_io_delete(struct nexus_team *team, unsigned long arg)
{
	struct nexus_port_id data;
	struct nexus_port *port;

	if (copy_from_user(&data, (struct __user nexus_port_id*)arg, sizeof(data)))
		return -EFAULT;

	port = idr_find(&nexus_port_idr, data.id);
	if (port == NULL) {
		data.ret = B_BAD_PORT_ID;
	} else {
		idr_remove(&nexus_port_idr, port->id);
		if (port->is_open)
			nexus_port_close(port);
		port->id = 0;
		kref_put(&port->ref_count, nexus_port_destroy);
		data.ret = B_OK;
	}

	if (copy_to_user((struct __user nexus_port_id*)arg, &data, sizeof(data)))
		return -EFAULT;

	return 0;
}

long nexus_port_io_read(struct nexus_team *team, unsigned long arg)
{
	struct nexus_port_read data;
	struct nexus_port *port;

	if (copy_from_user(&data, (struct __user nexus_port_read*)arg, sizeof(data)))
		return -EFAULT;

	port = idr_find(&nexus_port_idr, data.id);
	if (port == NULL)
		data.ret = B_BAD_PORT_ID;
	else
		data.ret = nexus_port_read(port, data.code, data.buffer,
			&data.size, data.flags, data.timeout);

	if (copy_to_user((struct __user nexus_port_read*)arg, &data, sizeof(data)))
		return -EFAULT;

	return 0;
}

long nexus_port_io_write(struct nexus_team *team, unsigned long arg)
{
	struct nexus_port_write data;
	struct nexus_port *port;

	if (copy_from_user(&data, (struct __user nexus_port_write*)arg, sizeof(data)))
		return -EFAULT;

	port = idr_find(&nexus_port_idr, data.id);
	data.ret = port ? nexus_port_write(port, data.code, data.buffer,
		data.size, data.flags, data.timeout) : B_BAD_PORT_ID;

	if (copy_to_user((struct __user nexus_port_write*)arg, &data, sizeof(data)))
		return -EFAULT;

	return 0;
}

long nexus_port_io_info(struct nexus_team *team, unsigned long arg)
{
	struct nexus_port_get_info data;
	struct nexus_port *port;

	if (copy_from_user(&data, (struct __user nexus_port_get_info*)arg, sizeof(data)))
		return -EFAULT;

	port = idr_find(&nexus_port_idr, data.id);
	data.ret = port ? nexus_port_info(port, data.info) : B_BAD_PORT_ID;

	if (copy_to_user((struct __user nexus_port_get_info*)arg, &data, sizeof(data)))
		return -EFAULT;

	return 0;
}

long nexus_port_io_message_info(struct nexus_team *team, unsigned long arg)
{
	struct nexus_port_get_message_info data;
	struct nexus_port *port;

	if (copy_from_user(&data, (struct __user nexus_port_get_message_info*)arg, sizeof(data)))
		return -EFAULT;

	port = idr_find(&nexus_port_idr, data.id);
	data.ret = port ? nexus_port_message_info(port, data.info, data.size,
		data.flags, data.timeout) : B_BAD_PORT_ID;

	if (copy_to_user((struct __user nexus_port_get_message_info*)arg, &data, sizeof(data)))
		return -EFAULT;

	return 0;
}

long nexus_port_io_write_caps(struct nexus_team *team, unsigned long arg)
{
	struct nexus_port_write_caps data;
	struct nexus_port *port;

	if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
		return -EFAULT;

	port = idr_find(&nexus_port_idr, data.id);
	data.ret = port ? nexus_port_write_with_caps(port, data.code,
		data.buffer, data.size, data.caps, data.caps_count,
		data.flags, data.timeout) : B_BAD_PORT_ID;

	if (copy_to_user((void __user *)arg, &data, sizeof(data)))
		return -EFAULT;
	return 0;
}

long nexus_port_io_read_caps(struct nexus_team *team, unsigned long arg)
{
	struct nexus_port_read_caps data;
	struct nexus_port *port;

	if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
		return -EFAULT;

	port = idr_find(&nexus_port_idr, data.id);
	data.ret = port ? nexus_port_read_with_caps(port, data.code,
		data.buffer, &data.size, data.caps, &data.caps_count,
		data.flags, data.timeout) : B_BAD_PORT_ID;

	if (copy_to_user((void __user *)arg, &data, sizeof(data)))
		return -EFAULT;
	return 0;
}

long nexus_port_io_set_owner(struct nexus_team *team, unsigned long arg)
{
	struct nexus_port_set_owner data;
	struct nexus_port *port;

	if (copy_from_user(&data, (struct __user nexus_port_set_owner*)arg, sizeof(data)))
		return -EFAULT;

	port = idr_find(&nexus_port_idr, data.id);
	if (port == NULL)
		data.ret = B_BAD_PORT_ID;
	else if (port->team == NULL || port->team->id != current->tgid)
		data.ret = B_NOT_ALLOWED;
	else
		data.ret = nexus_set_port_owner(port, data.team) == 0 ? B_OK : B_ERROR;

	if (copy_to_user((struct __user nexus_port_set_owner*)arg, &data, sizeof(data)))
		return -EFAULT;

	return 0;
}


