// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026 Dario Casalinuovo
 */

#include "nexus.h"

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/ktime.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/rbtree.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "errors.h"
#include "nexus_private.h"
#include "vref.h"

/* Port id table. A leaf spinlock: team-of lookups run from node_monitor
 * under mark->lock (atomic). Entries are inserted with a preloaded
 * GFP_NOWAIT allocation. */
static DEFINE_IDR(nexus_port_idr);
static DEFINE_SPINLOCK(nexus_port_idr_lock);

#define NEXUS_PORT_SLOT_BITS	12
#define NEXUS_PORT_MAX_SLOTS	(1 << NEXUS_PORT_SLOT_BITS)
#define NEXUS_PORT_GEN_BITS	19
#define NEXUS_PORT_GEN_MASK	((1u << NEXUS_PORT_GEN_BITS) - 1)

static DEFINE_IDA(nexus_port_slot_ida);
/* A slot's generation is only touched by the holder of the slot. */
static uint32_t nexus_port_slot_gen[NEXUS_PORT_MAX_SLOTS];

static struct proc_dir_entry *nexus_proc_root;
static struct proc_dir_entry *nexus_proc_ports;

/* Reserve a slot and compute the id. Id 0 means "no port", so slot 0
 * starts at generation 1. */
static int nexus_port_id_reserve(void)
{
	int slot;

	slot = ida_alloc_max(&nexus_port_slot_ida, NEXUS_PORT_MAX_SLOTS - 1,
		GFP_KERNEL);
	if (slot < 0)
		return slot;

	if (slot == 0 && nexus_port_slot_gen[0] == 0)
		nexus_port_slot_gen[0] = 1;

	return (int)((nexus_port_slot_gen[slot] << NEXUS_PORT_SLOT_BITS)
		| (uint32_t)slot);
}

static void nexus_port_id_free(int id)
{
	int slot = id & (NEXUS_PORT_MAX_SLOTS - 1);

	nexus_port_slot_gen[slot] = (nexus_port_slot_gen[slot] + 1)
		& NEXUS_PORT_GEN_MASK;
	ida_free(&nexus_port_slot_ida, slot);
}

static int nexus_port_publish(struct nexus_port *port)
{
	unsigned long flags;
	int ret;

	idr_preload(GFP_KERNEL);
	spin_lock_irqsave(&nexus_port_idr_lock, flags);
	ret = idr_alloc(&nexus_port_idr, port, port->id, port->id + 1,
		GFP_NOWAIT);
	spin_unlock_irqrestore(&nexus_port_idr_lock, flags);
	idr_preload_end();

	return ret == port->id ? 0 : -ENOSPC;
}

/* Resolve an id to a live port and take a reference. A port whose last
 * reference is being dropped is still in the table for a moment and must
 * not be revived. Pair with nexus_port_put(). */
struct nexus_port *nexus_port_lookup(port_id id)
{
	struct nexus_port *port;
	unsigned long flags;

	spin_lock_irqsave(&nexus_port_idr_lock, flags);
	port = idr_find(&nexus_port_idr, id);
	if (port != NULL && !kref_get_unless_zero(&port->ref_count))
		port = NULL;
	spin_unlock_irqrestore(&nexus_port_idr_lock, flags);
	return port;
}

void nexus_port_put(struct nexus_port *port)
{
	if (port != NULL)
		kref_put(&port->ref_count, nexus_port_destroy);
}

/* Timeouts. The deadline is fixed once, on the boottime clock like the
 * semaphore and thread paths, and each sleep gets the time left. */
struct nexus_port_deadline {
	bool	timed;
	u64		ns;
};

static void nexus_port_deadline_init(struct nexus_port_deadline *dl,
	uint32_t flags, int64_t timeout)
{
	u64 us = (u64)timeout;

	dl->timed = false;
	dl->ns = 0;

	if (flags & B_ABSOLUTE_TIMEOUT) {
		if (us <= U64_MAX / 1000ULL) {
			dl->timed = true;
			dl->ns = us * 1000ULL;
		}
	} else if (flags & B_RELATIVE_TIMEOUT) {
		if (timeout != B_INFINITE_TIMEOUT && us <= U64_MAX / 1000ULL) {
			u64 now = ktime_get_boottime_ns();

			dl->timed = true;
			dl->ns = now + us * 1000ULL;
			if (dl->ns < now)
				dl->timed = false;
		}
	}
}

/* Time left in ns; 0 when the deadline passed. Untimed never reaches
 * here. */
static u64 nexus_port_deadline_left(const struct nexus_port_deadline *dl)
{
	u64 now = ktime_get_boottime_ns();

	return now >= dl->ns ? 0 : dl->ns - now;
}

/* Port membership. Both helpers need the owning team lock(s) and
 * port->lock. */
static void nexus_port_link_locked(struct nexus_port *port,
	struct nexus_team *team)
{
	struct rb_node **p = &team->ports.rb_node;
	struct rb_node *parent = NULL;
	struct nexus_port *next;

	while (*p) {
		parent = *p;
		next = rb_entry(parent, struct nexus_port, node);
		if (port->id > next->id)
			p = &(*p)->rb_right;
		else
			p = &(*p)->rb_left;
	}
	rb_link_node(&port->node, parent, p);
	rb_insert_color(&port->node, &team->ports);
	port->team = team;
	WRITE_ONCE(port->team_id, team->id);
}

/* True if the port was linked: the caller then owns the team's reference
 * and must drop it. */
static bool nexus_port_unlink_locked(struct nexus_port *port)
{
	bool was_linked = port->team != NULL && !RB_EMPTY_NODE(&port->node);

	if (was_linked) {
		rb_erase(&port->node, &port->team->ports);
		RB_CLEAR_NODE(&port->node);
	}
	port->team = NULL;
	WRITE_ONCE(port->team_id, -1);
	return was_linked;
}

/* The port's current team with a reference, or NULL when unlinked. The
 * team stays valid while port->team points at it, so the reference can be
 * taken under port->lock. */
static struct nexus_team *nexus_port_get_owner(struct nexus_port *port)
{
	struct nexus_team *team;

	mutex_lock(&port->lock);
	team = port->team;
	if (team != NULL)
		kref_get(&team->ref_count);
	mutex_unlock(&port->lock);
	return team;
}

/* Take the owning team's lock and port->lock together. Returns the team
 * (referenced, lock held) or NULL when the port is unlinked, in which case
 * only port->lock is held. */
static struct nexus_team *nexus_port_lock_owner(struct nexus_port *port)
{
	struct nexus_team *team;

	for (;;) {
		team = nexus_port_get_owner(port);
		if (team == NULL) {
			mutex_lock(&port->lock);
			if (port->team == NULL)
				return NULL;
			mutex_unlock(&port->lock);
			continue;
		}

		mutex_lock(&team->lock);
		mutex_lock(&port->lock);
		if (port->team == team)
			return team;
		mutex_unlock(&port->lock);
		mutex_unlock(&team->lock);
		nexus_team_put(team);
	}
}

/* Leave the owner's tree. True if this call dropped the port out of a
 * tree, which hands the caller the tree's reference. */
static bool nexus_port_unlink_owner(struct nexus_port *port)
{
	struct nexus_team *team;
	bool was_linked;

	team = nexus_port_lock_owner(port);
	was_linked = nexus_port_unlink_locked(port);
	mutex_unlock(&port->lock);
	if (team != NULL) {
		mutex_unlock(&team->lock);
		nexus_team_put(team);
	}
	return was_linked;
}

long nexus_port_find(unsigned long arg)
{
	char name[B_OS_NAME_LENGTH];
	struct nexus_port_find_req in_data;
	struct nexus_port *p;
	unsigned long flags;
	int id;

	if (copy_from_user(&in_data, (struct __user nexus_port_find_req*)arg,
			sizeof(in_data))) {
		return -EFAULT;
	}

	if (strncpy_from_user(name, in_data.name, B_OS_NAME_LENGTH) < 0)
		return -EFAULT;
	name[B_OS_NAME_LENGTH - 1] = '\0';

	in_data.id = B_ERROR;
	in_data.ret = B_NAME_NOT_FOUND;

	spin_lock_irqsave(&nexus_port_idr_lock, flags);
	idr_for_each_entry(&nexus_port_idr, p, id) {
		if (strcmp(p->name, name) == 0) {
			in_data.id = p->id;
			in_data.ret = B_OK;
			break;
		}
	}
	spin_unlock_irqrestore(&nexus_port_idr_lock, flags);

	if (copy_to_user((struct __user nexus_port_find_req*)arg, &in_data,
			sizeof(in_data))) {
		return -EFAULT;
	}

	return 0;
}

long nexus_port_create(struct nexus_team* team, unsigned long arg)
{
	struct nexus_port *port = NULL;
	struct nexus_port_create in_data;
	int id;

	if (copy_from_user(&in_data, (struct __user nexus_port_create*)arg,
			sizeof(in_data))) {
		return -EFAULT;
	}

	if (in_data.capacity < 0 || in_data.capacity > PORT_MAX_QUEUE
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
	mutex_init(&port->lock);
	init_waitqueue_head(&port->buffer_read);
	init_waitqueue_head(&port->buffer_write);
	RB_CLEAR_NODE(&port->node);
	INIT_LIST_HEAD(&port->queue);

	port->write_count = in_data.capacity;
	port->is_open = true;
	port->capacity = in_data.capacity;
	port->read_count = 0;
	port->team_id = -1;

	if (strncpy_from_user(port->name, in_data.name, B_OS_NAME_LENGTH) < 0) {
		kfree(port);
		return -EFAULT;
	}
	port->name[B_OS_NAME_LENGTH - 1] = '\0';

	/* The id comes first so the team tree stays sorted by port id. The
	 * port joins the tree before it is published, so a delete or an
	 * owner change that finds it by id always finds it linked. */
	id = nexus_port_id_reserve();
	if (id < 0) {
		kfree(port);
		in_data.ret = B_NO_MORE_PORTS;
		goto out_copy;
	}
	port->id = id;

	mutex_lock(&team->lock);
	mutex_lock(&port->lock);
	nexus_port_link_locked(port, team);
	mutex_unlock(&port->lock);
	mutex_unlock(&team->lock);

	if (nexus_port_publish(port) < 0) {
		nexus_port_unlink_owner(port);
		nexus_port_id_free(id);
		kfree(port);
		in_data.ret = B_NO_MORE_PORTS;
		goto out_copy;
	}

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
	mutex_lock(&port->lock);
	port->is_open = false;
	mutex_unlock(&port->lock);
	wake_up_interruptible(&port->buffer_write);
	wake_up_interruptible(&port->buffer_read);

	return B_OK;
}

static void nexus_buffer_free(struct nexus_buffer *buf)
{
	int i;

	if (buf == NULL)
		return;
	for (i = 0; i < buf->cap_count; i++)
		nexus_vref_kref_release(buf->caps[i].vref);
	kfree(buf->caps);
	kfree(buf->buffer);
	kfree(buf);
}

/* Last reference gone: nobody can reach the port except through the id
 * table, and a lookup cannot revive it. */
void nexus_port_destroy(struct kref* ref)
{
	struct nexus_port* port = container_of(ref, struct nexus_port, ref_count);
	struct nexus_buffer *buf, *tmp;

	/* PORT_DELETE clears the id once it has unpublished the port. */
	if (port->id != 0) {
		unsigned long flags;

		spin_lock_irqsave(&nexus_port_idr_lock, flags);
		idr_remove(&nexus_port_idr, port->id);
		spin_unlock_irqrestore(&nexus_port_idr_lock, flags);
		nexus_port_id_free(port->id);
	}

	/* The tree holds a reference, so a linked port cannot get here. */
	WARN_ON_ONCE(!RB_EMPTY_NODE(&port->node));

	list_for_each_entry_safe(buf, tmp, &port->queue, node) {
		list_del(&buf->node);
		nexus_buffer_free(buf);
	}

	kfree(port);
}

/* Team teardown: take every port out of the tree and drop the tree's
 * reference. The team is already unpublished and marked dead. */
void nexus_port_team_teardown(struct nexus_team *team)
{
	struct nexus_port *port;
	struct rb_node *node;

	for (;;) {
		mutex_lock(&team->lock);
		node = rb_first(&team->ports);
		if (node == NULL) {
			mutex_unlock(&team->lock);
			break;
		}
		port = rb_entry(node, struct nexus_port, node);
		mutex_lock(&port->lock);
		nexus_port_unlink_locked(port);
		mutex_unlock(&port->lock);
		mutex_unlock(&team->lock);

		nexus_port_close(port);
		nexus_port_put(port);
	}
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
	mutex_lock(&team->lock);
	for (node = rb_first(&team->ports); node != NULL; node = rb_next(node)) {
		struct nexus_port *p = rb_entry(node, struct nexus_port, node);
		if (p->id <= req.cookie)
			continue;

		mutex_lock(&p->lock);
		req.info.port       = p->id;
		req.info.team       = team->id;
		req.info.capacity   = p->capacity;
		req.info.queue_count = p->read_count;
		req.info.total_count = p->total_count;
		mutex_unlock(&p->lock);
		strscpy(req.info.name, p->name, B_OS_NAME_LENGTH);
		req.info.name[B_OS_NAME_LENGTH - 1] = '\0';
		req.ret = B_OK;
		break;
	}
	mutex_unlock(&team->lock);
	nexus_team_put(team);

out_copy:
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

/* Move a port to another team. When caller is not negative the port must
 * belong to that team (B_NOT_ALLOWED otherwise). Both team locks are taken
 * in ascending id order, then the port lock, and the owner is revalidated
 * under them. */
static long nexus_port_move(struct nexus_port *port, pid_t caller,
	pid_t target_team)
{
	struct nexus_team *src, *dest = NULL;
	long ret;

	for (;;) {
		src = nexus_port_get_owner(port);
		if (src == NULL) {
			ret = caller >= 0 ? B_NOT_ALLOWED : B_ERROR;
			break;
		}
		if (caller >= 0 && src->id != caller) {
			nexus_team_put(src);
			ret = B_NOT_ALLOWED;
			break;
		}

		if (dest == NULL) {
			dest = nexus_find_team(target_team);
			if (dest == NULL) {
				nexus_team_put(src);
				ret = B_ERROR;
				break;
			}
		}

		if (src == dest) {
			nexus_team_put(src);
			ret = B_OK;
			break;
		}

		nexus_lock_two_teams(src, dest);
		mutex_lock(&port->lock);
		if (port->team != src) {
			/* Moved or torn down meanwhile: look again. */
			mutex_unlock(&port->lock);
			nexus_unlock_two_teams(src, dest);
			nexus_team_put(src);
			continue;
		}

		if (dest->dead) {
			ret = B_ERROR;
		} else {
			nexus_port_unlink_locked(port);
			nexus_port_link_locked(port, dest);
			ret = B_OK;
		}
		mutex_unlock(&port->lock);
		nexus_unlock_two_teams(src, dest);
		nexus_team_put(src);
		break;
	}

	nexus_team_put(dest);
	return ret;
}

long nexus_set_port_owner(struct nexus_port* port, pid_t target_team)
{
	return nexus_port_move(port, -1, target_team);
}

/* Wait for a queued message. Called and returns with port->lock held. 0
 * when read_count > 0, else a B_* error (the lock is still held). */
static long nexus_port_wait_readable(struct nexus_port *port, uint32_t flags,
	int64_t timeout)
{
	struct nexus_port_deadline dl;
	u64 left;
	int ret;

	nexus_port_deadline_init(&dl, flags, timeout);

	while (port->read_count == 0) {
		if (port->deleted)
			return B_BAD_PORT_ID;

		if (!(flags & B_ABSOLUTE_TIMEOUT)
				&& (flags & B_RELATIVE_TIMEOUT) && timeout <= 0)
			return B_WOULD_BLOCK;

		left = 0;
		if (dl.timed) {
			left = nexus_port_deadline_left(&dl);
			if (left == 0)
				return B_TIMED_OUT;
		}

		mutex_unlock(&port->lock);
		if (dl.timed)
			ret = wait_event_interruptible_hrtimeout(port->buffer_read,
				READ_ONCE(port->read_count) > 0
					|| !READ_ONCE(port->is_open),
				ns_to_ktime(left));
		else
			ret = wait_event_interruptible(port->buffer_read,
				READ_ONCE(port->read_count) > 0
					|| !READ_ONCE(port->is_open));
		mutex_lock(&port->lock);

		/* Revalidate: the port may have been deleted or closed. */
		if (port->deleted)
			return B_BAD_PORT_ID;
		if (port->read_count > 0)
			break;
		if (!port->is_open)
			return B_BAD_PORT_ID;
		if (ret == -ERESTARTSYS || ret == -ERESTARTNOHAND
				|| ret == -ERESTARTNOINTR)
			return B_INTERRUPTED;
		if (ret == -ETIME)
			return B_TIMED_OUT;
	}

	return 0;
}

/* Reserve a queue slot for a writer, waiting for room. Called and
 * returns with port->lock held. 0 means the reservation is held; on error
 * it has been given back. */
static long nexus_port_wait_writable(struct nexus_port *port, uint32_t flags,
	int64_t timeout)
{
	struct nexus_port_deadline dl;
	long err;
	u64 left;
	int ret;

	if (!port->is_open || port->deleted)
		return B_BAD_PORT_ID;

	port->write_count--;
	if (port->write_count >= 0)
		return 0;

	nexus_port_deadline_init(&dl, flags, timeout);

	while (port->write_count < 0) {
		if (!(flags & B_ABSOLUTE_TIMEOUT)
				&& (flags & B_RELATIVE_TIMEOUT) && timeout <= 0) {
			err = B_WOULD_BLOCK;
			goto fail;
		}

		left = 0;
		if (dl.timed) {
			left = nexus_port_deadline_left(&dl);
			if (left == 0) {
				err = B_TIMED_OUT;
				goto fail;
			}
		}

		mutex_unlock(&port->lock);
		if (dl.timed)
			ret = wait_event_interruptible_hrtimeout(port->buffer_write,
				READ_ONCE(port->write_count) >= 0
					|| !READ_ONCE(port->is_open),
				ns_to_ktime(left));
		else
			ret = wait_event_interruptible(port->buffer_write,
				READ_ONCE(port->write_count) >= 0
					|| !READ_ONCE(port->is_open));
		mutex_lock(&port->lock);

		if (ret == -ERESTARTSYS || ret == -ERESTARTNOHAND
				|| ret == -ERESTARTNOINTR) {
			err = B_INTERRUPTED;
			goto fail;
		}
		if (!port->is_open || port->deleted) {
			err = B_BAD_PORT_ID;
			goto fail;
		}
		if (port->write_count >= 0)
			break;
		if (ret == -ETIME) {
			err = B_TIMED_OUT;
			goto fail;
		}
	}

	return 0;

fail:
	port->write_count++;
	return err;
}

/* Give a reservation back after a failed write. */
static void nexus_port_unreserve(struct nexus_port *port)
{
	mutex_lock(&port->lock);
	port->write_count++;
	mutex_unlock(&port->lock);
}

/* Queue a finished message against the held reservation. */
static long nexus_port_enqueue(struct nexus_port *port,
	struct nexus_buffer *buf)
{
	mutex_lock(&port->lock);
	if (!port->is_open || port->deleted) {
		port->write_count++;
		mutex_unlock(&port->lock);
		nexus_buffer_free(buf);
		return B_BAD_PORT_ID;
	}
	list_add_tail(&buf->node, &port->queue);
	port->read_count++;
	mutex_unlock(&port->lock);

	wake_up_interruptible(&port->buffer_read);
	return B_OK;
}

long nexus_port_read(struct nexus_port* port, int32_t* code, void* buffer,
	size_t* size, uint32_t flags, int64_t timeout)
{
	struct nexus_buffer* buf = NULL;
	long err;

	if ((buffer == NULL && *size > 0)
			|| *size > PORT_MAX_MESSAGE_SIZE || timeout < 0) {
		return B_BAD_VALUE;
	}

	flags &= B_RELATIVE_TIMEOUT | B_ABSOLUTE_TIMEOUT;

	mutex_lock(&port->lock);
	if (port->deleted || (!port->is_open && port->read_count == 0)) {
		mutex_unlock(&port->lock);
		return B_BAD_PORT_ID;
	}

	err = nexus_port_wait_readable(port, flags, timeout);
	if (err != 0) {
		mutex_unlock(&port->lock);
		return err;
	}

	buf = list_first_entry_or_null(&port->queue, struct nexus_buffer, node);
	if (buf == NULL) {
		mutex_unlock(&port->lock);
		return B_BAD_VALUE;
	}

	if (buf->cap_count > 0)
		pr_warn_ratelimited("nexus_port: LEGACY_READ_DROPS_CAPS "
			"port=%d(%s) reader=%d(%s) caps=%d size=%zu\n",
			port->id, port->name, current->tgid, current->comm,
			buf->cap_count, buf->size);

	list_del(&buf->node);
	port->read_count--;
	port->write_count++;
	port->total_count++;
	mutex_unlock(&port->lock);

	wake_up_interruptible(&port->buffer_write);

	{
		size_t copySize = min(*size, buf->size);

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
	}

	nexus_buffer_free(buf);
	return B_OK;
}

static long _nexus_port_write(struct nexus_port* port, int32_t* msg_code,
	const void* buffer, size_t size, uint32_t flags, int64_t timeout,
	bool from_user)
{
	struct nexus_buffer* buf = NULL;
	long err;

	if ((buffer == NULL && size != 0) || size > PORT_MAX_MESSAGE_SIZE
			|| timeout < 0) {
		return B_BAD_VALUE;
	}

	flags &= B_RELATIVE_TIMEOUT | B_ABSOLUTE_TIMEOUT;

	mutex_lock(&port->lock);
	err = nexus_port_wait_writable(port, flags, timeout);
	mutex_unlock(&port->lock);
	if (err != 0)
		return err;

	buf = kzalloc(sizeof(struct nexus_buffer), GFP_KERNEL);
	if (buf == NULL) {
		nexus_port_unreserve(port);
		return B_NO_MEMORY;
	}

	if (from_user) {
		buf->sender = from_kuid_munged(current_user_ns(), current_uid());
		buf->sender_group = from_kgid_munged(current_user_ns(), current_gid());
		buf->sender_team = task_tgid_nr(current);
	}

	if (buffer != NULL) {
		buf->buffer = kzalloc(size, GFP_KERNEL);
		if (buf->buffer == NULL) {
			kfree(buf);
			nexus_port_unreserve(port);
			return B_NO_MEMORY;
		}
		if (from_user) {
			if (copy_from_user(buf->buffer, buffer, size)) {
				kfree(buf->buffer);
				kfree(buf);
				nexus_port_unreserve(port);
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
			nexus_port_unreserve(port);
			return B_BAD_VALUE;
		}
	} else {
		buf->code = *msg_code;
	}

	return nexus_port_enqueue(port, buf);
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
	struct nexus_port *port;
	long ret;

	port = nexus_port_lookup(id);
	if (port == NULL)
		return B_BAD_PORT_ID;

	ret = nexus_port_write_kernel(port, &code, buffer, buffer_size);
	nexus_port_put(port);
	return ret;
}

EXPORT_SYMBOL(nexus_write_port);

/* Safe under node_monitor's mark->lock: the id table spinlock and an
 * atomic read of the mirrored team id, nothing that sleeps. */
pid_t nexus_port_team_of(uint32_t id)
{
	struct nexus_port *port;
	unsigned long flags;
	pid_t team = -1;

	spin_lock_irqsave(&nexus_port_idr_lock, flags);
	port = idr_find(&nexus_port_idr, id);
	if (port != NULL)
		team = READ_ONCE(port->team_id);
	spin_unlock_irqrestore(&nexus_port_idr_lock, flags);
	return team;
}
EXPORT_SYMBOL(nexus_port_team_of);

/* Same lookup; kept for the team-exit callback that calls it under a
 * spinlock. */
pid_t nexus_port_team_of_locked(uint32_t id)
{
	return nexus_port_team_of(id);
}
EXPORT_SYMBOL(nexus_port_team_of_locked);

static long _nexus_port_write_with_caps(struct nexus_port* port,
	int32_t* msg_code, const void* buffer, size_t size,
	const struct nexus_port_cap_in* caps, size_t cap_count,
	uint32_t flags, int64_t timeout, bool from_user)
{
	struct nexus_buffer* buf = NULL;
	struct nexus_port_cap_kref* caps_arr = NULL;
	struct nexus_port_cap_in* caps_tmp = NULL;
	long err;
	long ret = 0;
	size_t i = 0;

	if ((buffer == NULL && size != 0) || size > PORT_MAX_MESSAGE_SIZE
			|| timeout < 0) {
		return B_BAD_VALUE;
	}
	if (cap_count > 0 && caps == NULL)
		return B_BAD_VALUE;

	// Max caps per message
	if (cap_count > 1024)
		return B_BAD_VALUE;

	flags &= B_RELATIVE_TIMEOUT | B_ABSOLUTE_TIMEOUT;

	mutex_lock(&port->lock);
	err = nexus_port_wait_writable(port, flags, timeout);
	mutex_unlock(&port->lock);
	if (err != 0)
		return err;

	buf = kzalloc(sizeof(struct nexus_buffer), GFP_KERNEL);
	if (buf == NULL) {
		ret = B_NO_MEMORY;
		goto err_count;
	}

	if (from_user) {
		buf->sender = from_kuid_munged(current_user_ns(), current_uid());
		buf->sender_group = from_kgid_munged(current_user_ns(),
			current_gid());
		buf->sender_team = task_tgid_nr(current);
	}

	if (buffer != NULL && size > 0) {
		buf->buffer = kzalloc(size, GFP_KERNEL);
		if (buf->buffer == NULL) {
			ret = B_NO_MEMORY;
			goto err_buf;
		}
		if (from_user) {
			if (copy_from_user(buf->buffer, buffer, size)) {
				ret = B_BAD_VALUE;
				goto err_buf;
			}
		} else {
			memcpy(buf->buffer, buffer, size);
		}
		buf->size = size;
	}

	if (from_user) {
		if (copy_from_user(&buf->code, msg_code, sizeof(*msg_code))) {
			ret = B_BAD_VALUE;
			goto err_buf;
		}
	} else {
		buf->code = *msg_code;
	}

	if (cap_count > 0) {
		caps_arr = kzalloc(cap_count * sizeof(*caps_arr), GFP_KERNEL);
		if (caps_arr == NULL) {
			ret = B_NO_MEMORY;
			goto err_caps;
		}
		if (from_user) {
			caps_tmp = kmalloc_array(cap_count, sizeof(*caps_tmp),
				GFP_KERNEL);
			if (caps_tmp == NULL) {
				ret = B_NO_MEMORY;
				goto err_caps;
			}
			if (copy_from_user(caps_tmp, caps,
					cap_count * sizeof(*caps_tmp))) {
				ret = B_BAD_VALUE;
				goto err_caps;
			}
		} else {
			/* Kernel caller passes an in-kernel array directly. */
			caps_tmp = (struct nexus_port_cap_in*)caps;
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
		if (from_user)
			kfree(caps_tmp);
		buf->caps = caps_arr;
		buf->cap_count = cap_count;
	}

	return nexus_port_enqueue(port, buf);

err_caps_acquired:
	while (i-- > 0)
		nexus_vref_kref_release(caps_arr[i].vref);
err_caps:
	if (from_user)
		kfree(caps_tmp);
	kfree(caps_arr);
err_buf:
	kfree(buf->buffer);
	kfree(buf);
err_count:
	nexus_port_unreserve(port);
	return ret;
}


static long nexus_port_write_with_caps(struct nexus_port* port,
	int32_t* msg_code, const void __user* buffer, size_t size,
	const struct nexus_port_cap_in __user* user_caps, size_t cap_count,
	uint32_t flags, int64_t timeout)
{
	return _nexus_port_write_with_caps(port, msg_code,
		(const void*)buffer, size,
		(const struct nexus_port_cap_in*)user_caps, cap_count,
		flags, timeout, true);
}


status_t nexus_write_port_with_caps(uint32_t id, int32_t code,
	const void* buffer, size_t size,
	const struct nexus_port_cap_in* caps, size_t cap_count)
{
	struct nexus_port *port;
	int32_t code_val = code;
	long ret;

	port = nexus_port_lookup(id);
	if (port == NULL)
		return B_BAD_PORT_ID;

	ret = _nexus_port_write_with_caps(port, &code_val, buffer, size,
		caps, cap_count, B_RELATIVE_TIMEOUT, 0, false);
	nexus_port_put(port);
	return ret;
}
EXPORT_SYMBOL(nexus_write_port_with_caps);


/* The message stays queued until every copy to the caller succeeded, so
 * port->lock is held across the minting and the copies; only vref locks
 * nest inside it. */
static long nexus_port_read_with_caps(struct nexus_port* port, int32_t* code,
	void __user* buffer, size_t* size_inout,
	struct nexus_port_cap_out __user* user_caps, size_t* caps_count_inout,
	uint32_t flags, int64_t timeout,
	uint32_t* out_sender_uid, uint32_t* out_sender_gid,
	int32_t* out_sender_team)
{
	struct nexus_buffer* buf = NULL;
	struct nexus_port_cap_out* caps_out = NULL;
	long ret;
	int i;

	if ((buffer == NULL && *size_inout > 0)
			|| *size_inout > PORT_MAX_MESSAGE_SIZE || timeout < 0) {
		return B_BAD_VALUE;
	}
	if (*caps_count_inout > 0 && user_caps == NULL)
		return B_BAD_VALUE;

	flags &= B_RELATIVE_TIMEOUT | B_ABSOLUTE_TIMEOUT;

	mutex_lock(&port->lock);
	if (port->deleted || (!port->is_open && port->read_count == 0)) {
		mutex_unlock(&port->lock);
		return B_BAD_PORT_ID;
	}

	ret = nexus_port_wait_readable(port, flags, timeout);
	if (ret != 0)
		goto out_unlock;

	buf = list_first_entry_or_null(&port->queue, struct nexus_buffer, node);
	if (buf == NULL) {
		ret = B_BAD_VALUE;
		goto out_unlock;
	}

	if (*size_inout < buf->size
			|| *caps_count_inout < (size_t)buf->cap_count) {
		*size_inout = buf->size;
		*caps_count_inout = buf->cap_count;
		ret = B_BUFFER_OVERFLOW;
		goto out_unlock;
	}

	if (buf->cap_count > 0) {
		caps_out = kzalloc(buf->cap_count * sizeof(*caps_out), GFP_KERNEL);
		if (caps_out == NULL) {
			ret = B_NO_MEMORY;
			goto out_unlock;
		}
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

	if (out_sender_uid != NULL)
		*out_sender_uid = buf->sender;
	if (out_sender_gid != NULL)
		*out_sender_gid = buf->sender_group;
	if (out_sender_team != NULL)
		*out_sender_team = buf->sender_team;

	list_del(&buf->node);
	port->read_count--;
	port->write_count++;
	port->total_count++;
	mutex_unlock(&port->lock);

	wake_up_interruptible(&port->buffer_write);
	nexus_buffer_free(buf);
	kfree(caps_out);
	return B_OK;

out:
	kfree(caps_out);
out_unlock:
	mutex_unlock(&port->lock);
	return ret;
}


long nexus_port_info(struct nexus_port* port, struct nexus_port_info* info)
{
	struct nexus_port_info message_info;

	memset(&message_info, 0, sizeof(message_info));

	if (info == NULL) {
		return B_BAD_VALUE;
	}

	mutex_lock(&port->lock);
	if (port->deleted || (!port->is_open && port->read_count == 0)
			|| port->team == NULL) {
		mutex_unlock(&port->lock);
		return B_BAD_PORT_ID;
	}

	message_info.port = port->id;
	message_info.team = port->team->id;
	message_info.capacity = port->capacity;
	message_info.queue_count = port->read_count;
	message_info.total_count = port->total_count;
	mutex_unlock(&port->lock);

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
	long err;

	memset(&message_info, 0, sizeof(message_info));

	if (info == NULL || timeout < 0) {
		return B_BAD_VALUE;
	}

	flags &= B_RELATIVE_TIMEOUT | B_ABSOLUTE_TIMEOUT;

	mutex_lock(&port->lock);
	if (port->deleted || (!port->is_open && port->read_count == 0)) {
		mutex_unlock(&port->lock);
		return B_BAD_PORT_ID;
	}

	err = nexus_port_wait_readable(port, flags, timeout);
	if (err != 0) {
		mutex_unlock(&port->lock);
		return err;
	}

	buf = list_first_entry_or_null(&port->queue, struct nexus_buffer, node);
	if (buf == NULL) {
		mutex_unlock(&port->lock);
		return B_BAD_VALUE;
	}

	message_info.size = buf->size;
	message_info.sender = buf->sender;
	message_info.sender_group = buf->sender_group;
	message_info.sender_team = buf->sender_team;
	mutex_unlock(&port->lock);

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

	port = nexus_port_lookup(data.id);
	if (port == NULL) {
		data.ret = B_BAD_PORT_ID;
	} else {
		data.ret = nexus_port_close(port);
		nexus_port_put(port);
	}

	if (copy_to_user((struct __user nexus_port_id*)arg, &data, sizeof(data)))
		return -EFAULT;

	return 0;
}

long nexus_port_io_delete(struct nexus_team *team, unsigned long arg)
{
	struct nexus_port_id data;
	struct nexus_port *port;
	unsigned long flags;

	if (copy_from_user(&data, (struct __user nexus_port_id*)arg, sizeof(data)))
		return -EFAULT;

	port = nexus_port_lookup(data.id);
	if (port == NULL) {
		data.ret = B_BAD_PORT_ID;
	} else {
		int dead_id = 0;

		/* Unpublish first so lookups fail even while other threads
		 * still hold a reference. Only the caller that clears the id
		 * deletes; a racing delete sees a bad id. */
		spin_lock_irqsave(&nexus_port_idr_lock, flags);
		if (port->id != 0) {
			idr_remove(&nexus_port_idr, port->id);
			dead_id = port->id;
			port->id = 0;
		}
		spin_unlock_irqrestore(&nexus_port_idr_lock, flags);

		if (dead_id == 0) {
			data.ret = B_BAD_PORT_ID;
		} else {
			nexus_port_id_free(dead_id);

			mutex_lock(&port->lock);
			port->deleted = true;
			mutex_unlock(&port->lock);
			nexus_port_close(port);

			/* Leave the team tree, then drop the tree's reference
			 * if this call is the one that took the port out. Team
			 * teardown does the same under the team lock, so the
			 * reference is dropped exactly once. */
			if (nexus_port_unlink_owner(port))
				nexus_port_put(port);
			data.ret = B_OK;
		}
		nexus_port_put(port);
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

	port = nexus_port_lookup(data.id);
	if (port == NULL)
		data.ret = B_BAD_PORT_ID;
	else {
		data.ret = nexus_port_read(port, data.code, data.buffer,
			&data.size, data.flags, data.timeout);
		nexus_port_put(port);
	}

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

	port = nexus_port_lookup(data.id);
	if (port == NULL)
		data.ret = B_BAD_PORT_ID;
	else {
		data.ret = nexus_port_write(port, data.code, data.buffer,
			data.size, data.flags, data.timeout);
		nexus_port_put(port);
	}

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

	port = nexus_port_lookup(data.id);
	if (port == NULL)
		data.ret = B_BAD_PORT_ID;
	else {
		data.ret = nexus_port_info(port, data.info);
		nexus_port_put(port);
	}

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

	port = nexus_port_lookup(data.id);
	if (port == NULL)
		data.ret = B_BAD_PORT_ID;
	else {
		data.ret = nexus_port_message_info(port, data.info, data.size,
			data.flags, data.timeout);
		nexus_port_put(port);
	}

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

	port = nexus_port_lookup(data.id);
	if (port == NULL)
		data.ret = B_BAD_PORT_ID;
	else {
		data.ret = nexus_port_write_with_caps(port, data.code,
			data.buffer, data.size, data.caps, data.caps_count,
			data.flags, data.timeout);
		nexus_port_put(port);
	}

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

	port = nexus_port_lookup(data.id);
	data.sender_uid = (uint32_t)-1;
	data.sender_gid = (uint32_t)-1;
	data.sender_team = -1;
	if (port == NULL)
		data.ret = B_BAD_PORT_ID;
	else {
		data.ret = nexus_port_read_with_caps(port, data.code,
			data.buffer, &data.size, data.caps, &data.caps_count,
			data.flags, data.timeout,
			&data.sender_uid, &data.sender_gid, &data.sender_team);
		nexus_port_put(port);
	}

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

	port = nexus_port_lookup(data.id);
	if (port == NULL) {
		data.ret = B_BAD_PORT_ID;
	} else {
		data.ret = nexus_port_move(port, current->tgid, data.team);
		nexus_port_put(port);
	}

	if (copy_to_user((struct __user nexus_port_set_owner*)arg, &data, sizeof(data)))
		return -EFAULT;

	return 0;
}

long nexus_port_dispatch(struct nexus_team *team, unsigned int cmd,
	unsigned long arg)
{
	switch (cmd) {
	case NEXUS_PORT_CREATE:
		return nexus_port_create(team, arg);
	case NEXUS_PORT_CLOSE:
		return nexus_port_io_close(team, arg);
	case NEXUS_PORT_DELETE:
		return nexus_port_io_delete(team, arg);
	case NEXUS_PORT_READ:
		return nexus_port_io_read(team, arg);
	case NEXUS_PORT_WRITE:
		return nexus_port_io_write(team, arg);
	case NEXUS_PORT_INFO:
		return nexus_port_io_info(team, arg);
	case NEXUS_PORT_MESSAGE_INFO:
		return nexus_port_io_message_info(team, arg);
	case NEXUS_SET_PORT_OWNER:
		return nexus_port_io_set_owner(team, arg);
	case NEXUS_PORT_WRITE_CAPS:
		return nexus_port_io_write_caps(team, arg);
	case NEXUS_PORT_READ_CAPS:
		return nexus_port_io_read_caps(team, arg);
	case NEXUS_PORT_FIND:
		return nexus_port_find(arg);
	case NEXUS_GET_NEXT_PORT_FOR_TEAM:
		return nexus_get_next_port_for_team(arg);
	default:
		return -ENOTTY;
	}
}

/* /proc/nexus/ports: one row per published port, from a snapshot taken
 * under the id table lock. Counters are read without port->lock (a mutex
 * cannot be taken there), so a row is a point-in-time approximation. */
struct nexus_ports_snapshot {
	port_id	id;
	pid_t	team;
	int32_t	capacity;
	int32_t	queue_count;
	int32_t	total_count;
	char	name[B_OS_NAME_LENGTH];
};

static int nexus_ports_snapshot_take(struct nexus_ports_snapshot **out)
{
	struct nexus_ports_snapshot *snaps = NULL;
	struct nexus_port *p;
	unsigned long flags;
	int id, n, cap = 16;

	for (;;) {
		kfree(snaps);
		snaps = kcalloc((size_t)cap, sizeof(*snaps), GFP_KERNEL);
		if (snaps == NULL)
			return -ENOMEM;

		n = 0;
		spin_lock_irqsave(&nexus_port_idr_lock, flags);
		idr_for_each_entry(&nexus_port_idr, p, id) {
			if (n < cap) {
				snaps[n].id = p->id;
				snaps[n].team = READ_ONCE(p->team_id);
				snaps[n].capacity = p->capacity;
				snaps[n].queue_count = READ_ONCE(p->read_count);
				snaps[n].total_count = READ_ONCE(p->total_count);
				strscpy(snaps[n].name, p->name, B_OS_NAME_LENGTH);
			}
			n++;
		}
		spin_unlock_irqrestore(&nexus_port_idr_lock, flags);

		if (n <= cap)
			break;
		cap = n + 16;
	}

	*out = snaps;
	return n;
}

static int nexus_ports_show(struct seq_file *m, void *v)
{
	struct nexus_ports_snapshot *snaps;
	int i, n;

	n = nexus_ports_snapshot_take(&snaps);
	if (n < 0)
		return n;

	for (i = 0; i < n; i++)
		seq_printf(m, "%d\t%d\t%s\t%u\t%d\t%d\n",
			snaps[i].id, snaps[i].team, snaps[i].name,
			snaps[i].capacity, snaps[i].queue_count,
			snaps[i].total_count);

	kfree(snaps);
	return 0;
}

static int nexus_ports_open(struct inode *inode, struct file *file)
{
	return single_open(file, nexus_ports_show, NULL);
}

static const struct proc_ops nexus_ports_proc_ops = {
	.proc_open = nexus_ports_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

int nexus_port_proc_init(void)
{
	nexus_proc_root = proc_mkdir("nexus", NULL);
	if (nexus_proc_root == NULL)
		return -ENOMEM;

	nexus_proc_ports = proc_create("ports", 0444, nexus_proc_root,
		&nexus_ports_proc_ops);
	if (nexus_proc_ports == NULL) {
		proc_remove(nexus_proc_root);
		nexus_proc_root = NULL;
		return -ENOMEM;
	}
	return 0;
}

void nexus_port_proc_exit(void)
{
	if (nexus_proc_ports != NULL) {
		proc_remove(nexus_proc_ports);
		nexus_proc_ports = NULL;
	}
	if (nexus_proc_root != NULL) {
		proc_remove(nexus_proc_root);
		nexus_proc_root = NULL;
	}
}
