// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026 Dario Casalinuovo
 */

#include <linux/version.h>
#include <linux/fsnotify.h>
#include <linux/miscdevice.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/xattr.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/fs.h>

#include "kmsg.h"
#include "node_monitor.h"
#include "nexus.h"
#include "vref.h"
#include "query.h"
#include "attribute.h"
#include "index.h"
#include "volume.h"

#ifndef NEXUS_NM_DEBUG
#define NEXUS_NM_DEBUG 0
#endif

#ifndef NEXUS_NM_DEBUG_EVENTS
#define NEXUS_NM_DEBUG_EVENTS 0
#endif

#ifndef NEXUS_NM_DEBUG_MESSAGES
#define NEXUS_NM_DEBUG_MESSAGES 0
#endif

#ifndef NEXUS_NM_DEBUG_LOCKS
#define NEXUS_NM_DEBUG_LOCKS 0
#endif

#define nm_err(fmt, ...)   pr_err("nexus_nm: ERROR: " fmt, ##__VA_ARGS__)
#define nm_warn(fmt, ...)  pr_warn("nexus_nm: WARN: " fmt, ##__VA_ARGS__)
#define nm_info(fmt, ...)  pr_info("nexus_nm: " fmt, ##__VA_ARGS__)

#if NEXUS_NM_DEBUG
#define nm_dbg(fmt, ...)   pr_info("nexus_nm: DBG: " fmt, ##__VA_ARGS__)
#else
#define nm_dbg(fmt, ...)   do {} while (0)
#endif

#if NEXUS_NM_DEBUG_EVENTS
#define nm_dbg_event(fmt, ...) pr_info("nexus_nm: EVT: " fmt, ##__VA_ARGS__)
#else
#define nm_dbg_event(fmt, ...) do {} while (0)
#endif

#if NEXUS_NM_DEBUG_MESSAGES
#define nm_dbg_msg(fmt, ...) pr_info("nexus_nm: MSG: " fmt, ##__VA_ARGS__)
#else
#define nm_dbg_msg(fmt, ...) do {} while (0)
#endif

#if NEXUS_NM_DEBUG_LOCKS
#define nm_dbg_lock(fmt, ...) pr_info("nexus_nm: LCK: " fmt, ##__VA_ARGS__)
#else
#define nm_dbg_lock(fmt, ...) do {} while (0)
#endif

#if NEXUS_NM_DEBUG_EVENTS
static const char *fsn_mask_str(uint32_t mask)
{
	static char buf[256];
	buf[0] = '\0';
	if (mask & FS_CREATE) strcat(buf, "CREATE ");
	if (mask & FS_DELETE) strcat(buf, "DELETE ");
	if (mask & FS_MODIFY) strcat(buf, "MODIFY ");
	if (mask & FS_ATTRIB) strcat(buf, "ATTRIB ");
	if (mask & FS_MOVED_FROM) strcat(buf, "MOVED_FROM ");
	if (mask & FS_MOVED_TO) strcat(buf, "MOVED_TO ");
	if (mask & FS_MOVE_SELF) strcat(buf, "MOVE_SELF ");
	if (mask & FS_CLOSE_WRITE) strcat(buf, "CLOSE_WRITE ");
	if (mask & FS_OPEN) strcat(buf, "OPEN ");
	if (mask & FS_ACCESS) strcat(buf, "ACCESS ");
	if (buf[0] == '\0') snprintf(buf, sizeof(buf), "0x%x", mask);
	return buf;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
#define FD_FILE(f) fd_file(f)
#else
#define FD_FILE(f) ((f).file)
#endif

#define MOVE_TIMEOUT_MS 1000

#define MARK_HASH_BITS 12
#define MOVE_HASH_BITS 8


typedef int32_t port_id;

extern uint32_t nexus_write_port(uint32_t port, int32_t code,
	const void *buffer, size_t buffer_size);

struct nexus_listener {
	struct list_head list;
	port_id port;
	uint32_t token;
	uint32_t flags;
};

struct nm_child_vref {
	struct list_head list;
	struct inode    *inode;
	int32_t          vref_id;
};

struct nexus_mark {
	struct fsnotify_mark fs_mark;
	dev_t device;
	ino_t inode;
	struct list_head listeners;
	spinlock_t lock;

	bool is_dir;
	bool watch_children;
	struct nexus_mark *parent;
	struct list_head children;
	struct list_head sibling;
	uint32_t inherited_flags;
	port_id inherited_port;
	uint32_t inherited_token;

	// for B_WATCH_INTERIM_STAT
	bool modified;

	struct hlist_node hash_node;

	int32_t          vref_id;
	struct vfsmount *mnt_stored;

	struct list_head children_vrefs;
	spinlock_t       children_vrefs_lock;
};

struct pending_move {
	struct list_head list;
	uint32_t cookie;
	dev_t device;
	ino_t old_dir;
	ino_t inode;
	unsigned long expires;
	char old_name[NAME_MAX];
};

static struct fsnotify_group *nexus_fsn_group;
static LIST_HEAD(pending_moves);
static DEFINE_SPINLOCK(move_lock);

static DEFINE_HASHTABLE(marks_hash, MARK_HASH_BITS);
static DEFINE_SPINLOCK(marks_hash_lock);

#define PROBE_SUPPRESS_BITS 6

struct probe_suppress_entry {
	struct hlist_node  node;
	struct task_struct *task;
};

static DEFINE_HASHTABLE(probe_suppress, PROBE_SUPPRESS_BITS);
static DEFINE_SPINLOCK(probe_suppress_lock);

bool nexus_probe_is_suppressed(void)
{
	struct probe_suppress_entry *e;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(&probe_suppress_lock, flags);
	hash_for_each_possible(probe_suppress, e, node,
		(unsigned long)current) {
		if (e->task == current) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&probe_suppress_lock, flags);
	return found;
}

void nexus_probe_suppress_enter(void)
{
	struct probe_suppress_entry *e;
	unsigned long flags;

	e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e) {
		nm_warn("probe_suppress_enter: alloc failed for task %d\n",
			task_pid_nr(current));
		return;
	}
	e->task = current;

	spin_lock_irqsave(&probe_suppress_lock, flags);
	hash_add(probe_suppress, &e->node, (unsigned long)current);
	spin_unlock_irqrestore(&probe_suppress_lock, flags);
}

void nexus_probe_suppress_exit(void)
{
	struct probe_suppress_entry *e;
	unsigned long flags;

	spin_lock_irqsave(&probe_suppress_lock, flags);
	hash_for_each_possible(probe_suppress, e, node,
		(unsigned long)current) {
		if (e->task == current) {
			hash_del(&e->node);
			kfree(e);
			break;
		}
	}
	spin_unlock_irqrestore(&probe_suppress_lock, flags);
}

#if NEXUS_NM_DEBUG
static atomic_t stat_watches = ATOMIC_INIT(0);
static atomic_t stat_events = ATOMIC_INIT(0);
static atomic_t stat_messages = ATOMIC_INIT(0);
#endif

static inline struct nexus_mark *get_nexus_mark(struct fsnotify_mark *fs_mark)
{
	return container_of(fs_mark, struct nexus_mark, fs_mark);
}

static inline uint32_t hash_dev_ino(dev_t dev, ino_t ino)
{
	return hash_32((uint32_t)dev ^ (uint32_t)(ino >> 32) ^ (uint32_t)ino, MARK_HASH_BITS);
}

/*
 * TODO: we could use a kernel thread with a lockless queue and/or run
 * a per-cpu queue. To minimize blocking.
 */
struct deferred_notification {
	struct list_head list;
	port_id port;
	uint32_t token;
	char buffer[KMSG_BUFFER_SIZE];
	size_t size;
};

static void queue_notification(struct list_head *queue,
	struct kmsg_builder *msg, port_id port, uint32_t token)
{
	struct deferred_notification *notif;

	notif = kmalloc(sizeof(*notif), GFP_ATOMIC);
	if (!notif) {
		nm_err("failed to allocate deferred notification\n");
		return;
	}

	notif->port = port;
	notif->token = token;
	notif->size = msg->size;

	kmsg_finalize(msg, port, token);
	memcpy(notif->buffer, msg->buffer, msg->size);

	list_add_tail(&notif->list, queue);

#if NEXUS_NM_DEBUG_MESSAGES
	nm_dbg_msg("queued notification: port=%d token=%u size=%zu\n",
		port, token, msg->size);
#endif
}

static void send_queued_notifications(struct list_head *queue)
{
	struct deferred_notification *notif, *tmp;
	int count = 0;

	list_for_each_entry_safe(notif, tmp, queue, list) {
		nm_dbg_msg("sending queued notification: port=%d token=%u\n",
			notif->port, notif->token);

		nexus_write_port(notif->port, B_NODE_MONITOR,
			notif->buffer, notif->size);

		list_del(&notif->list);
		kfree(notif);
		count++;

#if NEXUS_NM_DEBUG
		atomic_inc(&stat_messages);
#endif
	}

	if (count > 0)
		nm_dbg("sent %d queued notifications\n", count);
}

struct listener_snapshot {
	port_id port;
	uint32_t token;
	uint32_t flags;
};

static void send_to_listener(struct nexus_listener *listener,
	struct kmsg_builder *msg)
{
	nm_dbg_msg("send_to_listener: port=%d token=%u size=%zu\n",
		listener->port, listener->token, msg->size);

	kmsg_finalize(msg, listener->port, listener->token);

#if NEXUS_NM_DEBUG
	atomic_inc(&stat_messages);
#endif

	nexus_write_port(listener->port, B_NODE_MONITOR, msg->buffer, msg->size);
}

static void notify_attr_changed(struct nexus_listener *listener, dev_t device,
	int32_t node_vref_id, int32_t dir_vref_id, const char *attr, int cause)
{
	char buf[KMSG_BUFFER_SIZE];
	struct kmsg_builder msg;
	int64_t sentinel = (int64_t)nexus_volume_sentinel_dev();

	nm_dbg_msg("notify_attr_changed: dev=%u node_vref=%d dir_vref=%d "
		"attr='%s' cause=%d\n",
		(unsigned)device, node_vref_id, dir_vref_id,
		attr ? attr : "(null)", cause);

	kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
	kmsg_add_int32(&msg, "opcode", B_ATTR_CHANGED);
	kmsg_add_int64(&msg, "device", (int64_t)device);
	kmsg_add_noderef(&msg, "virtual:node", sentinel, (int64_t)node_vref_id);

	if (dir_vref_id >= 0)
		kmsg_add_entryref(&msg, "virtual:directory", sentinel,
			(int64_t)dir_vref_id, "");
	if (attr && attr[0])
		kmsg_add_string(&msg, "attr", attr);
	kmsg_add_int32(&msg, "cause", cause);
	send_to_listener(listener, &msg);
}

static struct pending_move *find_pending_move(uint32_t cookie)
{
	struct pending_move *pm;

	list_for_each_entry(pm, &pending_moves, list) {
		if (pm->cookie == cookie) {
			nm_dbg("find_pending_move: found cookie=%u\n", cookie);
			return pm;
		}
	}
	nm_dbg("find_pending_move: cookie=%u not found\n", cookie);
	return NULL;
}

static void cleanup_expired_moves(void)
{
	struct pending_move *pm, *tmp;
	unsigned long now = jiffies;
	int count = 0;

	list_for_each_entry_safe(pm, tmp, &pending_moves, list) {
		if (time_after(now, pm->expires)) {
			nm_dbg("cleanup_expired_moves: expiring cookie=%u\n", pm->cookie);
			list_del(&pm->list);
			kfree(pm);
			count++;
		}
	}
	if (count > 0)
		nm_dbg("cleanup_expired_moves: cleaned %d entries\n", count);
}

static void nexus_mark_free(struct fsnotify_mark *fs_mark)
{
	struct nexus_mark *mark = get_nexus_mark(fs_mark);
	struct nexus_listener *listener, *tmp;

	nm_dbg("nexus_mark_free: dev=%u ino=%lu vref_id=%d\n",
		(unsigned)mark->device, (unsigned long)mark->inode,
		mark->vref_id);

	unsigned long flags;
	nm_dbg_lock("nexus_mark_free: acquiring marks_hash_lock\n");
	spin_lock_irqsave(&marks_hash_lock, flags);
	hlist_del_init(&mark->hash_node);
	spin_unlock_irqrestore(&marks_hash_lock, flags);

	unsigned long lflags;
	spin_lock_irqsave(&mark->lock, lflags);
	list_for_each_entry_safe(listener, tmp, &mark->listeners, list) {
		nm_dbg("nexus_mark_free: freeing listener port=%d token=%u\n",
			listener->port, listener->token);
		list_del(&listener->list);
		kfree(listener);
#if NEXUS_NM_DEBUG
		atomic_dec(&stat_watches);
#endif
	}
	spin_unlock_irqrestore(&mark->lock, lflags);

	struct nm_child_vref *cv, *cv_tmp;
	unsigned long cflags;
	LIST_HEAD(to_release);

	spin_lock_irqsave(&mark->children_vrefs_lock, cflags);
	list_splice_init(&mark->children_vrefs, &to_release);
	spin_unlock_irqrestore(&mark->children_vrefs_lock, cflags);

	list_for_each_entry_safe(cv, cv_tmp, &to_release, list) {
		list_del(&cv->list);
		nexus_vref_drop_kernel_ref(cv->vref_id);
		kfree(cv);
	}

	if (mark->mnt_stored) {
		mntput(mark->mnt_stored);
		mark->mnt_stored = NULL;
	}

	// Linearize release
	mark->vref_id = -1;

	kfree(mark);
}

static void nexus_freeing_mark(struct fsnotify_mark *mark,
	struct fsnotify_group *group)
{
	nm_dbg("nexus_freeing_mark called\n");
}

static int32_t nm_vref_from_inode(struct inode *inode, struct vfsmount *mnt);

static int32_t nm_mark_lookup_child_vref(struct nexus_mark *mark,
	struct inode *inode)
{
	struct nm_child_vref *e;
	int32_t id = -1;
	unsigned long flags;

	spin_lock_irqsave(&mark->children_vrefs_lock, flags);
	list_for_each_entry(e, &mark->children_vrefs, list) {
		if (e->inode == inode) {
			id = e->vref_id;
			break;
		}
	}
	spin_unlock_irqrestore(&mark->children_vrefs_lock, flags);
	return id;
}

static int32_t nm_mark_get_or_mint_child_vref(struct nexus_mark *mark,
	struct inode *inode)
{
	struct nm_child_vref *e;
	int32_t id;
	unsigned long flags;

	id = nm_mark_lookup_child_vref(mark, inode);
	if (id >= 0)
		return id;

	if (!mark->mnt_stored)
		return -1;

	id = nm_vref_from_inode(inode, mark->mnt_stored);
	if (id < 0)
		return -1;

	e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e) {
		nexus_vref_drop_kernel_ref(id);
		return -1;
	}
	e->inode = inode;
	e->vref_id = id;

	struct nm_child_vref *existing;

	spin_lock_irqsave(&mark->children_vrefs_lock, flags);
	list_for_each_entry(existing, &mark->children_vrefs, list) {
		if (existing->inode == inode) {
			int32_t winner = existing->vref_id;
			spin_unlock_irqrestore(&mark->children_vrefs_lock, flags);
			kfree(e);
			nexus_vref_drop_kernel_ref(id);
			return winner;
		}
	}
	list_add(&e->list, &mark->children_vrefs);
	spin_unlock_irqrestore(&mark->children_vrefs_lock, flags);
	return id;
}

static inline int32_t nm_node_vref_for_event(struct nexus_mark *mark,
	struct inode *inode)
{
	if (inode->i_ino == mark->inode &&
	    inode->i_sb->s_dev == mark->device)
		return mark->vref_id;
	return nm_mark_get_or_mint_child_vref(mark, inode);
}

static int32_t nm_mark_release_child_vref(struct nexus_mark *mark,
	struct inode *inode)
{
	struct nm_child_vref *e, *tmp;
	int32_t id = -1;
	unsigned long flags;

	spin_lock_irqsave(&mark->children_vrefs_lock, flags);
	list_for_each_entry_safe(e, tmp, &mark->children_vrefs, list) {
		if (e->inode == inode) {
			id = e->vref_id;
			list_del(&e->list);
			kfree(e);
			break;
		}
	}
	spin_unlock_irqrestore(&mark->children_vrefs_lock, flags);

	if (id >= 0)
		nexus_vref_drop_kernel_ref(id);
	return id;
}

static int32_t nm_vref_from_inode(struct inode *inode, struct vfsmount *mnt)
{
	struct dentry *dentry;
	struct path p;
	struct file *f;
	int32_t vref_id = -1;

	if (!inode || !mnt)
		return -1;

	dentry = d_find_alias(inode);
	if (!dentry) {
		nm_dbg("nm_vref_from_inode: d_find_alias returned NULL for ino=%lu\n",
			(unsigned long)inode->i_ino);
		return -1;
	}

	p.dentry = dentry;
	p.mnt    = mnt;

	f = dentry_open(&p, O_PATH | O_NOFOLLOW, current_cred());
	if (IS_ERR(f)) {
		nm_dbg("nm_vref_from_inode: dentry_open failed (%ld) for ino=%lu\n",
			PTR_ERR(f), (unsigned long)inode->i_ino);
		dput(dentry);
		return -1;
	}

	vref_id = nexus_vref_create_from_file(f);
	fput(f);
	dput(dentry);

	if (vref_id < 0)
		nm_dbg("nm_vref_from_inode: nexus_vref_create_from_file failed for ino=%lu\n",
			(unsigned long)inode->i_ino);

	return vref_id;
}

static int nexus_handle_event(struct fsnotify_group *group, uint32_t mask,
	const void *data, int data_type, struct inode *dir,
	const struct qstr *file_name, uint32_t cookie,
	struct fsnotify_iter_info *iter_info)
{
	struct fsnotify_mark *fs_mark;
	struct nexus_mark *mark;
	struct inode *inode = NULL;
	const char *name;
	dev_t device;
	ino_t ino;
	unsigned long flags;
	int type;
	LIST_HEAD(notifications);
	int64_t sentinel;

	struct listener_snapshot *snap = NULL;
	int snap_count = 0, i;

#if NEXUS_NM_DEBUG
	atomic_inc(&stat_events);
#endif

	if (data_type == FSNOTIFY_EVENT_INODE) {
		inode = (struct inode *)data;
	} else if (data_type == FSNOTIFY_EVENT_PATH) {
		const struct path *path = data;
		if (path && path->dentry)
			inode = d_inode(path->dentry);
	}

	if (!inode) {
		nm_dbg_event("nexus_handle_event: no inode, mask=0x%x\n", mask);
		return 0;
	}

	if (file_name)
		name = file_name->name;
	else
		name = "";

	device = inode->i_sb->s_dev;
	ino = inode->i_ino;

	nm_dbg_event("nexus_handle_event: mask=%s dev=%u ino=%lu dir_ino=%lu "
		"name='%s' cookie=%u\n",
		fsn_mask_str(mask), (unsigned)device, (unsigned long)ino,
		(unsigned long)(dir ? dir->i_ino : ino), name, cookie);

	sentinel = (int64_t)nexus_volume_sentinel_dev();

	for (type = 0; type < FSNOTIFY_ITER_TYPE_COUNT; type++) {
		int32_t node_vref_id = -1;
		int32_t dir_vref_id  = -1;
		bool dir_vref_tried = false;

		fs_mark = iter_info->marks[type];
		if (!fs_mark)
			continue;
		if (fs_mark->group != group)
			continue;

		mark = get_nexus_mark(fs_mark);
		node_vref_id = mark->vref_id;

		nm_dbg_lock("nexus_handle_event: acquiring mark->lock\n");

		snap_count = 0;
		snap = NULL;
		spin_lock_irqsave(&mark->lock, flags);
		struct nexus_listener *l;
		list_for_each_entry(l, &mark->listeners, list)
			snap_count++;

		if (snap_count == 0) {
			spin_unlock_irqrestore(&mark->lock, flags);
			continue;
		}

		snap = kmalloc_array(snap_count, sizeof(*snap), GFP_ATOMIC);
		if (!snap) {
			spin_unlock_irqrestore(&mark->lock, flags);
			nm_err("failed to allocate listener snapshot\n");
			continue;
		}

		i = 0;
		l = NULL;
		list_for_each_entry(l, &mark->listeners, list) {
			snap[i].port = l->port;
			snap[i].token = l->token;
			snap[i].flags = l->flags;
			i++;
		}
		spin_unlock_irqrestore(&mark->lock, flags);
		snap_count = i;

		for (i = 0; i < snap_count; i++) {
			port_id port = snap[i].port;
			uint32_t token = snap[i].token;
			uint32_t lflags = snap[i].flags;

			nm_dbg_event("  processing listener port=%d flags=0x%x\n",
				port, lflags);

			if ((mask & FS_CREATE) && (lflags & B_WATCH_DIRECTORY)) {
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t child_vref_id;

				if (!dir_vref_tried && dir && mark->mnt_stored) {
					dir_vref_id = nm_vref_from_inode(dir,
						mark->mnt_stored);
					dir_vref_tried = true;
					if (dir_vref_id < 0)
						nm_dbg("handle_event CREATE: "
							"parent vref unavailable, "
							"virtual:directory omitted\n");
				}

				child_vref_id = nm_mark_get_or_mint_child_vref(mark,
					inode);
				if (child_vref_id < 0)
					nm_dbg("handle_event CREATE: child vref "
						"unavailable, virtual:node omitted\n");

				kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
				kmsg_add_int32(&msg, "opcode", B_ENTRY_CREATED);
				kmsg_add_int64(&msg, "device", (int64_t)device);

				if (dir_vref_id >= 0)
					kmsg_add_entryref(&msg, "virtual:directory",
						sentinel, (int64_t)dir_vref_id, name);

				if (child_vref_id >= 0)
					kmsg_add_noderef(&msg, "virtual:node",
						sentinel, (int64_t)child_vref_id);
				if (name && name[0])
					kmsg_add_string(&msg, "name", name);
				queue_notification(&notifications, &msg, port, token);
			}

			if ((mask & FS_DELETE) && (lflags & B_WATCH_DIRECTORY)) {
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t child_vref_id;

				if (!dir_vref_tried && dir && mark->mnt_stored) {
					dir_vref_id = nm_vref_from_inode(dir,
						mark->mnt_stored);
					dir_vref_tried = true;
					if (dir_vref_id < 0)
						nm_dbg("handle_event DELETE: "
							"parent vref unavailable, "
							"virtual:directory omitted\n");
				}

				child_vref_id = nm_mark_release_child_vref(mark, inode);

				kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
				kmsg_add_int32(&msg, "opcode", B_ENTRY_REMOVED);
				kmsg_add_int64(&msg, "device", (int64_t)device);
				if (dir_vref_id >= 0)
					kmsg_add_entryref(&msg, "virtual:directory",
						sentinel, (int64_t)dir_vref_id, name);
				if (child_vref_id >= 0)
					kmsg_add_noderef(&msg, "virtual:node",
						sentinel, (int64_t)child_vref_id);
				if (name && name[0])
					kmsg_add_string(&msg, "name", name);
				queue_notification(&notifications, &msg, port, token);
			}

			if ((mask & FS_MOVED_FROM) && (lflags & B_WATCH_NAME)) {
				struct pending_move *pm;
				unsigned long mflags;

				spin_lock_irqsave(&move_lock, mflags);
				cleanup_expired_moves();

				pm = kmalloc(sizeof(*pm), GFP_ATOMIC);
				if (pm) {
					pm->cookie = cookie;
					pm->device = device;
					pm->old_dir = dir ? dir->i_ino : ino;
					pm->inode = ino;
					pm->expires = jiffies +
						msecs_to_jiffies(MOVE_TIMEOUT_MS);
					strscpy(pm->old_name, name, NAME_MAX);
					list_add(&pm->list, &pending_moves);
				}
				spin_unlock_irqrestore(&move_lock, mflags);
			}

			if ((mask & FS_MOVED_TO) && (lflags & B_WATCH_NAME)) {
				struct pending_move *pm;
				unsigned long mflags;
				ino_t from_dir_ino = dir ? dir->i_ino : ino;
				char old_name[NAME_MAX] = "";
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t to_dir_vref_id  = -1;
				int32_t from_dir_vref_id = -1;
				int32_t child_vref_id;

				spin_lock_irqsave(&move_lock, mflags);
				pm = find_pending_move(cookie);
				if (pm) {
					from_dir_ino = pm->old_dir;
					strscpy(old_name, pm->old_name, NAME_MAX);
					list_del(&pm->list);
					kfree(pm);
				}
				spin_unlock_irqrestore(&move_lock, mflags);

				if (!dir_vref_tried && dir && mark->mnt_stored) {
					dir_vref_id = nm_vref_from_inode(dir,
						mark->mnt_stored);
					dir_vref_tried = true;
				}
				to_dir_vref_id = dir_vref_id;

				nm_dbg("handle_event MOVED_TO: from_dir vref unavailable "
					"(only ino=%lu stored), virtual:from directory "
					"will use sentinel+ino fallback\n",
					(unsigned long)from_dir_ino);

				from_dir_vref_id = (int32_t)from_dir_ino;

				child_vref_id = nm_mark_get_or_mint_child_vref(mark,
					inode);

				kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
				kmsg_add_int32(&msg, "opcode", B_ENTRY_MOVED);
				kmsg_add_int64(&msg, "device", (int64_t)device);

				kmsg_add_int64(&msg, "node device", (int64_t)device);
				kmsg_add_entryref(&msg, "virtual:from directory",
					sentinel, (int64_t)from_dir_vref_id,
					old_name[0] ? old_name : "");
				if (to_dir_vref_id >= 0)
					kmsg_add_entryref(&msg, "virtual:to directory",
						sentinel, (int64_t)to_dir_vref_id, name);
				if (child_vref_id >= 0)
					kmsg_add_noderef(&msg, "virtual:node",
						sentinel, (int64_t)child_vref_id);
				if (name && name[0])
					kmsg_add_string(&msg, "name", name);
				if (old_name[0])
					kmsg_add_string(&msg, "from name", old_name);
				queue_notification(&notifications, &msg, port, token);
			}

			if ((mask & FS_MODIFY) && (lflags & B_WATCH_STAT)) {
				bool interim = (lflags & B_WATCH_INTERIM_STAT) != 0;
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t target_vref =
					nm_node_vref_for_event(mark, inode);
				kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
				kmsg_add_int32(&msg, "opcode", B_STAT_CHANGED);
				kmsg_add_int64(&msg, "device", (int64_t)device);
				if (target_vref >= 0)
					kmsg_add_noderef(&msg, "virtual:node",
						sentinel, (int64_t)target_vref);
				kmsg_add_int32(&msg, "fields",
					B_STAT_SIZE | B_STAT_MODIFICATION_TIME);
				if (interim)
					kmsg_add_int32(&msg, "interim", 1);
				queue_notification(&notifications, &msg, port, token);
			}

			if ((mask & FS_ATTRIB) && (lflags & B_WATCH_STAT)) {
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t target_vref =
					nm_node_vref_for_event(mark, inode);
				kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
				kmsg_add_int32(&msg, "opcode", B_STAT_CHANGED);
				kmsg_add_int64(&msg, "device", (int64_t)device);
				if (target_vref >= 0)
					kmsg_add_noderef(&msg, "virtual:node",
						sentinel, (int64_t)target_vref);
				kmsg_add_int32(&msg, "fields",
					B_STAT_MODE | B_STAT_UID | B_STAT_GID |
					B_STAT_CHANGE_TIME);
				queue_notification(&notifications, &msg, port, token);
			}

			if ((mask & FS_ATTRIB) && (lflags & B_WATCH_ATTR)) {
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t target_vref =
					nm_node_vref_for_event(mark, inode);

				if (!dir_vref_tried && dir && mark->mnt_stored) {
					dir_vref_id = nm_vref_from_inode(dir,
						mark->mnt_stored);
					dir_vref_tried = true;
					if (dir_vref_id < 0)
						nm_dbg("handle_event ATTRIB: "
							"parent vref unavailable\n");
				}

				kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
				kmsg_add_int32(&msg, "opcode", B_ATTR_CHANGED);
				kmsg_add_int64(&msg, "device", (int64_t)device);
				if (target_vref >= 0)
					kmsg_add_noderef(&msg, "virtual:node",
						sentinel, (int64_t)target_vref);
				if (dir_vref_id >= 0)
					kmsg_add_entryref(&msg, "virtual:directory",
						sentinel, (int64_t)dir_vref_id, "");
				kmsg_add_int32(&msg, "cause", B_ATTR_CAUSE_CHANGED);
				queue_notification(&notifications, &msg, port, token);
			}
		}

		kfree(snap);
		snap = NULL;

		if (dir) {
			struct nexus_mark *parent_mark;
			uint32_t phash = hash_dev_ino(device, dir->i_ino);
			struct nexus_mark *pm_iter;
			unsigned long hlflags;

			parent_mark = NULL;
			spin_lock_irqsave(&marks_hash_lock, hlflags);
			hlist_for_each_entry(pm_iter, &marks_hash[phash], hash_node) {
				if (pm_iter->device == device &&
				    pm_iter->inode == dir->i_ino) {
					parent_mark = pm_iter;
					break;
				}
			}
			spin_unlock_irqrestore(&marks_hash_lock, hlflags);

			if (parent_mark) {
				struct listener_snapshot *psnap = NULL;
				int psnap_count = 0, pi;
				struct nexus_listener *l;

				spin_lock_irqsave(&parent_mark->lock, hlflags);
				list_for_each_entry(l,
					&parent_mark->listeners, list)
					psnap_count++;

				if (psnap_count > 0) {
					psnap = kmalloc_array(psnap_count,
						sizeof(*psnap), GFP_ATOMIC);
					if (psnap) {
						struct nexus_listener *l;
						pi = 0;
						list_for_each_entry(l,
							&parent_mark->listeners,
							list) {
							psnap[pi].port = l->port;
							psnap[pi].token = l->token;
							psnap[pi].flags = l->flags;
							pi++;
						}
						psnap_count = pi;
					}
				}
				spin_unlock_irqrestore(&parent_mark->lock, hlflags);

				for (pi = 0; psnap && pi < psnap_count; pi++) {
					uint32_t pflags = psnap[pi].flags;

					if (!(pflags & B_WATCH_CHILDREN))
						continue;

					if ((mask & FS_CREATE) &&
					    (pflags & B_WATCH_DIRECTORY)) {
						char buf2[KMSG_BUFFER_SIZE];
						struct kmsg_builder msg2;
						int32_t pdvref = -1;
						int32_t cvref;

						if (parent_mark->mnt_stored)
							pdvref = nm_vref_from_inode(
								dir,
								parent_mark->mnt_stored);
						cvref = nm_mark_get_or_mint_child_vref(
							parent_mark, inode);
						kmsg_init(&msg2, buf2,
							sizeof(buf2), B_NODE_MONITOR);
						kmsg_add_int32(&msg2, "opcode",
							B_ENTRY_CREATED);
						kmsg_add_int64(&msg2, "device",
							(int64_t)device);
						if (pdvref >= 0)
							kmsg_add_entryref(&msg2,
								"virtual:directory",
								sentinel,
								(int64_t)pdvref,
								name);
						if (cvref >= 0)
							kmsg_add_noderef(&msg2,
								"virtual:node",
								sentinel,
								(int64_t)cvref);
						if (name && name[0])
							kmsg_add_string(&msg2, "name",
								name);
						queue_notification(&notifications,
							&msg2, psnap[pi].port,
							psnap[pi].token);
					}

					if ((mask & FS_DELETE) &&
					    (pflags & B_WATCH_DIRECTORY)) {
						char buf2[KMSG_BUFFER_SIZE];
						struct kmsg_builder msg2;
						int32_t pdvref = -1;
						int32_t cvref;

						if (parent_mark->mnt_stored)
							pdvref = nm_vref_from_inode(
								dir,
								parent_mark->mnt_stored);

						cvref = nm_mark_release_child_vref(
							parent_mark, inode);
						kmsg_init(&msg2, buf2,
							sizeof(buf2), B_NODE_MONITOR);
						kmsg_add_int32(&msg2, "opcode",
							B_ENTRY_REMOVED);
						kmsg_add_int64(&msg2, "device",
							(int64_t)device);
						if (pdvref >= 0)
							kmsg_add_entryref(&msg2,
								"virtual:directory",
								sentinel,
								(int64_t)pdvref,
								name);
						if (cvref >= 0)
							kmsg_add_noderef(&msg2,
								"virtual:node",
								sentinel,
								(int64_t)cvref);
						if (name && name[0])
							kmsg_add_string(&msg2, "name",
								name);
						queue_notification(&notifications,
							&msg2, psnap[pi].port,
							psnap[pi].token);
					}
				}

				kfree(psnap);
			}
		} else {
			nm_dbg("nexus_handle_event: dir=NULL, "
				"B_WATCH_CHILDREN walk skipped\n");
		}
	}

	send_queued_notifications(&notifications);
	return 0;
}

static const struct fsnotify_ops nexus_fsn_ops = {
	.handle_event = nexus_handle_event,
	.freeing_mark = nexus_freeing_mark,
	.free_mark = nexus_mark_free,
};

static struct nexus_mark *find_or_create_mark(struct inode *inode)
{
	struct fsnotify_mark *fs_mark;
	struct nexus_mark *mark;
	int ret;

	nm_dbg("find_or_create_mark: inode=%lu\n", (unsigned long)inode->i_ino);

	fs_mark = fsnotify_find_mark(&inode->i_fsnotify_marks,
		FSNOTIFY_OBJ_TYPE_INODE, nexus_fsn_group);
	if (fs_mark) {
		nm_dbg("find_or_create_mark: found existing mark\n");
		return get_nexus_mark(fs_mark);
	}

	mark = kzalloc(sizeof(*mark), GFP_KERNEL);
	if (!mark) {
		nm_err("find_or_create_mark: failed to allocate mark\n");
		return ERR_PTR(-ENOMEM);
	}

	fsnotify_init_mark(&mark->fs_mark, nexus_fsn_group);
	INIT_LIST_HEAD(&mark->listeners);
	INIT_LIST_HEAD(&mark->children);
	INIT_LIST_HEAD(&mark->sibling);
	INIT_LIST_HEAD(&mark->children_vrefs);
	spin_lock_init(&mark->lock);
	spin_lock_init(&mark->children_vrefs_lock);

	mark->device = inode->i_sb->s_dev;
	mark->inode = inode->i_ino;
	mark->is_dir = S_ISDIR(inode->i_mode);
	mark->vref_id = -1;
	mark->mnt_stored = NULL;

	nm_dbg("find_or_create_mark: creating new mark dev=%u ino=%lu is_dir=%d\n",
		(unsigned)mark->device, (unsigned long)mark->inode, mark->is_dir);

	ret = fsnotify_add_inode_mark(&mark->fs_mark, inode, 0);
	if (ret) {
		nm_err("find_or_create_mark: fsnotify_add_inode_mark failed: %d\n", ret);
		kfree(mark);
		return ERR_PTR(ret);
	}

	unsigned long flags;
	uint32_t hash = hash_dev_ino(mark->device, mark->inode);
	nm_dbg_lock("find_or_create_mark: acquiring marks_hash_lock\n");
	spin_lock_irqsave(&marks_hash_lock, flags);
	hlist_add_head(&mark->hash_node, &marks_hash[hash]);
	spin_unlock_irqrestore(&marks_hash_lock, flags);

	return mark;
}

static uint32_t flags_to_fsnotify_mask(uint32_t flags)
{
	uint32_t mask = 0;

	if (flags & B_WATCH_NAME)
		mask |= FS_MOVED_FROM | FS_MOVED_TO | FS_MOVE_SELF;
	if (flags & B_WATCH_STAT)
		mask |= FS_MODIFY | FS_ATTRIB | FS_CLOSE_WRITE;
	if (flags & B_WATCH_ATTR)
		mask |= FS_ATTRIB;
	if (flags & B_WATCH_DIRECTORY)
		mask |= FS_CREATE | FS_DELETE | FS_MOVED_FROM | FS_MOVED_TO;

	nm_dbg("flags_to_fsnotify_mask: B_WATCH=0x%x -> fsnotify=0x%x\n",
		flags, mask);
	return mask;
}


// Note: This is needed because fsnotify_detach_mark may not be exported
// in all kernel versions.
static void nexus_detach_mark(struct fsnotify_mark *mark)
{
	nm_dbg("nexus_detach_mark: mark=%p\n", mark);

	fsnotify_group_assert_locked(mark->group);

	spin_lock(&mark->lock);
	if (!(mark->flags & FSNOTIFY_MARK_FLAG_ATTACHED)) {
		spin_unlock(&mark->lock);
		nm_dbg("nexus_detach_mark: mark already detached\n");
		return;
	}
	mark->flags &= ~FSNOTIFY_MARK_FLAG_ATTACHED;
	list_del_init(&mark->g_list);
	spin_unlock(&mark->lock);

	fsnotify_put_mark(mark);
}

static int nexus_start_watching(struct nexus_watch_fd __user *exchange)
{
	struct nexus_watch_fd req;
	struct nexus_mark *mark;
	struct nexus_listener *listener;
	struct fd f;
	struct file *file;
	struct inode *inode;
	unsigned long flags;

	if (copy_from_user(&req, exchange, sizeof(req)))
		return -EFAULT;

	nm_dbg("nexus_start_watching: fd=%d flags=0x%x port=%d token=%u\n",
		req.fd, req.flags, req.port, req.token);

	if (req.fd < 0) {
		if (req.flags == B_WATCH_MOUNT) {
			nm_dbg("nexus_start_watching: B_WATCH_MOUNT handled in userspace\n");
			return 0;
		}
		nm_err("nexus_start_watching: invalid fd=%d with flags=0x%x\n",
			req.fd, req.flags);
		return -EINVAL;
	}

	f = fdget(req.fd);
	file = FD_FILE(f);
	if (!file) {
		nm_err("nexus_start_watching: bad fd=%d\n", req.fd);
		return -EBADF;
	}

	inode = file_inode(file);
	if (!inode) {
		nm_err("nexus_start_watching: no inode for fd=%d\n", req.fd);
		fdput(f);
		return -EINVAL;
	}

	mark = find_or_create_mark(inode);
	if (IS_ERR(mark)) {
		fdput(f);
		return PTR_ERR(mark);
	}

	if ((req.flags & B_WATCH_CHILDREN) && !mark->is_dir) {
		nm_err("nexus_start_watching: B_WATCH_CHILDREN on non-directory\n");
		fdput(f);
		fsnotify_put_mark(&mark->fs_mark);
		return -ENOTDIR;
	}

	listener = kmalloc(sizeof(*listener), GFP_KERNEL);
	if (!listener) {
		nm_err("nexus_start_watching: failed to allocate listener\n");
		fdput(f);
		fsnotify_put_mark(&mark->fs_mark);
		return -ENOMEM;
	}

	listener->port = req.port;
	listener->token = req.token;
	listener->flags = req.flags;

	if (mark->vref_id < 0) {
		int32_t vref = nexus_vref_create_from_file(file);
		if (vref < 0) {
			nm_warn("nexus_start_watching: vref creation failed for fd=%d "
				"(vref_id will be -1, virtual:node unavailable)\n",
				req.fd);
		} else {
			mark->vref_id = vref;
			nm_dbg("nexus_start_watching: created vref_id=%d for ino=%lu\n",
				vref, (unsigned long)inode->i_ino);
		}
	}

	if (!mark->mnt_stored && file->f_path.mnt) {
		mark->mnt_stored = mntget(file->f_path.mnt);
		nm_dbg("nexus_start_watching: stored mnt %p for ino=%lu\n",
			mark->mnt_stored, (unsigned long)inode->i_ino);
	}

	nm_dbg_lock("nexus_start_watching: acquiring mark->lock\n");
	spin_lock_irqsave(&mark->lock, flags);
	list_add(&listener->list, &mark->listeners);

	if (req.flags & B_WATCH_CHILDREN) {
		mark->watch_children = true;
		mark->inherited_flags = req.flags;
		mark->inherited_port = req.port;
		mark->inherited_token = req.token;
		nm_dbg("nexus_start_watching: B_WATCH_CHILDREN enabled\n");
	}
	spin_unlock_irqrestore(&mark->lock, flags);

	mark->fs_mark.mask |= flags_to_fsnotify_mask(req.flags);

#if NEXUS_NM_DEBUG
	atomic_inc(&stat_watches);
	nm_dbg("nexus_start_watching: success, total watches=%d\n",
		atomic_read(&stat_watches));
#endif

	fdput(f);
	fsnotify_put_mark(&mark->fs_mark);
	return 0;
}

static int nexus_stop_watching(struct nexus_unwatch_fd __user *exchange)
{
	struct nexus_unwatch_fd req;
	struct fsnotify_mark *fs_mark;
	struct nexus_mark *mark;
	struct nexus_listener *listener, *tmp;
	unsigned long flags;
	int found = 0;

	if (copy_from_user(&req, exchange, sizeof(req)))
		return -EFAULT;

	nm_dbg("nexus_stop_watching: dev=%llu node=%llu port=%d token=%u\n",
		req.device, req.node, req.port, req.token);

	if (req.device == (uint64_t)-1 && req.node == (uint64_t)-1) {
		nm_dbg("nexus_stop_watching: mount watching, handled in userspace\n");
		return 0;
	}

	nm_dbg_lock("nexus_stop_watching: acquiring mark_mutex\n");
	mutex_lock(&nexus_fsn_group->mark_mutex);

	list_for_each_entry(fs_mark, &nexus_fsn_group->marks_list, g_list) {
		mark = get_nexus_mark(fs_mark);
		if (mark->device != (dev_t)req.device || mark->inode != (ino_t)req.node)
			continue;

		nm_dbg_lock("nexus_stop_watching: acquiring mark->lock\n");
		spin_lock_irqsave(&mark->lock, flags);

		list_for_each_entry_safe(listener, tmp, &mark->listeners, list) {
			if (listener->port == req.port && listener->token == req.token) {
				nm_dbg("nexus_stop_watching: removing listener port=%d token=%u\n",
					listener->port, listener->token);
				list_del(&listener->list);
				kfree(listener);
				found = 1;
#if NEXUS_NM_DEBUG
				atomic_dec(&stat_watches);
#endif
				break;
			}
		}

		if (list_empty(&mark->listeners) && !mark->parent) {
			nm_dbg("nexus_stop_watching: no more listeners, detaching mark\n");
			spin_unlock_irqrestore(&mark->lock, flags);
			nexus_detach_mark(fs_mark);
		} else {
			spin_unlock_irqrestore(&mark->lock, flags);
		}
		break;
	}

	mutex_unlock(&nexus_fsn_group->mark_mutex);

	nm_dbg("nexus_stop_watching: %s\n", found ? "found and removed" : "not found");
	return found ? 0 : -ENOENT;
}

static int nexus_stop_notifying(struct nexus_stop_notifying __user *exchange)
{
	struct nexus_stop_notifying req;
	struct fsnotify_mark *fs_mark, *tmp_mark;
	struct nexus_mark *mark;
	struct nexus_listener *listener, *tmp;
	unsigned long flags;
	int removed = 0;

	struct nexus_mark **marks_to_remove = NULL;
	int marks_count = 0;
	int marks_capacity = 16;
	int i;

	if (copy_from_user(&req, exchange, sizeof(req)))
		return -EFAULT;

	nm_dbg("nexus_stop_notifying: port=%d token=%u\n", req.port, req.token);

	marks_to_remove = kmalloc_array(marks_capacity, sizeof(*marks_to_remove),
		GFP_KERNEL);
	if (!marks_to_remove) {
		nm_err("failed to allocate marks_to_remove array\n");
		return -ENOMEM;
	}

	nm_dbg_lock("nexus_stop_notifying: acquiring mark_mutex\n");
	mutex_lock(&nexus_fsn_group->mark_mutex);

	list_for_each_entry_safe(fs_mark, tmp_mark,
		&nexus_fsn_group->marks_list, g_list) {

		mark = get_nexus_mark(fs_mark);

		nm_dbg_lock("nexus_stop_notifying: acquiring mark->lock\n");
		spin_lock_irqsave(&mark->lock, flags);

		list_for_each_entry_safe(listener, tmp, &mark->listeners, list) {
			if (listener->port == req.port && listener->token == req.token) {
				nm_dbg("nexus_stop_notifying: removing listener from mark dev=%u ino=%lu\n",
					(unsigned)mark->device, (unsigned long)mark->inode);
				list_del(&listener->list);
				kfree(listener);
				removed++;
#if NEXUS_NM_DEBUG
				atomic_dec(&stat_watches);
#endif
			}
		}

		if (list_empty(&mark->listeners) && !mark->parent) {
			if (marks_count >= marks_capacity) {
				int new_cap = marks_capacity * 2;
				struct nexus_mark **new_arr;
				new_arr = krealloc(marks_to_remove,
					new_cap * sizeof(*marks_to_remove), GFP_ATOMIC);
				if (new_arr) {
					marks_to_remove = new_arr;
					marks_capacity = new_cap;
				}
			}

			if (marks_count < marks_capacity) {
				// TODO kernel doesn't seem to export that
				//fsnotify_get_mark(&mark->fs_mark);
				marks_to_remove[marks_count++] = mark;
			}
		}

		spin_unlock_irqrestore(&mark->lock, flags);
	}

	mutex_unlock(&nexus_fsn_group->mark_mutex);

	// fsnotify_put_mark is going to handle RCU locking
	for (i = 0; i < marks_count; i++) {
		struct nexus_mark *m = marks_to_remove[i];
		nm_dbg("nexus_stop_notifying: destroying mark dev=%u ino=%lu\n",
			(unsigned)m->device, (unsigned long)m->inode);
		fsnotify_destroy_mark(&m->fs_mark, nexus_fsn_group);
		fsnotify_put_mark(&m->fs_mark);
	}

	kfree(marks_to_remove);

	nm_dbg("nexus_stop_notifying: removed %d listeners\n", removed);
	return 0;
}

static int nexus_nm_open(struct inode *inode, struct file *file)
{
	nm_dbg("nexus_nm_open\n");
	return 0;
}

static int nexus_nm_release(struct inode *inode, struct file *file)
{
	nm_dbg("nexus_nm_release\n");
	return 0;
}

static long nexus_nm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	nm_dbg("nexus_nm_ioctl: cmd=0x%x\n", cmd);

	switch (cmd) {
	case NEXUS_START_WATCHING:
		return nexus_start_watching((void __user *)arg);
	case NEXUS_STOP_WATCHING:
		return nexus_stop_watching((void __user *)arg);
	case NEXUS_STOP_NOTIFYING:
		return nexus_stop_notifying((void __user *)arg);
	case NEXUS_VREF_CREATE:
	case NEXUS_VREF_ACQUIRE:
	case NEXUS_VREF_ACQUIRE_FD:
	case NEXUS_VREF_OPEN:
	case NEXUS_VREF_RELEASE:
		return nexus_vref_ioctl(cmd, arg);
	case NEXUS_QUERY_VOLUME_FLAGS:
		return nexus_volume_ioctl_query_flags(arg);
	case NEXUS_ATTR_DIR_OPEN:
		return nexus_attr_ioctl_dir_open(arg);
	case NEXUS_ATTR_READ:
		return nexus_attr_ioctl_read(arg);
	case NEXUS_ATTR_WRITE:
		return nexus_attr_ioctl_write(arg);
	case NEXUS_ATTR_STAT:
		return nexus_attr_ioctl_stat(arg);
	case NEXUS_ATTR_REMOVE:
		return nexus_attr_ioctl_remove(arg);
	case NEXUS_ATTR_RENAME:
		return nexus_attr_ioctl_rename(arg);
	case NEXUS_INDEX_DIR_OPEN:
		return nexus_index_ioctl_dir_open(arg);
	case NEXUS_INDEX_CREATE:
		return nexus_index_ioctl_create(arg);
	case NEXUS_INDEX_REMOVE:
		return nexus_index_ioctl_remove(arg);
	case NEXUS_INDEX_STAT:
		return nexus_index_ioctl_stat(arg);
	case NEXUS_QUERY_OPEN:
		return nexus_query_ioctl_open(arg);
	default:
		nm_warn("nexus_nm_ioctl: unknown cmd=0x%x\n", cmd);
		return -ENOTTY;
	}
}

static const struct file_operations nexus_nm_fops = {
	.owner = THIS_MODULE,
	.open = nexus_nm_open,
	.release = nexus_nm_release,
	.unlocked_ioctl = nexus_nm_ioctl,
	.compat_ioctl = nexus_nm_ioctl
};

static struct miscdevice nexus_nm_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = NEXUS_NODE_MONITOR_DEVICE,
	.fops = &nexus_nm_fops,
};

uint64_t nexus_node_monitor_dev(void)
{
	return nexus_nm_miscdev.this_device
		? (uint64_t)nexus_nm_miscdev.this_device->devt : 0;
}

struct xattr_probe_data {
	struct inode *inode;
	char name[XATTR_NAME_MAX];
	int cause;
};

static void notify_xattr_change(struct inode *inode, const char *name, int cause)
{
	struct fsnotify_mark *fs_mark;
	struct nexus_mark *mark;
	struct nexus_listener *listener;
	unsigned long flags;

	// TODO we can't notify if we are in an atomic context, we need
	// to queue this elsewhere so that we can execute the operation
	// atomically.
	if (in_atomic() || irqs_disabled())
		return;

	if (!inode)
		return;

	nm_dbg("notify_xattr_change: ino=%lu name='%s' cause=%d\n",
		(unsigned long)inode->i_ino, name ? name : "(null)", cause);

	// Only user.beos.* xattrs are visible
	if (!name)
		return;
	static const char kBeosPrefix[] = "user.beos.";
	if (strncmp(name, kBeosPrefix, sizeof(kBeosPrefix) - 1) != 0)
		return;
	const char *stripped_name = name + sizeof(kBeosPrefix) - 1;

	fs_mark = fsnotify_find_mark(&inode->i_fsnotify_marks,
		FSNOTIFY_OBJ_TYPE_INODE, nexus_fsn_group);
	if (!fs_mark)
		return;

	mark = get_nexus_mark(fs_mark);

	struct listener_snapshot *snap = NULL;
	int snap_count = 0, i = 0;
	int32_t node_vref_id;
	dev_t device;

	nm_dbg_lock("notify_xattr_change: acquiring mark->lock\n");
	spin_lock_irqsave(&mark->lock, flags);
	node_vref_id = mark->vref_id;
	device = mark->device;
	list_for_each_entry(listener, &mark->listeners, list)
		if (listener->flags & B_WATCH_ATTR)
			snap_count++;
	if (snap_count > 0) {
		snap = kmalloc_array(snap_count, sizeof(*snap), GFP_ATOMIC);
		if (snap) {
			list_for_each_entry(listener, &mark->listeners, list) {
				if (listener->flags & B_WATCH_ATTR) {
					snap[i].port  = listener->port;
					snap[i].token = listener->token;
					snap[i].flags = listener->flags;
					i++;
				}
			}
			snap_count = i;
		} else {
			snap_count = 0;
		}
	}
	spin_unlock_irqrestore(&mark->lock, flags);

	for (i = 0; i < snap_count; i++) {
		struct nexus_listener tmp_listener = {
			.port  = snap[i].port,
			.token = snap[i].token,
			.flags = snap[i].flags,
		};
		notify_attr_changed(&tmp_listener, device,
			node_vref_id, -1, stripped_name, cause);
	}
	kfree(snap);

	fsnotify_put_mark(fs_mark);
}

void nexus_emit_attr_changed(struct file *file, const char *attr, int cause)
{
	struct inode *inode;
	struct fsnotify_mark *fs_mark;
	struct nexus_mark *mark;
	struct nexus_listener *listener;
	unsigned long flags;
	int32_t node_vref_id = -1;
	int32_t dir_vref_id  = -1;

	if (!file || !attr)
		return;

	inode = file_inode(file);
	if (!inode)
		return;

	nm_dbg("nexus_emit_attr_changed: ino=%lu attr='%s' cause=%d\n",
		(unsigned long)inode->i_ino, attr, cause);

	fs_mark = fsnotify_find_mark(&inode->i_fsnotify_marks,
		FSNOTIFY_OBJ_TYPE_INODE, nexus_fsn_group);
	if (!fs_mark)
		return;

	mark = get_nexus_mark(fs_mark);

	node_vref_id = mark->vref_id;
	if (mark->mnt_stored) {
		struct dentry *dentry = d_find_alias(inode);
		if (dentry) {
			struct dentry *parent = dget_parent(dentry);
			if (parent && parent != dentry)
				dir_vref_id = nm_vref_from_inode(d_inode(parent),
								 mark->mnt_stored);
			dput(parent);
			dput(dentry);
		}
	}

	struct listener_snapshot *snap = NULL;
	int snap_count = 0, i = 0;
	dev_t device = mark->device;

	nm_dbg_lock("nexus_emit_attr_changed: acquiring mark->lock\n");
	spin_lock_irqsave(&mark->lock, flags);
	list_for_each_entry(listener, &mark->listeners, list)
		if (listener->flags & B_WATCH_ATTR)
			snap_count++;
	if (snap_count > 0) {
		snap = kmalloc_array(snap_count, sizeof(*snap), GFP_ATOMIC);
		if (snap) {
			list_for_each_entry(listener, &mark->listeners, list) {
				if (listener->flags & B_WATCH_ATTR) {
					snap[i].port  = listener->port;
					snap[i].token = listener->token;
					snap[i].flags = listener->flags;
					i++;
				}
			}
			snap_count = i;
		} else {
			snap_count = 0;
		}
	}
	spin_unlock_irqrestore(&mark->lock, flags);

	for (i = 0; i < snap_count; i++) {
		struct nexus_listener tmp_listener = {
			.port  = snap[i].port,
			.token = snap[i].token,
			.flags = snap[i].flags,
		};
		notify_attr_changed(&tmp_listener, device,
				    node_vref_id, dir_vref_id,
				    attr, cause);
	}
	kfree(snap);

	fsnotify_put_mark(fs_mark);
}

static int setxattr_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct xattr_probe_data *data = (struct xattr_probe_data *)ri->data;

#ifdef CONFIG_X86_64
	struct dentry *dentry = (struct dentry *)regs->si;
	const char *name = (const char *)regs->dx;
#elif defined(CONFIG_ARM64)
	struct dentry *dentry = (struct dentry *)regs->regs[1];
	const char *name = (const char *)regs->regs[2];
#else
	nm_dbg("setxattr_entry_handler: unsupported architecture\n");
	data->inode = NULL;
	return 0;
#endif

	if (dentry && d_inode(dentry)) {
		data->inode = d_inode(dentry);
		if (name)
			strscpy(data->name, name, XATTR_NAME_MAX);
		else
			data->name[0] = '\0';
		data->cause = B_ATTR_CAUSE_CHANGED;
		nm_dbg("setxattr_entry_handler: ino=%lu name='%s'\n",
			(unsigned long)data->inode->i_ino, data->name);
	} else {
		data->inode = NULL;
	}
	return 0;
}

static int setxattr_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct xattr_probe_data *data = (struct xattr_probe_data *)ri->data;
	long ret = regs_return_value(regs);

	nm_dbg("setxattr_ret_handler: ret=%ld\n", ret);

	if (nexus_probe_is_suppressed()) {
		nm_dbg("setxattr_ret_handler: suppressed, skipping\n");
		data->inode = NULL;
		return 0;
	}

	if (ret == 0 && data->inode && data->name[0])
		notify_xattr_change(data->inode, data->name, data->cause);

	data->inode = NULL;
	return 0;
}

static int removexattr_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct xattr_probe_data *data = (struct xattr_probe_data *)ri->data;

#ifdef CONFIG_X86_64
	struct dentry *dentry = (struct dentry *)regs->si;
	const char *name = (const char *)regs->dx;
#elif defined(CONFIG_ARM64)
	struct dentry *dentry = (struct dentry *)regs->regs[1];
	const char *name = (const char *)regs->regs[2];
#else
	data->inode = NULL;
	return 0;
#endif

	if (dentry && d_inode(dentry)) {
		data->inode = d_inode(dentry);
		if (name)
			strscpy(data->name, name, XATTR_NAME_MAX);
		else
			data->name[0] = '\0';
		data->cause = B_ATTR_CAUSE_REMOVED;
		nm_dbg("removexattr_entry_handler: ino=%lu name='%s'\n",
			(unsigned long)data->inode->i_ino, data->name);
	} else {
		data->inode = NULL;
	}
	return 0;
}

static int removexattr_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct xattr_probe_data *data = (struct xattr_probe_data *)ri->data;
	long ret = regs_return_value(regs);

	nm_dbg("removexattr_ret_handler: ret=%ld\n", ret);

	if (nexus_probe_is_suppressed()) {
		nm_dbg("removexattr_ret_handler: suppressed, skipping\n");
		data->inode = NULL;
		return 0;
	}

	if (ret == 0 && data->inode && data->name[0])
		notify_xattr_change(data->inode, data->name, B_ATTR_CAUSE_REMOVED);

	data->inode = NULL;
	return 0;
}

static struct kretprobe setxattr_kretprobe = {
	.handler = setxattr_ret_handler,
	.entry_handler = setxattr_entry_handler,
	.maxactive = 20,
	.data_size = sizeof(struct xattr_probe_data),
	.kp.symbol_name = "vfs_setxattr",
};

static struct kretprobe removexattr_kretprobe = {
	.handler = removexattr_ret_handler,
	.entry_handler = removexattr_entry_handler,
	.maxactive = 20,
	.data_size = sizeof(struct xattr_probe_data),
	.kp.symbol_name = "vfs_removexattr",
};

static int register_xattr_kprobes(void)
{
	int ret;

	ret = register_kretprobe(&setxattr_kretprobe);
	if (ret < 0) {
		nm_warn("setxattr kretprobe registration failed: %d\n", ret);
		return ret;
	}

	ret = register_kretprobe(&removexattr_kretprobe);
	if (ret < 0) {
		nm_warn("removexattr kretprobe registration failed: %d\n", ret);
		unregister_kretprobe(&setxattr_kretprobe);
		return ret;
	}

	nm_info("xattr kprobes registered successfully\n");
	return 0;
}

static void unregister_xattr_kprobes(void)
{
	unregister_kretprobe(&setxattr_kretprobe);
	unregister_kretprobe(&removexattr_kretprobe);
	nm_dbg("xattr kprobes unregistered\n");
}

static int __init nexus_node_monitor_init(void)
{
	int ret;

	nm_info("initializing nexus node monitor\n");

	nexus_fsn_group = fsnotify_alloc_group(&nexus_fsn_ops, 0);
	if (IS_ERR(nexus_fsn_group)) {
		nm_err("failed to allocate fsnotify group: %ld\n",
			PTR_ERR(nexus_fsn_group));
		return PTR_ERR(nexus_fsn_group);
	}

	ret = misc_register(&nexus_nm_miscdev);
	if (ret) {
		nm_err("failed to register misc device: %d\n", ret);
		fsnotify_put_group(nexus_fsn_group);
		return ret;
	}

	ret = register_xattr_kprobes();
	if (ret < 0)
		nm_warn("xattr tracking disabled (kprobes failed)\n");

	nexus_volume_init();
	nexus_vref_init();
	nexus_register_team_exit(nexus_vref_team_exit);
	nexus_query_init();
	nexus_attr_init();
	nexus_index_init();

	nm_info("loaded successfully: /dev/%s\n", NEXUS_NODE_MONITOR_DEVICE);
	return 0;
}

static void __exit nexus_node_monitor_exit(void)
{
	struct pending_move *pm, *tmp;

	nm_info("unloading\n");

#if NEXUS_NM_DEBUG
	nm_info("stats: watches=%d events=%d messages=%d\n",
		atomic_read(&stat_watches),
		atomic_read(&stat_events),
		atomic_read(&stat_messages));
#endif

		nexus_index_exit();
	nexus_attr_exit();
	nexus_query_exit();
	nexus_unregister_team_exit(nexus_vref_team_exit);
	nexus_vref_exit();
	nexus_volume_exit();

	unregister_xattr_kprobes();
	misc_deregister(&nexus_nm_miscdev);
	fsnotify_put_group(nexus_fsn_group);

	spin_lock(&move_lock);
	list_for_each_entry_safe(pm, tmp, &pending_moves, list) {
		list_del(&pm->list);
		kfree(pm);
	}
	spin_unlock(&move_lock);

	nm_info("unloaded\n");
}

module_init(nexus_node_monitor_init);
module_exit(nexus_node_monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dario Casalinuovo");
MODULE_DESCRIPTION("Nexus node monitor");
MODULE_VERSION("0.9");
