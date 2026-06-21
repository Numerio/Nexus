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
#include <linux/workqueue.h>
#include <linux/sched/mm.h>
#include <linux/mnt_idmapping.h>

#include "kmsg.h"
#include "node_monitor.h"
#include "nexus.h"
#include "nexus_private.h"
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

// Ratelimited so a bursty hot path (Deskbar menu open, bulk renames, etc.)
// can't saturate the serial console and starve every other process waiting
// on console_sem.
#define nm_err(fmt, ...)   pr_err_ratelimited("nexus_nm: ERROR: " fmt, ##__VA_ARGS__)
#define nm_warn(fmt, ...)  pr_warn_ratelimited("nexus_nm: WARN: " fmt, ##__VA_ARGS__)
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


/* For each B_NODE_REF_TYPE / B_REF_TYPE field in a finalized KMessage
 * buffer, ensure target_team has a kernel slot for the embedded vref id.
 * Kernel ships these KMessages via plain port write (no cap-transport),
 * so without a pre-minted slot the receiver's acquire would EPERM. */
static void
nm_grant_vrefs_in_kmsg(const char *buffer, size_t size, pid_t target_team)
{
	size_t off;

	if (target_team <= 0 || buffer == NULL || size < KMSG_HEADER_SIZE)
		return;

	off = KMSG_HEADER_SIZE;
	while (off + 18 <= size) {
		const char *fp = buffer + off;
		uint32_t type = *(const uint32_t *)(fp + 0);
		int32_t field_size = *(const int32_t *)(fp + 12);
		int16_t header_size = *(const int16_t *)(fp + 16);

		if (field_size <= 0 || (size_t)field_size > size - off)
			break;
		if (header_size <= 0
				|| (size_t)header_size > (size_t)field_size)
			break;

		if ((type == B_NODE_REF_TYPE || type == B_REF_TYPE)
				&& (size_t)header_size + 16 <= (size_t)field_size) {
			/* Field value: [4-byte length][dev:8][id:8]. */
			const char *vp = fp + header_size;
			int64_t id = *(const int64_t *)(vp + 4 + 8);

			if (id >= 0 && id <= S32_MAX)
				nexus_vref_grant_slot_for_id((int32_t)id,
					target_team);
		}

		off += (size_t)((field_size + 3) & ~3);
	}
}

/* Walks a finalized KMessage buffer and applies op to every embedded
 * vref id (B_NODE_REF_TYPE / B_REF_TYPE fields). Used to bump/drop the
 * kernel ref on each id so the vref outlives a mark teardown that
 * happens between queue_notification and the dispatch worker's send. */
typedef bool (*nm_vref_id_op)(int32_t id);

static int
nm_walk_vref_ids_in_kmsg(const char *buffer, size_t size, nm_vref_id_op op)
{
	size_t off;
	int count = 0;

	if (buffer == NULL || size < KMSG_HEADER_SIZE)
		return 0;

	off = KMSG_HEADER_SIZE;
	while (off + 18 <= size) {
		const char *fp = buffer + off;
		uint32_t type = *(const uint32_t *)(fp + 0);
		int32_t field_size = *(const int32_t *)(fp + 12);
		int16_t header_size = *(const int16_t *)(fp + 16);

		if (field_size <= 0 || (size_t)field_size > size - off)
			break;
		if (header_size <= 0
				|| (size_t)header_size > (size_t)field_size)
			break;

		if ((type == B_NODE_REF_TYPE || type == B_REF_TYPE)
				&& (size_t)header_size + 16 <= (size_t)field_size) {
			const char *vp = fp + header_size;
			int64_t id = *(const int64_t *)(vp + 4 + 8);

			if (id >= 0 && id <= S32_MAX) {
				if (op((int32_t)id))
					count++;
			}
		}
		off += (size_t)((field_size + 3) & ~3);
	}
	return count;
}

static bool nm_vref_acquire_op(int32_t id)
{
	return nexus_vref_acquire_kernel_ref(id);
}

static bool nm_vref_drop_op(int32_t id)
{
	nexus_vref_drop_kernel_ref(id);
	return true;
}

struct nexus_listener {
	struct list_head list;
	port_id port;
	uint32_t token;
	uint32_t flags;
};

struct nm_child_vref {
	struct list_head list;
	dev_t            device;
	ino_t            inode;
	int32_t          vref_id;
};

struct nexus_mark {
	struct fsnotify_mark fs_mark;
	dev_t device;
	ino_t inode;
	bool is_dir;

	struct list_head listeners;     // protected by lock
	spinlock_t lock;

	struct hlist_node hash_node;    // protected by marks_hash_lock

	int32_t          vref_id;       // -1 if unminted
	struct vfsmount *mnt_stored;    // for nm_vref_from_inode

	struct list_head children_vrefs;
	spinlock_t       children_vrefs_lock;
};

struct pending_move {
	struct list_head list;
	uint32_t cookie;
	int32_t old_dir_vref_id;   // mark->vref_id from MOVED_FROM; never dropped (mark owns it)
	unsigned long expires;
	char old_name[NAME_MAX + 1];
};

/* Deferred child-vref creation queue.  The fsnotify event handler runs on
 * the originating syscall thread (mkdir, open, etc.).  Calling
 * nm_vref_from_inode there (d_find_alias + dentry_open) is too expensive
 * and freezes the whole desktop.  Instead we igrab the inode, queue it
 * here, and let the dispatch worker mint the vref off-thread. */
struct pending_child_vref {
	struct list_head list;
	struct nexus_mark *mark;   /* refcount-held */
	struct inode    *inode;    /* igrab'd */
	struct vfsmount *mnt;      /* mntget'd */
	dev_t            device;
	ino_t            ino;
};

static LIST_HEAD(nm_pending_vrefs);
static DEFINE_SPINLOCK(nm_pending_vrefs_lock);

static struct fsnotify_group *nexus_fsn_group;
static LIST_HEAD(pending_moves);
static DEFINE_SPINLOCK(move_lock);

static DEFINE_HASHTABLE(marks_hash, MARK_HASH_BITS);
static DEFINE_SPINLOCK(marks_hash_lock);
// Serializes find-then-attach in find_or_create_mark. Distinct from
// fsnotify's group->mark_mutex (which add_inode_mark takes internally,
// so we can't wrap it ourselves).
static DEFINE_MUTEX(find_or_create_mutex);

#if NEXUS_NM_DEBUG
static atomic_t stat_watches = ATOMIC_INIT(0);
static atomic_t stat_events = ATOMIC_INIT(0);
static atomic_t stat_messages = ATOMIC_INIT(0);
#endif
// Counts xattr-change events dropped because we were in atomic context
// (interrupt / spinlock). Visible regardless of NEXUS_NM_DEBUG so we can
// see whether the in_atomic() guard is silently losing notifications.
static atomic_t stat_attr_dropped_atomic = ATOMIC_INIT(0);

static inline struct nexus_mark *get_nexus_mark(struct fsnotify_mark *fs_mark)
{
	return container_of(fs_mark, struct nexus_mark, fs_mark);
}

static inline uint32_t hash_dev_ino(dev_t dev, ino_t ino)
{
	return hash_32((uint32_t)dev ^ (uint32_t)(ino >> 32) ^ (uint32_t)ino, MARK_HASH_BITS);
}

struct deferred_notification {
	struct list_head list;
	port_id port;
	uint32_t token;
	char buffer[KMSG_BUFFER_SIZE];
	size_t size;
};

// Global dispatch queue. fsnotify callbacks enqueue here and return
// immediately; a workqueue drains and writes to ports from kthread
// context, so we never block the FS-syscall thread on nexus_main_lock
// or a full receiver port.
static LIST_HEAD(nm_dispatch_queue);
static DEFINE_SPINLOCK(nm_dispatch_lock);
static unsigned int nm_dispatch_depth;
// Cap on outstanding notifications. Past this, new ones are dropped at
// queue time. Tracker treats missed node-monitor events as a "lost some,
// rescan if you care" signal — better than runaway queue + OOM.
#define NM_DISPATCH_MAX_DEPTH 2048
static struct workqueue_struct *nm_dispatch_wq;
static void nm_dispatch_work(struct work_struct *w);
static void nm_process_pending_vrefs(void);
static DECLARE_WORK(nm_dispatch_work_item, nm_dispatch_work);

static void queue_notification(struct kmsg_builder *msg, port_id port, uint32_t token)
{
	struct deferred_notification *notif;
	unsigned long flags;
	bool over_cap;

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

	nm_walk_vref_ids_in_kmsg(notif->buffer, notif->size,
		nm_vref_acquire_op);

	spin_lock_irqsave(&nm_dispatch_lock, flags);
	over_cap = nm_dispatch_depth >= NM_DISPATCH_MAX_DEPTH;
	if (!over_cap) {
		list_add_tail(&notif->list, &nm_dispatch_queue);
		nm_dispatch_depth++;
	}
	spin_unlock_irqrestore(&nm_dispatch_lock, flags);

	if (over_cap) {
		nm_walk_vref_ids_in_kmsg(notif->buffer, notif->size,
			nm_vref_drop_op);
		kfree(notif);
		nm_warn("dispatch queue full (>%u); dropping notification\n",
			NM_DISPATCH_MAX_DEPTH);
	}
}

static void nm_dispatch_work(struct work_struct *w)
{
	struct deferred_notification *notif;
	unsigned long flags;

	(void)w;

	/* Mint deferred child vrefs first, so they're available for
	 * notifications about to be dispatched. */
	nm_process_pending_vrefs();

	for (;;) {
		spin_lock_irqsave(&nm_dispatch_lock, flags);
		notif = list_first_entry_or_null(&nm_dispatch_queue,
			struct deferred_notification, list);
		if (notif) {
			list_del(&notif->list);
			nm_dispatch_depth--;
		}
		spin_unlock_irqrestore(&nm_dispatch_lock, flags);
		if (!notif)
			break;

		nm_grant_vrefs_in_kmsg(notif->buffer, notif->size,
			nexus_port_team_of(notif->port));
		nexus_write_port(notif->port, B_NODE_MONITOR,
			notif->buffer, notif->size);
#if NEXUS_NM_DEBUG
		atomic_inc(&stat_messages);
#endif
		nm_walk_vref_ids_in_kmsg(notif->buffer, notif->size,
			nm_vref_drop_op);
		kfree(notif);
	}
}

static void send_queued_notifications(void)
{
	if (nm_dispatch_wq)
		queue_work(nm_dispatch_wq, &nm_dispatch_work_item);
}

struct listener_snapshot {
	port_id port;
	uint32_t token;
	uint32_t flags;
};

/* Synchronous send used by the kprobe-driven attr path
 * (notify_xattr_change -> notify_attr_changed).  The in_atomic() guard in
 * notify_xattr_change keeps us out of contexts where a blocking port write
 * would be illegal. */
static void send_to_listener(struct nexus_listener *listener,
	struct kmsg_builder *msg)
{
	nm_dbg_msg("send_to_listener: port=%d token=%u size=%zu\n",
		listener->port, listener->token, msg->size);

	kmsg_finalize(msg, listener->port, listener->token);

#if NEXUS_NM_DEBUG
	atomic_inc(&stat_messages);
#endif

	nm_grant_vrefs_in_kmsg(msg->buffer, msg->size,
		nexus_port_team_of(listener->port));
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
	kmsg_add_uint64(&msg, "device", (uint64_t)device);
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
			/* old_dir_vref_id is mark->vref_id, not a
			 * freshly-minted ref — do not drop it. */
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

	if (mark->vref_id >= 0)
		nexus_vref_drop_kernel_ref(mark->vref_id);
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
		if (e->inode == inode->i_ino &&
		    e->device == inode->i_sb->s_dev) {
			id = e->vref_id;
			break;
		}
	}
	spin_unlock_irqrestore(&mark->children_vrefs_lock, flags);
	return id;
}

static void nm_queue_child_vref(struct nexus_mark *mark, struct inode *inode);

/* Synchronous vref creation for CREATE/MOVED_TO paths.  These are
 * relatively rare events (file creation, rename), and subscribers
 * like Tracker need a complete node_ref in the notification to
 * create or update their Pose.  The cost of d_find_alias +
 * dentry_open(O_PATH) is small relative to the filesystem I/O
 * that the originating syscall is already performing. */
static int32_t nm_mark_get_or_mint_child_vref(struct nexus_mark *mark,
	struct inode *inode)
{
	struct nm_child_vref *e;
	int32_t id = nm_mark_lookup_child_vref(mark, inode);
	if (id >= 0)
		return id;

	id = nm_vref_from_inode(inode, mark->mnt_stored);
	if (id < 0)
		return -1;

	e = kzalloc(sizeof(*e), GFP_ATOMIC);
	if (!e) {
		nexus_vref_drop_kernel_ref(id);
		return -1;
	}
	e->device  = inode->i_sb->s_dev;
	e->inode   = inode->i_ino;
	e->vref_id = id;

	{
		unsigned long cflags;
		struct nm_child_vref *existing;
		spin_lock_irqsave(&mark->children_vrefs_lock, cflags);
		list_for_each_entry(existing, &mark->children_vrefs, list) {
			if (existing->inode == e->inode &&
			    existing->device == e->device) {
				spin_unlock_irqrestore(
					&mark->children_vrefs_lock, cflags);
				nexus_vref_drop_kernel_ref(id);
				kfree(e);
				return existing->vref_id;
			}
		}
		list_add(&e->list, &mark->children_vrefs);
		spin_unlock_irqrestore(&mark->children_vrefs_lock, cflags);
	}
	return id;
}

/* Cache-only lookup for frequent events (MODIFY/ATTRIB/CLOSE_WRITE).
 * If the child was CREATE'd after the watch was established, the
 * vref is already cached here.  For pre-existing children, queue
 * a background warm-up so subsequent events find the vref. */
static inline int32_t nm_node_vref_for_event(struct nexus_mark *mark,
	struct inode *inode)
{
	int32_t id;
	if (inode->i_ino == mark->inode &&
	    inode->i_sb->s_dev == mark->device)
		return mark->vref_id;
	id = nm_mark_lookup_child_vref(mark, inode);
	if (id < 0)
		nm_queue_child_vref(mark, inode);
	return id;
}


/* Dir-side equivalent: when an event fires on a directory mark, the
 * parent inode is the watched mark itself, so reuse mark->vref_id rather
 * than minting a fresh vref via nm_vref_from_inode().  Userspace stores
 * the watch fd's vref id at start_watching time and compares incoming
 * notifications by node_ref equality; without this dedup every emitted
 * "virtual:directory" carried a different vref id than the one Tracker
 * holds, so the dirNode != targetModel->NodeRef() guard in
 * BPoseView::FSNotification dropped every CREATE/DELETE/MOVED. */
static inline int32_t nm_dir_vref_for_event(struct nexus_mark *mark,
	struct inode *dir)
{
	if (!dir)
		return -1;
	if (dir->i_ino == mark->inode &&
	    dir->i_sb->s_dev == mark->device)
		return mark->vref_id;
	/* Slow path (dir != mark): return -1 rather than blocking the
	 * syscall thread with nm_vref_from_inode.  Subscribers resolve
	 * by device + name. */
	return -1;
}

static int32_t nm_mark_release_child_vref(struct nexus_mark *mark,
	struct inode *inode)
{
	struct nm_child_vref *e, *tmp;
	int32_t id = -1;
	unsigned long flags;

	spin_lock_irqsave(&mark->children_vrefs_lock, flags);
	list_for_each_entry_safe(e, tmp, &mark->children_vrefs, list) {
		if (e->inode == inode->i_ino &&
		    e->device == inode->i_sb->s_dev) {
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
	unsigned int nofs_flags;

	if (!inode || !mnt)
		return -1;

	// Force GFP_NOFS for every allocation reachable from here.
	// We are typically on the fsnotify callback path with the
	// inode lock held by the originating syscall; without this,
	// dentry_open's GFP_KERNEL allocations can recurse into
	// writeback -> fsnotify -> us and deadlock under memory pressure.
	nofs_flags = memalloc_nofs_save();

	dentry = d_find_alias(inode);
	if (!dentry) {
		memalloc_nofs_restore(nofs_flags);
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
		memalloc_nofs_restore(nofs_flags);
		return -1;
	}

	vref_id = nexus_vref_create_from_file(f);
	fput(f);
	dput(dentry);

	memalloc_nofs_restore(nofs_flags);

	if (vref_id < 0)
		nm_dbg("nm_vref_from_inode: nexus_vref_create_from_file failed for ino=%lu\n",
			(unsigned long)inode->i_ino);

	return vref_id;
}

/* Queue an async child-vref creation.  Called from the fsnotify hot path
 * (nexus_handle_event).  Must be non-blocking. */
static void nm_queue_child_vref(struct nexus_mark *mark, struct inode *inode)
{
	struct pending_child_vref *pcv;
	struct inode *grabbed;

	if (!mark->mnt_stored)
		return;

	/* Dedup: skip if an entry for this (dev, ino) is already pending.
	 * Cheap O(n) scan under the lock — the list is short and only
	 * contains entries the worker hasn't drained yet. */
	spin_lock(&nm_pending_vrefs_lock);
	list_for_each_entry(pcv, &nm_pending_vrefs, list) {
		if (pcv->mark == mark &&
		    pcv->device == inode->i_sb->s_dev &&
		    pcv->ino == inode->i_ino) {
			spin_unlock(&nm_pending_vrefs_lock);
			return;
		}
	}
	spin_unlock(&nm_pending_vrefs_lock);

	grabbed = igrab(inode);
	if (!grabbed)
		return;

	pcv = kmalloc(sizeof(*pcv), GFP_ATOMIC);
	if (!pcv) {
		iput(grabbed);
		return;
	}

	refcount_inc(&mark->fs_mark.refcnt);
	pcv->mark   = mark;
	pcv->inode  = grabbed;
	pcv->mnt    = mntget(mark->mnt_stored);
	pcv->device = inode->i_sb->s_dev;
	pcv->ino    = inode->i_ino;

	spin_lock(&nm_pending_vrefs_lock);
	list_add_tail(&pcv->list, &nm_pending_vrefs);
	spin_unlock(&nm_pending_vrefs_lock);
}

/* Worker-side: mint all pending child vrefs.  Runs in kthread context,
 * so d_find_alias + dentry_open + nexus_vref_create_from_file are safe. */
static void nm_process_pending_vrefs(void)
{
	struct pending_child_vref *pcv, *tmp;
	LIST_HEAD(local);

	spin_lock(&nm_pending_vrefs_lock);
	list_splice_init(&nm_pending_vrefs, &local);
	spin_unlock(&nm_pending_vrefs_lock);

	list_for_each_entry_safe(pcv, tmp, &local, list) {
		int32_t id;
		struct nm_child_vref *e;
		unsigned long cflags;
		struct nm_child_vref *existing;

		/* Check cache first — another path may have created it */
		id = nm_mark_lookup_child_vref(pcv->mark, pcv->inode);
		if (id >= 0)
			goto release;

		id = nm_vref_from_inode(pcv->inode, pcv->mnt);
		if (id < 0)
			goto release;

		e = kmalloc(sizeof(*e), GFP_KERNEL);
		if (!e) {
			nexus_vref_drop_kernel_ref(id);
			goto release;
		}
		e->device  = pcv->device;
		e->inode   = pcv->ino;
		e->vref_id = id;

		spin_lock_irqsave(&pcv->mark->children_vrefs_lock, cflags);
		list_for_each_entry(existing, &pcv->mark->children_vrefs, list) {
			if (existing->inode == pcv->ino &&
			    existing->device == pcv->device) {
				spin_unlock_irqrestore(
					&pcv->mark->children_vrefs_lock, cflags);
				kfree(e);
				nexus_vref_drop_kernel_ref(id);
				goto release;
			}
		}
		list_add(&e->list, &pcv->mark->children_vrefs);
		spin_unlock_irqrestore(&pcv->mark->children_vrefs_lock, cflags);

		nm_dbg("nm_process_pending_vrefs: minted vref_id=%d for "
			"dev=%u ino=%lu\n", id,
			(unsigned)pcv->device, (unsigned long)pcv->ino);

	release:
		fsnotify_put_mark(&pcv->mark->fs_mark);
		iput(pcv->inode);
		mntput(pcv->mnt);
		list_del(&pcv->list);
		kfree(pcv);
	}
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

	if (!mask)
		return 0;

	bool parent_in_iter = false;

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

		if (dir && mark->inode == dir->i_ino &&
		    mark->device == device)
			parent_in_iter = true;

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

			if ((mask & FS_CREATE) && (lflags & (B_WATCH_DIRECTORY | B_WATCH_CHILDREN))) {
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t child_vref_id;

				if (!dir_vref_tried && dir && mark->mnt_stored) {
					dir_vref_id = nm_dir_vref_for_event(mark, dir);
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
				kmsg_add_uint64(&msg, "device", (uint64_t)device);

				if (dir_vref_id >= 0)
					kmsg_add_entryref(&msg, "virtual:directory",
						sentinel, (int64_t)dir_vref_id, name);

				if (child_vref_id >= 0)
					kmsg_add_noderef(&msg, "virtual:node",
						sentinel, (int64_t)child_vref_id);
				if (name && name[0])
					kmsg_add_string(&msg, "name", name);
				queue_notification(&msg, port, token);
			}

			if ((mask & FS_DELETE) && (lflags & (B_WATCH_DIRECTORY | B_WATCH_CHILDREN))) {
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t child_vref_id;

				if (!dir_vref_tried && dir && mark->mnt_stored) {
					dir_vref_id = nm_dir_vref_for_event(mark, dir);
					dir_vref_tried = true;
					if (dir_vref_id < 0)
						nm_dbg("handle_event DELETE: "
							"parent vref unavailable, "
							"virtual:directory omitted\n");
				}

				child_vref_id = nm_mark_release_child_vref(mark, inode);

				kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
				kmsg_add_int32(&msg, "opcode", B_ENTRY_REMOVED);
				kmsg_add_uint64(&msg, "device", (uint64_t)device);
				if (dir_vref_id >= 0)
					kmsg_add_entryref(&msg, "virtual:directory",
						sentinel, (int64_t)dir_vref_id, name);
				if (child_vref_id >= 0)
					kmsg_add_noderef(&msg, "virtual:node",
						sentinel, (int64_t)child_vref_id);
				if (name && name[0])
					kmsg_add_string(&msg, "name", name);
				queue_notification(&msg, port, token);
			}

			if ((mask & FS_MOVED_FROM)
				&& (lflags & (B_WATCH_NAME | B_WATCH_DIRECTORY | B_WATCH_CHILDREN))) {
				struct pending_move *pm;
				unsigned long mflags;
				int32_t old_dir_vref = -1;
				/* nm_dir_vref_for_event returns mark->vref_id
				 * (not a freshly-minted ref), so we never drop
				 * it here — the mark owns its lifetime. */
				if (dir)
					old_dir_vref = nm_dir_vref_for_event(mark, dir);

				spin_lock_irqsave(&move_lock, mflags);
				cleanup_expired_moves();

				if (cookie) {
					pm = kmalloc(sizeof(*pm), GFP_ATOMIC);
					if (pm) {
						pm->cookie = cookie;
						pm->old_dir_vref_id = old_dir_vref;
						pm->expires = jiffies +
							msecs_to_jiffies(MOVE_TIMEOUT_MS);
						strscpy(pm->old_name, name,
							sizeof(pm->old_name));
						list_add(&pm->list, &pending_moves);
					}
				}
				spin_unlock_irqrestore(&move_lock, mflags);
			}

			if ((mask & FS_MOVED_TO)
				&& (lflags & (B_WATCH_NAME | B_WATCH_DIRECTORY | B_WATCH_CHILDREN))) {
				struct pending_move *pm;
				unsigned long mflags;
				char old_name[NAME_MAX + 1] = "";
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t to_dir_vref_id  = -1;
				int32_t from_dir_vref_id = -1;
				int32_t child_vref_id;

				spin_lock_irqsave(&move_lock, mflags);
				pm = find_pending_move(cookie);
				if (pm) {
					from_dir_vref_id = pm->old_dir_vref_id;
					pm->old_dir_vref_id = -1; // ownership transferred
					strscpy(old_name, pm->old_name, sizeof(old_name));
					list_del(&pm->list);
					kfree(pm);
				}
				spin_unlock_irqrestore(&move_lock, mflags);

				if (!dir_vref_tried && dir && mark->mnt_stored) {
					dir_vref_id = nm_dir_vref_for_event(mark, dir);
					dir_vref_tried = true;
				}
				to_dir_vref_id = dir_vref_id;

				child_vref_id = nm_mark_get_or_mint_child_vref(mark,
					inode);

				kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
				kmsg_add_int32(&msg, "opcode", B_ENTRY_MOVED);
				kmsg_add_uint64(&msg, "device", (uint64_t)device);

				kmsg_add_int64(&msg, "node device", (int64_t)device);
				if (from_dir_vref_id >= 0)
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
				queue_notification(&msg, port, token);
			}

			if ((mask & FS_MODIFY) && (lflags & B_WATCH_STAT)) {
				bool interim = (lflags & B_WATCH_INTERIM_STAT) != 0;
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t target_vref =
					nm_node_vref_for_event(mark, inode);
				uint32_t fields =
					B_STAT_SIZE | B_STAT_MODIFICATION_TIME;
				if (interim)
					fields |= B_STAT_INTERIM_UPDATE;
				kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
				kmsg_add_int32(&msg, "opcode", B_STAT_CHANGED);
				kmsg_add_uint64(&msg, "device", (uint64_t)device);
				if (target_vref >= 0)
					kmsg_add_noderef(&msg, "virtual:node",
						sentinel, (int64_t)target_vref);
				kmsg_add_int32(&msg, "fields", (int32_t)fields);
				queue_notification(&msg, port, token);
			}

			if ((mask & FS_ATTRIB) && (lflags & B_WATCH_STAT)) {
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t target_vref =
					nm_node_vref_for_event(mark, inode);
				kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
				kmsg_add_int32(&msg, "opcode", B_STAT_CHANGED);
				kmsg_add_uint64(&msg, "device", (uint64_t)device);
				if (target_vref >= 0)
					kmsg_add_noderef(&msg, "virtual:node",
						sentinel, (int64_t)target_vref);
				kmsg_add_int32(&msg, "fields",
					B_STAT_MODE | B_STAT_UID | B_STAT_GID |
					B_STAT_CHANGE_TIME);
				queue_notification(&msg, port, token);
			}

			// FS_ATTRIB with B_WATCH_ATTR is intentionally NOT
			// handled here.  Attribute-change notifications are the
			// exclusive domain of the vfs_setxattr/vfs_removexattr
			// kretprobes (see notify_xattr_change), which fire on the
			// actual xattr write and carry the real attribute name.
			// Emitting B_ATTR_CHANGED from this fsnotify path too
			// would duplicate every attribute notification.

			// FS_CLOSE_WRITE -> B_STAT_CHANGED.  Linux fires this
			// once when a writer closes a file; the matching Haiku
			// semantic is a final size+mtime update.  FS_MODIFY covers
			// per-write churn; this branch is the "writer done" hint
			// that many editor-save flows depend on.
			if ((mask & FS_CLOSE_WRITE) && (lflags & B_WATCH_STAT)) {
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t target_vref =
					nm_node_vref_for_event(mark, inode);
				kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
				kmsg_add_int32(&msg, "opcode", B_STAT_CHANGED);
				kmsg_add_uint64(&msg, "device", (uint64_t)device);
				if (target_vref >= 0)
					kmsg_add_noderef(&msg, "virtual:node",
						sentinel, (int64_t)target_vref);
				kmsg_add_int32(&msg, "fields",
					B_STAT_SIZE | B_STAT_MODIFICATION_TIME);
				queue_notification(&msg, port, token);
			}

			// FS_MOVE_SELF -> B_ENTRY_MOVED for the watched node
			// itself.  Linux fires this on the inode after a rename;
			// we don't get the from-name from fsnotify here (it was
			// delivered earlier via FS_MOVED_FROM on the old parent
			// mark, if any).  Emit a degraded B_ENTRY_MOVED with the
			// post-move location populated and from-info left empty;
			// receivers re-resolve from there.
			if ((mask & FS_MOVE_SELF) && (lflags & B_WATCH_NAME)) {
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t to_dir_vref_id = -1;
				int32_t target_vref =
					nm_node_vref_for_event(mark, inode);

				if (!dir_vref_tried && dir && mark->mnt_stored) {
					dir_vref_id = nm_dir_vref_for_event(mark, dir);
					dir_vref_tried = true;
				}
				to_dir_vref_id = dir_vref_id;

				kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
				kmsg_add_int32(&msg, "opcode", B_ENTRY_MOVED);
				kmsg_add_uint64(&msg, "device", (uint64_t)device);
				kmsg_add_int64(&msg, "node device", (int64_t)device);
				if (to_dir_vref_id >= 0)
					kmsg_add_entryref(&msg, "virtual:to directory",
						sentinel, (int64_t)to_dir_vref_id, name);
				if (target_vref >= 0)
					kmsg_add_noderef(&msg, "virtual:node",
						sentinel, (int64_t)target_vref);
				if (name && name[0])
					kmsg_add_string(&msg, "name", name);
				queue_notification(&msg, port, token);
			}

			// FS_DELETE_SELF -> B_ENTRY_REMOVED for the watched node
			// itself.  Receivers of B_WATCH_NAME on a file get this
			// when the file disappears; previously only
			// B_WATCH_DIRECTORY parent watchers got DELETE
			// notifications about their children.
			if ((mask & FS_DELETE_SELF) && (lflags & B_WATCH_NAME)) {
				char buf[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg;
				int32_t target_vref =
					nm_node_vref_for_event(mark, inode);

				if (!dir_vref_tried && dir && mark->mnt_stored) {
					dir_vref_id = nm_dir_vref_for_event(mark, dir);
					dir_vref_tried = true;
				}

				kmsg_init(&msg, buf, sizeof(buf), B_NODE_MONITOR);
				kmsg_add_int32(&msg, "opcode", B_ENTRY_REMOVED);
				kmsg_add_uint64(&msg, "device", (uint64_t)device);
				if (dir_vref_id >= 0)
					kmsg_add_entryref(&msg, "virtual:directory",
						sentinel, (int64_t)dir_vref_id,
						name ? name : "");
				if (target_vref >= 0)
					kmsg_add_noderef(&msg, "virtual:node",
						sentinel, (int64_t)target_vref);
				if (name && name[0])
					kmsg_add_string(&msg, "name", name);
				queue_notification(&msg, port, token);
			}
		}

		kfree(snap);
		snap = NULL;
	}

	if (dir && !parent_in_iter) {
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
		if (parent_mark)
			refcount_inc(&parent_mark->fs_mark.refcnt);
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

				if (mask & FS_CREATE) {
					char buf2[KMSG_BUFFER_SIZE];
					struct kmsg_builder msg2;
					int32_t pdvref = -1;
					int32_t cvref;

					pdvref = nm_dir_vref_for_event(parent_mark, dir);
					cvref = nm_mark_get_or_mint_child_vref(
						parent_mark, inode);
					kmsg_init(&msg2, buf2,
						sizeof(buf2), B_NODE_MONITOR);
					kmsg_add_int32(&msg2, "opcode",
						B_ENTRY_CREATED);
					kmsg_add_uint64(&msg2, "device",
						(uint64_t)device);
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
					queue_notification(
						&msg2, psnap[pi].port,
						psnap[pi].token);
				}

				if (mask & FS_DELETE) {
					char buf2[KMSG_BUFFER_SIZE];
					struct kmsg_builder msg2;
					int32_t pdvref = -1;
					int32_t cvref;

					pdvref = nm_dir_vref_for_event(parent_mark, dir);

					cvref = nm_mark_release_child_vref(
						parent_mark, inode);
					kmsg_init(&msg2, buf2,
						sizeof(buf2), B_NODE_MONITOR);
					kmsg_add_int32(&msg2, "opcode",
						B_ENTRY_REMOVED);
					kmsg_add_uint64(&msg2, "device",
						(uint64_t)device);
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
					queue_notification(
						&msg2, psnap[pi].port,
						psnap[pi].token);
				}

				// Parent-walk MOVED_FROM -> B_ENTRY_REMOVED.
				// Receivers handle remove+create across a rename;
				// cookie-pair upgrade to B_ENTRY_MOVED is omitted.
				if (mask & FS_MOVED_FROM) {
					char buf2[KMSG_BUFFER_SIZE];
					struct kmsg_builder msg2;
					int32_t pdvref = -1;
					int32_t cvref;

					if (parent_mark->mnt_stored)
						pdvref = nm_dir_vref_for_event(parent_mark, dir);
					cvref = nm_mark_lookup_child_vref(parent_mark, inode);

					kmsg_init(&msg2, buf2, sizeof(buf2), B_NODE_MONITOR);
					kmsg_add_int32(&msg2, "opcode", B_ENTRY_REMOVED);
					kmsg_add_uint64(&msg2, "device", (uint64_t)device);
					if (pdvref >= 0)
						kmsg_add_entryref(&msg2, "virtual:directory", sentinel, (int64_t)pdvref, name);
					if (cvref >= 0)
						kmsg_add_noderef(&msg2, "virtual:node", sentinel, (int64_t)cvref);
					if (name && name[0])
						kmsg_add_string(&msg2, "name", name);
					queue_notification(&msg2, psnap[pi].port, psnap[pi].token);
				}

				// Parent-walk MOVED_TO -> B_ENTRY_CREATED.
				if (mask & FS_MOVED_TO) {
					char buf2[KMSG_BUFFER_SIZE];
					struct kmsg_builder msg2;
					int32_t pdvref = -1;
					int32_t cvref;

					if (parent_mark->mnt_stored)
						pdvref = nm_dir_vref_for_event(parent_mark, dir);
					cvref = nm_mark_get_or_mint_child_vref(parent_mark, inode);

					kmsg_init(&msg2, buf2, sizeof(buf2), B_NODE_MONITOR);
					kmsg_add_int32(&msg2, "opcode", B_ENTRY_CREATED);
					kmsg_add_uint64(&msg2, "device", (uint64_t)device);
					if (pdvref >= 0)
						kmsg_add_entryref(&msg2, "virtual:directory", sentinel, (int64_t)pdvref, name);
					if (cvref >= 0)
						kmsg_add_noderef(&msg2, "virtual:node", sentinel, (int64_t)cvref);
					if (name && name[0])
						kmsg_add_string(&msg2, "name", name);
					queue_notification(&msg2, psnap[pi].port, psnap[pi].token);
				}

			// Parent-walk MODIFY -> B_STAT_CHANGED (size + mtime).
			if ((mask & FS_MODIFY) && (pflags & B_WATCH_STAT)) {
				bool interim = (pflags & B_WATCH_INTERIM_STAT) != 0;
				char buf2[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg2;
				int32_t cvref = nm_mark_lookup_child_vref(parent_mark, inode);
				if (cvref < 0) {
					nm_queue_child_vref(parent_mark, inode);
				}
				uint32_t fields = B_STAT_SIZE | B_STAT_MODIFICATION_TIME;
					if (interim)
						fields |= B_STAT_INTERIM_UPDATE;

					kmsg_init(&msg2, buf2, sizeof(buf2), B_NODE_MONITOR);
					kmsg_add_int32(&msg2, "opcode", B_STAT_CHANGED);
					kmsg_add_uint64(&msg2, "device", (uint64_t)device);
					if (cvref >= 0)
						kmsg_add_noderef(&msg2, "virtual:node", sentinel, (int64_t)cvref);
					kmsg_add_int32(&msg2, "fields", (int32_t)fields);
					queue_notification(&msg2, psnap[pi].port, psnap[pi].token);
				}

			// Parent-walk ATTRIB -> B_STAT_CHANGED (mode/uid/gid/ctime).
			if ((mask & FS_ATTRIB) && (pflags & B_WATCH_STAT)) {
				char buf2[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg2;
				int32_t cvref = nm_mark_lookup_child_vref(parent_mark, inode);
				if (cvref < 0) {
					nm_queue_child_vref(parent_mark, inode);
				}

				kmsg_init(&msg2, buf2, sizeof(buf2), B_NODE_MONITOR);
				kmsg_add_int32(&msg2, "opcode", B_STAT_CHANGED);
				kmsg_add_uint64(&msg2, "device", (uint64_t)device);
				if (cvref >= 0)
					kmsg_add_noderef(&msg2, "virtual:node", sentinel, (int64_t)cvref);
				kmsg_add_int32(&msg2, "fields", B_STAT_MODE | B_STAT_UID | B_STAT_GID | B_STAT_CHANGE_TIME);
				queue_notification(&msg2, psnap[pi].port, psnap[pi].token);
			}

			// Parent-walk CLOSE_WRITE -> B_STAT_CHANGED.
			if ((mask & FS_CLOSE_WRITE) && (pflags & B_WATCH_STAT)) {
				char buf2[KMSG_BUFFER_SIZE];
				struct kmsg_builder msg2;
				int32_t cvref = nm_mark_lookup_child_vref(parent_mark, inode);
				if (cvref < 0) {
					nm_queue_child_vref(parent_mark, inode);
				}

				kmsg_init(&msg2, buf2, sizeof(buf2), B_NODE_MONITOR);
				kmsg_add_int32(&msg2, "opcode", B_STAT_CHANGED);
				kmsg_add_uint64(&msg2, "device", (uint64_t)device);
				if (cvref >= 0)
					kmsg_add_noderef(&msg2, "virtual:node", sentinel, (int64_t)cvref);
				kmsg_add_int32(&msg2, "fields", B_STAT_SIZE | B_STAT_MODIFICATION_TIME);
				queue_notification(&msg2, psnap[pi].port, psnap[pi].token);
			}
		}

			kfree(psnap);
		}
		if (parent_mark)
			fsnotify_put_mark(&parent_mark->fs_mark);
	}

	send_queued_notifications();
	return 0;
}

static const struct fsnotify_ops nexus_fsn_ops = {
	.handle_event = nexus_handle_event,
	.freeing_mark = nexus_freeing_mark,
	.free_mark = nexus_mark_free,
};

static struct nexus_mark *find_or_create_mark(struct inode *inode,
	uint32_t initial_mask)
{
	struct fsnotify_mark *fs_mark;
	struct nexus_mark *mark;
	int ret;

	nm_dbg("find_or_create_mark: inode=%lu\n", (unsigned long)inode->i_ino);

	mutex_lock(&find_or_create_mutex);

	fs_mark = fsnotify_find_mark(&inode->i_fsnotify_marks,
		FSNOTIFY_OBJ_TYPE_INODE, nexus_fsn_group);
	if (fs_mark) {
		nm_dbg("find_or_create_mark: found existing mark\n");
		mutex_unlock(&find_or_create_mutex);
		return get_nexus_mark(fs_mark);
	}

	mark = kzalloc(sizeof(*mark), GFP_KERNEL);
	if (!mark) {
		nm_err("find_or_create_mark: failed to allocate mark\n");
		mutex_unlock(&find_or_create_mutex);
		return ERR_PTR(-ENOMEM);
	}

	fsnotify_init_mark(&mark->fs_mark, nexus_fsn_group);
	INIT_LIST_HEAD(&mark->listeners);
	INIT_LIST_HEAD(&mark->children_vrefs);
	spin_lock_init(&mark->lock);
	spin_lock_init(&mark->children_vrefs_lock);

	mark->device = inode->i_sb->s_dev;
	mark->inode = inode->i_ino;
	mark->is_dir = S_ISDIR(inode->i_mode);
	mark->vref_id = -1;
	mark->mnt_stored = NULL;

	nm_dbg("find_or_create_mark: creating new mark dev=%u ino=%lu is_dir=%d "
		"initial_mask=0x%x\n",
		(unsigned)mark->device, (unsigned long)mark->inode, mark->is_dir,
		initial_mask);

	// Seed the connector mask with the union of every fsnotify bit any
	// future listener might widen to. fsnotify_recalc_mask isn't exported,
	// so a later `mark->fs_mark.mask |= ...` updates the field but not the
	// connector's routing cache — events for the missing bits skip nexus
	// entirely. Per-listener flag filtering still runs in the dispatch
	// loop, so listeners only see events they asked for; the cost is one
	// extra dispatch-loop iteration per uninteresting kernel event.
	if (mark->is_dir)
		mark->fs_mark.mask = initial_mask
			| FS_CREATE | FS_DELETE
			| FS_MOVED_FROM | FS_MOVED_TO
			| FS_MOVE_SELF | FS_DELETE_SELF
			| FS_MODIFY | FS_ATTRIB | FS_CLOSE_WRITE;
	else
		mark->fs_mark.mask = initial_mask
			| FS_MODIFY | FS_ATTRIB | FS_CLOSE_WRITE
			| FS_MOVE_SELF | FS_DELETE_SELF;

	ret = fsnotify_add_inode_mark(&mark->fs_mark, inode, 0);
	if (ret == -EEXIST) {
		// Some other path attached a mark for our group to this inode
		// between our find_mark and add (find_or_create_mutex serializes
		// THIS function but apparently not every path). Discover the
		// winner and return it. Not an error worth logging.
		kfree(mark);
		fs_mark = fsnotify_find_mark(&inode->i_fsnotify_marks,
			FSNOTIFY_OBJ_TYPE_INODE, nexus_fsn_group);
		if (fs_mark) {
			mark = get_nexus_mark(fs_mark);
			mark->fs_mark.mask |= initial_mask;
			mutex_unlock(&find_or_create_mutex);
			return mark;
		}
		mutex_unlock(&find_or_create_mutex);
		return ERR_PTR(-EEXIST);
	}
	if (ret) {
		nm_err("find_or_create_mark: fsnotify_add_inode_mark failed: %d\n", ret);
		kfree(mark);
		mutex_unlock(&find_or_create_mutex);
		return ERR_PTR(ret);
	}

	unsigned long flags;
	uint32_t hash = hash_dev_ino(mark->device, mark->inode);
	spin_lock_irqsave(&marks_hash_lock, flags);
	hlist_add_head(&mark->hash_node, &marks_hash[hash]);
	spin_unlock_irqrestore(&marks_hash_lock, flags);

	mutex_unlock(&find_or_create_mutex);
	return mark;
}

static uint32_t flags_to_fsnotify_mask(uint32_t flags)
{
	uint32_t mask = 0;

	if (flags & B_WATCH_NAME)
		mask |= FS_MOVED_FROM | FS_MOVED_TO | FS_MOVE_SELF
			| FS_DELETE_SELF;
	if (flags & B_WATCH_STAT)
		mask |= FS_MODIFY | FS_ATTRIB | FS_CLOSE_WRITE;
	if (flags & B_WATCH_ATTR)
		mask |= FS_ATTRIB;
	if (flags & (B_WATCH_DIRECTORY | B_WATCH_CHILDREN))
		mask |= FS_CREATE | FS_DELETE | FS_MOVED_FROM | FS_MOVED_TO;

	nm_dbg("flags_to_fsnotify_mask: B_WATCH=0x%x -> fsnotify=0x%x\n",
		flags, mask);
	return mask;
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

	mark = find_or_create_mark(inode, flags_to_fsnotify_mask(req.flags));
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

	spin_lock_irqsave(&mark->lock, flags);
	list_add(&listener->list, &mark->listeners);
	spin_unlock_irqrestore(&mark->lock, flags);

	// Mask widening on an existing mark: the connector cache won't pick
	// up new bits without fsnotify_recalc_mask, which isn't exported. For
	// Tracker's workflow the first subscriber always seeds the full mask
	// in find_or_create_mark, so secondary watches still see events for
	// bits the first watch requested.
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

	struct fsnotify_mark *to_destroy = NULL;

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

		if (list_empty(&mark->listeners)) {
			to_destroy = fs_mark;
			// fsnotify_get_mark isn't exported on 6.12; bump refcnt
			// directly so the mark survives past mark_mutex unlock.
			refcount_inc(&to_destroy->refcnt);
		}
		spin_unlock_irqrestore(&mark->lock, flags);
		break;
	}

	mutex_unlock(&nexus_fsn_group->mark_mutex);

	if (to_destroy) {
		nm_dbg("nexus_stop_watching: no more listeners, destroying mark\n");
		fsnotify_destroy_mark(to_destroy, nexus_fsn_group);
		fsnotify_put_mark(to_destroy);
	}

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

		if (list_empty(&mark->listeners)) {
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
				// fsnotify_get_mark isn't exported on 6.12; bump
				// refcnt directly so the mark survives past
				// mark_mutex unlock, matching stop_watching's pattern.
				refcount_inc(&fs_mark->refcnt);
				marks_to_remove[marks_count++] = mark;
			}
		}

		spin_unlock_irqrestore(&mark->lock, flags);
	}

	mutex_unlock(&nexus_fsn_group->mark_mutex);

	// marks_list iteration doesn't bump refs, and destroy_mark doesn't
	// expect a caller-held ref. Just destroy; no put.
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
	case NEXUS_VREF_RELEASE:
	case NEXUS_VREF_OPEN:
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

/* =====================================================================
 * xattr change notification via kretprobes
 *
 * vfs_setxattr / vfs_removexattr are kretprobed.  On successful return the
 * inode + xattr name are handed to notify_xattr_change, which filters to
 * user.beos.* attributes and emits a B_ATTR_CHANGED to every listener with
 * B_WATCH_ATTR.  This is the SOLE source of attribute notifications; the
 * fsnotify FS_ATTRIB path deliberately does not emit B_ATTR_CHANGED, so each
 * attribute write produces exactly one notification.
 * ===================================================================== */

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
	// atomically. Until then, count drops so the loss is observable.
	if (in_atomic() || irqs_disabled()) {
		atomic_inc(&stat_attr_dropped_atomic);
		return;
	}

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

static int setxattr_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct xattr_probe_data *data = (struct xattr_probe_data *)ri->data;

#ifdef CONFIG_X86_64
	struct mnt_idmap *idmap = (struct mnt_idmap *)regs->di;
	struct dentry *dentry = (struct dentry *)regs->si;
	const char *name = (const char *)regs->dx;
#elif defined(CONFIG_ARM64)
	struct mnt_idmap *idmap = (struct mnt_idmap *)regs->regs[0];
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
		// Distinguish first-write (CREATED) from overwrite (CHANGED)
		// by probing whether the xattr already exists.  Safe here: the
		// kretprobe entry fires before vfs_setxattr takes inode_lock,
		// and vfs_getxattr is not one of our probed symbols so no
		// re-entrancy.
		if (name && name[0]) {
			unsigned int nofs = memalloc_nofs_save();
			ssize_t exist = vfs_getxattr(idmap, dentry, name, NULL, 0);
			memalloc_nofs_restore(nofs);
			data->cause = (exist >= 0)
				? B_ATTR_CAUSE_CHANGED : B_ATTR_CAUSE_CREATED;
		} else {
			data->cause = B_ATTR_CAUSE_CHANGED;
		}
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

/* Team-exit cleanup: when a process dies, drop every listener it owned and
 * destroy any mark left empty. Without this, listeners owned by SIGKILL'd
 * receivers accumulate on marks forever and every subsequent fs event pays
 * the cost of dispatching to a dead port (B_BAD_PORT_ID). Treat owner<=0
 * (port already torn down) the same as a match so we sweep stragglers too. */
static void node_monitor_team_exit(pid_t team)
{
	struct fsnotify_mark *fs_mark, *tmp_mark;
	struct nexus_mark *mark;
	struct nexus_listener *listener, *tmp;
	struct nexus_mark **marks_to_remove;
	int marks_count = 0, marks_capacity = 16, i;
	unsigned long flags;

	if (!nexus_fsn_group)
		return;

	marks_to_remove = kmalloc_array(marks_capacity, sizeof(*marks_to_remove),
		GFP_KERNEL);
	if (!marks_to_remove)
		return;

	mutex_lock(&nexus_fsn_group->mark_mutex);
	list_for_each_entry_safe(fs_mark, tmp_mark,
		&nexus_fsn_group->marks_list, g_list) {
		mark = get_nexus_mark(fs_mark);
		spin_lock_irqsave(&mark->lock, flags);
		list_for_each_entry_safe(listener, tmp, &mark->listeners, list) {
			pid_t owner = nexus_port_team_of((uint32_t)listener->port);
			if (owner == team || owner <= 0) {
				list_del(&listener->list);
				kfree(listener);
			}
		}
		if (list_empty(&mark->listeners)) {
			if (marks_count >= marks_capacity) {
				int new_cap = marks_capacity * 2;
				struct nexus_mark **new_arr = krealloc(marks_to_remove,
					new_cap * sizeof(*marks_to_remove), GFP_ATOMIC);
				if (new_arr) {
					marks_to_remove = new_arr;
					marks_capacity = new_cap;
				}
			}
			if (marks_count < marks_capacity) {
				refcount_inc(&fs_mark->refcnt);
				marks_to_remove[marks_count++] = mark;
			}
		}
		spin_unlock_irqrestore(&mark->lock, flags);
	}
	mutex_unlock(&nexus_fsn_group->mark_mutex);

	for (i = 0; i < marks_count; i++) {
		fsnotify_destroy_mark(&marks_to_remove[i]->fs_mark, nexus_fsn_group);
		fsnotify_put_mark(&marks_to_remove[i]->fs_mark);
	}
	kfree(marks_to_remove);
}

static int __init nexus_node_monitor_init(void)
{
	int ret;

	nm_info("initializing nexus node monitor\n");

	nm_dispatch_wq = alloc_workqueue("nexus_nm", WQ_UNBOUND, 1);
	if (!nm_dispatch_wq) {
		nm_err("failed to allocate dispatch workqueue\n");
		return -ENOMEM;
	}

	nexus_fsn_group = fsnotify_alloc_group(&nexus_fsn_ops, 0);
	if (IS_ERR(nexus_fsn_group)) {
		nm_err("failed to allocate fsnotify group: %ld\n",
			PTR_ERR(nexus_fsn_group));
		destroy_workqueue(nm_dispatch_wq);
		nm_dispatch_wq = NULL;
		return PTR_ERR(nexus_fsn_group);
	}

	ret = misc_register(&nexus_nm_miscdev);
	if (ret) {
		nm_err("failed to register misc device: %d\n", ret);
		fsnotify_put_group(nexus_fsn_group);
		destroy_workqueue(nm_dispatch_wq);
		nm_dispatch_wq = NULL;
		return ret;
	}

	ret = register_xattr_kprobes();
	if (ret < 0)
		nm_warn("xattr tracking disabled (kprobes failed)\n");

	if (nexus_register_team_exit(node_monitor_team_exit) < 0)
		nm_warn("team-exit callback registration failed; "
			"listeners from crashed teams will accumulate\n");

	if (nexus_volume_init())
		nm_warn("volume subsystem init failed\n");
	if (nexus_query_init())
		nm_warn("query subsystem init failed\n");
	if (nexus_attr_init())
		nm_warn("attr subsystem init failed\n");
	if (nexus_index_init())
		nm_warn("index subsystem init failed\n");

	nm_info("loaded successfully: /dev/%s\n", NEXUS_NODE_MONITOR_DEVICE);
	return 0;
}

static void __exit nexus_node_monitor_exit(void)
{
	struct pending_move *pm, *tmp;
	struct workqueue_struct *wq;
	struct deferred_notification *notif, *tnotif;
	unsigned long flags;

	nm_info("unloading\n");

#if NEXUS_NM_DEBUG
	nm_info("stats: watches=%d events=%d messages=%d\n",
		atomic_read(&stat_watches),
		atomic_read(&stat_events),
		atomic_read(&stat_messages));
#endif
	{
		int dropped = atomic_read(&stat_attr_dropped_atomic);
		if (dropped > 0)
			nm_warn("xattr events dropped in atomic context: %d\n",
				dropped);
	}

	nexus_unregister_team_exit(node_monitor_team_exit);

	nexus_index_exit();
	nexus_attr_exit();
	nexus_query_exit();
	nexus_volume_exit();

	unregister_xattr_kprobes();
	misc_deregister(&nexus_nm_miscdev);

	// Stop new enqueues FIRST (the NULL check in send_queued_notifications
	// guards on this pointer) so no callback races a freed workqueue.
	wq = nm_dispatch_wq;
	nm_dispatch_wq = NULL;
	if (wq) {
		flush_workqueue(wq);
		destroy_workqueue(wq);
	}

	spin_lock_irqsave(&nm_dispatch_lock, flags);
	list_for_each_entry_safe(notif, tnotif, &nm_dispatch_queue, list) {
		nm_walk_vref_ids_in_kmsg(notif->buffer, notif->size,
			nm_vref_drop_op);
		list_del(&notif->list);
		kfree(notif);
	}
	spin_unlock_irqrestore(&nm_dispatch_lock, flags);

	// destroy_group isn't exported on 6.12. After misc_deregister no new
	// ioctls can create marks; put_group runs the final destroy when
	// outstanding mark refs drop.
	fsnotify_put_group(nexus_fsn_group);

	spin_lock_irqsave(&move_lock, flags);
	list_for_each_entry_safe(pm, tmp, &pending_moves, list) {
		/* old_dir_vref_id is mark->vref_id — do not drop */
		list_del(&pm->list);
		kfree(pm);
	}
	spin_unlock_irqrestore(&move_lock, flags);

	/* Drain pending child-vref creations */
	{
		struct pending_child_vref *pcv, *ptmp;
		spin_lock_irqsave(&nm_pending_vrefs_lock, flags);
		list_for_each_entry_safe(pcv, ptmp, &nm_pending_vrefs, list) {
			fsnotify_put_mark(&pcv->mark->fs_mark);
			iput(pcv->inode);
			mntput(pcv->mnt);
			list_del(&pcv->list);
			kfree(pcv);
		}
		spin_unlock_irqrestore(&nm_pending_vrefs_lock, flags);
	}

	nm_info("unloaded\n");
}

module_init(nexus_node_monitor_init);
module_exit(nexus_node_monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dario Casalinuovo");
MODULE_DESCRIPTION("Nexus node monitor");
MODULE_VERSION("0.9");
