// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026 Dario Casalinuovo
 */

#ifndef _NEXUS_NODE_MONITOR_H
#define _NEXUS_NODE_MONITOR_H


#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/ioctl.h>

#define B_STOP_WATCHING         0x0000
#define B_WATCH_NAME            0x0001
#define B_WATCH_STAT            0x0002
#define B_WATCH_ATTR            0x0004
#define B_WATCH_DIRECTORY       0x0008
#define B_WATCH_ALL             0x000f
#define B_WATCH_MOUNT           0x0010
#define B_WATCH_INTERIM_STAT    0x0020
#define B_WATCH_CHILDREN        0x0040

#define B_ENTRY_CREATED         1
#define B_ENTRY_REMOVED         2
#define B_ENTRY_MOVED           3
#define B_STAT_CHANGED          4
#define B_ATTR_CHANGED          5
#define B_DEVICE_MOUNTED        6
#define B_DEVICE_UNMOUNTED      7

#define B_STAT_INTERIM_UPDATE 0x1000
#define B_ATTR_REMOVED		2

#define B_STAT_MODE             0x0001
#define B_STAT_UID              0x0002
#define B_STAT_GID              0x0004
#define B_STAT_SIZE             0x0008
#define B_STAT_ACCESS_TIME      0x0010
#define B_STAT_MODIFICATION_TIME 0x0020
#define B_STAT_CREATION_TIME    0x0040
#define B_STAT_CHANGE_TIME      0x0080

#define B_ATTR_CAUSE_CREATED    1
#define B_ATTR_CAUSE_REMOVED    2
#define B_ATTR_CAUSE_CHANGED    3

#define B_NODE_MONITOR          0x4e444d4e

#endif // __KERNEL__


#define NEXUS_NODE_MONITOR_MAGIC 'H'

#define NEXUS_START_WATCHING \
	_IOW(NEXUS_NODE_MONITOR_MAGIC, 1, struct nexus_watch_fd)
#define NEXUS_STOP_WATCHING \
	_IOW(NEXUS_NODE_MONITOR_MAGIC, 2, struct nexus_unwatch_fd)
#define NEXUS_STOP_NOTIFYING \
	_IOW(NEXUS_NODE_MONITOR_MAGIC, 3, struct nexus_stop_notifying)

#define NEXUS_NODE_MONITOR_DEVICE "nexus_node_monitor"

struct nexus_watch_fd {
	int32_t		fd;
	uint32_t	flags;
	//
	int32_t		port;
	uint32_t	token;
};

struct nexus_unwatch_fd {
	uint64_t	device;
	uint64_t	node;
	//
	int32_t		port;
	uint32_t	token;
};

struct nexus_stop_notifying {
	int32_t		port;
	uint32_t	token;
};

struct nexus_event {
	uint32_t	type;
	uint32_t	mask;

	uint64_t	device;
	uint64_t	inode;
	// TODO: rename parent_dir_inode
	uint64_t 	dir_inode;

	// Correlate move_from/move_to
	uint64_t	cookie;

	// B_STAT_CHANGED
	uint32_t	stat_fields;
	// B_ATTR_CHANGED
	uint32_t	attr_cause;

	char 		name[NAME_MAX];
	char 		attr_name[XATTR_NAME_MAX];

	uint64_t	old_dir_inode;
	char		old_name[NAME_MAX];
};

struct xattr_event {
	uint64_t	device;
	uint64_t	inode;

	uint32_t	cause;
	char		name[XATTR_NAME_MAX];
};

#endif // _NEXUS_NODE_MONITOR_H
