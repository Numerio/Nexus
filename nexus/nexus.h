// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2025 Dario Casalinuovo
 */

#ifndef __VOS_NEXUS
#define __VOS_NEXUS

#include <linux/types.h>

// NOTE: not sure if we want that stuff to be configurable
// just in case better to leave a note here.
#define MAX_PORTS 4096
#define PORT_MAX_QUEUE 4096
#define PORT_MAX_MESSAGE_SIZE (1024 *  256)
#define NAME_LENGTH 32

#define IOCTL_BASE	'n'

#define NEXUS_THREAD_SPAWN			_IO(IOCTL_BASE, 1)
#define NEXUS_THREAD_EXIT			_IO(IOCTL_BASE, 2)
#define NEXUS_THREAD_SET_PRIORITY	_IO(IOCTL_BASE, 2)
#define NEXUS_THREAD_OP				_IO(IOCTL_BASE, 3)

#define NEXUS_PORT_CREATE			_IO(IOCTL_BASE, 10)
#define NEXUS_PORT_OP				_IO(IOCTL_BASE, 11)
#define NEXUS_PORT_FIND				_IO(IOCTL_BASE, 12)

#define NEXUS_AREA_CREATE			_IO(IOCTL_BASE, 1)
#define NEXUS_AREA_CLONE			_IO(IOCTL_BASE, 2)
#define NEXUS_AREA_DELETE			_IO(IOCTL_BASE, 4)
#define NEXUS_AREA_FD_GET			_IO(IOCTL_BASE, 5)
#define NEXUS_AREA_TRANSFER			_IO(IOCTL_BASE, 6)

#define NEXUS_SEM_CREATE			_IO(IOCTL_BASE, 1)
#define NEXUS_SEM_ACQUIRE			_IO(IOCTL_BASE, 2)
#define NEXUS_SEM_RELEASE			_IO(IOCTL_BASE, 3)
#define NEXUS_SEM_DELETE			_IO(IOCTL_BASE, 4)
#define NEXUS_SEM_COUNT				_IO(IOCTL_BASE, 5)
//#define NEXUS_SEM_SET_OWNER		_IO(IOCTL_BASE, 6)

#define NEXUS_FDREF_CREATE			_IO(IOCTL_BASE, 1)
#define NEXUS_FDREF_ACQUIRE			_IO(IOCTL_BASE, 2)
#define NEXUS_FDREF_RELEASE			_IO(IOCTL_BASE, 3)


struct nexus_thread_exchange {
	uint32_t				op;

	int32_t					sender;
	int32_t					receiver;

	const void*				buffer;
	ssize_t					size;

	uint32_t				flags;
	uint64_t				timeout;

	int32_t					status;

	int32_t					return_code;
};

struct nexus_port_exchange {
	uint32_t				op;
	int32_t					id;

	//
	int32_t*				code;
	const void*				buffer;
	size_t					size;
	uint32_t				flags;
	int64_t					timeout;

	int32_t					cookie;
	int32_t					return_code;
};

struct nexus_port_message_info {
	size_t		size;
	uid_t		sender;
	gid_t		sender_group;
	pid_t		sender_team;
};

struct nexus_port_info {
	int32_t		port;

	int32_t		team;
	char		name[NAME_LENGTH];
	int32_t		capacity;
	int32_t		queue_count;
	int32_t		total_count;
};

struct nexus_sem_exchange {
	int32_t		id;

	int32_t		count;
	char*		name;
	int32_t		flags;
	int64_t		timeout;
};

struct nexus_area_exchange {
	int32_t		id;

	char		name[NAME_LENGTH];
	int64_t		fd;
	void**		start_addr;
	uint32_t	addr_spec;
	size_t		size;
	uint32_t	lock;
	uint32_t	protection;
};

enum thread_ops {
	NEXUS_THREAD_SET_NAME = 0,
	NEXUS_THREAD_READ,
	NEXUS_THREAD_WRITE,
	NEXUS_THREAD_HAS_DATA,
	NEXUS_THREAD_BLOCK,
	NEXUS_THREAD_UNBLOCK,
	NEXUS_THREAD_WAITFOR
};

enum port_ops {
	NEXUS_PORT_DELETE = 0,
	NEXUS_PORT_CLOSE,
	NEXUS_PORT_READ,
	NEXUS_PORT_WRITE,
	NEXUS_PORT_INFO,
	NEXUS_PORT_MESSAGE_INFO,
	NEXUS_SET_PORT_OWNER, // TODO deprecate
};

#endif
