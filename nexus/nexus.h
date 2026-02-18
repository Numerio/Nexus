/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2022-2026 Dario Casalinuovo
 */

#ifndef __VOS_NEXUS
#define __VOS_NEXUS

#include <linux/types.h>

#define PORT_MAX_QUEUE 4096
#define PORT_MAX_MESSAGE_SIZE (1024 *  256)

#ifdef __KERNEL__

#define B_OS_NAME_LENGTH 32

typedef s32 status_t;
typedef s32 port_id;
typedef s32 area_id;
typedef s32 sem_id;
typedef s32 vref_id;
typedef pid_t team_id;
typedef pid_t thread_id;
typedef s64 bigtime_t;

#endif

#define NEXUS_MAGIC	'n'

#define NEXUS_THREAD_SPAWN			_IO(NEXUS_MAGIC, 1)
#define NEXUS_THREAD_EXIT			_IO(NEXUS_MAGIC, 2)
#define NEXUS_THREAD_SET_PRIORITY	_IO(NEXUS_MAGIC, 2)
#define NEXUS_THREAD_OP				_IO(NEXUS_MAGIC, 3)
#define NEXUS_THREAD_WAIT_NEWBORN	_IO(NEXUS_MAGIC, 4)
#define NEXUS_THREAD_CLONE_EXECUTED	_IO(NEXUS_MAGIC, 5)
#define NEXUS_THREAD_RESUME			_IO(NEXUS_MAGIC, 6)

#define NEXUS_PORT_CREATE			_IO(NEXUS_MAGIC, 10)
#define NEXUS_PORT_OP				_IO(NEXUS_MAGIC, 11)
#define NEXUS_PORT_FIND				_IO(NEXUS_MAGIC, 12)

#define NEXUS_SEM_CREATE			_IO(NEXUS_MAGIC, 1)
#define NEXUS_SEM_ACQUIRE			_IO(NEXUS_MAGIC, 2)
#define NEXUS_SEM_RELEASE			_IO(NEXUS_MAGIC, 3)
#define NEXUS_SEM_DELETE			_IO(NEXUS_MAGIC, 4)
#define NEXUS_SEM_COUNT				_IO(NEXUS_MAGIC, 5)
#define NEXUS_SEM_INFO				_IO(NEXUS_MAGIC, 6)
#define NEXUS_SEM_NEXT_INFO			_IO(NEXUS_MAGIC, 7)

//#define NEXUS_VREF_MAGIC	'V'

#define NEXUS_VREF_CREATE			_IO(NEXUS_MAGIC, 1)
#define NEXUS_VREF_ACQUIRE			_IO(NEXUS_MAGIC, 2)
#define NEXUS_VREF_ACQUIRE_FD		_IO(NEXUS_MAGIC, 3)
#define NEXUS_VREF_OPEN				_IO(NEXUS_MAGIC, 4)
#define NEXUS_VREF_RELEASE			_IO(NEXUS_MAGIC, 5)

#define NEXUS_AREA_MAGIC 'A'

#define NEXUS_AREA_CREATE			_IOWR(NEXUS_AREA_MAGIC, 1, struct nexus_area_create)
#define NEXUS_AREA_CLONE			_IOWR(NEXUS_AREA_MAGIC, 2, struct nexus_area_clone)
#define NEXUS_AREA_DELETE			_IOW (NEXUS_AREA_MAGIC, 3, struct nexus_area_delete)
#define NEXUS_AREA_FIND				_IOWR(NEXUS_AREA_MAGIC, 4, struct nexus_area_find)
#define NEXUS_AREA_GET_INFO			_IOWR(NEXUS_AREA_MAGIC, 5, struct nexus_area_get_info)
#define NEXUS_AREA_RESIZE			_IOW (NEXUS_AREA_MAGIC, 6, struct nexus_area_resize)
#define NEXUS_AREA_SET_PROTECTION	_IOW (NEXUS_AREA_MAGIC, 7, struct nexus_area_set_protection)
#define NEXUS_AREA_TRANSFER			_IOWR(NEXUS_AREA_MAGIC, 8, struct nexus_area_transfer)
#define NEXUS_AREA_GET_NEXT			_IOWR(NEXUS_AREA_MAGIC, 9, struct nexus_area_get_next)


/* Thread */


enum thread_ops {
	NEXUS_THREAD_SET_NAME = 0,
	NEXUS_THREAD_READ,
	NEXUS_THREAD_WRITE,
	NEXUS_THREAD_HAS_DATA,
	NEXUS_THREAD_WAITFOR
};

struct nexus_thread_spawn {
	const char*				name;
	thread_id				father;
};

struct nexus_thread_exchange {
	uint32_t				op;

	int32_t					sender;
	int32_t					receiver;

	void*					buffer;
	ssize_t					size;

	uint32_t				flags;
	uint64_t				timeout;

	int32_t					status;

	int32_t					return_code;
};


/* Port */


enum port_ops {
	NEXUS_PORT_DELETE = 0,
	NEXUS_PORT_CLOSE,
	NEXUS_PORT_READ,
	NEXUS_PORT_WRITE,
	NEXUS_PORT_INFO,
	NEXUS_PORT_MESSAGE_INFO,
	NEXUS_SET_PORT_OWNER,
};

struct nexus_port_exchange {
	uint32_t				op;
	int32_t					id;

	//
	int32_t*				code;
	void*					buffer;
	size_t					size;
	uint32_t				flags;
	int64_t					timeout;

	int32_t					cookie;
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
	char		name[B_OS_NAME_LENGTH];
	int32_t		capacity;
	int32_t		queue_count;
	int32_t		total_count;
};


/* Sem */


struct nexus_sem_exchange {
	sem_id  	id;

	int32_t   	count;
	uint32_t  	flags;
	bigtime_t 	timeout;
	const char 	*name;

	team_id   	team;
};

struct nexus_sem_info {
	sem_id    	sem;
	//
	team_id   	team;
	char      	name[B_OS_NAME_LENGTH];
	int32_t   	count;
	thread_id 	latest_holder;
};

struct nexus_sem_next_info {
	team_id   	team;
	int32_t   	cookie;
	//
	struct nexus_sem_info info;
};


/* Areas */


struct nexus_area_create {
	int         fd;
	char        name[B_OS_NAME_LENGTH];
	uint64_t    size;
	uint32_t    lock;
	uint32_t    protection;
	//
	area_id     area;
};

struct nexus_area_clone {
	area_id     source;
	char        name[B_OS_NAME_LENGTH];
	uint32_t    protection;
	//
	area_id     area;
	int         fd;
	uint64_t    size;
};

struct nexus_area_delete {
	area_id     area;
};

struct nexus_area_find {
	char        name[B_OS_NAME_LENGTH];
	//
	area_id     area;
	uint64_t    size;
};

struct nexus_area_get_info {
	area_id     area;
	//
	char        name[B_OS_NAME_LENGTH];
	uint64_t    size;
	uint32_t    lock;
	uint32_t    protection;
	int32_t     team;
};

struct nexus_area_resize {
	area_id     area;
	uint64_t    new_size;
};

struct nexus_area_set_protection {
	area_id     area;
	uint32_t    protection;
};

struct nexus_area_transfer {
	area_id     area;
	int32_t     target;
	//
	area_id     new_area;
	int         fd;
};

struct nexus_area_get_next {
	int32_t     team;
	int32_t     cookie;
	//
	area_id     area;
	char        name[B_OS_NAME_LENGTH];
	uint64_t    size;
	uint32_t    lock;
	uint32_t    protection;
	int32_t     next_cookie;
};


/* User facing API */


#ifndef __KERNEL__

inline int32_t nexus_io(int nexus, unsigned long request, void* msg)
{
	int ret = ioctl(nexus, request, msg);
	if (ret == -1)
		return -errno;

	return ret;
};


#endif


#endif // __VOS_NEXUS
