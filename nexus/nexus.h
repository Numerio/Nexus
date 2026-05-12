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

#define NEXUS_THREAD_SPAWN			_IO (NEXUS_MAGIC, 1)
#define NEXUS_THREAD_SET_NAME      _IOW (NEXUS_MAGIC, 3,  struct nexus_thread_set_name_req)
#define NEXUS_THREAD_READ          _IOWR(NEXUS_MAGIC, 20, struct nexus_thread_rw)
#define NEXUS_THREAD_WRITE         _IOW (NEXUS_MAGIC, 21, struct nexus_thread_rw)
#define NEXUS_THREAD_HAS_DATA      _IOWR(NEXUS_MAGIC, 22, struct nexus_thread_rw)
#define NEXUS_THREAD_WAITFOR       _IOWR(NEXUS_MAGIC, 23, struct nexus_thread_waitfor_req)
#define NEXUS_THREAD_WAIT_NEWBORN	_IO (NEXUS_MAGIC, 4)
#define NEXUS_THREAD_CLONE_EXECUTED	_IO (NEXUS_MAGIC, 5)
#define NEXUS_THREAD_RESUME			_IO (NEXUS_MAGIC, 6)
#define NEXUS_THREAD_SET_RETURN_CODE _IO (NEXUS_MAGIC, 7)

#define NEXUS_PORT_CREATE        _IOWR(NEXUS_MAGIC, 10, struct nexus_port_create)
#define NEXUS_PORT_CLOSE         _IOW (NEXUS_MAGIC, 11, struct nexus_port_id)
#define NEXUS_PORT_DELETE        _IOW (NEXUS_MAGIC, 30, struct nexus_port_id)
#define NEXUS_PORT_READ          _IOWR(NEXUS_MAGIC, 31, struct nexus_port_read)
#define NEXUS_PORT_WRITE         _IOW (NEXUS_MAGIC, 32, struct nexus_port_write)
#define NEXUS_PORT_INFO          _IOWR(NEXUS_MAGIC, 33, struct nexus_port_get_info)
#define NEXUS_PORT_MESSAGE_INFO  _IOWR(NEXUS_MAGIC, 34, struct nexus_port_get_message_info)
#define NEXUS_SET_PORT_OWNER     _IOW (NEXUS_MAGIC, 35, struct nexus_port_set_owner)
#define NEXUS_PORT_FIND          _IOWR(NEXUS_MAGIC, 12, struct nexus_port_find_req)
#define NEXUS_GET_NEXT_PORT_FOR_TEAM	_IOWR(NEXUS_MAGIC, 13, struct nexus_get_next_port)

#define NEXUS_SEM_CREATE   _IOWR(NEXUS_MAGIC, 40, struct nexus_sem_create)
#define NEXUS_SEM_ACQUIRE  _IOW (NEXUS_MAGIC, 41, struct nexus_sem_op)
#define NEXUS_SEM_RELEASE  _IOW (NEXUS_MAGIC, 42, struct nexus_sem_op)
#define NEXUS_SEM_DELETE   _IOW (NEXUS_MAGIC, 43, struct nexus_sem_delete_req)
#define NEXUS_SEM_COUNT    _IOWR(NEXUS_MAGIC, 44, struct nexus_sem_count_req)
#define NEXUS_SEM_INFO     _IOWR(NEXUS_MAGIC, 45, struct nexus_sem_info_req)
#define NEXUS_SEM_NEXT_INFO _IOWR(NEXUS_MAGIC, 46, struct nexus_sem_next_info)

#define NEXUS_VREF_MAGIC	'V'

#define NEXUS_VREF_CREATE			_IO(NEXUS_VREF_MAGIC, 1)
#define NEXUS_VREF_ACQUIRE			_IO(NEXUS_VREF_MAGIC, 2)
#define NEXUS_VREF_ACQUIRE_FD		_IO(NEXUS_VREF_MAGIC, 3)
#define NEXUS_VREF_OPEN				_IO(NEXUS_VREF_MAGIC, 4)
#define NEXUS_VREF_RELEASE			_IO(NEXUS_VREF_MAGIC, 5)

#ifdef __KERNEL__
/* Team-exit notification callbacks — callable from external modules */
typedef void (*nexus_team_notify_fn)(pid_t team);
int  nexus_register_team_exit(nexus_team_notify_fn fn);
void nexus_unregister_team_exit(nexus_team_notify_fn fn);
#endif

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




struct nexus_thread_spawn {
	const char*				name;
	thread_id				father;
};

struct nexus_thread_set_name_req {
	const char*	name;
	size_t		size;
};

struct nexus_thread_rw {
	int32_t		sender;
	int32_t		receiver;
	void*		buffer;
	ssize_t		size;
	uint32_t	flags;
	int64_t		timeout;
	int32_t		return_code;
};

struct nexus_thread_waitfor_req {
	int32_t		receiver;
	uint32_t	flags;
	int64_t		timeout;
	/* out */
	int32_t		return_code;
};


/* Port */




struct nexus_port_create {
	const char*		name;
	size_t			size;		/* length of name string */
	int32_t			capacity;
	/* out */
	int32_t			id;
};

struct nexus_port_id {
	int32_t			id;
};

struct nexus_port_read {
	int32_t			id;
	int32_t*		code;
	void*			buffer;
	size_t			size;		/* in: buf capacity, out: bytes read */
	uint32_t		flags;
	int64_t			timeout;
};

struct nexus_port_write {
	int32_t			id;
	int32_t*		code;
	const void*		buffer;
	size_t			size;
	uint32_t		flags;
	int64_t			timeout;
};

struct nexus_port_get_info {
	int32_t			id;
	/* out via nexus_port_info pointer */
	struct nexus_port_info* info;
};

struct nexus_port_get_message_info {
	int32_t			id;
	size_t			size;
	uint32_t		flags;
	int64_t			timeout;
	/* out via nexus_port_message_info pointer */
	struct nexus_port_message_info* info;
};

struct nexus_port_set_owner {
	int32_t			id;
	int32_t			team;
};

struct nexus_port_find_req {
	const char*		name;
	size_t			size;		/* length of name string */
	/* out */
	int32_t			id;
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

struct nexus_get_next_port {
	pid_t					team;
	int32_t					cookie;		/* in: last seen port id (0 = start) */
	/* out */
	struct nexus_port_info	info;
};


/* Sem */


struct nexus_sem_create {
	const char*	name;
	int32_t		count;
	/* out */
	sem_id		id;
};

struct nexus_sem_op {
	sem_id		id;
	int32_t		count;
	uint32_t	flags;
	bigtime_t	timeout;
};

struct nexus_sem_delete_req {
	sem_id		id;
};

struct nexus_sem_count_req {
	sem_id		id;
	/* out */
	int32_t		count;
};

struct nexus_sem_info {
	sem_id    	sem;
	//
	team_id   	team;
	char      	name[B_OS_NAME_LENGTH];
	int32_t   	count;
	thread_id 	latest_holder;
};

struct nexus_sem_info_req {
	sem_id		id;
	team_id		team;
	/* out */
	struct nexus_sem_info info;
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
