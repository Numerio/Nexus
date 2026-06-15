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

typedef int32_t status_t;
typedef int32_t port_id;
typedef int32_t area_id;
typedef int32_t sem_id;
typedef int32_t vref_id;
typedef uint64_t vref_key;
typedef pid_t team_id;
typedef pid_t thread_id;
typedef int64_t bigtime_t;

#endif

#define NEXUS_MAGIC	'n'

#define NEXUS_THREAD_SPAWN			_IO (NEXUS_MAGIC, 1)
#define NEXUS_THREAD_SET_NAME      _IOW (NEXUS_MAGIC, 3,  struct nexus_thread_set_name_req)
#define NEXUS_THREAD_READ          _IOWR(NEXUS_MAGIC, 20, struct nexus_thread_rw)
#define NEXUS_THREAD_WRITE         _IOWR(NEXUS_MAGIC, 21, struct nexus_thread_rw)
#define NEXUS_THREAD_HAS_DATA      _IOWR(NEXUS_MAGIC, 22, struct nexus_thread_rw)
#define NEXUS_THREAD_WAITFOR       _IOWR(NEXUS_MAGIC, 23, struct nexus_thread_waitfor_req)
#define NEXUS_THREAD_WAIT_NEWBORN	_IO (NEXUS_MAGIC, 4)
#define NEXUS_THREAD_CLONE_EXECUTED	_IO (NEXUS_MAGIC, 5)
#define NEXUS_THREAD_RESUME			_IO (NEXUS_MAGIC, 6)
#define NEXUS_THREAD_SET_RETURN_CODE _IO (NEXUS_MAGIC, 7)

#define NEXUS_PORT_CREATE        _IOWR(NEXUS_MAGIC, 10, struct nexus_port_create)
#define NEXUS_PORT_CLOSE         _IOWR(NEXUS_MAGIC, 11, struct nexus_port_id)
#define NEXUS_PORT_DELETE        _IOWR(NEXUS_MAGIC, 30, struct nexus_port_id)
#define NEXUS_PORT_READ          _IOWR(NEXUS_MAGIC, 31, struct nexus_port_read)
#define NEXUS_PORT_WRITE         _IOWR(NEXUS_MAGIC, 32, struct nexus_port_write)
#define NEXUS_PORT_INFO          _IOWR(NEXUS_MAGIC, 33, struct nexus_port_get_info)
#define NEXUS_PORT_MESSAGE_INFO  _IOWR(NEXUS_MAGIC, 34, struct nexus_port_get_message_info)
#define NEXUS_SET_PORT_OWNER     _IOWR(NEXUS_MAGIC, 35, struct nexus_port_set_owner)
#define NEXUS_PORT_WRITE_CAPS    _IOWR(NEXUS_MAGIC, 36, struct nexus_port_write_caps)
#define NEXUS_PORT_READ_CAPS     _IOWR(NEXUS_MAGIC, 37, struct nexus_port_read_caps)
#define NEXUS_PORT_FIND          _IOWR(NEXUS_MAGIC, 12, struct nexus_port_find_req)
#define NEXUS_GET_NEXT_PORT_FOR_TEAM	_IOWR(NEXUS_MAGIC, 13, struct nexus_get_next_port)

#define NEXUS_SEM_CREATE   _IOWR(NEXUS_MAGIC, 40, struct nexus_sem_create)
#define NEXUS_SEM_ACQUIRE  _IOWR(NEXUS_MAGIC, 41, struct nexus_sem_op)
#define NEXUS_SEM_RELEASE  _IOWR(NEXUS_MAGIC, 42, struct nexus_sem_op)
#define NEXUS_SEM_DELETE   _IOWR(NEXUS_MAGIC, 43, struct nexus_sem_delete_req)
#define NEXUS_SEM_COUNT    _IOWR(NEXUS_MAGIC, 44, struct nexus_sem_count_req)
#define NEXUS_SEM_INFO     _IOWR(NEXUS_MAGIC, 45, struct nexus_sem_info_req)
#define NEXUS_SEM_NEXT_INFO _IOWR(NEXUS_MAGIC, 46, struct nexus_sem_next_info)

#define NEXUS_VREF_MAGIC	'V'

struct nexus_vref_create {
	int			fd;
	/* out */
	vref_id		id;
	vref_key	key;
};

struct nexus_vref_op {
	vref_id		id;
	vref_key	key;
};


struct nexus_vref_open {
	vref_id		id;
	vref_key	key;
	uint32_t	requested_mode;
	/* out */
	int			fd_out;
};

#define NEXUS_VREF_CREATE	_IOWR(NEXUS_VREF_MAGIC, 6, struct nexus_vref_create)
#define NEXUS_VREF_ACQUIRE	_IOWR(NEXUS_VREF_MAGIC, 7, struct nexus_vref_op)
#define NEXUS_VREF_RELEASE	_IOWR(NEXUS_VREF_MAGIC, 8, struct nexus_vref_op)
#define NEXUS_VREF_OPEN		_IOWR(NEXUS_VREF_MAGIC, 9, struct nexus_vref_open)

#ifdef __KERNEL__
typedef void (*nexus_team_notify_fn)(pid_t team);
int  nexus_register_team_exit(nexus_team_notify_fn fn);
void nexus_unregister_team_exit(nexus_team_notify_fn fn);
#endif

#define NEXUS_VOLUME_MAGIC 'F'

#define NEXUS_QUERY_VOLUME_FLAGS _IOWR(NEXUS_VOLUME_MAGIC, 3, struct nexus_query_volume_flags)

#define NEXUS_ATTR_DIR_OPEN  _IOWR('F', 10, struct nexus_attr_dir_open)
#define NEXUS_ATTR_READ      _IOWR('F', 11, struct nexus_attr_io)
#define NEXUS_ATTR_WRITE     _IOWR('F', 12, struct nexus_attr_io)
#define NEXUS_ATTR_STAT      _IOWR('F', 13, struct nexus_attr_stat)
#define NEXUS_ATTR_REMOVE    _IOW ('F', 14, struct nexus_attr_remove)
#define NEXUS_ATTR_RENAME    _IOW ('F', 15, struct nexus_attr_rename)

#define NEXUS_AREA_MAGIC 'A'

#define NEXUS_AREA_CREATE			_IOWR(NEXUS_AREA_MAGIC, 1, struct nexus_area_create)
#define NEXUS_AREA_CLONE			_IOWR(NEXUS_AREA_MAGIC, 2, struct nexus_area_clone)
#define NEXUS_AREA_DELETE			_IOWR(NEXUS_AREA_MAGIC, 3, struct nexus_area_delete)
#define NEXUS_AREA_FIND				_IOWR(NEXUS_AREA_MAGIC, 4, struct nexus_area_find)
#define NEXUS_AREA_GET_INFO			_IOWR(NEXUS_AREA_MAGIC, 5, struct nexus_area_get_info)
#define NEXUS_AREA_SET_PROTECTION	_IOWR(NEXUS_AREA_MAGIC, 7, struct nexus_area_set_protection)
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
	int32_t		ret;
};

struct nexus_thread_waitfor_req {
	int32_t		receiver;
	uint32_t	flags;
	int64_t		timeout;
	int32_t		return_code;
	int32_t		ret;
};

/* Port */

struct nexus_port_create {
	const char*		name;
	size_t			size;
	int32_t			capacity;
	/* out */
	int32_t			id;
	int32_t			ret;
};

struct nexus_port_id {
	int32_t			id;
	/* out */
	int32_t			ret;
};

struct nexus_port_read {
	int32_t			id;
	int32_t*		code;
	void*			buffer;
	size_t			size;
	uint32_t		flags;
	int64_t			timeout;
	/* out */
	int32_t			ret;
};

struct nexus_port_write {
	int32_t			id;
	int32_t*		code;
	const void*		buffer;
	size_t			size;
	uint32_t		flags;
	int64_t			timeout;
	/* out */
	int32_t			ret;
};

/* Phase 2a: cap-bearing port I/O. kind = 1 (VREF) is the only kind
 * defined. buffer_offset is purely receiver-side bookkeeping; the
 * kernel does not interpret the message bytes. */
#define NEXUS_PORT_CAP_VREF 1

struct nexus_port_cap_in {
	uint32_t		kind;
	int32_t			vref_id;
	uint32_t		buffer_offset;
	uint32_t		_pad;
};

struct nexus_port_cap_out {
	uint32_t		kind;
	int32_t			vref_id;
	uint32_t		buffer_offset;
	uint32_t		_pad;
	uint64_t		key;	/* freshly minted slot in receiver team */
};

struct nexus_port_write_caps {
	int32_t			id;
	int32_t*		code;
	const void*		buffer;
	size_t			size;
	const struct nexus_port_cap_in*	caps;
	size_t			caps_count;
	uint32_t		flags;
	int64_t			timeout;
	/* out */
	int32_t			ret;
};

struct nexus_port_read_caps {
	int32_t			id;
	int32_t*		code;
	void*			buffer;
	size_t			size;		/* in: capacity; out: actual */
	struct nexus_port_cap_out*	caps;
	size_t			caps_count;	/* in: capacity; out: actual */
	uint32_t		flags;
	int64_t			timeout;
	/* out */
	int32_t			ret;
};

struct nexus_port_get_info {
	int32_t			id;
	/* out */
	struct nexus_port_info* info;
	int32_t			ret;
};

struct nexus_port_get_message_info {
	int32_t			id;
	size_t			size;
	uint32_t		flags;
	int64_t			timeout;
	/* out */
	struct nexus_port_message_info* info;
	int32_t			ret;
};

struct nexus_port_set_owner {
	int32_t			id;
	int32_t			team;
	/* out */
	int32_t			ret;
};

struct nexus_port_find_req {
	const char*		name;
	size_t			size;
	/* out */
	int32_t			id;
	int32_t			ret;
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
	int32_t					cookie;
	/* out */
	struct nexus_port_info	info;
	int32_t					ret;
};


/* Sem */


struct nexus_sem_create {
	const char*	name;
	int32_t		count;
	/* out */
	sem_id		id;
	int32_t		ret;
};

struct nexus_sem_op {
	sem_id		id;
	int32_t		count;
	uint32_t	flags;
	bigtime_t	timeout;
	/* out */
	int32_t		ret;
};

struct nexus_sem_delete_req {
	sem_id		id;
	/* out */
	int32_t		ret;
};

struct nexus_sem_count_req {
	sem_id		id;
	/* out */
	int32_t		count;
	int32_t		ret;
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
	int32_t		ret;
};

struct nexus_sem_next_info {
	team_id   	team;
	int32_t   	cookie;
	/* out */
	struct nexus_sem_info info;
	int32_t		ret;
};


/* Areas */


struct nexus_area_create {
	int         fd;
	char        name[B_OS_NAME_LENGTH];
	uint64_t    size;
	uint32_t    lock;
	uint32_t    protection;
	/* out */
	area_id     area;
	int32_t     ret;
};

struct nexus_area_clone {
	area_id     source;
	char        name[B_OS_NAME_LENGTH];
	uint32_t    protection;
	/* out */
	area_id     area;
	int         fd;
	uint64_t    size;
	int32_t     ret;
};

struct nexus_area_delete {
	area_id     area;
	/* out */
	int32_t     ret;
};

struct nexus_area_find {
	char        name[B_OS_NAME_LENGTH];
	/* out */
	area_id     area;
	uint64_t    size;
	int32_t     ret;
};

struct nexus_area_get_info {
	area_id     area;
	/* out */
	char        name[B_OS_NAME_LENGTH];
	uint64_t    size;
	uint32_t    lock;
	uint32_t    protection;
	int32_t     team;
	int32_t     ret;
};

struct nexus_area_set_protection {
	area_id     area;
	uint32_t    protection;
	/* out */
	int32_t     ret;
};

struct nexus_area_transfer {
	area_id     area;
	int32_t     target;
	/* out */
	area_id     new_area;
	int         fd;
	int32_t     ret;
};

struct nexus_area_get_next {
	int32_t     team;
	int32_t     cookie;
	/* out */
	area_id     area;
	char        name[B_OS_NAME_LENGTH];
	uint64_t    size;
	uint32_t    lock;
	uint32_t    protection;
	int32_t     next_cookie;
	int32_t     ret;
};


/* Volume flags query */


struct nexus_query_volume_flags {
	int32_t    target_fd;
	uint32_t   flags;
};


/* Attribute ioctl structs */


struct nexus_attr_dir_open {
	int32_t   target_fd;
	uint32_t  flags;
};

struct nexus_attr_io {
	int32_t   target_fd;
	char      name[256];
	uint32_t  type;
	int64_t   pos;
	uint64_t  buf_addr;
	uint64_t  buf_len;
};

struct nexus_attr_stat {
	int32_t  target_fd;
	char     name[256];
	uint32_t type_out;
	uint64_t size_out;
};

struct nexus_attr_remove {
	int32_t target_fd;
	char  name[256];
};

struct nexus_attr_rename {
	int32_t from_fd;
	char  from_name[256];
	int32_t to_fd;
	char  to_name[256];
};

#define NEXUS_ATTR_NAME_MAX 245

#define NEXUS_QUERY_OPEN  _IOWR('F', 30, struct nexus_query_open)

struct nexus_query_open {
	int32_t  target_fd;
	uint32_t  predicate_len;
	uint64_t  predicate_addr;
	uint32_t  flags;
	int32_t  port;
	int32_t  token;
};

#define NEXUS_INDEX_DIR_OPEN  _IOWR('F', 20, struct nexus_index_dir_open)
#define NEXUS_INDEX_CREATE    _IOW ('F', 21, struct nexus_index_create)
#define NEXUS_INDEX_REMOVE    _IOW ('F', 22, struct nexus_index_remove)
#define NEXUS_INDEX_STAT      _IOWR('F', 23, struct nexus_index_stat)

struct nexus_index_dir_open {
	int32_t target_fd;
};

struct nexus_index_create {
	int32_t target_fd;
	char  name[256];
	uint32_t type;
	uint32_t flags;
};

struct nexus_index_remove {
	int32_t target_fd;
	char  name[256];
};

struct nexus_index_stat {
	int32_t target_fd;
	char  name[256];
	uint32_t type;
	uint32_t flags;
	uint64_t size;
	int64_t  modification_time;
	int64_t  creation_time;
	uint32_t uid;
	uint32_t gid;
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
