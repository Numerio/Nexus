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

#define NEXUS_THREAD_SPAWN		_IO(IOCTL_BASE, 1)
#define NEXUS_THREAD_EXIT		_IO(IOCTL_BASE, 2)
#define NEXUS_THREAD_OP			_IO(IOCTL_BASE, 3)

#define NEXUS_PORT_CREATE		_IO(IOCTL_BASE, 4)
#define NEXUS_PORT_OP			_IO(IOCTL_BASE, 5)
#define NEXUS_PORT_FIND			_IO(IOCTL_BASE, 6)

struct nexus_thread_exchange {
	uint32_t				op;

	int32_t					sender;
	int32_t					receiver;

	void*					buffer;
	ssize_t					size;

	int32_t					return_code;
};

struct nexus_port_exchange {
	uint32_t				op;
	int32_t					id;

	int32_t*				code;
	void*					buffer;
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

enum thread_ops {
	NEXUS_THREAD_SET_NAME = 0,
	NEXUS_THREAD_READ,
	NEXUS_THREAD_WRITE,
	NEXUS_THREAD_HAS_DATA
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

enum area_ops {
	NEXUS_AREA_CREATE = 0,
	NEXUS_AREA_CLONE,
	NEXUS_AREA_DELETE,
	NEXUS_AREA_TRANSFER
};

#endif
