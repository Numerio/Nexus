// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026 Dario Casalinuovo
 */

#ifndef __VOS_NEXUS_PRIVATE
#define __VOS_NEXUS_PRIVATE


#define B_INFINITE_TIMEOUT	(9223372036854775807LL)
// NOTE: not sure if we want that stuff to be configurable
// just in case better to leave a note here.
#define MAX_SEMS 65536
#define MAX_PORTS 4096

enum {
	B_TIMEOUT						= 0x8,
	B_RELATIVE_TIMEOUT				= 0x8,
	B_ABSOLUTE_TIMEOUT				= 0x10,
};

enum {
	B_RELEASE_IF_WAITING_ONLY		= 0x06,
	B_RELEASE_ALL					= 0x08
};

#define B_CAN_INTERRUPT        0x01
#define B_CHECK_PERMISSION     0x04
#define B_KILL_CAN_INTERRUPT   0x20
#define B_DO_NOT_RESCHEDULE    0x02

#define B_NAME_NOT_FOUND -2147454966


struct nexus_thread;

struct nexus_team {
	struct hlist_node		node;
	team_id					id;

	//uint32_t				status;

	struct rb_root			threads;
	struct rb_root			ports;

	// that will be in the main_thread
	//struct task_struct	*tsk;
	//struct files_struct	*files;

	struct nexus_thread*	main_thread;
};

struct nexus_thread {
	struct rb_node			node;
	struct kref				ref_count;

	thread_id				id;

	char					name[B_OS_NAME_LENGTH];

	//uint32_t				status;
	bool					thread_resumed;
	bool					thread_wait_newborn;
	bool					has_thread_exited;

	thread_id				child_thread;

	wait_queue_head_t		thread_suspended;
	wait_queue_head_t		thread_has_newborn;
	wait_queue_head_t		thread_exit;

	struct semaphore		sem_read;
	struct semaphore		sem_write;

	wait_queue_head_t		buffer_read;
	int						buffer_ready;

	void*					buffer;
	ssize_t					buffer_size;

	thread_id				sender;

	int32_t					return_code;
	int32_t					unblock_code;
	int32_t					exit_status;

	//struct task_struct	*tsk;

	struct nexus_team*		team;
};

struct nexus_buffer {
	struct list_head		node;

	int32_t					code;
	void*					buffer;
	size_t					size;

	uid_t					sender;
	gid_t					sender_group;
	team_id					sender_team;
};

struct nexus_port {
	struct rb_node			node;
	struct kref				ref_count;

	port_id					id;
	char					name[B_OS_NAME_LENGTH];
	uint32_t				capacity;

	//uint32_t				status;
	bool					is_open;

	struct list_head		queue;
	wait_queue_head_t		buffer_read;
	wait_queue_head_t		buffer_write;
	int32_t					write_count;
	int32_t					read_count;
	int32_t					total_count;

	rwlock_t				rw_lock;

	struct nexus_team*		team;
};

struct nexus_sem_waiter {
	struct list_head    	list;

	struct task_struct  	*task;
	int32_t             	count;
	status_t            	status;
	bool                	woken;
};

struct nexus_sem {
	sem_id              	id;

	char                	name[B_OS_NAME_LENGTH];
	int32_t             	count;
	thread_id           	latest_holder;
	bool                	deleted;

	spinlock_t          	lock;
	struct list_head    	waiters;
	atomic_t            	ref_count;

	team_id             	owner;
	struct hlist_node   	team_node;
};

// nexus_team_sem_list
struct team_sem_list {
	team_id             	team;

	struct hlist_head   	sems;
	spinlock_t          	lock;

	struct hlist_node		hash_node;
};

struct nexus_area {
	area_id					id;

	char					name[B_OS_NAME_LENGTH];
	struct file				*file;
	size_t					size;
	s32						lock;
	s32		              	protection;
	pid_t					team;

	struct kref				ref_count;
	struct hlist_node		node;
};

typedef struct area_info {
	int32_t					area;
	char					name[B_OS_NAME_LENGTH];
	size_t					size;
	int32_t					lock;
	int32_t					protection;
	pid_t					team;
	size_t					ram_size;
	int32_t					copy_count;
	int32_t					in_count;
	int32_t					out_count;
	void*					address;
} area_info;

struct nexus_vref {
	struct hlist_node		node;
	struct kref				ref_count;

	int32_t					id;
	struct file*			file;

	// struct task
	pid_t					team;
};


struct nexus_team*		nexus_team_init(void);
void					nexus_team_destroy(struct nexus_team *team);

struct nexus_thread*	nexus_thread_init(struct nexus_team *team, pid_t thread, const char *name);
void 					nexus_thread_destroy(struct kref* ref);
long					nexus_thread_op(struct nexus_thread *thread, unsigned long cmd);

long					nexus_port_init(struct nexus_team* team, unsigned long arg);
void					nexus_port_destroy(struct kref* ref);
long					nexus_port_op(struct nexus_team *team, unsigned long cmd);

void					nexus_sem_delete(struct kref* ref);
/*
struct nexus_area*		nexus_area_init(struct nexus_team *team, int user_fd);
void					nexus_area_destroy(struct nexus_area *area);
int						nexus_area_clone(struct nexus_area *area, uint32_t source_area);
void					nexus_area_transfer(struct nexus_area *area, struct nexus_team *source_team,
							struct nexus_team *destination_team);
*/

#endif
