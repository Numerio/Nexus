// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2025 Dario Casalinuovo
 */

#ifndef __VOS_NEXUS_PRIVATE
#define __VOS_NEXUS_PRIVATE

#define B_OS_NAME_LENGTH	32
#define B_INFINITE_TIMEOUT	(9223372036854775807LL)

enum {
	B_TIMEOUT						= 0x8,
	B_RELATIVE_TIMEOUT				= 0x8,
	B_ABSOLUTE_TIMEOUT				= 0x10,
};

enum {
	B_RELEASE_ALL				= 0x08
};

struct nexus_thread;

struct nexus_team {
	struct hlist_node		node;
	pid_t					id;

	struct rb_root			threads;
	struct rb_root			ports;

	//struct task_struct	*tsk;
	//struct files_struct	*files;

	struct nexus_thread*	main_thread;
};

struct nexus_thread {
	struct rb_node			node;
	struct kref				ref_count;

	pid_t					id;

	char					name[B_OS_NAME_LENGTH];

	bool					is_thread_blocked;
	bool					has_thread_exited;

	wait_queue_head_t		thread_block;
	wait_queue_head_t		thread_exit;

	struct semaphore		sem_read;
	struct semaphore		sem_write;

	wait_queue_head_t		buffer_read;
	int						buffer_ready;

	const void*				buffer;
	ssize_t					buffer_size;

	pid_t					sender;

	int32_t					return_code;

	struct nexus_team*		team;
};

struct nexus_buffer {
	struct list_head		node;

	int32_t					code;
	const void*				buffer;
	size_t					size;

	uid_t					sender;
	gid_t					sender_group;
	pid_t					sender_team;
};

struct nexus_port {
	struct rb_node			node;
	struct kref				ref_count;

	int32_t					id;
	char					name[B_OS_NAME_LENGTH];
	uint32_t				capacity;

	bool					is_open;

	struct list_head		queue;
	wait_queue_head_t		buffer_read;
	wait_queue_head_t		buffer_write;
	int32_t					write_count;
	int32_t					read_count;
	int32_t					total_count;

	// TODO remove
	rwlock_t				rw_lock;

	struct nexus_team*		team;
};

struct nexus_sem {
	struct rb_node			node;
	struct kref				ref_count;

	int32_t					id;
	char*					name;
	//uint32_t				status;
	bool					deleted;

	atomic_t				count;
	atomic_t				acquire_count;
	pid_t					last_holder;

    struct wait_queue_head	wait_queue;

	struct task_struct*		team;
};

struct nexus_area {
	struct rb_node			node;
	struct kref				ref_count;

	int32_t					id;
	char					name[B_OS_NAME_LENGTH];

	bool					is_clone;
	struct nexus_area*		source_area;
	struct nexus_area*		clones;

	struct file*			file;

	bool					transfer_done;

	pid_t					team;
};

struct nexus_vref {
	struct hlist_node		node;
	struct kref				ref_count;

	int32_t					id;
	struct file*			file;

	struct list_head		fd_list;

	//int					fd;
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
