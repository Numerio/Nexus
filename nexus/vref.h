// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026. Dario Casalinuovo
 */
#ifndef _NEXUS_VREF_H
#define _NEXUS_VREF_H

#include <linux/file.h>
#include <linux/types.h>

int      nexus_vref_init(void);
void     nexus_vref_exit(void);
void     nexus_vref_team_exit(pid_t team);
long     nexus_vref_ioctl(unsigned int cmd, unsigned long arg);
int32_t  nexus_vref_create_from_file(struct file *file);
int      nexus_vref_grant_slot_for_id(int32_t id, pid_t target_team);
/* Pins the given path (dentry + vfsmount) for the vref's lifetime. */
int32_t  nexus_vref_create_from_path(const struct path *src, fmode_t mode);
void     nexus_vref_drop_kernel_ref(int32_t id);
/* Bump kref on id; true if found. Use to extend lifetime past the original
 * holder (e.g., a queued notification's embedded id until delivery). */
bool     nexus_vref_acquire_kernel_ref(int32_t id);

struct nexus_vref;
struct nexus_vref *nexus_vref_kref_acquire(int32_t id);
void               nexus_vref_kref_release(struct nexus_vref *entry);
int                nexus_vref_mint_slot_for(struct nexus_vref *entry,
                       pid_t target_team, uint64_t *out_key);

#endif
