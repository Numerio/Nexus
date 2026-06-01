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
void     nexus_vref_drop_kernel_ref(int32_t id);

#endif
