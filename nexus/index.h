/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 Dario Casalinuovo
 */

#ifndef _NEXUS_INDEX_H
#define _NEXUS_INDEX_H

int  nexus_index_init(void);
void nexus_index_exit(void);

long nexus_index_ioctl_dir_open(unsigned long arg);
long nexus_index_ioctl_create(unsigned long arg);
long nexus_index_ioctl_remove(unsigned long arg);
long nexus_index_ioctl_stat(unsigned long arg);

#endif /* _NEXUS_INDEX_H */
