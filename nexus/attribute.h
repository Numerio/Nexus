/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 Dario Casalinuovo
 */

#ifndef _NEXUS_ATTRIBUTE_H
#define _NEXUS_ATTRIBUTE_H

int  nexus_attr_init(void);
void nexus_attr_exit(void);

long nexus_attr_ioctl_dir_open(unsigned long arg);
long nexus_attr_ioctl_read(unsigned long arg);
long nexus_attr_ioctl_write(unsigned long arg);
long nexus_attr_ioctl_stat(unsigned long arg);
long nexus_attr_ioctl_remove(unsigned long arg);
long nexus_attr_ioctl_rename(unsigned long arg);

#endif /* _NEXUS_ATTRIBUTE_H */
