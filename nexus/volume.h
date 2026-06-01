/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 Dario Casalinuovo
 */

#ifndef _NEXUS_VOLUME_H
#define _NEXUS_VOLUME_H

#include <linux/types.h>
struct inode;

#define NX_FS_IS_READONLY               0x00000001
#define NX_FS_IS_REMOVABLE              0x00000002
#define NX_FS_IS_PERSISTENT             0x00000004
#define NX_FS_IS_SHARED                 0x00000008
#define NX_FS_HAS_MIME                  0x00010000
#define NX_FS_HAS_ATTR                  0x00020000
#define NX_FS_HAS_QUERY                 0x00040000
#define NX_FS_SUPPORTS_NODE_MONITORING  0x00200000
#define NX_FS_SUPPORTS_MONITOR_CHILDREN 0x00400000

int  nexus_volume_init(void);
void nexus_volume_exit(void);

uint32_t nexus_caps_for_inode(struct inode *inode);
int nexus_uuid_for_inode(struct inode *inode, char *out);
uint64_t nexus_volume_sentinel_dev(void);
long nexus_volume_ioctl_query_flags(unsigned long arg);

#endif /* _NEXUS_VOLUME_H */
