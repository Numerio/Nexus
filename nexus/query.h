// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Dario Casalinuovo
 */

#ifndef _NEXUS_QUERY_H
#define _NEXUS_QUERY_H

int  nexus_query_init(void);
void nexus_query_exit(void);
long nexus_query_ioctl_open(unsigned long arg);

#endif /* _NEXUS_QUERY_H */
