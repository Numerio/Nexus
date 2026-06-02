// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Dario Casalinuovo
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include "query.h"

int nexus_query_init(void) { pr_info("nexus_query: initialized (stub)\n"); return 0; }
void nexus_query_exit(void) {}

long nexus_query_ioctl_open(unsigned long arg)
{
	(void)arg;
	return -ENOSYS;
}
