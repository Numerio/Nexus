// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include "attribute.h"
int nexus_attr_init(void) { pr_info("nexus_attr: initialized (stub)\n"); return 0; }
void nexus_attr_exit(void) {}