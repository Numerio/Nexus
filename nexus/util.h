// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026 Dario Casalinuovo
 */

#ifndef __VOS_NEXUS_UTIL
#define __VOS_NEXUS_UTIL

static inline bigtime_t system_time(void)
{
	return ktime_to_us(ktime_get());
}

static long calculate_timeout(bigtime_t timeout, uint32_t flags)
{
	bigtime_t now, us;

	if (!(flags & (B_RELATIVE_TIMEOUT | B_ABSOLUTE_TIMEOUT)))
		return MAX_SCHEDULE_TIMEOUT;

	if (flags & B_ABSOLUTE_TIMEOUT) {
		now = system_time();
		if (timeout <= now)
			return 0;
		us = timeout - now;
	} else {
		if (timeout == 0)
			return 0;
		us = timeout;
	}

	return usecs_to_jiffies(us) + 1;
}

#endif // __VOS_NEXUS_PRIVATE
