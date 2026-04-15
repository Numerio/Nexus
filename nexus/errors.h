// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026 Dario Casalinuovo
 */

#ifndef _NEXUS_ERRORS_H
#define _NEXUS_ERRORS_H

#define B_GENERAL_ERROR_BASE		INT_MIN
#define B_OS_ERROR_BASE				(B_GENERAL_ERROR_BASE + 0x2000)

#define B_TIMED_OUT					-ETIMEDOUT

#define B_BAD_SEM_ID				(B_OS_ERROR_BASE + 1)
#define B_NO_MORE_SEMS				-ENOLCK
#define B_BAD_THREAD_ID				(B_OS_ERROR_BASE + 3)
#define B_BAD_PORT_ID				(B_OS_ERROR_BASE + 8)
#define B_NO_MORE_PORTS				-ENFILE

#define B_BAD_TEAM_ID				-ESRCH
#define B_BAD_VALUE					-EINVAL
#define B_NO_MEMORY					-ENOMEM
#define B_ENTRY_NOT_FOUND			-ENOENT
#define B_WOULD_BLOCK				-EAGAIN
#define B_INTERRUPTED				-EINTR

#define B_BAD_ADDRESS				-EFAULT
#define B_NOT_ALLOWED				(B_GENERAL_ERROR_BASE + 16)

#define B_ERROR						(-1)
#define B_OK						((int)0)
#define B_NO_ERROR					((int)0)

#endif
