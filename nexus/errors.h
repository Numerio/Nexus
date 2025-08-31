// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2025 Dario Casalinuovo
 */

#ifndef _NEXUS_ERRORS_H
#define _NEXUS_ERRORS_H

// TODO we could use negative errno in V\OS for our codes

#define B_GENERAL_ERROR_BASE		INT_MIN
#define B_OS_ERROR_BASE				(B_GENERAL_ERROR_BASE + 0x1000)

#define B_BAD_PORT_ID				(B_OS_ERROR_BASE + 0x200)
#define B_NO_MORE_PORTS				(B_OS_ERROR_BASE + 0x201)

#define B_BAD_VALUE					(B_GENERAL_ERROR_BASE + 5)

#define B_ERROR						(-1)
#define B_OK						((int)0)
#define B_NO_ERROR					((int)0)

#define B_TIMED_OUT					(B_GENERAL_ERROR_BASE + 9)
#define B_WOULD_BLOCK				(B_GENERAL_ERROR_BASE + 11)

#endif
