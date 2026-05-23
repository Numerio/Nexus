/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NEXUS_VREF_H
#define _NEXUS_VREF_H

int  nexus_vref_init(void);
void nexus_vref_exit(void);
void nexus_vref_team_exit(pid_t team);
long nexus_vref_ioctl(unsigned int cmd, unsigned long arg);

#endif
