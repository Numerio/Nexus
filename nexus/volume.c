// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Dario Casalinuovo
 */

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/uuid.h>

#include "nexus.h"
#include "node_monitor.h"
#include "volume.h"
#include "fs_caps_kernel.h"

int nexus_volume_init(void) { return 0; }
void nexus_volume_exit(void) {}

uint32_t nexus_caps_for_inode(struct inode *inode)
{
	const char *n;
	uint32_t caps = 0;

	if (!inode || !inode->i_sb || !inode->i_sb->s_type)
		return 0;
	n = inode->i_sb->s_type->name;

	if (fs_caps_kernel_is_pseudo(n))
		return 0;

	u32 tf = fs_caps_kernel_caps_for(n);
	if (tf & FS_CAP_ATTR)
		caps |= NX_FS_HAS_ATTR;
	if (tf & FS_CAP_QUERY)
		caps |= NX_FS_HAS_QUERY;
	if (tf & FS_CAP_NODEMON)
		caps |= NX_FS_SUPPORTS_NODE_MONITORING
			| NX_FS_SUPPORTS_MONITOR_CHILDREN;
	if (tf == 0)
		caps = NX_FS_HAS_ATTR | NX_FS_HAS_QUERY
			| NX_FS_SUPPORTS_NODE_MONITORING
			| NX_FS_SUPPORTS_MONITOR_CHILDREN;

	if (inode->i_sb->s_flags & SB_RDONLY)
		caps |= NX_FS_IS_READONLY;

	return caps;
}

int nexus_uuid_for_inode(struct inode *inode, char *out)
{
	if (!inode || !inode->i_sb || !out)
		return -EINVAL;

	// Bail if s_uuid is the zero uuid (tmpfs/proc/sys/etc.) */
	if (uuid_is_null((uuid_t *)&inode->i_sb->s_uuid))
		return -ENODATA;

	// %pUb formats a uuid_t as 36-char lowercase canonical form
	snprintf(out, 37, "%pUb", &inode->i_sb->s_uuid);
	return 0;
}

uint64_t nexus_volume_sentinel_dev(void)
{
	return nexus_node_monitor_dev();
}

long nexus_volume_ioctl_query_flags(unsigned long arg)
{
	struct nexus_query_volume_flags req;
	struct file *file;
	uint32_t caps;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	file = fget(req.target_fd);
	if (!file)
		return -EBADF;

	caps = nexus_caps_for_inode(file_inode(file));
	fput(file);

	req.flags = caps;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}
