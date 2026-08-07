/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2026 Dario Casalinuovo
 */

#ifndef _NEXUS_FS_CAPS_H
#define _NEXUS_FS_CAPS_H

#ifdef __KERNEL__
#  include <linux/types.h>
#  include <linux/string.h>
#else
#  include <stdint.h>
#  include <string.h>
#  include <strings.h>
#endif

/* Version tag logged at module init; bump when the table changes. */
#define FS_CAPS_CHECKSUM 0xea8c3f43u

#define FS_CAP_PSEUDO     (1u << 0)
#define FS_CAP_PERSISTENT (1u << 1)
#define FS_CAP_READONLY   (1u << 2)
#define FS_CAP_ATTR       (1u << 3)
#define FS_CAP_QUERY      (1u << 4)
#define FS_CAP_NODEMON    (1u << 5)
#define FS_CAP_IDMAP      (1u << 6)

struct fs_cap_entry {
	const char*	name;
	uint32_t	magic;		/* Linux statfs f_type; 0 = mount-only id */
	uint32_t	flags;
	const char*	legacy_name;	/* Be display name; "" for pseudo fs */
};

struct fs_cap_alias {
	const char*	alias;
	const char*	name;
};

static const struct fs_cap_entry fs_caps_entries[] = {
	{ "ext2",          0x0000ef53u, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_QUERY | FS_CAP_NODEMON | FS_CAP_IDMAP, "EXT2 File System" },
	{ "ext3",          0x0000ef53u, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_QUERY | FS_CAP_NODEMON | FS_CAP_IDMAP, "EXT3 File System" },
	{ "ext4",          0x0000ef53u, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_QUERY | FS_CAP_NODEMON | FS_CAP_IDMAP, "EXT4 File System" },
	{ "xfs",           0x58465342u, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_QUERY | FS_CAP_NODEMON | FS_CAP_IDMAP, "XFS File System" },
	{ "btrfs",         0x9123683eu, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_QUERY | FS_CAP_NODEMON | FS_CAP_IDMAP, "Btrfs File System" },
	{ "f2fs",          0xf2f52010u, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_QUERY | FS_CAP_NODEMON | FS_CAP_IDMAP, "F2FS File System" },
	{ "jfs",           0x3153464au, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_NODEMON, "JFS File System" },
	{ "reiserfs",      0x52654973u, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_NODEMON, "ReiserFS File System" },
	{ "bcachefs",      0xca451a4eu, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_NODEMON, "bcachefs File System" },
	{ "nilfs2",        0x00003434u, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_NODEMON, "NILFS2 File System" },
	{ "zfs",           0x2fc12fc1u, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_NODEMON, "ZFS File System" },
	{ "ufs",           0x00011954u, FS_CAP_PERSISTENT | FS_CAP_NODEMON, "UFS File System" },
	{ "vfat",          0x00004d44u, FS_CAP_PERSISTENT | FS_CAP_NODEMON, "FAT32 File System" },
	{ "msdos",         0x00004d44u, FS_CAP_PERSISTENT | FS_CAP_NODEMON, "FAT File System" },
	{ "exfat",         0x2011bab0u, FS_CAP_PERSISTENT | FS_CAP_NODEMON, "exFAT File System" },
	{ "ntfs",          0x5346544eu, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_NODEMON, "NTFS File System" },
	{ "ntfs3",         0x5346544eu, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_NODEMON, "NTFS File System" },
	{ "fuseblk",       0x65735546u, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_NODEMON, "NTFS File System" },
	{ "hfs",           0x00004244u, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_NODEMON, "HFS File System" },
	{ "hfsplus",       0x0000482bu, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_NODEMON, "HFS+ File System" },
	{ "bfs",           0x42465331u, FS_CAP_PERSISTENT | FS_CAP_ATTR | FS_CAP_QUERY | FS_CAP_NODEMON, "Be File System" },
	{ "iso9660",       0x00009660u, FS_CAP_PERSISTENT | FS_CAP_READONLY, "ISO9660 File System" },
	{ "udf",           0x15013346u, FS_CAP_PERSISTENT, "UDF File System" },
	{ "squashfs",      0x73717368u, FS_CAP_PERSISTENT | FS_CAP_READONLY | FS_CAP_ATTR, "SquashFS File System" },
	{ "erofs",         0xe0f5e1e2u, FS_CAP_PERSISTENT | FS_CAP_READONLY | FS_CAP_ATTR, "EROFS File System" },
	{ "overlay",       0x794c7630u, FS_CAP_ATTR | FS_CAP_NODEMON, "OverlayFS" },
	{ "aufs",          0x61756673u, FS_CAP_ATTR | FS_CAP_NODEMON, "AUFS" },
	{ "nfs",           0x00006969u, FS_CAP_PERSISTENT, "NFS" },
	{ "cifs",          0xff534d42u, FS_CAP_PERSISTENT, "CIFS" },
	{ "fuse",          0x65735546u, 0, "FUSE" },
	{ "tmpfs",         0x01021994u, FS_CAP_ATTR | FS_CAP_NODEMON, "RAM File System" },
	{ "ramfs",         0x858458f6u, FS_CAP_ATTR | FS_CAP_NODEMON, "RAM File System" },
	{ "proc",          0x00009fa0u, FS_CAP_PSEUDO | FS_CAP_READONLY, "" },
	{ "sysfs",         0x62656572u, FS_CAP_PSEUDO, "" },
	{ "devtmpfs",      0x00001373u, FS_CAP_PSEUDO, "" },
	{ "devpts",        0x00001cd1u, FS_CAP_PSEUDO, "" },
	{ "cgroup",        0x0027e0ebu, FS_CAP_PSEUDO, "" },
	{ "cgroup2",       0x63677270u, FS_CAP_PSEUDO, "" },
	{ "securityfs",    0x73636673u, FS_CAP_PSEUDO, "" },
	{ "selinuxfs",     0xf97cff8cu, FS_CAP_PSEUDO, "" },
	{ "pstore",        0x6165676cu, FS_CAP_PSEUDO, "" },
	{ "efivarfs",      0xde5e81e4u, FS_CAP_PSEUDO, "" },
	{ "bpf",           0xcafe4a11u, FS_CAP_PSEUDO, "" },
	{ "tracefs",       0x74726163u, FS_CAP_PSEUDO, "" },
	{ "debugfs",       0x64626720u, FS_CAP_PSEUDO, "" },
	{ "configfs",      0x62656570u, FS_CAP_PSEUDO, "" },
	{ "fusectl",       0x65735543u, FS_CAP_PSEUDO, "" },
	{ "hugetlbfs",     0x958458f6u, FS_CAP_PSEUDO, "" },
	{ "mqueue",        0x19800202u, FS_CAP_PSEUDO, "" },
	{ "autofs",        0x00000187u, FS_CAP_PSEUDO, "" },
	{ "rpc_pipefs",    0x67596969u, FS_CAP_PSEUDO, "" },
	{ "nfsd",          0x6e667364u, FS_CAP_PSEUDO, "" },
	{ "binfmt_misc",   0x42494e4du, FS_CAP_PSEUDO, "" },
	{ "nsfs",          0x6e736673u, FS_CAP_PSEUDO, "" },
	{ "pipefs",        0x50495045u, FS_CAP_PSEUDO, "" },
	{ "sockfs",        0x534f434bu, FS_CAP_PSEUDO, "" },
	{ "anon_inodefs",  0x09041934u, FS_CAP_PSEUDO, "" },
};

static const unsigned int fs_caps_entry_count =
	sizeof(fs_caps_entries) / sizeof(fs_caps_entries[0]);

/* Alternate mnt_type strings mapping to a canonical entry (userspace lookup
 * only; the kernel matches canonical names exactly). */
static const struct fs_cap_alias fs_caps_aliases[] = {
	{ "fat",       "vfat" },
	{ "fat32",     "vfat" },
	{ "fat16",     "msdos" },
	{ "ntfs-3g",   "ntfs" },
	{ "overlayfs", "overlay" },
	{ "nfs4",      "nfs" },
	{ "smbfs",     "cifs" },
	{ 0, 0 }
};


/* --- Kernel-facing lookups: exact name match, no alias resolution. --- */

static inline const struct fs_cap_entry*
fs_caps_kernel_by_name(const char* n)
{
	unsigned int i;
	if (!n)
		return 0;
	for (i = 0; i < fs_caps_entry_count; i++) {
		if (!strcmp(n, fs_caps_entries[i].name))
			return &fs_caps_entries[i];
	}
	return 0;
}

static inline bool fs_caps_kernel_is_pseudo(const char* n)
{
	const struct fs_cap_entry* e = fs_caps_kernel_by_name(n);
	return e && (e->flags & FS_CAP_PSEUDO);
}

static inline bool fs_caps_kernel_is_readonly(const char* n)
{
	const struct fs_cap_entry* e = fs_caps_kernel_by_name(n);
	return e && (e->flags & FS_CAP_READONLY);
}

static inline uint32_t fs_caps_kernel_caps_for(const char* n)
{
	const struct fs_cap_entry* e = fs_caps_kernel_by_name(n);
	return e ? e->flags : 0;
}


#ifdef __cplusplus

/* --- Userspace-facing wrappers: case-insensitive, alias-aware. --- */

namespace BPrivate { namespace FsCaps {

typedef ::fs_cap_entry Entry;

enum {
	PSEUDO     = FS_CAP_PSEUDO,
	PERSISTENT = FS_CAP_PERSISTENT,
	READONLY   = FS_CAP_READONLY,
	ATTR       = FS_CAP_ATTR,
	QUERY      = FS_CAP_QUERY,
	NODEMON    = FS_CAP_NODEMON,
	IDMAP      = FS_CAP_IDMAP
};

static inline const Entry*
by_name(const char* mntType)
{
	if (mntType == 0)
		return 0;
	for (unsigned int i = 0; i < fs_caps_entry_count; i++) {
		if (strcasecmp(mntType, fs_caps_entries[i].name) == 0)
			return &fs_caps_entries[i];
	}
	for (unsigned int i = 0; fs_caps_aliases[i].alias != 0; i++) {
		if (strcasecmp(mntType, fs_caps_aliases[i].alias) == 0) {
			for (unsigned int j = 0; j < fs_caps_entry_count; j++) {
				if (strcmp(fs_caps_entries[j].name,
						fs_caps_aliases[i].name) == 0)
					return &fs_caps_entries[j];
			}
		}
	}
	return 0;
}

static inline const Entry*
by_magic(uint32_t fType)
{
	for (unsigned int i = 0; i < fs_caps_entry_count; i++) {
		if (fs_caps_entries[i].magic == fType)
			return &fs_caps_entries[i];
	}
	return 0;
}

static inline bool is_pseudo(const char* mntType) {
	const Entry* e = by_name(mntType);
	return e != 0 && (e->flags & PSEUDO);
}
static inline bool is_persistent(const char* mntType) {
	const Entry* e = by_name(mntType);
	return e != 0 && (e->flags & PERSISTENT);
}
static inline bool is_readonly(const char* mntType) {
	const Entry* e = by_name(mntType);
	return e != 0 && (e->flags & READONLY);
}
static inline bool is_idmap_capable(const char* mntType) {
	const Entry* e = by_name(mntType);
	return e != 0 && (e->flags & IDMAP);
}
static inline bool supports_node_monitor(uint32_t fType) {
	const Entry* e = by_magic(fType);
	return e != 0 && (e->flags & NODEMON);
}
static inline const char* legacy_name(const char* mntType) {
	const Entry* e = by_name(mntType);
	if (e == 0 || e->legacy_name == 0 || e->legacy_name[0] == 0)
		return mntType;
	return e->legacy_name;
}

} } // namespace BPrivate::FsCaps

#endif // __cplusplus

#endif // _NEXUS_FS_CAPS_H
