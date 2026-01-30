// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026 Dario Casalinuovo
 */

#include <linux/cdev.h>
#include <linux/file.h>
#include <linux/hashtable.h>

#include "errors.h"
#include "nexus.h"
#include "nexus_private.h"

#define DEV_NAME "nexus_area"

static int major = -1;
static struct cdev nexus_cdev;
static struct class *nexus_class = NULL;

// TODO maybe IDR fits better here
static DEFINE_HASHTABLE(area_hashmap, 12);
static DEFINE_MUTEX(area_lock);
static atomic_t area_id_counter = ATOMIC_INIT(1);

static void nexus_area_destroy(struct kref *kref)
{
	struct nexus_area *area = container_of(kref, struct nexus_area, ref_count);

	pr_debug("nexus_area: destroy area %d '%s'\n", area->id, area->name);

	if (area->file)
		fput(area->file);

	hash_del(&area->node);
	kfree(area);
}

static struct nexus_area *find_area_by_id(area_id id)
{
	struct nexus_area *area;

	hash_for_each_possible(area_hashmap, area, node, id) {
		if (area->id == id)
			return area;
	}
	return NULL;
}

static struct nexus_area *find_area_by_name(const char *name)
{
	struct nexus_area *area;
	int bkt;

	hash_for_each(area_hashmap, bkt, area, node) {
		if (strncmp(area->name, name, B_OS_NAME_LENGTH) == 0)
			return area;
	}
	return NULL;
}


static long nexus_area_create(struct nexus_area_create __user *arg)
{
	struct nexus_area_create create;
	struct nexus_area *area;
	struct file *file;

	if (copy_from_user(&create, arg, sizeof(create)))
		return -EFAULT;

	file = fget(create.fd);
	if (!file)
		return -EBADF;

	area = kzalloc(sizeof(*area), GFP_KERNEL);
	if (!area) {
		fput(file);
		return B_NO_MEMORY;
	}

	mutex_lock(&area_lock);

	kref_init(&area->ref_count);
	area->id = atomic_inc_return(&area_id_counter);
	strscpy(area->name, create.name, B_OS_NAME_LENGTH);
	area->file = file;
	area->size = create.size;
	area->lock = create.lock;
	area->protection = create.protection;
	area->team = current->tgid;

	hash_add(area_hashmap, &area->node, area->id);

	mutex_unlock(&area_lock);

	pr_debug("nexus_area: created area %d '%s' size=%llu\n",
			 area->id, area->name, (unsigned long long)area->size);

	create.area = area->id;

	if (copy_to_user(arg, &create, sizeof(create)))
		return -EFAULT;

	return B_OK;
}

static long nexus_area_clone(struct nexus_area_clone __user *arg)
{
	struct nexus_area_clone clone;
	struct nexus_area *source, *area;
	struct file *file;
	int fd;

	if (copy_from_user(&clone, arg, sizeof(clone)))
		return -EFAULT;

	mutex_lock(&area_lock);

	source = find_area_by_id(clone.source);
	if (!source) {
		mutex_unlock(&area_lock);
		return B_BAD_VALUE;
	}

	area = kzalloc(sizeof(*area), GFP_KERNEL);
	if (!area) {
		mutex_unlock(&area_lock);
		return B_NO_MEMORY;
	}

	file = get_file(source->file);

	fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fput(file);
		kfree(area);
		mutex_unlock(&area_lock);
		return B_NO_MEMORY;
	}
	fd_install(fd, file);

	kref_init(&area->ref_count);
	area->id = atomic_inc_return(&area_id_counter);
	strscpy(area->name, clone.name, B_OS_NAME_LENGTH);
	area->file = get_file(source->file);
	area->size = source->size;
	area->lock = source->lock;
	area->protection = clone.protection;
	area->team = current->tgid;

	hash_add(area_hashmap, &area->node, area->id);

	mutex_unlock(&area_lock);

	pr_debug("nexus_area: cloned area %d from %d\n", area->id, source->id);

	clone.area = area->id;
	clone.fd = fd;
	clone.size = source->size;

	if (copy_to_user(arg, &clone, sizeof(clone)))
		return -EFAULT;

	return B_OK;
}

static long nexus_area_delete(struct nexus_area_delete __user *arg)
{
	struct nexus_area_delete del;
	struct nexus_area *area;

	if (copy_from_user(&del, arg, sizeof(del)))
		return -EFAULT;

	mutex_lock(&area_lock);

	area = find_area_by_id(del.area);
	if (!area) {
		mutex_unlock(&area_lock);
		return B_BAD_VALUE;
	}

	kref_put(&area->ref_count, nexus_area_destroy);

	mutex_unlock(&area_lock);

	return B_OK;
}

static long nexus_area_find(struct nexus_area_find __user *arg)
{
	struct nexus_area_find find;
	struct nexus_area *area;

	if (copy_from_user(&find, arg, sizeof(find)))
		return -EFAULT;

	find.name[B_OS_NAME_LENGTH - 1] = '\0';

	mutex_lock(&area_lock);

	area = find_area_by_name(find.name);
	if (!area) {
		mutex_unlock(&area_lock);
		return B_NAME_NOT_FOUND;
	}

	find.area = area->id;
	find.size = area->size;

	mutex_unlock(&area_lock);

	if (copy_to_user(arg, &find, sizeof(find)))
		return -EFAULT;

	return B_OK;
}

static long nexus_area_get_info(struct nexus_area_get_info __user *arg)
{
	struct nexus_area_get_info info;
	struct nexus_area *area;

	if (copy_from_user(&info, arg, sizeof(info)))
		return -EFAULT;

	mutex_lock(&area_lock);

	area = find_area_by_id(info.area);
	if (!area) {
		mutex_unlock(&area_lock);
		return B_BAD_VALUE;
	}

	strscpy(info.name, area->name, B_OS_NAME_LENGTH);
	info.size = area->size;
	info.lock = area->lock;
	info.protection = area->protection;
	info.team = area->team;

	mutex_unlock(&area_lock);

	if (copy_to_user(arg, &info, sizeof(info)))
		return -EFAULT;

	return B_OK;
}

static long nexus_area_resize(struct nexus_area_resize __user *arg)
{
	struct nexus_area_resize resize;
	struct nexus_area *area;

	if (copy_from_user(&resize, arg, sizeof(resize)))
		return -EFAULT;

	mutex_lock(&area_lock);

	area = find_area_by_id(resize.area);
	if (!area) {
		mutex_unlock(&area_lock);
		return B_BAD_VALUE;
	}

	area->size = resize.new_size;

	mutex_unlock(&area_lock);

	return B_OK;
}

static long nexus_area_set_protection(struct nexus_area_set_protection __user *arg)
{
	struct nexus_area_set_protection prot;
	struct nexus_area *area;

	if (copy_from_user(&prot, arg, sizeof(prot)))
		return -EFAULT;

	mutex_lock(&area_lock);

	area = find_area_by_id(prot.area);
	if (!area) {
		mutex_unlock(&area_lock);
		return B_BAD_VALUE;
	}

	area->protection = prot.protection;

	mutex_unlock(&area_lock);

	return B_OK;
}

static long area_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	// TODO we should expect reinit on fork otherwise kill the team?
	switch (cmd) {
		case NEXUS_AREA_CREATE:
			return nexus_area_create((struct nexus_area_create __user *)arg);
		case NEXUS_AREA_CLONE:
			return nexus_area_clone((struct nexus_area_clone __user *)arg);
		case NEXUS_AREA_DELETE:
			return nexus_area_delete((struct nexus_area_delete __user *)arg);
		case NEXUS_AREA_FIND:
			return nexus_area_find((struct nexus_area_find __user *)arg);
		case NEXUS_AREA_GET_INFO:
			return nexus_area_get_info((struct nexus_area_get_info __user *)arg);
		case NEXUS_AREA_RESIZE:
			return nexus_area_resize((struct nexus_area_resize __user *)arg);
		case NEXUS_AREA_SET_PROTECTION:
			return nexus_area_set_protection((struct nexus_area_set_protection __user *)arg);
		default:
			return -EINVAL;
	}
}

static int area_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int area_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations area_fops = {
	.owner = THIS_MODULE,
	.open = area_open,
	.release = area_release,
	.unlocked_ioctl = area_ioctl,
	.compat_ioctl = area_ioctl,
};

static void cleanup_dev(int device_created)
{
	if (device_created) {
		device_destroy(nexus_class, major);
		cdev_del(&nexus_cdev);
	}
	if (nexus_class)
		class_destroy(nexus_class);
	if (major != -1)
		unregister_chrdev_region(major, 1);
}

static int __init area_init(void)
{
	int device_created = 0;

	if (alloc_chrdev_region(&major, 0, 1, DEV_NAME "_proc") < 0)
		goto error;

	nexus_class = class_create(DEV_NAME "_sys");
	if (nexus_class == NULL)
		goto error;

	if (device_create(nexus_class, NULL, major, NULL, DEV_NAME) == NULL)
		goto error;

	device_created = 1;
	cdev_init(&nexus_cdev, &area_fops);
	if (cdev_add(&nexus_cdev, major, 1) == -1)
		goto error;

	pr_info("nexus_area: module loaded\n");
	return 0;

error:
	cleanup_dev(device_created);
	return -1;
}

static void __exit area_exit(void)
{
	struct nexus_area *area;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&area_lock);
	hash_for_each_safe(area_hashmap, bkt, tmp, area, node) {
		hash_del(&area->node);
		if (area->file)
			fput(area->file);
		kfree(area);
	}
	mutex_unlock(&area_lock);

	cleanup_dev(1);
	pr_info("nexus_area: module unloaded\n");
}

module_init(area_init);
module_exit(area_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dario Casalinuovo");
MODULE_DESCRIPTION("Nexus Shared Memory Area");
MODULE_VERSION("1.0");
