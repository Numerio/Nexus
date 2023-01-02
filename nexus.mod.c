#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xbbcac5c1, "module_layout" },
	{ 0xfb578fc5, "memset" },
	{ 0x50287116, "cdev_add" },
	{ 0xfb21267f, "cdev_init" },
	{ 0x42491684, "device_create" },
	{ 0xc037ef1, "__class_create" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0xca9360b5, "rb_next" },
	{ 0xece784c2, "rb_first" },
	{ 0xe68efe41, "_raw_write_lock" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x40f6f48c, "get_pid_task" },
	{ 0xc1a9a52b, "find_get_pid" },
	{ 0xcf2a6966, "up" },
	{ 0x6626afca, "down" },
	{ 0xa5526619, "rb_insert_color" },
	{ 0xea47aa2f, "get_task_pid" },
	{ 0x4d9b652b, "rb_erase" },
	{ 0xd9a5ea54, "__init_waitqueue_head" },
	{ 0x68f31cbd, "__list_add_valid" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0xc50dfc48, "kmem_cache_alloc_trace" },
	{ 0xbde1edaf, "kmalloc_caches" },
	{ 0x296695f, "refcount_warn_saturate" },
	{ 0x46ad8c4a, "__put_task_struct" },
	{ 0x3eeb2322, "__wake_up" },
	{ 0xc5850110, "printk" },
	{ 0x37a0cba, "kfree" },
	{ 0xe1537255, "__list_del_entry_valid" },
	{ 0xc959d152, "__stack_chk_fail" },
	{ 0x46a4b118, "hrtimer_cancel" },
	{ 0xc1b7908b, "hrtimer_sleeper_start_expires" },
	{ 0x3952887, "ktime_add_safe" },
	{ 0x63f7ebf0, "hrtimer_init_sleeper" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x92540fbf, "finish_wait" },
	{ 0x8c26d495, "prepare_to_wait_event" },
	{ 0x1000e51, "schedule" },
	{ 0xfe487975, "init_wait_entry" },
	{ 0x409bcb62, "mutex_unlock" },
	{ 0x2ab7989d, "mutex_lock" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x1f0cd6a1, "current_task" },
	{ 0x20b8fce0, "cdev_del" },
	{ 0xc7b5fbdd, "device_destroy" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0x55ee1476, "class_destroy" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x56470118, "__warn_printk" },
	{ 0x5b8239ca, "__x86_return_thunk" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "7C2A103938DBC46D07EB885");
