#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x887b4cdc, "module_layout" },
	{ 0x992c8ec1, "netlink_kernel_release" },
	{ 0x9eb149da, "netlink_kernel_create" },
	{ 0xb9bb2308, "init_net" },
	{ 0x8a0a2260, "netlink_unicast" },
	{ 0x330365cc, "skb_put" },
	{ 0xfac7ff53, "__alloc_skb" },
	{ 0x27e1a049, "printk" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "5CD6182B5387AB24501E5F9");
