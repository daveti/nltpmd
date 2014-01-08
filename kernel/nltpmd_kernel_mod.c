/*
 * nltpmd_kernel_mod.c
 * nltpmd kernel module using netlink
 * Kernel version: 2.6.X
 * Jan 7, 2014
 * daveti@cs.uoregon.edu
 * http://daveti.blog.com
 */

#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#define NLTPMD_NETLINK	77

struct sock *nl_sk = NULL;

static void nltpmd_nl_recv_msg(struct sk_buff *skb)
{
        struct nlmsghdr *nlh;
        int pid;
        struct sk_buff *skb_out;
        int msg_size;
        char *msg="hello_from_nltpmd_kernel_module";
        int res;

        printk(KERN_INFO "nltpmd: entering: %s\n", __FUNCTION__);

        msg_size = strlen(msg);
        nlh = (struct nlmsghdr*)skb->data;
	pid = nlh->nlmsg_pid; /*pid of sending process */
        printk(KERN_INFO "nltpmd: netlink received msg payload: [%s], from pid: [%u]\n",
                (char*)nlmsg_data(nlh), pid);

        /* Send the msg from kernel to the user */
        skb_out = nlmsg_new(msg_size, 0);
        if (!skb_out) {
                printk(KERN_ERR "nltpmd: failed to allocate new skb\n");
                return;
        }

        nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);  
        NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
        strncpy(nlmsg_data(nlh), msg, msg_size);

        res = nlmsg_unicast(nl_sk, skb_out, pid);

        if (res)
                printk(KERN_INFO "nltpmd: error while sending back to user\n");
}

static int __init nltpmd_kmod_init(void)
{
        printk("entering: %s\n", __FUNCTION__);
	nl_sk = netlink_kernel_create(&init_net, NLTPMD_NETLINK, 0, nltpmd_nl_recv_msg,
                                        NULL, THIS_MODULE);
        if(!nl_sk) {
                printk(KERN_ALERT "nltpmd: error creating socket.\n");
                return -10;
        }

        return 0;
}

static void __exit nltpmd_kmod_exit(void)
{
        printk(KERN_INFO "exiting nltpmd kernel module\n");
        netlink_kernel_release(nl_sk);
}

module_init(nltpmd_kmod_init);
module_exit(nltpmd_kmod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("nltpmd kernel module");
MODULE_AUTHOR("daveti");
