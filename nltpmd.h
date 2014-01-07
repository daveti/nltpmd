/*
 * nltpmd.h
 * Header file for nltpmd
 * Dec 12, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#ifndef NLTPMD_INCLUDE
#define NLTPMD_INCLUDE

#define NLTPMD_NETLINK		33
#define NLTPMD_RECV_BUFF_LEN	1024*1024

/* Init the netlink */
int nltpmd_init_netlink(void);

#endif
