#ifndef _IPT_ULOG_H
#define _IPT_ULOG_H

#ifdef __KERNEL__
#include <linux/netdevice.h>
#endif

#define ULOG_MAC_LEN	80


/* just until this is in netfilter.h */
#ifndef NETLINK_NFLOG
#define NETLINK_NFLOG 25
#endif

struct ipt_ulog_info {
	unsigned char logflags;
	unsigned int nl_group;
	char prefix[30];
};

typedef struct ulog_packet_msg {
	unsigned long mark;
	long timestamp_sec;
	long timestamp_usec;
	unsigned int hook;
	char indev_name[IFNAMSIZ];
	char outdev_name[IFNAMSIZ];
	size_t data_len;
	char prefix[30];
	unsigned char mac_len;
	unsigned char mac[ULOG_MAC_LEN];
	unsigned char payload[0];
} ulog_packet_msg_t;

#endif /*_IPT_ULOG_H*/
