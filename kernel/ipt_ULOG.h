#ifndef _IPT_ULOG_H
#define _IPT_ULOG_H

#define ULOG_MAC_LEN	80
#define ULOG_PREFIX_LEN	32

struct ipt_ulog_info {
	unsigned char logflags;
	unsigned int nl_group;
	char prefix[ULOG_PREFIX_LEN];
};

typedef struct ulog_packet_msg {
	unsigned long mark;
	long timestamp_sec;
	long timestamp_usec;
	unsigned int hook;
	char indev_name[IFNAMSIZ];
	char outdev_name[IFNAMSIZ];
	size_t data_len;
	char prefix[ULOG_PREFIX_LEN];
	unsigned char mac_len;
	unsigned char mac[ULOG_MAC_LEN];
	unsigned char payload[0];
} ulog_packet_msg_t;

#endif /*_IPT_ULOG_H*/
