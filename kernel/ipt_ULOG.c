/* 
 * netfilter module for userspace packet logging daemons
 *
 * (C) 2000 by Harald Welte <laforge@sunbeam.franken.de>
 * 
 * Released under the terms of the GPL
 *
 * $Id$
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/config.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/netdevice.h>
#include <linux/mm.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_ULOG.h>

#define NETLINK_NFLOG 	25
#define ULOG_NL_EVENT	111

#if 1
#define DEBUGP	printk
#else
#define DEBUGP(format, args ...)
#endif

struct sock *nflognl;

static void nflog_rcv(struct sock *sk, int len)
{
	printk("nflog_rcv: did receive netlink message ?!?\n");
}

static unsigned int ipt_ulog_target(
	struct sk_buff **pskb,
	unsigned int hooknum,
	const struct net_device *in,
	const struct net_device *out,
	const void *targinfo,
	void *userinfo)
{
	ulog_packet_msg_t *pm;
	size_t size;
	struct sk_buff *nlskb;
	unsigned char *old_tail;
	struct nlmsghdr *nlh;
	struct ipt_ulog_info *loginfo = (struct ipt_ulog_info *)targinfo;

	/* calculate the size of the skb needed */

	size = NLMSG_SPACE(sizeof(*pm) + (*pskb)->len);
	nlskb = alloc_skb(size, GFP_ATOMIC);
	if (!nlskb)
		goto nlmsg_failure;
	
	old_tail = nlskb->tail;
	nlh = NLMSG_PUT(nlskb, 0, 0, ULOG_NL_EVENT, size - sizeof(*nlh));
	pm = NLMSG_DATA(nlh);
	
	/* copy hook, prefix, timestamp, payload, etc. */

	pm->data_len = (*pskb)->len;
	pm->timestamp_sec = (*pskb)->stamp.tv_sec;
	pm->timestamp_usec = (*pskb)->stamp.tv_usec;
	pm->mark = (*pskb)->nfmark;
	pm->hook = hooknum;
	if (loginfo->prefix)
		strcpy(pm->prefix, loginfo->prefix);

	if (in && !out)
	{
		if ((*pskb)->dev && (*pskb)->dev->hard_header_len > 0 
			&& (*pskb)->dev->hard_header_len <= ULOG_MAC_LEN)
		{
			memcpy(pm->mac, (*pskb)->mac.raw, (*pskb)->dev->hard_header_len);
			pm->mac_len = (*pskb)->dev->hard_header_len;
		}

	}
/*
	if (in) strcpy(pm->indev_name, in->name);
	else pm->indev_name[0] = '\0';
*/
	if ((*pskb)->len)
		memcpy(pm->payload, (*pskb)->data, (*pskb)->len);
	nlh->nlmsg_len = nlskb->tail - old_tail;
	NETLINK_CB(nlskb).dst_groups = loginfo->nl_group;
	DEBUGP("ipt_ULOG: going to throw out a packet to netlink groupmask %u\n", loginfo->nl_group);
	netlink_broadcast(nflognl, nlskb, 0, loginfo->nl_group, GFP_ATOMIC);

	return IPT_CONTINUE;

nlmsg_failure:
	if (nlskb)
		kfree(nlskb);	
	printk("ipt_ULOG: Error building netlink message\n");
	return IPT_CONTINUE;

}

static int ipt_ulog_checkentry(
	const char *tablename,
	const struct ipt_entry *e,
	void *targinfo,
	unsigned int targinfosize,
	unsigned int hookmask)
{
	return 1;
}
	

static struct ipt_target ipt_ulog_reg =
  { { NULL, NULL }, "ULOG", ipt_ulog_target, ipt_ulog_checkentry, NULL,
	THIS_MODULE };

static int __init init(void)
{
	DEBUGP("ipt_ULOG: init module\n");
	nflognl = netlink_kernel_create(NETLINK_NFLOG, nflog_rcv);
	if (ipt_register_target(&ipt_ulog_reg))
		return -EINVAL;

	return 0;
}

static void __exit fini(void)
{       
	DEBUGP("ipt_ULOG: cleanup_module\n");
	ipt_unregister_target(&ipt_ulog_reg);
}

module_init(init);
module_exit(fini);
