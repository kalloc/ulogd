/*
 * netfilter module for userspace packet logging daemons
 *
 * (C) 2000 by Harald Welte <laforge@sunbeam.franken.de>
 *
 * Released under the terms of the GPL
 *
 * $Id: ipt_ULOG.c,v 1.4 2000/07/31 11:41:06 laforge Exp $
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
#include <linux/socket.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_ULOG.h>
#include <net/sock.h>

#define ULOG_NL_EVENT	111	/* Harald's favorite number */

#if 0
#define DEBUGP	printk
#else
#define DEBUGP(format, args...)
#endif

static struct sock *nflognl;

static void nflog_rcv(struct sock *sk, int len)
{
	printk("nflog_rcv: did receive netlink message ?!?\n");
}

static unsigned int ipt_ulog_target(struct sk_buff **pskb,
				    unsigned int hooknum,
				    const struct net_device *in,
				    const struct net_device *out,
				    const void *targinfo, void *userinfo)
{
	ulog_packet_msg_t *pm;
	size_t size, copy_len;
	struct sk_buff *nlskb;
	unsigned char *old_tail;
	struct nlmsghdr *nlh;
	struct ipt_ulog_info *loginfo = (struct ipt_ulog_info *) targinfo;

	/* calculate the size of the skb needed */
	if ((loginfo->copy_range == 0) ||
	    (loginfo->copy_range > (*pskb)->len)) {
		copy_len = (*pskb)->len;
	} else {
		copy_len = loginfo->copy_range;
	}
	size = NLMSG_SPACE(sizeof(*pm) + copy_len);
	nlskb = alloc_skb(size, GFP_ATOMIC);
	if (!nlskb)
		goto nlmsg_failure;

	old_tail = nlskb->tail;
	nlh = NLMSG_PUT(nlskb, 0, 0, ULOG_NL_EVENT, size - sizeof(*nlh));
	pm = NLMSG_DATA(nlh);

	/* copy hook, prefix, timestamp, payload, etc. */

	pm->data_len = copy_len;
	pm->timestamp_sec = (*pskb)->stamp.tv_sec;
	pm->timestamp_usec = (*pskb)->stamp.tv_usec;
	pm->mark = (*pskb)->nfmark;
	pm->hook = hooknum;
	if (loginfo->prefix[0] != '\0')
		strcpy(pm->prefix, loginfo->prefix);

	if (in && in->hard_header_len > 0
	    && (*pskb)->mac.raw != (void *) (*pskb)->nh.iph
	    && in->hard_header_len <= ULOG_MAC_LEN) {
		memcpy(pm->mac, (*pskb)->mac.raw, in->hard_header_len);
		pm->mac_len = in->hard_header_len;
	}

	if (in)
		strcpy(pm->indev_name, in->name);
	else
		pm->indev_name[0] = '\0';

	if (out)
		strcpy(pm->outdev_name, out->name);
	else
		pm->outdev_name[0] = '\0';

	if (copy_len)
		memcpy(pm->payload, (*pskb)->data, copy_len);
	nlh->nlmsg_len = nlskb->tail - old_tail;
	NETLINK_CB(nlskb).dst_groups = loginfo->nl_group;
	DEBUGP
	    ("ipt_ULOG: going to throw a packet to netlink groupmask %u\n",
	     loginfo->nl_group);
	netlink_broadcast(nflognl, nlskb, 0, loginfo->nl_group,
			  GFP_ATOMIC);

	return IPT_CONTINUE;

      nlmsg_failure:
	if (nlskb)
		kfree(nlskb);
	printk("ipt_ULOG: Error building netlink message\n");
	return IPT_CONTINUE;
}

static int ipt_ulog_checkentry(const char *tablename,
			       const struct ipt_entry *e,
			       void *targinfo,
			       unsigned int targinfosize,
			       unsigned int hookmask)
{
	struct ipt_ulog_info *loginfo = (struct ipt_ulog_info *) targinfo;

	if (targinfosize != IPT_ALIGN(sizeof(struct ipt_ulog_info))) {
		DEBUGP("ULOG: targinfosize %u != 0\n", targinfosize);
		return 0;
	}

	if (loginfo->prefix[sizeof(loginfo->prefix) - 1] != '\0') {
		DEBUGP("ULOG: prefix term %i\n",
		       loginfo->prefix[sizeof(loginfo->prefix) - 1]);
		return 0;
	}

	return 1;
}

static struct ipt_target ipt_ulog_reg =
    { {NULL, NULL}, "ULOG", ipt_ulog_target, ipt_ulog_checkentry, NULL,
THIS_MODULE
};

static int __init init(void)
{
	DEBUGP("ipt_ULOG: init module\n");
	nflognl = netlink_kernel_create(NETLINK_NFLOG, nflog_rcv);
	if (!nflognl)
		return -ENOMEM;

	if (ipt_register_target(&ipt_ulog_reg) != 0) {
		sock_release(nflognl->socket);
		return -EINVAL;
	}

	return 0;
}

static void __exit fini(void)
{
	DEBUGP("ipt_ULOG: cleanup_module\n");

	ipt_unregister_target(&ipt_ulog_reg);
	sock_release(nflognl->socket);
}

module_init(init);
module_exit(fini);
