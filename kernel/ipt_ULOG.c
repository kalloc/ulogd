/*
 * netfilter module for userspace packet logging daemons
 *
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * 2000/09/22 ulog-cprange feature added
 * 2001/01/04 in-kernel queue as proposed by Sebastian Zander 
 * 						<zander@fokus.gmd.de>
 *
 * Released under the terms of the GPL
 *
 * $Id: ipt_ULOG.c,v 1.7 2001/01/30 09:27:31 laforge Exp $
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/config.h>
#include <linux/spinlock.h>
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
#define ULOG_SLAB_MAX	100000	/* from mm/slab.c: 131072 */

#if 0
#define DEBUGP	printk
#else
#define DEBUGP(format, args...)
#endif

MODULE_AUTHOR("Harald Welte <laforge@gnumonks.org>");
MODULE_DESCRIPTION("IP tables userspace logging module");

static struct sock *nflognl;	/* our socket */
static struct sk_buff *nlskb;	/* the skb containing the nlmsg */
static size_t qlen;		/* current length of multipart-nlmsg */
static size_t max_size;		/* maximum gross size of one packet */
static size_t max_qthresh;	/* maximum queue threshold of all rules */
static spinlock_t ulog_lock;	/* spinlock */

static void nflog_rcv(struct sock *sk, int len)
{
	printk("ipt_ULOG:nflog_rcv() did receive netlink message ?!?\n");
}

static unsigned int ipt_ulog_target(struct sk_buff **pskb,
				    unsigned int hooknum,
				    const struct net_device *in,
				    const struct net_device *out,
				    const void *targinfo, void *userinfo)
{
	ulog_packet_msg_t *pm;
	size_t size, copy_len;
	struct sk_buff *newskb = NULL;
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

	spin_lock_bh(ulog_lock);

	if ((qlen == 0) || (!nlskb)) {
		/* alloc skb which should be big enough for a whole
		 * multipart message. WARNING: has to be <= 131000
		 * due to slab allocator restrictions */
		nlskb = alloc_skb((max_qthresh * max_size), GFP_ATOMIC);
	} else if (size > skb_tailroom(nlskb)) {
		DEBUGP("ipt_ULOG: copy expand %d %d\n", 
			skb_tailroom(nlskb), size);
		newskb = skb_copy_expand(nlskb, skb_headroom(nlskb),
					 size, GFP_ATOMIC);
		if (!newskb) {
			printk("ipt_ULOG: OOM\n");
			goto oom_failure;
		}
		
		kfree_skb(nlskb);
		nlskb = newskb;
	}

	if (!nlskb)
		goto nlmsg_failure;

	DEBUGP("ipt_ULOG: qlen %d, qthreshold %d\n", qlen, loginfo->qthreshold);

	nlh = NLMSG_PUT(nlskb, 0, qlen, ULOG_NL_EVENT, size - sizeof(*nlh));
	qlen++;

	pm = NLMSG_DATA(nlh);

	/* copy hook, prefix, timestamp, payload, etc. */

	pm->data_len = copy_len;
	pm->timestamp_sec = (*pskb)->stamp.tv_sec;
	pm->timestamp_usec = (*pskb)->stamp.tv_usec;
	pm->mark = (*pskb)->nfmark;
	pm->hook = hooknum;
	if (loginfo->prefix[0] != '\0')
		strcpy(pm->prefix, loginfo->prefix);
	else
		*(pm->prefix) = '\0';

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
	
	/* check if we are building multi-part messages */
	if (loginfo->qthreshold > 1) {
		nlh->nlmsg_flags |= NLM_F_MULTI;
	}

	/* if threshold is reached, send message to userspace */
	if (qlen >= loginfo->qthreshold) {
		if (loginfo->qthreshold > 1)
			nlh->nlmsg_type = NLMSG_DONE;
		NETLINK_CB(nlskb).dst_groups = loginfo->nl_group;
		DEBUGP("ipt_ULOG: throwing %d packets to netlink mask %u\n",
			qlen, loginfo->nl_group);
		netlink_broadcast(nflognl, nlskb, 0, loginfo->nl_group,
				  GFP_ATOMIC);
		qlen = 0;
		nlskb = NULL;
	}

	spin_unlock_bh(ulog_lock);

	return IPT_CONTINUE;

oom_failure:
	if (newskb)
		kfree_skb(newskb);
nlmsg_failure:
	if (nlskb) {
		kfree(nlskb);
		nlskb = NULL;
	}

	printk("ipt_ULOG: Error building netlink message\n");

	spin_unlock_bh(ulog_lock);

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
		DEBUGP("ipt_ULOG: targinfosize %u != 0\n", targinfosize);
		return 0;
	}

	if (loginfo->prefix[sizeof(loginfo->prefix) - 1] != '\0') {
		DEBUGP("ipt_ULOG: prefix term %i\n",
		       loginfo->prefix[sizeof(loginfo->prefix) - 1]);
		return 0;
	}

	if (loginfo->qthreshold > ULOG_MAX_QLEN) {
		DEBUGP("ipt_ULOG: queue threshold %i > MAX_QLEN\n",
			loginfo->qthreshold);
		return 0;
	}

	if (loginfo->qthreshold > max_qthresh) {
		if (loginfo->qthreshold * max_size > ULOG_SLAB_MAX) {
			DEBUGP("ipt_ULOG: qthresh too big\n");
			return 0;
		}
		DEBUGP("ipt_ULOG: increasing max_qthresh to %u\n", 
			loginfo->qthreshold);
		max_qthresh = loginfo->qthreshold;
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

	/* FIXME: does anybody know an easy way to determine the biggest
	 * MTU of all interfaces in the system ? */
	max_size = 1500;

	spin_lock_init(ulog_lock);

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
