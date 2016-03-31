/* Redirect.  Simple mapping which alters dst to a local IP address. */
/* (C) 1999-2001 Paul `Rusty' Russell
* (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation.
http://bbs.chinaunix.net/forum.php?mod=viewthread&action=printable&tid=1976797
TODO: copy and modify skb: http://stackoverflow.com/questions/10245281/using-sk-buff-to-add-an-ethernet-frame-header
book: http://www.embeddedlinux.org.cn/linux_net/0596002556/understandlni-CHP-2-SECT-1.html
idea: http://gmd20.blog.163.com/blog/static/16843923200991325910251/
append data: http://stackoverflow.com/questions/12529497/how-to-append-data-on-a-packet-from-kernel-space
流程：http://nano-chicken.blogspot.jp/2010/03/linux-modules12-netfilter.html
中文系列文章： http://blog.csdn.net/shanshanpt/article/details/21024465
spinlock sumery: http://blog.csdn.net/wesleyluo/article/details/8807919
seria2: http://blog.csdn.net/majieyue/article/details/7722632
setsockopt: http://www.programering.com/a/MjMxYjMwATE.html
*/

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/inet.h>//in_aton
#include <linux/timer.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/inetdevice.h>
#include <net/protocol.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat_rule.h>

#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/nf_tproxy_core.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netfilter Core Team <coreteam@netfilter.org>");
MODULE_DESCRIPTION("iptables REDIRECT target module");

//char *dst="192.168.6.1";
//__be16 dport=80;
//module_param(dst,charp,0644);
//module_param(dport,ushort,0644);
static struct nf_hook_ops tproxy_ops;
unsigned int tproxy_func(unsigned int hooknum, struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int(*okfn)(struct sk_buff*))
{
        struct nf_conn *ct;
        enum ip_conntrack_info ctinfo;
        __be32 newdst;
        struct nf_nat_range newrange;
        union nf_conntrack_man_proto min, max;

        struct iphdr *nowiph;
	struct udphdr _hdr, *hp;
	struct sock *sk;

        struct net_device *dev;
        uint16_t dport = 3333;
        uint32_t sip = 0xc0a80101;

        uint32_t taddr;

        nowiph = (struct iphdr *)skb_network_header(skb);
        if(nowiph->protocol != IPPROTO_TCP && nowiph->protocol != IPPROTO_UDP) {
            printk("1 ");
            return NF_ACCEPT;
        }

        taddr = ntohl(nowiph->saddr);
        if ( ((taddr & 0xFFFFFF00) != (sip & 0xFFFFFF00)) || (taddr == sip) ) {
            //ignore local ip or not subnet ip
            printk("2 ");
            return NF_ACCEPT;
        }

	hp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_hdr), &_hdr);
	if (hp == NULL) {
            printk("3 ");
            return NF_ACCEPT;
        }

        /* nowtcp = (struct tcphdr *)(skb->data + (nowiph->ihl*4));
        if(ntohs(nowtcp->dest) != 80) {
            return NF_ACCEPT;
        } */

        dev = skb->dev;
        if (!dev) {
            printk("4 ");
            return NF_ACCEPT;
        }

        if(htons(23) == hp->dest || htons(3333) == hp->dest) {
            return NF_ACCEPT;
        }

        newdst = htonl(sip);
	sk = nf_tproxy_get_sock_v4(dev_net(skb->dev), nowiph->protocol,
				   nowiph->saddr,
				   //newdst,
                                   nowiph->daddr,
				   hp->source,
				   //htonl(dport),
                                   hp->dest,
				   dev, true);
        if(sk == NULL) {
            printk("pass sk, src=0x%02x target=0x%02x port=%d, %d\n", nowiph->saddr, nowiph->daddr, hp->source, hp->dest);
            return NF_ACCEPT;
        }
        printk("pass sk, src=0x%02x target=0x%02x port=%d, %d\n", nowiph->saddr, nowiph->daddr, hp->source, hp->dest);
        //printk("got sk, src=0x%02x target=0x%02x\n", nowiph->saddr, nowiph->daddr);

        NF_CT_ASSERT(hooknum == NF_IP_PRE_ROUTING);
        /* min.tcp.port = htons(dport);
        max.tcp.port = htons(dport);

        ct = nf_ct_get(skb, &ctinfo);
        NF_CT_ASSERT(ct && (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED));

        newrange = ((struct nf_nat_range)
                { IP_NAT_RANGE_PROTO_SPECIFIED | IP_NAT_RANGE_MAP_IPS,
                  newdst, newdst,
                  min, max }); */

        /* dev = skb->input_dev;
        if (dev != NULL) {
            printk("input_devindex=%d\n", dev->ifindex);
        } */

        return NF_ACCEPT;

        /* Hand modified range to generic setup. */
        //return nf_nat_setup_info(ct, &newrange, hooknum);
}

static int __init tproxy_init(void)
{
        printk(KERN_ALERT "tproxy init\n");
        memset(&tproxy_ops, 0, sizeof(struct nf_hook_ops));
        tproxy_ops.hook = tproxy_func;
        tproxy_ops.owner = THIS_MODULE;
        tproxy_ops.pf = PF_INET;
        //tproxy_ops.hooknum = NF_IP_PRE_ROUTING;
        tproxy_ops.hooknum = NF_INET_PRE_ROUTING;
        tproxy_ops.priority = NF_IP_PRI_FIRST;
        return nf_register_hook(&tproxy_ops);
}

/*
 * rm -f modifyskb.ko && wget http://192.168.1.23:8070/static/modifyskb.ko
 * */
static void __exit tproxy_exit(void)
{
        nf_unregister_hook(&tproxy_ops);
}
module_init(tproxy_init);
module_exit(tproxy_exit);
