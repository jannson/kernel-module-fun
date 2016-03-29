/* Redirect.  Simple mapping which alters dst to a local IP address. */
/* (C) 1999-2001 Paul `Rusty' Russell
* (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation.
http://bbs.chinaunix.net/forum.php?mod=viewthread&action=printable&tid=1976797
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netfilter Core Team <coreteam@netfilter.org>");
MODULE_DESCRIPTION("iptables REDIRECT target module");

//char *dst="192.168.6.1";
//__be16 dport=80;
//module_param(dst,charp,0644);
//module_param(dport,ushort,0644);
static struct nf_hook_ops redirectport;
unsigned int redirectport_func(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int(*okfn)(struct sk_buff*))
{
        struct nf_conn *ct;
        enum ip_conntrack_info ctinfo;
        __be32 newdst;
        struct nf_nat_range newrange;
        union nf_conntrack_man_proto min, max;
        struct iphdr *nowiph;
        struct tcphdr *nowtcp;
        uint16_t dport = 3333;
        uint32_t sip = 0xc0a80101;
        uint32_t taddr;

        nowiph = (struct iphdr *)skb_network_header(skb);
        if(nowiph->protocol != IPPROTO_TCP) {
            return NF_ACCEPT;
        }

        taddr = ntohl(nowiph->saddr);
        if ( ((taddr & 0xFFFFFF00) != (sip & 0xFFFFFF00)) || (taddr == sip) ) {
            //ignore local ip or not subnet ip
            return NF_ACCEPT;
        }

        nowtcp = (struct tcphdr *)(skb->data + (nowiph->ihl*4));
        if(ntohs(nowtcp->dest) != 80) {
            return NF_ACCEPT;
        }

        newdst = htonl(sip);
        min.tcp.port = htons(dport);
        max.tcp.port = htons(dport);
        NF_CT_ASSERT(hooknum == NF_IP_PRE_ROUTING);

        ct = nf_ct_get(skb, &ctinfo);
        NF_CT_ASSERT(ct && (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED));

        /* Make range. */
        newrange = ((struct nf_nat_range)
                { IP_NAT_RANGE_PROTO_SPECIFIED | IP_NAT_RANGE_MAP_IPS,
                  newdst, newdst,
                  min, max });

        printk("src=0x%02x target=0x%02x\n", nowiph->saddr, nowiph->daddr);
        return NF_ACCEPT;

        /* Hand modified range to generic setup. */
        //return nf_nat_setup_info(ct, &newrange, hooknum);
}

static int __init redirectport_init(void)
{
        printk(KERN_ALERT "redirectport init\n");
        memset(&redirectport, 0, sizeof(struct nf_hook_ops));
        redirectport.hook = redirectport_func;
        redirectport.owner = THIS_MODULE;
        redirectport.pf = PF_INET;
        redirectport.hooknum = NF_IP_PRE_ROUTING;
        redirectport.priority = INT_MIN;
        return nf_register_hook(&redirectport);
}

static void __exit redirectport_exit(void)
{
        nf_unregister_hook(&redirectport);
}
module_init(redirectport_init);
module_exit(redirectport_exit);
