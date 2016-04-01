#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/route.h>
#include <net/icmp.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/nf_tproxy_core.h>

/*
 * http://nano-chicken.blogspot.jp/2010/03/linux-modules12-netfilter.html
 * TODO conntrack http://www.dedecms.com/knowledge/servers/linux-bsd/2012/1217/17746.html
 * TODO contrack http://blog.csdn.net/lickylin/article/details/35828205
 * */

/*

netlink: http://stackoverflow.com/questions/3299386/how-to-use-netlink-socket-to-communicate-with-a-kernel-module
getorigdst: nf_conntrack_l3proto_ipv4.c

#!/bin/sh
N=modifyudp
rm -f ${N}.ko && wget http://192.168.1.23:8070/static/${N}.ko
#rmmod ${N}.ko
#insmod ${N}.ko

./udp_arm 42.51.158.136:8888 192.168.1.1:9999
*/

MODULE_LICENSE("GPL");

//uint8_t DMAC[ETH_ALEN] = {0x50, 0xE5, 0x49, 0xEC, 0x46, 0x8B};
uint8_t DMAC[ETH_ALEN] = {0x0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

inline void dumpIpHdr(const char *fn, const struct sk_buff *skb)
{
    const struct iphdr *ip = ip_hdr(skb);

    if(ip->protocol != IPPROTO_UDP) {
        return;
    }

    printk("%s, saddr:%pI4, daddr:%pI4\n", fn, &ip->saddr, &ip->daddr);
}

static unsigned int prerouting(unsigned int hook, struct sk_buff *__skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff*))
{
    struct sk_buff *skb;
    struct net_device *dev = NULL;
    struct iphdr *iph;
    struct udphdr *udph;
    struct ethhdr* ethh;
    int total_len, iph_len, ret;
    struct sock *sk;
    uint32_t olddip;
    uint16_t olddport;

    uint16_t dport = 8888;
    uint32_t sip = in_aton("192.168.1.23");
    //uint32_t dip = in_aton("42.51.158.136");
    uint32_t dip = in_aton("192.168.1.1");

    skb = __skb;
    if (NULL == skb) {
        return NF_ACCEPT;
    }

    dumpIpHdr(__FUNCTION__, skb);

    iph = ip_hdr(skb);
    if(NULL == iph) {
        return NF_ACCEPT;
    }

    total_len = ntohs(iph->tot_len);
    if(iph->saddr == sip) {
        iph_len = ip_hdrlen(skb);
        skb_pull(skb, iph_len);
        skb_reset_transport_header(skb);
        if(IPPROTO_UDP == iph->protocol) {
            udph = udp_hdr(skb);
            olddip = iph->daddr;
            olddport = udph->dest;
            iph->daddr = dip;
            udph->dest = htons(dport);

            udph->check = 0;
            skb->csum = csum_partial((uint8_t*)udph
                    , total_len - iph_len
                    , 0);
            udph->check = csum_tcpudp_magic(iph->saddr
                    , iph->daddr
                    , total_len - iph_len
                    , iph->protocol
                    , skb->csum);

            iph->check = 0;
            iph->check = ip_fast_csum(iph, iph->ihl);

            skb->ip_summed = CHECKSUM_NONE;
            skb->pkt_type = PACKET_OTHERHOST;
            //dev = dev_get_by_name(&init_net, "br0");
            //skb->dev = dev;
            skb_push(skb, iph_len);
            ethh = (struct ethhdr*)skb_push(skb, 14);
            memcpy(ethh->h_dest, DMAC, ETH_ALEN);

            sk = nf_tproxy_get_sock_v4(dev_net(skb->dev)
                    , iph->protocol
                    , iph->saddr
                    , olddip
                    , udph->source
                    , olddport
                    , skb->dev
                    , true);
            if(sk != NULL) {
                printk("old found sk\n");
            }

            sk = nf_tproxy_get_sock_v4(dev_net(skb->dev)
                    , iph->protocol
                    , iph->saddr
                    , iph->daddr
                    , udph->source
                    , udph->dest
                    , skb->dev
                    , true);
            if(sk != NULL) {
                printk("new found sk\n");
            }

            if (sk && nf_tproxy_assign_sock(skb, sk)) {
                    /* This should be in a separate target, but we don't do multiple
                       targets on the same rule yet */
                    skb->mark = (skb->mark & ~1) ^ 1;

                    /* reset to layer ip*/
                    skb_pull(skb, 14);
                    skb_reset_transport_header(skb);

                    printk("redirecting: proto %u %08x:%u -> %08x:%u, mark: %x\n",
                             iph->protocol, ntohl(iph->daddr), ntohs(udph->dest),
                             dip, dport, skb->mark);
                    return NF_ACCEPT;
            }

            ret = dev_queue_xmit(skb);
            if (ret < 0) {
                printk("dev_queue_xmit() error\n");
                goto out;
            }
            printk("stolen\n");

            return NF_STOLEN;
        }

        skb_push(skb, iph_len);
        skb_reset_transport_header(skb);

    }

    return NF_ACCEPT;

out:
    if(NULL != dev) {
        dev_put(dev);
    }
    return NF_DROP;
}

#if 0
static unsigned int prerouting(unsigned int hook, struct sk_buff *__skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff*))
{
    struct sk_buff *skb;
    struct net_device *dev = NULL;
    struct iphdr *iph;
    struct udphdr *udph;
    struct ethhdr* ethh;
    int total_len, iph_len, ret;

    uint16_t dport = 3333;
    uint32_t dip = in_aton("192.168.1.23");
    uint32_t sip = in_aton("42.51.158.136");

    skb = __skb;
    if (NULL == skb) {
        return NF_ACCEPT;
    }

    dumpIpHdr(__FUNCTION__, skb);

    iph = ip_hdr(skb);
    if(NULL == iph) {
        return NF_ACCEPT;
    }

    total_len = ntohs(iph->tot_len);
    if(iph->saddr == sip) {
        iph_len = ip_hdrlen(skb);
        skb_pull(skb, iph_len);
        skb_reset_transport_header(skb);
        if(IPPROTO_UDP == iph->protocol) {
            udph = udp_hdr(skb);
            iph->daddr = dip;
            udph->dest = htons(dport);

            udph->check = 0;
            skb->csum = csum_partial((uint8_t*)udph
                    , total_len - iph_len
                    , 0);
            udph->check = csum_tcpudp_magic(iph->saddr
                    , iph->daddr
                    , total_len - iph_len
                    , iph->protocol
                    , skb->csum);

            iph->check = 0;
            iph->check = ip_fast_csum(iph, iph->ihl);

            skb->ip_summed = CHECKSUM_NONE;
            skb->pkt_type = PACKET_OTHERHOST;
            dev = dev_get_by_name(&init_net, "br0");
            skb->dev = dev;
            skb_push(skb, iph_len);
            ethh = (struct ethhdr*)skb_push(skb, 14);
            memcpy(ethh->h_dest, DMAC, ETH_ALEN);
            ret = dev_queue_xmit(skb);
            if (ret < 0) {
                printk("dev_queue_xmit() error\n");
                goto out;
            }

            return NF_STOLEN;
        }

        skb_push(skb, iph_len);
        skb_reset_transport_header(skb);

    }

    return NF_ACCEPT;

out:
    if(NULL != dev) {
        dev_put(dev);
    }
    return NF_DROP;
}
#endif

static unsigned int
localin(unsigned int hook, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff*))
{
    dumpIpHdr(__FUNCTION__, skb);
    return NF_ACCEPT;
}

static unsigned int
localout(unsigned int hook, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff*))
{
    dumpIpHdr(__FUNCTION__, skb);
    return NF_ACCEPT;
}

static unsigned int
postrouting(unsigned int hook, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff*))
{
    dumpIpHdr(__FUNCTION__, skb);
    return NF_ACCEPT;
}

static unsigned int
fwding(unsigned int hook, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff*))
{
    dumpIpHdr(__FUNCTION__, skb);
    return NF_ACCEPT;
}

static struct nf_hook_ops brook_ops[] __read_mostly = {
    {
        .hook = prerouting,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_RAW,
        .owner = THIS_MODULE,
    }, {
        .hook = localin,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_RAW,
        .owner = THIS_MODULE,
    }, {
        .hook = fwding,
        .pf = PF_INET,
        .hooknum = NF_INET_FORWARD,
        .priority = NF_IP_PRI_RAW,
        .owner = THIS_MODULE,
    }, {
        .hook = localout,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_RAW,
        .owner = THIS_MODULE,
    }, {
        .hook = postrouting,
        .pf = PF_INET,
        .hooknum = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_RAW,
        .owner = THIS_MODULE,
    },
};

static int __init init_modules(void)
{
    printk(KERN_ALERT "modifyudp init\n");

    nf_defrag_ipv4_enable();
    if (nf_register_hooks(brook_ops, ARRAY_SIZE(brook_ops)) < 0) {
        printk("nf_register_hook failed\n");
    }
    return 0;
}

static void __exit exit_modules(void)
{
    nf_unregister_hooks(brook_ops, ARRAY_SIZE(brook_ops));
}

module_init(init_modules);
module_exit(exit_modules);
