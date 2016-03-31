#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/dst.h>
#include <net/netfilter/nf_conntrack_acct.h>


MODULE_AUTHOR("xtt");
MODULE_DESCRIPTION("gll");
MODULE_LICENSE("GPL");
MODULE_ALIAS("XTT and GLL");

struct nf_conn_priv {
        struct nf_conn_counter ncc[IP_CT_DIR_MAX];
        struct dst_entry *dst[IP_CT_DIR_MAX];
};

static unsigned int ipv4_conntrack_getdst (unsigned int hooknum,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int (*okfn)(struct sk_buff *))
{
        struct nf_conn *ct;
        enum ip_conntrack_info ctinfo;
        struct nf_conn_counter *acct;
        struct nf_conn_priv *dst_info;
        ct = nf_ct_get(skb, &ctinfo);
        if (!ct || ct == &nf_conntrack_untracked)
                return NF_ACCEPT;
        acct = nf_conn_acct_find(ct);
        if (acct) {
                int dir = CTINFO2DIR(ctinfo);
                dst_info = (struct nf_conn_priv *)acct;
                if (dst_info->dst[dir] == NULL) {
                        dst_hold(skb_dst(skb));
                        dst_info->dst[dir] = skb_dst(skb);
                }
        }
        return NF_ACCEPT;
}

static unsigned int ipv4_conntrack_setdst (unsigned int hooknum,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int (*okfn)(struct sk_buff *))
{
        struct nf_conn *ct;
        enum ip_conntrack_info ctinfo;
        struct nf_conn_counter *acct;
        struct nf_conn_priv *dst_info;
        ct = nf_ct_get(skb, &ctinfo);
        if (!ct || ct == &nf_conntrack_untracked)
                return NF_ACCEPT;
        acct = nf_conn_acct_find(ct);
        if (acct) {
                int dir = CTINFO2DIR(ctinfo);
                dst_info = (struct nf_conn_priv *)acct;
                if (dst_info->dst[dir] != NULL) {
                       // If this is SKB DST, then the ip_rcv_finish will not go the route table lookup
                        skb_dst_set(skb, dst_info->dst[dir]);
                }
        }
        return NF_ACCEPT;
}
static struct nf_hook_ops ipv4_conn_dst_info[] __read_mostly = {
        {
                .hook           = ipv4_conntrack_getdst,
                .owner          = THIS_MODULE,
                .pf             = NFPROTO_IPV4,
                .hooknum        = NF_INET_POST_ROUTING,
                .priority       = NF_IP_PRI_CONNTRACK + 1,
        },
        {
                .hook           = ipv4_conntrack_getdst,
                .owner          = THIS_MODULE,
                .pf             = NFPROTO_IPV4,
                .hooknum        = NF_INET_LOCAL_IN,
                .priority       = NF_IP_PRI_CONNTRACK + 1,
        },
        {
                .hook           = ipv4_conntrack_setdst,
                .owner          = THIS_MODULE,
                .pf             = NFPROTO_IPV4,
                .hooknum        = NF_INET_PRE_ROUTING,
                .priority       = NF_IP_PRI_CONNTRACK + 1,
        },
};

static int __init test_info_init(void)
{
        int err;
        err = nf_register_hooks(ipv4_conn_dst_info, ARRAY_SIZE(ipv4_conn_dst_info));
        if (err) {
                return err;
        }
        return err;
}

static void __exit test_info_exit(void)
{
        nf_unregister_hooks(ipv4_conn_dst_info, ARRAY_SIZE(ipv4_conn_dst_info));
}

module_init(test_info_init);
module_exit(test_info_exit);
