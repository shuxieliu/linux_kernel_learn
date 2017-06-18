//#include "library.h"
//
//#include <stdio.h>
//
//void hello(void) {
//    printf("Hello, World!\n");
//}
//

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <net/tcp.h>
#include <net/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <net/netfilter/nf_conntrack.h>
#include "hook.h"

static struct nf_hook_ops nfho;
struct sock *nl_sk = NULL;
EXPORT_SYMBOL_GPL(nl_sk);

static unsigned int icmp_off = 0;
static unsigned int drop_ip = 0;


//netlink hook func in kernel version < 2.6
//void input (struct sock* sk, int len)
//{
//    struct sk_buff* skb = NULL;
//    struct nlmsghdr* nlh = NULL;
//
//    printk("net_link: data is ready to read.\n");
//    while((skb = skb_dequeue(&sk->sk_receive_queue))!=NULL)
//    {
//        nlh = (struct nlmsghdr*)skb->data;
//        icmp_off = ((OWN *)NLMSG_DATA(nlh))->icmp_off;
//        drop_ip = ((OWN *)NLMSG_DATA(nlh))->drop_ip;
//    }
//
//    return;
//}

static struct sock *netlinkfd = NULL;

int send_msg(int8_t *pbuf, uint16_t len, int nl_proto_type)
{
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;

    int ret;

    nl_skb = nlmsg_new(len, GFP_ATOMIC);
    if(!nl_skb)
    {
        printk("netlink_alloc_skb error\n");
        return -1;
    }

    nlh = nlmsg_put(nl_skb, 0, 0, nl_proto_type, len, 0);
    if(nlh == NULL)
    {
        printk("nlmsg_put() error\n");
        nlmsg_free(nl_skb);
        return -1;
    }
    memcpy(nlmsg_data(nlh), pbuf, len);

    ret = netlink_unicast(netlinkfd, nl_skb, USER_PORT, MSG_DONTWAIT);

    return ret;
}

static void recv_cb(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    void *data = NULL;

    printk("skb->len:%u\n", skb->len);
    if(skb->len >= nlmsg_total_size(0))
    {
        nlh = nlmsg_hdr(skb);
        data = NLMSG_DATA(nlh);
        if(data)
        {

            //printk("kernel receive data: %s\n", (int8_t *)data);

            icmp_off = ((OWN *)data)->icmp_off;
            drop_ip = ((OWN *)data)->drop_ip;
            printk("kernel receive data: icmp_off=%u, drop_ip=%u\n", icmp_off, drop_ip);

            send_msg(data, nlmsg_len(nlh), NETLINK_TEST);
        }
    }
}

struct netlink_kernel_cfg cfg =
        {
                .input = recv_cb,
        };


static int test_netlink(void) {
    //nl_sk = netlink_kernel_create(NETLINK_TEST, 0, input, THIS_MODULE);
    netlinkfd = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);

    if (!netlinkfd) {
        printk("net_link: Cannot create netlink socket.\n");
        return -EIO;
    }
    printk("net_link: create socket ok.\n");
    return 0;
}

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

// old kernel version < 2.6
//unsigned int hook_func(unsigned int hooknum,
//                       struct sk_buff **skb,
//                       const struct net_device *in,
//                       const struct net_device *out,
//                       int (*okfn)(struct sk_buff *))
unsigned int hook_func(void *priv,
                       struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
    struct sk_buff *sb = skb;
    struct iphdr     *iph ;

    iph = ip_hdr(sb);
    switch(iph->protocol)
    {
        case IPPROTO_ICMP:{
            struct icmphdr _icmph;
            struct icmphdr* ich;

            ich = skb_header_pointer(sb, iph->ihl*4, sizeof(_icmph), &_icmph);
            printk("icmp type %u\n", ich->type);
            if(icmp_off == 1)
            {
                printk("now we drop icmp from %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
                return NF_DROP;
            }
            break;
        }
        case IPPROTO_TCP:{
            struct tcphdr* th = NULL;
            struct tcphdr _tcph;
            th = skb_header_pointer(sb, iph->ihl*4, sizeof(_tcph), &_tcph);
            if(th == NULL)
            {
                printk("get tcp header error\n");
                return NF_DROP;
            }
            //unsigned int sip = ntohs(th->source);
            printk("saddr:%d.%d.%d.%d,sport:%u\n", NIPQUAD(iph->saddr),ntohs(th->source));
            printk("daddr:%d.%d.%d.%d,dport:%u\n", NIPQUAD(iph->daddr),ntohs(th->dest));
            if(iph->saddr ==drop_ip)
            {
                printk("now we drop tcp from %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
                return NF_DROP;
            }

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
            enum ip_conntrack_info ctinfo;
            struct nf_conn *ct;
            const struct ip_ct_tcp *state;

	        ct = nf_ct_get(skb, &ctinfo);
	        state = &ct->proto.tcp;
            printk("conntrack state info: %d, tcp last seq:%d.\n", ctinfo, state->last_seq);
#endif

            break;
        }
        default:
            break;
    }
    return NF_ACCEPT;
}

static int __init hook_init(void)
{
    printk("insmod hook test!\n");
    test_netlink();
    nfho.hook      = hook_func;
    nfho.hooknum   = 1;//NF_IP_LOCAL_IN;
    nfho.pf        = PF_INET;
    nfho.priority  = NF_IP_PRI_FIRST;

    nf_register_hook(&nfho);

    return 0;
}

static void __exit hook_exit(void)
{
    printk("rmmod hook test!\n");
    nf_unregister_hook(&nfho);
    if (nl_sk != NULL){
        sock_release(nl_sk->sk_socket);
    }
}

module_init(hook_init);
module_exit(hook_exit);