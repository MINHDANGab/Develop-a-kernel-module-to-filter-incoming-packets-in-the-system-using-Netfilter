// fw_netlink_kmod.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/byteorder/generic.h> // ntohl

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mdang");
MODULE_DESCRIPTION("Firewall: multi-IP block + multi-IP rate-limit via Netlink (list_head)");
MODULE_VERSION("2.0");

#define NETLINK_FW NETLINK_USERSOCK


enum fw_cmd {
    FW_CMD_BLOCK_ADD = 1,
    FW_CMD_BLOCK_DEL,
    FW_CMD_RL_ADD,         
    FW_CMD_RL_DEL,
    FW_CMD_SHOW,
};

struct fw_msg {
    __u32 cmd;
    __u32 ipv4_be;        
    __u32 bytes_per_sec;  
};


struct blocked_ip {
    __be32 ip;
    struct list_head list;
};


struct rl_ip {
    __be32 ip;
    unsigned long bytes_per_sec;

    unsigned long window_start; 
    unsigned long bytes_count;  

    struct list_head list;
};

static LIST_HEAD(blocked_ip_list);
static LIST_HEAD(rl_ip_list);


static DEFINE_SPINLOCK(rule_lock);


static const unsigned long rl_window = HZ;


static struct sock *nl_sk = NULL;


static void fmt_ipv4(char *out, size_t outsz, __be32 ip_be)
{
    u32 ip = ntohl(ip_be);
    snprintf(out, outsz, "%u.%u.%u.%u",
             (ip >> 24) & 0xff,
             (ip >> 16) & 0xff,
             (ip >> 8)  & 0xff,
             ip & 0xff);
}


static void nl_send_reply(u32 pid, const char *text)
{
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    int len = strlen(text) + 1;

    skb_out = nlmsg_new(len, GFP_KERNEL);
    if (!skb_out) return;

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, len, 0);
    memcpy(nlmsg_data(nlh), text, len);

    nlmsg_unicast(nl_sk, skb_out, pid);
}

/* ===== Netfilter hook =====
   - Block: nếu IP nằm trong blocked list -> DROP
   - Rate-limit: nếu IP nằm trong rl list -> kiểm tra bytes/s -> DROP nếu vượt
*/
static unsigned int fw_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    unsigned long flags;
    struct blocked_ip *b;
    struct rl_ip *r;
    unsigned long now;

    if (!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    spin_lock_irqsave(&rule_lock, flags);

    /* 1) Block list */
    list_for_each_entry(b, &blocked_ip_list, list) {
        if (iph->saddr == b->ip) {
            spin_unlock_irqrestore(&rule_lock, flags);
            pr_info("fw: DROP (blocked) from %pI4\n", &iph->saddr);
            return NF_DROP;
        }
    }

    /* 2) Rate-limit list */
    now = jiffies;
    list_for_each_entry(r, &rl_ip_list, list) {
        if (iph->saddr == r->ip) {
            /* reset window if needed */
            if (time_after(now, r->window_start + rl_window)) {
                r->window_start = now;
                r->bytes_count = 0;
            }

            r->bytes_count += skb->len;

            if (r->bytes_count > r->bytes_per_sec) {
                spin_unlock_irqrestore(&rule_lock, flags);
                pr_info("fw: DROP (ratelimit %lu B/s) from %pI4\n",
                        r->bytes_per_sec, &iph->saddr);
                return NF_DROP;
            }
            break; 
        }
    }

    spin_unlock_irqrestore(&rule_lock, flags);
    return NF_ACCEPT;
}

static struct nf_hook_ops fw_nfho = {
    .hook     = fw_hook,
    .pf       = PF_INET,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};


static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct fw_msg *m;
    u32 pid;
    char reply[512];
    char ipbuf[32];
    unsigned long flags;

    struct blocked_ip *b, *btmp;
    struct rl_ip *r, *rtmp;

    if (!skb) return;

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid;

    if (nlmsg_len(nlh) < sizeof(*m)) {
        nl_send_reply(pid, "ERR: message too short");
        return;
    }

    m = (struct fw_msg *)nlmsg_data(nlh);

    spin_lock_irqsave(&rule_lock, flags);

    switch (m->cmd) {

    case FW_CMD_BLOCK_ADD:
        list_for_each_entry(b, &blocked_ip_list, list) {
            if (b->ip == (__be32)m->ipv4_be) {
                fmt_ipv4(ipbuf, sizeof(ipbuf), (__be32)m->ipv4_be);
                snprintf(reply, sizeof(reply), "ERR: already blocked %s", ipbuf);
                spin_unlock_irqrestore(&rule_lock, flags);
                nl_send_reply(pid, reply);
                return;
            }
        }
        b = kmalloc(sizeof(*b), GFP_KERNEL);
        if (!b) {
            spin_unlock_irqrestore(&rule_lock, flags);
            nl_send_reply(pid, "ERR: no memory");
            return;
        }
        b->ip = (__be32)m->ipv4_be;
        list_add(&b->list, &blocked_ip_list);

        fmt_ipv4(ipbuf, sizeof(ipbuf), b->ip);
        snprintf(reply, sizeof(reply), "OK: blocked %s", ipbuf);
        spin_unlock_irqrestore(&rule_lock, flags);
        nl_send_reply(pid, reply);
        return;

    case FW_CMD_BLOCK_DEL:
        list_for_each_entry_safe(b, btmp, &blocked_ip_list, list) {
            if (b->ip == (__be32)m->ipv4_be) {
                list_del(&b->list);
                kfree(b);
                fmt_ipv4(ipbuf, sizeof(ipbuf), (__be32)m->ipv4_be);
                snprintf(reply, sizeof(reply), "OK: unblocked %s", ipbuf);
                spin_unlock_irqrestore(&rule_lock, flags);
                nl_send_reply(pid, reply);
                return;
            }
        }
        fmt_ipv4(ipbuf, sizeof(ipbuf), (__be32)m->ipv4_be);
        snprintf(reply, sizeof(reply), "ERR: not found %s", ipbuf);
        spin_unlock_irqrestore(&rule_lock, flags);
        nl_send_reply(pid, reply);
        return;

    case FW_CMD_RL_ADD:
        /* nếu đã tồn tại thì update rate */
        list_for_each_entry(r, &rl_ip_list, list) {
            if (r->ip == (__be32)m->ipv4_be) {
                r->bytes_per_sec = (unsigned long)m->bytes_per_sec;
                r->window_start = jiffies;
                r->bytes_count = 0;

                fmt_ipv4(ipbuf, sizeof(ipbuf), r->ip);
                snprintf(reply, sizeof(reply), "OK: ratelimit update %s %lu B/s",
                         ipbuf, r->bytes_per_sec);
                spin_unlock_irqrestore(&rule_lock, flags);
                nl_send_reply(pid, reply);
                return;
            }
        }

        r = kmalloc(sizeof(*r), GFP_KERNEL);
        if (!r) {
            spin_unlock_irqrestore(&rule_lock, flags);
            nl_send_reply(pid, "ERR: no memory");
            return;
        }
        r->ip = (__be32)m->ipv4_be;
        r->bytes_per_sec = (unsigned long)m->bytes_per_sec;
        r->window_start = jiffies;
        r->bytes_count = 0;
        list_add(&r->list, &rl_ip_list);

        fmt_ipv4(ipbuf, sizeof(ipbuf), r->ip);
        snprintf(reply, sizeof(reply), "OK: ratelimit add %s %lu B/s",
                 ipbuf, r->bytes_per_sec);
        spin_unlock_irqrestore(&rule_lock, flags);
        nl_send_reply(pid, reply);
        return;

    case FW_CMD_RL_DEL:
        list_for_each_entry_safe(r, rtmp, &rl_ip_list, list) {
            if (r->ip == (__be32)m->ipv4_be) {
                list_del(&r->list);
                kfree(r);
                fmt_ipv4(ipbuf, sizeof(ipbuf), (__be32)m->ipv4_be);
                snprintf(reply, sizeof(reply), "OK: ratelimit del %s", ipbuf);
                spin_unlock_irqrestore(&rule_lock, flags);
                nl_send_reply(pid, reply);
                return;
            }
        }
        fmt_ipv4(ipbuf, sizeof(ipbuf), (__be32)m->ipv4_be);
        snprintf(reply, sizeof(reply), "ERR: ratelimit ip not found %s", ipbuf);
        spin_unlock_irqrestore(&rule_lock, flags);
        nl_send_reply(pid, reply);
        return;

    case FW_CMD_SHOW: {
        int n = 0;
        char t[32];

        n += snprintf(reply + n, sizeof(reply) - n, "BLOCKED:\n");
        list_for_each_entry(b, &blocked_ip_list, list) {
            fmt_ipv4(t, sizeof(t), b->ip);
            n += snprintf(reply + n, sizeof(reply) - n, " - %s\n", t);
            if (n > (int)sizeof(reply) - 64) break;
        }

        n += snprintf(reply + n, sizeof(reply) - n, "RATELIMIT:\n");
        list_for_each_entry(r, &rl_ip_list, list) {
            fmt_ipv4(t, sizeof(t), r->ip);
            n += snprintf(reply + n, sizeof(reply) - n, " - %s : %lu B/s\n", t, r->bytes_per_sec);
            if (n > (int)sizeof(reply) - 64) break;
        }

        spin_unlock_irqrestore(&rule_lock, flags);
        nl_send_reply(pid, reply);
        return;
    }

    default:
        spin_unlock_irqrestore(&rule_lock, flags);
        nl_send_reply(pid, "ERR: unknown cmd");
        return;
    }
}

static int __init fw_init(void)
{
    int ret;
    struct netlink_kernel_cfg cfg = { .input = nl_recv_msg };

    ret = nf_register_net_hook(&init_net, &fw_nfho);
    if (ret) {
        pr_err("fw: nf_register_net_hook failed: %d\n", ret);
        return ret;
    }

    nl_sk = netlink_kernel_create(&init_net, NETLINK_FW, &cfg);
    if (!nl_sk) {
        nf_unregister_net_hook(&init_net, &fw_nfho);
        pr_err("fw: netlink_kernel_create failed\n");
        return -ENOMEM;
    }

    pr_info("fw: loaded (multi block + multi ratelimit)\n");
    return 0;
}

static void __exit fw_exit(void)
{
    struct blocked_ip *b, *btmp;
    struct rl_ip *r, *rtmp;
    unsigned long flags;

    spin_lock_irqsave(&rule_lock, flags);

    list_for_each_entry_safe(b, btmp, &blocked_ip_list, list) {
        list_del(&b->list);
        kfree(b);
    }
    list_for_each_entry_safe(r, rtmp, &rl_ip_list, list) {
        list_del(&r->list);
        kfree(r);
    }

    spin_unlock_irqrestore(&rule_lock, flags);

    if (nl_sk) netlink_kernel_release(nl_sk);
    nf_unregister_net_hook(&init_net, &fw_nfho);
    pr_info("fw: unloaded\n");
}

module_init(fw_init);
module_exit(fw_exit);
