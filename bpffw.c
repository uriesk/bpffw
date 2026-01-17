#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define BPF_PRINTK(fmt, ...) \
({ \
  char ____fmt[] = fmt; \
  bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

/*
 * rate limit structs
 */

struct rate_limit_entry {
  __u64 last_update;
  __u8 blocked;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 16384);
  __type(key, __u32);  // v4 address
  __type(value, struct rate_limit_entry);
} rate_limit_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 16384);
  __type(key, __u64);  // first 64 bit of v6 address
  __type(value, struct rate_limit_entry);
} rate_limit_v6 SEC(".maps");

/*
 * tick rate limiter, return whether or not blocked
 */
static __always_inline int tick_rate_limit(struct rate_limit_entry *rate_limiter, __u8 pps) {
  if (!rate_limiter) {
    return 0;
  }

  __u64 current_time = bpf_ktime_get_ns();

  if (rate_limiter->blocked) {
    if (rate_limiter->last_update < current_time) {
      rate_limiter->last_update = current_time;
      rate_limiter->blocked = 0;
      return 0;
    }
    return 1;
  }

  if (rate_limiter->last_update < current_time) {
    rate_limiter->last_update = current_time + 1000000000 / pps;
    return 0;
  }

  // allow 200 packets per second
  rate_limiter->last_update += 1000000000 / pps;

  if (rate_limiter->last_update > current_time + 1000000000) {
    // block for an hour after this packet
    rate_limiter->last_update = current_time + 1000000000ULL * 3600;
    BPF_PRINTK("ratelimit triggered");
    rate_limiter->blocked = 1;
    return 2;
  }
  return 0;
}

/*
 * Check if TCP packet is allowed
 * Note: We only filer SYN packets here, ESTABLISHED and RELATED needs to be
 * additionally filtered with iptables
 */
static __always_inline int is_tcp_allowed(struct tcphdr *tcph, struct rate_limit_entry *rate_limiter) {
  // Only act on SYN packets
  if (!(tcph->syn && !tcph->ack)) {
    return 1;
  }

  if (tick_rate_limit(rate_limiter, 150)) {
    return 0;
  }

  __u16 dest_port = bpf_ntohs(tcph->dest);

  switch (dest_port) {
    case 443: // https
    case 80: // http
    case 25:
    case 993:
    case 587:
    case 50000: // ssh
    case 25565: // Minecraft
    case 3478: // STUN
    case 3479: // STUN
      return 1;
    default:
      return 0;
  }
}

/*
 * Check if UDP packet is allowed
 */
static __always_inline int is_udp_allowed(struct udphdr *udph, struct rate_limit_entry *rate_limiter) {
  if (tick_rate_limit(rate_limiter, 200)) {
    return 0;
  }

  __u16 dest_port = bpf_ntohs(udph->dest);

  switch (dest_port) {
    case 25565: // Minecraft
    case 3478: // STUN
    case 3479: // STUN
      return 1;
  }

  if (dest_port >= 65400 && dest_port <= 65535) {
    return 1;
  }

  /**
   * we do not have access to conntrack and do not know which incomming package
   * is part of an outbound established connection, so we just ratelimit known
   * services we need hard
   */

  __u16 src_port = bpf_ntohs(udph->source);

  if (
    // DNS responses
    (src_port == 53 && dest_port >= 1024)
    // DHCP responses
    || (src_port == 67 && dest_port == 68)
    // NTP responses
    || (src_port == 123 && dest_port == 123)
  ) {
    return 1;
  }

  return 0;
}


SEC("prog")
int xdp_firewall_filter(struct xdp_md *ctx) {
  // allow all otbound
  if (ctx->rx_queue_index == 0xFFFFFFFF || ctx->ingress_ifindex == 0) {
    return XDP_PASS;
  }

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  // bound check
  if ((void *)eth + sizeof(*eth) > data_end) {
    return XDP_PASS;
  }

  // IPv4 handling
  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *iph = data + sizeof(*eth);
    // bound check
    if ((void *)iph + sizeof(*iph) > data_end) {
      return XDP_PASS;
    }

    __u32 addr = bpf_ntohl(iph->saddr);
    struct rate_limit_entry *rate_limiter = bpf_map_lookup_elem(&rate_limit_v4, &addr);
    if (!rate_limiter) {
      struct rate_limit_entry new_entry;
      __builtin_memset(&new_entry, 0, sizeof(new_entry));
      bpf_map_update_elem(&rate_limit_v4, &addr, &new_entry, BPF_ANY);
      rate_limiter = bpf_map_lookup_elem(&rate_limit_v4, &addr);
    }

    // TCP
    if (iph->protocol == IPPROTO_TCP) {
      // fragments in tcp don't need attention
      if (iph->frag_off & bpf_htons(0x1FFF)) {
        return XDP_PASS;
      }

      struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
      // bound check
      if ((void *)tcph + sizeof(*tcph) > data_end) {
        return XDP_PASS;
      }

      if (is_tcp_allowed(tcph, rate_limiter)) {
        return XDP_PASS;
      }
      return XDP_DROP;
    }
    // UDP
    else if (iph->protocol == IPPROTO_UDP) {
      // fragments in udp need ratelimit
      if (iph->frag_off & bpf_htons(0x1FFF)) {
        if (tick_rate_limit(rate_limiter, 50)) {
          return XDP_DROP;
        }
        return XDP_PASS;
      }

      struct udphdr *udph = (void *)iph + (iph->ihl * 4);
      // bound check
      if ((void *)udph + sizeof(*udph) > data_end) {
        return XDP_PASS;
      }

      if (is_udp_allowed(udph, rate_limiter)) {
        return XDP_PASS;
      }
      return XDP_DROP;
    }
  }
  
  // IPv6 handling
  else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6h = data + sizeof(*eth);
    // bound check
    if ((void *)ip6h + sizeof(*ip6h) > data_end) {
      return XDP_PASS;
    }

    __u64 addrv6 = ((__u64)bpf_ntohl(ip6h->saddr.in6_u.u6_addr32[0]) << 32) |
    bpf_ntohl(ip6h->saddr.in6_u.u6_addr32[1]);
    struct rate_limit_entry *rate_limiter = bpf_map_lookup_elem(&rate_limit_v6, &addrv6);
    if (!rate_limiter) {
      struct rate_limit_entry new_entry;
      __builtin_memset(&new_entry, 0, sizeof(new_entry));
      bpf_map_update_elem(&rate_limit_v6, &addrv6, &new_entry, BPF_ANY);
      rate_limiter = bpf_map_lookup_elem(&rate_limit_v6, &addrv6);
    }
    
    // TCP
    if (ip6h->nexthdr == IPPROTO_TCP) {
      struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*ip6h);
      // bound check
      if ((void *)tcph + sizeof(*tcph) > data_end) {
        return XDP_PASS;
      }
      
      if (is_tcp_allowed(tcph, rate_limiter)) {
        return XDP_PASS;
      }
      return XDP_DROP;
    }
    // UDP
    else if (ip6h->nexthdr == IPPROTO_UDP) {
      struct udphdr *udph = data + sizeof(*eth) + sizeof(*ip6h);
      // bound check
      if ((void *)udph + sizeof(*udph) > data_end) {
        return XDP_PASS;
      }
      
      if (is_udp_allowed(udph, rate_limiter)) {
        return XDP_PASS;
      }
      return XDP_DROP;
    }
    // fragments
    else if (ip6h->nexthdr == IPPROTO_FRAGMENT) {
      if (tick_rate_limit(rate_limiter, 50)) {
        return XDP_DROP;
      }
      return XDP_PASS;
    }
  }

  return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
