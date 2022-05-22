#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/hash.h>


/**
 * Copied from <uapi/linux/tcp.h>,
 * which by itself causes errors related to `atomic64_t`.
 */

#define IPPROTO_TCP 6

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80

struct tcphdr {
        __u16   source;
        __u16   dest;
        __u32   seq;
        __u32   ack_seq;
        union {
            u16 flags;
            struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u16   res1:4,
                doff:4,
                fin:1,
                syn:1,
                rst:1,
                psh:1,
                ack:1,
                urg:1,
                ece:1,
                cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u16   doff:4,
                res1:4,
                cwr:1,
                ece:1,
                urg:1,
                ack:1,
                psh:1,
                rst:1,
                syn:1,
                fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
            };
        };
        __u16   window;
        __u16   check;
        __u16   urg_ptr;
};

/* eBPF requires all functions to be inlined */
#define INTERNAL static __attribute__((always_inline))

/**
 * Packet processing context.
 */
struct Packet {
    /* For verification to for passing to BPF helpers. */
    struct xdp_md* ctx;

    /* Layer headers (may be NULL on lower stages) */
    struct ethhdr* ether;
    struct iphdr* ip;
    struct tcphdr* tcp;
};

BPF_HASH(counter, uint32_t, long);
INTERNAL int
process_tcp(struct Packet* packet) {
    struct tcphdr* tcp  = packet->tcp;
    struct iphdr* ip = packet->ip;

    uint32_t tcp_port;
    uint32_t tcp_saddr;
    uint32_t tcp_flag;
    long *value;
    long zero = 0;
    int filter = 1;

    unsigned int randomnumber;
    randomnumber = bpf_get_prandom_u32() % 100;
    tcp_port = bpf_ntohs(tcp->source);
    tcp_flag = bpf_ntohs(tcp->flags) 0xff;
    tcp_saddr = ip->saddr;

    if (SYN == 1 && ((tcp_flag & TH_SYN) != TH_SYN)) {
      filter = 0;
    }

    if( filter ) {
      if ( PORTNUM == -1 || tcp_port == PORTNUM ) {
        if ( IP == -1 || tcp_saddr == IP ) {
          if (randomnumber < JITTER) {
            value = counter.lookup_or_init(&tcp_saddr, &zero);
            (*value) += 1;
            return XDP_DROP;
          }
        }
      }
    }
    return XDP_PASS;
}

INTERNAL int
process_ip(struct Packet* packet) {
    struct iphdr* ip = packet->ip;

    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }
    struct tcphdr* tcp = (struct tcphdr*)(ip + 1);
    if ((void*)(tcp + 1) > (void*)packet->ctx->data_end) {
        return XDP_DROP; /* malformed packet */
    }
    packet->tcp = tcp;

    return process_tcp(packet);
}

INTERNAL int
process_ether(struct Packet* packet) {
    struct ethhdr* ether = packet->ether;

    if (ether->h_proto != bpf_ntohs(ETH_P_IP)) {
        return XDP_PASS;
    }
    struct iphdr* ip = (struct iphdr*)(ether + 1);
    if ((void*)(ip + 1) > (void*)packet->ctx->data_end) {
        return XDP_DROP; /* malformed packet */
    }
    packet->ip = ip;
    return process_ip(packet);
}

int xdp_main(struct xdp_md* ctx) {
    struct Packet packet;
    packet.ctx = ctx;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *ether = data;
    if ((void*)(ether + 1) > (void*)ctx->data_end) {
        return XDP_DROP; /* malformed packet */
    }
    packet.ether = ether;
    return process_ether(&packet);
}

