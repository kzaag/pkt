#include "pkt_digest.h"
#include <arpa/inet.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <pcap/dlt.h>
#include <stdio.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/if_pppox.h>

#define RETURN_RCV { *next = NULL; return; }

static inline void set_pkt_meta(struct pkt_meta * meta, PROTO_ID id) {
    if(meta->proto_len >= MAX_PROTO_LEN)  {
        //fputs("proto overflow\n", stderr);
        return;
    }
    meta->protos[meta->proto_len++] = id;
}

void rcv_udp(const u_char ** p, u_int32_t * plen, struct pkt_digest * i) {
    if(*plen < sizeof(struct udphdr)) {
        return;
    }

    struct udphdr * h = (struct udphdr *)*p;

    i->udp.source = ntohs(h->source);
    i->udp.dest = ntohs(h->dest);
    set_pkt_meta(&i->meta, ID_UDP);

    return;
}

void rcv_tcp(const u_char ** p, u_int32_t * plen, struct pkt_digest * i) {
    if(*plen < sizeof(struct tcphdr)) {
        return;
    }

    struct tcphdr * h = (struct tcphdr *)*p;

    i->tcp.source = ntohs(h->source);
    i->tcp.dest = ntohs(h->dest);
    set_pkt_meta(&i->meta, ID_TCP);
}


void rcv_icmp(const u_char ** p, u_int32_t * plen, struct pkt_digest * i) {
    set_pkt_meta(&i->meta, ID_ICMP);
}

pktcallback switch_ipproto(unsigned char proto) {
    switch(proto) {
    case IPPROTO_TCP:
        return rcv_tcp;
    case IPPROTO_UDP:
        return rcv_udp;
    case IPPROTO_ICMP:
        return rcv_icmp;
    default:
        return NULL;
    }
}

void rcv_ipv4(const u_char ** p, u_int32_t * plen, struct pkt_digest * i) {
    if(*plen < sizeof(struct iphdr))
        return;

    struct iphdr * h = (struct iphdr *)*p;

    if(h->version != 4)
        return;

    i->ipv4.saddr.s_addr = h->saddr;
    i->ipv4.daddr.s_addr = h->daddr;
    set_pkt_meta(&i->meta, ID_IPV4);
    
    u_char size = h->ihl * 5;
    *p += size;
    *plen -= size;
    i->meta.nexthop = switch_ipproto(h->protocol);
}

/*
    return next handler for packet inside link frame
*/
pktcallback switch_ethertype(u_int16_t ethtype) {
    switch(ethtype) {
    case ETH_P_IP:
        return rcv_ipv4;
    case ETH_P_IPV6:
    case ETH_P_ARP:
    case ETH_P_PPP_DISC:
    case ETH_P_PPP_SES:
    default:
        return NULL;
    }
}

/*
    handle ethernet (802.3) headers 
*/
void rcv_dlt_en10mb(const u_char ** p, u_int32_t * plen, struct pkt_digest * i) {
    if(*plen < sizeof(struct ethhdr))
        return;

    struct ethhdr * h = (struct ethhdr*)(*p);
    i->en10mb.ethertype = ntohs(h->h_proto);
    memcpy(i->en10mb.hwdest, h->h_dest, ETH_ALEN);
    memcpy(i->en10mb.hwsrc, h->h_source, ETH_ALEN);
    set_pkt_meta(&i->meta, ID_EN10MB);
    *p += sizeof(struct ethhdr);
    *plen -= sizeof(struct ethhdr);
    i->meta.nexthop = switch_ethertype(i->en10mb.ethertype);
}

struct linux_sllhdr {
   u_int16_t pkt_type;
   u_int16_t arphrd;
   u_int16_t link_addr_len;
   unsigned char __pad[8];
   u_int16_t proto;
} __attribute__((packed));

/*
    handle packets which have been scrambled by linux modules (for example by pppoe)   
*/
void rcv_dlt_linux_sll(const u_char ** p, u_int32_t * plen, struct pkt_digest * i) {
    if(*plen < sizeof(struct linux_sllhdr)) 
        return;

    struct linux_sllhdr * hdr = (struct linux_sllhdr *)*p;
    
    i->sll.ethertype = ntohs(hdr->proto);
    
    set_pkt_meta(&i->meta, ID_LINUX_SLL);

    // this could be encapsulated novell 802.3, 802.2 llc, or CAN - in that case abort
    if(i->sll.ethertype <= 1500)
        return;

    *p += sizeof(struct linux_sllhdr);
    *plen -= sizeof(struct linux_sllhdr);
    i->meta.nexthop = switch_ethertype(i->sll.ethertype);
}

// buff must be 3 * ETH_ALEN: XX:XX: ... :XX:XX\0
void sprintf_hwaddr(char * buff, u_char * hwaddr) {
    u_char i;
    for(i = 0; i < ETH_ALEN-1; i++)
        sprintf(buff+(3*i), "%02x:", hwaddr[i]);
    sprintf(buff+(3*i), "%02x", hwaddr[i]);
}

const char * PROTO_ID_STR[] = {
    "SLL",
    "ETH",
    "IP4",
    "TCP",
    "UDP",
    "ICMP"
};


// s length must be >= (MAX_SUMMARY_LEN)
int sprintf_pkg_summary(char * s, struct pkt_digest * pi) {
    if(!pi->meta.proto_len) {
        s[0] = 0;
        return 0;
    }
    int wrote = 0, total_wrote = 0;
    for(PROTO_ID i = 0; i < pi->meta.proto_len; i++) {
        const char * proto = PROTO_ID_STR[pi->meta.protos[i]];
        if(i < pi->meta.proto_len - 1)
            wrote = sprintf(s, "%s-", proto);
        else 
            wrote = sprintf(s, "%s", proto);
        s += wrote;
        total_wrote += wrote;
    }
    return total_wrote;
}

    // char sh[3*ETH_ALEN], dh[3 * ETH_ALEN];
    // sprintf_hwaddr(sh, pi->hsrc);
    // sprintf_hwaddr(dh, pi->hdest);
    // printf("h_proto=%04x dlt=%d %s -> %s\n", pi->ethtype, globals.dlt, sh, dh);
    // if(pi->aethtype == ETH_P_IP) {
    //     char saddrs[16], daddrs[16];
    //     char * sp = inet_ntoa(pi->ipv4.saddr);
    //     memcpy(saddrs, sp, 15);
    //     sp = inet_ntoa(pi->ipv4.daddr);
    //     memcpy(daddrs, sp, 15);
    //     saddrs[15] = 0;
    //     daddrs[15] = 0;
    //     printf("%s -> %s\n", saddrs, daddrs);
    // }
