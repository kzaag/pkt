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

#define set_pkt_meta(meta, id) set_pkt_meta_f(meta, 1<<id)

static inline void set_pkt_meta_f(struct pkt_meta * meta, proto_t flag) {
    if(meta->proto_flags & flag){
        fprintf(stderr, "found duplicate protocol (%u | %u), aborting\n", meta->proto_flags, flag);
        exit(1);
    }
    meta->proto_flags |= flag;
}


void rcv_udp(const u_char ** p, u_int32_t * plen, struct pkt_digest * i) {
    set_pkt_meta(&i->meta, ID_UDP);

    if(*plen < sizeof(struct udphdr)) {
        set_pkt_meta(&i->meta, ID_PROTO_ETERM);
        i->udp.source = 0;
        i->udp.dest = 0;
        return;
    }

    struct udphdr * h = (struct udphdr *)*p;

    i->udp.source = ntohs(h->source);
    i->udp.dest = ntohs(h->dest);

    set_pkt_meta(&i->meta, ID_PROTO_TERM);
    return;
}

void rcv_tcp(const u_char ** p, u_int32_t * plen, struct pkt_digest * i) {
    set_pkt_meta(&i->meta, ID_TCP);

    if(*plen < sizeof(struct tcphdr)) {
        set_pkt_meta(&i->meta, ID_PROTO_ETERM);
        i->tcp.source = 0;
        i->tcp.dest = 0;
        return;
    }

    struct tcphdr * h = (struct tcphdr *)*p;

    i->tcp.source = ntohs(h->source);
    i->tcp.dest = ntohs(h->dest);

    set_pkt_meta(&i->meta, ID_PROTO_TERM);
}


void rcv_icmp(const u_char ** p, u_int32_t * plen, struct pkt_digest * i) {
    set_pkt_meta(&i->meta, ID_ICMP);
    set_pkt_meta(&i->meta, ID_PROTO_TERM);
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
    set_pkt_meta(&i->meta, ID_IPV4);

    if(*plen < sizeof(struct iphdr)) {
        set_pkt_meta(&i->meta, ID_PROTO_ETERM);
        i->ipv4.saddr.s_addr = INADDR_TEST_NET_1;
        i->ipv4.daddr.s_addr = INADDR_TEST_NET_1;
        return;
    }

    struct iphdr * h = (struct iphdr *)*p;

    if(h->version != 4) {
        set_pkt_meta(&i->meta, ID_PROTO_UNKOWN);
        i->ipv4.saddr.s_addr = INADDR_TEST_NET_1;
        i->ipv4.daddr.s_addr = INADDR_TEST_NET_1;
        return;
    }

    i->ipv4.saddr.s_addr = h->saddr;
    i->ipv4.daddr.s_addr = h->daddr;
    
    u_char size = h->ihl * 4;
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
    set_pkt_meta(&i->meta, ID_EN10MB);

    if(*plen < sizeof(struct ethhdr)) {
        set_pkt_meta(&i->meta, ID_PROTO_ETERM);
        bzero(i->en10mb.hwsrc, ETH_ALEN);
        bzero(i->en10mb.hwdest, ETH_ALEN);
        return;
    }

    struct ethhdr * h = (struct ethhdr*)(*p);
    i->en10mb.ethertype = ntohs(h->h_proto);
    memcpy(i->en10mb.hwdest, h->h_dest, ETH_ALEN);
    memcpy(i->en10mb.hwsrc, h->h_source, ETH_ALEN);
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
    
    set_pkt_meta(&i->meta, ID_LINUX_SLL);

    if(*plen < sizeof(struct linux_sllhdr)) {
        set_pkt_meta(&i->meta, ID_PROTO_ETERM);
        return;
    }

    struct linux_sllhdr * hdr = (struct linux_sllhdr *)*p;
    
    i->sll.ethertype = ntohs(hdr->proto);

    // this could be encapsulated novell 802.3, 802.2 llc, or CAN - in that case abort
    if(i->sll.ethertype <= 1500) {
        set_pkt_meta(&i->meta, ID_PROTO_UNKOWN);
        return;
    }

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
    "SLL",  /* ID_LINUX_SLL */
    "ETH",  /* ID_EN10MB */
    "IP4",  /* ID_IPV4 */
    "TCP",  /* ID_TCP */
    "UDP",  /* ID_UDP */
    "ICMP", /* ID_ICMP */

    "x",     /* ID_PROTO_ETERM */
    "*",      /* ID_PROTO_TERM */

    "?"    /* ID_PROTO_UNKOWN */
};


// s length must be >= (MAX_SUMMARY_LEN)
int sprintf_proto(char * s, proto_t t) {

    int wrote = 0;

    for(int i = 0; i < ID_PROTO_START; i++)
        if((t >> i) & (u_char)1)
            wrote += snprintf(s+wrote, MAX_SUMMARY_LEN-wrote, "%s-", PROTO_ID_STR[i]);

    if(t & IDF(ID_PROTO_TERM)) {
        /* wrote += snprintf(s+wrote, MAX_SUMMARY_LEN-wrote, PROTO_ID_STR[ID_PROTO_TERM]); */
        wrote--;
        s[wrote] = 0;
    } else if(t & IDF(ID_PROTO_ETERM)) {
        wrote--;
        wrote += snprintf(s+wrote, MAX_SUMMARY_LEN-wrote, PROTO_ID_STR[ID_PROTO_ETERM]);
    } else {
        wrote += snprintf(s+wrote, MAX_SUMMARY_LEN-wrote, PROTO_ID_STR[ID_PROTO_UNKOWN]);
    }

    return wrote;
}
