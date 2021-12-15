
#ifndef PKT_DIGEST_H
#define PKT_DIGEST_H 1

#include <stdlib.h>
#include <linux/if_ether.h>
#include <netinet/in.h>

typedef u_char PROTO_ID;
#define ID_LINUX_SLL 0
#define ID_EN10MB    1
#define ID_IPV4      2
#define ID_TCP       3
#define ID_UDP       4
#define ID_ICMP      5

#define MAX_PROTO_LEN 8

struct pkt_digest;

typedef void (*pktcallback)(
    const u_char **p,
    u_int32_t *plen,
    struct pkt_digest *i);

struct pkt_meta {
    PROTO_ID protos[MAX_PROTO_LEN];
    PROTO_ID proto_len;
    pktcallback nexthop;
};


struct pkt_digest
{
    struct pkt_meta meta;

    union {
        struct
        {
            /* host byte order */
            u_int16_t ethertype;
        } sll;

        struct
        {
            u_char hwdest[ETH_ALEN];
            u_char hwsrc[ETH_ALEN];
            /* host byte order */
            u_int16_t ethertype;
        } en10mb;
    };

    union {
        struct
        {
            u_char protocol;
            /* network byte order */
            struct in_addr saddr;
            /* network byte order */
            struct in_addr daddr;
        } ipv4;

        struct
        {
            u_char next_header;
        } ipv6;
    };

    struct {
        uint16_t source;
        uint16_t dest;
    } tcp;

    struct {
        uint16_t source;
        uint16_t dest;
    } udp;

    // struct
    // {
    // } arp;

    // struct
    // {
    // } ppp_disc;

    // struct
    // {
    // } ppp_sess;

    // struct {
    // } icmp;
};

void sprintf_pkg_summary(char * s, struct pkt_digest * pi);

void rcv_dlt_en10mb(const u_char ** p, u_int32_t * plen, struct pkt_digest * i);
void rcv_dlt_linux_sll(const u_char ** p, u_int32_t * plen, struct pkt_digest * i);

#endif
