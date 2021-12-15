#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <signal.h>

#include "pkt_digest.h"


// clean terminal
#define tclean() printf("\033[H\033[J")
// dont wrap content on overflow
#define tsetnowrap() printf("\033[?7l")

struct {
    // device, for example:
    // -d enp68s0
    // -d ppp0
    // -d lo
    char * d;
    uint32_t g_summary;
} opts = {
    .d = NULL,
    .g_summary = 0,
};

int init_opts(int argc, char * argv[])
{
    int o;

    while((o = getopt(argc, argv, "d:")) != -1) {
        switch(o) {
        case 'd':
            opts.d = strdup(optarg);
            break;
        }
    }

    return 0;
}

struct table_row {
    char ** keys;
    uint64_t count;
};

struct table {
    struct table_row * rows;
    size_t cap;
    size_t len;
};

struct globals {
    pcap_t * pcap_handle;
    struct in_addr laddr;
    u_char wladdr;
    int dlt;
    struct table t;
} globals = {
    .pcap_handle = NULL,
    .wladdr = 0,
    .dlt = -1,
    .t = {
        .rows = NULL,
    },
};

static char pcaperr[PCAP_ERRBUF_SIZE];

#define print_errno(hdr) fprintf(stderr, #hdr " %s\n", errno ? strerror(errno) : "unkown error");
#define print_errno_ret(hdr) { \
    print_errno(hdr);            \
    return 1;                       \
}

#define print_pcap_err(hdr) fprintf(stderr, #hdr " %s\n", pcaperr);
// print_pcap_err and return 1
#define print_pcap_err_ret(hdr) { \
    print_pcap_err(hdr);            \
    return 1;                       \
}

#define print_err_ret(err) { \
    fputs(#err "\n", stderr);   \
    return 1;              \
}

char summary_buff[5 * MAX_PROTO_LEN];

void upsert(struct table * t, struct pkt_digest * dg) {

    if(opts.g_summary) {
        sprintf_pkg_summary(summary_buff, dg);
    }

    for(size_t i = 0; i < t->len; i++) {
        if(opts.g_summary && strcmp(summary_buff, t->rows[i].keys[0]))
            continue;
        t->rows[i].count++;
        return;
    }

    if(t->len >= t->cap) return;

    t->rows[t->len++].count = 1;
    if(opts.g_summary)
        strcpy(t->rows[t->len++].keys[0], summary_buff);
}

int get_device_info() {

    pcap_if_t * devs;
    int ret = 0;
    if((ret = pcap_findalldevs(&devs, pcaperr))) 
        print_pcap_err_ret(get_device_info:)

    for(pcap_if_t *d=devs; d!=NULL; d=d->next) {
        
        if(opts.d != NULL && strcmp(d->name, opts.d)) {
            continue;
        }

        for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {

            if(a->addr->sa_family == AF_INET) {
                globals.laddr.s_addr = ((struct sockaddr_in*)a->addr)->sin_addr.s_addr;
                globals.wladdr = 1;
            }

            if(!opts.d) opts.d = strdup(d->name);

            return 0;
        }
    }

    fprintf(stderr, "get_device_info: couldnt find device\n");
    return 1;
}

void cleanup()
{
    puts("cleanup...");
    if(opts.d) free(opts.d);
    if(globals.pcap_handle) pcap_close(globals.pcap_handle);
    if(globals.t.rows) free(globals.t.rows);
}

/*
    since pcap will run rcv_pkt in single thread it should be ok to
    to store info from currently processed packet in global variable.
*/
struct pkt_digest pkt_buffer;

void rcv_pkt(u_char * const args, const struct pcap_pkthdr * const _h, const u_char * const _p) {

    const u_char * pktptr = _p;
    bpf_u_int32 pktlen = _h->caplen;
    pktcallback next = NULL;

    switch(globals.dlt) {
    case DLT_EN10MB:
        pkt_buffer.meta.nexthop = rcv_dlt_en10mb;
        break;
    case DLT_LINUX_SLL:
        pkt_buffer.meta.nexthop = rcv_dlt_linux_sll;
        break;
    }

    pkt_buffer.meta.proto_len = 0;

    while(pkt_buffer.meta.nexthop) {
        next = pkt_buffer.meta.nexthop;
        pkt_buffer.meta.nexthop = NULL;
        next(&pktptr, &pktlen, &pkt_buffer);
    }

    upsert(&globals.t, &pkt_buffer);
}

void initabl(struct table * t) {
    t->cap = 30;
    t->len = 0;
    t->rows = malloc(sizeof(struct table_row) * t->cap);
    for(size_t i = 0 ; i < t->cap; i++) {
        t->rows[i].keys = malloc()
    }
}

int main(int argc, char *argv[]) 
{
    if(init_opts(argc, argv)) return 1;

    if(get_device_info()) return 1;

    if (!(globals.pcap_handle = pcap_create(opts.d, pcaperr)))
        print_pcap_err_ret(pcap_create:)

    if (pcap_set_snaplen(globals.pcap_handle, 
        /* im only using linux_sll, and 802.3 headers. ethhdr is bigger */
        sizeof(struct ethhdr)
        /* max ipv4, also it is bigger than max ipv6 header size since ipv6 is only 40 octets  */
        +sizeof(struct iphdr)+40
        /* also max udp header size */ 
        +sizeof(struct tcphdr) 
    )) print_errno_ret(pcap_set_snaplen:)

    if(pcap_set_immediate_mode(globals.pcap_handle, 1)) 
        print_errno_ret(pcap_set_immediate_mode:)   

    if(pcap_activate(globals.pcap_handle)) print_errno_ret(pcap_activate:)

    globals.dlt = pcap_datalink(globals.pcap_handle);

    printf("listening on %s\n", opts.d);
    signal(SIGINT, cleanup);

    tclean();
    tsetnowrap();

    if(pcap_loop(globals.pcap_handle, -1, rcv_pkt, NULL)) print_errno_ret(pcap_loop:)

    cleanup();
    return 0;
}


