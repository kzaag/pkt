#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <signal.h>
#include <pthread.h>

#include "pkt_digest.h"

/* unlikely ip addresses which we may use for testing */

#define INADDR_TEST_NET_1 ((in_addr_t)0xc0000200) /* 192.0.2.0 */

static char pcaperr[PCAP_ERRBUF_SIZE];

#define print_errno(hdr) fprintf(stderr, #hdr " %s\n", errno ? strerror(errno) : "unkown error");
#define print_errno_ret(hdr) { \
    print_errno(hdr);            \
    return 1;                       \
}
#define print_errno_exit(hdr) {     \
    print_errno(hdr);                \
    exit(1);                         \
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

// clean terminal
#define tclean() printf("\033[H\033[J")
// dont wrap content on overflow
#define tsetnowrap() printf("\033[?7l")
// set cursor position
#define tgotoxy(x, y) printf("\033[%d;%dH", x, y)

/* indexes for specified columns within colspec */
#define SUMMARY_CIX   0
#define IP4SADDR_CIX  1
#define IP4DADDR_CIX  2

#define COUNT_CIX 3
#define SIZE_CIX  4

#define CT_CSTR   0
#define CT_DOUBLE 1
#define CT_UINT64 2
#define CT_INADDR 3

struct colspec {
    char * hdr;
    uint16_t max_size;
    uint16_t c_size;
    u_char coltype;
    u_char visible  : 1;
    /* if set to 0 will indicate that column value may change, 
        and cstr must be updated on every display */
    u_char readonly : 1;
} colspec [] = {
    /* dims - not visible by default */
    {
        .hdr = "SUM",
        .c_size = 4,
        /* XXXX-YYYY-ZZZZ\0 */
        .max_size = MAX_SUMMARY_LEN,
        .coltype = CT_CSTR,
        .visible = 0,
        .readonly = 1,
    },
    {         
        .hdr = "IP4SADDR",
        .c_size = 10,
        /* xxx.xxx.xxx.xxx\0 */
        .max_size = 16,
        .coltype = CT_INADDR,
        .visible = 0,
        .readonly = 1,
    },
    {         
        .hdr = "IP4DADDR",
        .c_size = 10,
        /* xxx.xxx.xxx.xxx\0 */
        .max_size = 16,
        .coltype = CT_INADDR,
        .visible = 0,
        .readonly = 1,
    },
    /* facts - visible by default */
    {
        .hdr = "COUNT",
        .c_size = 6,
        /* XXXXXXXXX\0 */
        .max_size = 10,
        .coltype = CT_UINT64,
        .visible = 1,
        .readonly = 0,
    },
    {
        .hdr = "SIZE",
        .c_size = 5,
        /* XXXXX.XX{B,K,M,...}\0 */
        .max_size = 10,
        .coltype = CT_DOUBLE,
        .visible = 1,
        .readonly = 0,
    },
};


/* max column size */
#define MCSZ(IX) colspec[IX].max_size
/* is column visible */
#define CVIS(IX) colspec[IX].visible
/* current column size */
#define CCSZ(IX) colspec[IX].c_size
/* column type */
#define CTP(IX) colspec[IX].coltype
/* is column readonly */
#define CRDONLY(IX) colspec[IX].readonly

struct {
    // device, for example:
    // -d enp68s0
    // -d ppp0
    // -d lo
    char * d;
    // refresh interval in seconds
    // -i 2
    int i;
} opts = {
    .d = NULL,
    .i = 1,
};

int init_opts(int argc, char * argv[])
{
    int o;
    size_t i = 0;

    while((o = getopt(argc, argv, "d:g:i:")) != -1) {
        switch(o) {
        case 'd':
            opts.d = strdup(optarg);
            break;
        case 'g':
            for(;;) {
                if(!optarg[i]) break;
                switch(optarg[i]) {
                case 's':
                    CVIS(SUMMARY_CIX) = 1;
                    break;
                case 'z':
                    CVIS(IP4SADDR_CIX) = 1;
                    break;
                case 'x':
                    CVIS(IP4DADDR_CIX) = 1;
                    break;
                default:
                    fprintf(stderr, "%s: unkown group option -- %c\n", argv[0], optarg[i]);
                    break;
                }
                i++;
            }
            break;
        case 'i':
            opts.i = atoi(optarg);
            if(opts.i <= 0) {
                fprintf(stderr, "%s: invalid option -- 'i' %s\n", argv[0], optarg);
                exit(1);
            }
            break;
        default:
            exit(1);
        }
    }

    return 0;
}

struct td {
    char * cstr;
    union {
        uint64_t uint64_val;
        struct in_addr in_addr_val;
    };
};

struct table {
    /* rows are first, then columns, then table cell */
    struct td ** data;
    unsigned short maxrows;
    unsigned short rows;
    unsigned short cols;
};

struct globals {
    pcap_t * pcap_handle;
    struct in_addr laddr;
    u_char wladdr;
    int dlt;
    struct table t;
    pthread_t rthr;
    pthread_spinlock_t sync;
} globals = {
    .pcap_handle = NULL,
    .wladdr = 0,
    .dlt = -1,
    .t = {
        .data = NULL
    },
    .rthr = 0,
};

char summary_buff[MAX_SUMMARY_LEN];

int
snprintf_size(char *buf, int blen, double size) {
    int i = 0;
    const char units[] = {'B', 'K', 'M', 'G', 'T', 'P'};
    while (size > 1024) {
        if(i == 5) break;
        size /= 1024;
        i++;
    }
    if(i > 2) i = 2;
    return snprintf(buf, blen, "%.*lf%c", i, size, units[i]);
}

double atof_size(char * sizestr) {
    char d;
    double sz;
    if(sscanf(sizestr, "%lf%c", &sz, &d) != 2) {
        return 0;
    }

    switch(d) {
    case 'P':
        sz *= 1024;
    case 'T':
        sz *= 1024;
    case 'G':
        sz *= 1024;
    case 'M':
        sz *= 1024;
    case 'K':
        sz *= 1024;
    }

    return sz;
}

void upsert(struct table * t, struct pkt_digest * dg, uint32_t len) {

    if(pthread_spin_lock(&globals.sync)) 
        print_errno_exit(upsert:)

    int sumwrote;

    if(CVIS(SUMMARY_CIX)) {
        sumwrote = sprintf_pkg_summary(summary_buff, dg) + 1;
    }

    u_char ispv4 = 0;
    for(PROTO_ID j = 0; j < dg->meta.proto_len; j++) {
        if(dg->meta.protos[j] == ID_IPV4) {
            ispv4 = 1;
            break;
        }
    }

    for(size_t i = 1; i < t->rows; i++) {

        if(CVIS(SUMMARY_CIX) && strcmp(summary_buff, t->data[i][SUMMARY_CIX].cstr))
            continue;
        
        if(CVIS(IP4SADDR_CIX)) {
            if(ispv4) {
                if(dg->ipv4.saddr.s_addr != t->data[i][IP4SADDR_CIX].in_addr_val.s_addr)
                    continue;
            } else {
                if(INADDR_TEST_NET_1 != t->data[i][IP4SADDR_CIX].in_addr_val.s_addr)
                    continue;
            }
        }

        if(CVIS(COUNT_CIX)) {
            t->data[i][COUNT_CIX].uint64_val++;
        }

        if(CVIS(SIZE_CIX)) {
            t->data[i][SIZE_CIX].uint64_val += len;
        }

        pthread_spin_unlock(&globals.sync);
        return;
    }

    if(t->rows >= t->maxrows) {
        pthread_spin_unlock(&globals.sync);
        return;
    }

    if(CVIS(IP4SADDR_CIX)) {
        if(ispv4) {
            t->data[t->rows][IP4SADDR_CIX].in_addr_val = dg->ipv4.saddr;
        } else {
            t->data[t->rows][IP4SADDR_CIX].in_addr_val.s_addr = INADDR_TEST_NET_1;
        }
    }

    if(CVIS(COUNT_CIX)) {
        t->data[t->rows][COUNT_CIX].uint64_val = 1;
    }

    if(CVIS(SIZE_CIX)) {
        t->data[t->rows][SIZE_CIX].uint64_val = len;
    }

    if(CVIS(SUMMARY_CIX)) {
        strncpy(t->data[t->rows][SUMMARY_CIX].cstr, summary_buff, MCSZ(SUMMARY_CIX));
        if(sumwrote > CCSZ(SUMMARY_CIX))
            CCSZ(SUMMARY_CIX) = sumwrote;
    }
    
    t->rows++;

    pthread_spin_unlock(&globals.sync);
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


/*
    since pcap will run rcv_pkt in single thread it should be ok to
    to store info from currently processed packet in global variable.
*/
struct pkt_digest pkt_digest;

void rcv_pkt(u_char * const args, const struct pcap_pkthdr * const _h, const u_char * const _p) {

    const u_char * pktptr = _p;
    bpf_u_int32 pktlen = _h->caplen;
    pktcallback next = NULL;

    switch(globals.dlt) {
    case DLT_EN10MB:
        pkt_digest.meta.nexthop = rcv_dlt_en10mb;
        break;
    case DLT_LINUX_SLL:
        pkt_digest.meta.nexthop = rcv_dlt_linux_sll;
        break;
    }

    pkt_digest.meta.proto_len = 0;

    while(pkt_digest.meta.nexthop) {
        next = pkt_digest.meta.nexthop;
        pkt_digest.meta.nexthop = NULL;
        next(&pktptr, &pktlen, &pkt_digest);
    }

    upsert(&globals.t, &pkt_digest, _h->len);
}

const char ct[] = "cleanup... ";

void cleanup()
{
    write(STDOUT_FILENO, ct, sizeof(ct));
    if(opts.d) free(opts.d);
    if(globals.rthr) pthread_cancel(globals.rthr);
    if(globals.pcap_handle) {
        pcap_breakloop(globals.pcap_handle);
        pcap_close(globals.pcap_handle);
    }
    pthread_spin_destroy(&globals.sync);
    if(globals.t.data) {
        for(size_t i = 0; i < globals.t.maxrows; i++) {
            for(size_t j = 0; j < globals.t.cols; j++) {
                if(i > 0)
                    free(globals.t.data[i][j].cstr);
            }
            free(globals.t.data[i]);
        }
        free(globals.t.data);
    }
    puts("done");
    exit(0);
}

void printbl(struct table * t) {
    int wrote;
    unsigned short csz;
    
    tgotoxy(0, 1);
    
    for(size_t i = 0; i < t->rows; i++) {
        for(size_t j = 0; j < t->cols; j++) {

            if(!t->data[i][j].cstr) 
                continue;

            if(!t->data[i][j].cstr[0] || (!CRDONLY(j) && i > 0)) {

                switch(CTP(j)) {
                case CT_DOUBLE:
                    wrote = snprintf_size(
                        t->data[i][j].cstr, 
                        MCSZ(j), (double)t->data[i][j].uint64_val);
                    break;
                case CT_INADDR:

                    if(t->data[i][j].in_addr_val.s_addr == INADDR_TEST_NET_1) {
                        wrote = sprintf(t->data[i][j].cstr, "?");
                    } else {
                        wrote = snprintf(
                            t->data[i][j].cstr, 
                            MCSZ(IP4SADDR_CIX), 
                            inet_ntoa(t->data[i][j].in_addr_val));
                    }

                    break;
                case CT_UINT64:
                    wrote = snprintf(
                        t->data[i][j].cstr, 
                        MCSZ(j), 
                        "%lu", t->data[i][j].uint64_val);

                    break;
                default:

                    wrote = sprintf(t->data[i][j].cstr, "?");
                    break;
                }

                wrote++;
                if(wrote > CCSZ(j))
                    CCSZ(j) = wrote;
            }

            csz = CCSZ(j);
            printf("%*.*s", csz, csz, t->data[i][j].cstr);
        }
        puts("");
    }
}

void initbl(struct table * t) {

    int maxcap = 10;
    /* predefined limit + 1 to account for header row */
    t->maxrows = maxcap + 1;
    /* 1 because of header row */
    t->rows = 1;
    t->cols = sizeof(colspec)/sizeof(struct colspec);
    
    t->data = malloc(sizeof(struct td **) * t->maxrows);
    for(size_t i = 0; i < t->maxrows; i++) {
        t->data[i] = calloc(t->cols, sizeof(struct td));
        struct td * row = t->data[i];

        for(size_t j = 0; j < t->cols; j++) {
            if(!colspec[j].visible) 
                continue;
            if(i == 0) {
                row[j].cstr = colspec[j].hdr;
            } else {
                row[j].cstr = malloc(colspec[j].max_size);
                row[j].cstr[0] = 0;
            }
        }
    }
}

void * run_readloop(void * args) {

    for(;;) {
        if(pthread_spin_lock(&globals.sync)) 
            print_errno_exit(run_readloop:);
        printbl(&globals.t);
        pthread_spin_unlock(&globals.sync);
        sleep(opts.i);
    }
    return NULL;
}

int main(int argc, char *argv[]) {

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

    tclean();
    tsetnowrap();
    tgotoxy(0,0);

    //Printf("listening on %s\n", opts.d);
    signal(SIGINT, cleanup);


    initbl(&globals.t);

    pthread_spin_init(&globals.sync, 0);
    if(pthread_create(&globals.rthr, NULL, run_readloop, NULL)) print_errno_ret(pthread_create:)

    if(pcap_loop(globals.pcap_handle, -1, rcv_pkt, NULL)) print_errno_ret(pcap_loop:)

    cleanup();
    return 0;
}
