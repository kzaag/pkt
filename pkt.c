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
#define COUNT_CIX 1
#define SIZE_CIX  2

struct colspec {
    uint16_t max_size;
    char * hdr;
    u_char visible;
    uint16_t c_size;
} colspec [] = {
    /* dims - not visible by default */
    {
        .hdr = "SUM",
        .c_size = 4,
        .max_size = MAX_SUMMARY_LEN,
        .visible = 0,
    },
    /* facts - visible by default */
    {
        .hdr = "COUNT",
        .c_size = 6,
        .max_size = 10,
        .visible = 1,
    },
    {
        .hdr = "SIZE",
        .c_size = 5,
        .max_size = 10,
        .visible = 1,
    }
};

/* max column size */
#define MCSZ(IX) colspec[IX].max_size
/* is column visible */
#define CVIS(IX) colspec[IX].visible
/* current column size */
#define CCSZ(IX) colspec[IX].c_size

struct {
    // device, for example:
    // -d enp68s0
    // -d ppp0
    // -d lo
    char * d;
    // refresh interval in seconds
    // -i 2
    int i;
    uint32_t g_summary;
} opts = {
    .d = NULL,
    .g_summary = 0,
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
                    opts.g_summary = 1; 
                    CVIS(SUMMARY_CIX) = 1;
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

struct table {
    /* 2-D table of c-strings: rows are first, then columns, then cstring */
    char *** data;
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

    uint64_t c;
    double sz;
    int wrote;
    int sumwrote;

    if(CVIS(SUMMARY_CIX)) {
        sumwrote = sprintf_pkg_summary(summary_buff, dg) + 1;
    }


    for(size_t i = 1; i < t->rows; i++) {

        /* dims */

        if(CVIS(SUMMARY_CIX) && strcmp(summary_buff, t->data[i][SUMMARY_CIX]))
            continue;

        /* facts */

        if(CVIS(COUNT_CIX)) {
            c = atoi(t->data[i][COUNT_CIX]);
            wrote = snprintf(t->data[i][COUNT_CIX], MCSZ(COUNT_CIX), "%lu", c+1) + 1;
            if(wrote > CCSZ(COUNT_CIX))
                CCSZ(COUNT_CIX) = wrote;
        }

        if(CVIS(SIZE_CIX)) {
            sz = atof_size(t->data[i][SIZE_CIX]);
            wrote = snprintf_size(t->data[i][SIZE_CIX], MCSZ(SIZE_CIX), sz + (double)len) + 1;
            if(wrote > CCSZ(SIZE_CIX))
                CCSZ(SIZE_CIX) = wrote;
        }

        pthread_spin_unlock(&globals.sync);
        return;
    }

    if(t->rows >= t->maxrows) {
        pthread_spin_unlock(&globals.sync);
        return;
    }

    if(CVIS(COUNT_CIX)) {
        /* this is never bigger than current CCSZ*/
        t->data[t->rows][COUNT_CIX][0] = '1';
        t->data[t->rows][COUNT_CIX][1] = 0;
    }
    if(CVIS(SIZE_CIX)) {
        wrote = snprintf_size(t->data[t->rows][SIZE_CIX], MCSZ(SIZE_CIX), (double)len) + 1;
        if(wrote > CCSZ(SIZE_CIX))
            CCSZ(SIZE_CIX) = wrote;
    }
    if(CVIS(SUMMARY_CIX)) {
        strncpy(t->data[t->rows][SUMMARY_CIX], summary_buff, MCSZ(SUMMARY_CIX));
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

    upsert(&globals.t, &pkt_buffer, _h->len);
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
                    free(globals.t.data[i][j]);
            }
            free(globals.t.data[i]);
        }
        free(globals.t.data);
    }
    puts("done");
    exit(0);
}

void printbl(struct table * t) {
    
    tgotoxy(0, 1);
    unsigned short csz;
    
    for(size_t i = 0; i < t->rows; i++) {
        for(size_t j = 0; j < t->cols; j++) {
            if(!t->data[i][j])
                continue;
            csz = CCSZ(j);
            printf("%*.*s", csz, csz, t->data[i][j]);
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
    
    t->data = malloc(sizeof(char **) * t->maxrows);
    for(size_t i = 0; i < t->maxrows; i++) {
        t->data[i] = calloc(t->cols, sizeof(char *));
        char ** row = t->data[i];

        for(size_t j = 0; j < t->cols; j++) {
            if(!colspec[j].visible) 
                continue;
            if(i == 0) {
                row[j] = colspec[j].hdr;
            } else {
                row[j] = malloc(colspec[j].max_size);
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


