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
/* IPv4 address pair */
#define IP4SADDR_CIX  1
#define IP4DADDR_CIX  2
/* UDP/TCP port pair */
#define SRC_CIX       3
#define DST_CIX       4

#define CIX_FACT_START 5

#define COUNT_CIX CIX_FACT_START
#define SIZE_CIX  (CIX_FACT_START+1)
#define TIME_CIX  (CIX_FACT_START+2)

#define CT_DOUBLE 0
#define CT_UINT64 1
#define CT_INADDR 2
#define CT_PKTSUM 3
#define CT_TIME   4
#define CT_UINT16 5

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
        .coltype = CT_PKTSUM,
        .visible = 0,
        .readonly = 1,
    },
    {         
        .hdr = "IPV4SADDR",
        .c_size = 11,
        /* xxx.xxx.xxx.xxx\0 */
        .max_size = 16,
        .coltype = CT_INADDR,
        .visible = 0,
        .readonly = 1,
    },
    {         
        .hdr = "IPV4DADDR",
        .c_size = 11,
        /* xxx.xxx.xxx.xxx\0 */
        .max_size = 16,
        .coltype = CT_INADDR,
        .visible = 0,
        .readonly = 1,
    },
    {         
        .hdr = "SRC",
        .c_size = 6,
        /* xxxxx\0 */
        .max_size = 6,
        .coltype = CT_UINT16,
        .visible = 0,
        .readonly = 1,
    },
    {         
        .hdr = "DST",
        .c_size = 6,
        /* xxxxx\0 */
        .max_size = 6,
        .coltype = CT_UINT16,
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
    {
        .hdr = "LTIME",
        .c_size = 6,
        .max_size = 10,
        .coltype = CT_TIME,
        .visible = 1,
        .readonly = 0
    }
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
    /* raw output only */
    int r;
} opts = {
    .d = NULL,
    .i = 1,
    .r = 0,
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
                case 'c':
                    CVIS(SRC_CIX) = 1;
                    break;
                case 'v':
                    CVIS(DST_CIX) = 1;
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


const char * clr_norm = "\x1B[0m";
const char * clr_red =  "\x1B[31m";
const char * clr_grn =  "\x1B[32m";
const char * clr_yel =  "\x1B[33m";
const char * clr_blu = "\x1B[34m";
const char * clr_mag = "\x1B[35m";
const char * clr_cyn = "\x1B[36m";
const char * clr_wht = "\x1B[37m";

/* this color is used to display local data such as local ports, local addresses, ... */
#define clr_local clr_mag

struct td {
    char * cstr;
    const char * adrstart;
    const char * adrend;
    union {
        uint64_t uint64_val;
        uint16_t uint16v;
        struct in_addr in_addr_val;
        proto_t proto;
        time_t time;
    };
};

struct rowspec {
    uint8_t frefresh;
};

struct table {
    /* rows are first, then columns, then table cell */
    struct td ** data;
    unsigned short maxrows;
    unsigned short rows;
    unsigned short cols;
    /* be very careful when handling this array.
        data may be sorted and reordered. In that case rowspec will refer to wrong rows */
    struct rowspec * rowspec;
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


/* size in bytes to human readable form */
int snprintf_size(char *buf, int blen, double size) {
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

#define MIN  60
#define HR  ((MIN) * 60)
#define DAY ((HR) * 24)

/* time in secondas to human readable form */
int snprintf_time(char * buf, int blen, time_t time) {
    struct {
        uint32_t noday;     /* max = a lot */
        uint32_t nohr  :5;  /* max 24 */
        uint32_t nomin :6; /* max 60 */
        uint32_t nosec :6; /* max 60 */
        uint32_t _pad  :15;
    } x = {0};
    while(time >= DAY) {
        time -= DAY;
        x.noday++;
    }
    while(time >= HR) {
        time -= HR;
        x.nohr++;
    }
    while(time >= MIN) {
        time -= MIN;
        x.nomin++;
    }
    x.nosec = time;

    int wrote = 0;
    if(x.noday)
        wrote += snprintf(buf+wrote, blen-wrote, "%ud", x.noday);
    if(x.nohr && (blen-wrote > 1))
        wrote += snprintf(buf+wrote, blen-wrote, "%uh", x.nohr);
    if(x.nomin && (blen-wrote > 1))
        wrote += snprintf(buf+wrote, blen-wrote, "%um", x.nomin);
    if((blen-wrote) > 1)
        wrote = snprintf(buf+wrote, blen-wrote, "%us", x.nosec);

    return wrote;
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


#define in_addr_cmp(a,b) ((a).s_addr != (b).s_addr)

static inline void swaprow(struct td ** tdata, u_int16_t i, u_int16_t j) {
    if(i == j) 
        return;
    struct td * cpy = tdata[i];
    tdata[i] = tdata[j];
    tdata[j] = cpy;
}

/* 1 if bigger */
static inline int trowcmp(struct td ** tdata, u_int16_t i, u_int16_t j) {
    if(tdata[i][TIME_CIX].time > tdata[j][TIME_CIX].time)
        return 1;
    if(tdata[i][TIME_CIX].time < tdata[j][TIME_CIX].time)
        return 0;
    if(CVIS(COUNT_CIX))
        return tdata[i][COUNT_CIX].uint64_val > tdata[j][COUNT_CIX].uint64_val;
    return 0;
}

/* note that this won't sort rowspec. 
    So make sure to remove any meaningful data from rowspec before calling sort*/
void sort(struct table * t) {
    /* note that first rows in table is header and thus should be excluded from the sort */
    if(t->rows < 3 || !CVIS(TIME_CIX)) 
        return;

    struct td ** tdata = t->data;
    int len = t->rows - 1;

    tdata++;

    uint16_t i, j;

    for(i = 6; i < len; i++) {
        if(trowcmp(tdata, i, i-6))
            swaprow(tdata, i, i-6);
    }

    for(i = 1; i < len; i++) {
        for(j = i; j > 0 && trowcmp(tdata, j, j-1); j--) {
            swaprow(tdata, j, j-1);
        }
    }
}

#define FORMAT_INADDR(a, b) (!opts.r && globals.wladdr && !in_addr_cmp(a, b))

void upsert(struct table * t, struct pkt_digest * dg) {
    struct in_addr inaddr1, inaddr2;
    uint16_t uint16_1, uint16_2;


    if(CVIS(IP4SADDR_CIX)) {
        if(dg->meta.proto_flags&IDF(ID_IPV4)) {
            inaddr1 = dg->ipv4.saddr;
        } else {
            inaddr1.s_addr = INADDR_TEST_NET_1;
        }
    }

    if(CVIS(IP4DADDR_CIX)) {
        if(dg->meta.proto_flags&IDF(ID_IPV4)) {
            inaddr2 = dg->ipv4.daddr;
        } else {
            inaddr2.s_addr = INADDR_TEST_NET_1;
        }
    }

    if(CVIS(SRC_CIX)) {
        if(dg->meta.proto_flags&IDF(ID_UDP)) {
            uint16_1 = dg->udp.source;
        } else if(dg->meta.proto_flags&IDF(ID_TCP)) {
            uint16_1 = dg->tcp.source;
        } else {
            uint16_1 = 0;
        }
    }

    if(CVIS(DST_CIX)) {
        if(dg->meta.proto_flags&IDF(ID_UDP)) {
            uint16_2 = dg->udp.dest;
        } else if(dg->meta.proto_flags&IDF(ID_TCP)) {
            uint16_2 = dg->tcp.dest;
        } else {
            uint16_2 = 0;
        }
    }

    struct td * row;
    uint16_t i;

    if(pthread_spin_lock(&globals.sync)) 
        print_errno_exit(upsert:)

    for(i = 1; i < t->rows; i++) {

        row = t->data[i];

        if(CVIS(SUMMARY_CIX) && dg->meta.proto_flags != row[SUMMARY_CIX].proto)
            continue;
        
        if(CVIS(IP4SADDR_CIX) && in_addr_cmp(row[IP4SADDR_CIX].in_addr_val, inaddr1))
            continue;

        if(CVIS(IP4DADDR_CIX) && in_addr_cmp(row[IP4DADDR_CIX].in_addr_val, inaddr2))
            continue;

        if(CVIS(SRC_CIX) && uint16_1 != row[SRC_CIX].uint16v)
            continue;

        if(CVIS(DST_CIX) && uint16_2 != row[DST_CIX].uint16v)
            continue;

        /* row is the same => update facts */

        if(CVIS(COUNT_CIX)) {
            row[COUNT_CIX].uint64_val++;
        }

        if(CVIS(SIZE_CIX)) {
            row[SIZE_CIX].uint64_val += dg->meta.total_len;
        }

        if(CVIS(TIME_CIX)) {
            row[TIME_CIX].time = time(NULL);
        }

        goto UNLOCK_END;
    }

    if(t->rows >= t->maxrows) {
        row = t->data[t->rows - 1];
        t->rowspec[t->rows - 1].frefresh = 1;
    } else {
        row = t->data[t->rows];
        t->rows++;
    }

    if(CVIS(IP4SADDR_CIX)) {
        if(FORMAT_INADDR(inaddr1, globals.laddr)) {
            row[IP4SADDR_CIX].adrstart = clr_local;
            row[IP4SADDR_CIX].adrend = clr_norm;
        } else {
            row[IP4SADDR_CIX].adrstart = NULL;
            row[IP4SADDR_CIX].adrend = NULL;
        }
        row[IP4SADDR_CIX].in_addr_val = inaddr1;
    }

    if(CVIS(IP4DADDR_CIX)) {
        if(FORMAT_INADDR(inaddr2, globals.laddr)) {
            row[IP4DADDR_CIX].adrstart = clr_local;
            row[IP4DADDR_CIX].adrend = clr_norm;
        } else {
            row[IP4DADDR_CIX].adrstart = NULL;
            row[IP4DADDR_CIX].adrend = NULL;
        }
        row[IP4DADDR_CIX].in_addr_val = inaddr2;
    }

    if(CVIS(SRC_CIX)) {
        if(dg->meta.proto_flags&IDF(ID_IPV4) && FORMAT_INADDR(dg->ipv4.saddr, globals.laddr)) {
            row[SRC_CIX].adrstart = clr_local;
            row[SRC_CIX].adrend = clr_norm;
        } else {
            row[SRC_CIX].adrstart = NULL;
            row[SRC_CIX].adrend = NULL;
        }
        row[SRC_CIX].uint16v = uint16_1;
    }

    if(CVIS(DST_CIX)) {
        if(dg->meta.proto_flags&IDF(ID_IPV4) && FORMAT_INADDR(dg->ipv4.daddr, globals.laddr)) {
            row[DST_CIX].adrstart = clr_local;
            row[DST_CIX].adrend = clr_norm;
        } else {
            row[DST_CIX].adrstart = NULL;
            row[DST_CIX].adrend = NULL;
        }
        row[DST_CIX].uint16v = uint16_2;
    }

    if(CVIS(COUNT_CIX)) {
        row[COUNT_CIX].uint64_val = 1;
    }

    if(CVIS(SIZE_CIX)) {
        row[SIZE_CIX].uint64_val = dg->meta.total_len;
    }

    if(CVIS(SUMMARY_CIX)) {
        row[SUMMARY_CIX].proto = dg->meta.proto_flags;
    }

    if(CVIS(TIME_CIX)) {
       row[TIME_CIX].time = time(NULL);
    }
    
UNLOCK_END:
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
    to store info of currently processed packet in global variable.
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

    pkt_digest.meta.proto_flags = 0;
    pkt_digest.meta.total_len = _h->len;

    while(pkt_digest.meta.nexthop) {
        next = pkt_digest.meta.nexthop;
        pkt_digest.meta.nexthop = NULL;
        next(&pktptr, &pktlen, &pkt_digest);
    }

    upsert(&globals.t, &pkt_digest);
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
        free(globals.t.rowspec);
    }
    puts("done");
    exit(0);
}

void printbl(struct table * t) {
    int wrote;
    unsigned short csz;
    
    tgotoxy(0, 1);

    time_t now = time(NULL);

    for(size_t i = 0; i < t->rows; i++) {
        for(size_t j = 0; j < t->cols; j++) {

            if(!CVIS(j)) 
                continue;

            if(t->rowspec[i].frefresh || !t->data[i][j].cstr[0] || (!CRDONLY(j) && i > 0)) {

                switch(CTP(j)) {
                case CT_PKTSUM:
                    wrote = sprintf_proto(t->data[i][j].cstr, t->data[i][j].proto);
                    break;
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
                case CT_UINT16:
                    if(t->data[i][j].uint16v) {
                        wrote = snprintf(
                            t->data[i][j].cstr, 
                            MCSZ(j), 
                            "%u", t->data[i][j].uint16v);
                    } else {
                        wrote = sprintf(t->data[i][j].cstr, "?");
                    }
                    break;
                case CT_TIME:
                    if(now < 1 || t->data[i][j].time < 1)
                        wrote = sprintf(t->data[i][j].cstr, "?");
                    else
                        wrote = snprintf_time(t->data[i][j].cstr, MCSZ(j), now - t->data[i][j].time);
                    break;
                default:

                    wrote = sprintf(t->data[i][j].cstr, "?");
                    break;
                }

                wrote++;
                if(wrote > CCSZ(j))
                    CCSZ(j) = wrote;
            }
        }

        if(t->rowspec[i].frefresh)
            t->rowspec[i].frefresh = 0;
    }

    sort(t);

    /*
        other loop is needed because certain cells could resize whole column,
        so im iterating over all of them first, and then drawing.
    */

    for(size_t i = 0; i < t->rows; i++) {
        for(size_t j = 0; j < t->cols; j++) {
            if(!CVIS(j)) 
                continue;
            csz = CCSZ(j);
            if(t->data[i][j].adrstart) {
                printf("%s%*.*s%s", 
                    t->data[i][j].adrstart, 
                    csz, csz, 
                    t->data[i][j].cstr, 
                    t->data[i][j].adrend);
            } else {
                printf("%*.*s", csz, csz, t->data[i][j].cstr);
            }
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
    
    t->data = malloc(sizeof(struct td *) * t->maxrows);
    t->rowspec = calloc(t->maxrows, sizeof(struct rowspec));
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
