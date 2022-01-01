#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <linux/if_pppox.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include "pkt_digest.h"

static char pcaperr[PCAP_ERRBUF_SIZE];

#if defined(DBG)

static int dfd = 0;

static const char timefmt[] = "%Y-%m-%d %H:%M:%S: ";

#define pkt_log(cstr) pkt_logf(cstr); 

/* at least 24 characters */
#define LOG_BUFF_SIZE 1024

static __thread char logbuffer[LOG_BUFF_SIZE];

static int strftimenow() {
	time_t t = time(NULL);
	if(t == (time_t)-1)
		return 0;
	struct tm tm;
	localtime_r(&t, &tm);
	return strftime(logbuffer, LOG_BUFF_SIZE, timefmt, &tm);
}

#if defined(DBG1)
static int strftimenow_ms() {
	struct timeval tv;
	if(gettimeofday(&tv, NULL) != 0) {
		return strftimenow();
	}
	struct tm tm;
	localtime_r(&tv.tv_sec, &tm);
	int tw = strftime(logbuffer, LOG_BUFF_SIZE, timefmt, &tm);
	/* moving back to omit ': ' characters in timefmt */
	tw -= 2;
	tw += snprintf(logbuffer+tw, LOG_BUFF_SIZE-tw, ".%06ld: ", tv.tv_usec);
	return tw;
}
#endif

static void pkt_logf(const char * _fmt, ...) {
	va_list args;
	va_start(args, _fmt);
	int tw = 0;
#if defined(DBG1)
	tw = strftimenow_ms();
#else
	tw = strftimenow();
#endif
	tw += vsnprintf(logbuffer+tw, LOG_BUFF_SIZE-tw, _fmt, args);
	/*
	 * on overflow vsnprintf wont return actual amount of written characters,
	 * instead it will return length of the full array. (also it won't null terminate string)
	 * and people wonder why BOs still happen. It's not scanf, it's inconsitencies like this.
	 * */
	if(tw > LOG_BUFF_SIZE) {
		tw = LOG_BUFF_SIZE;
		/* on overflow terminate text in new line */
		logbuffer[tw-1] = '\n';
	}
	write(dfd, logbuffer, tw);
}



#else

#define pkt_logf(...)
#define pkt_log(...)

#endif

#if defined(DBG1)

/* these symbols are used to extra verbose logging */
#define pkt_logf1 pkt_logf
#define pkt_log1 pkt_log

#else

#define pkt_logf1(...)
#define pkt_log1(...)

#endif

#define print_errno(hdr) { 							\
	pkt_logf(#hdr " %s\n", errno ? strerror(errno) : "unkown error"); 	\
	fprintf(stderr, #hdr " %s\n", errno ? strerror(errno) : "unkown error"); \
}

#define print_errno_ret(hdr) { 		\
	print_errno(hdr);            	\
	return 1;                       \
}

#define print_errno_exit(hdr) {     	\
	print_errno(hdr);                \
	exit(1);                         \
}

#define print_pcap_err(hdr) { 			\
	pkt_logf(#hdr "%s\n", pcaperr);		\
	fprintf(stderr, #hdr " %s\n", pcaperr); \
}

// print_pcap_err and return 1
#define print_pcap_err_ret(hdr) { 	\
	print_pcap_err(hdr);            \
	return 1;                       \
}

/* clean terminal */
#define tclean() printf("\033[H\033[J")
/* dont wrap content on overflow */
#define tsetnowrap() printf("\033[?7l")
/* set cursor position */
#define tgotoxy(x, y) printf("\033[%d;%dH", x, y)

#define SS_PINFO_SZ 40
struct sockstat_info {
	proto_t proto;
	union {
		struct sockaddr_in lsaddr;
		struct sockaddr_in6 lsaddr6;
	};
	union {
		struct sockaddr_in psaddr;
		struct sockaddr_in6 psaddr6;
	};
	char pinfo[SS_PINFO_SZ];
	uint64_t _hash;
};


/* indexes for specified columns within colspec */
#define SUMMARY_CIX   0
/* IPv4/v6 address pair */
#define IPSADDR_CIX  1
#define IPDADDR_CIX  2
/* UDP/TCP port pair */
#define SRC_CIX       3
#define DST_CIX       4

#define CIX_FACT_START 5

#define COUNT_CIX CIX_FACT_START
#define SIZE_CIX  (CIX_FACT_START+1)
#define TIME_CIX  (CIX_FACT_START+2)
#define PINFO_CIX (CIX_FACT_START+3)

/* column type (CT_) represents which union field present under 'struct td' will be used to determine cell cstr 
*/

/* uses .uint64_val and formats output as %d{K/M/G} representing amount of bytes */
#define CT_SIZE 0
/* uses .uint64_val does no extra formatting */
#define CT_UINT64 1
/* uses .in_addr_val and formats output in IpV4 cidr xxx.xxx.xxx.xxx */
#define CT_INADDR 2
/* uses .proto and formats output according to its protocol chain ex. ETH-IP4-UDP */
#define CT_PKTSUM 3
/* uses .time and formats output in number of elapsed seconds, minutes since the measurement. 
   ex. 1h34m2s
   */
#define CT_TIME   4
/* uses .uint16_val, does no extra formatting */
#define CT_PORT 5
/* uses .in6_addr_val, formats output to IPv6 CIDR */
#define CT_IN6ADDR 6

/* no backing field, stored process info */
#define CT_PINFO 7

typedef u_char celltype_t;

struct colspec {
	/*
	   this is text which will be displayed as the column header
	   */
	char * hdr;
	/*
	   maximum allowed size for this column to expand
	   */
	uint16_t max_size;
	/*
	   current size. must be <= max_size and must be >= (strlen(hdr) + 1)
	   this value will dynamically expand to match max_size if needed.
	   note that column will never shrink
	   */
	uint16_t c_size;
	/*
	   datatype stored in the column
	   */
	celltype_t coltype;
	/*
	   controls whether column is displayed - determined by grouping options provided by user
	   */
	u_char visible  : 1;
	/* 
	   if column is marked as read-write (readonly=0) 
	   then its cstr will be refreshed on every print.
	   otherwise its only being set on init
	   */
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
		.hdr = "IPSADDR",
		.c_size = 11,
		/* ipv4/v6 */
		.max_size = 61,
		/* by default ipv4 */
		.coltype = CT_INADDR,
		.visible = 0,
		.readonly = 1,
	},
	{         
		.hdr = "IPDADDR",
		.c_size = 11,
		/* ipv4/v6 */
		.max_size = 61,
		/* by default ipv4 */
		.coltype = CT_INADDR,
		.visible = 0,
		.readonly = 1,
	},
	{         
		.hdr = "SRC",
		.c_size = 6,
		/* xxxxx\0 */
		.max_size = 6,
		.coltype = CT_PORT,
		.visible = 0,
		.readonly = 1,
	},
	{         
		.hdr = "DST",
		.c_size = 6,
		/* xxxxx\0 */
		.max_size = 6,
		.coltype = CT_PORT,
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
		.coltype = CT_SIZE,
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
	}, 
	{
		.hdr = "PINFO",
		.c_size = 6,
		.max_size = SS_PINFO_SZ,
	 	.coltype = CT_PINFO,
       		.visible = 0,
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
	
	/* try to obtain process info */
	int p;

} opts = {
	.d = NULL,
	.i = 1,
	.r = 0,
	.p = 0
};


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
	celltype_t celltype;
	union {
		uint64_t uint64_val;
		uint16_t uint16v;
		struct in6_addr in6_addr_val;
		struct in_addr in_addr_val;
		proto_t proto;
		time_t time;
	};
};

/* cell type */
#define TDTP(row, cix) row[cix].celltype ? row[cix].celltype : CTP(cix) 

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

static struct globals {
	pcap_t * pcap_handle;

	struct in_addr laddr;
	u_char wladdr;

	struct in6_addr laddr6;
	u_char wladdr6;

	int dlt;
	struct table t;
	pthread_t rthr;
	pthread_spinlock_t sync;

	struct sockstat_info ** ssht;
	int ssht_len;
} globals = {
	.pcap_handle = NULL,
	.wladdr = 0,
	.dlt = -1,
	.wladdr6 = 0,
	.t = {
		.data = NULL
	},
	.rthr = 0,

	.ssht = NULL,
	.ssht_len = 0
};

int init_opts(int argc, char * argv[])
{
	int o;
	size_t i = 0;
	char spec = 0;

	while((o = getopt(argc, argv, "p46l:d:g:n:")) != -1) {
		switch(o) {
		case 'd':
			opts.d = strdup(optarg);
			break;
		case '4':
			spec = 4;
			break;
		case '6':
			spec = 6;
			break;
		case 'l':
			switch(spec) {
			case 6:
				if(inet_pton(AF_INET6, optarg, &globals.laddr6)) {
					fprintf(stderr, "%s: invalid option -- 'l' %s", argv[0], optarg);
					exit(1);
				}
				globals.wladdr6 = 1;
			case 4:
			default:
				if(!inet_aton(optarg, &globals.laddr)) {
					fprintf(stderr, "%s: invalid option -- 'l' %s", argv[0], optarg);
					exit(1);
				}
				globals.wladdr = 1;
			}
			break;
		case 'g':
			for(;;) {
				if(!optarg[i]) 
					break;
				switch(optarg[i]) {
				case 's':
					CVIS(SUMMARY_CIX) = 1;
					break;
				case 'z':
					CVIS(IPSADDR_CIX) = 1;
					break;
				case 'x':
					CVIS(IPDADDR_CIX) = 1;
					break;
				case 'c':
					CVIS(SRC_CIX) = 1;
					break;
				case 'v':
					CVIS(DST_CIX) = 1;
					break;
				default:
					fprintf(stderr, "%s: unkown group option -- %c\n", argv[0], optarg[i]);
					exit(1);
				}
				i++;
			}
			break;
		case 'n':
			opts.i = atoi(optarg);
			if(opts.i <= 0) {
				fprintf(stderr, "%s: invalid option -- 'n' %s\n", argv[0], optarg);
				exit(1);
			}
			break;
		case 'p':
			opts.p = 1;
			CVIS(PINFO_CIX) = 1;
			break;
		default:
			exit(1);
		}
	}

	return 0;
}


/* size in bytes to human readable form */
static int snprintf_size(char *buf, int blen, double size) {
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

/* time in seconds to human readable form */
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
		wrote += snprintf(buf+wrote, blen-wrote, "%us", x.nosec);

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

#define IS_LADDR(a) (globals.wladdr && !in_addr_cmp((a), globals.laddr))
#define IS_LADDR6(a) (globals.wladdr6 && !memcmp((a), &globals.laddr6, sizeof(struct in6_addr)))

/* determines if specified address is local on the interface and can be pretty printed */
#define FORMAT_INADDR(a) (!opts.r && IS_LADDR(a))
/* same as FORMAT_INADDR but for ipv6, a must be pointer to in6_addr */
#define FORMAT_IN6ADDR(a) (!opts.r && IS_LADDR6(a)) 

/* check if digest contains specified proto_id */
static inline int isproto(struct pkt_digest * dg, proto_t id) {
	return dg->meta.proto_flags&IDF(id);
}

/* 
   determines if specified packet should be grouped with row
   cix is column index. this can be either IPSADDR_CIX or IPSADDR_CIX
   returns 1 if packet matches or if column is not visible, otherwise returns 0 
   */
static inline int groupip(struct pkt_digest * dg, int cix, struct td * row) {
	if(CVIS(cix)){
		if(isproto(dg, ID_IPV4)) {
			if(in_addr_cmp(row[cix].in_addr_val, 
					cix == IPSADDR_CIX ? dg->ipv4.saddr : dg->ipv4.daddr))
				return 0;
		} else if(isproto(dg, ID_IPV6)) {
			if(memcmp(cix == IPSADDR_CIX ? &dg->ipv6.saddr : &dg->ipv6.daddr, 
						&row[cix].in6_addr_val, sizeof(struct in6_addr)))
				return 0;
		} else if(row[cix].in_addr_val.s_addr != INADDR_TEST_NET_1) {
			return 0;
		}
	}
	return 1;
}

/*
   set cell specified by column index (cix) and row to ip value 
   do nothing if column is not visible
   cix may be IPSADDR_CIX or IPDADDR_CIX
   */
static inline void setipcell(struct pkt_digest * dg, int cix, struct td * row) {
	if(!CVIS(cix)) {
		return;
	}

	if(isproto(dg, ID_IPV4)) {
		struct in_addr a =  cix == IPSADDR_CIX ? dg->ipv4.saddr : dg->ipv4.daddr;
		row[cix].celltype = 0; /* return type to default - ipv4 */
		row[cix].in_addr_val = a;
		if(FORMAT_INADDR(a)) {
			row[cix].adrstart = clr_local;
			row[cix].adrend = clr_norm;
		} else {
			row[cix].adrstart = NULL;
			row[cix].adrend = NULL;
		}
	} else if(isproto(dg, ID_IPV6)) {
		struct in6_addr * i6 =  cix == IPSADDR_CIX ? &dg->ipv6.saddr : &dg->ipv6.daddr;
		row[cix].celltype = CT_IN6ADDR; /* override default column typ to ipv6 */
		row[cix].in6_addr_val = *i6;
		if(FORMAT_IN6ADDR(i6)) {
			row[cix].adrstart = clr_local;
			row[cix].adrend = clr_norm;
		} else {
			row[cix].adrstart = NULL;
			row[cix].adrend = NULL;
		}
	} else {
		row[cix].celltype = 0;
		row[cix].in_addr_val.s_addr = INADDR_TEST_NET_1;
		row[cix].adrstart = NULL;
		row[cix].adrend = NULL;
	}
}

/* 
   determines if specified packet should be grouped with row
   cix is column index. this can be either SRC_CIX or DST_CIX
   returns 1 if packet matches or if column is not visible, otherwise returns 0 
   */
static inline int group_port(struct pkt_digest * dg, int cix, struct td * row) {
	if(CVIS(cix)){
		if(isproto(dg, ID_TCP)) {
			if((cix == SRC_CIX ? dg->tcp.source : dg->tcp.dest) != row[cix].uint16v) {
				return 0;
			}
		} else if(isproto(dg, ID_UDP)) {
			if((cix == SRC_CIX ? dg->udp.source : dg->udp.dest) != row[cix].uint16v) {
				return 0;
			}
		} else if(row[cix].uint16v) {
			return 0;
		}
	}
	return 1;
}

/*
   set cell specified by column index (cix) and row to tcp / udp port value 
   do nothing if column is not visible

   cix may be SRC_CIX or DST_CIX
   */
static inline void setportcell(struct pkt_digest * dg, int cix, struct td * row) {
	if(!CVIS(cix))
		return;

	if(isproto(dg, ID_UDP)) {
		row[cix].uint16v = (cix == SRC_CIX ? dg->udp.source : dg->udp.dest);
	} else if(isproto(dg, ID_TCP)) {
		row[cix].uint16v = (cix == SRC_CIX ? dg->tcp.source : dg->tcp.dest);
	} else {
		row[cix].uint16v = 0;
	}

	if(	( isproto(dg, ID_IPV4) && FORMAT_INADDR(cix == SRC_CIX ? dg->ipv4.saddr : dg->ipv4.daddr) ) ||
		( isproto(dg, ID_IPV6) && FORMAT_IN6ADDR(cix == SRC_CIX ? &dg->ipv6.saddr : &dg->ipv6.daddr))
	  ) {
		row[cix].adrstart = clr_local;
		row[cix].adrend = clr_norm;
	} else {
		row[cix].adrstart = NULL;
		row[cix].adrend = NULL;
	}
}

void upsert(struct table * t, struct pkt_digest * dg) {

	struct td * row;
	uint16_t i;

	if(pthread_spin_lock(&globals.sync)) 
		print_errno_exit(upsert:)

	for(i = 1; i < t->rows; i++) {

		row = t->data[i];

		if(CVIS(SUMMARY_CIX) && dg->meta.proto_flags != row[SUMMARY_CIX].proto)
			continue;

		if(!groupip(dg, IPSADDR_CIX, row))
			continue;

		if(!groupip(dg, IPDADDR_CIX, row))
			continue;

		if(!group_port(dg, SRC_CIX, row))
			continue;

		if(!group_port(dg, DST_CIX, row))
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

	setipcell(dg, IPSADDR_CIX, row);
	setipcell(dg, IPDADDR_CIX, row);

	setportcell(dg, SRC_CIX, row);
	setportcell(dg, DST_CIX, row);

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

	ret = 0;

	for(pcap_if_t *d=devs; d!=NULL; d=d->next) {

		if(opts.d != NULL && strcmp(d->name, opts.d)) {
			continue;
		}

		for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {

			if(!globals.wladdr && a->addr->sa_family == AF_INET) {
				globals.laddr.s_addr = ((struct sockaddr_in*)a->addr)->sin_addr.s_addr;
				globals.wladdr = 1;
			}

			if(!globals.wladdr6 && a->addr->sa_family == AF_INET6) {
				memcpy( &globals.laddr6, 
					&((struct sockaddr_in6*)a->addr)->sin6_addr, 
					sizeof(globals.laddr6));
				globals.wladdr6 = 1;
			}

			if(!opts.d) 
				opts.d = strdup(d->name);
		}

		return 0;
	}

	fprintf(stderr, "get_device_info: couldnt find device\n");
	return 1;
}

void rcv_pkt(u_char * const args, const struct pcap_pkthdr * const _h, const u_char * const _p) {

	/* since pcap will run rcv_pkt in single thread it should be ok to
	 * to store info of currently processed packet in global variable. */
	static struct pkt_digest pkt_digest;
	
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


void cleanup()
{
	const char ct[] = "cleanup... ";
	pkt_log("starting cleanup\n");
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
	if(globals.ssht) {
		for(size_t i = 0; i < globals.ssht_len; i++)
			free(globals.ssht[i]);
	}

	pkt_log("done cleanup\n");

#if defined(DBG)
	if(dfd > 0) 
		close(dfd);
#endif 

	puts("done");
	exit(0);
}

int is_laddr_any(struct td * row, int cix) {
	switch(TDTP(row, cix)) {
	case CT_INADDR:
		return IS_LADDR(row[cix].in_addr_val);
	case CT_IN6ADDR:
		return IS_LADDR6(&row[cix].in6_addr_val);
	}
	return 0;
}

int saddr_from_td(struct td * row, int cix, int pix, 
		struct sockaddr_in * saddr, struct sockaddr_in6 * saddr6) {
	if(!CVIS(pix))
		return 0;
	switch(TDTP(row, cix)) {
	case CT_INADDR:
		saddr->sin_family = AF_INET;
		saddr->sin_addr.s_addr = row[cix].in_addr_val.s_addr;	
		saddr->sin_port = row[pix].uint16v;
		return 1;
	case CT_IN6ADDR:
		saddr6->sin6_family = AF_INET6;
		saddr6->sin6_addr = row[cix].in6_addr_val;
		saddr6->sin6_port = row[pix].uint16v;
		return 1;
	}

	return 0;
}

/* return 1 if ok,
 * 0 otherwise
 * */
int set_ss_sadr_from_row(struct td * row, struct sockstat_info * buf) {
	if(is_laddr_any(row, IPSADDR_CIX)) {
		if(!saddr_from_td(row, IPSADDR_CIX, SRC_CIX, &buf->lsaddr, &buf->lsaddr6))
			return 0;
		if(!saddr_from_td(row, IPDADDR_CIX, DST_CIX, &buf->psaddr, &buf->psaddr6))
			return 0;
		return 1;
	} else if(is_laddr_any(row, IPDADDR_CIX)) {
		if(!saddr_from_td(row, IPDADDR_CIX, DST_CIX, &buf->lsaddr, &buf->lsaddr6))
			return 0;
		if(!saddr_from_td(row, IPSADDR_CIX, SRC_CIX, &buf->psaddr, &buf->psaddr6))
			return 0;
		return 1;
	}
	return 0;
}	

static inline void fnv1a_step(uint64_t * h, const unsigned char * d, int dl) {
	while(dl--) {
		*h ^= (uint64_t)*d;
		d++;
		*h *= 0x100000001b3;
	}
}

/* return 0 on failure */
uint64_t sshf(struct sockstat_info * ss) {
	uint64_t hash = 0xcbf29ce484222325;
	if(ss->proto&IDF(ID_IPV6)) {
		fnv1a_step(&hash, (unsigned char *)&ss->lsaddr6.sin6_addr, sizeof(ss->lsaddr6.sin6_addr));
		fnv1a_step(&hash, (unsigned char *)&ss->lsaddr6.sin6_port, sizeof(ss->lsaddr6.sin6_port));
		fnv1a_step(&hash, (unsigned char *)&ss->psaddr6.sin6_addr, sizeof(ss->psaddr6.sin6_addr));
		fnv1a_step(&hash, (unsigned char *)&ss->psaddr6.sin6_port, sizeof(ss->psaddr6.sin6_port));	
	} else if(ss->proto&IDF(ID_IPV4)){
		fnv1a_step(&hash, (unsigned char*)&ss->lsaddr.sin_addr, sizeof(ss->lsaddr.sin_addr));
		fnv1a_step(&hash, (unsigned char *)&ss->lsaddr.sin_port, sizeof(ss->lsaddr.sin_port));
		fnv1a_step(&hash, (unsigned char *)&ss->psaddr.sin_port, sizeof(ss->psaddr.sin_port));
		fnv1a_step(&hash, (unsigned char*)&ss->psaddr.sin_addr, sizeof(ss->psaddr.sin_addr));
	} else {
		return 0;
	}
	fnv1a_step(&hash, (unsigned char *)&ss->proto, sizeof(ss->proto));
	if(!hash)
		hash++;
	return hash;
}


static struct sockstat_info * ssht_lookup(struct sockstat_info * req) {
	uint64_t hash = sshf(req);
	req->_hash = hash;
	hash %= globals.ssht_len;
	uint64_t init_hash = hash;
	struct sockstat_info * i;
	
	pkt_logf1("ssht_lookup l:%u:%d p:%u:%d proto=%d  hash=%lu \n", 
			req->lsaddr.sin_addr.s_addr, req->lsaddr.sin_port,
                        req->psaddr.sin_addr.s_addr, req->psaddr.sin_port,
			req->proto, req->_hash);



	for(;;) {
		i = globals.ssht[hash];
		/*
		 * i can return here because element cannot be present behind a hole in hash table
		 * 	( elements can only be added and never removed )
		 * */
		if(!i)
			return NULL;	
		if(i->_hash == req->_hash)
		       return i;
		hash = (hash + 1) % globals.ssht_len;
		if(hash == init_hash)
			return NULL;
	}
	return NULL;
}


static struct sockstat_info * ssht_row_lookup(struct td * row) { 
	static struct sockstat_info buf;
	if(!CVIS(SUMMARY_CIX))
		return NULL;
	int flags = IDF(ID_IPV4) | IDF(ID_IPV6) | IDF(ID_UDP) | IDF(ID_TCP);
	buf.proto = row[SUMMARY_CIX].proto & flags;
	if(!set_ss_sadr_from_row(row, &buf))
		return NULL;
	return ssht_lookup(&buf);
}

/*
 * return number of written bytes	
 * */
static int write_into_cell_cstr(struct table * t, int i, int j, time_t now) {
	
	struct sockstat_info * si;
	int wrote;
	celltype_t celltype;

	celltype = t->data[i][j].celltype;
	if(!celltype) {
		celltype = CTP(j);
	}

	switch(celltype) {
	case CT_PKTSUM:
		wrote = sprintf_proto(t->data[i][j].cstr, t->data[i][j].proto);
		break;
	case CT_SIZE:
		wrote = snprintf_size(t->data[i][j].cstr, MCSZ(j), (double)t->data[i][j].uint64_val);
		break;
	case CT_INADDR:

		if(t->data[i][j].in_addr_val.s_addr == INADDR_TEST_NET_1) {
			wrote = sprintf(t->data[i][j].cstr, "?");
		} else {
			wrote = snprintf(
				t->data[i][j].cstr, 
				MCSZ(IPSADDR_CIX), 
				inet_ntoa(t->data[i][j].in_addr_val));
		}
		break;
		
	case CT_UINT64:
		wrote = snprintf(t->data[i][j].cstr, MCSZ(j), "%lu", t->data[i][j].uint64_val);
		break;

	case CT_PORT:
		if(t->data[i][j].uint16v) {
			wrote = snprintf(t->data[i][j].cstr, MCSZ(j), "%u", t->data[i][j].uint16v);
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
	
	case CT_IN6ADDR:
		if(inet_ntop(AF_INET6, &t->data[i][j].in6_addr_val, t->data[i][j].cstr, MCSZ(j)))
			wrote = strlen(t->data[i][j].cstr);
		else
			wrote = sprintf(t->data[i][j].cstr, "!(err=%d)", errno);
		break;
	case CT_PINFO:
		si = ssht_row_lookup(t->data[i]);
		if(si) {
			strncpy(t->data[i][j].cstr, si->pinfo, SS_PINFO_SZ);
			/* just sanity thing here */
			t->data[i][j].cstr[SS_PINFO_SZ-1] = 0;
			wrote = strlen(t->data[i][j].cstr);
		} else {
			wrote = sprintf(t->data[i][j].cstr, "?");
		}
		break;
	default:
		wrote = sprintf(t->data[i][j].cstr, "?");
		break;
	}

	return wrote;

}

void printbl(struct table * t) {
	unsigned short csz;
	int wrote;

	tgotoxy(0, 1);

	time_t now = time(NULL);

	for(size_t i = 0; i < t->rows; i++) {
		for(size_t j = 0; j < t->cols; j++) {

			if(!CVIS(j)) 
				continue;

			if(t->rowspec[i].frefresh || !t->data[i][j].cstr[0] || (!CRDONLY(j) && i > 0)) {	
				wrote = write_into_cell_cstr(t, i, j, now) + 1;
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


	int maxcap = 40;
	/* predefined limit + 1 to account for header row */
	t->maxrows = maxcap + 1;
	/* 1 because of header row */
	t->rows = 1;
	t->cols = sizeof(colspec)/sizeof(struct colspec);

	pkt_logf("initbl: %d rows, %d cols\n", t->maxrows, t->cols);
	
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
#if defined(DBG)
	for(size_t j = 0; j < t->cols; j++) {
		if(!colspec[j].visible)
			continue;
		pkt_logf("initbl allocated: %d bytes for cells in column %s\n", t->maxrows * colspec[j].max_size, colspec[j].hdr);
	}
#endif
	pkt_logf("initbl allocated: %d bytes for rowspec\n", sizeof(struct rowspec) * t->maxrows);
	pkt_logf("initbl allocated: %d bytes for %d rows\n", sizeof(struct td *) * t->maxrows, t->maxrows);
	pkt_logf("initbl allocated: %d bytes for %d cols\n", sizeof(struct td) * t->cols * t->maxrows, t->cols);
}

static inline int is_white_char(char c) {
	switch(c) {
	case '\n':
		return 1;
	case '\t':
		return 1;
	case ' ': 
		return 1;
	}
	return 0;
}

char * skip_white_chars(char * buf, int r) {
	if(!buf || !*buf)
		return NULL;
	while(*buf) {
		if(is_white_char(*buf)) {
			if(r)
				return buf;
			else
				buf++;
		} else {
			if(r)
				buf++;
			else
				return buf;
		}
	}
	return NULL;
}

/* 
 * this is not thread safe
 * parse source ip4/ip6 cidr s which is of length l 
 * 	into dst which must be at least sizeof(struct sockaddr_in6) 
 * return 1 on success 0 on failure
 * */
static int inet_atos(const char * const s, int l, void * dst) {
	if(l <= 3)
		return 0;
	
	static char addr_buf[80];
	int isv6 = s[0] == '[';
	char * sep = memchr(s, isv6 ? ']' : ':', l);
	if(!sep)
		return 0;
	
	if((sep-s) > (sizeof(addr_buf) -1))
		return 0;
	memcpy(addr_buf, s, sep-s);
	addr_buf[sep-s] = 0;

	if(isv6) {
		struct sockaddr_in6 * saddr6 = (struct sockaddr_in6*)dst;
		saddr6->sin6_family = AF_INET6;
		if(!inet_pton(AF_INET6, addr_buf + 1, &saddr6->sin6_addr))
			return 0;
		/* [::1]:ddddd
		 *     ^
		 *     because sep is here */
		sep+=2;
	} else {
		struct sockaddr_in * saddr = (struct sockaddr_in*)dst;
		saddr->sin_family = AF_INET;
		if(!inet_aton(addr_buf, &saddr->sin_addr))
			return 0;
		/* 0.0.0.0:dddd
		 *        ^
		 *        because sep is here
		 */
		sep++;
	}

	int plen = (s+l) - sep;
	if(plen > 5 || plen <= 0)
		return 0;
	memcpy(addr_buf, sep, plen);
	addr_buf[plen] = 0;
	int _p = atoi(addr_buf);
	if(_p <= 0)
		return 0;
	if(isv6)
		((struct sockaddr_in6*)dst)->sin6_port = _p;
	else
		((struct sockaddr_in*)dst)->sin_port = _p;
	
	return 1;
}

/* 1 if ok, 0 if not */
static int parse_ss_saddr(char * start, char * end, void * dst, struct sockstat_info * i) {
	if(!inet_atos(start, end-start, dst))
		return 0;
	unsigned short af = *((unsigned short*)dst);
	switch(af) {
	case AF_INET:
		i->proto |= IDF(ID_IPV4);
		break;
	case AF_INET6:
		i->proto |= IDF(ID_IPV6);
		break;
	default:
		return 0;		
	}
	return 1;
}

/*
 *	return start of new line,
 *	buf must be null terminated
 * */
static char * parse_ss_line(char * buf, struct sockstat_info * i) {
	char * s;
	int mode = 0;
	
	while(*buf) {
		if(!(buf = skip_white_chars(buf, 0)))
			return NULL;
		s = buf;
		/* flag '1' means that we skip TO white char */
		if(!(buf = skip_white_chars(buf, 1)))
			return NULL;
		switch(mode) {
			/* Netid*/
			case 0:
				if((buf - s) != 3)
					return NULL;
				/* zero the proto on first use */
				i->proto = 0;
				if(!memcmp(s, "tcp", 3)) {
					i->proto |= IDF(ID_TCP);
				} else if(!memcmp(s, "udp", 3)) {
					i->proto |= IDF(ID_UDP);	
				} else {
					return NULL;
				}
				mode++;
				break;		
			/* State */
			case 1:
				mode++;
				break;
			/* recv-q */
			case 2:
				mode++;
				break;
			/* send-q */
			case 3:
				mode++;
				break;
			/* laddr:port */
			case 4:	
				if(!parse_ss_saddr(s, buf, &i->lsaddr, i))
					return NULL;
				mode++;
				break;
			/* paddr:port */
			case 5:
				if(!parse_ss_saddr(s, buf, &i->psaddr, i))
					return NULL;
				mode++;
				break;
			/* psum */
			case 6:
				if(buf-s >= SS_PINFO_SZ) {	
					memcpy(i->pinfo, s, SS_PINFO_SZ-1);
					i->pinfo[SS_PINFO_SZ-1] = 0;
				} else {
					memcpy(i->pinfo, s, buf-s);
					i->pinfo[buf-s] = 0;
				}
				buf = skip_white_chars(buf, 0);
				/* if next line exists then return it */
				if(buf)
					return buf;
				/* otherwise return end of string */
				s += strlen(s);
				return s;
			default:
				return NULL;
		}
	}
	return NULL;	
}

/* insert into ssht, which is of len ssht_len, element ss.
 * note that ss will be copied and mallocked.
 * return 1 on success, 0 on failure 
 * */
int insert_ssht(struct sockstat_info ** ssht, int ssht_len, struct sockstat_info *ss) {
	uint64_t hash = sshf(ss);
	if(!hash)
		return 0;
	ss->_hash = hash;

	hash %= ssht_len;
	
	uint64_t initial_hash = hash;
	struct sockstat_info ** sp;

	for(;;) {
		sp = &ssht[hash];
		if(!*sp) {
			*sp = malloc(sizeof(struct sockstat_info));
			break;
		}
		hash = (hash + 1) % ssht_len;
		if(hash == initial_hash)
			return 0;
		
	};
	
	memcpy(*sp, ss, sizeof(**sp));

	return 1;
}

void set_ssht(struct sockstat_info ** ssht, int ssht_len) {
	
	if(ssht == NULL || ssht_len == 0) {
		return;
	}

	for(int i = 0; i < ssht_len; i++) {
		if(!ssht[i])
			continue;
		free(ssht[i]);
		ssht[i] = NULL;
	}

	pid_t pid;
	int status;
	int pipefd[2];
	int close_pipe = 0;

	if(pipe(pipefd)) {
		pkt_logf("%s: pipe: %s\n", __func__, strerror(errno));
		goto ERR;
	}

	close_pipe = 1;

	if((pid = fork()) == 0) {
		/* replace stdout, stderr, and close pipe - not needed any more  */
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		close(pipefd[0]);

		const char * paths[] = {
			"/bin/ss",
			"/usr/bin/ss",
			"/usr/sbin/ss",
			"/sbin/ss"
		};

		for(int i = 0; i < sizeof(paths); i++) {
			/* 
			 * -t = tcp
			 * -u = udp
			 * -p = show process
			 * -H = suppress header
			 * -O = one line
			 * -n = dont try to resolve service names
			 * */
			execl(paths[i], "ss", "-tpuHOn", NULL);
		}	

		/* if we are here then all of the execl must have failed */
		char * e = strerror(errno);
		write(STDOUT_FILENO, e, strlen(e));
			
		_exit(1);
	}

	if(pid == -1) {	
		pkt_logf("%s: fork: %s\n", __func__, strerror(errno));
		goto ERR;
	}

	close(pipefd[1]);
	if(waitpid(pid, &status, 0) == -1) {
		pkt_logf("%s: waitpid: %s\n", __func__, strerror(errno));
		goto ERR;
	}

	static char pistr[2048];
	char * pistr_ptr = pistr;
	char * parsed = NULL;
	int pistr_len = sizeof(pistr) - 1;
	int nonce = 0, off = 0;
	static struct sockstat_info li;

	for(;;) {
		/* couldn't parse full buffer */
		if(pistr_len <= 0) {
			pkt_logf("%s: warn: unrecognized ss format, or buffer too small\n", __func__);
			break;
		}
		pistr_len = read(pipefd[0], pistr_ptr, pistr_len);
		if(pistr_len <= 0)
			break;
		/* pkt_logf("done read, pistr_len = %d += %d, pistr_ptr reset\n", pistr_len, pistr_ptr-pistr); */
		pistr_ptr[pistr_len] = 0;
		pistr_len += pistr_ptr-pistr;
		pistr_ptr = pistr;

		if(!nonce) {
		       	if(!WIFEXITED(status) || WEXITSTATUS(status)) {
				pkt_logf("%s: call to ss failed '%s'\n", __func__, pistr);
				goto ERR;
			}
			nonce = 1;
		}
	
		for(;;) {
			/* bzero(&li, sizeof(li)); */
			parsed = parse_ss_line(pistr_ptr, &li);
			if(!parsed) {
				off = (pistr+pistr_len) - pistr_ptr;		
				/* pkt_logf("failed to parse, offset=%d len=%d\n", off, sizeof(pistr)-1-off);*/
				memcpy(pistr, pistr_ptr, off);
				pistr_ptr = pistr+off;
				pistr_len = sizeof(pistr) - 1 - off;
				break;
			}
			
			if(!insert_ssht(ssht, ssht_len, &li)) {
				pkt_logf("%s: couldn't insert ss info into ssht\n", __func__);
				goto ERR;
			}

			pistr_ptr = parsed;
			if(!*parsed) {
				pistr_ptr = pistr;
				pistr_len = sizeof(pistr) - 1;
				break;
			}	
		}

	}
	if(close_pipe)
		close(pipefd[0]);
	return;
ERR:
	pkt_logf("won't try to %s any more\n", __func__);
	opts.p = 0;
	if(close_pipe)
		close(pipefd[0]);
}

#define CLOCK_DIF_MICRO(start, end) (1e6 * (float)((end)-(start)) / CLOCKS_PER_SEC)

void * run_readloop(void * args) {
	pkt_logf("started readloop\n");

#if defined(DBG1)	
	clock_t start, end;
#endif

	for(;;) {
		if(opts.p) {
#if defined(DBG1)
			start = clock();
#endif	
			set_ssht(globals.ssht, globals.ssht_len);
#if defined(DBG1)
			end = clock();
			pkt_logf1("set_ssht done in %.1f μs\n", CLOCK_DIF_MICRO(start, end));
#endif
		}
#if defined(DBG1)
		start = clock();
#endif
		if(pthread_spin_lock(&globals.sync)) 
			print_errno_exit(run_readloop:);
		printbl(&globals.t);
		pthread_spin_unlock(&globals.sync);
#if defined(DBG1)
		end = clock();		
		pkt_logf1("printbl done in %.1f μs\n", CLOCK_DIF_MICRO(start, end));
#endif		
		sleep(opts.i);
	}
	return NULL;
}

void pkt_logf_laddr6() {
	char buff[60];
	if(!inet_ntop(AF_INET6, &globals.laddr6, buff, 60)){
		print_errno_exit(inet_ntop laddr6: );
	}
	pkt_logf("laddr6: %s\n", buff);
}

void init_ssht() {
	globals.ssht_len = 160;
	globals.ssht = calloc(globals.ssht_len, sizeof(*globals.ssht));
	if(!globals.ssht)
		print_errno_exit(ssht calloc:);
	pkt_logf("init_ssht allocated %d bytes for hashtable (len=%d)\n", 
			globals.ssht_len * sizeof(*globals.ssht), globals.ssht_len);
}

int main(int argc, char *argv[]) {

	if(init_opts(argc, argv)) 
		return 1;

#if defined(DBG)
	dfd = open("out", O_WRONLY|O_CREAT|O_APPEND, 0644);
	if(dfd == -1)
		print_errno_ret(open debug:);
#endif
	pkt_log("pkt starting\n");

	if(get_device_info()) 
		return 1;
	
	pkt_logf("device: %s\n", opts.d); 
	pkt_logf("printbl interval: %ds\n", opts.i);
	if(globals.wladdr)
		pkt_logf("laddr4: %s\n", inet_ntoa(globals.laddr));
	if(globals.wladdr6)
		pkt_logf_laddr6();

	if (!(globals.pcap_handle = pcap_create(opts.d, pcaperr)))
		print_pcap_err_ret(pcap_create:)

	int snaplen = 
		/* im only using linux_sll, and 802.3 headers. latter is bigger */
		sizeof(struct ethhdr)
		+ sizeof(struct pppoe_hdr)
		/* max ipv4, ipv6  */
		+ sizeof(struct iphdr)+40
		/* also max udp header size */ 
		+ sizeof(struct tcphdr);

	pkt_logf("snaplen: %d\n", snaplen);

	if (pcap_set_snaplen(globals.pcap_handle, snaplen)) 
		print_errno_ret(pcap_set_snaplen:)

	if(pcap_set_immediate_mode(globals.pcap_handle, 1)) 
		print_errno_ret(pcap_set_immediate_mode:)   

	if(pcap_activate(globals.pcap_handle)) 
		print_errno_ret(pcap_activate:)

	globals.dlt = pcap_datalink(globals.pcap_handle);

	tclean();
	tsetnowrap();
	tgotoxy(0,0);

	signal(SIGINT, cleanup);

	initbl(&globals.t);

	if(opts.p)
		init_ssht();

	pthread_spin_init(&globals.sync, 0);
	
	if(pthread_create(&globals.rthr, NULL, run_readloop, NULL)) 
		print_errno_ret(pthread_create:)
	
	pkt_logf("starting pcap_loop\n");

	if(pcap_loop(globals.pcap_handle, -1, rcv_pkt, NULL)) 
		print_errno_ret(pcap_loop:)

	cleanup();
	return 0;
}
