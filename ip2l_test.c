#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>
#include <linux/in.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "ip2l.h"

#define TYPE_DB11 1
const char * db11path = "tmp/IP2LOCATION-LITE-DB11.CSV";
#define TYPE_PX11 2
const char * px11path = "tmp/IP2PROXY-LITE-PX11.CSV";
#define TYPE_ASN  3
const char * asnpath = "tmp/IP2LOCATION-LITE-ASN.CSV";

void print_iprange(struct in_addr s, struct in_addr d) {
	s.s_addr = htonl(s.s_addr);
	d.s_addr = htonl(d.s_addr);
	char * sc = inet_ntoa(s);
	char dst[strlen(sc)+1];
	strcpy(dst, sc);
	printf("start=%s end=%s ", dst, inet_ntoa(d));
}

int test_addr(const char * const fpath, char *l, int ll, int line, struct in_addr a) {
	static int warn = 0;
	static char lb[LINE_BUF_SZ];
	int lbl;
	int x;
	lbl = sizeof(lb);
	a.s_addr = htonl(a.s_addr);
	if((x = search_in(fpath, a, lb, &lbl)) <= 0) {
		printf("Couldn't find line:"
			"LINE:%d=%*.*s\n", line, ll, ll, l);
		return -1;
	}
	if(x > 25) {
		warn++;
		printf("warn: iterations should be around log_2(~3000000) ~ 22. instead got: %d\n", x);	
		if(warn >= 10)
			return -1;
	}
	if(lbl != ll) {
		printf("returned line:\nLINE=%s\n"
			"has different length than original line\nLINE=%*.*s\n",
			lb, ll, ll, l);
		return -1;
	}
	return 0;
}

/* tests whether all files in ip2l file can be successfuly parsed by handlers present in ip2l.c */
void test_parser(const char * const fpath, int type) {
	static char buf[LINE_BUF_SZ];
	char * ptr = buf;
	int ptrl = sizeof(buf);

#define errnot { \
	printf("test_parser failed: %s\n", strerror(errno)); \
	if(fd > 0) close(fd); \
	exit(2); \
}

#define cret(msg) { \
	printf("%s\n", msg); \
	if(fd > 0) close(fd); \
	exit(2); \
}
	struct db11 db;
	struct px11 px;
	struct asn asn;
	struct addrpair * pair;
	int line = 1;
	int r, s, linestart, off, x;
	int fd = open(fpath, O_RDONLY);
	if(fd < 0) 
		errnot;

	for(;;) {
		r = read(fd, ptr, ptrl);
		if(r < 0)
			errnot
		else if(r == 0) {
			if(ptr-buf)
				cret("read is done but buffer is not empty");
			return;
		}

		r += ptr-buf;
		ptr = buf;
		ptrl = sizeof(buf);
		s = -1;
		linestart = 0;

		while(s++ < r) {
			if(ptr[s] != '\n')
				continue;
			
			switch(type) {
			case TYPE_DB11:
				x = parse_db11_line(&db, ptr+linestart, s-linestart);
				pair = (struct addrpair*)&db;
				break;
			case TYPE_ASN:
				x = parse_asn_line(&asn, ptr+linestart, s-linestart);
				pair = (struct addrpair*)&asn;
				break;
			case TYPE_PX11:
				x = parse_px11_line(&px, ptr+linestart, s-linestart);
				pair = (struct addrpair*)&px;
				break;
			default:
				cret("unrecognized type");
			}
			
			if(x) {
				if(s-linestart == 0) {
					printf("warn: empty line @ %d\n", line);
				} else {
					printf("LINE:%d=%*.*s\n", line, s-linestart, s-linestart, ptr+linestart);
					cret("failed to parse line above");
				}
			} else {
				if(-1 == test_addr(fpath, ptr+linestart, s-linestart, line, pair->start))
					cret("fail");	
				if(-1 == test_addr(fpath, ptr+linestart, s-linestart, line, pair->end))
					cret("fail");
			}
			
			line++;
			linestart = s + 1;
		}

		if(!linestart) {
			printf("for line: (%d) %*.*s\n", r, r, r, ptr);
			cret("invalid file format, or buffer too small");
		}

		/* something is left in the buffer */
		if(linestart < r) {
			off = r-linestart;
			memcpy(buf, ptr+linestart, off);
			ptr = buf+off;
			ptrl = sizeof(buf) - off; 
		} else {
			ptr = buf;
			ptrl = sizeof(buf);
		}
	}
}

void test_ip(const char * ip, const char * const fpath) {
        struct in_addr a;
        if(inet_aton(ip, &a) != 1) {
                printf("invalid ip\n");
                exit(2);
        }
        
	printf("testing %s... (%u)\n", ip, ntohl(a.s_addr));
        
	static char dst[320];
        static struct db11 db;
	static struct asn  asn;
	static struct px11 px;

	int l = sizeof(dst);
	
	clock_t start = clock();
	int x = search_in(fpath, a, dst, &l);
        clock_t end = clock();
        
	if(x > 0) {
                printf("%s\n", dst);
        	
		if(!strcmp(fpath, db11path)) {
			if(parse_db11_line(&db, dst, l)) {
				printf("failed to parse\n");
				exit(1);
			}
			print_iprange(db.start, db.end);	
			printf("country=%s city=%s\n", db.country, db.city);
		} else if(!strcmp(fpath, px11path)) {
			if(parse_px11_line(&px, dst, l)) {
				printf("failed to parse\n");
				exit(1);
			}
			print_iprange(px.start, px.end);
			printf("type=%s country=%s city=%s isp=%s domain=%s usage_type=%s asn=%ld as=%s threat=%s\n",
				px.proxy_type, px.country, px.city, px.isp, px.domain, px.usage_type,
				px.asn, px.asname, px.threat);
		} else if(!strcmp(fpath, asnpath)) {
			if(parse_asn_line(&asn, dst, l)) {
				printf("failed to parse\n");
				exit(1);
			}
			print_iprange(asn.start, asn.end);
			printf("iprange=%s asn=%ld as=%s\n", asn.iprange, asn.asn, asn.asname);
		}

	}

        printf("search time=%.1fμs %d iterations\n", 
		1e6 * (float)((end)-(start)) / CLOCKS_PER_SEC, x);
}

void test_bin_search() {
	printf("#### TESTING GEO ####\n");

	test_ip("0.0.0.0", db11path);
        test_ip("255.255.255.255", db11path);
        test_ip("123.43.54.43", db11path);
        
	test_ip("224.1.1.1", db11path);
	test_ip("192.168.0.1", db11path);
        test_ip("127.0.0.1", db11path);
        test_ip("88.33.139.0", db11path);
        test_ip("88.33.139.255", db11path);
        test_ip("220.80.1.0", db11path);
        test_ip("220.80.14.255", db11path);
        test_ip("220.80.8.42", db11path);
	
	printf("#### TESTING PROXY ####\n");

	test_ip("0.0.0.0", px11path);
	test_ip("1.0.5.1", px11path);
	test_ip("1.0.4.1", px11path);
	test_ip("185.245.80.112", px11path);
	test_ip("1.0.130.112", px11path);
	test_ip("1.0.130.113", px11path);
	test_ip("223.255.247.205", px11path);
	test_ip("255.255.255.255", px11path);

	printf("#### TESTING ASNs ####\n");

	test_ip("0.0.0.0", asnpath);
	test_ip("1.0.0.0", asnpath);
	test_ip("1.0.5.1", asnpath);
	test_ip("255.255.255.255", asnpath);
	test_ip("224.0.0.0", asnpath);
	test_ip("157.240.0.0", asnpath);
}

int main() {

#if defined(IP2L_TEST_COMPAT)	
	printf("testing asn parser...\n");
	test_parser(asnpath, TYPE_ASN);
	printf("testing db11 parser...\n");
	test_parser(db11path, TYPE_DB11);
	printf("testing px11 parser...\n");
	test_parser(px11path, TYPE_PX11);
#else
	test_bin_search();
#endif

}

