#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>
#include <linux/in.h>

#include "ip2l.h"

void test_ip(const char * ip, const char * const fpath) {
        struct in_addr a;
        if(inet_aton(ip, &a) != 1) {
                printf("invalid ip\n");
                return;
        }
        printf("testing %s... (%u)\n", ip, ntohl(a.s_addr));
        static char dst[320];
        clock_t start = clock();
        int x = search_in(fpath, a, dst, sizeof(dst));
        clock_t end = clock();
        if(x > 0) {
                printf("%s\n", dst);
        }
	*dst = 0;
        printf("t=%.1fμs %d iterations\n", 
		1e6 * (float)((end)-(start)) / CLOCKS_PER_SEC,
		x);
}

int main() {
        const char * db11path = "tmp/IP2LOCATION-LITE-DB11.CSV";
        const char * px11path = "tmp/IP2PROXY-LITE-PX11.CSV";
	const char * asnpath = "tmp/IP2LOCATION-LITE-ASN.CSV";

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

