#if !defined(IP2L_H)
#define IP2L_H 1

#include <linux/in.h>

#define IP2L_ERR_NOT_FOUND -3
#define IP2L_ERR_ERRNO     -1
#define IP2L_ERR_EFORMAT   -2


/* [this function uses static buffer, thus it's not thread safe]
 * perform binary search on ip2loc csv file specified by fpath
 * looking for in_addr x which must be in network order
 * put matching csv line into lb which is of *lb_len length
 * return > 0 which is amount of iterations on success, write strlen(lb) into lb_len 
 * return IP2L_ERR_* on error
 * */
int search_in(const char * fpath, struct in_addr x, char * lb, int * lb_len);

#define COUNTRY_SIZE 12
#define CITY_SIZE 12

#define __ADDRPAIR \
	struct in_addr start; \
	struct in_addr end;

struct addrpair {
	__ADDRPAIR
};

struct db11 {
	__ADDRPAIR
	char country[COUNTRY_SIZE];
	char city[CITY_SIZE];
};

int parse_db11_line(struct db11 * dst, char * line, int len);

#define ASNAME_SIZE 32

#define DOMAIN_SIZE 18
#define ISP_SIZE 24
#define PROXY_TYPE_SIZE (3+1)
/* dont know why ip2location but ip2location says that this is 11 bytes
 * even tho they enumerate possible values and all of them are 3 letters
 * */
#define USAGE_TYPE_SIZE (3+1)
#define THREAT_SIZE 16
struct px11 {
	__ADDRPAIR
	char proxy_type[PROXY_TYPE_SIZE];
	char country[COUNTRY_SIZE];
	char city[CITY_SIZE];
	char isp[ISP_SIZE];
	char domain[DOMAIN_SIZE];	
	char usage_type[USAGE_TYPE_SIZE];
	long asn;
	char asname[ASNAME_SIZE];
	char threat[THREAT_SIZE]; 
};

int parse_px11_line(struct px11 * dst, char * line, int len);


/* strictly speaking 19 is enough (18 + null) 
 *     but i want this to be aligned properly too */
#define NET_SIZE 24
struct asn {
	__ADDRPAIR
	char iprange[NET_SIZE];
	long asn;
	char asname[ASNAME_SIZE];	
};

int parse_asn_line(struct asn * dst, char * line, int len);

/* this buffer must be able to contain at least 2 arbitrary selected lines */
#define LINE_BUF_SZ 512

#endif
