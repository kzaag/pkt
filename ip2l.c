/*
 * ip2location database handlers
 * */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ip2l.h"

/*
 * parse long long from decimal representation, stored in d which is of length l
 * return -1 if edgy input
 * */
 static long long atonll(const char * d, int l) {
	long long ret = 0;
	for(int i = 0; i < l; i++) {
		if(d[i] < '0' || d[i] > '9') {
			return -1;
		}
		ret = (ret*10)+(d[i]-'0');
	}

	return ret;
}

/* will return valid uint32 in long long, or -1
 * set end pointer to the position of '"' char after ip
 * */
static long long parse_in(char * seek_buf, int start, int len, char ** end) {
	if(len-start <= 0)
		return -1;
	char * ptr = memchr(seek_buf+start, '"', len-start);
	if(!ptr)
		return -1;
	*end = ptr;
	long long taddr = atonll(seek_buf+start, ptr-(seek_buf+start));
	if(taddr < 0 || taddr > (__be32)-1) {
		return -1;
	}
	return taddr;
}

/* write line starting at current fd position into lb which must be at least lbl long
 * return IP2L_ERR_EFORMAT if buffer too small
 * return 0 if ok, IP2L_ERR if not. 
 * */
static int grab_line(int fd, char * lb, int * lbl) {
	static char line[LINE_BUF_SZ];
	int i;
	int f = 0;
	
	int r = read(fd, line, sizeof(line));

	if(r <= 0)
		return IP2L_ERR_EFORMAT;

	for(i =0; i < r; i++) {
		if(line[i] == '\n') {
			f=1;
			break;
		}
	}

	if(!f || i >= *lbl)
		return IP2L_ERR_EFORMAT;

	memcpy(lb, line, i);
	lb[i] = 0;
	*lbl = i;

	return 0;
}

/*
 * buf must be set to the opening quote of the 1st ip, like that:
 * "3696211968","3696212223"
 * ^
 * buf must be here
 * will write ips to a,b and return end offset:
 * "3696211968","3696212223"
 *                         ^
 *                         return offset in relation to buf
 * return 0 on fail
 * */
static int parse_inaddr_pair(
		char * buf, int l, 
		struct in_addr * a, 
		struct in_addr * b) {
	
	long long taddr;
	int start = 0;
	char * endp;
	
	if(l <= start || *buf != '"') {
		return 0;
	}

	start++;

	if((taddr = parse_in(buf, start, l, &endp)) == -1)
		return 0;
	a->s_addr = (__be32)taddr;
	
	start = endp - buf;
	start+=3;
	
	if((taddr = parse_in(buf, start, l, &endp)) == -1)
		return 0;
	b->s_addr = (__be32)taddr;
	
	return endp-buf;
}

int search_in(const char * fpath, struct in_addr x, char * lb, int * lb_len) {
	static char seek_buf[LINE_BUF_SZ];
	const int max = sizeof(seek_buf);
	int fd = open(fpath, O_RDONLY);
	if(fd <= 0) {
		return IP2L_ERR_ERRNO;
	}

	size_t r;
	int start, sol;
	int left = 0, 
	    right = lseek(fd, 0, SEEK_END), m;
	struct in_addr saddr, daddr;

	x.s_addr = ntohl(x.s_addr);

	//printf("x=%u\n", x.s_addr);

	int nosteps = 0;

#define creturn(code) { \
		close(fd); \
		return (code); }

	for(;;) {
		if(left > right)
			creturn(IP2L_ERR_NOT_FOUND);

		m = (left+right) / 2;
		
		//printf("l=%d r=%d m=%d\n", left, right, m);
	
		if((m = lseek(fd, m, SEEK_SET)) == (off_t)-1)
			creturn(IP2L_ERR_ERRNO);
		
		r = read(fd, seek_buf, max);
	       	if(r == 0) 
			creturn(IP2L_ERR_NOT_FOUND)
		else if(r < 0)
			creturn(IP2L_ERR_ERRNO)
	
		nosteps++;

		start = -1;

		while(++start < r) {
			if(m || start) {
				if(seek_buf[start] != '\n')
					continue;
				start++;
			}

			sol = start;

			if(parse_inaddr_pair(
					seek_buf+start, 
					r-start, 
					&saddr, &daddr) <= 0) {
				continue;
			}

			if(saddr.s_addr > x.s_addr) {
				/* look left */
				right = m - 1;
				break;
			}

			if(daddr.s_addr < x.s_addr) {
				/* look right */
				left = m + 1;
				break;
			}

			if(lseek(fd, m+sol, SEEK_SET) == (off_t)-1)
                        	creturn(IP2L_ERR_ERRNO);
			if((m = grab_line(fd, lb, lb_len)) < 0)
				creturn(m);
			creturn(nosteps);
		}

		if(start >= r)
			creturn(IP2L_ERR_NOT_FOUND);
	}
}

const char delim[] = {'"', ',', '"'};

/* 0 if was ok otherwise 1 */
static inline int skip_delim(char ** s, int * len) {
	if(*len < sizeof(delim))
		return -1;
	if(memcmp(*s, delim, sizeof(delim)))
		return -1;
	*s += sizeof(delim);
	*len -= sizeof(delim);
	return 0;
}

static inline int skip_to_delim(char ** s, int * len) {
	for(int i = 0; i < *len; i++) {
		if((*s)[i] == delim[0] && 
				*len > i + sizeof(delim) &&
				!memcmp(*s + i, delim, sizeof(delim))) {
			*s += i;
			*len -= i;
			return 0;
		}
	}
	return -1;
}

/* apparently ip2l csvs terminate lines with crlf.
 * */
static inline int skip_to_end(char ** s, int * len) {
	for(int i = 0; i < *len; i++) {
		if((*s)[i] == '\r' && i > 0 && i == *len - 1) {
			*s += i - 1;
			*len -= i - 1;
			return 0;
		}
	}
	return -1;
}

static inline int skip_field(char ** s, int * len) {
	if(skip_delim(s, len))
		return -1;
	if(skip_to_delim(s, len))
		return -1;
	return skip_delim(s, len);
}

static inline int skip_cfield(char ** s, int * l) {
	if(skip_to_delim(s, l))
                return -1;
        return skip_delim(s, l);
}

static inline int fieldcpy(char * f, int flen, char * dst, int dstlen) {
	if(flen < 0 || dstlen < 1)
		return -1;
	dstlen--;
	if(flen > dstlen)
		flen = dstlen;
	memcpy(dst, f, flen);
	dst[flen] = 0;
	return 0;
}

/*
 * -1 on failure, 0 on success
 * */
int parse_db11_line(struct db11 * dst, char * line, int len) {
	int off;
	if((off = parse_inaddr_pair(line, len, &dst->start, &dst->end)) <= 0) {
		return -1;
	}
	line += off;
	len-=off;

	if(skip_field(&line, &len))
		return -1;
	
	char * f = line;
	int fl;

	if(skip_to_delim(&line, &len))
		return -1;

	fl = line - f;

	if(fieldcpy(f, fl, dst->country, COUNTRY_SIZE))
		return -1;

	if(skip_field(&line, &len))
		return -1;

	f = line;
	if(skip_to_delim(&line, &len))
		return -1;

	fl = line - f;

	if(fieldcpy(f, fl, dst->city, CITY_SIZE))
		return -1;
	
	return 0;
}

int skip_fieldcpy(char ** line, int * len, char * dst, int dstl) {
	char * f = *line;
	if(skip_to_delim(line, len))
		return -1;
	int fl = *line - f;
	if(fieldcpy(f, fl, dst, dstl))
		return -1;
	return skip_delim(line, len);
}

/*
 * -1 on failure, 0 on success
 * */
int parse_asn_line(struct asn * dst, char * line, int len) {
	int off;
	if((off = parse_inaddr_pair(line, len, &dst->start, &dst->end)) <= 0) {
		return -1;
	}
	line += off;
	len-=off;

	if(skip_delim(&line, &len))
		return -1;

	if(skip_fieldcpy(&line, &len, dst->iprange, NET_SIZE))
		return -1;


	char asnbuf[11];

	if(skip_fieldcpy(&line, &len, asnbuf, sizeof(asnbuf)))	
		return -1;
		
	dst->asn = atol(asnbuf);

	char * f = line;
	if(skip_to_end(&line, &len))
		return -1;	
	int fl = line - f;
	if(fieldcpy(f, fl, dst->asname, ASNAME_SIZE))
		return -1;

	return 0;
}

int parse_px11_line(struct px11 * dst, char * line, int len) {
	int off;
        if((off = parse_inaddr_pair(line, len, &dst->start, &dst->end)) <= 0) {
                return -1;
        }
        line += off;
        len-=off;
	
      	if(skip_delim(&line, &len))
		return -1;
	
	if(skip_fieldcpy(&line, &len, dst->proxy_type, PROXY_TYPE_SIZE))
		return -1;

	if(skip_cfield(&line, &len))
		return -1;

	if(skip_fieldcpy(&line, &len, dst->country, COUNTRY_SIZE))
                return -1;

	if(skip_cfield(&line, &len))
		return -1;

	if(skip_fieldcpy(&line, &len, dst->city, CITY_SIZE))
		return -1;
	
	if(skip_fieldcpy(&line, &len, dst->isp, ISP_SIZE))
		return -1;

	if(skip_fieldcpy(&line, &len, dst->domain, DOMAIN_SIZE))
		return -1;

	if(skip_fieldcpy(&line, &len, dst->usage_type, USAGE_TYPE_SIZE))
		return -1;

	char asnbuf[16];
	if(skip_fieldcpy(&line, &len, asnbuf, sizeof(asnbuf)))
		return -1;
	dst->asn = atol(asnbuf);

	if(skip_fieldcpy(&line, &len, dst->asname, ASNAME_SIZE))
		return -1;

	if(skip_cfield(&line, &len))
		return -1;

	if(skip_fieldcpy(&line, &len, dst->threat, THREAT_SIZE))
		return -1;

	return 0;
}

