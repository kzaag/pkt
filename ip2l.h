#if !defined(IP2L_H)
#define IP2L_H 1

#include <linux/in.h>

#define IP2L_ERR_NOT_FOUND -3
#define IP2L_ERR_ERRNO     -1
#define IP2L_ERR_EFORMAT   -2


/* [this function uses static buffer, thus it's not thread safe]
 * perform binary search on ip2loc csv file specified by fpath
 * looking for in_addr x
 * put matching csv line into lb which is of lb_len length
 * return > 0 which is amount of iterations on success, 
 * return IP2L_ERR_* on error
 * */
int search_in(const char * fpath, struct in_addr x, char * lb, int lb_len);


#endif
