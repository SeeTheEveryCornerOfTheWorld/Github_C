
#ifndef __IPADDR_H__
#define __IPADDR_H__
/* system include */
/* local include */

// #include "proto.h"
int ipaddr_list (int ifindex, uint32_t *array, int max_elem);
int ipaddr_op (int ifindex, uint32_t addr,int prefix, int addF);

#endif	/* __IPADDR_H__ */

