// This is stolen from
// https://github.com/dove0rz/iftop-android/blob/master/if_nameindex.h
// It is is needen on Android, because Android doesn't have if_nameindex()
// note: for libretroshare, i have added lots of casts to if_nameindex.cc

#ifndef __IF_NAMEINDEX_H_ /* include guard */
#define __IF_NAMEINDEX_H_

#include <netinet/in.h>
#include <netinet/in6.h>
//#include <linux/in.h>
//#include <linux/in6.h>
#include <linux/rtnetlink.h>

#define   AF_LINK         18              /* Link layer interface */

struct if_nameindex {
    unsigned int   if_index;  /* 1, 2, ... */
    char          *if_name;   /* null terminated line name */
};

struct ifaddrs
{
    struct ifaddrs *ifa_next;
    char            ifa_name[16];
    int             ifa_ifindex;
    struct sockaddr *ifa_addr;
    struct sockaddr_storage ifa_addrbuf;
};

struct if_nameindex *if_nameindex(void);


#endif /* __IFTOP_H_ */
