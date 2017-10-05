#ifndef DNS_SPOOFER_GATWAYINFO_H
#define DNS_SPOOFER_GATWAYINFO_H


#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <netinet/in.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
class GatewayInfo {

public:
    char * getGateway();

};


#endif //DNS_SPOOFER_GATWAYINFO_H
