#ifndef DNS_SPOOFER_DNSSPOOFER_H
#define DNS_SPOOFER_DNSSPOOFER_H

static const char *const FILTER_DNS = "udp and port 53";

#include <iostream>
#include <net/if.h>
#include <pcap/pcap.h>
#include<linux/if_ether.h>
#include<netinet/ip.h>    //Provides declarations for ip header



using std::cout;
using std::endl;

class DnsSpoofer {
public:
    DnsSpoofer();
    void start_spoofing(char* device);
private:
    char *_errbuf;
};


#endif //DNS_SPOOFER_DNSSPOOFER_H
