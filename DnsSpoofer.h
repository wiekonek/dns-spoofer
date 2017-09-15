#ifndef DNS_SPOOFER_DNSSPOOFER_H
#define DNS_SPOOFER_DNSSPOOFER_H

#include <iostream>

using std::cout;
using std::endl;

class DnsSpoofer {
public:
    DnsSpoofer();
    void start_spoofing(char* device);
};


#endif //DNS_SPOOFER_DNSSPOOFER_H
