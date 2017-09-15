#include <iostream>
#include "ArpSpoofer.h"
#include "DnsSpoofer.h"


int main() {
    if(fork()){
        auto arpSpoofer = new ArpSpoofer();
        arpSpoofer->start_spoofing("wlo1", "", "");
    } else {
        DnsSpoofer *dnsSpoofer = new DnsSpoofer();
        dnsSpoofer->start_spoofing("wlo1");
    }


    return 0;
}