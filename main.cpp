#include <iostream>
#include "ArpSpoofer.h"
#include "DnsSpoofer.h"

char const *interface = "wlo1";

int main() {
    if(fork()){
        DnsSpoofer *dnsSpoofer = new DnsSpoofer();
        dnsSpoofer->start_spoofing(const_cast<char *>(interface));
        cout << "Stoped" << endl;
    } else {
//        auto arpSpoofer = new ArpSpoofer();
//        arpSpoofer->start_spoofing(const_cast<char *>(interface), "", "");
    }


    return 0;
}