#include <iostream>
#include "ArpSpoofer.h"
#include "DnsSpoofer.h"


int main() {
    if(fork()){
        DnsSpoofer *dnsSpoofer = new DnsSpoofer();
        dnsSpoofer->start_spoofing("wlan0");
        cout << "Stoped" << endl;
    } else {
//        auto arpSpoofer = new ArpSpoofer();
//        arpSpoofer->start_spoofing("wlo1", "", "");
    }


    return 0;
}