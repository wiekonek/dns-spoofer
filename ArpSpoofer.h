#ifndef DNS_SPOOFER_ARPSPOOFER_H
#define DNS_SPOOFER_ARPSPOOFER_H


#include "consts.h"


#define ARP_ETHER_TYPE 0x0806

struct arphdr_ex {
    u_int16_t ftype;
    u_int16_t ptype;
    u_int8_t flen;
    u_int8_t plen;
    u_int16_t option;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

class ArpSpoofer {
public:
    ArpSpoofer();
    void start_spoofing(char* interface, char* target_host, char* remote_host);

private:
    const char *getArpOption(const uint16_t optionCode);
    const char *macToString(const uint8_t mac[6]);
    const char *ipToString(const uint8_t *ip);
    const uint32_t ipToInt(const uint8_t *ip);
};


#endif //DNS_SPOOFER_ARPSPOOFER_H
