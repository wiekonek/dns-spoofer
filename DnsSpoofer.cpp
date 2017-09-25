#include <netinet/in.h>
#include <linux/if_ether.h>
#include <iostream>
#include <udns.h>
#include <libnet.h>
#include "DnsSpoofer.h"

#include <algorithm>

using std::for_each;

struct dnsquery {
    char *qname;
    char qtype[2];
    char qclass[2];
};

DnsSpoofer::DnsSpoofer() {

}

void handle_dns_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
vector<unsigned char *> get_domain_name(unsigned char *query_payload);

void DnsSpoofer::start_spoofing(char *device) {
    struct bpf_program fp;
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
    pcap_loop(pcap, -1, handle_dns_packet, NULL);
}

vector<unsigned char *> get_domain_name(unsigned char *query_payload) {
    vector<unsigned char*> domain_name;
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
            domain_name.push_back(domain_segment);
        }
    }
    return domain_name;
}

void handle_dns_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    auto dns = (unsigned char *)(bytes + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct libnet_udp_hdr));

    printf("========= DNS =========\n");
    printf("Transaction ID: 0x%04x\n", dns_qid(dns));
    printf("Questions: %i\n", dns_numqd(dns));
    printf("Answer RRs: %i\n", dns_numan(dns));
    printf("Authority RRs: %i\n", dns_numns(dns));
    printf("Additional RRs: %i\n", dns_numar(dns));
    printf("response/request 0x%02x\n", dns_qr(dns));

    if(dns_qr(dns) > 0) {
        printf("We caught request query!\n");
        auto domain_name_segments = get_domain_name(dns_payload(dns));
        for(auto segment: domain_name_segments) {
            printf("%s.", segment);
        }
        cout <<  endl;
    }

    cout << "=======================" << endl << endl;
}
