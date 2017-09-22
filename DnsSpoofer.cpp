#include <netinet/in.h>
#include <linux/if_ether.h>
#include <iostream>
#include <udns.h>
#include <libnet.h>
#include "DnsSpoofer.h"


DnsSpoofer::DnsSpoofer() {

}

void handle_dns_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

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

void handle_dns_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    unsigned char *dns = (unsigned char *)(bytes + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct libnet_udp_hdr));

    printf("========= DNS =========\n");
    printf("Transaction ID: 0x%04x\n", dns_qid(dns));
    printf("Questions: %i\n", dns_numqd(dns));
    printf("Answer RRs: %i\n", dns_numan(dns));
    printf("Authority RRs: %i\n", dns_numns(dns));
    printf("Additional RRs: %i\n", dns_numar(dns));

    cout << "data: " << dns_payload(dns) << endl;
    cout << "=======================" << endl << endl;
}
