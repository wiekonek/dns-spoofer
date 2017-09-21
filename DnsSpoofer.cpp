#include <netinet/in.h>
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
    struct ethhdr * ethernetHeader = (struct ethhdr *) bytes;
//    uint16_t eth_type = ntohs(ethernetHeader->h_proto);
//    struct iphdr *iph = (struct iphdr*)(bytes + sizeof(struct ethhdr));
//    cout << iph->protocol << endl;
    for(int i = 1; i<h->len; i++){
        if('a' <= i && i <= 'z'){
            cout << (char)bytes[i];
        }
    }
    cout << endl <<  "======" << endl;
}
