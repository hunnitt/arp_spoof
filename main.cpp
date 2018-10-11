#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <libnet.h>
#include <string.h>
#include <pcap.h>
#include "arp_spoofing.h"

void usage(void) {
    printf("Usage : ./arp_spoofing <interface> <sender ip1> <target ip1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: ./arp_spoofing wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
    exit(0);
}

int main(int argc, char * argv[]) {
    if (argc < 4 || argc % 2 != 0 || argc > 102)                // sender ip & target ip have to be paired. || max == 100 pairs
        usage();

    const char * dev = argv[1];                                 // interface name
    const int s_t_pair = (argc-2)/2;
    uint32_t sender_ip[s_t_pair];
    uint32_t target_ip[s_t_pair];

    for(int i=0; i<s_t_pair; i++){
        str_to_ip(sender_ip, i, argv[2*i+2]);
        str_to_ip(target_ip, i, argv[2*i+3]);
    }



    
}