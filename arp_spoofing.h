#pragma pack(push, 1)

typedef struct ethernet_header {
    // Ethernet
    __uint8_t dst[6];    //mac destination.
    __uint8_t src[6];    //mac source.
    __uint16_t type;    //protocol type.
} eth_hdr;

typedef struct arp_header {
    // ARP
    __uint16_t hw_type;    //hardware type.
    __uint16_t p_type;    //protocol type.
    __uint8_t hw_len;    //hardware address length.
    __uint8_t p_len;    //protocol address length.
    __uint16_t op;    //operation.
    __uint8_t s_hw_addr[6];    //sender hardware address.
    __uint8_t s_p_addr[4];    //sender protocol address.
    __uint8_t t_hw_addr[6];    //target hardware address.
    __uint8_t t_p_addr[4];    //target protocol address.
} arp_hdr;

typedef struct arp_packet {
    eth_hdr eh;
    arp_hdr ah;
} ARP_pkt;

#pragma pack(pop)

void str_to_ip(uint32_t * arr, int index, char * ipstr);