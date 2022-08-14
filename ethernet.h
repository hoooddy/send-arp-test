#include <stdio.h>
#include <pcap.h>

#define ETHER_ADDR_LEN 6

struct ethernet_hdr{
    uint8_t dmac_[ETHER_ADDR_LEN];
    uint8_t smac_[ETHER_ADDR_LEN];
    uint16_t type_;
}__attribute__((packed)); // 


struct ethernet_hdr* get_ether_hdr(const u_char* data);