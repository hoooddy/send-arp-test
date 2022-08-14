#include <stdio.h>
#include <pcap.h>
#include "ethernet.h"

struct ethernet_hdr* get_ether_hdr(const u_char* data){
	struct ethernet_hdr *eth_header = (struct ethernet_hdr *)data;

	if(ntohs(eth_header->type_) != 0x806) // check arp
		return NULL;
	
	return eth_header;
}