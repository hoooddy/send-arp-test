#include "arp.h"

struct ArpHdr* get_arp_hdr(const u_char* data){
	struct ArpHdr * arp_header = (struct ArpHdr *)data;
	if(ntohs(arp_header->op_) != 0x0002)
		return NULL;
	return arp_header;
}