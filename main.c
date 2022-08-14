#include "arp.h"
#include "ethernet.h"
#include "ip.h"
#include "mac.h"
#include <string.h>
#include <stdbool.h>

struct EthArpPacket{
	struct ethernet_hdr eth_;
    struct ArpHdr arp_;
};

int main(int argc, char* argv[]) {

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	int num_sender = (argc-2)/2; // 
	int num_reply = num_sender; // number of senders
	struct EthArpPacket pck[num_sender];
	
	for(int i = 0; i < num_sender; i++){
		// make ethernet header;
		for(int j = 0; j < 6; j++)
			pck[i].eth_.dmac_[j] = 0xFF;
		memcpy(pck[i].eth_.smac_, Get_mac(),sizeof(pck[i].eth_.smac_));
		pck[i].eth_.type_=htons(0x806);

		// make arp header;
		pck[i].arp_.hard_ = htons(0x0001);
		pck[i].arp_.pro_ = htons(0x0800);
		pck[i].arp_.hln_ = 0x06;
		pck[i].arp_.pln_ = 0x04;
		pck[i].arp_.op_ = htons(0x001);

		memcpy(pck[i].arp_.smac_, Get_mac(),sizeof(pck[i].arp_.smac_));
		memcpy(pck[i].arp_.sip_, Get_ip(), sizeof(pck[i].arp_.sip_));

		for(int j = 0; j<6; j++)
			pck[i].arp_.tmac_[j] = 0x00;
		memcpy(pck[i].arp_.tip_, StrIptoByte(argv[i*2 + 2]), sizeof(pck[i].arp_.tip_));

		int res = pcap_sendpacket(handle, (const u_char*)&pck[i], sizeof(struct EthArpPacket));
		if (res != 0)
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	while(num_reply != 0){
		struct pcap_pkthdr *recv_header;
		const u_char* recv_pkt;
		struct ethernet_hdr* eth_header;
		struct ArpHdr* arp_header;

		int res = pcap_next_ex(handle, &recv_header, &recv_pkt);
		
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		if((eth_header = get_ether_hdr(recv_pkt)) == NULL) continue; // if not ethernet header then continue
		recv_pkt += 14;
		if((arp_header = get_arp_hdr(recv_pkt)) == NULL) continue; // if not arp header then continue

		else {
			for(int i = 0; i<num_sender; i++){
				if(!memcmp(pck[i].arp_.tip_, arp_header->sip_, sizeof(arp_header->sip_))){ 
					
					memcpy(pck[i].arp_.tmac_, arp_header->smac_, sizeof(arp_header->smac_));
					memcpy(pck[i].eth_.dmac_, arp_header->smac_, sizeof(arp_header->smac_));

					num_reply--;
				}
			}
		}
	}


	for(int i = 0; i < num_sender; i++){
		memcpy(pck[i].eth_.smac_, Get_mac(),sizeof(pck[i].eth_.smac_));
		pck[i].eth_.type_=htons(0x806);

		// make arp header;
		pck[i].arp_.hard_ = htons(0x0001);
		pck[i].arp_.pro_ = htons(0x0800);
		pck[i].arp_.hln_ = 0x06;
		pck[i].arp_.pln_ = 0x04;
		pck[i].arp_.op_ = htons(0x0002);
		memcpy(pck[i].arp_.smac_, Get_mac(),sizeof(pck[i].arp_.smac_));

		memcpy(pck[i].arp_.sip_, StrIptoByte(argv[i*2 + 3]), sizeof(pck[i].arp_.sip_));
		memcpy(pck[i].arp_.tip_, StrIptoByte(argv[i*2 + 2]), sizeof(pck[i].arp_.tip_));

		int res1 = pcap_sendpacket(handle, (const u_char*)&pck[i], sizeof(struct EthArpPacket));
		if (res1 != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
		}
	}
	pcap_close(handle);
	printf("done!\n");
	return 0;
}
