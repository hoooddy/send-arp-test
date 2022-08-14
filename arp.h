#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stddef.h>

struct ArpHdr{
	uint16_t hard_;// 1
	uint16_t pro_; // 0x800
	uint8_t hln_; //6, mac length
	uint8_t pln_; //4, ip ength
	uint16_t op_; // 1=request, 2=reply
	uint8_t smac_[6];
	uint8_t sip_[4];
	uint8_t tmac_[6];
	uint8_t tip_[4];
}__attribute__((packed));

struct ArpHdr* get_arp_hdr(const u_char* data);