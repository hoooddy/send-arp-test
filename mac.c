#include <netdb.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <string.h>


uint8_t* Get_mac(){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	static uint8_t mac[6]; // static for using in main
    strcpy(s.ifr_name, "eth0");
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        int i;
        for (i = 0; i < 6; ++i){
            mac[i] = (uint8_t) s.ifr_addr.sa_data[i];
			//printf("%02x ", mac[i]);
		}
    }
	return mac;
}