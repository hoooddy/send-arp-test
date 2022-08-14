#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

 
 uint8_t* StrIptoByte(char* from){
        char* tmp = strtok(from, ".");
		static uint8_t to[4]; // static for using in main

        for(int i = 0; tmp != NULL; i++){
                to[i]=(uint8_t)atoi(tmp);
                tmp = strtok(NULL,".");
				//printf("%d ", to[i]);
        }
	//	printf("\n");
        return to;
}


uint8_t* Get_ip(){
    int fd;
 	struct ifreq ifr;

 	fd = socket(AF_INET, SOCK_DGRAM, 0);
 	ifr.ifr_addr.sa_family = AF_INET;
 	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
 	ioctl(fd, SIOCGIFADDR, &ifr);
 	close(fd);
	uint8_t ip[4];
	memcpy(ip, StrIptoByte(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)), sizeof(ip));
	// for(int i = 0; i<4; i++)
	// 	printf("%d ",ip[i]);
 	return StrIptoByte(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}