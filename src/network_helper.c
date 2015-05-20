#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>

#include "arp.h"
#include "udp.h"
#include "ethernet.h"
#include "tcp.h"
#include "network_helper.h"


void network_network_error(const char* where, const char* msg)
{
	printf("[ERROR in %s]: %s\n", where, msg);
	exit(1);
}


void get_device_network_address(const char *device, unsigned char mac[6])
{
	int s, i = 0;
	struct ifreq ifr;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifr.ifr_name, device);
	ioctl(s, SIOCGIFHWADDR, &ifr);
	for(i = 0; i < 6; i++)
		mac[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
}

void get_device_ip_address(const char *device, unsigned char ip[4])
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, device, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);

	struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;

	unsigned char *temp_ip = (unsigned char*)&ipaddr->sin_addr;

	int i = 0;
	for(i = 0; i < IP_ADDR_LEN; ++i)
		ip[i] = temp_ip[i];
}



void print_arp(const struct arp_hdr* arp_header)
{
	printf("----------------- ARP Header ------------------\n");

	int i = 0;
	printf("Hardware type: %s (code: %x)\n", (ntohs(arp_header->htype) == 1)
						 ? "Ethernet" : "Unknown"
						, arp_header->htype);
	printf("Protocol type: %s (code: %04x)\n", (ntohs(arp_header->ptype)
						== 0x0800) ? "IPv4" : "Unknown"
						, arp_header->ptype);
	printf("Operation: %s (code: %x)\n", (ntohs(arp_header->opcode)
				== ARP_REQUEST) ? "ARP Request" : "ARP Reply"
				, arp_header->opcode);

	/* If is Ethernet and IPv4, print packet contents */
	if (ntohs(arp_header->htype) == 1 && ntohs(arp_header->ptype) == 0x0800){
		printf("Sender MAC: ");

		for(i=0; i<6;i++)
			printf("%02x:", arp_header->sha[i]);

		printf("\nSender IP: ");

		for(i=0; i<4;i++)
			printf("%d.", arp_header->spa[i]);

		printf("\nTarget MAC: ");

		for(i=0; i<6;i++)
			printf("%02x:", arp_header->tha[i]);

		printf("\nTarget IP: ");

		for(i=0; i<4; i++)
			printf("%d.", arp_header->tpa[i]);

		printf("\n");

	}
}

void print_ether(const struct ether_hdr* ether_header)
{
	int i = 0;

	printf("----------------- Ethernet header ------------------\n");

	printf("SRC: %02x",ether_header->ether_src_addr[0]);
	for(i = 1; i < ETHER_ADDR_LEN; ++i)
		printf(":%02x",ether_header->ether_src_addr[i]);

	printf("\nDEST: %02x",ether_header->ether_dest_addr[0]);
	for(i = 1; i < ETHER_ADDR_LEN; ++i)
		printf(":%02x",ether_header->ether_dest_addr[i]);

	printf("\n");
}

void print_mac(const unsigned char mac[6])
{
	int i = 0;
	printf("MAC: %02x",mac[0]);
	for(i = 1; i < ETHER_ADDR_LEN; ++i)
		printf(":%02x",mac[i]);
	printf("\n");
}

void print_ip(const unsigned char ip[4])
{
	int i = 0;
	printf("IP: %u",ip[0]);
	for(i = 1; i < IP_ADDR_LEN; ++i)
		printf(".%d",ip[i]);
	printf("\n");
}

void parse_network_address(const char *string, unsigned char mac[6])
{
	int values[6];
	int i = 0;
	if( 6 == sscanf(string, "%x:%x:%x:%x:%x:%x",
				&values[0], &values[1], &values[2],
				&values[3], &values[4], &values[5] ) )
	{
		/* convert to bytes */
		for( i = 0; i < 6; ++i )
			mac[i] = (unsigned char) values[i];
	}
}

void parse_ip_address(const char *string, unsigned char ip[4])
{
	int values[4];
	int i = 0;
	if( 4 == sscanf(string, "%d.%d.%d.%d",
				&values[0], &values[1], &values[2],
				&values[3]) )
	{
		/* convert to bytes */
		for( i = 0; i < 4; ++i )
			ip[i] = (unsigned char) values[i];
	}
}

int send_packet(const char* device, const struct ether_hdr* packet, int size)
{
	char errbuf[PCAP_ERRBUF_SIZE];		/* Error message buffer */
	struct bpf_program filter;		/* Filter for pcap	*/
	bpf_u_int32 netaddr=0, mask=0;		/* To store network address
						   and netmask  */

	if(device == NULL)
		device = pcap_lookupdev(errbuf);
	if(device == NULL)
		network_error("pcap device", errbuf);

	printf("Using device: %s\n", device);

	pcap_t* pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
	if(pcap_handle == NULL)
		network_error("pcap_open_live",errbuf);

	if(pcap_lookupnet(device, &netaddr, &mask, errbuf) == -1)
		network_error("pcap_lookupnet",errbuf);

	if(pcap_compile(pcap_handle, &filter, "arp", 1, mask) == -1)
		network_error("pcap_compile","-- NO INFO --");

	if(pcap_setfilter(pcap_handle, &filter) == -1)
		network_error("pcap_setfilter","-- NO INFO --");

	if(pcap_inject(pcap_handle,(unsigned char*)packet, size) != size)
			network_error("pcap_sendpacket","Packet size not sent");

	return 0;
}
