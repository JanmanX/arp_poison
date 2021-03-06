#include <stdio.h>
#include <stdlib.h>

#include "lib/tcp.h"
#include "lib/ipv4.h"
#include "lib/ethernet.h"
#include "lib/network_helper.h"

void error(char *func, char *msg)
{
	printf("[ERROR %s]: %s\n",func, msg);
	exit(1);
}

int main(int argc, char **argv)
{
	if(argc < 3) {
		printf("USAGE: syn_flood <target_ip> <port>");
		exit(0);
	}

	/* Allocate a memory block of continuous memory for the packets */
	const char* packet = (char*)malloc(ETHER_HDR_LEN
					   + IP_HDR_LEN
					    + TCP_HDR_LEN);

	struct ether_hdr* ether = packet;
	struct ip_hdr* ip = packet+ETHER_HDR_LEN;
	struct tcp_hdr* tcp = packet+ETHER_HDR_LEN+TCP_HDR_LEN;

	printf("ETH: %p\nIP: %p\nTCP: %p\n", ether, ip, tcp);
	printf("ETHER_HDR_LEN: %d\nIP_HDR_LEN: %d\nTCP_HDR_LEN: %d\n",
	       ETHER_HDR_LEN,
	       IP_HDR_LEN,
	       TCP_HDR_LEN);

	/* Set ethernet packet */


	return 0;
}
