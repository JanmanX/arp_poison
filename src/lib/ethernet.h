#ifndef ETHERNET_NETWORK_HEADER_H
#define ETHERNET_NETWORK_HEADER_H

/* Lengths */
#define ETHER_ADDR_LEN 	6
#define IP_ADDR_LEN	4
#define ETHER_HDR_LEN 	14

/* Types (for ether_type field) */
#define ETHER_TYPE_IP4 0x800
#define ETHER_TYPE_ARP 0x806

/* Data link layer abstraction */
struct ether_hdr {
	unsigned char ether_dest_addr[ETHER_ADDR_LEN];
	unsigned char ether_src_addr[ETHER_ADDR_LEN];
	unsigned short ether_type;
}__attribute__((packed));

#endif
