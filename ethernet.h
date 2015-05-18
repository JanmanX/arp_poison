#ifndef ETHERNET_NETWORK_HEADER_H
#define ETHERNET_NETWORK_HEADER_H

#define ETHER_ADDR_LEN 	6
#define IP_ADDR_LEN	4
#define ETHER_HDR_LEN 	14

/* Data link layer abstraction */
struct ether_hdr {
	unsigned char ether_dest_addr[ETHER_ADDR_LEN];
	unsigned char ether_src_addr[ETHER_ADDR_LEN];
	unsigned short ether_type;
}__attribute__((packed));

#endif
