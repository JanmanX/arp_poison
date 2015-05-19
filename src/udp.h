#ifndef UDP_NETWORK_HEADER_H
#define UDP_NETWORK_HEADER_H

/*
 * User Datagram Protocol header layout:
 *
 * ______2_bytes________|______2_bytes________|
 * |	Source Port     |   Destination Port  |
 * |	Length		|   Checksum          |
 * |------------------------------------------|
 *
 * Packet size = 2 * 4 bytes = 8 bytes
 */
#define UDP_HDR_LEN 8

typedef struct udp_hdr {
	unsigned short int src;
	unsigned short int dst;
	unsigned short int len;
	unsigned short int check;
} udp_hdr_t;

#endif
