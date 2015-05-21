#ifndef ARP_NETWORK_HEADER_H
#define ARP_NETWORK_HEADER_H

/* ARP HEADER layout
 * ------------------- 4 bytes -------------------
 * _______2 bytes________|________2 bytes_______
 * |	Hardware type    |	Protocol type	|
 * |  HW_LEN   | P_LEN	 |	OPCODE		|
 * |		Source HW_ADDR			|
 * |		Source protocol address		|
 * |		Destination HW_ADDR		|
 * |		Destination protocol address	|
 * |		::DATA				|
 * ----------------------------------------------
 *  == 28 bytes
 */

/* Hardware type constants */
#define HW_TYPE_ETHERNET 1

/* Protocol type constants */
#define P_TYPE_IP 0x800

/* Lengths */
#define ETHER_ADDR_LEN	6
#define IP_ADDR_LEN	4
#define ARP_HDR_LEN	28

/* Opcode */
#define ARP_REQUEST	1	/* ARP REQUEST 	*/
#define ARP_REPLY	2	/* ARP REPLY	*/
#define RARP_REQUEST	3	/* Reverse request */
#define RARP_REPLY	4	/* Reverse reply */


typedef struct arp_hdr {
	unsigned short int htype;	/* Hardware type 	*/
	unsigned short int ptype;	/* Protocol type	*/
	unsigned char hlen;		/* Hardware Address Lenght */
	unsigned char plen;		/* Protocol Address Lenght */
	unsigned short int opcode;	/* Operation code	*/

	unsigned char sha[ETHER_ADDR_LEN];	/* Sender Hardware Address */
	unsigned char spa[IP_ADDR_LEN];		/* Sender IP Address */
	unsigned char tha[ETHER_ADDR_LEN];	/* Target Hardware Address */
	unsigned char tpa[IP_ADDR_LEN];		/* Target IP address */
} arp_hdr_t;

/*
 * Sources:
 * http://www.networksorcery.com/enp/protocol/arp.htm
 */
#endif
