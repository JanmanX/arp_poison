#ifndef TCP_NETWORK_HEADER_H
#define TCP_NETWORK_HEADER_H

#define TCP_HDR_LEN 160

typedef struct tcp_hdr {
	unsigned short int	source;
	unsigned short int	dest;
	unsigned int		seq;
	unsigned int		ack_seq;
	unsigned short int	res1:4,
				doff:4,
				fin:1,
				syn:1,
				rst:1,
				psh:1,
				ack:1,
				urg:1,
				ece:1,
				cwr:1;
	unsigned short int	window;
	unsigned short int	check;
	unsigned short int	urg_ptr;
}tcp_hdr_t;

#endif
