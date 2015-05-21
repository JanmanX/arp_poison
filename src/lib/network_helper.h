#ifndef NETWORK_HELPER_H
#define NETWORK_HELPER_H

#include "arp.h"
#include "udp.h"
#include "tcp.h"
#include "ethernet.h"

void network_error(const char* where, const char* msg);

void print_arp(const struct arp_hdr* arp_header);
void print_ether(const struct ether_hdr*);
void print_mac(const unsigned char mac[6]);
void print_ip(const unsigned char ip[4]);

void get_device_network_address(const char *device, unsigned char mac[6]);
void get_device_ip_address(const char *device, unsigned char ip[4]);

void parse_network_address(const char *string, unsigned char mac[6]);
void parse_ip_address(const char *string, unsigned char mac[4]);

int send_packet(const char* device, const struct ether_hdr* hdr, int size);

#endif
