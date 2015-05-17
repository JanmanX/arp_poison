#ifndef NETWORK_HELPER_H
#define NETWORK_HELPER_H


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
#include "ethernet.h"

void print_arp(const struct arp_hdr* arp_header);
void print_ether(const struct ether_hdr*);
void print_mac(const unsigned char mac[6]);
void print_ip(const unsigned char ip[4]);

void get_device_network_address(const char *device, unsigned char mac[6]);
void get_device_ip_address(const char *device, unsigned char ip[4]);

void parse_network_address(const char *string, unsigned char mac[6]);
void parse_ip_address(const char *string, unsigned char mac[4]);



/* Prints a formatted message and terminates the program */
void sniffer_fatal(const char *in, const char *msg);

#endif
