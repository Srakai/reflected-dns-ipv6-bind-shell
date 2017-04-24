#ifndef NET_UTL_H_
#define NET_UTL_H_

#include "structs.h"

#include <stdint.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <stdlib.h>

uint16_t udp6_checksum (struct ip6_hdr, struct udphdr, uint8_t *, unsigned int);

uint16_t checksum (uint16_t *addr, unsigned int);


unsigned int craft_querry_name(unsigned char *, unsigned char *,unsigned int);

unsigned int extract_querry(unsigned char *,unsigned char *);

unsigned int craft_packet(struct net_address, unsigned char *, unsigned int ,unsigned short);


unsigned int recive_bytes(fd_set, int, unsigned char[]);

unsigned int recive_bytes_from(fd_set,int, unsigned char[], struct sockaddr_in6 *);

unsigned int recv_packet_len(fd_set, int, char *, struct net_address *, char, char *);

unsigned int recv_and_join(fd_set, int, char *, struct net_address *, char, unsigned char *, unsigned int *, unsigned int);


void send_udp(struct sockaddr_in6, int, unsigned char *, unsigned int);

void craft_and_send(unsigned char *, unsigned int, unsigned char *, struct net_address, unsigned char *, int, unsigned short);

void craft_and_send_noencode_data(unsigned char *, unsigned int, unsigned char *, struct net_address, unsigned char *, int, unsigned short);

void fragment_and_send(unsigned char *, unsigned int, struct net_address, unsigned char *, int, unsigned short);

#endif
