#ifndef STRUCTS_H_
#define STRUCTS_H_

#include <netinet/ip6.h>

/*---------------DNS-HEADER---------------*/
struct dns_hdr
{
	unsigned short id; // identification number

	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	//unsigned char cd :1; // checking disabled	<-- totaly wrong!
	//unsigned char ad :1; // authenticated data
	unsigned char z :3; // its z! reserved		<-- z flag has 3 bits
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};
/*---------------DNS-HEADER---------------*/


/*-----------ETHERNET-II-FRAME------------*/
struct eth2_frm
{
	unsigned char mac_dst[6];

	unsigned char mac_src[6];

	unsigned short eth_type;
					//sad it's useless by now :((
};
/*-----------ETHERNET-II-FRAME------------*/

struct net_address
{
	struct sockaddr_in6 c_addr;

	struct sockaddr_in6 my_addr;
	
	struct sockaddr_in6 spoofed_addr;

};

#endif
