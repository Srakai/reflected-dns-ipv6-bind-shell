#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>    

#include "structs.h"
#include "base64.h"
#include "net_utils.h"
#include "utils.h"

#define MAX_DNS_QRRY 250
#define MAX_DNS_PKT_SIZE 512
#define BUFF_SIZE 8192


int main(int argc,char **argv)
{

if(argc<3){printf("usage: %s my_addr(real) s_addreses.spoofed_addr dns_addr \n",argv[0]);exit(1);}

struct net_address s_addreses;
fd_set read_handler;					//for pipe
unsigned char *p_buffer;
unsigned short port = 5000;
unsigned char my_ip6_addr[sizeof(s_addreses.my_addr.sin6_addr)];
unsigned int querry_len;
int pay_len, r_sock, s_sock;

p_buffer = malloc(MAX_DNS_PKT_SIZE);			//buffer for our packet
memset(p_buffer,0,MAX_DNS_PKT_SIZE);

unsigned char *nxt_data;
nxt_data = p_buffer + sizeof(struct ip6_hdr) + sizeof(struct udphdr) + sizeof(struct dns_hdr);


//create sockd for sending
s_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
if(s_sock < 0)
{
	perror("socket()");
	exit(EXIT_FAILURE);
}

int optval = 1;
if (setsockopt(s_sock, IPPROTO_IPV6, IPV6_HDRINCL, (char *)&optval, sizeof(optval)) != 0)
{
	perror("setsockopt()");
	exit(EXIT_FAILURE);
}

//setup addres to connet to (DNS server addr)
memset(&s_addreses.c_addr,0,sizeof(s_addreses.c_addr));
s_addreses.c_addr.sin6_family = AF_INET6;
if(inet_pton(AF_INET6,argv[3],&s_addreses.c_addr.sin6_addr) == 0)
{
	printf("Invalid addres\n");
	exit(EXIT_FAILURE);
}

//setup spoofed addres
memset(&s_addreses.spoofed_addr,0,sizeof(s_addreses.spoofed_addr));
s_addreses.spoofed_addr.sin6_family = AF_INET6;
if(inet_pton(AF_INET6,argv[2],&s_addreses.spoofed_addr.sin6_addr) == 0)	//here goes spoofed addres
{
	printf("Invalid addres\n");
	exit(EXIT_FAILURE);
} 

//setup my addres

if(inet_pton(AF_INET6,argv[1],my_ip6_addr) == 0)	//here goes spoofed addres
{
	printf("Invalid addres\n");
	exit(EXIT_FAILURE);
} 


//prepare my real addr
memset(&s_addreses.my_addr,0,sizeof(s_addreses.my_addr));
s_addreses.my_addr.sin6_family = s_addreses.my_addr.sin6_family = AF_INET6;
s_addreses.my_addr.sin6_addr  = in6addr_any;
s_addreses.my_addr.sin6_port = htons(5001);

//create sockd for reciving
r_sock = socket(AF_INET6,SOCK_DGRAM,0);
if(r_sock < 0)
{
	perror("socket()");
	exit(EXIT_FAILURE);
}


if(bind(r_sock, (struct sockaddr *) &s_addreses.my_addr, sizeof(s_addreses.my_addr) ) <0)
{
	perror("bind()");
	exit(EXIT_FAILURE);
}

//prepare main loop

unsigned int bytes, packet_count, data_len, ret_val;
unsigned char *addres;			//for fragmenting
unsigned char buffer[BUFF_SIZE];
unsigned char buffer2[256];
unsigned char prolog_buff[4];
char retval, is_client = 1, exit_loop = 0;

void *recive_buffer,*decoding_buffer;

//send asociation packet
memset(prolog_buff,'0',4);
craft_and_send((unsigned char *) &my_ip6_addr , sizeof(my_ip6_addr), prolog_buff, s_addreses, p_buffer, s_sock, port);


while(1)
{
	bytes = read(0, buffer, BUFF_SIZE);
	if(bytes==0)
	{
		printf("error reading from stdin\n");
		continue;
	}
	fragment_and_send(buffer, bytes, s_addreses, p_buffer, s_sock, port);
	
	
	do
	{
		packet_count = recv_packet_len(read_handler, r_sock, buffer, &(s_addreses), is_client, NULL);
	}while(packet_count == 0 );

	if( ( recive_buffer = malloc(MAX_DNS_QRRY*(packet_count)) ) ==0)
	{
		perror("malloc()");
		exit(EXIT_FAILURE);
	}
	if( ( decoding_buffer = malloc( (((MAX_DNS_QRRY*(packet_count))*3)/4)+4)  ) ==0)
	{
		perror("malloc()");
		exit(EXIT_FAILURE);
	}
	
	data_len = sizeof(recive_buffer);
	do{
		ret_val = recv_and_join(read_handler, r_sock, buffer, &(s_addreses), is_client, recive_buffer, &data_len, packet_count);
		if(ret_val==0)
		{
			exit_loop =1;
			break;
		}
	}while(ret_val==1);
	
	if (exit_loop == 1)
	{
		exit_loop=0;
		continue;
	}
	
	bytes = sizeof(decoding_buffer);
	base64_decode(recive_buffer, data_len, decoding_buffer, &bytes);
	printf("%.*s",bytes,decoding_buffer);
	
	free(recive_buffer);
	free(decoding_buffer);
}


return 0;
}
