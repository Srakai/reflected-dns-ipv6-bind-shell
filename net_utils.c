#include "net_utils.h"
#include "structs.h"
#include "base64.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/socket.h>  

#define IP_MAXPACKET 65535
#define BUFF_SIZE 1024
#define SLEEP_VAL 2
#define MAX_DNS_QRRY 250

uint16_t checksum (uint16_t *addr,unsigned int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

uint16_t udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, unsigned int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];
  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src.s6_addr);
  chksumlen += sizeof (iphdr.ip6_src.s6_addr);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy UDP length into buf (32 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}



unsigned int craft_querry_name(unsigned char *output, unsigned char *input,unsigned int data_len)
{
// max dns querry name len .63.63.63.62. =255 bytes = 250 readable chars
if (data_len >250 || data_len ==0)return 1;

unsigned char pieces,piece_len;
unsigned char *j, *k;
unsigned int ret_len =0 ;
pieces = (data_len/63) + 1;

if ((data_len %63) == 0) pieces++;	//if last piece is 63, add one more piece to store 1 char xD

k = input;
j = output;
for(int i=0;i<pieces;i++)
{

	if(i+1 == pieces)	//last piece
	{
		if(data_len >62){ piece_len =62;} 	//if we have more than 1 piece, and is last len is 62
		else piece_len = data_len;		//obvious..
	}
	else
	{
		if(i==0) (piece_len = (data_len-62)%63 ? ((data_len-62)%63) : 63 );	//first piece is %of datalen or if its 0 then its 63 (cause 63%63=0)
		else piece_len = 63;							//only first and last is special
	}
	*j = piece_len;
	j += sizeof(unsigned char);
	ret_len++;
	memcpy(j,k,piece_len);
	k += (piece_len * sizeof(unsigned char));
	j += (piece_len * sizeof(unsigned char));
	ret_len += piece_len;

}

*j = '\0';
j += sizeof(unsigned char);
ret_len++;

return ret_len;
}


unsigned int extract_querry(unsigned char *buffer_in,unsigned char *buffer_out)
{
//2 bytes id,2 bytes flags,2 bytes questions,2 bytes answer rrs,
//2 bytes authorites, 2 bytes additional rrs, and querry at 12 byte offset
unsigned char pre,len=0;

for(int i=11;;i+=pre+1)//12 byte offset
{

	pre = buffer_in[i+1];
	if (pre==0)return len;
	memcpy(buffer_out+len,buffer_in+i+2,pre);
	len += pre;
}

}



unsigned int craft_packet(struct net_address s_addreses, unsigned char *p_buffer, unsigned int querry_len, unsigned short src_port)
{
struct sockaddr_in6 c_addr = s_addreses.c_addr;
struct sockaddr_in6 my_addr = s_addreses.spoofed_addr;

unsigned int payload_len;
unsigned short *q_type, *q_class;				//for DNS Question section

unsigned char *data = (unsigned char *) p_buffer;

//devide buffer and fill it
struct ip6_hdr *ip_6_header = (struct ip6_hdr *) data; 	//ip6 header
data += sizeof(*ip_6_header);		

struct udphdr  *udp_header = (struct udphdr *) data;	//udp header
data += sizeof(*udp_header);				

struct dns_hdr *dns_header = (struct dns_hdr *) data;	//dns header
data += sizeof(*dns_header);

payload_len = sizeof(*ip_6_header) + sizeof(*udp_header) + sizeof(*dns_header) + querry_len + sizeof(*q_type) + sizeof(*q_class);
//printf("Plen=%d\nsizeof(*ip_6_header)=%d\nsizeof(*udp_header)=%d\nsizeof(*dns_header)=%d\nquerry_len=%d\nrest=%d\n",payload_len,sizeof(*ip_6_header),sizeof(*udp_header),sizeof(*dns_header),querry_len, sizeof(*q_type) + sizeof(*q_class));

// IPv6 header
ip_6_header->ip6_flow = htonl (6 << 28);				// IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
ip_6_header->ip6_plen = htons(payload_len - sizeof(*ip_6_header));	// Payload length UDP header + DNS header + DNS querry
ip_6_header->ip6_nxt = IPPROTO_UDP;					// Next header
ip_6_header->ip6_hops = 64;						// Hop limit 

memcpy(&ip_6_header->ip6_src,&my_addr.sin6_addr,sizeof(my_addr.sin6_addr));
memcpy(&ip_6_header->ip6_dst,&c_addr.sin6_addr,sizeof(c_addr.sin6_addr));

// UDP header
udp_header->source = htons(src_port);
udp_header->dest = htons(53);
udp_header->len = htons(payload_len - sizeof(*ip_6_header));	// Payload length UDP header + DNS header + DNS querry

// DNS header
dns_header->id = (unsigned short) htons(0xbeef);
dns_header->qr = 0;						//This is a query
dns_header->opcode = 0;					//This is a standard query
dns_header->aa = 0;						//Not Authoritative
dns_header->tc = 0;						//This message is not truncated
dns_header->rd = 0;						//Recursion Desired
dns_header->ra = 0;						//Recursion not available
dns_header->z = 0;						//Z flag =0
dns_header->rcode = 0;					//Not a response
dns_header->q_count = htons(1);			//1 question
dns_header->ans_count = 0;
dns_header->auth_count = 0;
dns_header->add_count = 0;


// DNS Question section 
							//We already have our querry setup on data addr
q_type = (unsigned short *)(data + querry_len);				//Get addres after querry
q_class = (unsigned short *)(data + querry_len + sizeof(*q_type));
*q_type = htons(1);					//QTYPE - A record
*q_class = htons(1);					//QCLASS - internet

//Checksum
udp_header->check = udp6_checksum (*ip_6_header, *udp_header,(uint8_t *) dns_header,payload_len- sizeof(*ip_6_header) - sizeof(*udp_header));


return payload_len;
}



unsigned int recive_bytes(fd_set read_handler,int s,unsigned char buffer[BUFF_SIZE])
{
unsigned int retval,recieved;
struct timeval timeout_i;
FD_ZERO(&read_handler);
FD_SET(s,&read_handler);
timeout_i.tv_sec = 3;
timeout_i.tv_usec =0;

retval = select(s+1,&read_handler,NULL,NULL,NULL);
if(retval == -1)
{
	perror("select");
	exit(EXIT_FAILURE);
}
else if(retval == 0)
{
	printf("timeout\n");
	return 0;
}
else
{
	if(!FD_ISSET(s,&read_handler)) 
	{
		printf("descriptor not set\n");
		exit(EXIT_FAILURE);
	}
	if((recieved=recv(s,buffer,BUFF_SIZE,0)) <0)
	{
		printf("error recieving bytes\n");
		return 0;
	}
	return recieved;
}

}


unsigned int recive_bytes_from(fd_set read_handler,int s,unsigned char buffer[BUFF_SIZE],struct sockaddr_in6* c_addr)
{
unsigned int retval,recieved;
struct timeval timeout_i;
struct sockaddr_in6 inet_c_addr;
socklen_t c_addr_l;
FD_ZERO(&read_handler);
FD_SET(s,&read_handler);
timeout_i.tv_sec = 3;
timeout_i.tv_usec =0;
c_addr_l = sizeof(*c_addr);

retval = select(s+1,&read_handler,NULL,NULL,NULL);
if(retval == -1)
{
	perror("select()");
	exit(EXIT_FAILURE);
}
else if(retval == 0)
{
	printf("timeout\n");
	return 0;
}
else
	{
	if(!FD_ISSET(s,&read_handler))
	{
		printf("descriptor not set\n");
		exit(EXIT_FAILURE);
	}
	if((recieved=recvfrom(s,buffer,BUFF_SIZE,0,(struct sockaddr*) c_addr, &c_addr_l)) <0)
	{
		printf("error recieving bytes\n");
		return 0;
	}
	return recieved;
	}
}

unsigned int recv_packet_len(fd_set read_handler, int r_sock, char *buffer, struct net_address *s_addreses, char is_client, char *is_addr_setup)
{
	unsigned char buffer2[256];
	unsigned int bytes, packet_count;
	
	bytes = recive_bytes_from(read_handler, r_sock, buffer, &(s_addreses->c_addr));
	//port must be set 0 in sending ;)
	s_addreses->c_addr.sin6_port = 0;
	bytes = extract_querry(buffer,buffer2);
	//printf("paket type:%c\n",buffer2[0]);
	switch(buffer2[0])
	{

	case '0':
		if (is_client) break;
		//get ipv6 addr
		base64_decode(buffer2 + sizeof(int),bytes -sizeof(int), buffer, &bytes);
		memcpy(&s_addreses->spoofed_addr.sin6_addr,buffer,sizeof(s_addreses->spoofed_addr.sin6_addr));
		//printf("spoofed addr\n");
		//hex_dump((unsigned char *)&s_addreses->spoofed_addr.sin6_addr,bytes);
		*is_addr_setup =1;
		return 0;
	break;

	case '1':
		if (!is_client)
		{
			if(*is_addr_setup ==0)return 0;
		}
		base64_decode(buffer2 + sizeof(int),bytes -sizeof(int), buffer, &bytes);
		packet_count = *buffer;
		printf("incoming pakets:%u\n",packet_count);
		return packet_count;

	default:
		printf("not our querry\n");
		return 0;
	}
return 0;
}

unsigned int recv_and_join(fd_set read_handler, int r_sock, char *buffer, struct net_address *s_addreses, char is_client, unsigned char *big_buffer, unsigned int *data_len, unsigned int packet_count)
{
	unsigned char buffer2[256];
	unsigned int bytes, last_bytes, packet_id, packets_recevied=0, mask;
	
	bytes = recive_bytes_from(read_handler, r_sock, buffer, &(s_addreses->c_addr));
	//port must be set 0 in sending ;)
	s_addreses->c_addr.sin6_port = 0;
	//printf("%.*s\n", bytes, buffer);
	bytes = extract_querry(buffer,buffer2);
	
switch(buffer2[0])
	{

	case '0':
	if (is_client) break;
	//get ipv6 addr
	base64_decode(buffer2 + sizeof(int),bytes -sizeof(int), buffer, &bytes);
	memcpy(&s_addreses->spoofed_addr.sin6_addr,buffer,sizeof(s_addreses->spoofed_addr.sin6_addr));
	//printf("spoofed addr\n");
	//hex_dump((unsigned char *)&s_addreses->spoofed_addr.sin6_addr,bytes);
	return 0;
	//break;
	
	case '3':
	//for now only id can be only betwen approx 0-32  ('0'-'Z')
	packet_id = buffer2[1];
	if(packet_id=='0')
	{
		//bytes = sizeof(decoding_buffer);
		*data_len = ((MAX_DNS_QRRY-sizeof(int))*(packet_count-1) + last_bytes);
		//printf("datalen:%u\n", *data_len);
		return 3;

	}
	else
	{
		memcpy(big_buffer+((MAX_DNS_QRRY-sizeof(int))*(packet_id-'A')),buffer2 + sizeof(int),bytes -sizeof(int));
		last_bytes = bytes -sizeof(int);
		mask =1;
		mask = mask << (packet_id-'A');
		packets_recevied |= mask;
		//print_binary(packets_recevied);
		return 1;
	}
	
	//break;
	
	default:
	
	printf("Not our querry\n");
	return 1;
	}
return 0;
}


void send_udp(struct sockaddr_in6 c_addr, int sock_fd,unsigned char *data,unsigned int data_len)
{
sleep(SLEEP_VAL);
if(sendto(sock_fd,data,data_len,0,(struct sockaddr*) &c_addr,sizeof(c_addr) )<0 )
{
	printf("sending error\n");
	perror("Send to()");
	exit(EXIT_FAILURE);
}

}

void craft_and_send(unsigned char *data_to_send, unsigned int dts_len, unsigned char *msg_prologue, struct net_address s_addreses, unsigned char *p_buff,int s_sock,unsigned short port)
{
	unsigned char buffer[BUFF_SIZE];
	unsigned char *nxt_data = (unsigned char *) p_buff + sizeof(struct ip6_hdr) + sizeof(struct udphdr) + sizeof(struct dns_hdr);
	unsigned int bytes;
	memcpy(buffer,msg_prologue,4);
	bytes = BUFF_SIZE;
	base64_encode(data_to_send , dts_len, buffer+sizeof(int), &bytes);
	bytes = craft_querry_name(nxt_data, buffer, bytes+ sizeof(int));
	bytes = craft_packet(s_addreses, p_buff, bytes, port);
	send_udp(s_addreses.c_addr, s_sock, p_buff, bytes);

}

void craft_and_send_noencode_data(unsigned char *data_to_send, unsigned int dts_len, unsigned char *msg_prologue, struct net_address s_addreses, unsigned char *p_buff,int s_sock, unsigned short port)
{
	unsigned char buffer[BUFF_SIZE];
	unsigned char *nxt_data = (unsigned char *) p_buff + sizeof(struct ip6_hdr) + sizeof(struct udphdr) + sizeof(struct dns_hdr);
	unsigned int bytes;
	memcpy(buffer, msg_prologue,4);
	bytes = BUFF_SIZE;
	memcpy(buffer+sizeof(int), data_to_send, dts_len);
	bytes = craft_querry_name(nxt_data, buffer, dts_len+ sizeof(int));
	bytes = craft_packet(s_addreses, p_buff, bytes, port);
	send_udp(s_addreses.c_addr, s_sock, p_buff, bytes);

}

void fragment_and_send(unsigned char *data_to_send, unsigned int dts_len, struct net_address s_addreses, unsigned char *p_buffer, int s_sock, unsigned short port)
{

	unsigned int base_len, bytes_base64, packet_id, packet_count;
	unsigned char *addres;			//for fragmenting
	unsigned char prolog_buff[4];
	
	bytes_base64 =(((dts_len*4)/3)+3); 		//should be stable..
	unsigned char *message = malloc(bytes_base64);
	base_len = bytes_base64;
	base64_encode(data_to_send,dts_len,message,&base_len);
	//fragment encoded data to 250 chars chunks
	//then craft querries, packets, send opening packet
	//then send fragmented data
	//
	//struct of message CBBBBB..BBB
	//C-special char, B-base64 encoded message (249 bytes max)
	//we put SC in front of message, on top of old message
	//SC =0 - association packet;SC =1 - incoming packets;SC =2 - control packet;SC =3 - data packet; SC =[4-9] - reserved;
	//craft packet with SC =1

	memset(prolog_buff,'0',4);
	prolog_buff[0] = '1';
	packet_count = (base_len/(MAX_DNS_QRRY-sizeof(int))) + 1;
	craft_and_send((unsigned char *)&packet_count, sizeof(int), prolog_buff, s_addreses, p_buffer, s_sock, port);
	
	packet_id=0;
	for(int i=0;i<base_len;i+=(MAX_DNS_QRRY- sizeof(int)))
	{
		if(packet_id ==24 && 1==0)
		{
			//send control message to check if all packet are recieved corrrectly *DISABLED BY NOW*
			/*
			memset(buffer,'0',4);
			buffer[0] = '2';
			packet_count = 25;
			bytes = BUFF_SIZE;
			base64_encode((unsigned char *) &packet_count , sizeof(int), buffer+sizeof(int), &bytes);
			//this code creates sets buffer like so: 1000AAAAA A-is packet count
			querry_len = craft_querry_name(nxt_data,buffer,bytes+ sizeof(int));
			pay_len = craft_packet(s_addreses, p_buffer, querry_len,5000);
			send_udp(s_addreses.c_addr,s_sock,p_buffer,pay_len);
			
			packet_id = 0;
			//wait for response if there is any need of resending packets 
			*/
			
		}
		addres = (message)+i;
		//printf("packet_id=%d\n",packet_id);
		//create prologue
		
		prolog_buff[0] = '3';
		prolog_buff[1] = 'A'+(packet_id%25);	//here id
		prolog_buff[2] = 'A';
		prolog_buff[3] = 'A';
		
		if ((i+(MAX_DNS_QRRY -sizeof(int))) < base_len) 
		{
			//we have more packets
			craft_and_send_noencode_data(addres, MAX_DNS_QRRY - sizeof(int), prolog_buff, s_addreses, p_buffer, s_sock, port);
		} 	
		else
		{
			//last packet
			unsigned int len = (base_len%(MAX_DNS_QRRY -sizeof(int)));
			craft_and_send_noencode_data(addres, len, prolog_buff, s_addreses, p_buffer, s_sock, port);
		}
		packet_id++;
	}
	prolog_buff[0]= '3';
	prolog_buff[1]= '0';
	prolog_buff[2]= 'A';
	prolog_buff[3]= 'A';	//id = 0 - execve
	
	craft_and_send(NULL, 0, prolog_buff, s_addreses, p_buffer, s_sock, port);
	
	free(message);
}
