#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>

#include "analysis.h"
#include "swap.h"


void find(const u_char *src, u_char *start,u_char *end, u_char *dst,int len)
{
	int i,j;
	for(i = 0; i < len; i++) {
		if (len-i-1>strlen(start) && memcmp(src+i,start,strlen(start)) == 0){
			break;
		}
	}
	for(j = i; j < len; j++) {
		if (len-j-1>strlen(end) && memcmp(src+j,end,strlen(end)) == 0){
			break;
		}
	}
	if (len-i>strlen(start) && len-j>strlen(end)) {
		if (j-i<100) {
			memcpy(dst,src+strlen(start)+i,j-i-strlen(start));
		}
	}
}



void packet_request_handle(const u_char *tcp_payload, int payload_len)
{
	int i;
	char host[128];
	char request[][20]={"GET","POST","HEAD","PUT","DELETE","TRACE","CONNECT","OPTIONS"};
	for(i=0;i<sizeof(request)/sizeof(request[0]);i++) {
		if (memcmp(tcp_payload,request[i],strlen(request[i]))==0){
			memset(host,'\0',sizeof(host));
			find(tcp_payload,"Host: ","\r", host,payload_len);
			if (strlen(host)>0) {
				printf("%s\n",host);
				struct timeval tv;
				gettimeofday(&tv,NULL);
				sql_insert(request[i], host, tv.tv_sec);
			}
		}
	}
}

void packet_response_handle(const u_char *tcp_payload, int payload_len)
{
	int i;
	char host[128];
	char response[][20]={"HTTP/1.1","HTTP/1.0"};
	for(i=0;i<sizeof(response)/sizeof(response[0]);i++) {
		if (memcmp(tcp_payload,response[i],strlen(response[i]))==0){
			memset(host,'\0',sizeof(host));
			find(tcp_payload,"title>","<", host,payload_len);
			if (strlen(host)>0) {
				printf("%s\n",host);
				struct timeval tv;
				gettimeofday(&tv,NULL);
				sql_insert(response[i], host, tv.tv_sec);
			}
		}
	}
}

void http_protocol_analysis(const u_char *buf,int len)
{
	uint16_t e_type;
	uint32_t offset;
	int payload_len;
	const u_char *tcp_payload;

	struct ethhdr *eth = NULL;
	eth = (struct ethhdr *)buf;
	e_type = ntohs(eth->h_proto);
	offset = sizeof(struct ethhdr);

	while (e_type == ETH_P_8021Q) {
		e_type = (buf[offset + 2] << 8) + buf[offset + 3];
		offset += 4;
	}
	if (e_type != ETH_P_IP) {
		return ;
	}

	struct iphdr *ip = (struct iphdr *)(buf + offset);
	e_type = ntohs(ip->protocol);
	offset += sizeof(struct iphdr);

	if (ip->protocol != IPPROTO_TCP) {
		return;
	}

	struct tcphdr *tcp = (struct tcphdr *)(buf + offset);
	offset += (tcp->doff << 2);
	payload_len = len - offset;
	tcp_payload = (buf + offset);

	if (payload_len <= 0) {
		return;
	}

	if (htobe16(tcp->dest)==80 || htobe16(tcp->source)==80 || \
		htobe16(tcp->dest)==8080 || htobe16(tcp->source)==8080) {
			packet_request_handle(tcp_payload, payload_len);
			packet_response_handle(tcp_payload, payload_len);
	}

	return;
}

void protocol_analysis(const u_char *buf,int len)
{
	http_protocol_analysis(buf,len);
}