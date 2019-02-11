#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "header.h"
#include "analysis.h"
#include "swap.h"

void http_protocol_analysis(u_char *str,int len)
{
	int i,j;
	sniff_eth_t eth;
	sniff_ip_t ip;
	sniff_tcp_t tcp;

	char request[][9]={"HTTP","GET","POST","HEAD","PUT","DELETE","TRACE","CONNECT","OPTIONS"};

	int offset = 0;
	memcpy(&eth, str, sizeof(sniff_eth_t));
	offset += sizeof(sniff_eth_t);
	if (0x0800 != htobe16(eth.ether_type)) {
		return;
	}

	memcpy(&ip, str+offset, sizeof(sniff_ip_t));
	offset += ((ip.ip_vhl)&0x0f)*4;
	if(0x06 != ip.ip_p) {
		return;
	}

	memcpy(&tcp, str+offset, sizeof(sniff_tcp_t));
	offset += tcp.th_offx2/4;
	//printf("th_offx2:%d",tcp.th_offx2);

	if(htobe16(tcp.th_sport) == 80 || htobe16(tcp.th_dport) == 80) {
		for(i=0;i<sizeof(request)/sizeof(request[0]);i++) {
			for(j=0;j<sizeof(request[i]);j++) {
				if (*(str+offset+j) != request[i][j]) {
					break;
				}
			}
			if (request[i][j] == '\0') {
				for (i = offset; i < len; i++) {
					printf("%c", *(str+i));
				}
				printf("\n\n\n\n");
				return;
			}
		}
	}
	return;
}

void protocol_analysis(u_char *str,int len)
{
	http_protocol_analysis(str,len);
}