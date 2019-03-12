#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "header.h"
#include "analysis.h"
#include "swap.h"
#include "sqlite.h"
#include "sds.h"

char *find(char *src, char *start, char *end, char *dst)
{
	char *p,*q,*d;
	int num;

	p = strstr(src,start);
	if (p!=NULL) {
		q = strstr(p,end);
		if (q!=NULL){
			d = dst;
			num = 0;
			p += strlen(start);
			for(;q!=p;p++) {
				*d++ = *p;
				num++;
				if (num >= 128) {
					return NULL;
				}
			}
			*d='\0';
			return q;
		}
	}
	return NULL;
}

void http_protocol_analysis(uint8_t *str,int len,uint32_t t)
{
	int i,j;
	sniff_eth_t eth;
	sniff_ip_t ip;
	sniff_tcp_t tcp;
	char dst[128];

	char request[][20]={"GET","POST","HEAD","PUT","DELETE","TRACE","CONNECT","OPTIONS"};
	char response[][20]={"HTTP/1.1","HTTP/1.0"};

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
		sds buf = sdsnewlen(str+offset,len-offset);
		buf = sdscat(buf,"\0");
		for(i=0;i<sizeof(request)/sizeof(request[0]);i++) {
			for(j=0;j<sizeof(request[i]);j++) {
				if (*(str+offset+j) != request[i][j]) {
					break;
				}
			}
			if (request[i][j] == '\0') {
				char *insert = find((char *)buf, "Host: ", "\r\n", dst);
				if (insert != NULL) {
					sql_insert(request[i], dst, t);
				}
				break;
			}
		}
		for(i=0;i<sizeof(response)/sizeof(response[0]);i++) {
			for(j=0;j<sizeof(response[i]);j++) {
				if (*(str+offset+j) != response[i][j]) {
					break;
				}
			}
			if (response[i][j] == '\0') {
				char *insert = (char *)buf;
				insert = find(insert, "Content-Length: ", "\r\n", dst);
				if (insert != NULL) {
					insert = strstr(insert,"\r\n\r\n"); //OCSP is error
					if (insert!=NULL) {
						char *tmp = (char *)malloc(20);
						sprintf(tmp,"%d",strlen(insert)+4);
						if (strcmp(dst,tmp)==0 || strcmp(dst,"65536")==0) {
							printf("len:%d\n",strlen(insert));
						}
						free(tmp);
					}
				}
				break;
			}
		}
		sdsfree(buf);
	}

	return;
}

void protocol_analysis(uint8_t *str,int len,uint32_t t)
{
	http_protocol_analysis(str,len,t);
}