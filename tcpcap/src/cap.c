#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <unistd.h>
#include <pthread.h>

#include "debug.h"
#include "list.h"
#include "cap.h"
#include "analysis.h"

#define DEVICE		"br-lan"
char *filter_app = "ip and tcp and not port 22";

list_t *list_deals;
pthread_mutex_t mutex;

void get_packet(u_char * user, const struct pcap_pkthdr *pkthdr,
		const u_char *packet)
{
	pthread_mutex_lock(&mutex);
	packet_buf_t *pb;
	if (pkthdr->len < 65535 && pkthdr->len > 0) {

		pb = (packet_buf_t *)malloc(sizeof(packet_buf_t));
		if (pb == NULL) {
			debug(LOG_ERR,"malloc packet_buf_t errot\n");
			return ;
		}
		pb->len = pkthdr->len;
		pb->buf = (u_char *)malloc(pkthdr->len);
		memcpy(pb->buf,packet,pkthdr->len);
		list_rpush(list_deals, list_node_new(pb));
	}
	pthread_mutex_unlock(&mutex);
}

int packet_capture()
{
	char errBuf[PCAP_ERRBUF_SIZE];
	pcap_t *dev;
	bpf_u_int32 netp, maskp;
	char *net, *mask;
	struct in_addr addr;
	struct bpf_program filter;

	if (pcap_lookupnet(DEVICE, &netp, &maskp, errBuf)) {
		debug(LOG_ERR,"get net failure!");
		exit(1);
	}

	addr.s_addr = netp;
	net = inet_ntoa(addr);
	debug(LOG_ERR,"network: %s", net);

	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	debug(LOG_ERR,"mask: %s", mask);

	dev = pcap_open_live(DEVICE, 65536, 1, 0, errBuf);
	if (NULL == dev) {
		debug(LOG_ERR,"open %s failure!", DEVICE);
		exit(1);
	}

	pcap_compile(dev, &filter, filter_app, 0, netp);
	debug(LOG_ERR,"pcap_compile is starting!");
    pcap_setfilter(dev, &filter);
	debug(LOG_ERR,"pcap_setfilter is starting!");

	pcap_loop(dev, 0, get_packet, NULL);
	pcap_close(dev);

	return 0;
}

void *capture_loop(void)
{
	packet_capture();
	return NULL;
}

void *compile_loop(void)
{
	list_node_t *node;
	packet_buf_t *p,*data;

	while(1) {
		pthread_mutex_lock(&mutex);
		if (list_deals->len > 0) {
			node = list_at(list_deals, 0);
			p = node->val;
			data = (packet_buf_t *)malloc(sizeof(packet_buf_t));
			if (data == NULL) {
				debug(LOG_ERR,"malloc packet_buf_t is error!");
				return NULL;
			}
			memcpy(data,p,sizeof(packet_buf_t));
			data->buf = (u_char *)malloc(p->len);
			if (data->buf == NULL) {
				debug(LOG_ERR,"malloc data->buf is error!");
				return NULL;
			}
			memcpy(data->buf,p->buf,p->len);
			free(p->buf);
			free(p);
			list_remove(list_deals, node);
		}
		pthread_mutex_unlock(&mutex);
		if (data != NULL){
			protocol_analysis(data->buf, data->len);
		}
		usleep(10);
	}
	return NULL;
}

int main()
{
	int result;
    pthread_t tid,sid;
	
	pthread_mutex_init(&mutex,NULL);
	list_deals = list_new();

    result = pthread_create(&tid, NULL, (void *)capture_loop, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new thread (wdctl) - exiting");
    }

    result = pthread_create(&sid, NULL, (void *)compile_loop, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to compile the capture file");
    }

	pthread_join(sid, NULL);
    pthread_join(tid, NULL);
	pthread_mutex_destroy(&mutex);

	return 1;
}