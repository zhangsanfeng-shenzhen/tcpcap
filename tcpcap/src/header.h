#ifndef __HEADER_H
#define __HEADER_H

#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */  
#define SNAP_LEN 1518  
  
/* ethernet headers are always exactly 14 bytes [1] */  
#define SIZE_ETHERNET 14  
  
/* Ethernet addresses are 6 bytes */  
#define ETHER_ADDR_LEN    6  

typedef struct sniff_file_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t linktype;
}sniff_file_header;
 
typedef struct sniff_timestamp{
	uint32_t timestamp_s;
	uint32_t timestamp_ms;
}sniff_timestamp;

typedef struct sniff_header{
	sniff_timestamp ts;
	uint32_t capture_len;
	uint32_t len;
}sniff_header;

/* Ethernet header */  
typedef struct sniff_ethernet {  
        uint8_t ether_dhost[ETHER_ADDR_LEN]; /* destination host address */  
        uint8_t ether_shost[ETHER_ADDR_LEN]; /* source host address */  
        uint16_t ether_type; /* IP? ARP? RARP? etc */  
}sniff_eth_t;

/* IP header */  
typedef struct sniff_ip {  
        uint8_t ip_vhl; /* version << 4 | header length >> 2 */  
        uint8_t ip_tos; /* type of service */  
        uint16_t ip_len; /* total length */  
        uint16_t ip_id; /* identification */  
        uint16_t ip_off; /* fragment offset field */  
        #define IP_RF 0x8000 /* reserved fragment flag */  
        #define IP_DF 0x4000 /* dont fragment flag */  
        #define IP_MF 0x2000 /* more fragments flag */  
        #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */  
        uint8_t ip_ttl; /* time to live */  
        uint8_t ip_p; /* protocol */  
        uint16_t ip_sum; /* checksum */  
        struct in_addr ip_src,ip_dst; /* source and dest address */  
}sniff_ip_t;

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)  
#define IP_V(ip) (((ip)->ip_vhl) >> 4)  
  
/* TCP header */  
typedef uint32_t tcp_seq;  
  
typedef struct sniff_tcp {  
        uint16_t th_sport; /* source port */  
        uint16_t th_dport; /* destination port */  
        tcp_seq th_seq; /* sequence number */  
        tcp_seq th_ack; /* acknowledgement number */  
        uint8_t th_offx2; /* data offset, rsvd */  
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)  
        uint8_t th_flags;  
        #define TH_FIN 0x01  
        #define TH_SYN 0x02  
        #define TH_RST 0x04  
        #define TH_PUSH 0x08  
        #define TH_ACK 0x10  
        #define TH_URG 0x20  
        #define TH_ECE 0x40  
        #define TH_CWR 0x80  
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)  
        uint16_t th_win; /* window */  
        uint16_t th_sum; /* checksum */  
        uint16_t th_urp; /* urgent pointer */  
}sniff_tcp_t;

#endif