#ifndef _ANALYSIS_H_
#define _ANALYSIS_H_
/*
#include "sds.h"

typedef struct http_buf {
	uint32_t th_ack;
	long len;

}http_buf_t;
*/
void protocol_analysis(const u_char *buf,int len);
void http_protocol_analysis(const u_char *buf,int len);

#endif /* _ANALYSIS_H_ */