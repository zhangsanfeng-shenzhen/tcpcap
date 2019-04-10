/** @file debug.h
    @brief Debug output routines
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _CAP_H_
#define _CAP_H_

typedef enum DATA_STATUS
{ 
	WRITEING=1, 
	READING, 
	FREE
}DATA_STATUS_E;


typedef struct packet_buf {
	int len;
	void *buf;
}packet_buf_t;

#define PACKET_HEAD (sizeof(packet_buf_t)-sizeof(void *))

#endif /* _CAP_H_ */