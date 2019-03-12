#ifndef _SQLITE_H_
#define _SQLITE_H_

#include <pcap.h>
#include <arpa/inet.h>

int sql_insert(char *method, char* host ,uint32_t t);

#endif /* _SQLITE_H_ */