#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


#ifdef _WIN32
#include <winsock2.h>

#ifndef BOF
#include <ws2tcpip.h> // this causes issues with bof defs...
#endif 

#elif __linux__
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <inttypes.h>

#define MIN_PORT 1
#define MAX_PORT 65535

typedef struct port_input Prt;
struct port_input {
	unsigned int start;
	unsigned int end;
	Prt * next;
};

typedef struct HstIPRange {
	struct in_addr start_addr;
	struct in_addr end_addr;
} HstIPRange;

typedef struct HstIPHost {
	char *name; // ip addr or hostname in str format
	struct addrinfo *res; // result from running getaddrinfo
} HstIPHost;

typedef enum {
	HIT_IPHOST, // this works for both ip and host because we use getaddrinfo
	HIT_RANGE, // this work for both range and cidr
	HIT_UNK
} HstInputType;

typedef struct host_input Hst;
struct host_input {
	Hst * next;
	void * hst; // pointer to ether a HstIPHost or HstIPRange
	HstInputType type;
};



Prt* parse_ports(char *input);
Hst* parse_hosts(char *input);

HstIPRange* generate_ips_from_range(const char *range);

void free_hosts(Hst *host);
void free_ports(Prt *port);

