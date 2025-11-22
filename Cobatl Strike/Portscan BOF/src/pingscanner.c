#include <winsock2.h>
#include <windows.h>

#include <stdio.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#pragma comment(lib, "iphlpapi.lib")

#ifdef BOF
#include "beacon.h"
#include "pingscanner-bof-inc.h"
#include "trustedsec-bof-print.h"

// cute hack
#include "parser.c" 
#include "trustedsec-bof-print.c" 
#endif

// NOTE: I haven't looked into the ICMP full specs
// so there could be other options/values that are set by the host's `ping` command
// however looking at the packets I'm not able to differentiate which is which.
// TLDR. Do your own research.

// match the default ping command's data
#define ICMP_ECHO_DATA "abcdefghijklmnopqrstuvwabdcefghi"
#define ICMP_REPLY_SIZE sizeof(ICMP_ECHO_REPLY) + sizeof(ICMP_ECHO_DATA)

#define ICMP_TIMEOUT 800 // in ms

// passing a handle to the hIcmpFile here so it can be reused
// probably not threadsafe tbh
DWORD ping_ip(HANDLE hIcmpFile, IPAddr ip, PICMP_ECHO_REPLY reply) {

	IP_OPTION_INFORMATION options = {0};
	options.Ttl = 128; // match the default ping command's ttl

	return IcmpSendEcho(
			hIcmpFile,
			ip,
			ICMP_ECHO_DATA,
			sizeof(ICMP_ECHO_DATA)-1, // cant remember why you need -1 here but IcmpSendEcho complains otherwise
			&options, 
			reply,
			ICMP_REPLY_SIZE,
			(DWORD) ICMP_TIMEOUT
			);
}

int ping_targets(char* targets) {
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        printf("WSAStartup failed with error: %d\n", err);
        return 1;
    }

    // TODO: check that WSA startup loaded a useable winsock version
    // https://learn.microsoft.com/en-gb/windows/win32/api/winsock/nf-winsock-wsastartup

    HANDLE hIcmpFile;
    char replyBuffer[ICMP_REPLY_SIZE];
    PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)replyBuffer;

    Hst* hosts = parse_hosts(targets);
    Hst* curr = hosts;

    // Open a handle for ICMP
    hIcmpFile = IcmpCreateFile();
    if (hIcmpFile == INVALID_HANDLE_VALUE) {
        printf("Unable to open ICMP handle. Error: %ld\n", GetLastError());
        return 1;
    }

    do {
        if (curr->type == HIT_RANGE) {
            // iterate over each ip from start to end
            uint32_t start = ntohl(((HstIPRange*)(curr->hst))->start_addr.s_addr);
            uint32_t end = ntohl(((HstIPRange*)(curr->hst))->end_addr.s_addr);

            struct in_addr tmp;
            char ipAddressStr[INET_ADDRSTRLEN];

            for (uint32_t i = start; i <= end; i++) {
                tmp.s_addr = htonl(i);
                inet_ntop(AF_INET, &tmp, ipAddressStr, INET_ADDRSTRLEN);

                IPAddr ipAddr = inet_addr(ipAddressStr);
                if (ipAddr == INADDR_NONE) {
                    printf("Invalid IP address: %s\n", ipAddressStr);
                    return 1;
                }

                DWORD dwRetVal = ping_ip(hIcmpFile, ipAddr, reply);

                if (dwRetVal != 0) {
                    printf("Reply from %s: bytes=%ld time=%ldms TTL=%d\n",
                           ipAddressStr,
                           reply->DataSize,
                           reply->RoundTripTime,
                           reply->Options.Ttl
                           );
                }
                // else: printf("Ping failed for %s. Error: %ld\n", ipAddressStr, GetLastError());
            }
        } else if (curr->type == HIT_IPHOST) {
            HstIPHost *r = (HstIPHost*)(curr->hst);
            char *hostname = ((HstIPHost*)(curr->hst))->name;
            char ipAddressStr[INET_ADDRSTRLEN];

            for (struct addrinfo *p = r->res; p != NULL; p = p->ai_next) {
                void *addr;
                if (p->ai_family == AF_INET) {  // IPv4
                    struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                    addr = &(ipv4->sin_addr);
                    /*        // currently not support IPV6
                          } else if (p->ai_family == AF_INET6) {  // IPv6
                          struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
                          addr = &(ipv6->sin6_addr);
                    */
                } else {
                    continue;
                }

                inet_ntop(p->ai_family, addr, ipAddressStr, sizeof(ipAddressStr));

                IPAddr ipAddr = inet_addr(ipAddressStr);
                if (ipAddr == INADDR_NONE) {
                    printf("Invalid IP address: %s\n", ipAddressStr);
                    return 1;
                }

                DWORD dwRetVal = ping_ip(hIcmpFile, ipAddr, reply);

                if (dwRetVal != 0) {
                    printf("Reply from %s [%s]: bytes=%ld time=%ldms TTL=%d\n",
                           hostname,
                           ipAddressStr,
                           reply->DataSize,
                           reply->RoundTripTime,
                           reply->Options.Ttl
                           );
                }
                // else: printf("Ping failed for %s [%s]. Error: %ld\n", hostname, ipAddressStr, GetLastError());
            }
        }
    } while((curr = curr->next) != NULL);

    IcmpCloseHandle(hIcmpFile);
    WSACleanup();

    //free_hosts(hosts);
    return 0;
}

#ifdef BOF

int go(char *argv, int argc) {
    if(!bofstart()) return 1; // init trustedsec output
    
    char *targets;
    int targets_len = -1;
    datap parser;
    BeaconDataParse(&parser, argv, argc);
    targets = BeaconDataExtract(&parser, &targets_len);
	if (targets_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No targets provided\n");
		return 1;
	}
    
    BeaconPrintf(CALLBACK_OUTPUT, "[.] Attempting to ping targets: %s\n", targets);
    ping_targets(targets);

    printoutput(TRUE);

    return 0;
}

#else

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Usage: %s <IP Address>\n", argv[0]);
		return 1;
	}

    ping_targets(argv[1]);

    return 0;
}

#endif
