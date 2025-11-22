#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <lm.h>


#include <time.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Netapi32.lib")

#ifndef BOF
#include "parser.h"
#endif

#ifdef BOF
#include "beacon.h"
#include "portscanner-bof-inc.h"
#include "trustedsec-bof-print.h"

// cute hack
#include "parser.c" 

#include "trustedsec-bof-print.c" 

#include "utils.c"
#endif
    
#define MAX_NUM_SOCKETS 128
#define BUFFER_LEN 1024
#define CONN_TIMEOUT 100
#define READ_TIMEOUT 500


void connectOrTimeout(SOCKET *sockets, int socket_count) {
    WSAPOLLFD pollFd[MAX_NUM_SOCKETS];
    int numSockets = socket_count;
    char buffer[BUFFER_LEN];

    // Initialize the pollFd array
    for (int i = 0; i < numSockets; i++) {
        pollFd[i].fd = INVALID_SOCKET;
        pollFd[i].events = 0;
        pollFd[i].revents = 0;
    }

    // Add sockets to the pollFd array
    for (int i = 0; i < numSockets; i++) {
        pollFd[i].fd = sockets[i];
        pollFd[i].events = POLLOUT; // Specify POLLIN for reading
    }

    // Poll the sockets
    int result = WSAPoll(pollFd, numSockets, CONN_TIMEOUT);
    if (result > 0) {
        // Check the revents field for each socket
        for (int i = 0; i < numSockets; i++) {
            if (!(pollFd[i].revents & POLLOUT)) {
                pollFd[i].fd = INVALID_SOCKET;
                pollFd[i].events = 0;
                pollFd[i].revents = 0;
            } else {
                pollFd[i].revents = 0;
                pollFd[i].events = POLLIN; // Specify POLLIN for reading
            }
        }

        int result = WSAPoll(pollFd, numSockets, READ_TIMEOUT);
            // Check the revents field for each socket
        for (int i = 0; i < numSockets; i++) {
            if (pollFd[i].fd == INVALID_SOCKET) continue;

            *buffer = '\0';

            // get ip and port
            struct sockaddr_in peerAddress;
            int peerAddressLen = sizeof(peerAddress);
            getpeername(sockets[i], (struct sockaddr*)&peerAddress, &peerAddressLen);

            char target[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &peerAddress.sin_addr, target, INET_ADDRSTRLEN);
            int port = ntohs(peerAddress.sin_port);


            if (pollFd[i].revents & POLLIN) {
                int bytesRead = recv(sockets[i], buffer, BUFFER_LEN, 0);
                if (bytesRead > 0) {
                    buffer[bytesRead] = '\0'; // Null-terminate the received data
                }
            } else if (port == 445) {
                WCHAR  wtarget[256];
                const size_t WCHARBUF = strlen(target)+1;
                mbstowcs(wtarget, target, WCHARBUF);
                get_server_info(wtarget, buffer);
            }

            trimws(buffer);
            if (strlen(buffer))
                printf("%s:%d (%s)\n", target, port, buffer);
            else
                printf("%s:%d\n",target, port);
        }
    }
}

int connectTCPSocket(SOCKET sock, char *target, int port) {

    struct in_addr addr;
    addr.s_addr = inet_addr(target); // Convert string to in_addr

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // basically convert struct in_addr type to struct sockaddr_in type
    memcpy(&server.sin_addr, &addr, sizeof(server.sin_addr));

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR)
        return (WSAGetLastError() == WSAEWOULDBLOCK);

    return 1;

}

SOCKET createTCPSocket() {
    SOCKET sock = INVALID_SOCKET;
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    // set socket to non-blocking mode
    u_long mode = 1;
    if (ioctlsocket(sock, FIONBIO, &mode) != NO_ERROR) {
        printf("ioctlsocket failed: %d\n", WSAGetLastError());
        closesocket(sock);
        return INVALID_SOCKET;
    }
    return sock;
}

void closeAllSockets(SOCKET *sockets, int *socket_count) {
    for (int i=0;i<*socket_count;i++) closesocket(sockets[i]);
    *socket_count = 0;
}

void testPortsOnIp(char* target, Prt* ports) {
    SOCKET sockets[MAX_NUM_SOCKETS]; 
    int socket_count = 0;

    Prt* curr = ports;
    do {
        for(u_int i = curr->start; i <= curr->end; i++) {
            // create TCP Socket
            SOCKET s = createTCPSocket();
            if (s == INVALID_SOCKET) {
                // soemthing went wrong
                printf("[error] while allocating sockets\n");
                closeAllSockets(sockets, &socket_count);
                return;
            }

            // connect to socket
            if (!connectTCPSocket(s, target, (int) i)) {
                closesocket(s);
                continue;
            }

            sockets[socket_count] = s;
            socket_count++;

            if (socket_count != MAX_NUM_SOCKETS) continue;
            connectOrTimeout(sockets, socket_count);
            // close sockets 
            closeAllSockets(sockets, &socket_count);
        }

    } while ((curr=curr->next) != NULL);
    connectOrTimeout(sockets, socket_count);
    closeAllSockets(sockets, &socket_count);
}

int portscan(char *targetsStr, char *portsStr) {

    Hst* hosts = parse_hosts(targetsStr);
    Hst* hcurr = hosts;
    Prt* ports = parse_ports(portsStr);

    if (hosts == NULL || ports == NULL) {
        fprintf(stderr, "Couldn't parse ports or hosts\n");
        return EXIT_FAILURE;
    }

    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        printf("WSAStartup failed with error: %d\n", err);
        return EXIT_FAILURE;
    }

    do {
        if (hcurr->type == HIT_RANGE) {
            uint32_t start = ntohl(((HstIPRange*)(hcurr->hst))->start_addr.s_addr);
            uint32_t end = ntohl(((HstIPRange*)(hcurr->hst))->end_addr.s_addr);

            struct in_addr tmp;
            char ipAddressStr[INET_ADDRSTRLEN];

            for (uint32_t i = start; i <= end; i++) {
                tmp.s_addr = htonl(i);
                inet_ntop(AF_INET, &tmp, ipAddressStr, INET_ADDRSTRLEN);

                testPortsOnIp(ipAddressStr, ports);
            }
        } else if (hcurr->type == HIT_IPHOST) {

            HstIPHost *r = (HstIPHost*)(hcurr->hst);
            char *hostname = ((HstIPHost*)(hcurr->hst))->name;
            char ipAddressStr[INET_ADDRSTRLEN];

            for (struct addrinfo *p = r->res; p != NULL; p = p->ai_next) {
                void *addr;
                if (p->ai_family == AF_INET) {  // IPv4
                    struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                    addr = &(ipv4->sin_addr);
                } else {
                    continue;
                }

                inet_ntop(p->ai_family, addr, ipAddressStr, sizeof(ipAddressStr));

                testPortsOnIp(ipAddressStr, ports);
            }
        }
    } while((hcurr = hcurr->next) != NULL);

    free_hosts(hosts);
    free_ports(ports);

    WSACleanup();
}

#ifdef BOF
int go(char *argv, int argc) {
    if(!bofstart()) return 1; // init trustedsec output

    char *targets;
    int targets_len = -1;
    char *ports;
    int ports_len = -1;
    datap parser;
    BeaconDataParse(&parser, argv, argc);
    targets = BeaconDataExtract(&parser, &targets_len);
    ports = BeaconDataExtract(&parser, &ports_len);

    if (targets_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No targets provided\n");
        return 1;
    }

    if (ports_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No ports provided\n");
        return 1;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[.] portscanner: Scanning %s %s\n", targets, ports);

    portscan(targets, ports);

    printoutput(TRUE);

    return EXIT_SUCCESS;
}

#else

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <IP/Hostname> <Port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    time_t start_time, end_time;

    // Record start time
    time(&start_time);
    printf("Program started at: %s", ctime(&start_time));

    if (portscan(argv[1], argv[2]) == EXIT_FAILURE) return EXIT_FAILURE;

    // Record end time
    time(&end_time);
    printf("Program ended at: %s", ctime(&end_time));

    // Optionally, calculate elapsed time
    double elapsed_time = difftime(end_time, start_time);
    printf("Elapsed time: %.2f seconds\n", elapsed_time);

    return EXIT_SUCCESS;
}

#endif
