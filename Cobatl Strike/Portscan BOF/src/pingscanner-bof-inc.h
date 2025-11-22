//WS2_32
// defining this here to avoid including ws2tcpip.h which results in include order warnings when bofs include windows.h before bofdefs.h

#define INET_ADDRSTRLEN 64


typedef struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    size_t ai_addrlen;
    char *ai_canonname;
    struct sockaddr *ai_addr;
    struct addrinfo *ai_next;
} ADDRINFOA,*PADDRINFOA;

DECLSPEC_IMPORT PCSTR WINAPI WS2_32$inet_ntop(INT Family,VOID *pAddr,PSTR pStringBuf,size_t StringBufSize);
#define inet_ntop WS2_32$inet_ntop

WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
#define free MSVCRT$free
WINBASEAPI u_long WINAPI WS2_32$htonl(u_long hostlong);
#define htonl WS2_32$htonl
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
#define GetLastError KERNEL32$GetLastError
DECLSPEC_IMPORT int __stdcall WS2_32$getaddrinfo(char* host, char* port, const struct addrinfo* hints, struct addrinfo** result);
#define getaddrinfo WS2_32$getaddrinfo
WINBASEAPI unsigned long WINAPI WSOCK32$inet_addr(const char *cp);
#define inet_addr WSOCK32$inet_addr
WINBASEAPI int WINAPI WS2_32$WSACleanup(void);
#define WSACleanup WS2_32$WSACleanup
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
#define CloseHandle KERNEL32$CloseHandle
WINBASEAPI int WINAPI WS2_32$WSAStartup(WORD wVersionRequested,LPWSADATA lpWSAData);
#define WSAStartup WS2_32$WSAStartup
WINBASEAPI char *__cdecl MSVCRT$strtok(char * __restrict__ _Str,const char * __restrict__ _Delim);
#define strtok MSVCRT$strtok
DECLSPEC_IMPORT void __stdcall WS2_32$freeaddrinfo(struct addrinfo* ai);
#define freeaddrinfo WS2_32$freeaddrinfo
WINBASEAPI INT WINAPI WS2_32$inet_pton(INT Family, LPCSTR pStringBuf, PVOID pAddr);
#define inet_pton WS2_32$inet_pton
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
#define memset MSVCRT$memset
WINBASEAPI int __cdecl MSVCRT$sscanf(const char * __restrict__ _Src,const char * __restrict__ _Format,...);
#define sscanf MSVCRT$sscanf
WINBASEAPI int WINAPI WS2_32$socket(int af,int type,int protocol);
#define socket WS2_32$socket
WINBASEAPI PCHAR __cdecl MSVCRT$strchr(const char *haystack, int needle);
#define strchr MSVCRT$strchr
DECLSPEC_IMPORT ULONG WINAPI WS2_32$ntohl(ULONG netlong);
#define ntohl WS2_32$ntohl
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
#define malloc MSVCRT$malloc
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$IcmpSendEcho(HANDLE IcmpHandle,IPAddr DestinationAddress,LPVOID RequestData,WORD RequestSize,PIP_OPTION_INFORMATION RequestOptions,LPVOID ReplyBuffer,DWORD ReplySize,DWORD Timeout);
#define IcmpSendEcho IPHLPAPI$IcmpSendEcho
DECLSPEC_IMPORT HANDLE WINAPI IPHLPAPI$IcmpCreateFile();
#define IcmpCreateFile IPHLPAPI$IcmpCreateFile
DECLSPEC_IMPORT BOOL WINAPI IPHLPAPI$IcmpCloseHandle(HANDLE IcmpHandle);
#define IcmpCloseHandle IPHLPAPI$IcmpCloseHandle


void internal_printf(const char* format, ...);

// simple fix
//#define printf(...) BeaconPrintf(CALLBACK_OUTPUT, ##__VA_ARGS__)
#define printf(x, ...) internal_printf(x, ##__VA_ARGS__)
//#define fprintf(x, ...) BeaconPrintf(x==stderr?CALLBACK_ERROR:CALLBACK_OUTPUT, ##__VA_ARGS__)
#define fprintf(x, ...) BeaconPrintf(CALLBACK_ERROR, ##__VA_ARGS__)
