typedef WCHAR* LMSTR;

WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
#define memset MSVCRT$memset
WINBASEAPI int WINAPI WS2_32$WSAStartup(WORD wVersionRequested,LPWSADATA lpWSAData);
#define WSAStartup WS2_32$WSAStartup
WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar (UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
#define MultiByteToWideChar KERNEL32$MultiByteToWideChar
WINBASEAPI PCHAR __cdecl MSVCRT$strchr(const char *haystack, int needle);
#define strchr MSVCRT$strchr
WINBASEAPI int __cdecl MSVCRT$sscanf(const char * __restrict__ _Src,const char * __restrict__ _Format,...);
#define sscanf MSVCRT$sscanf
DECLSPEC_IMPORT PCSTR WINAPI WS2_32$inet_ntop(INT Family,const VOID *pAddr,PSTR pStringBuf,size_t StringBufSize);
#define inet_ntop WS2_32$inet_ntop
DECLSPEC_IMPORT void __stdcall WS2_32$freeaddrinfo(struct addrinfo* ai);
#define freeaddrinfo WS2_32$freeaddrinfo
WINBASEAPI char *__cdecl MSVCRT$strtok(char * __restrict__ _Str,const char * __restrict__ _Delim);
#define strtok MSVCRT$strtok
DECLSPEC_IMPORT int __stdcall WS2_32$connect(SOCKET sock, const struct sockaddr* name, int namelen);
#define connect WS2_32$connect
WINBASEAPI INT WINAPI WS2_32$inet_pton(INT Family, LPCSTR pStringBuf, PVOID pAddr);
#define inet_pton WS2_32$inet_pton
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
#define malloc MSVCRT$malloc
WINBASEAPI int WINAPI WS2_32$setsockopt(SOCKET s,int level,int optname,const char *optval,int optlen);
#define setsockopt WS2_32$setsockopt
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetWkstaGetInfo(LMSTR servername,DWORD level,LPBYTE *bufptr);
#define NetWkstaGetInfo NETAPI32$NetWkstaGetInfo
DECLSPEC_IMPORT int __stdcall WS2_32$select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout);
#define select WS2_32$select
WINBASEAPI int WINAPI WS2_32$WSAGetLastError(void);
#define WSAGetLastError WS2_32$WSAGetLastError
WINBASEAPI u_short WINAPI WS2_32$htons(u_short hostshort);
#define htons WS2_32$htons
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
#define strlen MSVCRT$strlen
DECLSPEC_IMPORT ULONG WINAPI WS2_32$ntohl(ULONG netlong);
#define ntohl WS2_32$ntohl
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
#define sprintf MSVCRT$sprintf
WINBASEAPI unsigned long WINAPI WSOCK32$inet_addr(const char *cp);
#define inet_addr WSOCK32$inet_addr
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);
#define NetApiBufferFree NETAPI32$NetApiBufferFree
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
#define GetLastError KERNEL32$GetLastError
DECLSPEC_IMPORT int __stdcall WS2_32$getaddrinfo(char* host, char* port, const struct addrinfo* hints, struct addrinfo** result);
#define getaddrinfo WS2_32$getaddrinfo
WINBASEAPI u_long WINAPI WS2_32$htonl(u_long hostlong);
#define htonl WS2_32$htonl
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
#define memcpy MSVCRT$memcpy
WINBASEAPI int WINAPI WS2_32$WSACleanup(void);
#define WSACleanup WS2_32$WSACleanup
WINBASEAPI int WINAPI WS2_32$closesocket(SOCKET s);
#define closesocket WS2_32$closesocket
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
#define free MSVCRT$free
WINBASEAPI int WINAPI WS2_32$socket(int af,int type,int protocol);
#define socket WS2_32$socket
DECLSPEC_IMPORT int __stdcall WS2_32$ioctlsocket(SOCKET sock, long cmd, u_long* arg);
#define ioctlsocket WS2_32$ioctlsocket
WINBASEAPI int __cdecl MSVCRT$isspace(int _C);
#define isspace MSVCRT$isspace
DECLSPEC_IMPORT int __stdcall WS2_32$__WSAFDIsSet(SOCKET sock, struct fd_set* fdset);
#define __WSAFDIsSet WS2_32$__WSAFDIsSet 
WINBASEAPI int WINAPI WS2_32$recv(SOCKET s, char *buf, int len, int flags);
#define recv WS2_32$recv
WINBASEAPI  size_t      __cdecl     MSVCRT$mbstowcs (wchar_t*, const char*, size_t);
#define mbstowcs MSVCRT$mbstowcs


WINBASEAPI int WINAPI WS2_32$WSAPoll(WSAPOLLFD *fd,int x, int timeout);
#define WSAPoll WS2_32$WSAPoll
WINBASEAPI int WINAPI WS2_32$getpeername(SOCKET s,struct sockaddr *name, int *namelen);
#define getpeername WS2_32$getpeername
WINBASEAPI int WINAPI WS2_32$ntohs(u_short netshort);
#define ntohs WS2_32$ntohs

void internal_printf(const char* format, ...);

// simple fix
//#define printf(...) BeaconPrintf(CALLBACK_OUTPUT, ##__VA_ARGS__)
#define printf(x, ...) internal_printf(x, ##__VA_ARGS__)
//#define fprintf(x, ...) BeaconPrintf(x==stderr?CALLBACK_ERROR:CALLBACK_OUTPUT, ##__VA_ARGS__)
#define fprintf(x, ...) BeaconPrintf(CALLBACK_ERROR, ##__VA_ARGS__)
