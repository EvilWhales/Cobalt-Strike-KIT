#pragma once
#include <windows.h>

typedef enum _PROXY_METHOD {
    PROXY_NONE = 0,
    PROXY_DRAUGR = 1,
    PROXY_REGWAIT = 2,
    PROXY_TIMER = 3
} PROXY_METHOD;

typedef enum _ALLOCATION_METHOD {
    ALLOC_HEAP = 0,
    ALLOC_VIRTUALALLOC = 1,
    ALLOC_STOMPING = 2
} ALLOCATION_METHOD;

typedef struct {
    PROXY_METHOD        Proxy;
    ALLOCATION_METHOD   Allocation;
    BYTE                StompModule[32];
    BOOL                AllocRWX;
    BOOL                UnhookNtdll;
    DWORD               Timeout;
    struct {
        BYTE            ModuleName[64];
        BYTE            ProcedureName[64];
        DWORD           Offset;
    } SpoofThread;

    // Use for module stomping
    struct {
        PVOID   OriginalContent;
        DWORD   ContentSize;
        PVOID   ModuleAddress;
    } RestoreStomping;
} CONFIG, *PCONFIG;

typedef struct _UNHOOK_MODULE {
    PVOID  pTextSectionAddress;  
    DWORD  dwTextSectionSize;    
    PVOID  pOriginalContent;     
} UNHOOK_MODULE, * PUNHOOK_MODULE;

// KERNEL32
DECLSPEC_IMPORT HMODULE     WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
DECLSPEC_IMPORT FARPROC     WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
DECLSPEC_IMPORT DWORD       WINAPI KERNEL32$GetLastError();
DECLSPEC_IMPORT VOID        WINAPI KERNEL32$ExitThread();
DECLSPEC_IMPORT int         WINAPI KERNEL32$MultiByteToWideChar(...);
DECLSPEC_IMPORT int         WINAPI KERNEL32$WideCharToMultiByte(...);

#define GetModuleHandleA  KERNEL32$GetModuleHandleA
#define GetProcAddress    KERNEL32$GetProcAddress
#define GetLastError      KERNEL32$GetLastError
#define ExitThread        KERNEL32$ExitThread
#define MultiByteToWideChar KERNEL32$MultiByteToWideChar
#define WideCharToMultiByte KERNEL32$WideCharToMultiByte

// NTDLL
DECLSPEC_IMPORT ULONG NTAPI                 NTDLL$RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
DECLSPEC_IMPORT	PRUNTIME_FUNCTION WINAPI	KERNEL32$RtlLookupFunctionEntry(DWORD64 ControlPc, PDWORD64 ImageBase,PUNWIND_HISTORY_TABLE HistoryTable);

#define RtlInitUnicodeString        NTDLL$RtlInitUnicodeString
#define RtlLookupFunctionEntry      KERNEL32$RtlLookupFunctionEntry

// MSVCRT
DECLSPEC_IMPORT PCHAR   __cdecl MSVCRT$strcmp(const char* str1, const char* str2);
DECLSPEC_IMPORT PVOID   __cdecl MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void    __cdecl MSVCRT$free(void* memblock);
DECLSPEC_IMPORT int     __cdecl MSVCRT$_vsnwprintf_s(...);
DECLSPEC_IMPORT int     __cdecl MSVCRT$vsnprintf(...);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$strncpy_s(...);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$wcsncpy_s(...);

#define strcmp MSVCRT$strcmp
#define malloc MSVCRT$malloc
#define free MSVCRT$free
#define _vsnwprintf_s MSVCRT$_vsnwprintf_s
#define vsnprintf MSVCRT$vsnprintf
#define strncpy_s MSVCRT$strncpy_s
#define wcsncpy_s MSVCRT$wcsncpy_s