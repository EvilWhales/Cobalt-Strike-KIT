#ifndef ASYNC_BOF_H
#define ASYNC_BOF_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <winsock.h>
#include <iphlpapi.h>
#include <winwlx.h>
#include <ntsecapi.h>
#include <winternl.h>

// 添加ETW和事件日志相关头文件
#include <evntrace.h>
#include <evntcons.h>
#include <winevt.h>

// 定义一些可能缺失的类型
#ifndef EVT_HANDLE
#define EVT_HANDLE HANDLE
#endif

#ifndef EVT_SUBSCRIBE_NOTIFY_ACTION
typedef enum _EVT_SUBSCRIBE_NOTIFY_ACTION {
    EvtSubscribeActionError,
    EvtSubscribeActionDeliver
} EVT_SUBSCRIBE_NOTIFY_ACTION;
#endif

#ifndef EVT_SUBSCRIBE_CALLBACK
typedef DWORD (WINAPI *EVT_SUBSCRIBE_CALLBACK)(
    EVT_SUBSCRIBE_NOTIFY_ACTION Action,
    PVOID UserContext,
    EVT_HANDLE Event
);
#endif

#ifndef PEVENT_RECORD
typedef struct _EVENT_RECORD EVENT_RECORD, *PEVENT_RECORD;
#endif

// 确保基本类型定义可用
#ifndef ULONG_PTR
#ifdef _WIN64
#define ULONG_PTR unsigned long long
#else
#define ULONG_PTR unsigned long
#endif
#endif

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

// 常量定义
#ifndef CF_TEXT
#define CF_TEXT 1
#endif

#ifndef IF_TYPE_IEEE80211
#define IF_TYPE_IEEE80211 71
#endif

#ifndef ERROR_FILE_NOT_FOUND
#define ERROR_FILE_NOT_FOUND 2L
#endif

#ifndef SERVICE_RUNNING
#define SERVICE_RUNNING 0x00000004
#endif

#ifndef SC_MANAGER_CONNECT
#define SC_MANAGER_CONNECT 0x0001
#endif

#ifndef SERVICE_QUERY_STATUS
#define SERVICE_QUERY_STATUS 0x0004
#endif

// 事件监控相关常量
#define MAX_EVENT_BUFFER_SIZE 1024
#define EVENT_LOG_CHANNEL_SECURITY L"Security"
#define EVENT_LOG_CHANNEL_SYSTEM L"System"
#define EVENT_LOG_CHANNEL_APPLICATION L"Application"

// 真实事件监控函数声明
// （将在结构体定义之后重新声明）

// ETW相关常量
// #define KERNEL_LOGGER_NAME L"NT Kernel Logger"  // 注释掉，使用系统定义
#define PROCESS_TRACE_CONTROL_GUID {0x68fdd900, 0x4a3e, 0x11d1, {0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3}}

// Cobalt Strike BOF API definitions
typedef struct {
    char* original;
    char* resolved;
} datap;

// Beacon API函数声明
void BeaconPrintf(int type, char* fmt, ...);
void BeaconDataParse(datap* parser, char* buffer, int size);
int BeaconDataInt(datap* parser);
short BeaconDataShort(datap* parser);
int BeaconDataLength(datap* parser);
char* BeaconDataExtract(datap* parser, int* size);

// 内存操作函数声明
void* MSVCRT$malloc(size_t size);
void MSVCRT$free(void* ptr);
void* MSVCRT$calloc(size_t num, size_t size);
int MSVCRT$strcmp(const char* str1, const char* str2);
char* MSVCRT$strcpy(char* dest, const char* src);
char* MSVCRT$strncpy(char* dest, const char* src, size_t n);
size_t MSVCRT$strlen(const char* str);
void* MSVCRT$memset(void* ptr, int value, size_t num);
int MSVCRT$sprintf(char* str, const char* format, ...);
char* MSVCRT$strstr(const char* str, const char* substr);

// Windows API函数声明
// 基本Windows API
BOOL WINAPI KERNEL32$GetLastError(VOID);
HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
BOOL WINAPI KERNEL32$GlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer);
HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
BOOL WINAPI KERNEL32$FindClose(HANDLE hFindFile);

// 事件日志相关API
HANDLE WINAPI ADVAPI32$OpenEventLogA(LPCSTR lpUNCServerName, LPCSTR lpSourceName);
BOOL WINAPI ADVAPI32$ReadEventLogA(HANDLE hEventLog, DWORD dwReadFlags, DWORD dwRecordOffset, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, DWORD *pnBytesRead, DWORD *pnMinNumberOfBytesNeeded);
BOOL WINAPI ADVAPI32$CloseEventLog(HANDLE hEventLog);

// 新的Windows事件API (Vista+)
#ifdef __cplusplus
extern "C" {
#endif
EVT_HANDLE WINAPI WEVTAPI$EvtSubscribe(EVT_HANDLE Session, HANDLE SignalEvent, LPCWSTR ChannelPath, LPCWSTR Query, EVT_HANDLE Bookmark, PVOID Context, EVT_SUBSCRIBE_CALLBACK Callback, DWORD Flags);
BOOL WINAPI WEVTAPI$EvtClose(EVT_HANDLE Object);
#ifdef __cplusplus
}
#endif
HANDLE WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
HANDLE WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DWORD WINAPI KERNEL32$GetCurrentThreadId(VOID);
DWORD WINAPI KERNEL32$GetTickCount(VOID);
DWORD WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
HGLOBAL WINAPI KERNEL32$GlobalLock(HGLOBAL hMem);
BOOL WINAPI KERNEL32$GlobalUnlock(HGLOBAL hMem);
HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL hMem);

LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LONG WINAPI ADVAPI32$RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
LONG WINAPI ADVAPI32$RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);
LONG WINAPI ADVAPI32$RegDeleteValueA(HKEY hKey, LPCSTR lpValueName);
LONG WINAPI ADVAPI32$RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey);
LONG WINAPI ADVAPI32$RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime);
BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
BOOL WINAPI ADVAPI32$AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD nSubAuthority0, DWORD nSubAuthority1, DWORD nSubAuthority2, DWORD nSubAuthority3, DWORD nSubAuthority4, DWORD nSubAuthority5, DWORD nSubAuthority6, DWORD nSubAuthority7, PSID *pSid);
BOOL WINAPI ADVAPI32$EqualSid(PSID pSid1, PSID pSid2);
PVOID WINAPI ADVAPI32$FreeSid(PSID pSid);

HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL WINAPI KERNEL32$Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL WINAPI KERNEL32$Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess);
BOOL WINAPI ADVAPI32$QueryServiceStatus(SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus);
BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
DWORD WINAPI IPHLPAPI$GetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen);
DWORD WINAPI IPHLPAPI$GetNetworkParams(PFIXED_INFO pFixedInfo, PULONG pOutBufLen);

// USER32 API函数声明 (用于剪贴板和键盘监控)
BOOL WINAPI USER32$OpenClipboard(HWND hWndNewOwner);
BOOL WINAPI USER32$CloseClipboard(VOID);
HANDLE WINAPI USER32$GetClipboardData(UINT uFormat);
BOOL WINAPI USER32$AddClipboardFormatListener(HWND hwnd);
BOOL WINAPI USER32$RemoveClipboardFormatListener(HWND hwnd);
BOOL WINAPI USER32$GetLastInputInfo(PLASTINPUTINFO plii);

// 添加LASTINPUTINFO结构体定义
#ifndef LASTINPUTINFO
typedef struct tagLASTINPUTINFO {
    UINT cbSize;
    DWORD dwTime;
} LASTINPUTINFO, *PLASTINPUTINFO;
#endif

// 添加MEMORYSTATUSEX结构体定义
#ifndef MEMORYSTATUSEX
typedef struct _MEMORYSTATUSEX {
    DWORD dwLength;
    DWORD dwMemoryLoad;
    DWORDLONG ullTotalPhys;
    DWORDLONG ullAvailPhys;
    DWORDLONG ullTotalPageFile;
    DWORDLONG ullAvailPageFile;
    DWORDLONG ullTotalVirtual;
    DWORDLONG ullAvailVirtual;
    DWORDLONG ullAvailExtendedVirtual;
} MEMORYSTATUSEX, *LPMEMORYSTATUSEX;
#endif

// 添加WIN32_FIND_DATAA结构体定义
#ifndef WIN32_FIND_DATAA
typedef struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[MAX_PATH];
    CHAR cAlternateFileName[14];
} WIN32_FIND_DATAA, *PWIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;
#endif

// Token相关API
BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
DWORD WINAPI KERNEL32$GetTickCount64(VOID);

// 事件类型定义
typedef enum {
    EVENT_ADMIN_LOGIN,
    EVENT_PROCESS_START,
    EVENT_USER_LOGIN,
    EVENT_NETWORK_ISOLATION,
    EVENT_VPN_CONNECTION,
    EVENT_WIFI_CONNECTION,
    EVENT_TICKET_EXPIRATION,
    EVENT_CLIPBOARD_COPY,
    EVENT_KEYBOARD_INPUT,
    EVENT_USER_LOGON,
    // 新增真实事件监控类型
    EVENT_REAL_PROCESS_CREATE,    // 真实进程创建事件
    EVENT_REAL_PROCESS_TERMINATE, // 真实进程终止事件
    EVENT_REAL_FILE_ACCESS,       // 文件访问事件
    EVENT_REAL_REGISTRY_CHANGE,   // 注册表变更事件
    EVENT_REAL_NETWORK_CONNECTION,// 网络连接事件
    EVENT_REAL_LOGIN_ATTEMPT,     // 真实登录尝试事件
    EVENT_REAL_PRIVILEGE_ESCALATION // 权限提升事件
} event_type_t;

// 任务状态定义
typedef enum {
    TASK_PENDING,
    TASK_RUNNING,
    TASK_COMPLETED,
    TASK_CANCELLED
} task_status_t;

// 事件监控模式
typedef enum {
    MONITOR_MODE_POLLING,    // 轮询模式（当前实现）
    MONITOR_MODE_EVENT_LOG,  // Windows事件日志
    MONITOR_MODE_ETW,        // Event Tracing for Windows
    MONITOR_MODE_WMI,        // WMI事件订阅
    MONITOR_MODE_HOOK        // API Hook
} monitor_mode_t;

// 事件结构体
typedef struct {
    event_type_t type;
    char host[64];
    monitor_mode_t mode;  // 监控模式
    DWORD event_id;       // Windows事件ID
    ULONGLONG timestamp;  // 事件时间戳
    union {
        struct {
            char username[64];
            DWORD session_id;
            char source_ip[32];
        } admin_login;
        struct {
            char process_name[64];
            DWORD process_id;
            DWORD parent_pid;
            char command_line[256];
            char image_path[260];
        } process_start;
        struct {
            char username[64];
            int is_remote;
            DWORD session_id;
            char source_workstation[64];
        } user_login;
        struct {
            char ssid[64];
            char adapter_name[64];
        } wifi_connection;
        struct {
            unsigned int minutes_left;
            char ticket_type[32];
        } ticket_expiration;
        struct {
            char file_path[260];
            DWORD access_type;
            char process_name[64];
        } file_access;
        struct {
            char key_path[260];
            char value_name[64];
            DWORD change_type;
        } registry_change;
        struct {
            char local_address[32];
            char remote_address[32];
            DWORD local_port;
            DWORD remote_port;
            char protocol[16];
        } network_connection;
        struct {
            char name[64];
            char data[128];
        } custom;
    } data;
} event_t;

// 任务结构体
typedef struct async_task {
    char name[64];
    task_status_t status;
    event_type_t event_type;
    monitor_mode_t monitor_mode;  // 监控模式
    char params[256];
    unsigned int interval;   // 检查间隔（秒）
    unsigned int last_check; // 上次检查时间
    unsigned int task_id;    // 任务ID
    HANDLE thread_handle;    // 线程句柄
    DWORD thread_id;         // 线程ID
    
    // 事件监控相关句柄
    HANDLE event_log_handle;      // 事件日志句柄
    HANDLE etw_session_handle;    // ETW会话句柄
    EVT_HANDLE event_subscription; // 事件订阅句柄
    
    // 统计信息
    DWORD events_detected;        // 检测到的事件数
    DWORD false_positives;        // 误报数
    ULONGLONG start_time;         // 任务开始时间
    
    struct async_task* next; // 指向下一个任务的指针
} async_task_t;

// 函数声明
void go(char* args, int length);
int check_event(async_task_t* task);
void report_event(async_task_t* task);
event_t* create_event(event_type_t type, const char* host);
void destroy_event(event_t* event);
int monitor_admin_login(async_task_t* task);
int monitor_process_start(async_task_t* task);
int monitor_user_login(async_task_t* task);
int monitor_network_isolation(async_task_t* task);
int monitor_vpn_connection(async_task_t* task);
int monitor_wifi_connection(async_task_t* task);
int monitor_ticket_expiration(async_task_t* task);
DWORD WINAPI task_thread_proc(LPVOID param);
async_task_t* create_task(const char* name, event_type_t type, const char* params, unsigned int interval);
void destroy_task(async_task_t* task);
int save_task(async_task_t* task);
int load_tasks();
int cancel_task(unsigned int task_id);
void list_tasks();
int delete_task(unsigned int task_id);
async_task_t* get_task_by_id(unsigned int task_id);

// 新增的监控函数
int monitor_clipboard_copy(async_task_t* task);
int monitor_keyboard_input(async_task_t* task);
int monitor_user_logon(async_task_t* task);

// 真实事件监控函数
int monitor_real_process_events(async_task_t* task);
int monitor_real_file_access(async_task_t* task);
int monitor_real_registry_changes(async_task_t* task);
int monitor_real_network_events(async_task_t* task);
int monitor_real_login_events(async_task_t* task);
int monitor_real_privilege_escalation(async_task_t* task);
int monitor_process_events_via_eventlog(async_task_t* task);
int monitor_process_events_via_etw(async_task_t* task);

// 事件监控设置函数
int setup_event_log_monitoring(async_task_t* task);
int setup_etw_monitoring(async_task_t* task);
int setup_wmi_monitoring(async_task_t* task);
void cleanup_event_monitoring(async_task_t* task);

// 事件解析辅助函数
char* extract_username_from_event(EVENTLOGRECORD* pRecord);
const char* get_login_event_description(DWORD event_id);

// 事件处理回调函数
DWORD WINAPI event_log_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID user_context, EVT_HANDLE event);
void WINAPI etw_event_callback(PEVENT_RECORD event_record);

// 工具函数
WCHAR* get_event_xml_data(EVT_HANDLE event, LPCWSTR property_name);
DWORD get_event_data_dword(EVT_HANDLE event, LPCWSTR property_name);
ULONGLONG get_event_data_ulonglong(EVT_HANDLE event, LPCWSTR property_name);
int parse_event_data(EVT_HANDLE event, event_t* parsed_event);

// 错误处理和日志记录
typedef enum {
    ASYNC_BOF_SUCCESS = 0,
    ASYNC_BOF_ERROR_MEMORY_ALLOCATION,
    ASYNC_BOF_ERROR_INVALID_PARAMETER,
    ASYNC_BOF_ERROR_API_FAILURE,
    ASYNC_BOF_ERROR_REGISTRY_ACCESS,
    ASYNC_BOF_ERROR_THREAD_CREATION,
    ASYNC_BOF_ERROR_EVENT_LOG_ACCESS,
    ASYNC_BOF_ERROR_PERMISSION_DENIED,
    ASYNC_BOF_ERROR_TIMEOUT,
    ASYNC_BOF_ERROR_UNKNOWN
} async_bof_error_t;

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARNING = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_CRITICAL = 4
} log_level_t;

// 错误处理函数声明
void set_last_error(async_bof_error_t error, const char* message);
async_bof_error_t get_last_error();
const char* get_last_error_message();
const char* get_error_string(async_bof_error_t error);
void log_message(log_level_t level, const char* function, int line, const char* format, ...);
void set_log_level(log_level_t level);
void* safe_malloc(size_t size);
void safe_free(void* ptr);
int safe_strcpy(char* dest, size_t dest_size, const char* src);
int safe_strncpy(char* dest, size_t dest_size, const char* src, size_t count);
int safe_sprintf(char* dest, size_t dest_size, const char* format, ...);
int safe_strcat(char* dest, size_t dest_size, const char* src);
int validate_task_params(const char* name, event_type_t type, const char* params);
int check_win32_error(const char* api_name, BOOL result);
int check_admin_privileges();
void cleanup_resources();
void init_error_handling();

#ifndef BOF_BUILD
// 本地测试环境不需要重新声明这些函数
#else
// BOF环境下的缺失API声明
int MSVCRT$vsprintf(char* str, const char* format, va_list args);
char* MSVCRT$strncat(char* dest, const char* src, size_t n);
char* MSVCRT$strcat(char* dest, const char* src);
// 注意：GetLastError() 在Windows.h中已经声明，不需要重复声明
#endif

// 日志记录宏定义
#define LOG_DEBUG(format, ...) log_message(LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) log_message(LOG_LEVEL_INFO, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define LOG_WARNING(format, ...) log_message(LOG_LEVEL_WARNING, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) log_message(LOG_LEVEL_ERROR, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define LOG_CRITICAL(format, ...) log_message(LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)

// OPSEC和安全函数声明
unsigned int get_randomized_interval(unsigned int base_interval);
void secure_zero_memory(void* ptr, size_t size);
void secure_zero_string(char* str);
void xor_obfuscate(char* data, size_t len, BYTE key);
void xor_deobfuscate(char* data, size_t len, BYTE key);
int is_debugger_present();
int is_sandbox_environment();
void perform_decoy_operations();
void* resolve_api(const char* dll_name, const char* api_name);
int indirect_syscall(DWORD syscall_number, void* params);
void configure_opsec(int randomize_intervals, int use_decoy_ops, 
                    int clean_memory, int obfuscate_strings, int min_footprint);
void get_opsec_config(int* config_array);
int perform_security_check();
void obfuscate_memory_data(void* data, size_t size, BYTE key);
void deobfuscate_memory_data(void* data, size_t size, BYTE key);

// 本地测试相关函数声明
#ifndef BOF_BUILD
int main(int argc, char* argv[]);
void test_local_functionality();
#endif

#endif // ASYNC_BOF_H