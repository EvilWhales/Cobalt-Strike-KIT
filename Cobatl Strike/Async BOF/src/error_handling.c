#include "async_bof.h"

// 本地测试时的函数映射
#ifndef BOF_BUILD
#define MSVCRT$vsprintf vsprintf
#define MSVCRT$strncat strncat
#define MSVCRT$strcat strcat
#endif

// ================================================================
// 错误处理和日志记录模块
// ================================================================

// 全局错误状态
static async_bof_error_t last_error = ASYNC_BOF_SUCCESS;
static char last_error_message[512] = {0};
static log_level_t current_log_level = LOG_LEVEL_INFO;

// 错误代码到字符串的映射
const char* get_error_string(async_bof_error_t error) {
    switch (error) {
        case ASYNC_BOF_SUCCESS:
            return "Success";
        case ASYNC_BOF_ERROR_MEMORY_ALLOCATION:
            return "Memory allocation failed";
        case ASYNC_BOF_ERROR_INVALID_PARAMETER:
            return "Invalid parameter";
        case ASYNC_BOF_ERROR_API_FAILURE:
            return "Windows API call failed";
        case ASYNC_BOF_ERROR_REGISTRY_ACCESS:
            return "Registry access failed";
        case ASYNC_BOF_ERROR_THREAD_CREATION:
            return "Thread creation failed";
        case ASYNC_BOF_ERROR_EVENT_LOG_ACCESS:
            return "Event log access failed";
        case ASYNC_BOF_ERROR_PERMISSION_DENIED:
            return "Permission denied";
        case ASYNC_BOF_ERROR_TIMEOUT:
            return "Operation timeout";
        default:
            return "Unknown error";
    }
}

// 设置错误状态
void set_last_error(async_bof_error_t error, const char* message) {
    last_error = error;
    if (message) {
        MSVCRT$strncpy(last_error_message, message, sizeof(last_error_message) - 1);
        last_error_message[sizeof(last_error_message) - 1] = '\0';
    } else {
        last_error_message[0] = '\0';
    }
}

// 获取最后的错误
async_bof_error_t get_last_error() {
    return last_error;
}

// 获取最后的错误消息
const char* get_last_error_message() {
    return last_error_message;
}

// 日志记录函数
void log_message(log_level_t level, const char* function, int line, const char* format, ...) {
    // 检查日志级别
    if (level < current_log_level) {
        return;
    }
    
    // 获取时间戳
    DWORD tick_count = KERNEL32$GetTickCount();
    
    // 日志级别字符串
    const char* level_str[] = {"DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"};
    
    // 构建日志消息
    char log_buffer[1024];
    char format_buffer[512];
    
    // 添加时间戳和级别信息
    safe_sprintf(format_buffer, sizeof(format_buffer), "[%s][%lu][%s:%d] %s", 
                   level_str[level], tick_count, function, line, format);
    
    // 格式化用户消息
    va_list args;
    va_start(args, format);
    MSVCRT$vsprintf(log_buffer, format_buffer, args);
    va_end(args);
    
    // 输出到Beacon
    int beacon_type = (level >= LOG_LEVEL_ERROR) ? 2 : 0;
    BeaconPrintf(beacon_type, "%s", log_buffer);
}

// 设置日志级别
void set_log_level(log_level_t level) {
    current_log_level = level;
}

// 错误处理宏定义
#define SET_ERROR(code, msg) set_last_error(code, msg)
#define LOG_DEBUG(format, ...) log_message(LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) log_message(LOG_LEVEL_INFO, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define LOG_WARNING(format, ...) log_message(LOG_LEVEL_WARNING, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) log_message(LOG_LEVEL_ERROR, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define LOG_CRITICAL(format, ...) log_message(LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)

// 安全的内存分配函数
void* safe_malloc(size_t size) {
    if (size == 0) {
        SET_ERROR(ASYNC_BOF_ERROR_INVALID_PARAMETER, "Invalid memory size (0)");
        return NULL;
    }
    
    void* ptr = MSVCRT$malloc(size);
    if (!ptr) {
        SET_ERROR(ASYNC_BOF_ERROR_MEMORY_ALLOCATION, "Memory allocation failed");
        LOG_ERROR("Failed to allocate %zu bytes", size);
    } else {
        LOG_DEBUG("Allocated %zu bytes at %p", size, ptr);
        MSVCRT$memset(ptr, 0, size); // 初始化为0
    }
    
    return ptr;
}

// 安全的内存释放函数
void safe_free(void* ptr) {
    if (ptr) {
        LOG_DEBUG("Freeing memory at %p", ptr);
        MSVCRT$free(ptr);
    }
}

// 安全的字符串复制函数
int safe_strcpy(char* dest, size_t dest_size, const char* src) {
    if (!dest || !src || dest_size == 0) {
        SET_ERROR(ASYNC_BOF_ERROR_INVALID_PARAMETER, "Invalid parameter for strcpy");
        return 0;
    }
    
    size_t src_len = MSVCRT$strlen(src);
    if (src_len >= dest_size) {
        LOG_WARNING("String truncation in strcpy: %zu -> %zu", src_len, dest_size - 1);
        MSVCRT$strncpy(dest, src, dest_size - 1);
        dest[dest_size - 1] = '\0';
        return 0;
    }
    
    MSVCRT$strcpy(dest, src);
    return 1;
}

// 安全的字符串复制函数（带长度限制）
int safe_strncpy(char* dest, size_t dest_size, const char* src, size_t count) {
    if (!dest || !src || dest_size == 0) {
        SET_ERROR(ASYNC_BOF_ERROR_INVALID_PARAMETER, "Invalid parameter for strncpy");
        return 0;
    }
    
    size_t copy_len = count < dest_size - 1 ? count : dest_size - 1;
    MSVCRT$strncpy(dest, src, copy_len);
    dest[copy_len] = '\0';
    
    if (count >= dest_size - 1) {
        LOG_WARNING("String truncation in strncpy: requested %zu, copied %zu", count, copy_len);
        return 0;
    }
    
    return 1;
}

// 安全的字符串格式化函数
int safe_sprintf(char* dest, size_t dest_size, const char* format, ...) {
    if (!dest || !format || dest_size == 0) {
        SET_ERROR(ASYNC_BOF_ERROR_INVALID_PARAMETER, "Invalid parameter for sprintf");
        return 0;
    }
    
    va_list args;
    va_start(args, format);
    
    // 使用vsnprintf的等效实现
    char temp_buffer[4096]; // 临时缓冲区
    int result = MSVCRT$vsprintf(temp_buffer, format, args);
    va_end(args);
    
    if (result < 0) {
        SET_ERROR(ASYNC_BOF_ERROR_API_FAILURE, "Formatting failed");
        return 0;
    }
    
    size_t temp_len = MSVCRT$strlen(temp_buffer);
    if (temp_len >= dest_size) {
        LOG_WARNING("String truncation in sprintf: %zu -> %zu", temp_len, dest_size - 1);
        MSVCRT$strncpy(dest, temp_buffer, dest_size - 1);
        dest[dest_size - 1] = '\0';
        return 0;
    }
    
    MSVCRT$strcpy(dest, temp_buffer);
    return 1;
}

// 安全的字符串连接函数
int safe_strcat(char* dest, size_t dest_size, const char* src) {
    if (!dest || !src || dest_size == 0) {
        SET_ERROR(ASYNC_BOF_ERROR_INVALID_PARAMETER, "Invalid parameter for strcat");
        return 0;
    }
    
    size_t dest_len = MSVCRT$strlen(dest);
    size_t src_len = MSVCRT$strlen(src);
    
    if (dest_len + src_len >= dest_size) {
        LOG_WARNING("String truncation in strcat: %zu + %zu > %zu", dest_len, src_len, dest_size - 1);
        size_t copy_len = dest_size - dest_len - 1;
        MSVCRT$strncat(dest, src, copy_len);
        dest[dest_size - 1] = '\0';
        return 0;
    }
    
    MSVCRT$strcat(dest, src);
    return 1;
}

// 验证参数的辅助函数
int validate_task_params(const char* name, event_type_t type, const char* params) {
    if (!name || MSVCRT$strlen(name) == 0) {
        SET_ERROR(ASYNC_BOF_ERROR_INVALID_PARAMETER, "Task name cannot be empty");
        return 0;
    }
    
    if (MSVCRT$strlen(name) >= 64) {
        SET_ERROR(ASYNC_BOF_ERROR_INVALID_PARAMETER, "Task name too long");
        return 0;
    }
    
    if (type < EVENT_ADMIN_LOGIN || type > EVENT_REAL_PRIVILEGE_ESCALATION) {
        SET_ERROR(ASYNC_BOF_ERROR_INVALID_PARAMETER, "Invalid event type");
        return 0;
    }
    
    if (!params) {
        SET_ERROR(ASYNC_BOF_ERROR_INVALID_PARAMETER, "Parameters cannot be NULL");
        return 0;
    }
    
    return 1;
}

// Windows API错误检查函数
int check_win32_error(const char* api_name, BOOL result) {
    if (!result) {
        DWORD error_code = GetLastError();
        char error_msg[256];
        safe_sprintf(error_msg, sizeof(error_msg), "%s failed with error code %lu", api_name, error_code);
        SET_ERROR(ASYNC_BOF_ERROR_API_FAILURE, error_msg);
        LOG_ERROR("%s", error_msg);
        return 0;
    }
    return 1;
}

// 权限检查函数
int check_admin_privileges() {
    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        LOG_WARNING("Failed to open process token for privilege check");
        return 0;
    }
    
    DWORD dwSize = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);
    if (dwSize == 0) {
        KERNEL32$CloseHandle(hToken);
        return 0;
    }
    
    PTOKEN_GROUPS pGroupInfo = (PTOKEN_GROUPS)safe_malloc(dwSize);
    if (!pGroupInfo) {
        KERNEL32$CloseHandle(hToken);
        return 0;
    }
    
    if (!ADVAPI32$GetTokenInformation(hToken, TokenGroups, pGroupInfo, dwSize, &dwSize)) {
        safe_free(pGroupInfo);
        KERNEL32$CloseHandle(hToken);
        return 0;
    }
    
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
    PSID pAdminSid = NULL;
    int is_admin = 0;
    
    if (ADVAPI32$AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID, 
                                         DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSid)) {
        for (DWORD i = 0; i < pGroupInfo->GroupCount; i++) {
            if (ADVAPI32$EqualSid(pAdminSid, pGroupInfo->Groups[i].Sid)) {
                is_admin = 1;
                break;
            }
        }
        ADVAPI32$FreeSid(pAdminSid);
    }
    
    safe_free(pGroupInfo);
    KERNEL32$CloseHandle(hToken);
    
    LOG_INFO("Admin privilege check result: %s", is_admin ? "YES" : "NO");
    return is_admin;
}

// 清理资源的函数
void cleanup_resources() {
    LOG_INFO("Cleaning up resources...");
    // 这里可以添加全局资源清理代码
}

// 初始化错误处理系统
void init_error_handling() {
    last_error = ASYNC_BOF_SUCCESS;
    last_error_message[0] = '\0';
    current_log_level = LOG_LEVEL_INFO;
    
    LOG_INFO("Error handling system initialized");
    
    // 检查运行环境
    int has_admin = check_admin_privileges();
    if (!has_admin) {
        LOG_WARNING("Running without administrator privileges - some features may be limited");
    }
}

#ifndef BOF_BUILD
// 本地测试的错误处理函数
// 移除了vsprintf和GetLastError的定义，使用系统版本
#endif