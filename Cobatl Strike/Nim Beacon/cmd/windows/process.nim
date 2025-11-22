import ../../[utils, meta]
import std/[os, strformat, endians]
import ../[types, result]
import winim
import winim/winstr

var system_info: SYSTEM_INFO
var system_info_initialized = false

# contribute to psutil-nim
proc pids*(): seq[int] = 
    ## Returns a list of PIDs currently running on the system.
    result = newSeq[int]()

    var procArray: seq[DWORD]
    var procArrayLen = 0
    # Stores the byte size of the returned array from enumprocesses
    var enumReturnSz: DWORD = 0

    while enumReturnSz == DWORD( procArrayLen * sizeof(DWORD) ):
        procArrayLen += 1024
        procArray = newSeq[DWORD](procArrayLen)

        if EnumProcesses( addr procArray[0], 
                          DWORD( procArrayLen * sizeof(DWORD) ), 
                          addr enumReturnSz ) == 0:
            return result

    # The number of elements is the returned size / size of each element
    let numberOfReturnedPIDs = int( int(enumReturnSz) / sizeof(DWORD) )
    for i in 0..<numberOfReturnedPIDs:
        result.add( procArray[i].int )

proc pid_name*(processID: int): string =
    #[
        function for getting the process name of pid
    ]#
    if processID == 0:
        return "System Idle Process"
    elif processID == 4:
        return "System"
    var szProcessName = newWideCString(MAX_PATH)
    var dwSize = MAX_PATH.DWORD

    var hProcess = OpenProcess( cast[DWORD](PROCESS_QUERY_LIMITED_INFORMATION), FALSE, cast[DWORD](processID) )
    defer: CloseHandle(hProcess)
    if hProcess == INVALID_HANDLE_VALUE:
        return ""
    
    if QueryFullProcessImageName(hProcess, 0, szProcessName, &dwSize) == 0:
        return ""

    var (_, name) = splitPath($szProcessName)
        
    return name

proc pid_user*(pid: int): string =

    ## Attempt to get the username associated with the given pid.
    var hProcess: HANDLE
    var hToken: HANDLE
    var pUser: ptr TOKEN_USER
    var peUse: SID_NAME_USE
    var dwUserLength = cast[DWORD](512)
    var dwDomainLength = cast[DWORD](512)
    var dwLength: DWORD
    var dwPid = cast[DWORD](pid)
    var wcUser = newWideCString(512)
    var wcDomain = newWideCString(512)

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid)
    if hProcess == cast[DWORD](-1) or hProcess == cast[DWORD](NULL):
        return ""

    if OpenProcessToken(hProcess, TOKEN_QUERY, cast[PHANDLE](hToken.addr)) == FALSE:
        dbg "[-] OpenProcessToken failed: " & $GetLastError() 
        return ""
    defer: CloseHandle(hProcess)

    if hToken == cast[HANDLE](-1) or hToken == cast[HANDLE](NULL):
        dbg "[-] Token handle is NULL: " & $GetLastError()
        return ""
    defer: CloseHandle(hToken)

    pUser = cast[ptr TOKEN_USER](alloc(50))
    defer: dealloc(pUser)
    ## Get required buffer size and allocate the TOKEN_USER buffer
    GetTokenInformation(hToken, tokenUser, pUser, cast[DWORD](0), cast[PDWORD](dwLength.addr))
    GetTokenInformation(hToken, tokenUser, pUser, cast[DWORD](dwLength), cast[PDWORD](dwLength.addr))
    
    if LookupAccountSidW(cast[LPCWSTR](NULL), pUser.User.Sid, wcUser, dwUserLength.addr, wcDomain, dwDomainLength.addr, peUse.addr) == FALSE:
        dbg fmt"{wcUser}, {dwUserLength}, {wcDomain}, {dwDomainLength}, {peUse}"
        dbg "[-] LookupAccountSidW failed: " & $GetLastError() 
        return ""

    return $wcUser

proc pid_parent*(pid: int): int =
    var h: HANDLE
    var pe: PROCESSENTRY32
    var ppid = cast[DWORD](0)
    pe.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(h)
    if Process32First(h, pe.addr):
        while Process32Next(h, pe.addr):
            if cast[int](pe.th32ProcessID) == pid:
                ppid = pe.th32ParentProcessID
                break
    
    return cast[int](ppid)

proc pid_session_id*(pid: int): int =
    var sessionId: DWORD = 0
    ProcessIdToSessionId(cast[DWORD](pid), sessionId.addr)
    return cast[int](sessionId)

proc pid_arch*(pid: int): string =
    if not system_info_initialized:
        GetNativeSystemInfo(system_info.addr)
    var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, cast[DWORD](pid))
    defer: CloseHandle(hProcess)

    var wow64: BOOL = 0
    IsWow64Process(hProcess, wow64.addr)

    case system_info.wProcessorArchitecture
    of PROCESSOR_ARCHITECTURE_ARM: return "arm"
    of PROCESSOR_ARCHITECTURE_INTEL: return "x86"
    of PROCESSOR_ARCHITECTURE_UNKNOWN: return "Unknown"
    of PROCESSOR_ARCHITECTURE_AMD64: 
        if wow64 == TRUE: return "x86"
        else: return "x64"
    of 12: # PROCESSOR_ARCHITECTURE_ARM64, contribute to winim
        if wow64 == TRUE: return "arm"
        else: return "arm64"
    of PROCESSOR_ARCHITECTURE_IA64:
        if wow64 == TRUE: return "x86"
        else: return "ia64"
    else: return "Unknown"

proc ps(buf: var seq[byte], cmd: command_type) = 
    var pending = parse_pending(buf)
    var total = ""

    for pid in pids():
        var name = pid_name(pid)
        var ppid = pid_parent(pid)
        var arch = pid_arch(pid)
        var owner = pid_user(pid)
        var session_id = pid_session_id(pid)
        total = &"{total}\n{name}\t{ppid}\t{pid}\t{arch}\t{owner}\t{session_id}"
    
    dbg "[+] total: " & total
    put_pending(buf, pending)
    buf.add(total.toSeq)

    if pending == 0:
        push_result(CALLBACK_PROCESS_LIST, buf)
    else:
        push_result(CALLBACK_PENDING, buf)

proc kill(buf: var seq[byte], cmd: command_type) = 
    when not defined(windows):
        push_result(CALLBACK_OUTPUT, "only suppported on windows".toSeq)
        return
    
    var pid: uint32
    var temp4: array[4, byte]
    for i in 0..<4: temp4[i] = buf[i]
    bigEndian32(addr pid, addr temp4)
    
    dbg "[+] kill pid: " & $pid
    var hProcess = OpenProcess(PROCESS_TERMINATE.DWORD, FALSE.WINBOOL, pid.DWORD)
    if hProcess == cast[HANDLE](-1) or hProcess == cast[HANDLE](NULL):
        push_result(CALLBACK_OUTPUT, "failed to open process".toSeq)
        return
    defer: CloseHandle(hProcess)
    if TerminateProcess(hProcess, 0) == FALSE:
        push_result(CALLBACK_OUTPUT, "failed to terminate process".toSeq)
        return
    push_result(CALLBACK_OUTPUT, (&"process {pid} killed").toSeq)

register_command(CMD_TYPE_PS, ps)
register_command(CMD_TYPE_KILL, kill)