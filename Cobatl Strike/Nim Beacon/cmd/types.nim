import std/[tables, endians, sequtils]
import ../utils

type 
    command_type* = range[1 .. 101]
    callback_type* = range[0 .. 32]
    command_result* = tuple[success: bool, message: string]

# defination from geacon_plus
const
    # cmd
    CMD_TYPE_SPAWN_IGNORE_TOKEN_X86*    = 1.command_type
    CMD_TYPE_EXIT*                      = 3.command_type
    CMD_TYPE_SLEEP*                     = 4.command_type
    CMD_TYPE_CD*                        = 5.command_type
    CMD_TYPE_DATA_JITTER*               = 6.command_type
    CMD_TYPE_CHECKIN*                   = 8.command_type
    CMD_TYPE_INJECT_X86*                = 9.command_type
    CMD_TYPE_UPLOAD_START*              = 10.command_type
    CMD_TYPE_DOWNLOAD*                  = 11.command_type
    CMD_TYPE_EXECUTE*                   = 12.command_type
    CMD_TYPE_SPAWN_TOX86*               = 13.command_type # only supply target, don't supply dll
    CMD_TYPE_CANCEL*                    = 19.command_type
    CMD_TYPE_GET_UID*                   = 27.command_type
    CMD_TYPE_REV2SELF*                  = 28.command_type
    CMD_TYPE_TIMESTOMP*                 = 29.command_type
    CMD_TYPE_STEAL_TOKEN*               = 31.command_type
    CMD_TYPE_PS*                        = 32.command_type
    CMD_TYPE_KILL*                      = 33.command_type
    CMD_TYPE_IMPORT_PS*                 = 37.command_type
    CMD_TYPE_RUNAS*                     = 38.command_type
    CMD_TYPE_PWD*                       = 39.command_type
    CMD_TYPE_JOB*                       = 40.command_type
    CMD_TYPE_LIST_JOBS*                 = 41.command_type
    CMD_TYPE_JOBKILL*                   = 42.command_type
    CMD_TYPE_INJECT_X64*                = 43.command_type
    CMD_TYPE_SPAWN_IGNORE_TOKEN_X64*    = 44.command_type
    CMD_TYPE_PAUSE*                     = 47.command_type
    CMD_TYPE_LIST_NETWORK*              = 48.command_type
    CMD_TYPE_MAKE_TOKEN*                = 49.command_type
    CMD_TYPE_PORT_FORWARD*              = 50.command_type
    CMD_TYPE_PORT_FORWARD_STOP*         = 51.command_type
    CMD_TYPE_FILE_BROWSE*               = 53.command_type
    CMD_TYPE_MAKEDIR*                   = 54.command_type
    CMD_TYPE_DRIVES*                    = 55.command_type
    CMD_TYPE_REMOVE*                    = 56.command_type
    CMD_TYPE_UPLOAD_LOOP*               = 67.command_type
    CMD_TYPE_SPAWN_TOX64*               = 69.command_type
    CMD_TYPE_EXEC_ASM_TOKEN_X86*        = 70.command_type
    CMD_TYPE_EXEC_ASM_TOKEN_X64*        = 71.command_type
    CMD_TYPE_SET_ENV*                   = 72.command_type
    CMD_TYPE_FILE_COPY*                 = 73.command_type
    CMD_TYPE_FILE_MOVE*                 = 74.command_type
    CMD_TYPE_GET_PRIVS*                 = 77.command_type
    CMD_TYPE_SHELL*                     = 78.command_type
    CMD_TYPE_WEB_DELIVERY*              = 79.command_type
    CMD_TYPE_EXEC_ASM_IGNORE_TOKEN_X86* = 87.command_type
    CMD_TYPE_EXEC_ASM_IGNORE_TOKEN_X64* = 88.command_type
    CMD_TYPE_SPAWN_TOKEN_X86*           = 89.command_type
    CMD_TYPE_SPAWN_TOKEN_X64*           = 90.command_type
    CMD_TYPE_GET_SYSTEM*                = 95.command_type
    CMD_TYPE_UNKNOWN_JOB*               = 101.command_type # same as 40 job?
    # callback
    CALLBACK_OUTPUT*            = 0.callback_type
    CALLBACK_KEYSTROKES*        = 1.callback_type
    CALLBACK_FILE*              = 2.callback_type
    CALLBACK_SCREENSHOT*        = 3.callback_type
    CALLBACK_CLOSE*             = 4.callback_type
    CALLBACK_READ*              = 5.callback_type
    CALLBACK_CONNECT*           = 6.callback_type
    CALLBACK_PING*              = 7.callback_type
    CALLBACK_FILE_WRITE*        = 8.callback_type
    CALLBACK_FILE_CLOSE*        = 9.callback_type
    CALLBACK_PIPE_OPEN*         = 10.callback_type
    CALLBACK_PIPE_CLOSE*        = 11.callback_type
    CALLBACK_PIPE_READ*         = 12.callback_type
    CALLBACK_POST_ERROR*        = 13.callback_type
    CALLBACK_PIPE_PING*         = 14.callback_type
    CALLBACK_TOKEN_STOLEN*      = 15.callback_type
    CALLBACK_TOKEN_GETUID*      = 16.callback_type
    CALLBACK_PROCESS_LIST*      = 17.callback_type
    CALLBACK_POST_REPLAY_ERROR* = 18.callback_type
    CALLBACK_PWD*               = 19.callback_type
    CALLBACK_LIST_JOBS*         = 20.callback_type
    CALLBACK_HASHDUMP*          = 21.callback_type
    CALLBACK_PENDING*           = 22.callback_type
    CALLBACK_ACCEPT*            = 23.callback_type
    CALLBACK_NETVIEW*           = 24.callback_type
    CALLBACK_PORTSCAN*          = 25.callback_type
    CALLBACK_DEAD*              = 26.callback_type
    CALLBACK_SSH_STATUS*        = 27.callback_type
    CALLBACK_CHUNK_ALLOCATE*    = 28.callback_type
    CALLBACK_CHUNK_SEND*        = 29.callback_type
    CALLBACK_OUTPUT_OEM*        = 30.callback_type
    CALLBACK_ERROR*             = 31.callback_type
    CALLBACK_OUTPUT_UTF8*       = 32.callback_type

var command_table* = initTable[command_type, proc (buf: var seq[byte], cmd: command_type)]()
proc register_command*(cmd_type: command_type, cmd: proc (buf: var seq[byte], cmd: command_type)) =
    if command_table.hasKey(cmd_type):
        dbg "[+] cmd: " & $cmd_type & "already registered"
    else:
        command_table[cmd_type] = cmd

proc parse_pending*(buf: var seq[byte]): int32 =
    var pending: int32
    var temp4: array[4, byte]
    for i in 0..<4: temp4[i] = buf[i]
    bigEndian32(addr pending, addr temp4)
    buf = buf[4..<buf.len]
    return pending

proc put_pending*(buf: var seq[byte], pending: int32) =
    var temp4: array[4, byte]
    bigEndian32(addr temp4, addr pending)
    buf.insert(temp4, 0)

proc parse_once*(buf: var seq[byte]): seq[byte] =
    var temp4: array[4, byte]
    for i in 0..<4: temp4[i] = buf[i]
    var arg_len: int32
    bigEndian32(addr arg_len, addr temp4)
    dbg "[+] arg len: " & $arg_len

    if arg_len == 0: return 
    result = buf[4..<4+arg_len]
    buf = buf[4+arg_len..<buf.len]

proc parse_multiple*(buf: var seq[byte], times: int): seq[seq[byte]] =
    for i in 0..<times: 
        result.add(parse_once(buf))

proc parse_int16*(buf: var seq[byte]): int16 =
    var temp2: array[2, byte]
    for i in 0..<2: temp2[i] = buf[i]
    bigEndian16(result.addr, temp2.addr)
    buf.delete(0..<2)

proc parse_int32*(buf: var seq[byte]): int32 =
    var temp4: array[4, byte]
    for i in 0..<4: temp4[i] = buf[i]
    bigEndian32(result.addr, temp4.addr)
    buf.delete(0..<4)
