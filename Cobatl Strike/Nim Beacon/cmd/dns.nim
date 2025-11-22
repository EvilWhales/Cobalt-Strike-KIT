import std/[os, strutils, sequtils, times, streams, endians, tables]
import ../[utils, config]
import types, result

proc dns_checkin(buf: var seq[byte], cmd: command_type) = 
    # No need to handle this?
    discard

register_command(CMD_TYPE_CHECKIN, dns_checkin)