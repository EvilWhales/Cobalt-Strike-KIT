import ../../[utils, config]
import ../[types, result]
import winim
import winim/inc/iphlpapi

## todo, not implemented
# proc ifconfig(buf: var seq[byte], cmd: command_type) =
#     dbg "[+] ifconfig"
#     var buf_len = 0.ULONG
#     var err = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nil, nil, &buf_len)
#     if err != ERROR_BUFFER_OVERFLOW:
#         dbg "[-] GetAdaptersAddresses failed: " & $err
#         return
#     var adapters = cast[PIP_ADAPTER_ADDRESSES](alloc(buf_len))
#     defer: dealloc(adapters)
#     err = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nil, adapters, &buf_len)
#     if err != ERROR_SUCCESS:
#         dbg "[-] GetAdaptersAddresses failed: " & $err
#         return

#     var res_str = ""
#     var adapter = adapters
#     while adapter != NULL:
#         if adapter.PhysicalAddressLength != 6: 
#             adapter = adapter.Next
#             continue
#         var unicast = adapter.FirstUnicastAddress
#         while unicast != NULL:
#             if unicast.Address.lpSockaddr.sa_family != AF_INET:
#                 unicast = unicast.Next
#                 continue

#             var ip_str: array[46, WCHAR]
#             var ip_addr = cast[LPSOCKADDRIN](unicast.Address.lpSockaddr)
#             InetNtop(AF_INET, &(ip_addr.sin_addr), &ip_str[0], sizeof(ip_str))
#             dbg "[+] IP: " & $ip_str & " - " & $adapter.FriendlyName

#             # var mask: ULONG
#             # var mask_str: array[16, WCHAR]
#             # if ConvertLengthToIpv4Mask(unicast.PrefixLength, &mask) != NO_ERROR:
#             #     dbg "[-] ConvertLengthToIpv4Mask failed: " & $GetLastError()
#             #     return        
#             # dbg "[+] Mask: " & $mask_str

#             # var mac_str: array[18, WCHAR]
#             # MacToStr(adapter.PhysicalAddress, &mac_str[0], sizeof(mac_str))
#         adapter = adapter.Next

# register_command(CMD_TYPE_LIST_NETWORK, ifconfig)