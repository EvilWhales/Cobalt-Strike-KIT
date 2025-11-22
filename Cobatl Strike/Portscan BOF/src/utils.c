void get_server_info(wchar_t *server, char *srv_inf) {
    // https://learn.microsoft.com/en-us/windows/win32/api/lmwksta/ns-lmwksta-wksta_info_100
    // https://learn.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstagetinfo
    WKSTA_INFO_100 *server_info= NULL;
    NET_API_STATUS status = NetWkstaGetInfo(server, 100, (LPBYTE*)&server_info);

    if (status == NERR_Success) {
        sprintf(srv_inf,
                "platform: %d version: %d.%d name: %ls domain: %ls",
                server_info->wki100_platform_id,
                server_info->wki100_ver_major,
                server_info->wki100_ver_minor,
                server_info->wki100_computername,
                server_info->wki100_langroup
                );
        NetApiBufferFree(server_info);
    } 
    // we don't care about the error in our case. it could be another service running on this port
}

char *trimws(char *str) {
  char *end;

  // Trim leading space
  while(isspace((unsigned char)*str)) str++;

  if(*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace((unsigned char)*end)) end--;

  // Write new null terminator character
  end[1] = '\0';

  return str;
}
