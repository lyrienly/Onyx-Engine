#include "StdAfx.h"

#include "PipeServer.h"

BOOL SetProtection()
{
    HMODULE k = LoadLibraryA("kernel32.dll");
    typedef BOOL  (WINAPI *SETPROCESSMITIGATIONPOLICY)(PROCESS_MITIGATION_POLICY MitigationPolicy, PVOID lpBuffer, SIZE_T dwLength);
    SETPROCESSMITIGATIONPOLICY p=(SETPROCESSMITIGATIONPOLICY)GetProcAddress(k, "SetProcessMitigationPolicy");

    if (p)
    {
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy;
        ZeroMemory(&policy, sizeof(policy));
        policy.MicrosoftSignedOnly = 1;

        BOOL r;
        r = p(ProcessSignaturePolicy, &policy, sizeof(policy));

        return r;
    }
    else
        return FALSE;
}

BOOL SetPrivilege(
    HANDLE hToken,
    LPCTSTR lpszPrivilege,
    BOOL bEnablePrivilege
    )
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if ( !LookupPrivilegeValue(
            NULL,
            lpszPrivilege,
            &luid ) )
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError() );
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if ( !AdjustTokenPrivileges(
           hToken,
           FALSE,
           &tp,
           sizeof(TOKEN_PRIVILEGES),
           (PTOKEN_PRIVILEGES) NULL,
           (PDWORD) NULL) )
    {
          printf("AdjustTokenPrivileges error: %u\n", GetLastError() );
          return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
          printf("The token does not have the specified privilege. \n");
          return FALSE;
    }

    return TRUE;
}

int WINAPI wWinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR lpCmdLine,
    _In_ int nShowCmd
    )
{
	CPipeServer *pw;
	HANDLE p;
	HANDLE hToken;

	p = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId() );
	OpenProcessToken( p, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken );
	SetPrivilege( hToken, SE_DEBUG_NAME, TRUE );
	CoInitialize(NULL);

    SetProtection();

	MSG m;
	PeekMessage(&m, (HWND)-1, 0,0,PM_REMOVE);

	if ((lpCmdLine) && (wcslen(lpCmdLine)))
	{
		int r;
		pw=new CPipeServer(lpCmdLine);
		r=pw->Start();

		delete pw;
		return r;
	}
	else
	{
		MessageBoxA(0, "No pipename provided","dotNET Data Collector", MB_ICONERROR);
		return 1;
	}
	return 0;
}
