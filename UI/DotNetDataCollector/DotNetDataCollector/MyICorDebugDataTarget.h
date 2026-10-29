#ifndef __CMyIcorDebugDataTarget_H__
#define __CMyIcorDebugDataTarget_H__

typedef BOOL (WINAPI *ISWOW64PROCESS)(_In_ HANDLE hProcess, _Out_ PBOOL Wow64Process);

class CMyIcorDebugDataTarget :
    public ICorDebugDataTarget

{
private:
	HANDLE processHandle;
	long m_ref;

	ISWOW64PROCESS _IsWow64Process;

public:
	CMyIcorDebugDataTarget(HANDLE p)
	{
		m_ref = 1;
		processHandle=p;
		_IsWow64Process=(ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "IsWow64Process");
	}

	~CMyIcorDebugDataTarget()
	{

	}

	STDMETHOD(QueryInterface)(__in REFIID InterfaceId, __out PVOID* Interface);
	STDMETHOD_(ULONG, AddRef)();
	STDMETHOD_(ULONG, Release)();

	    virtual HRESULT STDMETHODCALLTYPE GetPlatform(
			 CorDebugPlatform *pTargetPlatform);

        virtual HRESULT STDMETHODCALLTYPE ReadVirtual(
             CORDB_ADDRESS address,
             BYTE *pBuffer,
             ULONG32 bytesRequested,
             ULONG32 *pBytesRead);

        virtual HRESULT STDMETHODCALLTYPE GetThreadContext(
             DWORD dwThreadID,
             ULONG32 contextFlags,
             ULONG32 contextSize,
             BYTE *pContext);

};

#endif
