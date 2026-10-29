#include "stdafx.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	OutputDebugStringA("MDC: DllMain");
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		g_hInstance=hModule;
		DataCollectorThread=CreateThread(NULL, 0, DataCollectorEntry, NULL, 0, NULL);
		SuicideThread=0;
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
