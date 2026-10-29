#include <windows.h>
#include <stdio.h>
#include "cepluginsdk.h"
#include "bla.h"

int selfid;
int memorybrowserpluginid=-1;
int addresslistPluginID=-1;
int debugpluginID=-1;
int ProcesswatchpluginID=-1;
int PointerReassignmentPluginID=-1;
int MainMenuPluginID=-1;

ExportedFunctions Exported;

void __stdcall mainmenuplugin(void)
{
	Exported.ShowMessage("Main menu plugin");
	return;
}

void __stdcall PointersReassigned(int reserved)
{

	Exported.ShowMessage("Pointers got modified");
	return;
}

void __stdcall processWatcherEvent(ULONG processid, ULONG peprocess, BOOL Created)
{

	char x[100];
	if (Created)
		sprintf_s(x,100,"Processid %x (PEPROCESS: %x) has been created",processid,peprocess);
	else
		sprintf_s(x,100,"Processid %x (PEPROCESS: %x) has been destroyed",processid,peprocess);

	MessageBoxA(0,x,"Process Watcher Plugin Example", MB_OK);
	return;
}

int __stdcall debugeventplugin(LPDEBUG_EVENT DebugEvent)
{

	MessageBoxA(0,"A debug event has happened. You could do some editing of the context here...","Debug Event Plugin Example", MB_OK);
	return 0;
}

BOOL __stdcall addresslistplugin(PPLUGINTYPE0_RECORD SelectedRecord)
{
	char x[100];

	sprintf_s(x,100,"Selected record's description=%s Address=%0.8llx",SelectedRecord->description, (UINT64)SelectedRecord->address);
	Exported.ShowMessage(x);
	return FALSE;
}

BOOL __stdcall memorybrowserplugin(UINT_PTR *disassembleraddress, UINT_PTR *selected_disassembler_address, UINT_PTR *hexviewaddress)
{
	Exported.ShowMessage("A Plugin function got executed");
	*disassembleraddress=*hexviewaddress;
	return TRUE;
}

BOOL APIENTRY DllMain( HANDLE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:

			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}

    return TRUE;
}

BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv , int sizeofpluginversion)
{
	pv->version=CESDK_VERSION;
	pv->pluginname="C Example v1.3 (SDK version 4: 6.0+)";
	return TRUE;
}

int lua_pluginExample(lua_State *L)
{
	Exported.ShowMessage("Called from lua");
	lua_pushinteger(L, 123);
	return 1;
}

BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions ef , int pluginid)
{
	ADDRESSLISTPLUGIN_INIT init0;
	MEMORYVIEWPLUGIN_INIT init1;
	DEBUGEVENTPLUGIN_INIT init2;
	PROCESSWATCHERPLUGIN_INIT init3;
	POINTERREASSIGNMENTPLUGIN_INIT init4;
	MAINMENUPLUGIN_INIT init5;

	selfid=pluginid;

	Exported=*ef;
	if (Exported.sizeofExportedFunctions!=sizeof(Exported))
		return FALSE;

	init0.name="Sample plugin: Addresslist";
	init0.callbackroutine=addresslistplugin;
	addresslistPluginID=Exported.RegisterFunction(pluginid, ptAddressList, &init0);
	if ( addresslistPluginID == -1 )
	{
		Exported.ShowMessage("Failure to register the addresslist plugin");
		return FALSE;
	}

	init1.name="Sample plugin: Memoryview";
	init1.callbackroutine=memorybrowserplugin;
	init1.shortcut="Ctrl+Q";
	memorybrowserpluginid=Exported.RegisterFunction(pluginid, ptMemoryView, &init1);
	if ( memorybrowserpluginid == -1 )
	{
		Exported.ShowMessage("Failure to register the memoryview plugin");
		return FALSE;
	}

	init2.callbackroutine=debugeventplugin;
	debugpluginID=Exported.RegisterFunction(pluginid, ptOnDebugEvent, &init2);
	if ( debugpluginID == -1 )
	{
		Exported.ShowMessage("Failure to register the ondebugevent plugin");
		return FALSE;
	}

	init3.callbackroutine=processWatcherEvent;
	ProcesswatchpluginID=Exported.RegisterFunction(pluginid, ptProcesswatcherEvent, &init3);
	if ( ProcesswatchpluginID == -1 )
	{
		Exported.ShowMessage("Failure to register the processwatcherevent plugin");
		return FALSE;
	}

	init4.callbackroutine=PointersReassigned;
	PointerReassignmentPluginID=Exported.RegisterFunction(pluginid, ptFunctionPointerchange, &init4);
	if ( PointerReassignmentPluginID == -1 )
	{
		Exported.ShowMessage("Failure to register the pointer reassignment plugin");
		return FALSE;
	}

	init5.name="Sample plugin: Main Menu";
	init5.callbackroutine=mainmenuplugin;
	init5.shortcut="Ctrl+R";
	MainMenuPluginID=Exported.RegisterFunction(pluginid, ptMainMenu, &init5);
	if ( MainMenuPluginID == -1 )
	{
		Exported.ShowMessage("Failure to register the main menu plugin");
		return FALSE;
	}

	lua_State *lua_state=ef->GetLuaState();

	lua_register(lua_state, "pluginExample", lua_pluginExample);

	Exported.ShowMessage("The \"Example C\" plugin got enabled");
	return TRUE;
}

BOOL __stdcall CEPlugin_DisablePlugin(void)
{

	MessageBoxA(0,"disabled plugin","Example C plugin", MB_OK);

	return TRUE;
}
