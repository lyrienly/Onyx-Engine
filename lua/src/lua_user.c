#include <windows.h>
  #include "lua.h"
  #include "lua_user.h"

  static struct {
    CRITICAL_SECTION LockSct;
	HANDLE e;
    BOOL Init;
	int tid;
	int lockcount;
  } Gl;

  void LuaLockInitial(lua_State * L)
  {

    if (! Gl.Init)
    {

      InitializeCriticalSection(&Gl.LockSct);
      Gl.Init = TRUE;
    }
  }

  void LuaLockFinal(lua_State * L)
  {

	MessageBox(0, "LuaLockFinal","LuaLockFinal", MB_OK);

    if (Gl.Init)
    {

      DeleteCriticalSection(&Gl.LockSct);
      Gl.Init = FALSE;
    }

  }

  void LuaLock(lua_State * L)
  {
	  if (! Gl.Init)
		  LuaLockInitial(L);

    EnterCriticalSection(&Gl.LockSct);

  }

  void LuaUnlock(lua_State * L)
  {

    LeaveCriticalSection(&Gl.LockSct);
  }
