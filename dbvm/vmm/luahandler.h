#ifndef VMM_LUAHANDLER_H_
#define VMM_LUAHANDLER_H_

#include "lua/src/lua.h"

lua_State *initializeLua(void);
void enterLuaConsole(void);

#endif
