#define linit_c
#define LUA_LIB

#include "lprefix.h"

#include <stddef.h>

#include "lua.h"

#include "lualib.h"
#include "lauxlib.h"

static const luaL_Reg loadedlibs[] = {
  {"_G", luaopen_base},

  {LUA_STRLIBNAME, luaopen_string},

#if defined(LUA_COMPAT_BITLIB)
  {LUA_BITLIBNAME, luaopen_bit32},
#endif
  {NULL, NULL}
};

LUALIB_API void luaL_openlibs (lua_State *L) {
  const luaL_Reg *lib;

  for (lib = loadedlibs; lib->func; lib++) {
    luaL_requiref(L, lib->name, lib->func, 1);
    lua_pop(L, 1);
  }
}
