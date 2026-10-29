#define lbitlib_c
#define LUA_LIB

#include "lprefix.h"

#include "lua.h"

#include "lauxlib.h"
#include "lualib.h"

#if defined(LUA_COMPAT_BITLIB)

#define pushunsigned(L,n)	lua_pushinteger(L, (lua_Integer)(n))
#define checkunsigned(L,i)	((lua_Unsigned)luaL_checkinteger(L,i))

#if !defined(LUA_NBITS)
#define LUA_NBITS	32
#endif

#define ALLONES		(~(((~(lua_Unsigned)0) << (LUA_NBITS - 1)) << 1))

#define trim(x)		((x) & ALLONES)

#define mask(n)		(~((ALLONES << 1) << ((n) - 1)))

static lua_Unsigned andaux (lua_State *L) {
  int i, n = lua_gettop(L);
  lua_Unsigned r = ~(lua_Unsigned)0;
  for (i = 1; i <= n; i++)
    r &= checkunsigned(L, i);
  return trim(r);
}

static int b_and (lua_State *L) {
  lua_Unsigned r = andaux(L);
  pushunsigned(L, r);
  return 1;
}

static int b_test (lua_State *L) {
  lua_Unsigned r = andaux(L);
  lua_pushboolean(L, r != 0);
  return 1;
}

static int b_or (lua_State *L) {
  int i, n = lua_gettop(L);
  lua_Unsigned r = 0;
  for (i = 1; i <= n; i++)
    r |= checkunsigned(L, i);
  pushunsigned(L, trim(r));
  return 1;
}

static int b_xor (lua_State *L) {
  int i, n = lua_gettop(L);
  lua_Unsigned r = 0;
  for (i = 1; i <= n; i++)
    r ^= checkunsigned(L, i);
  pushunsigned(L, trim(r));
  return 1;
}

static int b_not (lua_State *L) {
  lua_Unsigned r = ~checkunsigned(L, 1);
  pushunsigned(L, trim(r));
  return 1;
}

static int b_shift (lua_State *L, lua_Unsigned r, lua_Integer i) {
  if (i < 0) {
    i = -i;
    r = trim(r);
    if (i >= LUA_NBITS) r = 0;
    else r >>= i;
  }
  else {
    if (i >= LUA_NBITS) r = 0;
    else r <<= i;
    r = trim(r);
  }
  pushunsigned(L, r);
  return 1;
}

static int b_lshift (lua_State *L) {
  return b_shift(L, checkunsigned(L, 1), luaL_checkinteger(L, 2));
}

static int b_rshift (lua_State *L) {
  return b_shift(L, checkunsigned(L, 1), -luaL_checkinteger(L, 2));
}

static int b_arshift (lua_State *L) {
  lua_Unsigned r = checkunsigned(L, 1);
  lua_Integer i = luaL_checkinteger(L, 2);
  if (i < 0 || !(r & ((lua_Unsigned)1 << (LUA_NBITS - 1))))
    return b_shift(L, r, -i);
  else {
    if (i >= LUA_NBITS) r = ALLONES;
    else
      r = trim((r >> i) | ~(trim(~(lua_Unsigned)0) >> i));
    pushunsigned(L, r);
    return 1;
  }
}

static int b_rot (lua_State *L, lua_Integer d) {
  lua_Unsigned r = checkunsigned(L, 1);
  int i = d & (LUA_NBITS - 1);
  r = trim(r);
  if (i != 0)
    r = (r << i) | (r >> (LUA_NBITS - i));
  pushunsigned(L, trim(r));
  return 1;
}

static int b_lrot (lua_State *L) {
  return b_rot(L, luaL_checkinteger(L, 2));
}

static int b_rrot (lua_State *L) {
  return b_rot(L, -luaL_checkinteger(L, 2));
}

static int fieldargs (lua_State *L, int farg, int *width) {
  lua_Integer f = luaL_checkinteger(L, farg);
  lua_Integer w = luaL_optinteger(L, farg + 1, 1);
  luaL_argcheck(L, 0 <= f, farg, "field cannot be negative");
  luaL_argcheck(L, 0 < w, farg + 1, "width must be positive");
  if (f + w > LUA_NBITS)
    luaL_error(L, "trying to access non-existent bits");
  *width = (int)w;
  return (int)f;
}

static int b_extract (lua_State *L) {
  int w;
  lua_Unsigned r = trim(checkunsigned(L, 1));
  int f = fieldargs(L, 2, &w);
  r = (r >> f) & mask(w);
  pushunsigned(L, r);
  return 1;
}

static int b_replace (lua_State *L) {
  int w;
  lua_Unsigned r = trim(checkunsigned(L, 1));
  lua_Unsigned v = trim(checkunsigned(L, 2));
  int f = fieldargs(L, 3, &w);
  lua_Unsigned m = mask(w);
  r = (r & ~(m << f)) | ((v & m) << f);
  pushunsigned(L, r);
  return 1;
}

static const luaL_Reg bitlib[] = {
  {"arshift", b_arshift},
  {"band", b_and},
  {"bnot", b_not},
  {"bor", b_or},
  {"bxor", b_xor},
  {"btest", b_test},
  {"extract", b_extract},
  {"lrotate", b_lrot},
  {"lshift", b_lshift},
  {"replace", b_replace},
  {"rrotate", b_rrot},
  {"rshift", b_rshift},
  {NULL, NULL}
};

LUAMOD_API int luaopen_bit32 (lua_State *L) {
  luaL_newlib(L, bitlib);
  return 1;
}

#else

LUAMOD_API int luaopen_bit32 (lua_State *L) {
  return luaL_error(L, "library 'bit32' has been deprecated");
}

#endif
