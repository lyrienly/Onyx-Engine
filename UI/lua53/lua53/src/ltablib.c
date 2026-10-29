#define ltablib_c
#define LUA_LIB

#include "lprefix.h"

#include <limits.h>
#include <stddef.h>

#include "lua.h"

#include "lauxlib.h"
#include "lualib.h"

typedef struct {
  int (*geti) (lua_State *L, int idx, lua_Integer n);
  void (*seti) (lua_State *L, int idx, lua_Integer n);
} TabA;

static void checktab (lua_State *L, int arg, TabA *ta) {
  ta->geti = NULL; ta->seti = NULL;
  if (lua_getmetatable(L, arg)) {
    lua_pushliteral(L, "__index");
    if (lua_rawget(L, -2) != LUA_TNIL)
      ta->geti = lua_geti;
    lua_pushliteral(L, "__newindex");
    if (lua_rawget(L, -3) != LUA_TNIL)
      ta->seti = lua_seti;
    lua_pop(L, 3);
  }
  if (ta->geti == NULL || ta->seti == NULL) {
    luaL_checktype(L, arg, LUA_TTABLE);
    if (ta->geti == NULL) ta->geti = lua_rawgeti;
    if (ta->seti == NULL) ta->seti = lua_rawseti;
  }
}

#define aux_getn(L,n,ta)	(checktab(L, n, ta), luaL_len(L, n))

#if defined(LUA_COMPAT_MAXN)
static int maxn (lua_State *L) {
  lua_Number max = 0;
  luaL_checktype(L, 1, LUA_TTABLE);
  lua_pushnil(L);
  while (lua_next(L, 1)) {
    lua_pop(L, 1);
    if (lua_type(L, -1) == LUA_TNUMBER) {
      lua_Number v = lua_tonumber(L, -1);
      if (v > max) max = v;
    }
  }
  lua_pushnumber(L, max);
  return 1;
}
#endif

static int tinsert (lua_State *L) {
  TabA ta;
  lua_Integer e = aux_getn(L, 1, &ta) + 1;
  lua_Integer pos;
  switch (lua_gettop(L)) {
    case 2: {
      pos = e;
      break;
    }
    case 3: {
      lua_Integer i;
      pos = luaL_checkinteger(L, 2);
      luaL_argcheck(L, 1 <= pos && pos <= e, 2, "position out of bounds");
      for (i = e; i > pos; i--) {
        (*ta.geti)(L, 1, i - 1);
        (*ta.seti)(L, 1, i);
      }
      break;
    }
    default: {
      return luaL_error(L, "wrong number of arguments to 'insert'");
    }
  }
  (*ta.seti)(L, 1, pos);
  return 0;
}

static int tremove (lua_State *L) {
  TabA ta;
  lua_Integer size = aux_getn(L, 1, &ta);
  lua_Integer pos = luaL_optinteger(L, 2, size);
  if (pos != size)
    luaL_argcheck(L, 1 <= pos && pos <= size + 1, 1, "position out of bounds");
  (*ta.geti)(L, 1, pos);
  for ( ; pos < size; pos++) {
    (*ta.geti)(L, 1, pos + 1);
    (*ta.seti)(L, 1, pos);
  }
  lua_pushnil(L);
  (*ta.seti)(L, 1, pos);
  return 1;
}

static int tmove (lua_State *L) {
  TabA ta;
  lua_Integer f = luaL_checkinteger(L, 2);
  lua_Integer e = luaL_checkinteger(L, 3);
  lua_Integer t = luaL_checkinteger(L, 4);
  int tt = !lua_isnoneornil(L, 5) ? 5 : 1;

  luaL_argcheck(L, f > 0, 2, "initial position must be positive");
  if (e >= f) {
    lua_Integer n, i;
    ta.geti = (luaL_getmetafield(L, 1, "__index") == LUA_TNIL)
      ? (luaL_checktype(L, 1, LUA_TTABLE), lua_rawgeti)
      : lua_geti;
    ta.seti = (luaL_getmetafield(L, tt, "__newindex") == LUA_TNIL)
      ? (luaL_checktype(L, tt, LUA_TTABLE), lua_rawseti)
      : lua_seti;
    n = e - f + 1;
    if (t > f) {
      for (i = n - 1; i >= 0; i--) {
        (*ta.geti)(L, 1, f + i);
        (*ta.seti)(L, tt, t + i);
      }
    }
    else {
      for (i = 0; i < n; i++) {
        (*ta.geti)(L, 1, f + i);
        (*ta.seti)(L, tt, t + i);
      }
    }
  }
  lua_pushvalue(L, tt);
  return 1;
}

static void addfield (lua_State *L, luaL_Buffer *b, TabA *ta, lua_Integer i) {
  (*ta->geti)(L, 1, i);
  if (!lua_isstring(L, -1))
    luaL_error(L, "invalid value (%s) at index %d in table for 'concat'",
                  luaL_typename(L, -1), i);
  luaL_addvalue(b);
}

static int tconcat (lua_State *L) {
  TabA ta;
  luaL_Buffer b;
  size_t lsep;
  lua_Integer i, last;
  const char *sep = luaL_optlstring(L, 2, "", &lsep);
  checktab(L, 1, &ta);
  i = luaL_optinteger(L, 3, 1);
  last = luaL_opt(L, luaL_checkinteger, 4, luaL_len(L, 1));
  luaL_buffinit(L, &b);
  for (; i < last; i++) {
    addfield(L, &b, &ta, i);
    luaL_addlstring(&b, sep, lsep);
  }
  if (i == last)
    addfield(L, &b, &ta, i);
  luaL_pushresult(&b);
  return 1;
}

static int pack (lua_State *L) {
  int i;
  int n = lua_gettop(L);
  lua_createtable(L, n, 1);
  lua_insert(L, 1);
  for (i = n; i >= 1; i--)
    lua_rawseti(L, 1, i);
  lua_pushinteger(L, n);
  lua_setfield(L, 1, "n");
  return 1;
}

static int unpack (lua_State *L) {
  TabA ta;
  lua_Integer i, e;
  lua_Unsigned n;
  checktab(L, 1, &ta);
  i = luaL_optinteger(L, 2, 1);
  e = luaL_opt(L, luaL_checkinteger, 3, luaL_len(L, 1));
  if (i > e) return 0;
  n = (lua_Unsigned)e - i;
  if (n >= (unsigned int)INT_MAX  || !lua_checkstack(L, (int)(++n)))
    return luaL_error(L, "too many results to unpack");
  do {
    (*ta.geti)(L, 1, i);
  } while (i++ < e);

  return (int)n;
}

static void set2 (lua_State *L, TabA *ta, int i, int j) {
  (*ta->seti)(L, 1, i);
  (*ta->seti)(L, 1, j);
}

static int sort_comp (lua_State *L, int a, int b) {
  if (!lua_isnil(L, 2)) {
    int res;
    lua_pushvalue(L, 2);
    lua_pushvalue(L, a-1);
    lua_pushvalue(L, b-2);
    lua_call(L, 2, 1);
    res = lua_toboolean(L, -1);
    lua_pop(L, 1);
    return res;
  }
  else
    return lua_compare(L, a, b, LUA_OPLT);
}

static void auxsort (lua_State *L, TabA *ta, int l, int u) {
  while (l < u) {
    int i, j;

    (*ta->geti)(L, 1, l);
    (*ta->geti)(L, 1, u);
    if (sort_comp(L, -1, -2))
      set2(L, ta, l, u);
    else
      lua_pop(L, 2);
    if (u-l == 1) break;
    i = (l+u)/2;
    (*ta->geti)(L, 1, i);
    (*ta->geti)(L, 1, l);
    if (sort_comp(L, -2, -1))
      set2(L, ta, i, l);
    else {
      lua_pop(L, 1);
      (*ta->geti)(L, 1, u);
      if (sort_comp(L, -1, -2))
        set2(L, ta, i, u);
      else
        lua_pop(L, 2);
    }
    if (u-l == 2) break;
    (*ta->geti)(L, 1, i);
    lua_pushvalue(L, -1);
    (*ta->geti)(L, 1, u-1);
    set2(L, ta, i, u-1);

    i = l; j = u-1;
    for (;;) {

      while ((*ta->geti)(L, 1, ++i), sort_comp(L, -1, -2)) {
        if (i>=u) luaL_error(L, "invalid order function for sorting");
        lua_pop(L, 1);
      }

      while ((*ta->geti)(L, 1, --j), sort_comp(L, -3, -1)) {
        if (j<=l) luaL_error(L, "invalid order function for sorting");
        lua_pop(L, 1);
      }
      if (j<i) {
        lua_pop(L, 3);
        break;
      }
      set2(L, ta, i, j);
    }
    (*ta->geti)(L, 1, u-1);
    (*ta->geti)(L, 1, i);
    set2(L, ta, u-1, i);

    if (i-l < u-i) {
      j=l; i=i-1; l=i+2;
    }
    else {
      j=i+1; i=u; u=j-2;
    }
    auxsort(L, ta, j, i);
  }
}

static int sort (lua_State *L) {
  TabA ta;
  int n = (int)aux_getn(L, 1, &ta);
  luaL_checkstack(L, 50, "");
  if (!lua_isnoneornil(L, 2))
    luaL_checktype(L, 2, LUA_TFUNCTION);
  lua_settop(L, 2);
  auxsort(L, &ta, 1, n);
  return 0;
}

static const luaL_Reg tab_funcs[] = {
  {"concat", tconcat},
#if defined(LUA_COMPAT_MAXN)
  {"maxn", maxn},
#endif
  {"insert", tinsert},
  {"pack", pack},
  {"unpack", unpack},
  {"remove", tremove},
  {"move", tmove},
  {"sort", sort},
  {NULL, NULL}
};

LUAMOD_API int luaopen_table (lua_State *L) {
  luaL_newlib(L, tab_funcs);
#if defined(LUA_COMPAT_UNPACK)

  lua_getfield(L, -1, "unpack");
  lua_setglobal(L, "unpack");
#endif
  return 1;
}
