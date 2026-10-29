#define lauxlib_c
#define LUA_LIB

#include "lprefix.h"

#include "lua.h"
#include "../../mm.h"

#include "lauxlib.h"

#define LEVELS1	10
#define LEVELS2	11

static int findfield (lua_State *L, int objidx, int level) {
  if (level == 0 || !lua_istable(L, -1))
    return 0;
  lua_pushnil(L);
  while (lua_next(L, -2)) {
    if (lua_type(L, -2) == LUA_TSTRING) {
      if (lua_rawequal(L, objidx, -1)) {
        lua_pop(L, 1);
        return 1;
      }
      else if (findfield(L, objidx, level - 1)) {
        lua_remove(L, -2);
        lua_pushliteral(L, ".");
        lua_insert(L, -2);
        lua_concat(L, 3);
        return 1;
      }
    }
    lua_pop(L, 1);
  }
  return 0;
}

static int pushglobalfuncname (lua_State *L, lua_Debug *ar) {
  int top = lua_gettop(L);
  lua_getinfo(L, "f", ar);
  lua_getfield(L, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
  if (findfield(L, top + 1, 2)) {
    const char *name = lua_tostring(L, -1);
    if (strncmp(name, "_G.", 3) == 0) {
      lua_pushstring(L, name + 3);
      lua_remove(L, -2);
    }
    lua_copy(L, -1, top + 1);
    lua_pop(L, 2);
    return 1;
  }
  else {
    lua_settop(L, top);
    return 0;
  }
}

static void pushfuncname (lua_State *L, lua_Debug *ar) {
  if (pushglobalfuncname(L, ar)) {
    lua_pushfstring(L, "function '%s'", lua_tostring(L, -1));
    lua_remove(L, -2);
  }
  else if (*ar->namewhat != '\0')
    lua_pushfstring(L, "%s '%s'", ar->namewhat, ar->name);
  else if (*ar->what == 'm')
      lua_pushliteral(L, "main chunk");
  else if (*ar->what != 'C')
    lua_pushfstring(L, "function <%s:%d>", ar->short_src, ar->linedefined);
  else
    lua_pushliteral(L, "?");
}

static int lastlevel (lua_State *L) {
  lua_Debug ar;
  int li = 1, le = 1;

  while (lua_getstack(L, le, &ar)) { li = le; le *= 2; }

  while (li < le) {
    int m = (li + le)/2;
    if (lua_getstack(L, m, &ar)) li = m + 1;
    else le = m;
  }
  return le - 1;
}

LUALIB_API void luaL_traceback (lua_State *L, lua_State *L1,
                                const char *msg, int level) {
  lua_Debug ar;
  int top = lua_gettop(L);
  int last = lastlevel(L1);
  int n1 = (last - level > LEVELS1 + LEVELS2) ? LEVELS1 : -1;
  if (msg)
    lua_pushfstring(L, "%s\n", msg);
  luaL_checkstack(L, 10, NULL);
  lua_pushliteral(L, "stack traceback:");
  while (lua_getstack(L1, level++, &ar)) {
    if (n1-- == 0) {
      lua_pushliteral(L, "\n\t...");
      level = last - LEVELS2 + 1;
    }
    else {
      lua_getinfo(L1, "Slnt", &ar);
      lua_pushfstring(L, "\n\t%s:", ar.short_src);
      if (ar.currentline > 0)
        lua_pushfstring(L, "%d:", ar.currentline);
      lua_pushliteral(L, " in ");
      pushfuncname(L, &ar);
      if (ar.istailcall)
        lua_pushliteral(L, "\n\t(...tail calls...)");
      lua_concat(L, lua_gettop(L) - top);
    }
  }
  lua_concat(L, lua_gettop(L) - top);
}

LUALIB_API int luaL_argerror (lua_State *L, int arg, const char *extramsg) {
  lua_Debug ar;
  if (!lua_getstack(L, 0, &ar))
    return luaL_error(L, "bad argument #%d (%s)", arg, extramsg);
  lua_getinfo(L, "n", &ar);
  if (strcmp(ar.namewhat, "method") == 0) {
    arg--;
    if (arg == 0)
      return luaL_error(L, "calling '%s' on bad self (%s)",
                           ar.name, extramsg);
  }
  if (ar.name == NULL)
    ar.name = (pushglobalfuncname(L, &ar)) ? lua_tostring(L, -1) : "?";
  return luaL_error(L, "bad argument #%d to '%s' (%s)",
                        arg, ar.name, extramsg);
}

static int typeerror (lua_State *L, int arg, const char *tname) {
  const char *msg;
  const char *typearg;
  if (luaL_getmetafield(L, arg, "__name") == LUA_TSTRING)
    typearg = lua_tostring(L, -1);
  else if (lua_type(L, arg) == LUA_TLIGHTUSERDATA)
    typearg = "light userdata";
  else
    typearg = luaL_typename(L, arg);
  msg = lua_pushfstring(L, "%s expected, got %s", tname, typearg);
  return luaL_argerror(L, arg, msg);
}

static void tag_error (lua_State *L, int arg, int tag) {
  typeerror(L, arg, lua_typename(L, tag));
}

LUALIB_API void luaL_where (lua_State *L, int level) {
  lua_Debug ar;
  if (lua_getstack(L, level, &ar)) {
    lua_getinfo(L, "Sl", &ar);
    if (ar.currentline > 0) {
      lua_pushfstring(L, "%s:%d: ", ar.short_src, ar.currentline);
      return;
    }
  }
  lua_pushfstring(L, "");
}

LUALIB_API int luaL_error (lua_State *L, const char *fmt, ...) {
  va_list argp;
  va_start(argp, fmt);
  luaL_where(L, 1);
  lua_pushvfstring(L, fmt, argp);
  va_end(argp);
  lua_concat(L, 2);
  return lua_error(L);
}

LUALIB_API int luaL_fileresult (lua_State *L UNUSED, int stat UNUSED, const char *fname UNUSED) {
  return 0;

}

#if !defined(l_inspectstat)

#if defined(LUA_USE_POSIX)

#include <sys/wait.h>

#define l_inspectstat(stat,what)  \
   if (WIFEXITED(stat)) { stat = WEXITSTATUS(stat); } \
   else if (WIFSIGNALED(stat)) { stat = WTERMSIG(stat); what = "signal"; }

#else

#define l_inspectstat(stat,what)

#endif

#endif

LUALIB_API int luaL_execresult (lua_State *L, int stat) {
  const char *what = "exit";
  if (stat == -1)
    return luaL_fileresult(L, 0, NULL);
  else {
    l_inspectstat(stat, what);
    if (*what == 'e' && stat == 0)
      lua_pushboolean(L, 1);
    else
      lua_pushnil(L);
    lua_pushstring(L, what);
    lua_pushinteger(L, stat);
    return 3;
  }
}

LUALIB_API int luaL_newmetatable (lua_State *L, const char *tname) {
  if (luaL_getmetatable(L, tname) != LUA_TNIL)
    return 0;
  lua_pop(L, 1);
  lua_createtable(L, 0, 2);
  lua_pushstring(L, tname);
  lua_setfield(L, -2, "__name");
  lua_pushvalue(L, -1);
  lua_setfield(L, LUA_REGISTRYINDEX, tname);
  return 1;
}

LUALIB_API void luaL_setmetatable (lua_State *L, const char *tname) {
  luaL_getmetatable(L, tname);
  lua_setmetatable(L, -2);
}

LUALIB_API void *luaL_testudata (lua_State *L, int ud, const char *tname) {
  void *p = lua_touserdata(L, ud);
  if (p != NULL) {
    if (lua_getmetatable(L, ud)) {
      luaL_getmetatable(L, tname);
      if (!lua_rawequal(L, -1, -2))
        p = NULL;
      lua_pop(L, 2);
      return p;
    }
  }
  return NULL;
}

LUALIB_API void *luaL_checkudata (lua_State *L, int ud, const char *tname) {
  void *p = luaL_testudata(L, ud, tname);
  if (p == NULL) typeerror(L, ud, tname);
  return p;
}

LUALIB_API int luaL_checkoption (lua_State *L, int arg, const char *def,
                                 const char *const lst[]) {
  const char *name = (def) ? luaL_optstring(L, arg, def) :
                             luaL_checkstring(L, arg);
  int i;
  for (i=0; lst[i]; i++)
    if (strcmp(lst[i], name) == 0)
      return i;
  return luaL_argerror(L, arg,
                       lua_pushfstring(L, "invalid option '%s'", name));
}

LUALIB_API void luaL_checkstack (lua_State *L, int space, const char *msg) {
  if (!lua_checkstack(L, space)) {
    if (msg)
      luaL_error(L, "stack overflow (%s)", msg);
    else
      luaL_error(L, "stack overflow");
  }
}

LUALIB_API void luaL_checktype (lua_State *L, int arg, int t) {
  if (lua_type(L, arg) != t)
    tag_error(L, arg, t);
}

LUALIB_API void luaL_checkany (lua_State *L, int arg) {
  if (lua_type(L, arg) == LUA_TNONE)
    luaL_argerror(L, arg, "value expected");
}

LUALIB_API const char *luaL_checklstring (lua_State *L, int arg, size_t *len) {
  const char *s = lua_tolstring(L, arg, len);
  if (!s) tag_error(L, arg, LUA_TSTRING);
  return s;
}

LUALIB_API const char *luaL_optlstring (lua_State *L, int arg,
                                        const char *def, size_t *len) {
  if (lua_isnoneornil(L, arg)) {
    if (len)
      *len = (def ? strlen(def) : 0);
    return def;
  }
  else return luaL_checklstring(L, arg, len);
}

LUALIB_API lua_Number luaL_checknumber (lua_State *L, int arg) {
  int isnum;
  lua_Number d = lua_tonumberx(L, arg, &isnum);
  if (!isnum)
    tag_error(L, arg, LUA_TNUMBER);
  return d;
}

LUALIB_API lua_Number luaL_optnumber (lua_State *L, int arg, lua_Number def) {
  return luaL_opt(L, luaL_checknumber, arg, def);
}

static void interror (lua_State *L, int arg) {
  if (lua_isnumber(L, arg))
    luaL_argerror(L, arg, "number has no integer representation");
  else
    tag_error(L, arg, LUA_TNUMBER);
}

LUALIB_API lua_Integer luaL_checkinteger (lua_State *L, int arg) {
  int isnum;
  lua_Integer d = lua_tointegerx(L, arg, &isnum);
  if (!isnum) {
    interror(L, arg);
  }
  return d;
}

LUALIB_API lua_Integer luaL_optinteger (lua_State *L, int arg,
                                                      lua_Integer def) {
  return luaL_opt(L, luaL_checkinteger, arg, def);
}

typedef struct UBox {
  void *box;
  size_t bsize;
} UBox;

static void *resizebox (lua_State *L, int idx, size_t newsize) {
  void *ud;
  lua_Alloc allocf = lua_getallocf(L, &ud);
  UBox *box = (UBox *)lua_touserdata(L, idx);
  void *temp = allocf(ud, box->box, box->bsize, newsize);
  if (temp == NULL && newsize > 0) {
    resizebox(L, idx, 0);
    luaL_error(L, "not enough memory for buffer allocation");
  }
  box->box = temp;
  box->bsize = newsize;
  return temp;
}

static int boxgc (lua_State *L) {
  resizebox(L, 1, 0);
  return 0;
}

static void *newbox (lua_State *L, size_t newsize) {
  UBox *box = (UBox *)lua_newuserdata(L, sizeof(UBox));
  box->box = NULL;
  box->bsize = 0;
  if (luaL_newmetatable(L, "LUABOX")) {
    lua_pushcfunction(L, boxgc);
    lua_setfield(L, -2, "__gc");
  }
  lua_setmetatable(L, -2);
  return resizebox(L, -1, newsize);
}

#define buffonstack(B)	((B)->b != (B)->initb)

LUALIB_API char *luaL_prepbuffsize (luaL_Buffer *B, size_t sz) {
  lua_State *L = B->L;
  if (B->size - B->n < sz) {
    char *newbuff;
    size_t newsize = B->size * 2;
    if (newsize - B->n < sz)
      newsize = B->n + sz;
    if (newsize < B->n || newsize - B->n < sz)
      luaL_error(L, "buffer too large");

    if (buffonstack(B))
      newbuff = (char *)resizebox(L, -1, newsize);
    else {
      newbuff = (char *)newbox(L, newsize);
      memcpy(newbuff, B->b, B->n * sizeof(char));
    }
    B->b = newbuff;
    B->size = newsize;
  }
  return &B->b[B->n];
}

LUALIB_API void luaL_addlstring (luaL_Buffer *B, const char *s, size_t l) {
  if (l > 0) {
    char *b = luaL_prepbuffsize(B, l);
    memcpy(b, s, l * sizeof(char));
    luaL_addsize(B, l);
  }
}

LUALIB_API void luaL_addstring (luaL_Buffer *B, const char *s) {
  luaL_addlstring(B, s, strlen(s));
}

LUALIB_API void luaL_pushresult (luaL_Buffer *B) {
  lua_State *L = B->L;
  lua_pushlstring(L, B->b, B->n);
  if (buffonstack(B)) {
    resizebox(L, -2, 0);
    lua_remove(L, -2);
  }
}

LUALIB_API void luaL_pushresultsize (luaL_Buffer *B, size_t sz) {
  luaL_addsize(B, sz);
  luaL_pushresult(B);
}

LUALIB_API void luaL_addvalue (luaL_Buffer *B) {
  lua_State *L = B->L;
  size_t l;
  const char *s = lua_tolstring(L, -1, &l);
  if (buffonstack(B))
    lua_insert(L, -2);
  luaL_addlstring(B, s, l);
  lua_remove(L, (buffonstack(B)) ? -2 : -1);
}

LUALIB_API void luaL_buffinit (lua_State *L, luaL_Buffer *B) {
  B->L = L;
  B->b = B->initb;
  B->n = 0;
  B->size = LUAL_BUFFERSIZE;
}

LUALIB_API char *luaL_buffinitsize (lua_State *L, luaL_Buffer *B, size_t sz) {
  luaL_buffinit(L, B);
  return luaL_prepbuffsize(B, sz);
}

#define freelist	0

LUALIB_API int luaL_ref (lua_State *L, int t) {
  int ref;
  if (lua_isnil(L, -1)) {
    lua_pop(L, 1);
    return LUA_REFNIL;
  }
  t = lua_absindex(L, t);
  lua_rawgeti(L, t, freelist);
  ref = (int)lua_tointeger(L, -1);
  lua_pop(L, 1);
  if (ref != 0) {
    lua_rawgeti(L, t, ref);
    lua_rawseti(L, t, freelist);
  }
  else
    ref = (int)lua_rawlen(L, t) + 1;
  lua_rawseti(L, t, ref);
  return ref;
}

LUALIB_API void luaL_unref (lua_State *L, int t, int ref) {
  if (ref >= 0) {
    t = lua_absindex(L, t);
    lua_rawgeti(L, t, freelist);
    lua_rawseti(L, t, ref);
    lua_pushinteger(L, ref);
    lua_rawseti(L, t, freelist);
  }
}

typedef struct LoadF {
  int n;
  FILE *f;
  char buff[BUFSIZ];
} LoadF;

static const char *getF (lua_State *L UNUSED, void *ud UNUSED, size_t *size UNUSED) {

  return NULL;
}

static int errfile (lua_State *L UNUSED, const char *what UNUSED, int fnameindex UNUSED) {
  return 0;

}

static int skipBOM (LoadF *lf UNUSED) {
  return 0;

}

static int skipcomment (LoadF *lf UNUSED, int *cp UNUSED) {
   return 0;

}

LUALIB_API int luaL_loadfilex (lua_State *L UNUSED, const char *filename UNUSED,
                                             const char *mode UNUSED) {

  return 0;
}

typedef struct LoadS {
  const char *s;
  size_t size;
} LoadS;

static const char *getS (lua_State *L, void *ud, size_t *size) {
  LoadS *ls = (LoadS *)ud;
  (void)L;
  if (ls->size == 0) return NULL;
  *size = ls->size;
  ls->size = 0;
  return ls->s;
}

LUALIB_API int luaL_loadbufferx (lua_State *L, const char *buff, size_t size,
                                 const char *name, const char *mode) {
  LoadS ls;
  ls.s = buff;
  ls.size = size;
  return lua_load(L, getS, &ls, name, mode);
}

LUALIB_API int luaL_loadstring (lua_State *L, const char *s) {
  return luaL_loadbuffer(L, s, strlen(s), s);
}

LUALIB_API int luaL_getmetafield (lua_State *L, int obj, const char *event) {
  if (!lua_getmetatable(L, obj))
    return LUA_TNIL;
  else {
    int tt;
    lua_pushstring(L, event);
    tt = lua_rawget(L, -2);
    if (tt == LUA_TNIL)
      lua_pop(L, 2);
    else
      lua_remove(L, -2);
    return tt;
  }
}

LUALIB_API int luaL_callmeta (lua_State *L, int obj, const char *event) {
  obj = lua_absindex(L, obj);
  if (luaL_getmetafield(L, obj, event) == LUA_TNIL)
    return 0;
  lua_pushvalue(L, obj);
  lua_call(L, 1, 1);
  return 1;
}

LUALIB_API lua_Integer luaL_len (lua_State *L, int idx) {
  lua_Integer l;
  int isnum;
  lua_len(L, idx);
  l = lua_tointegerx(L, -1, &isnum);
  if (!isnum)
    luaL_error(L, "object length is not an integer");
  lua_pop(L, 1);
  return l;
}

LUALIB_API const char *luaL_tolstring (lua_State *L, int idx, size_t *len) {
  if (luaL_callmeta(L, idx, "__tostring")) {
    if (!lua_isstring(L, -1))
      luaL_error(L, "'__tostring' must return a string");
  }
  else {
    switch (lua_type(L, idx)) {
      case LUA_TNUMBER: {
        if (lua_isinteger(L, idx))
          lua_pushfstring(L, "%I", (LUAI_UACINT)lua_tointeger(L, idx));
        else
          lua_pushfstring(L, "%f", (LUAI_UACNUMBER)lua_tonumber(L, idx));
        break;
      }
      case LUA_TSTRING:
        lua_pushvalue(L, idx);
        break;
      case LUA_TBOOLEAN:
        lua_pushstring(L, (lua_toboolean(L, idx) ? "true" : "false"));
        break;
      case LUA_TNIL:
        lua_pushliteral(L, "nil");
        break;
      default: {
        int tt = luaL_getmetafield(L, idx, "__name");
        const char *kind = (tt == LUA_TSTRING) ? lua_tostring(L, -1) :
                                                 luaL_typename(L, idx);
        lua_pushfstring(L, "%s: %p", kind, lua_topointer(L, idx));
        if (tt != LUA_TNIL)
          lua_remove(L, -2);
        break;
      }
    }
  }
  return lua_tolstring(L, -1, len);
}

#if defined(LUA_COMPAT_MODULE)

static const char *luaL_findtable (lua_State *L, int idx,
                                   const char *fname, int szhint) {
  const char *e;
  if (idx) lua_pushvalue(L, idx);
  do {
    e = strchr(fname, '.');
    if (e == NULL) e = fname + strlen(fname);
    lua_pushlstring(L, fname, e - fname);
    if (lua_rawget(L, -2) == LUA_TNIL) {
      lua_pop(L, 1);
      lua_createtable(L, 0, (*e == '.' ? 1 : szhint));
      lua_pushlstring(L, fname, e - fname);
      lua_pushvalue(L, -2);
      lua_settable(L, -4);
    }
    else if (!lua_istable(L, -1)) {
      lua_pop(L, 2);
      return fname;
    }
    lua_remove(L, -2);
    fname = e + 1;
  } while (*e == '.');
  return NULL;
}

static int libsize (const luaL_Reg *l) {
  int size = 0;
  for (; l && l->name; l++) size++;
  return size;
}

LUALIB_API void luaL_pushmodule (lua_State *L, const char *modname,
                                 int sizehint) {
  luaL_findtable(L, LUA_REGISTRYINDEX, LUA_LOADED_TABLE, 1);
  if (lua_getfield(L, -1, modname) != LUA_TTABLE) {
    lua_pop(L, 1);

    lua_pushglobaltable(L);
    if (luaL_findtable(L, 0, modname, sizehint) != NULL)
      luaL_error(L, "name conflict for module '%s'", modname);
    lua_pushvalue(L, -1);
    lua_setfield(L, -3, modname);
  }
  lua_remove(L, -2);
}

LUALIB_API void luaL_openlib (lua_State *L, const char *libname,
                               const luaL_Reg *l, int nup) {
  luaL_checkversion(L);
  if (libname) {
    luaL_pushmodule(L, libname, libsize(l));
    lua_insert(L, -(nup + 1));
  }
  if (l)
    luaL_setfuncs(L, l, nup);
  else
    lua_pop(L, nup);
}

#endif

LUALIB_API void luaL_setfuncs (lua_State *L, const luaL_Reg *l, int nup) {
  luaL_checkstack(L, nup, "too many upvalues");
  for (; l->name != NULL; l++) {
    int i;
    for (i = 0; i < nup; i++)
      lua_pushvalue(L, -nup);
    lua_pushcclosure(L, l->func, nup);
    lua_setfield(L, -(nup + 2), l->name);
  }
  lua_pop(L, nup);
}

LUALIB_API int luaL_getsubtable (lua_State *L, int idx, const char *fname) {
  if (lua_getfield(L, idx, fname) == LUA_TTABLE)
    return 1;
  else {
    lua_pop(L, 1);
    idx = lua_absindex(L, idx);
    lua_newtable(L);
    lua_pushvalue(L, -1);
    lua_setfield(L, idx, fname);
    return 0;
  }
}

LUALIB_API void luaL_requiref (lua_State *L, const char *modname,
                               lua_CFunction openf, int glb) {
  luaL_getsubtable(L, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
  lua_getfield(L, -1, modname);
  if (!lua_toboolean(L, -1)) {
    lua_pop(L, 1);
    lua_pushcfunction(L, openf);
    lua_pushstring(L, modname);
    lua_call(L, 1, 1);
    lua_pushvalue(L, -1);
    lua_setfield(L, -3, modname);
  }
  lua_remove(L, -2);
  if (glb) {
    lua_pushvalue(L, -1);
    lua_setglobal(L, modname);
  }
}

LUALIB_API const char *luaL_gsub (lua_State *L, const char *s, const char *p,
                                                               const char *r) {
  const char *wild;
  size_t l = strlen(p);
  luaL_Buffer b;
  luaL_buffinit(L, &b);
  while ((wild = strstr(s, p)) != NULL) {
    luaL_addlstring(&b, s, wild - s);
    luaL_addstring(&b, r);
    s = wild + l;
  }
  luaL_addstring(&b, s);
  luaL_pushresult(&b);
  return lua_tostring(L, -1);
}

static void *l_alloc (void *ud, void *ptr, size_t osize, size_t nsize) {
  (void)ud; (void)osize;
  if (nsize == 0) {
    free(ptr);
    return NULL;
  }
  else
    return realloc(ptr, nsize);
}

static int panic (lua_State *L) {
  sendstringf("LUA PANIC: unprotected error in call to Lua API (%s)\n", lua_tostring(L, -1));
  return 0;
}

LUALIB_API lua_State *luaL_newstate (void) {
  lua_State *L = lua_newstate(l_alloc, NULL);
  if (L) lua_atpanic(L, &panic);
  return L;
}

LUALIB_API void luaL_checkversion_ (lua_State *L, lua_Number ver, size_t sz) {
  const lua_Number *v = lua_version(L);
  if (sz != LUAL_NUMSIZES)
    luaL_error(L, "core and library have incompatible numeric types");
  if (v != lua_version(NULL))
    luaL_error(L, "multiple Lua VMs detected");
  else if (*v != ver)
    luaL_error(L, "version mismatch: app. needs %f, Lua core provides %f",
                  (LUAI_UACNUMBER)ver, (LUAI_UACNUMBER)*v);
}
