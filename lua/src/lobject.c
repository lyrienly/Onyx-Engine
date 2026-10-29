#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define lobject_c
#define LUA_CORE

#include "lua.h"

#include "ldo.h"
#include "lmem.h"
#include "lobject.h"
#include "lstate.h"
#include "lstring.h"
#include "lvm.h"
#include "llex.h"
#include "lnum.h"

const TValue luaO_nilobject_ = {{NULL}, LUA_TNIL};

int luaO_int2fb (unsigned int x) {
  int e = 0;
  while (x >= 16) {
    x = (x+1) >> 1;
    e++;
  }
  if (x < 8) return x;
  else return ((e+1) << 3) | (cast_int(x) - 8);
}

int luaO_fb2int (int x) {
  int e = (x >> 3) & 31;
  if (e == 0) return x;
  else return ((x & 7)+8) << (e - 1);
}

int luaO_log2 (unsigned int x) {
  static const lu_byte log_2[256] = {
    0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
    6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8
  };
  int l = -1;
  while (x >= 256) { l += 8; x >>= 8; }
  return l + log_2[x];

}

int luaO_rawequalObj (const TValue *l, const TValue *r) {
  int tl= ttype(l), tr= ttype(r);
  if (tl == tr) {
    switch (tl) {
      case LUA_TNIL:
        return 1;
#ifdef LUA_TINT
      case LUA_TINT:
        return ivalue(l) == ivalue(r);
#endif
      case LUA_TNUMBER:
#ifdef LNUM_COMPLEX
        if (!luai_numeq(nvalue_img_fast(l), nvalue_img_fast(r))) return 0;
#endif
        return luai_numeq(nvalue_fast(l), nvalue_fast(r));
      case LUA_TBOOLEAN:
        return bvalue(l) == bvalue(r);
      case LUA_TLIGHTUSERDATA:
        return pvalue(l) == pvalue(r);
      default:
        lua_assert(iscollectable(l));
        return gcvalue(l) == gcvalue(r);
    }
  }
#ifdef LUA_TINT
  else if (tl==LUA_TINT && tr==LUA_TNUMBER) {
# ifdef LNUM_COMPLEX
    if (nvalue_img_fast(r) != 0) return 0;
# endif

    lua_Integer tmp;
    return tt_integer_valued(r,&tmp) ? (ivalue(l) == tmp)
                : luai_numeq( cast_num(ivalue(l)), nvalue_fast(r) );
  }
  else if (tl==LUA_TNUMBER && tr==LUA_TINT) {
    return luaO_rawequalObj(r,l);
  }
#endif
  return 0;
}

static void pushstr (lua_State *L, const char *str) {
  setsvalue2s(L, L->top, luaS_new(L, str));
  incr_top(L);
}

const char *luaO_pushvfstring (lua_State *L, const char *fmt, va_list argp) {
  int n = 1;
  pushstr(L, "");
  for (;;) {
    const char *e = strchr(fmt, '%');
    if (e == NULL) break;
    setsvalue2s(L, L->top, luaS_newlstr(L, fmt, e-fmt));
    incr_top(L);
    switch (*(e+1)) {
      case 's': {
        const char *s = va_arg(argp, char *);
        if (s == NULL) s = "(null)";
        pushstr(L, s);
        break;
      }
      case 'c': {
        char buff[2];
        buff[0] = cast(char, va_arg(argp, int));
        buff[1] = '\0';
        pushstr(L, buff);
        break;
      }
      case 'd': {

        setivalue(L->top, (lua_Integer) va_arg(argp, l_uacInteger));
        incr_top(L);
        break;
      }
      case 'f': {
        setnvalue(L->top, cast_num(va_arg(argp, l_uacNumber)));
        incr_top(L);
        break;
      }
      case 'p': {
        char buff[4*sizeof(void *) + 8];
        sprintf(buff, "%p", va_arg(argp, void *));
        pushstr(L, buff);
        break;
      }
      case '%': {
        pushstr(L, "%");
        break;
      }
      default: {
        char buff[3];
        buff[0] = '%';
        buff[1] = *(e+1);
        buff[2] = '\0';
        pushstr(L, buff);
        break;
      }
    }
    n += 2;
    fmt = e+2;
  }
  pushstr(L, fmt);
  luaV_concat(L, n+1, cast_int(L->top - L->base) - 1);
  L->top -= n;
  return svalue(L->top - 1);
}

const char *luaO_pushfstring (lua_State *L, const char *fmt, ...) {
  const char *msg;
  va_list argp;
  va_start(argp, fmt);
  msg = luaO_pushvfstring(L, fmt, argp);
  va_end(argp);
  return msg;
}

void luaO_chunkid (char *out, const char *source, size_t bufflen) {
  if (*source == '=') {
    strncpy(out, source+1, bufflen);
    out[bufflen-1] = '\0';
  }
  else {
    if (*source == '@') {
      size_t l;
      source++;
      bufflen -= sizeof(" '...' ");
      l = strlen(source);
      strcpy(out, "");
      if (l > bufflen) {
        source += (l-bufflen);
        strcat(out, "...");
      }
      strcat(out, source);
    }
    else {
      size_t len = strcspn(source, "\n\r");
      bufflen -= sizeof(" [string \"...\"] ");
      if (len > bufflen) len = bufflen;
      strcpy(out, "[string \"");
      if (source[len] != '\0') {
        strncat(out, source, len);
        strcat(out, "...");
      }
      else
        strcat(out, source);
      strcat(out, "\"]");
    }
  }
}
