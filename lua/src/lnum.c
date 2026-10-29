#include <stdlib.h>
#include <math.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define lnum_c
#define LUA_CORE

#include "lua.h"
#include "llex.h"
#include "lnum.h"

#define lua_real2str(s,n)  sprintf((s), LUA_NUMBER_FMT, (n))

#ifdef LNUM_DOUBLE
# define lua_str2real	strtod
#elif defined(LNUM_FLOAT)
# define lua_str2real	strtof
#elif defined(LNUM_LDOUBLE)
# define lua_str2real	strtold
#endif

#define lua_integer2str(s,v) sprintf((s), LUA_INTEGER_FMT, (v))

void luaO_num2buf( char *s, const TValue *o )
{
  lua_Number n;
  lua_assert( ttisnumber(o) );

#ifdef LUA_TINT
  if (ttisint(o)) {
    lua_integer2str( s, ivalue(o) );
    return;
  }
#endif
  n= nvalue_fast(o);
  lua_real2str(s, n);

#ifdef LNUM_COMPLEX
  lua_Number n2= nvalue_img_fast(o);
  if (n2!=0) {
      int re0= (n == 0);
      char *s2= re0 ? s : strchr(s,'\0');
      if ((!re0) && (n2>0)) *s2++= '+';
      lua_real2str( s2, n2 );
      strcat(s2,"i");
  }
#endif
}

int  tt_integer_valued( const TValue *o, lua_Integer *ref ) {
  lua_Number d;
  lua_Integer i;

  lua_assert( ttype(o)==LUA_TNUMBER );
  lua_assert( ref );
#ifdef LNUM_COMPLEX
  if (nvalue_img_fast(o)!=0) return 0;
#endif
  d= nvalue_fast(o);
  lua_number2integer(i, d);
  if (cast_num(i) == d) {
    *ref= i; return 1;
  }
  return 0;
}

int luaO_str2d (const char *s, lua_Number *res_n, lua_Integer *res_i) {
  char *endptr;
  int ret;
  unsigned LUA_INTEGER add_me= 0;
  const char *s2= s;

  if (res_i) {

    unsigned LUA_INTEGER v= lua_str2ul(s, &endptr, 10);
    if ((endptr == s) && (*s!='.') && (*s!='+') && (*s!='-')) return 0;

    if (v <= LUA_INTEGER_MAX) {
      if (v==0 && toupper(*endptr)=='X') {
        errno= 0;
        v= lua_str2ul(endptr+1, &endptr, 16);
        if (errno==ERANGE)
          return 0;
      }

      if ((!*endptr) || isspace(*endptr)) {
        *res_i= v;
        while (isspace(cast(unsigned char, *endptr))) endptr++;
        return (!*endptr) ? TK_INT : 0;

      } else if (*endptr == '.') {

        const char *p= endptr+1;
        while( isdigit(*p) || isspace(*p) ) p++;
        if (*p=='\0') {
            s2= endptr;
            add_me= v;
        }
      }
    }
  }

  ret= TK_NUMBER;
  lua_assert(res_n);
  *res_n = lua_str2real(s2, &endptr) + cast_num(add_me);
  if (endptr == s2) {

    if ((*s2=='.') && (s2[1]=='\0') && s2!=s)
      return ret;
    else
      return 0;
  }
#ifdef LNUM_COMPLEX
  if (*endptr == 'i') { endptr++; ret= TK_NUMBER2; }
#endif
  if (!*endptr) return ret;

  while (isspace(cast(unsigned char, *endptr))) endptr++;
  return (!*endptr) ? ret : 0;
}

#ifdef LUA_TINT
int try_addint( lua_Integer *r, lua_Integer ib, lua_Integer ic ) {
  lua_Integer v= ib+ic;
  if (ib>0 && ic>0)      { if (v < 0) return 0;  }
  else if (ib<0 && ic<0) { if (v >= 0) return 0; }
  *r= v;
  return 1;
}

int try_subint( lua_Integer *r, lua_Integer ib, lua_Integer ic ) {
  lua_Integer v= ib-ic;
  if (ib>=0 && ic<0)     { if (v < 0) return 0;  }
  else if (ib<0 && ic>0) { if (v >= 0) return 0; }
  *r= v;
  return 1;
}

int try_mulint( lua_Integer *r, lua_Integer ib, lua_Integer ic ) {
  if (ib!=LUA_INTEGER_MIN && ic!=LUA_INTEGER_MIN) {
    lua_Integer b= luai_abs(ib), c= luai_abs(ic);
    if ( (ib==0) || (LUA_INTEGER_MAX/b >= c) ) {
      *r= ib*ic;
      return 1;
    }
  } else if (ib==0 || ic==0) {
    *r= 0; return 1;
  }

  if ( luai_nummul( cast_num(ib), cast_num(ic) ) == LUA_INTEGER_MIN ) {
    *r= LUA_INTEGER_MIN;
    return 1;
  }
  return 0;
}

int try_divint( lua_Integer *r, lua_Integer ib, lua_Integer ic ) {

  if (ic==0) return 0;

  if (ic==LUA_INTEGER_MIN) {
    if (ib==LUA_INTEGER_MIN) { *r=1; return 1; }
    if (ib==0) { *r=0; return 1; }

  } else if (ib==LUA_INTEGER_MIN) {
    lua_Number d= luai_numdiv( cast_num(LUA_INTEGER_MIN), cast_num(ic) );
    lua_Integer i; lua_number2integer(i,d);
    if (cast_num(i)==d) { *r= i; return 1; }

  } else {

     if (ib%ic == 0) { *r= ib/ic; return 1; }
  }

  return 0;
}

int try_modint( lua_Integer *r, lua_Integer ib, lua_Integer ic ) {
  if (ic!=0) {

    lua_Integer v= ib % ic;
    if ( v!=0 && (ib<0 || ic<0) ) {
      v= ib - ((ib/ic) - ((ib<=0 && ic<0) ? 0:1)) * ic;
    }

    lua_assert( (v<0) ? (ic<0) : (v>0) ? (ic>0) : 1 );
    *r= v;
    return 1;
  }
  return 0;
}

int try_powint( lua_Integer *r, lua_Integer ib, lua_Integer ic ) {

  if (ib==0) *r=0;
  else if (ic<0) return 0;
  else if (ib==2 && ic < (int)sizeof(lua_Integer)*8-1) *r= ((lua_Integer)1)<<ic;
  else if (ic==0) *r=1;
  else if (luai_abs(ib)==1) *r= (ic%2) ? ib:1;
  else {
    lua_Integer x= ib;
    while( --ic ) {
      if (!try_mulint( &x, x, ib ))
        return 0;
    }
    *r= x;
  }
  return 1;
}

int try_unmint( lua_Integer *r, lua_Integer ib ) {

  if ( ib != LUA_INTEGER_MIN )
    { *r= -ib; return 1; }
  return 0;
}
#endif
