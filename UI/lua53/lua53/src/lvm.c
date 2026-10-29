#define lvm_c
#define LUA_CORE

#include "lprefix.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lua.h"

#include "ldebug.h"
#include "ldo.h"
#include "lfunc.h"
#include "lgc.h"
#include "lobject.h"
#include "lopcodes.h"
#include "lstate.h"
#include "lstring.h"
#include "ltable.h"
#include "ltm.h"
#include "lvm.h"

#if !defined(LUA_FLOORN2I)
#define LUA_FLOORN2I		0
#endif

#define MAXTAGLOOP	2000

static int tofloat (const TValue *obj, lua_Number *n) {
  if (ttisfloat(obj)) *n = fltvalue(obj);
  else if (ttisinteger(obj)) {
    volatile lua_Number x = cast_num(ivalue(obj));
    *n = x;
  }
  else {
    *n = 0;
    return 0;
  }
  return 1;
}

int luaV_tonumber_ (const TValue *obj, lua_Number *n) {
  TValue v;
  if (ttisinteger(obj)) {
    *n = cast_num(ivalue(obj));
    return 1;
  }
  else if (cvt2num(obj) &&
            luaO_str2num(svalue(obj), &v) == tsvalue(obj)->len + 1) {
    *n = nvalue(&v);
    return 1;
  }
  else
    return 0;
}

static int tointeger_aux (const TValue *obj, lua_Integer *p, int mode) {
  TValue v;
 again:
  if (ttisfloat(obj)) {
    lua_Number n = fltvalue(obj);
    lua_Number f = l_floor(n);
    if (n != f) {
      if (mode == 0) return 0;
      else if (mode > 1)
        f += 1;
    }
    return lua_numbertointeger(f, p);
  }
  else if (ttisinteger(obj)) {
    *p = ivalue(obj);
    return 1;
  }
  else if (cvt2num(obj) &&
            luaO_str2num(svalue(obj), &v) == tsvalue(obj)->len + 1) {
    obj = &v;
    goto again;
  }
  return 0;
}

int luaV_tointeger_ (const TValue *obj, lua_Integer *p) {
  return tointeger_aux(obj, p, LUA_FLOORN2I);
}

static int forlimit (const TValue *obj, lua_Integer *p, lua_Integer step,
                     int *stopnow) {
  *stopnow = 0;
  if (!tointeger_aux(obj, p, (step < 0 ? 2 : 1))) {
    lua_Number n;
    if (!tonumber(obj, &n))
      return 0;
    if (n > 0) {
      *p = LUA_MAXINTEGER;
      if (step < 0) *stopnow = 1;
    }
    else {
      *p = LUA_MININTEGER;
      if (step >= 0) *stopnow = 1;
    }
  }
  return 1;
}

void luaV_gettable (lua_State *L, const TValue *t, TValue *key, StkId val) {
  int loop;
  for (loop = 0; loop < MAXTAGLOOP; loop++) {
    const TValue *tm;
    if (ttistable(t)) {
      Table *h = hvalue(t);
      const TValue *res = luaH_get(h, key);
      if (!ttisnil(res) ||
          (tm = fasttm(L, h->metatable, TM_INDEX)) == NULL) {
        setobj2s(L, val, res);
        return;
      }

    }
    else if (ttisnil(tm = luaT_gettmbyobj(L, t, TM_INDEX)))
      luaG_typeerror(L, t, "index");
    if (ttisfunction(tm)) {
      luaT_callTM(L, tm, t, key, val, 1);
      return;
    }
    t = tm;
  }
  luaG_runerror(L, "gettable chain too long; possible loop");
}

void luaV_settable (lua_State *L, const TValue *t, TValue *key, StkId val) {
  int loop;
  for (loop = 0; loop < MAXTAGLOOP; loop++) {
    const TValue *tm;
    if (ttistable(t)) {
      Table *h = hvalue(t);
      TValue *oldval = cast(TValue *, luaH_get(h, key));

      if (!ttisnil(oldval) ||

         ((tm = fasttm(L, h->metatable, TM_NEWINDEX)) == NULL &&

         (oldval != luaO_nilobject ||

         (oldval = luaH_newkey(L, h, key), 1)))) {

        setobj2t(L, oldval, val);
        invalidateTMcache(h);
        luaC_barrierback(L, h, val);
        return;
      }

    }
    else
      if (ttisnil(tm = luaT_gettmbyobj(L, t, TM_NEWINDEX)))
        luaG_typeerror(L, t, "index");

    if (ttisfunction(tm)) {
      luaT_callTM(L, tm, t, key, val, 0);
      return;
    }
    t = tm;
  }
  luaG_runerror(L, "settable chain too long; possible loop");
}

static int l_strcmp (const TString *ls, const TString *rs) {
  const char *l = getstr(ls);
  size_t ll = ls->len;
  const char *r = getstr(rs);
  size_t lr = rs->len;
  for (;;) {
    int temp = strcoll(l, r);
    if (temp != 0)
      return temp;
    else {
      size_t len = strlen(l);
      if (len == lr)
        return (len == ll) ? 0 : 1;
      else if (len == ll)
        return -1;

      len++;
      l += len; ll -= len; r += len; lr -= len;
    }
  }
}

int luaV_lessthan (lua_State *L, const TValue *l, const TValue *r) {
  int res;
  lua_Number nl, nr;
  if (ttisinteger(l) && ttisinteger(r))
    return (ivalue(l) < ivalue(r));
  else if (tofloat(l, &nl) && tofloat(r, &nr))
    return luai_numlt(nl, nr);
  else if (ttisstring(l) && ttisstring(r))
    return l_strcmp(tsvalue(l), tsvalue(r)) < 0;
  else if ((res = luaT_callorderTM(L, l, r, TM_LT)) < 0)
    luaG_ordererror(L, l, r);
  return res;
}

int luaV_lessequal (lua_State *L, const TValue *l, const TValue *r) {
  int res;
  lua_Number nl, nr;
  if (ttisinteger(l) && ttisinteger(r))
    return (ivalue(l) <= ivalue(r));
  else if (tofloat(l, &nl) && tofloat(r, &nr))
    return luai_numle(nl, nr);
  else if (ttisstring(l) && ttisstring(r))
    return l_strcmp(tsvalue(l), tsvalue(r)) <= 0;
  else if ((res = luaT_callorderTM(L, l, r, TM_LE)) >= 0)
    return res;
  else if ((res = luaT_callorderTM(L, r, l, TM_LT)) < 0)
    luaG_ordererror(L, l, r);
  return !res;
}

int luaV_equalobj (lua_State *L, const TValue *t1, const TValue *t2) {
  const TValue *tm;
  if (ttype(t1) != ttype(t2)) {
    if (ttnov(t1) != ttnov(t2) || ttnov(t1) != LUA_TNUMBER)
      return 0;
    else {
      lua_Number n1, n2;
      lua_assert(ttisnumber(t1) && ttisnumber(t2));
      cast_void(tofloat(t1, &n1)); cast_void(tofloat(t2, &n2));
      return luai_numeq(n1, n2);
    }
  }

  switch (ttype(t1)) {
    case LUA_TNIL: return 1;
    case LUA_TNUMINT: return (ivalue(t1) == ivalue(t2));
    case LUA_TNUMFLT: return luai_numeq(fltvalue(t1), fltvalue(t2));
    case LUA_TBOOLEAN: return bvalue(t1) == bvalue(t2);
    case LUA_TLIGHTUSERDATA: return pvalue(t1) == pvalue(t2);
    case LUA_TLCF: return fvalue(t1) == fvalue(t2);
    case LUA_TSHRSTR: return eqshrstr(tsvalue(t1), tsvalue(t2));
    case LUA_TLNGSTR: return luaS_eqlngstr(tsvalue(t1), tsvalue(t2));
    case LUA_TUSERDATA: {
      if (uvalue(t1) == uvalue(t2)) return 1;
      else if (L == NULL) return 0;
      tm = fasttm(L, uvalue(t1)->metatable, TM_EQ);
      if (tm == NULL)
        tm = fasttm(L, uvalue(t2)->metatable, TM_EQ);
      break;
    }
    case LUA_TTABLE: {
      if (hvalue(t1) == hvalue(t2)) return 1;
      else if (L == NULL) return 0;
      tm = fasttm(L, hvalue(t1)->metatable, TM_EQ);
      if (tm == NULL)
        tm = fasttm(L, hvalue(t2)->metatable, TM_EQ);
      break;
    }
    default:
      return gcvalue(t1) == gcvalue(t2);
  }
  if (tm == NULL)
    return 0;
  luaT_callTM(L, tm, t1, t2, L->top, 1);
  return !l_isfalse(L->top);
}

#define tostring(L,o)  \
	(ttisstring(o) || (cvt2str(o) && (luaO_tostring(L, o), 1)))

void luaV_concat (lua_State *L, int total) {
  lua_assert(total >= 2);
  do {
    StkId top = L->top;
    int n = 2;
    if (!(ttisstring(top-2) || cvt2str(top-2)) || !tostring(L, top-1))
      luaT_trybinTM(L, top-2, top-1, top-2, TM_CONCAT);
    else if (tsvalue(top-1)->len == 0)
      cast_void(tostring(L, top - 2));
    else if (ttisstring(top-2) && tsvalue(top-2)->len == 0) {
      setobjs2s(L, top - 2, top - 1);
    }
    else {

      size_t tl = tsvalue(top-1)->len;
      char *buffer;
      int i;

      for (i = 1; i < total && tostring(L, top-i-1); i++) {
        size_t l = tsvalue(top-i-1)->len;
        if (l >= (MAX_SIZE/sizeof(char)) - tl)
          luaG_runerror(L, "string length overflow");
        tl += l;
      }
      buffer = luaZ_openspace(L, &G(L)->buff, tl);
      tl = 0;
      n = i;
      do {
        size_t l = tsvalue(top-i)->len;
        memcpy(buffer+tl, svalue(top-i), l * sizeof(char));
        tl += l;
      } while (--i > 0);
      setsvalue2s(L, top-n, luaS_newlstr(L, buffer, tl));
    }
    total -= n-1;
    L->top -= n-1;
  } while (total > 1);
}

void luaV_objlen (lua_State *L, StkId ra, const TValue *rb) {
  const TValue *tm;
  switch (ttnov(rb)) {
    case LUA_TTABLE: {
      Table *h = hvalue(rb);
      tm = fasttm(L, h->metatable, TM_LEN);
      if (tm) break;
      setivalue(ra, luaH_getn(h));
      return;
    }
    case LUA_TSTRING: {
      setivalue(ra, tsvalue(rb)->len);
      return;
    }
    default: {
      tm = luaT_gettmbyobj(L, rb, TM_LEN);
      if (ttisnil(tm))
        luaG_typeerror(L, rb, "get length of");
      break;
    }
  }
  luaT_callTM(L, tm, rb, rb, ra, 1);
}

lua_Integer luaV_div (lua_State *L, lua_Integer m, lua_Integer n) {
  if (l_castS2U(n) + 1u <= 1u) {
    if (n == 0)
      luaG_runerror(L, "attempt to divide by zero");
    return intop(-, 0, m);
  }
  else {
    lua_Integer q = m / n;
    if ((m ^ n) < 0 && m % n != 0)
      q -= 1;
    return q;
  }
}

lua_Integer luaV_mod (lua_State *L, lua_Integer m, lua_Integer n) {
  if (l_castS2U(n) + 1u <= 1u) {
    if (n == 0)
      luaG_runerror(L, "attempt to perform 'n%%0'");
    return 0;
  }
  else {
    lua_Integer r = m % n;
    if (r != 0 && (m ^ n) < 0)
      r += n;
    return r;
  }
}

#define NBITS	cast_int(sizeof(lua_Integer) * CHAR_BIT)

lua_Integer luaV_shiftl (lua_Integer x, lua_Integer y) {
  if (y < 0) {
    if (y <= -NBITS) return 0;
    else return intop(>>, x, -y);
  }
  else {
    if (y >= NBITS) return 0;
    else return intop(<<, x, y);
  }
}

static LClosure *getcached (Proto *p, UpVal **encup, StkId base) {
  LClosure *c = p->cache;
  if (c != NULL) {
    int nup = p->sizeupvalues;
    Upvaldesc *uv = p->upvalues;
    int i;
    for (i = 0; i < nup; i++) {
      TValue *v = uv[i].instack ? base + uv[i].idx : encup[uv[i].idx]->v;
      if (c->upvals[i]->v != v)
        return NULL;
    }
  }
  return c;
}

static void pushclosure (lua_State *L, Proto *p, UpVal **encup, StkId base,
                         StkId ra) {
  int nup = p->sizeupvalues;
  Upvaldesc *uv = p->upvalues;
  int i;
  LClosure *ncl = luaF_newLclosure(L, nup);
  ncl->p = p;
  setclLvalue(L, ra, ncl);
  for (i = 0; i < nup; i++) {
    if (uv[i].instack)
      ncl->upvals[i] = luaF_findupval(L, base + uv[i].idx);
    else
      ncl->upvals[i] = encup[uv[i].idx];
    ncl->upvals[i]->refcount++;

  }
  if (!isblack(p))
    p->cache = ncl;
}

void luaV_finishOp (lua_State *L) {
  CallInfo *ci = L->ci;
  StkId base = ci->u.l.base;
  Instruction inst = *(ci->u.l.savedpc - 1);
  OpCode op = GET_OPCODE(inst);
  switch (op) {
    case OP_ADD: case OP_SUB: case OP_MUL: case OP_DIV: case OP_IDIV:
    case OP_BAND: case OP_BOR: case OP_BXOR: case OP_SHL: case OP_SHR:
    case OP_MOD: case OP_POW:
    case OP_UNM: case OP_BNOT: case OP_LEN:
    case OP_GETTABUP: case OP_GETTABLE: case OP_SELF: {
      setobjs2s(L, base + GETARG_A(inst), --L->top);
      break;
    }
    case OP_LE: case OP_LT: case OP_EQ: {
      int res = !l_isfalse(L->top - 1);
      L->top--;

      lua_assert(!ISK(GETARG_B(inst)));
      if (op == OP_LE &&
          ttisnil(luaT_gettmbyobj(L, base + GETARG_B(inst), TM_LE)))
        res = !res;
      lua_assert(GET_OPCODE(*ci->u.l.savedpc) == OP_JMP);
      if (res != GETARG_A(inst))
        ci->u.l.savedpc++;
      break;
    }
    case OP_CONCAT: {
      StkId top = L->top - 1;
      int b = GETARG_B(inst);
      int total = cast_int(top - 1 - (base + b));
      setobj2s(L, top - 2, top);
      if (total > 1) {
        L->top = top - 1;
        luaV_concat(L, total);
      }

      setobj2s(L, ci->u.l.base + GETARG_A(inst), L->top - 1);
      L->top = ci->top;
      break;
    }
    case OP_TFORCALL: {
      lua_assert(GET_OPCODE(*ci->u.l.savedpc) == OP_TFORLOOP);
      L->top = ci->top;
      break;
    }
    case OP_CALL: {
      if (GETARG_C(inst) - 1 >= 0)
        L->top = ci->top;
      break;
    }
    case OP_TAILCALL: case OP_SETTABUP: case OP_SETTABLE:
      break;
    default: lua_assert(0);
  }
}

#if !defined luai_runtimecheck
#define luai_runtimecheck(L, c)
#endif

#define RA(i)	(base+GETARG_A(i))

#define RB(i)	check_exp(getBMode(GET_OPCODE(i)) == OpArgR, base+GETARG_B(i))
#define RC(i)	check_exp(getCMode(GET_OPCODE(i)) == OpArgR, base+GETARG_C(i))
#define RKB(i)	check_exp(getBMode(GET_OPCODE(i)) == OpArgK, \
	ISK(GETARG_B(i)) ? k+INDEXK(GETARG_B(i)) : base+GETARG_B(i))
#define RKC(i)	check_exp(getCMode(GET_OPCODE(i)) == OpArgK, \
	ISK(GETARG_C(i)) ? k+INDEXK(GETARG_C(i)) : base+GETARG_C(i))
#define KBx(i)  \
  (k + (GETARG_Bx(i) != 0 ? GETARG_Bx(i) - 1 : GETARG_Ax(*ci->u.l.savedpc++)))

#define dojump(ci,i,e) \
  { int a = GETARG_A(i); \
    if (a > 0) luaF_close(L, ci->u.l.base + a - 1); \
    ci->u.l.savedpc += GETARG_sBx(i) + e; }

#define donextjump(ci)	{ i = *ci->u.l.savedpc; dojump(ci, i, 1); }

#define Protect(x)	{ {x;}; base = ci->u.l.base; }

#define checkGC(L,c)  \
  Protect( luaC_condGC(L,{L->top = (c);   \
                          luaC_step(L); \
                          L->top = ci->top;})   \
           luai_threadyield(L); )

#define vmdispatch(o)	switch(o)
#define vmcase(l)	case l:
#define vmbreak		break

void luaV_execute (lua_State *L) {
  CallInfo *ci = L->ci;
  LClosure *cl;
  TValue *k;
  StkId base;
 newframe:
  lua_assert(ci == L->ci);
  cl = clLvalue(ci->func);
  k = cl->p->k;
  base = ci->u.l.base;

  for (;;) {
    Instruction i = *(ci->u.l.savedpc++);
    StkId ra;
    if ((L->hookmask & (LUA_MASKLINE | LUA_MASKCOUNT)) &&
        (--L->hookcount == 0 || L->hookmask & LUA_MASKLINE)) {
      Protect(luaG_traceexec(L));
    }

    ra = RA(i);
    lua_assert(base == ci->u.l.base);
    lua_assert(base <= L->top && L->top < L->stack + L->stacksize);
    vmdispatch (GET_OPCODE(i)) {
      vmcase(OP_MOVE) {
        setobjs2s(L, ra, RB(i));
        vmbreak;
      }
      vmcase(OP_LOADK) {
        TValue *rb = k + GETARG_Bx(i);
        setobj2s(L, ra, rb);
        vmbreak;
      }
      vmcase(OP_LOADKX) {
        TValue *rb;
        lua_assert(GET_OPCODE(*ci->u.l.savedpc) == OP_EXTRAARG);
        rb = k + GETARG_Ax(*ci->u.l.savedpc++);
        setobj2s(L, ra, rb);
        vmbreak;
      }
      vmcase(OP_LOADBOOL) {
        setbvalue(ra, GETARG_B(i));
        if (GETARG_C(i)) ci->u.l.savedpc++;
        vmbreak;
      }
      vmcase(OP_LOADNIL) {
        int b = GETARG_B(i);
        do {
          setnilvalue(ra++);
        } while (b--);
        vmbreak;
      }
      vmcase(OP_GETUPVAL) {
        int b = GETARG_B(i);
        setobj2s(L, ra, cl->upvals[b]->v);
        vmbreak;
      }
      vmcase(OP_GETTABUP) {
        int b = GETARG_B(i);
        Protect(luaV_gettable(L, cl->upvals[b]->v, RKC(i), ra));
        vmbreak;
      }
      vmcase(OP_GETTABLE) {
        Protect(luaV_gettable(L, RB(i), RKC(i), ra));
        vmbreak;
      }
      vmcase(OP_SETTABUP) {
        int a = GETARG_A(i);
        Protect(luaV_settable(L, cl->upvals[a]->v, RKB(i), RKC(i)));
        vmbreak;
      }
      vmcase(OP_SETUPVAL) {
        UpVal *uv = cl->upvals[GETARG_B(i)];
        setobj(L, uv->v, ra);
        luaC_upvalbarrier(L, uv);
        vmbreak;
      }
      vmcase(OP_SETTABLE) {
        Protect(luaV_settable(L, ra, RKB(i), RKC(i)));
        vmbreak;
      }
      vmcase(OP_NEWTABLE) {
        int b = GETARG_B(i);
        int c = GETARG_C(i);
        Table *t = luaH_new(L);
        sethvalue(L, ra, t);
        if (b != 0 || c != 0)
          luaH_resize(L, t, luaO_fb2int(b), luaO_fb2int(c));
        checkGC(L, ra + 1);
        vmbreak;
      }
      vmcase(OP_SELF) {
        StkId rb = RB(i);
        setobjs2s(L, ra+1, rb);
        Protect(luaV_gettable(L, rb, RKC(i), ra));
        vmbreak;
      }
      vmcase(OP_ADD) {
        TValue *rb = RKB(i);
        TValue *rc = RKC(i);
        lua_Number nb; lua_Number nc;
        if (ttisinteger(rb) && ttisinteger(rc)) {
          lua_Integer ib = ivalue(rb); lua_Integer ic = ivalue(rc);
          setivalue(ra, intop(+, ib, ic));
        }
        else if (tonumber(rb, &nb) && tonumber(rc, &nc)) {
          setfltvalue(ra, luai_numadd(L, nb, nc));
        }
        else { Protect(luaT_trybinTM(L, rb, rc, ra, TM_ADD)); }
        vmbreak;
      }
      vmcase(OP_SUB) {
        TValue *rb = RKB(i);
        TValue *rc = RKC(i);
        lua_Number nb; lua_Number nc;
        if (ttisinteger(rb) && ttisinteger(rc)) {
          lua_Integer ib = ivalue(rb); lua_Integer ic = ivalue(rc);
          setivalue(ra, intop(-, ib, ic));
        }
        else if (tonumber(rb, &nb) && tonumber(rc, &nc)) {
          setfltvalue(ra, luai_numsub(L, nb, nc));
        }
        else { Protect(luaT_trybinTM(L, rb, rc, ra, TM_SUB)); }
        vmbreak;
      }
      vmcase(OP_MUL) {
        TValue *rb = RKB(i);
        TValue *rc = RKC(i);
        lua_Number nb; lua_Number nc;
        if (ttisinteger(rb) && ttisinteger(rc)) {
          lua_Integer ib = ivalue(rb); lua_Integer ic = ivalue(rc);
          setivalue(ra, intop(*, ib, ic));
        }
        else if (tonumber(rb, &nb) && tonumber(rc, &nc)) {
          setfltvalue(ra, luai_nummul(L, nb, nc));
        }
        else { Protect(luaT_trybinTM(L, rb, rc, ra, TM_MUL)); }
        vmbreak;
      }
      vmcase(OP_DIV) {
        TValue *rb = RKB(i);
        TValue *rc = RKC(i);
        lua_Number nb; lua_Number nc;
        if (tonumber(rb, &nb) && tonumber(rc, &nc)) {
          setfltvalue(ra, luai_numdiv(L, nb, nc));
        }
        else { Protect(luaT_trybinTM(L, rb, rc, ra, TM_DIV)); }
        vmbreak;
      }
      vmcase(OP_BAND) {
        TValue *rb = RKB(i);
        TValue *rc = RKC(i);
        lua_Integer ib; lua_Integer ic;
        if (tointeger(rb, &ib) && tointeger(rc, &ic)) {
          setivalue(ra, intop(&, ib, ic));
        }
        else { Protect(luaT_trybinTM(L, rb, rc, ra, TM_BAND)); }
        vmbreak;
      }
      vmcase(OP_BOR) {
        TValue *rb = RKB(i);
        TValue *rc = RKC(i);
        lua_Integer ib; lua_Integer ic;
        if (tointeger(rb, &ib) && tointeger(rc, &ic)) {
          setivalue(ra, intop(|, ib, ic));
        }
        else { Protect(luaT_trybinTM(L, rb, rc, ra, TM_BOR)); }
        vmbreak;
      }
      vmcase(OP_BXOR) {
        TValue *rb = RKB(i);
        TValue *rc = RKC(i);
        lua_Integer ib; lua_Integer ic;
        if (tointeger(rb, &ib) && tointeger(rc, &ic)) {
          setivalue(ra, intop(^, ib, ic));
        }
        else { Protect(luaT_trybinTM(L, rb, rc, ra, TM_BXOR)); }
        vmbreak;
      }
      vmcase(OP_SHL) {
        TValue *rb = RKB(i);
        TValue *rc = RKC(i);
        lua_Integer ib; lua_Integer ic;
        if (tointeger(rb, &ib) && tointeger(rc, &ic)) {
          setivalue(ra, luaV_shiftl(ib, ic));
        }
        else { Protect(luaT_trybinTM(L, rb, rc, ra, TM_SHL)); }
        vmbreak;
      }
      vmcase(OP_SHR) {
        TValue *rb = RKB(i);
        TValue *rc = RKC(i);
        lua_Integer ib; lua_Integer ic;
        if (tointeger(rb, &ib) && tointeger(rc, &ic)) {
          setivalue(ra, luaV_shiftl(ib, -ic));
        }
        else { Protect(luaT_trybinTM(L, rb, rc, ra, TM_SHR)); }
        vmbreak;
      }
      vmcase(OP_MOD) {
        TValue *rb = RKB(i);
        TValue *rc = RKC(i);
        lua_Number nb; lua_Number nc;
        if (ttisinteger(rb) && ttisinteger(rc)) {
          lua_Integer ib = ivalue(rb); lua_Integer ic = ivalue(rc);
          setivalue(ra, luaV_mod(L, ib, ic));
        }
        else if (tonumber(rb, &nb) && tonumber(rc, &nc)) {
          lua_Number m;
          luai_nummod(L, nb, nc, m);
          setfltvalue(ra, m);
        }
        else { Protect(luaT_trybinTM(L, rb, rc, ra, TM_MOD)); }
        vmbreak;
      }
      vmcase(OP_IDIV) {
        TValue *rb = RKB(i);
        TValue *rc = RKC(i);
        lua_Number nb; lua_Number nc;
        if (ttisinteger(rb) && ttisinteger(rc)) {
          lua_Integer ib = ivalue(rb); lua_Integer ic = ivalue(rc);
          setivalue(ra, luaV_div(L, ib, ic));
        }
        else if (tonumber(rb, &nb) && tonumber(rc, &nc)) {
          setfltvalue(ra, luai_numidiv(L, nb, nc));
        }
        else { Protect(luaT_trybinTM(L, rb, rc, ra, TM_IDIV)); }
        vmbreak;
      }
      vmcase(OP_POW) {
        TValue *rb = RKB(i);
        TValue *rc = RKC(i);
        lua_Number nb; lua_Number nc;
        if (tonumber(rb, &nb) && tonumber(rc, &nc)) {
          setfltvalue(ra, luai_numpow(L, nb, nc));
        }
        else { Protect(luaT_trybinTM(L, rb, rc, ra, TM_POW)); }
        vmbreak;
      }
      vmcase(OP_UNM) {
        TValue *rb = RB(i);
        lua_Number nb;
        if (ttisinteger(rb)) {
          lua_Integer ib = ivalue(rb);
          setivalue(ra, intop(-, 0, ib));
        }
        else if (tonumber(rb, &nb)) {
          setfltvalue(ra, luai_numunm(L, nb));
        }
        else {
          Protect(luaT_trybinTM(L, rb, rb, ra, TM_UNM));
        }
        vmbreak;
      }
      vmcase(OP_BNOT) {
        TValue *rb = RB(i);
        lua_Integer ib;
        if (tointeger(rb, &ib)) {
          setivalue(ra, intop(^, ~l_castS2U(0), ib));
        }
        else {
          Protect(luaT_trybinTM(L, rb, rb, ra, TM_BNOT));
        }
        vmbreak;
      }
      vmcase(OP_NOT) {
        TValue *rb = RB(i);
        int res = l_isfalse(rb);
        setbvalue(ra, res);
        vmbreak;
      }
      vmcase(OP_LEN) {
        Protect(luaV_objlen(L, ra, RB(i)));
        vmbreak;
      }
      vmcase(OP_CONCAT) {
        int b = GETARG_B(i);
        int c = GETARG_C(i);
        StkId rb;
        L->top = base + c + 1;
        Protect(luaV_concat(L, c - b + 1));
        ra = RA(i);
        rb = b + base;
        setobjs2s(L, ra, rb);
        checkGC(L, (ra >= rb ? ra + 1 : rb));
        L->top = ci->top;
        vmbreak;
      }
      vmcase(OP_JMP) {
        dojump(ci, i, 0);
        vmbreak;
      }
      vmcase(OP_EQ) {
        TValue *rb = RKB(i);
        TValue *rc = RKC(i);
        Protect(
          if (cast_int(luaV_equalobj(L, rb, rc)) != GETARG_A(i))
            ci->u.l.savedpc++;
          else
            donextjump(ci);
        )
        vmbreak;
      }
      vmcase(OP_LT) {
        Protect(
          if (luaV_lessthan(L, RKB(i), RKC(i)) != GETARG_A(i))
            ci->u.l.savedpc++;
          else
            donextjump(ci);
        )
        vmbreak;
      }
      vmcase(OP_LE) {
        Protect(
          if (luaV_lessequal(L, RKB(i), RKC(i)) != GETARG_A(i))
            ci->u.l.savedpc++;
          else
            donextjump(ci);
        )
        vmbreak;
      }
      vmcase(OP_TEST) {
        if (GETARG_C(i) ? l_isfalse(ra) : !l_isfalse(ra))
            ci->u.l.savedpc++;
          else
          donextjump(ci);
        vmbreak;
      }
      vmcase(OP_TESTSET) {
        TValue *rb = RB(i);
        if (GETARG_C(i) ? l_isfalse(rb) : !l_isfalse(rb))
          ci->u.l.savedpc++;
        else {
          setobjs2s(L, ra, rb);
          donextjump(ci);
        }
        vmbreak;
      }
      vmcase(OP_CALL) {
        int b = GETARG_B(i);
        int nresults = GETARG_C(i) - 1;
        if (b != 0) L->top = ra+b;
        if (luaD_precall(L, ra, nresults)) {
          if (nresults >= 0) L->top = ci->top;
          base = ci->u.l.base;
        }
        else {
          ci = L->ci;
          ci->callstatus |= CIST_REENTRY;
          goto newframe;
        }
        vmbreak;
      }
      vmcase(OP_TAILCALL) {
        int b = GETARG_B(i);
        if (b != 0) L->top = ra+b;
        lua_assert(GETARG_C(i) - 1 == LUA_MULTRET);
        if (luaD_precall(L, ra, LUA_MULTRET))
          base = ci->u.l.base;
        else {

          CallInfo *nci = L->ci;
          CallInfo *oci = nci->previous;
          StkId nfunc = nci->func;
          StkId ofunc = oci->func;

          StkId lim = nci->u.l.base + getproto(nfunc)->numparams;
          int aux;

          if (cl->p->sizep > 0) luaF_close(L, oci->u.l.base);

          for (aux = 0; nfunc + aux < lim; aux++)
            setobjs2s(L, ofunc + aux, nfunc + aux);
          oci->u.l.base = ofunc + (nci->u.l.base - nfunc);
          oci->top = L->top = ofunc + (L->top - nfunc);
          oci->u.l.savedpc = nci->u.l.savedpc;
          oci->callstatus |= CIST_TAIL;
          ci = L->ci = oci;
          lua_assert(L->top == oci->u.l.base + getproto(ofunc)->maxstacksize);
          goto newframe;
        }
        vmbreak;
      }
      vmcase(OP_RETURN) {
        int b = GETARG_B(i);
        if (b != 0) L->top = ra+b-1;
        if (cl->p->sizep > 0) luaF_close(L, base);
        b = luaD_poscall(L, ra);
        if (!(ci->callstatus & CIST_REENTRY))
          return;
        else {
          ci = L->ci;
          if (b) L->top = ci->top;
          lua_assert(isLua(ci));
          lua_assert(GET_OPCODE(*((ci)->u.l.savedpc - 1)) == OP_CALL);
          goto newframe;
        }
      }
      vmcase(OP_FORLOOP) {
        if (ttisinteger(ra)) {
          lua_Integer step = ivalue(ra + 2);
          lua_Integer idx = ivalue(ra) + step;
          lua_Integer limit = ivalue(ra + 1);
          if ((0 < step) ? (idx <= limit) : (limit <= idx)) {
            ci->u.l.savedpc += GETARG_sBx(i);
            setivalue(ra, idx);
            setivalue(ra + 3, idx);
          }
        }
        else {
          lua_Number step = fltvalue(ra + 2);
          lua_Number idx = luai_numadd(L, fltvalue(ra), step);
          lua_Number limit = fltvalue(ra + 1);
          if (luai_numlt(0, step) ? luai_numle(idx, limit)
                                  : luai_numle(limit, idx)) {
            ci->u.l.savedpc += GETARG_sBx(i);
            setfltvalue(ra, idx);
            setfltvalue(ra + 3, idx);
          }
        }
        vmbreak;
      }
      vmcase(OP_FORPREP) {
        TValue *init = ra;
        TValue *plimit = ra + 1;
        TValue *pstep = ra + 2;
        lua_Integer ilimit;
        int stopnow;
        if (ttisinteger(init) && ttisinteger(pstep) &&
            forlimit(plimit, &ilimit, ivalue(pstep), &stopnow)) {

          lua_Integer initv = (stopnow ? 0 : ivalue(init));
          setivalue(plimit, ilimit);
          setivalue(init, initv - ivalue(pstep));
        }
        else {
          lua_Number ninit; lua_Number nlimit; lua_Number nstep;
          if (!tonumber(plimit, &nlimit))
            luaG_runerror(L, "'for' limit must be a number");
          setfltvalue(plimit, nlimit);
          if (!tonumber(pstep, &nstep))
            luaG_runerror(L, "'for' step must be a number");
          setfltvalue(pstep, nstep);
          if (!tonumber(init, &ninit))
            luaG_runerror(L, "'for' initial value must be a number");
          setfltvalue(init, luai_numsub(L, ninit, nstep));
        }
        ci->u.l.savedpc += GETARG_sBx(i);
        vmbreak;
      }
      vmcase(OP_TFORCALL) {
        StkId cb = ra + 3;
        setobjs2s(L, cb+2, ra+2);
        setobjs2s(L, cb+1, ra+1);
        setobjs2s(L, cb, ra);
        L->top = cb + 3;
        Protect(luaD_call(L, cb, GETARG_C(i), 1));
        L->top = ci->top;
        i = *(ci->u.l.savedpc++);
        ra = RA(i);
        lua_assert(GET_OPCODE(i) == OP_TFORLOOP);
        goto l_tforloop;
      }
      vmcase(OP_TFORLOOP) {
        l_tforloop:
        if (!ttisnil(ra + 1)) {
          setobjs2s(L, ra, ra + 1);
           ci->u.l.savedpc += GETARG_sBx(i);
        }
        vmbreak;
      }
      vmcase(OP_SETLIST) {
        int n = GETARG_B(i);
        int c = GETARG_C(i);
        unsigned int last;
        Table *h;
        if (n == 0) n = cast_int(L->top - ra) - 1;
        if (c == 0) {
          lua_assert(GET_OPCODE(*ci->u.l.savedpc) == OP_EXTRAARG);
          c = GETARG_Ax(*ci->u.l.savedpc++);
        }
        luai_runtimecheck(L, ttistable(ra));
        h = hvalue(ra);
        last = ((c-1)*LFIELDS_PER_FLUSH) + n;
        if (last > h->sizearray)
          luaH_resizearray(L, h, last);
        for (; n > 0; n--) {
          TValue *val = ra+n;
          luaH_setint(L, h, last--, val);
          luaC_barrierback(L, h, val);
        }
        L->top = ci->top;
        vmbreak;
      }
      vmcase(OP_CLOSURE) {
        Proto *p = cl->p->p[GETARG_Bx(i)];
        LClosure *ncl = getcached(p, cl->upvals, base);
        if (ncl == NULL)
          pushclosure(L, p, cl->upvals, base, ra);
        else
          setclLvalue(L, ra, ncl);
        checkGC(L, ra + 1);
        vmbreak;
      }
      vmcase(OP_VARARG) {
        int b = GETARG_B(i) - 1;
        int j;
        int n = cast_int(base - ci->func) - cl->p->numparams - 1;
        if (b < 0) {
          b = n;
          Protect(luaD_checkstack(L, n));
          ra = RA(i);
          L->top = ra + n;
        }
        for (j = 0; j < b; j++) {
          if (j < n) {
            setobjs2s(L, ra + j, base - n + j);
          }
          else {
            setnilvalue(ra + j);
          }
        }
        vmbreak;
      }
      vmcase(OP_EXTRAARG) {
        lua_assert(0);
        vmbreak;
      }
    }
  }
}
