#define ldo_c
#define LUA_CORE

#include "lprefix.h"

#include "lua.h"

#include "lapi.h"
#include "ldebug.h"
#include "ldo.h"
#include "lfunc.h"
#include "lgc.h"
#include "lmem.h"
#include "lobject.h"
#include "lopcodes.h"
#include "lparser.h"
#include "lstate.h"
#include "lstring.h"
#include "ltable.h"
#include "ltm.h"
#include "lundump.h"
#include "lvm.h"
#include "lzio.h"

#define errorstatus(s)	((s) > LUA_YIELD)

#if !defined(LUAI_THROW)

#if defined(__cplusplus) && !defined(LUA_USE_LONGJMP)

#define LUAI_THROW(L,c)		throw(c)
#define LUAI_TRY(L,c,a) \
	try { a } catch(...) { if ((c)->status == 0) (c)->status = -1; }
#define luai_jmpbuf		int

#elif defined(LUA_USE_POSIX)

#define LUAI_THROW(L,c)		_longjmp((c)->b, 1)
#define LUAI_TRY(L,c,a)		if (_setjmp((c)->b) == 0) { a }
#define luai_jmpbuf		jmp_buf

#else

#define LUAI_THROW(L,c)		longjmp((c)->b, 1)
#define LUAI_TRY(L,c,a)		if (setjmp((c)->b) == 0) { a }
#define luai_jmpbuf		jmp_buf

#endif

#endif

struct lua_longjmp {
  struct lua_longjmp *previous;
  luai_jmpbuf b;
  volatile int status;
};

static void seterrorobj (lua_State *L, int errcode, StkId oldtop) {
  switch (errcode) {
    case LUA_ERRMEM: {
      setsvalue2s(L, oldtop, G(L)->memerrmsg);
      break;
    }
    case LUA_ERRERR: {
      setsvalue2s(L, oldtop, luaS_newliteral(L, "error in error handling"));
      break;
    }
    default: {
      setobjs2s(L, oldtop, L->top - 1);
      break;
    }
  }
  L->top = oldtop + 1;
}

l_noret luaD_throw (lua_State *L, int errcode) {
  if (L->errorJmp) {
    L->errorJmp->status = errcode;
    LUAI_THROW(L, L->errorJmp);
  }
  else {
    global_State *g = G(L);
    L->status = cast_byte(errcode);
    if (g->mainthread->errorJmp) {
      setobjs2s(L, g->mainthread->top++, L->top - 1);
      luaD_throw(g->mainthread, errcode);
    }
    else {
      if (g->panic) {
        seterrorobj(L, errcode, L->top);
        if (L->ci->top < L->top)
          L->ci->top = L->top;
        lua_unlock(L);
        g->panic(L);
      }
      abort();
    }
  }

  while(1);
}

int luaD_rawrunprotected (lua_State *L, Pfunc f, void *ud) {
  unsigned short oldnCcalls = L->nCcalls;
  struct lua_longjmp lj;
  lj.status = LUA_OK;
  lj.previous = L->errorJmp;
  L->errorJmp = &lj;
  LUAI_TRY(L, &lj,
    (*f)(L, ud);
  );
  L->errorJmp = lj.previous;
  L->nCcalls = oldnCcalls;
  return lj.status;
}

static void correctstack (lua_State *L, TValue *oldstack) {
  CallInfo *ci;
  UpVal *up;
  L->top = (L->top - oldstack) + L->stack;
  for (up = L->openupval; up != NULL; up = up->u.open.next)
    up->v = (up->v - oldstack) + L->stack;
  for (ci = L->ci; ci != NULL; ci = ci->previous) {
    ci->top = (ci->top - oldstack) + L->stack;
    ci->func = (ci->func - oldstack) + L->stack;
    if (isLua(ci))
      ci->u.l.base = (ci->u.l.base - oldstack) + L->stack;
  }
}

#define ERRORSTACKSIZE	(LUAI_MAXSTACK + 200)

void luaD_reallocstack (lua_State *L, int newsize) {
  TValue *oldstack = L->stack;
  int lim = L->stacksize;
  lua_assert(newsize <= LUAI_MAXSTACK || newsize == ERRORSTACKSIZE);
  lua_assert(L->stack_last - L->stack == L->stacksize - EXTRA_STACK);
  luaM_reallocvector(L, L->stack, L->stacksize, newsize, TValue);
  for (; lim < newsize; lim++)
    setnilvalue(L->stack + lim);
  L->stacksize = newsize;
  L->stack_last = L->stack + newsize - EXTRA_STACK;
  correctstack(L, oldstack);
}

void luaD_growstack (lua_State *L, int n) {
  int size = L->stacksize;
  if (size > LUAI_MAXSTACK)
    luaD_throw(L, LUA_ERRERR);
  else {
    int needed = cast_int(L->top - L->stack) + n + EXTRA_STACK;
    int newsize = 2 * size;
    if (newsize > LUAI_MAXSTACK) newsize = LUAI_MAXSTACK;
    if (newsize < needed) newsize = needed;
    if (newsize > LUAI_MAXSTACK) {
      luaD_reallocstack(L, ERRORSTACKSIZE);
      luaG_runerror(L, "stack overflow");
    }
    else
      luaD_reallocstack(L, newsize);
  }
}

static int stackinuse (lua_State *L) {
  CallInfo *ci;
  StkId lim = L->top;
  for (ci = L->ci; ci != NULL; ci = ci->previous) {
    if (lim < ci->top) lim = ci->top;
  }
  lua_assert(lim <= L->stack_last);
  return cast_int(lim - L->stack) + 1;
}

void luaD_shrinkstack (lua_State *L) {
  int inuse = stackinuse(L);
  int goodsize = inuse + (inuse / 8) + 2*EXTRA_STACK;
  if (goodsize > LUAI_MAXSTACK)
    goodsize = LUAI_MAXSTACK;
  if (L->stacksize > LUAI_MAXSTACK)
    luaE_freeCI(L);
  else
    luaE_shrinkCI(L);

  if (inuse <= (LUAI_MAXSTACK - EXTRA_STACK) &&
      goodsize < L->stacksize)
    luaD_reallocstack(L, goodsize);
  else
    condmovestack(L,{},{});
}

void luaD_inctop (lua_State *L) {
  luaD_checkstack(L, 1);
  L->top++;
}

void luaD_hook (lua_State *L, int event, int line) {
  lua_Hook hook = L->hook;
  if (hook && L->allowhook) {
    CallInfo *ci = L->ci;
    ptrdiff_t top = savestack(L, L->top);
    ptrdiff_t ci_top = savestack(L, ci->top);
    lua_Debug ar;
    ar.event = event;
    ar.currentline = line;
    ar.i_ci = ci;
    luaD_checkstack(L, LUA_MINSTACK);
    ci->top = L->top + LUA_MINSTACK;
    lua_assert(ci->top <= L->stack_last);
    L->allowhook = 0;
    ci->callstatus |= CIST_HOOKED;
    lua_unlock(L);
    (*hook)(L, &ar);
    lua_lock(L);
    lua_assert(!L->allowhook);
    L->allowhook = 1;
    ci->top = restorestack(L, ci_top);
    L->top = restorestack(L, top);
    ci->callstatus &= ~CIST_HOOKED;
  }
}

static void callhook (lua_State *L, CallInfo *ci) {
  int hook = LUA_HOOKCALL;
  ci->u.l.savedpc++;
  if (isLua(ci->previous) &&
      GET_OPCODE(*(ci->previous->u.l.savedpc - 1)) == OP_TAILCALL) {
    ci->callstatus |= CIST_TAIL;
    hook = LUA_HOOKTAILCALL;
  }
  luaD_hook(L, hook, -1);
  ci->u.l.savedpc--;
}

static StkId adjust_varargs (lua_State *L, Proto *p, int actual) {
  int i;
  int nfixargs = p->numparams;
  StkId base, fixed;

  fixed = L->top - actual;
  base = L->top;
  for (i = 0; i < nfixargs && i < actual; i++) {
    setobjs2s(L, L->top++, fixed + i);
    setnilvalue(fixed + i);
  }
  for (; i < nfixargs; i++)
    setnilvalue(L->top++);
  return base;
}

static void tryfuncTM (lua_State *L, StkId func) {
  const TValue *tm = luaT_gettmbyobj(L, func, TM_CALL);
  StkId p;
  if (!ttisfunction(tm))
    luaG_typeerror(L, func, "call");

  for (p = L->top; p > func; p--)
    setobjs2s(L, p, p-1);
  L->top++;
  setobj2s(L, func, tm);
}

static int moveresults (lua_State *L, const TValue *firstResult, StkId res,
                                      int nres, int wanted) {
  switch (wanted) {
    case 0: break;
    case 1: {
      if (nres == 0)
        firstResult = luaO_nilobject;
      setobjs2s(L, res, firstResult);
      break;
    }
    case LUA_MULTRET: {
      int i;
      for (i = 0; i < nres; i++)
        setobjs2s(L, res + i, firstResult + i);
      L->top = res + nres;
      return 0;
    }
    default: {
      int i;
      if (wanted <= nres) {
        for (i = 0; i < wanted; i++)
          setobjs2s(L, res + i, firstResult + i);
      }
      else {
        for (i = 0; i < nres; i++)
          setobjs2s(L, res + i, firstResult + i);
        for (; i < wanted; i++)
          setnilvalue(res + i);
      }
      break;
    }
  }
  L->top = res + wanted;
  return 1;
}

int luaD_poscall (lua_State *L, CallInfo *ci, StkId firstResult, int nres) {
  StkId res;
  int wanted = ci->nresults;
  if (L->hookmask & (LUA_MASKRET | LUA_MASKLINE)) {
    if (L->hookmask & LUA_MASKRET) {
      ptrdiff_t fr = savestack(L, firstResult);
      luaD_hook(L, LUA_HOOKRET, -1);
      firstResult = restorestack(L, fr);
    }
    L->oldpc = ci->previous->u.l.savedpc;
  }
  res = ci->func;
  L->ci = ci->previous;

  return moveresults(L, firstResult, res, nres, wanted);
}

#define next_ci(L) (L->ci = (L->ci->next ? L->ci->next : luaE_extendCI(L)))

#define checkstackp(L,n,p)  \
  luaD_checkstackaux(L, n, \
    ptrdiff_t t__ = savestack(L, p);   \
    luaC_checkGC(L),   \
    p = restorestack(L, t__))

int luaD_precall (lua_State *L, StkId func, int nresults) {
  lua_CFunction f;
  CallInfo *ci;
  switch (ttype(func)) {
    case LUA_TCCL:
      f = clCvalue(func)->f;
      goto Cfunc;
    case LUA_TLCF:
      f = fvalue(func);
     Cfunc: {
      int n;
      checkstackp(L, LUA_MINSTACK, func);
      ci = next_ci(L);
      ci->nresults = nresults;
      ci->func = func;
      ci->top = L->top + LUA_MINSTACK;
      lua_assert(ci->top <= L->stack_last);
      ci->callstatus = 0;
      if (L->hookmask & LUA_MASKCALL)
        luaD_hook(L, LUA_HOOKCALL, -1);
      lua_unlock(L);
      n = (*f)(L);
      lua_lock(L);
      api_checknelems(L, n);
      luaD_poscall(L, ci, L->top - n, n);
      return 1;
    }
    case LUA_TLCL: {
      StkId base;
      Proto *p = clLvalue(func)->p;
      int n = cast_int(L->top - func) - 1;
      int fsize = p->maxstacksize;
      checkstackp(L, fsize, func);
      if (p->is_vararg)
        base = adjust_varargs(L, p, n);
      else {
        for (; n < p->numparams; n++)
          setnilvalue(L->top++);
        base = func + 1;
      }
      ci = next_ci(L);
      ci->nresults = nresults;
      ci->func = func;
      ci->u.l.base = base;
      L->top = ci->top = base + fsize;
      lua_assert(ci->top <= L->stack_last);
      ci->u.l.savedpc = p->code;
      ci->callstatus = CIST_LUA;
      if (L->hookmask & LUA_MASKCALL)
        callhook(L, ci);
      return 0;
    }
    default: {
      checkstackp(L, 1, func);
      tryfuncTM(L, func);
      return luaD_precall(L, func, nresults);
    }
  }
}

static void stackerror (lua_State *L) {
  if (L->nCcalls == LUAI_MAXCCALLS)
    luaG_runerror(L, "C stack overflow");
  else if (L->nCcalls >= (LUAI_MAXCCALLS + (LUAI_MAXCCALLS>>3)))
    luaD_throw(L, LUA_ERRERR);
}

void luaD_call (lua_State *L, StkId func, int nResults) {
  if (++L->nCcalls >= LUAI_MAXCCALLS)
    stackerror(L);
  if (!luaD_precall(L, func, nResults))
    luaV_execute(L);
  L->nCcalls--;
}

void luaD_callnoyield (lua_State *L, StkId func, int nResults) {
  L->nny++;
  luaD_call(L, func, nResults);
  L->nny--;
}

static void finishCcall (lua_State *L, int status) {
  CallInfo *ci = L->ci;
  int n;

  lua_assert(ci->u.c.k != NULL && L->nny == 0);

  lua_assert((ci->callstatus & CIST_YPCALL) || status == LUA_YIELD);
  if (ci->callstatus & CIST_YPCALL) {
    ci->callstatus &= ~CIST_YPCALL;
    L->errfunc = ci->u.c.old_errfunc;
  }

  adjustresults(L, ci->nresults);
  lua_unlock(L);
  n = (*ci->u.c.k)(L, status, ci->u.c.ctx);
  lua_lock(L);
  api_checknelems(L, n);
  luaD_poscall(L, ci, L->top - n, n);
}

static void unroll (lua_State *L, void *ud) {
  if (ud != NULL)
    finishCcall(L, *(int *)ud);
  while (L->ci != &L->base_ci) {
    if (!isLua(L->ci))
      finishCcall(L, LUA_YIELD);
    else {
      luaV_finishOp(L);
      luaV_execute(L);
    }
  }
}

static CallInfo *findpcall (lua_State *L) {
  CallInfo *ci;
  for (ci = L->ci; ci != NULL; ci = ci->previous) {
    if (ci->callstatus & CIST_YPCALL)
      return ci;
  }
  return NULL;
}

static int recover (lua_State *L, int status) {
  StkId oldtop;
  CallInfo *ci = findpcall(L);
  if (ci == NULL) return 0;

  oldtop = restorestack(L, ci->extra);
  luaF_close(L, oldtop);
  seterrorobj(L, status, oldtop);
  L->ci = ci;
  L->allowhook = getoah(ci->callstatus);
  L->nny = 0;
  luaD_shrinkstack(L);
  L->errfunc = ci->u.c.old_errfunc;
  return 1;
}

static int resume_error (lua_State *L, const char *msg, int narg) {
  L->top -= narg;
  setsvalue2s(L, L->top, luaS_new(L, msg));
  api_incr_top(L);
  lua_unlock(L);
  return LUA_ERRRUN;
}

static void resume (lua_State *L, void *ud) {
  int n = *(cast(int*, ud));
  StkId firstArg = L->top - n;
  CallInfo *ci = L->ci;
  if (L->status == LUA_OK) {
    if (!luaD_precall(L, firstArg - 1, LUA_MULTRET))
      luaV_execute(L);
  }
  else {
    lua_assert(L->status == LUA_YIELD);
    L->status = LUA_OK;
    ci->func = restorestack(L, ci->extra);
    if (isLua(ci))
      luaV_execute(L);
    else {
      if (ci->u.c.k != NULL) {
        lua_unlock(L);
        n = (*ci->u.c.k)(L, LUA_YIELD, ci->u.c.ctx);
        lua_lock(L);
        api_checknelems(L, n);
        firstArg = L->top - n;
      }
      luaD_poscall(L, ci, firstArg, n);
    }
    unroll(L, NULL);
  }
}

LUA_API int lua_resume (lua_State *L, lua_State *from, int nargs) {
  int status;
  unsigned short oldnny = L->nny;
  lua_lock(L);
  if (L->status == LUA_OK) {
    if (L->ci != &L->base_ci)
      return resume_error(L, "cannot resume non-suspended coroutine", nargs);
  }
  else if (L->status != LUA_YIELD)
    return resume_error(L, "cannot resume dead coroutine", nargs);
  L->nCcalls = (from) ? from->nCcalls + 1 : 1;
  if (L->nCcalls >= LUAI_MAXCCALLS)
    return resume_error(L, "C stack overflow", nargs);
  luai_userstateresume(L, nargs);
  L->nny = 0;
  api_checknelems(L, (L->status == LUA_OK) ? nargs + 1 : nargs);
  status = luaD_rawrunprotected(L, resume, &nargs);
  if (status == -1)
    status = LUA_ERRRUN;
  else {
    while (errorstatus(status) && recover(L, status)) {

      status = luaD_rawrunprotected(L, unroll, &status);
    }
    if (errorstatus(status)) {
      L->status = cast_byte(status);
      seterrorobj(L, status, L->top);
      L->ci->top = L->top;
    }
    else lua_assert(status == L->status);
  }
  L->nny = oldnny;
  L->nCcalls--;
  lua_assert(L->nCcalls == ((from) ? from->nCcalls : 0));
  lua_unlock(L);
  return status;
}

LUA_API int lua_isyieldable (lua_State *L) {
  return (L->nny == 0);
}

LUA_API int lua_yieldk (lua_State *L, int nresults, lua_KContext ctx,
                        lua_KFunction k) {
  CallInfo *ci = L->ci;
  luai_userstateyield(L, nresults);
  lua_lock(L);
  api_checknelems(L, nresults);
  if (L->nny > 0) {
    if (L != G(L)->mainthread)
      luaG_runerror(L, "attempt to yield across a C-call boundary");
    else
      luaG_runerror(L, "attempt to yield from outside a coroutine");
  }
  L->status = LUA_YIELD;
  ci->extra = savestack(L, ci->func);
  if (isLua(ci)) {
    api_check(L, k == NULL, "hooks cannot continue after yielding");
  }
  else {
    if ((ci->u.c.k = k) != NULL)
      ci->u.c.ctx = ctx;
    ci->func = L->top - nresults - 1;
    luaD_throw(L, LUA_YIELD);
  }
  lua_assert(ci->callstatus & CIST_HOOKED);
  lua_unlock(L);
  return 0;
}

int luaD_pcall (lua_State *L, Pfunc func, void *u,
                ptrdiff_t old_top, ptrdiff_t ef) {
  int status;
  CallInfo *old_ci = L->ci;
  lu_byte old_allowhooks = L->allowhook;
  unsigned short old_nny = L->nny;
  ptrdiff_t old_errfunc = L->errfunc;
  L->errfunc = ef;
  status = luaD_rawrunprotected(L, func, u);
  if (status != LUA_OK) {
    StkId oldtop = restorestack(L, old_top);
    luaF_close(L, oldtop);
    seterrorobj(L, status, oldtop);
    L->ci = old_ci;
    L->allowhook = old_allowhooks;
    L->nny = old_nny;
    luaD_shrinkstack(L);
  }
  L->errfunc = old_errfunc;
  return status;
}

struct SParser {
  ZIO *z;
  Mbuffer buff;
  Dyndata dyd;
  const char *mode;
  const char *name;
};

static void checkmode (lua_State *L, const char *mode, const char *x) {
  if (mode && strchr(mode, x[0]) == NULL) {
    luaO_pushfstring(L,
       "attempt to load a %s chunk (mode is '%s')", x, mode);
    luaD_throw(L, LUA_ERRSYNTAX);
  }
}

static void f_parser (lua_State *L, void *ud) {
  LClosure *cl;
  struct SParser *p = cast(struct SParser *, ud);
  int c = zgetc(p->z);
  if (c == LUA_SIGNATURE[0]) {
    checkmode(L, p->mode, "binary");
    cl = luaU_undump(L, p->z, p->name);
  }
  else {
    checkmode(L, p->mode, "text");
    cl = luaY_parser(L, p->z, &p->buff, &p->dyd, p->name, c);
  }
  lua_assert(cl->nupvalues == cl->p->sizeupvalues);
  luaF_initupvals(L, cl);
}

int luaD_protectedparser (lua_State *L, ZIO *z, const char *name,
                                        const char *mode) {
  struct SParser p;
  int status;
  L->nny++;
  p.z = z; p.name = name; p.mode = mode;
  p.dyd.actvar.arr = NULL; p.dyd.actvar.size = 0;
  p.dyd.gt.arr = NULL; p.dyd.gt.size = 0;
  p.dyd.label.arr = NULL; p.dyd.label.size = 0;
  luaZ_initbuffer(L, &p.buff);
  status = luaD_pcall(L, f_parser, &p, savestack(L, L->top), L->errfunc);
  luaZ_freebuffer(L, &p.buff);
  luaM_freearray(L, p.dyd.actvar.arr, p.dyd.actvar.size);
  luaM_freearray(L, p.dyd.gt.arr, p.dyd.gt.size);
  luaM_freearray(L, p.dyd.label.arr, p.dyd.label.size);
  L->nny--;
  return status;
}
