#define lgc_c
#define LUA_CORE

#include "lprefix.h"

#include <string.h>

#include "lua.h"

#include "ldebug.h"
#include "ldo.h"
#include "lfunc.h"
#include "lgc.h"
#include "lmem.h"
#include "lobject.h"
#include "lstate.h"
#include "lstring.h"
#include "ltable.h"
#include "ltm.h"

#define GCSinsideatomic		(GCSpause + 1)

#define GCSWEEPCOST	((sizeof(TString) + 4) / 4)

#define GCSWEEPMAX	(cast_int((GCSTEPSIZE / GCSWEEPCOST) / 4))

#define GCFINALIZECOST	GCSWEEPCOST

#define STEPMULADJ		200

#define PAUSEADJ		100

#define maskcolors	(~(bitmask(BLACKBIT) | WHITEBITS))
#define makewhite(g,x)	\
 (x->marked = cast_byte((x->marked & maskcolors) | luaC_white(g)))

#define white2gray(x)	resetbits(x->marked, WHITEBITS)
#define black2gray(x)	resetbit(x->marked, BLACKBIT)

#define valiswhite(x)   (iscollectable(x) && iswhite(gcvalue(x)))

#define checkdeadkey(n)	lua_assert(!ttisdeadkey(gkey(n)) || ttisnil(gval(n)))

#define checkconsistency(obj)  \
  lua_longassert(!iscollectable(obj) || righttt(obj))

#define markvalue(g,o) { checkconsistency(o); \
  if (valiswhite(o)) reallymarkobject(g,gcvalue(o)); }

#define markobject(g,t)	{ if (iswhite(t)) reallymarkobject(g, obj2gco(t)); }

#define markobjectN(g,t)	{ if (t) markobject(g,t); }

static void reallymarkobject (global_State *g, GCObject *o);

#define gnodelast(h)	gnode(h, cast(size_t, sizenode(h)))

#define linkgclist(o,p)	((o)->gclist = (p), (p) = obj2gco(o))

static void removeentry (Node *n) {
  lua_assert(ttisnil(gval(n)));
  if (valiswhite(gkey(n)))
    setdeadvalue(wgkey(n));
}

static int iscleared (global_State *g, const TValue *o) {
  if (!iscollectable(o)) return 0;
  else if (ttisstring(o)) {
    markobject(g, tsvalue(o));
    return 0;
  }
  else return iswhite(gcvalue(o));
}

void luaC_barrier_ (lua_State *L, GCObject *o, GCObject *v) {
  global_State *g = G(L);
  lua_assert(isblack(o) && iswhite(v) && !isdead(g, v) && !isdead(g, o));
  if (keepinvariant(g))
    reallymarkobject(g, v);
  else {
    lua_assert(issweepphase(g));
    makewhite(g, o);
  }
}

void luaC_barrierback_ (lua_State *L, Table *t) {
  global_State *g = G(L);
  lua_assert(isblack(t) && !isdead(g, t));
  black2gray(t);
  linkgclist(t, g->grayagain);
}

void luaC_upvalbarrier_ (lua_State *L, UpVal *uv) {
  global_State *g = G(L);
  GCObject *o = gcvalue(uv->v);
  lua_assert(!upisopen(uv));
  if (keepinvariant(g))
    markobject(g, o);
}

void luaC_fix (lua_State *L, GCObject *o) {
  global_State *g = G(L);
  lua_assert(g->allgc == o);
  white2gray(o);
  g->allgc = o->next;
  o->next = g->fixedgc;
  g->fixedgc = o;
}

GCObject *luaC_newobj (lua_State *L, int tt, size_t sz) {
  global_State *g = G(L);
  GCObject *o = cast(GCObject *, luaM_newobject(L, novariant(tt), sz));
  o->marked = luaC_white(g);
  o->tt = tt;
  o->next = g->allgc;
  g->allgc = o;
  return o;
}

static void reallymarkobject (global_State *g, GCObject *o) {
 reentry:
  white2gray(o);
  switch (o->tt) {
    case LUA_TSHRSTR: {
      gray2black(o);
      g->GCmemtrav += sizelstring(gco2ts(o)->shrlen);
      break;
    }
    case LUA_TLNGSTR: {
      gray2black(o);
      g->GCmemtrav += sizelstring(gco2ts(o)->u.lnglen);
      break;
    }
    case LUA_TUSERDATA: {
      TValue uvalue;
      markobjectN(g, gco2u(o)->metatable);
      gray2black(o);
      g->GCmemtrav += sizeudata(gco2u(o));
      getuservalue(g->mainthread, gco2u(o), &uvalue);
      if (valiswhite(&uvalue)) {
        o = gcvalue(&uvalue);
        goto reentry;
      }
      break;
    }
    case LUA_TLCL: {
      linkgclist(gco2lcl(o), g->gray);
      break;
    }
    case LUA_TCCL: {
      linkgclist(gco2ccl(o), g->gray);
      break;
    }
    case LUA_TTABLE: {
      linkgclist(gco2t(o), g->gray);
      break;
    }
    case LUA_TTHREAD: {
      linkgclist(gco2th(o), g->gray);
      break;
    }
    case LUA_TPROTO: {
      linkgclist(gco2p(o), g->gray);
      break;
    }
    default: lua_assert(0); break;
  }
}

static void markmt (global_State *g) {
  int i;
  for (i=0; i < LUA_NUMTAGS; i++)
    markobjectN(g, g->mt[i]);
}

static void markbeingfnz (global_State *g) {
  GCObject *o;
  for (o = g->tobefnz; o != NULL; o = o->next)
    markobject(g, o);
}

static void remarkupvals (global_State *g) {
  lua_State *thread;
  lua_State **p = &g->twups;
  while ((thread = *p) != NULL) {
    lua_assert(!isblack(thread));
    if (isgray(thread) && thread->openupval != NULL)
      p = &thread->twups;
    else {
      UpVal *uv;
      *p = thread->twups;
      thread->twups = thread;
      for (uv = thread->openupval; uv != NULL; uv = uv->u.open.next) {
        if (uv->u.open.touched) {
          markvalue(g, uv->v);
          uv->u.open.touched = 0;
        }
      }
    }
  }
}

static void restartcollection (global_State *g) {
  g->gray = g->grayagain = NULL;
  g->weak = g->allweak = g->ephemeron = NULL;
  markobject(g, g->mainthread);
  markvalue(g, &g->l_registry);
  markmt(g);
  markbeingfnz(g);
}

static void traverseweakvalue (global_State *g, Table *h) {
  Node *n, *limit = gnodelast(h);

  int hasclears = (h->sizearray > 0);
  for (n = gnode(h, 0); n < limit; n++) {
    checkdeadkey(n);
    if (ttisnil(gval(n)))
      removeentry(n);
    else {
      lua_assert(!ttisnil(gkey(n)));
      markvalue(g, gkey(n));
      if (!hasclears && iscleared(g, gval(n)))
        hasclears = 1;
    }
  }
  if (g->gcstate == GCSpropagate)
    linkgclist(h, g->grayagain);
  else if (hasclears)
    linkgclist(h, g->weak);
}

static int traverseephemeron (global_State *g, Table *h) {
  int marked = 0;
  int hasclears = 0;
  int hasww = 0;
  Node *n, *limit = gnodelast(h);
  unsigned int i;

  for (i = 0; i < h->sizearray; i++) {
    if (valiswhite(&h->array[i])) {
      marked = 1;
      reallymarkobject(g, gcvalue(&h->array[i]));
    }
  }

  for (n = gnode(h, 0); n < limit; n++) {
    checkdeadkey(n);
    if (ttisnil(gval(n)))
      removeentry(n);
    else if (iscleared(g, gkey(n))) {
      hasclears = 1;
      if (valiswhite(gval(n)))
        hasww = 1;
    }
    else if (valiswhite(gval(n))) {
      marked = 1;
      reallymarkobject(g, gcvalue(gval(n)));
    }
  }

  if (g->gcstate == GCSpropagate)
    linkgclist(h, g->grayagain);
  else if (hasww)
    linkgclist(h, g->ephemeron);
  else if (hasclears)
    linkgclist(h, g->allweak);
  return marked;
}

static void traversestrongtable (global_State *g, Table *h) {
  Node *n, *limit = gnodelast(h);
  unsigned int i;
  for (i = 0; i < h->sizearray; i++)
    markvalue(g, &h->array[i]);
  for (n = gnode(h, 0); n < limit; n++) {
    checkdeadkey(n);
    if (ttisnil(gval(n)))
      removeentry(n);
    else {
      lua_assert(!ttisnil(gkey(n)));
      markvalue(g, gkey(n));
      markvalue(g, gval(n));
    }
  }
}

static lu_mem traversetable (global_State *g, Table *h) {
  const char *weakkey, *weakvalue;
  const TValue *mode = gfasttm(g, h->metatable, TM_MODE);
  markobjectN(g, h->metatable);
  if (mode && ttisstring(mode) &&
      ((weakkey = strchr(svalue(mode), 'k')),
       (weakvalue = strchr(svalue(mode), 'v')),
       (weakkey || weakvalue))) {
    black2gray(h);
    if (!weakkey)
      traverseweakvalue(g, h);
    else if (!weakvalue)
      traverseephemeron(g, h);
    else
      linkgclist(h, g->allweak);
  }
  else
    traversestrongtable(g, h);
  return sizeof(Table) + sizeof(TValue) * h->sizearray +
                         sizeof(Node) * cast(size_t, allocsizenode(h));
}

static int traverseproto (global_State *g, Proto *f) {
  int i;
  if (f->cache && iswhite(f->cache))
    f->cache = NULL;
  markobjectN(g, f->source);
  for (i = 0; i < f->sizek; i++)
    markvalue(g, &f->k[i]);
  for (i = 0; i < f->sizeupvalues; i++)
    markobjectN(g, f->upvalues[i].name);
  for (i = 0; i < f->sizep; i++)
    markobjectN(g, f->p[i]);
  for (i = 0; i < f->sizelocvars; i++)
    markobjectN(g, f->locvars[i].varname);
  return sizeof(Proto) + sizeof(Instruction) * f->sizecode +
                         sizeof(Proto *) * f->sizep +
                         sizeof(TValue) * f->sizek +
                         sizeof(int) * f->sizelineinfo +
                         sizeof(LocVar) * f->sizelocvars +
                         sizeof(Upvaldesc) * f->sizeupvalues;
}

static lu_mem traverseCclosure (global_State *g, CClosure *cl) {
  int i;
  for (i = 0; i < cl->nupvalues; i++)
    markvalue(g, &cl->upvalue[i]);
  return sizeCclosure(cl->nupvalues);
}

static lu_mem traverseLclosure (global_State *g, LClosure *cl) {
  int i;
  markobjectN(g, cl->p);
  for (i = 0; i < cl->nupvalues; i++) {
    UpVal *uv = cl->upvals[i];
    if (uv != NULL) {
      if (upisopen(uv) && g->gcstate != GCSinsideatomic)
        uv->u.open.touched = 1;
      else
        markvalue(g, uv->v);
    }
  }
  return sizeLclosure(cl->nupvalues);
}

static lu_mem traversethread (global_State *g, lua_State *th) {
  StkId o = th->stack;
  if (o == NULL)
    return 1;
  lua_assert(g->gcstate == GCSinsideatomic ||
             th->openupval == NULL || isintwups(th));
  for (; o < th->top; o++)
    markvalue(g, o);
  if (g->gcstate == GCSinsideatomic) {
    StkId lim = th->stack + th->stacksize;
    for (; o < lim; o++)
      setnilvalue(o);

    if (!isintwups(th) && th->openupval != NULL) {
      th->twups = g->twups;
      g->twups = th;
    }
  }
  else if (g->gckind != KGC_EMERGENCY)
    luaD_shrinkstack(th);
  return (sizeof(lua_State) + sizeof(TValue) * th->stacksize +
          sizeof(CallInfo) * th->nci);
}

static void propagatemark (global_State *g) {
  lu_mem size;
  GCObject *o = g->gray;
  lua_assert(isgray(o));
  gray2black(o);
  switch (o->tt) {
    case LUA_TTABLE: {
      Table *h = gco2t(o);
      g->gray = h->gclist;
      size = traversetable(g, h);
      break;
    }
    case LUA_TLCL: {
      LClosure *cl = gco2lcl(o);
      g->gray = cl->gclist;
      size = traverseLclosure(g, cl);
      break;
    }
    case LUA_TCCL: {
      CClosure *cl = gco2ccl(o);
      g->gray = cl->gclist;
      size = traverseCclosure(g, cl);
      break;
    }
    case LUA_TTHREAD: {
      lua_State *th = gco2th(o);
      g->gray = th->gclist;
      linkgclist(th, g->grayagain);
      black2gray(o);
      size = traversethread(g, th);
      break;
    }
    case LUA_TPROTO: {
      Proto *p = gco2p(o);
      g->gray = p->gclist;
      size = traverseproto(g, p);
      break;
    }
    default: lua_assert(0); return;
  }
  g->GCmemtrav += size;
}

static void propagateall (global_State *g) {
  while (g->gray) propagatemark(g);
}

static void convergeephemerons (global_State *g) {
  int changed;
  do {
    GCObject *w;
    GCObject *next = g->ephemeron;
    g->ephemeron = NULL;
    changed = 0;
    while ((w = next) != NULL) {
      next = gco2t(w)->gclist;
      if (traverseephemeron(g, gco2t(w))) {
        propagateall(g);
        changed = 1;
      }
    }
  } while (changed);
}

static void clearkeys (global_State *g, GCObject *l, GCObject *f) {
  for (; l != f; l = gco2t(l)->gclist) {
    Table *h = gco2t(l);
    Node *n, *limit = gnodelast(h);
    for (n = gnode(h, 0); n < limit; n++) {
      if (!ttisnil(gval(n)) && (iscleared(g, gkey(n)))) {
        setnilvalue(gval(n));
      }
      if (ttisnil(gval(n)))
        removeentry(n);
    }
  }
}

static void clearvalues (global_State *g, GCObject *l, GCObject *f) {
  for (; l != f; l = gco2t(l)->gclist) {
    Table *h = gco2t(l);
    Node *n, *limit = gnodelast(h);
    unsigned int i;
    for (i = 0; i < h->sizearray; i++) {
      TValue *o = &h->array[i];
      if (iscleared(g, o))
        setnilvalue(o);
    }
    for (n = gnode(h, 0); n < limit; n++) {
      if (!ttisnil(gval(n)) && iscleared(g, gval(n))) {
        setnilvalue(gval(n));
        removeentry(n);
      }
    }
  }
}

void luaC_upvdeccount (lua_State *L, UpVal *uv) {
  lua_assert(uv->refcount > 0);
  uv->refcount--;
  if (uv->refcount == 0 && !upisopen(uv))
    luaM_free(L, uv);
}

static void freeLclosure (lua_State *L, LClosure *cl) {
  int i;
  for (i = 0; i < cl->nupvalues; i++) {
    UpVal *uv = cl->upvals[i];
    if (uv)
      luaC_upvdeccount(L, uv);
  }
  luaM_freemem(L, cl, sizeLclosure(cl->nupvalues));
}

static void freeobj (lua_State *L, GCObject *o) {
  switch (o->tt) {
    case LUA_TPROTO: luaF_freeproto(L, gco2p(o)); break;
    case LUA_TLCL: {
      freeLclosure(L, gco2lcl(o));
      break;
    }
    case LUA_TCCL: {
      luaM_freemem(L, o, sizeCclosure(gco2ccl(o)->nupvalues));
      break;
    }
    case LUA_TTABLE: luaH_free(L, gco2t(o)); break;
    case LUA_TTHREAD: luaE_freethread(L, gco2th(o)); break;
    case LUA_TUSERDATA: luaM_freemem(L, o, sizeudata(gco2u(o))); break;
    case LUA_TSHRSTR:
      luaS_remove(L, gco2ts(o));
      luaM_freemem(L, o, sizelstring(gco2ts(o)->shrlen));
      break;
    case LUA_TLNGSTR: {
      luaM_freemem(L, o, sizelstring(gco2ts(o)->u.lnglen));
      break;
    }
    default: lua_assert(0);
  }
}

#define sweepwholelist(L,p)	sweeplist(L,p,MAX_LUMEM)
static GCObject **sweeplist (lua_State *L, GCObject **p, lu_mem count);

static GCObject **sweeplist (lua_State *L, GCObject **p, lu_mem count) {
  global_State *g = G(L);
  int ow = otherwhite(g);
  int white = luaC_white(g);
  while (*p != NULL && count-- > 0) {
    GCObject *curr = *p;
    int marked = curr->marked;
    if (isdeadm(ow, marked)) {
      *p = curr->next;
      freeobj(L, curr);
    }
    else {
      curr->marked = cast_byte((marked & maskcolors) | white);
      p = &curr->next;
    }
  }
  return (*p == NULL) ? NULL : p;
}

static GCObject **sweeptolive (lua_State *L, GCObject **p) {
  GCObject **old = p;
  do {
    p = sweeplist(L, p, 1);
  } while (p == old);
  return p;
}

static void checkSizes (lua_State *L, global_State *g) {
  if (g->gckind != KGC_EMERGENCY) {
    l_mem olddebt = g->GCdebt;
    if (g->strt.nuse < g->strt.size / 4)
      luaS_resize(L, g->strt.size / 2);
    g->GCestimate += g->GCdebt - olddebt;
  }
}

static GCObject *udata2finalize (global_State *g) {
  GCObject *o = g->tobefnz;
  lua_assert(tofinalize(o));
  g->tobefnz = o->next;
  o->next = g->allgc;
  g->allgc = o;
  resetbit(o->marked, FINALIZEDBIT);
  if (issweepphase(g))
    makewhite(g, o);
  return o;
}

static void dothecall (lua_State *L, void *ud UNUSED) {
  luaD_callnoyield(L, L->top - 2, 0);
}

static void GCTM (lua_State *L, int propagateerrors) {
  global_State *g = G(L);
  const TValue *tm;
  TValue v;
  setgcovalue(L, &v, udata2finalize(g));
  tm = luaT_gettmbyobj(L, &v, TM_GC);
  if (tm != NULL && ttisfunction(tm)) {
    int status;
    lu_byte oldah = L->allowhook;
    int running  = g->gcrunning;
    L->allowhook = 0;
    g->gcrunning = 0;
    setobj2s(L, L->top, tm);
    setobj2s(L, L->top + 1, &v);
    L->top += 2;
    L->ci->callstatus |= CIST_FIN;
    status = luaD_pcall(L, dothecall, NULL, savestack(L, L->top - 2), 0);
    L->ci->callstatus &= ~CIST_FIN;
    L->allowhook = oldah;
    g->gcrunning = running;
    if (status != LUA_OK && propagateerrors) {
      if (status == LUA_ERRRUN) {
        const char *msg = (ttisstring(L->top - 1))
                            ? svalue(L->top - 1)
                            : "no message";
        luaO_pushfstring(L, "error in __gc metamethod (%s)", msg);
        status = LUA_ERRGCMM;
      }
      luaD_throw(L, status);
    }
  }
}

static int runafewfinalizers (lua_State *L) {
  global_State *g = G(L);
  unsigned int i;
  lua_assert(!g->tobefnz || g->gcfinnum > 0);
  for (i = 0; g->tobefnz && i < g->gcfinnum; i++)
    GCTM(L, 1);
  g->gcfinnum = (!g->tobefnz) ? 0
                    : g->gcfinnum * 2;
  return i;
}

static void callallpendingfinalizers (lua_State *L) {
  global_State *g = G(L);
  while (g->tobefnz)
    GCTM(L, 0);
}

static GCObject **findlast (GCObject **p) {
  while (*p != NULL)
    p = &(*p)->next;
  return p;
}

static void separatetobefnz (global_State *g, int all) {
  GCObject *curr;
  GCObject **p = &g->finobj;
  GCObject **lastnext = findlast(&g->tobefnz);
  while ((curr = *p) != NULL) {
    lua_assert(tofinalize(curr));
    if (!(iswhite(curr) || all))
      p = &curr->next;
    else {
      *p = curr->next;
      curr->next = *lastnext;
      *lastnext = curr;
      lastnext = &curr->next;
    }
  }
}

void luaC_checkfinalizer (lua_State *L, GCObject *o, Table *mt) {
  global_State *g = G(L);
  if (tofinalize(o) ||
      gfasttm(g, mt, TM_GC) == NULL)
    return;
  else {
    GCObject **p;
    if (issweepphase(g)) {
      makewhite(g, o);
      if (g->sweepgc == &o->next)
        g->sweepgc = sweeptolive(L, g->sweepgc);
    }

    for (p = &g->allgc; *p != o; p = &(*p)->next) {  }
    *p = o->next;
    o->next = g->finobj;
    g->finobj = o;
    l_setbit(o->marked, FINALIZEDBIT);
  }
}

static void setpause (global_State *g) {
  l_mem threshold, debt;
  l_mem estimate = g->GCestimate / PAUSEADJ;
  lua_assert(estimate > 0);
  threshold = (g->gcpause < MAX_LMEM / estimate)
            ? estimate * g->gcpause
            : MAX_LMEM;
  debt = gettotalbytes(g) - threshold;
  luaE_setdebt(g, debt);
}

static void entersweep (lua_State *L) {
  global_State *g = G(L);
  g->gcstate = GCSswpallgc;
  lua_assert(g->sweepgc == NULL);
  g->sweepgc = sweeplist(L, &g->allgc, 1);
}

void luaC_freeallobjects (lua_State *L) {
  global_State *g = G(L);
  separatetobefnz(g, 1);
  lua_assert(g->finobj == NULL);
  callallpendingfinalizers(L);
  lua_assert(g->tobefnz == NULL);
  g->currentwhite = WHITEBITS;
  g->gckind = KGC_NORMAL;
  sweepwholelist(L, &g->finobj);
  sweepwholelist(L, &g->allgc);
  sweepwholelist(L, &g->fixedgc);
  lua_assert(g->strt.nuse == 0);
}

static l_mem atomic (lua_State *L) {
  global_State *g = G(L);
  l_mem work;
  GCObject *origweak, *origall;
  GCObject *grayagain = g->grayagain;
  lua_assert(g->ephemeron == NULL && g->weak == NULL);
  lua_assert(!iswhite(g->mainthread));
  g->gcstate = GCSinsideatomic;
  g->GCmemtrav = 0;
  markobject(g, L);

  markvalue(g, &g->l_registry);
  markmt(g);

  remarkupvals(g);
  propagateall(g);
  work = g->GCmemtrav;
  g->gray = grayagain;
  propagateall(g);
  g->GCmemtrav = 0;
  convergeephemerons(g);

  clearvalues(g, g->weak, NULL);
  clearvalues(g, g->allweak, NULL);
  origweak = g->weak; origall = g->allweak;
  work += g->GCmemtrav;
  separatetobefnz(g, 0);
  g->gcfinnum = 1;
  markbeingfnz(g);
  propagateall(g);
  g->GCmemtrav = 0;
  convergeephemerons(g);

  clearkeys(g, g->ephemeron, NULL);
  clearkeys(g, g->allweak, NULL);

  clearvalues(g, g->weak, origweak);
  clearvalues(g, g->allweak, origall);
  luaS_clearcache(g);
  g->currentwhite = cast_byte(otherwhite(g));
  work += g->GCmemtrav;
  return work;
}

static lu_mem sweepstep (lua_State *L, global_State *g,
                         int nextstate, GCObject **nextlist) {
  if (g->sweepgc) {
    l_mem olddebt = g->GCdebt;
    g->sweepgc = sweeplist(L, g->sweepgc, GCSWEEPMAX);
    g->GCestimate += g->GCdebt - olddebt;
    if (g->sweepgc)
      return (GCSWEEPMAX * GCSWEEPCOST);
  }

  g->gcstate = nextstate;
  g->sweepgc = nextlist;
  return 0;
}

static lu_mem singlestep (lua_State *L) {
  global_State *g = G(L);
  switch (g->gcstate) {
    case GCSpause: {
      g->GCmemtrav = g->strt.size * sizeof(GCObject*);
      restartcollection(g);
      g->gcstate = GCSpropagate;
      return g->GCmemtrav;
    }
    case GCSpropagate: {
      g->GCmemtrav = 0;
      lua_assert(g->gray);
      propagatemark(g);
       if (g->gray == NULL)
        g->gcstate = GCSatomic;
      return g->GCmemtrav;
    }
    case GCSatomic: {
      lu_mem work;
      propagateall(g);
      work = atomic(L);
      entersweep(L);
      g->GCestimate = gettotalbytes(g);  ;
      return work;
    }
    case GCSswpallgc: {
      return sweepstep(L, g, GCSswpfinobj, &g->finobj);
    }
    case GCSswpfinobj: {
      return sweepstep(L, g, GCSswptobefnz, &g->tobefnz);
    }
    case GCSswptobefnz: {
      return sweepstep(L, g, GCSswpend, NULL);
    }
    case GCSswpend: {
      makewhite(g, g->mainthread);
      checkSizes(L, g);
      g->gcstate = GCScallfin;
      return 0;
    }
    case GCScallfin: {
      if (g->tobefnz && g->gckind != KGC_EMERGENCY) {
        int n = runafewfinalizers(L);
        return (n * GCFINALIZECOST);
      }
      else {
        g->gcstate = GCSpause;
        return 0;
      }
    }
    default: lua_assert(0); return 0;
  }
}

void luaC_runtilstate (lua_State *L, int statesmask) {
  global_State *g = G(L);
  while (!testbit(statesmask, g->gcstate))
    singlestep(L);
}

static l_mem getdebt (global_State *g) {
  l_mem debt = g->GCdebt;
  int stepmul = g->gcstepmul;
  if (debt <= 0) return 0;
  else {
    debt = (debt / STEPMULADJ) + 1;
    debt = (debt < MAX_LMEM / stepmul) ? debt * stepmul : MAX_LMEM;
    return debt;
  }
}

void luaC_step (lua_State *L) {
  global_State *g = G(L);
  l_mem debt = getdebt(g);
  if (!g->gcrunning) {
    luaE_setdebt(g, -GCSTEPSIZE * 10);
    return;
  }
  do {
    lu_mem work = singlestep(L);
    debt -= work;
  } while (debt > -GCSTEPSIZE && g->gcstate != GCSpause);
  if (g->gcstate == GCSpause)
    setpause(g);
  else {
    debt = (debt / g->gcstepmul) * STEPMULADJ;
    luaE_setdebt(g, debt);
    runafewfinalizers(L);
  }
}

void luaC_fullgc (lua_State *L, int isemergency) {
  global_State *g = G(L);
  lua_assert(g->gckind == KGC_NORMAL);
  if (isemergency) g->gckind = KGC_EMERGENCY;
  if (keepinvariant(g)) {
    entersweep(L);
  }

  luaC_runtilstate(L, bitmask(GCSpause));
  luaC_runtilstate(L, ~bitmask(GCSpause));
  luaC_runtilstate(L, bitmask(GCScallfin));

  lua_assert(g->GCestimate == gettotalbytes(g));
  luaC_runtilstate(L, bitmask(GCSpause));
  g->gckind = KGC_NORMAL;
  setpause(g);
}
