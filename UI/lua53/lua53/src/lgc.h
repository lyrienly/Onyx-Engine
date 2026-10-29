#ifndef lgc_h
#define lgc_h

#include "lobject.h"
#include "lstate.h"

#if !defined(GCSTEPSIZE)

#define GCSTEPSIZE	(cast_int(100 * sizeof(TString)))
#endif

#define GCSpropagate	0
#define GCSatomic	1
#define GCSswpallgc	2
#define GCSswpfinobj	3
#define GCSswptobefnz	4
#define GCSswpend	5
#define GCScallfin	6
#define GCSpause	7

#define issweepphase(g)  \
	(GCSswpallgc <= (g)->gcstate && (g)->gcstate <= GCSswpend)

#define keepinvariant(g)	((g)->gcstate <= GCSatomic)

#define resetbits(x,m)		((x) &= cast(lu_byte, ~(m)))
#define setbits(x,m)		((x) |= (m))
#define testbits(x,m)		((x) & (m))
#define bitmask(b)		(1<<(b))
#define bit2mask(b1,b2)		(bitmask(b1) | bitmask(b2))
#define l_setbit(x,b)		setbits(x, bitmask(b))
#define resetbit(x,b)		resetbits(x, bitmask(b))
#define testbit(x,b)		testbits(x, bitmask(b))

#define WHITE0BIT	0
#define WHITE1BIT	1
#define BLACKBIT	2
#define FINALIZEDBIT	3

#define WHITEBITS	bit2mask(WHITE0BIT, WHITE1BIT)

#define iswhite(x)      testbits((x)->marked, WHITEBITS)
#define isblack(x)      testbit((x)->marked, BLACKBIT)
#define isgray(x)    \
	(!testbits((x)->marked, WHITEBITS | bitmask(BLACKBIT)))

#define tofinalize(x)	testbit((x)->marked, FINALIZEDBIT)

#define otherwhite(g)	((g)->currentwhite ^ WHITEBITS)
#define isdeadm(ow,m)	(!(((m) ^ WHITEBITS) & (ow)))
#define isdead(g,v)	isdeadm(otherwhite(g), (v)->marked)

#define changewhite(x)	((x)->marked ^= WHITEBITS)
#define gray2black(x)	l_setbit((x)->marked, BLACKBIT)

#define luaC_white(g)	cast(lu_byte, (g)->currentwhite & WHITEBITS)

#define luaC_condGC(L,c) \
	{if (G(L)->GCdebt > 0) {c;}; condchangemem(L);}
#define luaC_checkGC(L)		luaC_condGC(L, luaC_step(L);)

#define luaC_barrier(L,p,v) {  \
	if (iscollectable(v) && isblack(p) && iswhite(gcvalue(v)))  \
	luaC_barrier_(L,obj2gco(p),gcvalue(v)); }

#define luaC_barrierback(L,p,v) {  \
	if (iscollectable(v) && isblack(p) && iswhite(gcvalue(v)))  \
	luaC_barrierback_(L,p); }

#define luaC_objbarrier(L,p,o) {  \
	if (isblack(p) && iswhite(o)) \
		luaC_barrier_(L,obj2gco(p),obj2gco(o)); }

#define luaC_upvalbarrier(L,uv) \
  { if (iscollectable((uv)->v) && !upisopen(uv)) \
         luaC_upvalbarrier_(L,uv); }

LUAI_FUNC void luaC_fix (lua_State *L, GCObject *o);
LUAI_FUNC void luaC_freeallobjects (lua_State *L);
LUAI_FUNC void luaC_step (lua_State *L);
LUAI_FUNC void luaC_runtilstate (lua_State *L, int statesmask);
LUAI_FUNC void luaC_fullgc (lua_State *L, int isemergency);
LUAI_FUNC GCObject *luaC_newobj (lua_State *L, int tt, size_t sz);
LUAI_FUNC void luaC_barrier_ (lua_State *L, GCObject *o, GCObject *v);
LUAI_FUNC void luaC_barrierback_ (lua_State *L, Table *o);
LUAI_FUNC void luaC_upvalbarrier_ (lua_State *L, UpVal *uv);
LUAI_FUNC void luaC_checkfinalizer (lua_State *L, GCObject *o, Table *mt);
LUAI_FUNC void luaC_upvdeccount (lua_State *L, UpVal *uv);

#endif
