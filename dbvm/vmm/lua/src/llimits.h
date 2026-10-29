#ifndef llimits_h
#define llimits_h

#include "lua.h"

#if defined(LUAI_MEM)
typedef LUAI_UMEM lu_mem;
typedef LUAI_MEM l_mem;
#elif LUAI_BITSINT >= 32
typedef size_t lu_mem;
typedef ptrdiff_t l_mem;
#else
typedef unsigned long lu_mem;
typedef long l_mem;
#endif

typedef unsigned char lu_byte;

#define MAX_SIZET	((size_t)(~(size_t)0))

#define MAX_SIZE	(sizeof(size_t) < sizeof(lua_Integer) ? MAX_SIZET \
                          : (size_t)(LUA_MAXINTEGER))

#define MAX_LUMEM	((lu_mem)(~(lu_mem)0))

#define MAX_LMEM	((l_mem)(MAX_LUMEM >> 1))

#define MAX_INT		INT_MAX

#define point2uint(p)	((unsigned int)((size_t)(p) & UINT_MAX))

#if defined(LUAI_USER_ALIGNMENT_T)
typedef LUAI_USER_ALIGNMENT_T L_Umaxalign;
#else
typedef union {
  lua_Number n;
  double u;
  void *s;
  lua_Integer i;
  long l;
} L_Umaxalign;
#endif

typedef LUAI_UACNUMBER l_uacNumber;
typedef LUAI_UACINT l_uacInt;

#if defined(lua_assert)
#define check_exp(c,e)		(lua_assert(c), (e))

#define lua_longassert(c)	((c) ? (void)0 : lua_assert(0))
#else
#define lua_assert(c)		((void)0)
#define check_exp(c,e)		(e)
#define lua_longassert(c)	((void)0)
#endif

#if !defined(luai_apicheck)
#define luai_apicheck(l,e)	lua_assert(e)
#endif

#define api_check(l,e,msg)	luai_apicheck(l,(e) && msg)

#if !defined(UNUSED)
#define UNUSED(x)	((void)(x))
#endif

#define cast(t, exp)	((t)(exp))

#define cast_void(i)	cast(void, (i))
#define cast_byte(i)	cast(lu_byte, (i))
#define cast_num(i)	cast(lua_Number, (i))
#define cast_int(i)	cast(int, (i))
#define cast_uchar(i)	cast(unsigned char, (i))

#if !defined(l_castS2U)
#define l_castS2U(i)	((lua_Unsigned)(i))
#endif

#if !defined(l_castU2S)
#define l_castU2S(i)	((lua_Integer)(i))
#endif

#if defined(__GNUC__)
#define l_noret		void __attribute__((noreturn))
#elif defined(_MSC_VER) && _MSC_VER >= 1200
#define l_noret		void __declspec(noreturn)
#else
#define l_noret		void
#endif

#if !defined(LUAI_MAXCCALLS)
#define LUAI_MAXCCALLS		200
#endif

#if LUAI_BITSINT >= 32
typedef unsigned int Instruction;
#else
typedef unsigned long Instruction;
#endif

#if !defined(LUAI_MAXSHORTLEN)
#define LUAI_MAXSHORTLEN	40
#endif

#if !defined(MINSTRTABSIZE)
#define MINSTRTABSIZE	128
#endif

#if !defined(STRCACHE_N)
#define STRCACHE_N		53
#define STRCACHE_M		2
#endif

#if !defined(LUA_MINBUFFER)
#define LUA_MINBUFFER	32
#endif

#if !defined(lua_lock)
#define lua_lock(L)	((void) 0)
#define lua_unlock(L)	((void) 0)
#endif

#if !defined(luai_threadyield)
#define luai_threadyield(L)	{lua_unlock(L); lua_lock(L);}
#endif

#if !defined(luai_userstateopen)
#define luai_userstateopen(L)		((void)L)
#endif

#if !defined(luai_userstateclose)
#define luai_userstateclose(L)		((void)L)
#endif

#if !defined(luai_userstatethread)
#define luai_userstatethread(L,L1)	((void)L)
#endif

#if !defined(luai_userstatefree)
#define luai_userstatefree(L,L1)	((void)L)
#endif

#if !defined(luai_userstateresume)
#define luai_userstateresume(L,n)	((void)L)
#endif

#if !defined(luai_userstateyield)
#define luai_userstateyield(L,n)	((void)L)
#endif

#if !defined(luai_numidiv)
#define luai_numidiv(L,a,b)     ((void)L, l_floor(luai_numdiv(L,a,b)))
#endif

#if !defined(luai_numdiv)
#define luai_numdiv(L,a,b)      ((a)/(b))
#endif

#if !defined(luai_nummod)
#define luai_nummod(L,a,b,m)  \
  { (m) = l_mathop(fmod)(a,b); if ((m)*(b) < 0) (m) += (b); }
#endif

#if !defined(luai_numpow)
#define luai_numpow(L,a,b)      ((void)L, l_mathop(pow)(a,b))
#endif

#if !defined(luai_numadd)
#define luai_numadd(L,a,b)      ((a)+(b))
#define luai_numsub(L,a,b)      ((a)-(b))
#define luai_nummul(L,a,b)      ((a)*(b))
#define luai_numunm(L,a)        (-(a))
#define luai_numeq(a,b)         ((a)==(b))
#define luai_numlt(a,b)         ((a)<(b))
#define luai_numle(a,b)         ((a)<=(b))
#define luai_numisnan(a)        (!luai_numeq((a), (a)))
#endif

#if !defined(HARDSTACKTESTS)
#define condmovestack(L,pre,pos)	((void)0)
#else

#define condmovestack(L,pre,pos)  \
	{ int sz_ = (L)->stacksize; pre; luaD_reallocstack((L), sz_); pos; }
#endif

#if !defined(HARDMEMTESTS)
#define condchangemem(L,pre,pos)	((void)0)
#else
#define condchangemem(L,pre,pos)  \
	{ if (G(L)->gcrunning) { pre; luaC_fullgc(L, 0); pos; } }
#endif

#endif
