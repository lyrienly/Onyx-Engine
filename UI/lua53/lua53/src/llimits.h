#ifndef llimits_h
#define llimits_h

#include <limits.h>
#include <stddef.h>

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

#define point2int(p)	((unsigned int)((size_t)(p) & UINT_MAX))

#if defined(LUAI_USER_ALIGNMENT_T)
typedef LUAI_USER_ALIGNMENT_T L_Umaxalign;
#else
typedef union { double u; void *s; lua_Integer i; long l; } L_Umaxalign;
#endif

typedef LUAI_UACNUMBER l_uacNumber;
typedef LUAI_UACINT l_uacInt;

#if defined(lua_assert)
#define check_exp(c,e)		(lua_assert(c), (e))

#define lua_longassert(c)	{ if (!(c)) lua_assert(0); }
#else
#define lua_assert(c)		((void)0)
#define check_exp(c,e)		(e)
#define lua_longassert(c)	((void)0)
#endif

#if defined(LUA_USE_APICHECK)
#include <assert.h>
#define luai_apicheck(e)	assert(e)
#else
#define luai_apicheck(e)	lua_assert(e)
#endif

#define api_check(e,msg)	luai_apicheck((e) && msg)

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

#define MAXUPVAL	UCHAR_MAX

#if LUAI_BITSINT >= 32
typedef unsigned int Instruction;
#else
typedef unsigned long Instruction;
#endif

#if !defined(MINSTRTABSIZE)
#define MINSTRTABSIZE	64
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

#if !defined(HARDSTACKTESTS)
#define condmovestack(L)	((void)0)
#else

#define condmovestack(L)	luaD_reallocstack((L), (L)->stacksize)
#endif

#if !defined(HARDMEMTESTS)
#define condchangemem(L)	condmovestack(L)
#else
#define condchangemem(L)  \
	((void)(!(G(L)->gcrunning) || (luaC_fullgc(L, 0), 1)))
#endif

#endif
