#ifndef luaconf_h
#define luaconf_h

#include <limits.h>
#include <stddef.h>

#if !defined(LUA_USE_C89) && defined(_WIN32) && !defined(_WIN32_WCE)
#define LUA_USE_WINDOWS
#endif

#if defined(LUA_USE_WINDOWS)
#define LUA_DL_DLL
#define LUA_USE_C89
#endif

#if defined(LUA_USE_LINUX)
#define LUA_USE_POSIX
#define LUA_USE_DLOPEN
#define LUA_USE_READLINE
#endif

#if defined(LUA_USE_MACOSX)
#define LUA_USE_POSIX
#define LUA_USE_DLOPEN
#define LUA_USE_READLINE
#endif

#if defined(LUA_USE_C89) && !defined(LUA_USE_WINDOWS)
#define LUA_C89_NUMBERS
#endif

#if ((INT_MAX >> 15) >> 15) >= 1
#define LUAI_BITSINT	32
#else

#define LUAI_BITSINT	16
#endif

#if defined(LUA_32BITS)

#if LUAI_BITSINT >= 32
#define LUA_INT_INT
#else
#define LUA_INT_LONG
#endif
#define LUA_REAL_FLOAT

#elif defined(LUA_C89_NUMBERS)

#define LUA_INT_LONG
#define LUA_REAL_DOUBLE

#else

#define LUA_INT_LONGLONG
#define LUA_REAL_DOUBLE

#endif

#define LUA_VDIR	LUA_VERSION_MAJOR "." LUA_VERSION_MINOR
#if defined(_WIN32)

#define LUA_LDIR	"!\\lua\\"
#define LUA_CDIR	"!\\"
#define LUA_SHRDIR	"!\\..\\share\\lua\\" LUA_VDIR "\\"
#define LUA_PATH_DEFAULT  \
		LUA_LDIR"?.lua;"  LUA_LDIR"?\\init.lua;" \
		LUA_CDIR"?.lua;"  LUA_CDIR"?\\init.lua;" \
		LUA_SHRDIR"?.lua;" LUA_SHRDIR"?\\init.lua;" \
		".\\?.lua;" ".\\?\\init.lua"
#define LUA_CPATH_DEFAULT \
		LUA_CDIR"?.dll;" \
		LUA_CDIR"..\\lib\\lua\\" LUA_VDIR "\\?.dll;" \
		LUA_CDIR"loadall.dll;" ".\\?.dll" \
    LUA_CDIR"?53.dll;" ".\\?53.dll"

#else

#define LUA_ROOT	"/usr/local/"
#define LUA_LDIR	LUA_ROOT "share/lua/" LUA_VDIR "/"
#define LUA_CDIR	LUA_ROOT "lib/lua/" LUA_VDIR "/"
#define LUA_PATH_DEFAULT  \
		LUA_LDIR"?.lua;"  LUA_LDIR"?/init.lua;" \
		LUA_CDIR"?.lua;"  LUA_CDIR"?/init.lua;" \
		"./?.lua;" "./?/init.lua"
#define LUA_CPATH_DEFAULT \
		LUA_CDIR"?.so;" LUA_CDIR"loadall.so;" "./?.so" \
    LUA_CDIR"lib?53.so;" "./lib?53.so"
#endif

#if defined(_WIN32)
#define LUA_DIRSEP	"\\"
#else
#define LUA_DIRSEP	"/"
#endif

#if defined(LUA_BUILD_AS_DLL)

#if defined(LUA_CORE) || defined(LUA_LIB)
#define LUA_API __declspec(dllexport)
#else
#define LUA_API __declspec(dllimport)
#endif

#else

#define LUA_API		extern

#endif

#define LUALIB_API	LUA_API
#define LUAMOD_API	LUALIB_API

#if defined(__GNUC__) && ((__GNUC__*100 + __GNUC_MINOR__) >= 302) && \
    defined(__ELF__)
#define LUAI_FUNC	__attribute__((visibility("hidden"))) extern
#else
#define LUAI_FUNC	extern
#endif

#define LUAI_DDEC	LUAI_FUNC
#define LUAI_DDEF

#if defined(LUA_COMPAT_5_2)

#define LUA_COMPAT_MATHLIB

#define LUA_COMPAT_BITLIB

#define LUA_COMPAT_IPAIRS

#define LUA_COMPAT_APIINTCASTS

#endif

#if defined(LUA_COMPAT_5_1)

#define LUA_COMPAT_UNPACK

#define LUA_COMPAT_LOADERS

#define lua_cpcall(L,f,u)  \
	(lua_pushcfunction(L, (f)), \
	 lua_pushlightuserdata(L,(u)), \
	 lua_pcall(L,1,0,0))

#define LUA_COMPAT_LOG10

#define LUA_COMPAT_LOADSTRING

#define LUA_COMPAT_MAXN

#define lua_strlen(L,i)		lua_rawlen(L, (i))

#define lua_objlen(L,i)		lua_rawlen(L, (i))

#define lua_equal(L,idx1,idx2)		lua_compare(L,(idx1),(idx2),LUA_OPEQ)
#define lua_lessthan(L,idx1,idx2)	lua_compare(L,(idx1),(idx2),LUA_OPLT)

#define LUA_COMPAT_MODULE

#endif

#if defined(LUA_REAL_FLOAT)

#define LUA_NUMBER	float

#define LUAI_UACNUMBER	double

#define LUA_NUMBER_FRMLEN	""
#define LUA_NUMBER_FMT		"%.7g"

#define l_mathop(op)		op##f

#define lua_str2number(s,p)	strtof((s), (p))

#elif defined(LUA_REAL_LONGDOUBLE)

#define LUA_NUMBER	long double

#define LUAI_UACNUMBER	long double

#define LUA_NUMBER_FRMLEN	"L"
#define LUA_NUMBER_FMT		"%.19Lg"

#define l_mathop(op)		op##l

#define lua_str2number(s,p)	strtold((s), (p))

#elif defined(LUA_REAL_DOUBLE)

#define LUA_NUMBER	double

#define LUAI_UACNUMBER	double

#define LUA_NUMBER_FRMLEN	""
#define LUA_NUMBER_FMT		"%.14g"

#define l_mathop(op)		op

#define lua_str2number(s,p)	strtod((s), (p))

#else

#error "numeric real type not defined"

#endif

#define l_floor(x)		(l_mathop(floor)(x))

#define lua_number2str(s,n)	sprintf((s), LUA_NUMBER_FMT, (n))

#define lua_numbertointeger(n,p) \
  ((n) >= (LUA_NUMBER)(LUA_MININTEGER) && \
   (n) < -(LUA_NUMBER)(LUA_MININTEGER) && \
      (*(p) = (LUA_INTEGER)(n), 1))

#if defined(lobject_c) || defined(lvm_c)
#include <math.h>

#define luai_numidiv(L,a,b)	((void)L, l_mathop(floor)(luai_numdiv(L,a,b)))

#define luai_nummod(L,a,b,m)  \
  { (m) = l_mathop(fmod)(a,b); if ((m)*(b) < 0) (m) += (b); }

#define luai_numpow(L,a,b)	((void)L, l_mathop(pow)(a,b))

#endif

#if defined(LUA_CORE)
#define luai_numadd(L,a,b)	((a)+(b))
#define luai_numsub(L,a,b)	((a)-(b))
#define luai_nummul(L,a,b)	((a)*(b))
#define luai_numdiv(L,a,b)	((a)/(b))
#define luai_numunm(L,a)	(-(a))
#define luai_numeq(a,b)		((a)==(b))
#define luai_numlt(a,b)		((a)<(b))
#define luai_numle(a,b)		((a)<=(b))
#define luai_numisnan(a)	(!luai_numeq((a), (a)))
#endif

#define LUA_INTEGER_FMT		"%" LUA_INTEGER_FRMLEN "d"
#define lua_integer2str(s,n)	sprintf((s), LUA_INTEGER_FMT, (n))

#define LUAI_UACINT		LUA_INTEGER

#define LUA_UNSIGNED		unsigned LUAI_UACINT

#if defined(LUA_INT_INT)

#define LUA_INTEGER		int
#define LUA_INTEGER_FRMLEN	""

#define LUA_MAXINTEGER		INT_MAX
#define LUA_MININTEGER		INT_MIN

#elif defined(LUA_INT_LONG)

#define LUA_INTEGER		long
#define LUA_INTEGER_FRMLEN	"l"

#define LUA_MAXINTEGER		LONG_MAX
#define LUA_MININTEGER		LONG_MIN

#elif defined(LUA_INT_LONGLONG)

#if defined(LLONG_MAX)

#define LUA_INTEGER		long long
#define LUA_INTEGER_FRMLEN	"ll"

#define LUA_MAXINTEGER		LLONG_MAX
#define LUA_MININTEGER		LLONG_MIN

#elif defined(LUA_USE_WINDOWS)

#define LUA_INTEGER		__int64
#define LUA_INTEGER_FRMLEN	"I64"

#define LUA_MAXINTEGER		_I64_MAX
#define LUA_MININTEGER		_I64_MIN

#else

#error "Compiler does not support 'long long'. Use option '-DLUA_32BITS' \
  or '-DLUA_C89_NUMBERS' (see file 'luaconf.h' for details)"

#endif

#else

#error "numeric integer type not defined"

#endif

#if !defined(LUA_USE_C89)
#define lua_strx2number(s,p)	lua_str2number(s,p)
#endif

#if !defined(LUA_USE_C89) || defined(LUA_USE_WINDOWS)
#define LUA_USE_AFORMAT
#endif

#if defined(LUA_USE_C89) || (defined(HUGE_VAL) && !defined(HUGE_VALF))
#undef l_mathop
#undef lua_str2number
#define l_mathop(op)		(lua_Number)op
#define lua_str2number(s,p)	((lua_Number)strtod((s), (p)))
#endif

#define LUA_KCONTEXT	ptrdiff_t

#if !defined(LUA_USE_C89) && defined(__STDC_VERSION__) && \
    __STDC_VERSION__ >= 199901L
#include <stdint.h>
#if defined (INTPTR_MAX)
#undef LUA_KCONTEXT
#define LUA_KCONTEXT	intptr_t
#endif
#endif

#if LUAI_BITSINT >= 32
#define LUAI_MAXSTACK		1000000
#else
#define LUAI_MAXSTACK		15000
#endif

#define LUAI_FIRSTPSEUDOIDX	(-LUAI_MAXSTACK - 1000)

#define LUA_EXTRASPACE		(sizeof(void *))

#define LUA_IDSIZE	60

#define LUAI_MAXSHORTLEN        40

#define LUAL_BUFFERSIZE	((int)(0x80 * sizeof(void*) * sizeof(lua_Integer)))

#define LUA_QL(x)	"'" x "'"
#define LUA_QS		LUA_QL("%s")

#endif
