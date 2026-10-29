#ifndef lconfig_h
#define lconfig_h

#include <limits.h>
#include <stddef.h>

#define LUA_BUILD_AS_DLL
#define LNUM_INT64

#define LUA_PATH        "LUA_PATH"
#define LUA_CPATH       "LUA_CPATH"
#define LUA_INIT	"LUA_INIT"

#if defined(_WIN32)

#define LUA_LDIR	"!\\lua\\"
#define LUA_CDIR	"!\\"
#define LUA_PATH_DEFAULT  \
		".\\?.lua;"  LUA_LDIR"?.lua;"  LUA_LDIR"?\\init.lua;" \
		             LUA_CDIR"?.lua;"  LUA_CDIR"?\\init.lua"
#define LUA_CPATH_DEFAULT \
		".\\?.dll;"  LUA_CDIR"?.dll;" LUA_CDIR"loadall.dll;" \
		LUA_CDIR"clibs\\?.dll;" LUA_CDIR"clibs\\loadall.dll;" \
		".\\?51.dll;"  LUA_CDIR"?51.dll;" LUA_CDIR"clibs\\?51.dll"

#else
#define LUA_ROOT	"/usr/local/"
#define LUA_LDIR	LUA_ROOT "share/lua/5.1/"
#define LUA_CDIR	LUA_ROOT "lib/lua/5.1/"
#define LUA_PATH_DEFAULT  \
		"./?.lua;"  LUA_LDIR"?.lua;"  LUA_LDIR"?/init.lua;" \
		            LUA_CDIR"?.lua;"  LUA_CDIR"?/init.lua"
#define LUA_CPATH_DEFAULT \
		"./?.so;"  LUA_CDIR"?.so;" LUA_CDIR"loadall.so" \
		"./lib?51.so;" LUA_CDIR"lib?51.so;"
#endif

#ifdef LNUM_FLOAT
# define LUA_NUMBER         float
# define LUA_NUMBER_SCAN    "%f"
# define LUA_NUMBER_FMT     "%g"
#elif defined(LNUM_LDOUBLE)
# define LUA_NUMBER         long double
# define LUA_NUMBER_SCAN    "%Lg"
# define LUA_NUMBER_FMT     "%.20Lg"
#else
# define LUA_NUMBER	        double
# define LUA_NUMBER_SCAN    "%lf"
# define LUA_NUMBER_FMT     "%.14g"
#endif

#if INT_MAX-20 < 32760
#define LUAI_BITSINT	16
#elif INT_MAX > 2147483640L

#define LUAI_BITSINT	32
#else
#error "you must define LUA_BITSINT with number of bits in an integer"
#endif

#ifdef LNUM_INT64
# define LUA_INTEGER	long long
# ifdef _MSC_VER
#  define lua_str2ul    _strtoui64
# else
#  define lua_str2ul    strtoull
# endif
# define LUA_INTEGER_SCAN "%lld"
# define LUA_INTEGER_FMT "%lld"
# define LUA_INTEGER_MAX 0x7fffffffffffffffLL
# define LUA_INTEGER_MIN (-LUA_INTEGER_MAX - 1LL)

#else
# if LUAI_BITSINT == 32
#  define LUA_INTEGER   int
#  define LUA_INTEGER_SCAN "%d"
#  define LUA_INTEGER_FMT "%d"
# else

#  define LUA_INTEGER   long
#  define LUA_INTEGER_SCAN "%ld"
#  define LUA_INTEGER_FMT "%ld"
# endif
# define LUA_INTEGER_MAX 0x7FFFFFFF
#endif

#ifndef lua_str2ul
# define lua_str2ul (unsigned LUA_INTEGER)strtoul
#endif
#ifndef LUA_INTEGER_MIN
# define LUA_INTEGER_MIN (-LUA_INTEGER_MAX -1)
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

#define LUA_IDSIZE	60

#define LUAL_BUFFERSIZE		BUFSIZ

#undef LUA_COMPAT_GETN

#undef LUA_COMPAT_LOADLIB

#define LUA_COMPAT_VARARG

#define LUA_COMPAT_MOD

#define LUA_COMPAT_LSTR		1

#define LUA_COMPAT_GFIND

#define LUA_COMPAT_OPENLIB

#define LUA_COMPAT_TOINTEGER

#endif
