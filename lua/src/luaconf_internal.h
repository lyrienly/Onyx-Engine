#ifndef lconfig_internal_h
#define lconfig_internal_h

#ifdef lua_assert
# include <assert.h>
#endif

#if defined(__STRICT_ANSI__)
#define LUA_ANSI
#endif

#if !defined(LUA_ANSI) && defined(_WIN32)
#define LUA_WIN
#endif

#if defined(LUA_USE_LINUX)
#define LUA_USE_POSIX
#define LUA_USE_DLOPEN
#define LUA_USE_READLINE
#endif

#if defined(LUA_USE_MACOSX)
#define LUA_USE_POSIX
#define LUA_DL_DYLD
#endif

#if defined(LUA_USE_POSIX)
#define LUA_USE_MKSTEMP
#define LUA_USE_ISATTY
#define LUA_USE_POPEN
#define LUA_USE_ULONGJMP
#endif

#if defined(_WIN32)
#define LUA_DIRSEP	"\\"
#else
#define LUA_DIRSEP	"/"
#endif

#define LUA_PATHSEP	";"
#define LUA_PATH_MARK	"?"
#define LUA_EXECDIR	"!"
#define LUA_IGMARK	"-"

#if (!defined LNUM_DOUBLE) && (!defined LNUM_FLOAT) && (!defined LNUM_LDOUBLE)
# define LNUM_DOUBLE
#endif

#if defined(LNUM_COMPLEX) && (__STDC_VERSION__ < 199901L)
# error "Need C99 for complex (use '--std=c99' or similar)"
#elif defined(LNUM_LDOUBLE) && (__STDC_VERSION__ < 199901L) && !defined(_MSC_VER)
# error "Need C99 for 'long double' (use '--std=c99' or similar)"
#elif defined(LNUM_FLOAT) && (__STDC_VERSION__ < 199901L)

# error "Need C99 for 'float' (use '--std=c99' or similar)"
#endif

#if defined(LNUM_COMPLEX) && !(defined(LNUM_INT32) || defined(LNUM_INT64))
# error "LNUM_COMPLEX needs to be used together with LNUM_INTxx"
#endif

#ifdef LNUM_COMPLEX
# define _LNUM1 "complex "
#else
# define _LNUM1 ""
#endif
#ifdef LNUM_DOUBLE
# define _LNUM2 "double"
#elif defined(LNUM_FLOAT)
# define _LNUM2 "float"
#elif defined(LNUM_LDOUBLE)
# define _LNUM2 "ldouble"
#endif
#ifdef LNUM_INT32
# define _LNUM3 " int32"
#elif defined(LNUM_INT64)
# define _LNUM3 " int64"
#else
# define _LNUM3 ""
#endif
#ifdef __FAST_MATH__
# define _LNUM4 "fastmath"
#else
# define _LNUM4 ""
#endif
#define LUA_LNUM _LNUM1 _LNUM2 _LNUM3 _LNUM4

#ifdef LNUM_LDOUBLE
# define _LUAI_MN2S 44
#else
# define _LUAI_MN2S 24
#endif

#ifdef LNUM_COMPLEX
# define LUAI_MAXNUMBER2STR (2*_LUAI_MN2S)
#else
# define LUAI_MAXNUMBER2STR _LUAI_MN2S
#endif

#if defined(LNUM_DOUBLE) && !defined(LUA_ANSI) && !defined(__SSE2__) && \
    (defined(__i386) || defined (_M_IX86) || defined(__i386__))

# if defined(_MSC_VER)
#  define lua_number2int(i,d)   __asm fld d   __asm fistp i
# else

union luai_Cast { double l_d; long l_l; };
#  define lua_number2int(i,d) \
  { volatile union luai_Cast u; u.l_d = (d) + 6755399441055744.0; (i) = u.l_l; }
# endif

# ifndef LNUM_INT64
#  define lua_number2integer    lua_number2int
# endif

#else
# define lua_number2int(i,d)        ((i)=(int)(d))
#endif

#ifndef lua_number2integer
# define lua_number2integer(i,d)    ((i)=(lua_Integer)(d))
#endif

#ifdef LNUM_INT64
# if (__STDC_VERSION__ >= 199901L)
#  define luai_abs llabs
# else
#  define luai_abs(v) ((v) >= 0 ? (v) : -(v))
# endif
#else
# define luai_abs abs
#endif

#define LUAI_UACNUMBER	double
#define LUAI_UACINTEGER long

#ifdef LNUM_DOUBLE
# define _LF(name) name
#elif defined(LNUM_FLOAT)
# define _LF(name) name ## f
#elif defined(LNUM_LDOUBLE)
# define _LF(name) name ## l
#endif

#if defined(luaall_c)
#define LUAI_FUNC	static
#define LUAI_DATA

#elif defined(__GNUC__) && ((__GNUC__*100 + __GNUC_MINOR__) >= 302) && \
      defined(__ELF__)
#define LUAI_FUNC	__attribute__((visibility("hidden"))) extern
#define LUAI_DATA	LUAI_FUNC

#else
#define LUAI_FUNC	extern
#define LUAI_DATA	extern
#endif

#define LUA_QL(x)	"'" x "'"
#define LUA_QS		LUA_QL("%s")

#if defined(lua_c) || defined(luaall_c)

#if defined(LUA_USE_ISATTY)
#include <unistd.h>
#define lua_stdin_is_tty()	isatty(0)
#elif defined(LUA_WIN)
#include <io.h>
#include <stdio.h>
#define lua_stdin_is_tty()	_isatty(_fileno(stdin))
#else
#define lua_stdin_is_tty()	1
#endif

#define LUA_PROMPT		"> "
#define LUA_PROMPT2		">> "

#define LUA_PROGNAME		"lua"

#define LUA_MAXINPUT	512

#if defined(LUA_USE_READLINE)
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#define lua_readline(L,b,p)	((void)L, ((b)=readline(p)) != NULL)
#define lua_saveline(L,idx) \
	if (lua_strlen(L,idx) > 0)   \
	  add_history(lua_tostring(L, idx));
#define lua_freeline(L,b)	((void)L, free(b))
#else
#define lua_readline(L,b,p)	\
	((void)L, fputs(p, stdout), fflush(stdout),   \
	fgets(b, LUA_MAXINPUT, stdin) != NULL)
#define lua_saveline(L,idx)	{ (void)L; (void)idx; }
#define lua_freeline(L,b)	{ (void)L; (void)b; }
#endif

#endif

#define LUAI_GCPAUSE	200

#define LUAI_GCMUL	200

#if defined(LUA_USE_APICHECK)
#include <assert.h>
#define luai_apicheck(L,o)	{ (void)L; assert(o); }
#else
#define luai_apicheck(L,o)	{ (void)L; }
#endif

#if LUAI_BITSINT >= 32
#define LUAI_UINT32	unsigned int
#define LUAI_INT32	int
#define LUAI_MAXINT32	INT_MAX
#define LUAI_UMEM	size_t
#define LUAI_MEM	ptrdiff_t
#else

#define LUAI_UINT32	unsigned long
#define LUAI_INT32	long
#define LUAI_MAXINT32	LONG_MAX
#define LUAI_UMEM	unsigned long
#define LUAI_MEM	long
#endif

#define LUAI_MAXCALLS	20000

#define LUAI_MAXCSTACK	8000

#define LUAI_MAXCCALLS		200

#define LUAI_MAXVARS		200

#define LUAI_MAXUPVALUES	60

#define LUAI_USER_ALIGNMENT_T	union { LUA_NUMBER u; void *s; long l; }

#if defined(__cplusplus)

#define LUAI_THROW(L,c)	throw(c)
#define LUAI_TRY(L,c,a)	try { a } catch(...) \
	{ if ((c)->status == 0) (c)->status = -1; }
#define luai_jmpbuf	int

#elif defined(LUA_USE_ULONGJMP)

#define LUAI_THROW(L,c)	_longjmp((c)->b, 1)
#define LUAI_TRY(L,c,a)	if (_setjmp((c)->b) == 0) { a }
#define luai_jmpbuf	jmp_buf

#else

#define LUAI_THROW(L,c)	longjmp((c)->b, 1)
#define LUAI_TRY(L,c,a)	if (setjmp((c)->b) == 0) { a }
#define luai_jmpbuf	jmp_buf

#endif

#define LUA_MAXCAPTURES		32

#if defined(loslib_c) || defined(luaall_c)

#if defined(LUA_USE_MKSTEMP)
#include <unistd.h>
#define LUA_TMPNAMBUFSIZE	32
#define lua_tmpnam(b,e)	{ \
	strcpy(b, "/tmp/lua_XXXXXX"); \
	e = mkstemp(b); \
	if (e != -1) close(e); \
	e = (e == -1); }

#else
#define LUA_TMPNAMBUFSIZE	L_tmpnam
#define lua_tmpnam(b,e)		{ e = (tmpnam(b) == NULL); }
#endif

#endif

#if defined(LUA_USE_POPEN)

#define lua_popen(L,c,m)	((void)L, fflush(NULL), popen(c,m))
#define lua_pclose(L,file)	((void)L, (pclose(file) != -1))

#elif defined(LUA_WIN)

#define lua_popen(L,c,m)	((void)L, _popen(c,m))
#define lua_pclose(L,file)	((void)L, (_pclose(file) != -1))

#else

#define lua_popen(L,c,m)	((void)((void)c, m),  \
		luaL_error(L, LUA_QL("popen") " not supported"), (FILE*)0)
#define lua_pclose(L,file)		((void)((void)L, file), 0)

#endif

#if defined(LUA_USE_DLOPEN)
#define LUA_DL_DLOPEN
#endif

#if defined(LUA_WIN)
#define LUA_DL_DLL
#endif

#define LUAI_EXTRASPACE		0

#define luai_userstateopen(L)		((void)L)
#define luai_userstateclose(L)		((void)L)
#define luai_userstatethread(L,L1)	((void)L)
#define luai_userstatefree(L)		((void)L)
#define luai_userstateresume(L,n)	((void)L)
#define luai_userstateyield(L,n)	((void)L)

#endif
