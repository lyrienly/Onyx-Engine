#ifndef lobject_h
#define lobject_h

#include <stdarg.h>

#include "llimits.h"
#include "lua.h"

#define LUA_TPROTO	LUA_NUMTAGS
#define LUA_TDEADKEY	(LUA_NUMTAGS+1)

#define LUA_TOTALTAGS	(LUA_TPROTO + 2)

#define VARBITS		(3 << 4)

#define LUA_TLCL	(LUA_TFUNCTION | (0 << 4))
#define LUA_TLCF	(LUA_TFUNCTION | (1 << 4))
#define LUA_TCCL	(LUA_TFUNCTION | (2 << 4))

#define LUA_TSHRSTR	(LUA_TSTRING | (0 << 4))
#define LUA_TLNGSTR	(LUA_TSTRING | (1 << 4))

#define LUA_TNUMFLT	(LUA_TNUMBER | (0 << 4))
#define LUA_TNUMINT	(LUA_TNUMBER | (1 << 4))

#define BIT_ISCOLLECTABLE	(1 << 6)

#define ctb(t)			((t) | BIT_ISCOLLECTABLE)

typedef struct GCObject GCObject;

#define CommonHeader	GCObject *next; lu_byte tt; lu_byte marked

struct GCObject {
  CommonHeader;
};

typedef union Value Value;

#define TValuefields	Value value_; int tt_

typedef struct lua_TValue TValue;

#define NILCONSTANT	{NULL}, LUA_TNIL

#define val_(o)		((o)->value_)

#define rttype(o)	((o)->tt_)

#define novariant(x)	((x) & 0x0F)

#define ttype(o)	(rttype(o) & 0x3F)

#define ttnov(o)	(novariant(rttype(o)))

#define checktag(o,t)		(rttype(o) == (t))
#define checktype(o,t)		(ttnov(o) == (t))
#define ttisnumber(o)		checktype((o), LUA_TNUMBER)
#define ttisfloat(o)		checktag((o), LUA_TNUMFLT)
#define ttisinteger(o)		checktag((o), LUA_TNUMINT)
#define ttisnil(o)		checktag((o), LUA_TNIL)
#define ttisboolean(o)		checktag((o), LUA_TBOOLEAN)
#define ttislightuserdata(o)	checktag((o), LUA_TLIGHTUSERDATA)
#define ttisstring(o)		checktype((o), LUA_TSTRING)
#define ttisshrstring(o)	checktag((o), ctb(LUA_TSHRSTR))
#define ttislngstring(o)	checktag((o), ctb(LUA_TLNGSTR))
#define ttistable(o)		checktag((o), ctb(LUA_TTABLE))
#define ttisfunction(o)		checktype(o, LUA_TFUNCTION)
#define ttisclosure(o)		((rttype(o) & 0x1F) == LUA_TFUNCTION)
#define ttisCclosure(o)		checktag((o), ctb(LUA_TCCL))
#define ttisLclosure(o)		checktag((o), ctb(LUA_TLCL))
#define ttislcf(o)		checktag((o), LUA_TLCF)
#define ttisfulluserdata(o)	checktag((o), ctb(LUA_TUSERDATA))
#define ttisthread(o)		checktag((o), ctb(LUA_TTHREAD))
#define ttisdeadkey(o)		checktag((o), LUA_TDEADKEY)

#define ivalue(o)	check_exp(ttisinteger(o), val_(o).i)
#define fltvalue(o)	check_exp(ttisfloat(o), val_(o).n)
#define nvalue(o)	check_exp(ttisnumber(o), \
	(ttisinteger(o) ? cast_num(ivalue(o)) : fltvalue(o)))
#define gcvalue(o)	check_exp(iscollectable(o), val_(o).gc)
#define pvalue(o)	check_exp(ttislightuserdata(o), val_(o).p)
#define tsvalue(o)	check_exp(ttisstring(o), gco2ts(val_(o).gc))
#define uvalue(o)	check_exp(ttisfulluserdata(o), gco2u(val_(o).gc))
#define clvalue(o)	check_exp(ttisclosure(o), gco2cl(val_(o).gc))
#define clLvalue(o)	check_exp(ttisLclosure(o), gco2lcl(val_(o).gc))
#define clCvalue(o)	check_exp(ttisCclosure(o), gco2ccl(val_(o).gc))
#define fvalue(o)	check_exp(ttislcf(o), val_(o).f)
#define hvalue(o)	check_exp(ttistable(o), gco2t(val_(o).gc))
#define bvalue(o)	check_exp(ttisboolean(o), val_(o).b)
#define thvalue(o)	check_exp(ttisthread(o), gco2th(val_(o).gc))

#define deadvalue(o)	check_exp(ttisdeadkey(o), cast(void *, val_(o).gc))

#define l_isfalse(o)	(ttisnil(o) || (ttisboolean(o) && bvalue(o) == 0))

#define iscollectable(o)	(rttype(o) & BIT_ISCOLLECTABLE)

#define righttt(obj)		(ttype(obj) == gcvalue(obj)->tt)

#define checkliveness(g,obj) \
	lua_longassert(!iscollectable(obj) || \
			(righttt(obj) && !isdead(g,gcvalue(obj))))

#define settt_(o,t)	((o)->tt_=(t))

#define setfltvalue(obj,x) \
  { TValue *io=(obj); val_(io).n=(x); settt_(io, LUA_TNUMFLT); }

#define setivalue(obj,x) \
  { TValue *io=(obj); val_(io).i=(x); settt_(io, LUA_TNUMINT); }

#define setnilvalue(obj) settt_(obj, LUA_TNIL)

#define setfvalue(obj,x) \
  { TValue *io=(obj); val_(io).f=(x); settt_(io, LUA_TLCF); }

#define setpvalue(obj,x) \
  { TValue *io=(obj); val_(io).p=(x); settt_(io, LUA_TLIGHTUSERDATA); }

#define setbvalue(obj,x) \
  { TValue *io=(obj); val_(io).b=(x); settt_(io, LUA_TBOOLEAN); }

#define setgcovalue(L,obj,x) \
  { TValue *io = (obj); GCObject *i_g=(x); \
    val_(io).gc = i_g; settt_(io, ctb(i_g->tt)); }

#define setsvalue(L,obj,x) \
  { TValue *io = (obj); TString *x_ = (x); \
    val_(io).gc = obj2gco(x_); settt_(io, ctb(x_->tt)); \
    checkliveness(G(L),io); }

#define setuvalue(L,obj,x) \
  { TValue *io = (obj); Udata *x_ = (x); \
    val_(io).gc = obj2gco(x_); settt_(io, ctb(LUA_TUSERDATA)); \
    checkliveness(G(L),io); }

#define setthvalue(L,obj,x) \
  { TValue *io = (obj); lua_State *x_ = (x); \
    val_(io).gc = obj2gco(x_); settt_(io, ctb(LUA_TTHREAD)); \
    checkliveness(G(L),io); }

#define setclLvalue(L,obj,x) \
  { TValue *io = (obj); LClosure *x_ = (x); \
    val_(io).gc = obj2gco(x_); settt_(io, ctb(LUA_TLCL)); \
    checkliveness(G(L),io); }

#define setclCvalue(L,obj,x) \
  { TValue *io = (obj); CClosure *x_ = (x); \
    val_(io).gc = obj2gco(x_); settt_(io, ctb(LUA_TCCL)); \
    checkliveness(G(L),io); }

#define sethvalue(L,obj,x) \
  { TValue *io = (obj); Table *x_ = (x); \
    val_(io).gc = obj2gco(x_); settt_(io, ctb(LUA_TTABLE)); \
    checkliveness(G(L),io); }

#define setdeadvalue(obj)	settt_(obj, LUA_TDEADKEY)

#define setobj(L,obj1,obj2) \
	{ TValue *io1=(obj1); *io1 = *(obj2); \
	  (void)L; checkliveness(G(L),io1); }

#define setobjs2s	setobj

#define setobj2s	setobj
#define setsvalue2s	setsvalue
#define sethvalue2s	sethvalue
#define setptvalue2s	setptvalue

#define setobjt2t	setobj

#define setobj2t	setobj

#define setobj2n	setobj
#define setsvalue2n	setsvalue

union Value {
  GCObject *gc;
  void *p;
  int b;
  lua_CFunction f;
  lua_Integer i;
  lua_Number n;
};

struct lua_TValue {
  TValuefields;
};

typedef TValue *StkId;

typedef struct TString {
  CommonHeader;
  lu_byte extra;
  unsigned int hash;
  size_t len;
  struct TString *hnext;
} TString;

typedef union UTString {
  L_Umaxalign dummy;
  TString tsv;
} UTString;

#define getaddrstr(ts)	(cast(char *, (ts)) + sizeof(UTString))
#define getstr(ts)  \
  check_exp(sizeof((ts)->extra), cast(const char*, getaddrstr(ts)))

#define svalue(o)       getstr(tsvalue(o))

typedef struct Udata {
  CommonHeader;
  lu_byte ttuv_;
  struct Table *metatable;
  size_t len;
  union Value user_;
} Udata;

typedef union UUdata {
  L_Umaxalign dummy;
  Udata uv;
} UUdata;

#define getudatamem(u)  \
  check_exp(sizeof((u)->ttuv_), (cast(char*, (u)) + sizeof(UUdata)))

#define setuservalue(L,u,o) \
	{ const TValue *io=(o); Udata *iu = (u); \
	  iu->user_ = io->value_; iu->ttuv_ = io->tt_; \
	  checkliveness(G(L),io); }

#define getuservalue(L,u,o) \
	{ TValue *io=(o); const Udata *iu = (u); \
	  io->value_ = iu->user_; io->tt_ = iu->ttuv_; \
	  checkliveness(G(L),io); }

typedef struct Upvaldesc {
  TString *name;
  lu_byte instack;
  lu_byte idx;
} Upvaldesc;

typedef struct LocVar {
  TString *varname;
  int startpc;
  int endpc;
} LocVar;

typedef struct Proto {
  CommonHeader;
  lu_byte numparams;
  lu_byte is_vararg;
  lu_byte maxstacksize;
  int sizeupvalues;
  int sizek;
  int sizecode;
  int sizelineinfo;
  int sizep;
  int sizelocvars;
  int linedefined;
  int lastlinedefined;
  TValue *k;
  Instruction *code;
  struct Proto **p;
  int *lineinfo;
  LocVar *locvars;
  Upvaldesc *upvalues;
  struct LClosure *cache;
  TString  *source;
  GCObject *gclist;
} Proto;

typedef struct UpVal UpVal;

#define ClosureHeader \
	CommonHeader; lu_byte nupvalues; GCObject *gclist

typedef struct CClosure {
  ClosureHeader;
  lua_CFunction f;
  TValue upvalue[1];
} CClosure;

typedef struct LClosure {
  ClosureHeader;
  struct Proto *p;
  UpVal *upvals[1];
} LClosure;

typedef union Closure {
  CClosure c;
  LClosure l;
} Closure;

#define isLfunction(o)	ttisLclosure(o)

#define getproto(o)	(clLvalue(o)->p)

typedef union TKey {
  struct {
    TValuefields;
    int next;
  } nk;
  TValue tvk;
} TKey;

#define setnodekey(L,key,obj) \
	{ TKey *k_=(key); const TValue *io_=(obj); \
	  k_->nk.value_ = io_->value_; k_->nk.tt_ = io_->tt_; \
	  (void)L; checkliveness(G(L),io_); }

typedef struct Node {
  TValue i_val;
  TKey i_key;
} Node;

typedef struct Table {
  CommonHeader;
  lu_byte flags;
  lu_byte lsizenode;
  unsigned int sizearray;
  TValue *array;
  Node *node;
  Node *lastfree;
  struct Table *metatable;
  GCObject *gclist;
} Table;

#define lmod(s,size) \
	(check_exp((size&(size-1))==0, (cast(int, (s) & ((size)-1)))))

#define twoto(x)	(1<<(x))
#define sizenode(t)	(twoto((t)->lsizenode))

#define luaO_nilobject		(&luaO_nilobject_)

LUAI_DDEC const TValue luaO_nilobject_;

#define UTF8BUFFSZ	8

LUAI_FUNC int luaO_int2fb (unsigned int x);
LUAI_FUNC int luaO_fb2int (int x);
LUAI_FUNC int luaO_utf8esc (char *buff, unsigned long x);
LUAI_FUNC int luaO_ceillog2 (unsigned int x);
LUAI_FUNC void luaO_arith (lua_State *L, int op, const TValue *p1,
                           const TValue *p2, TValue *res);
LUAI_FUNC size_t luaO_str2num (const char *s, TValue *o);
LUAI_FUNC int luaO_hexavalue (int c);
LUAI_FUNC void luaO_tostring (lua_State *L, StkId obj);
LUAI_FUNC const char *luaO_pushvfstring (lua_State *L, const char *fmt,
                                                       va_list argp);
LUAI_FUNC const char *luaO_pushfstring (lua_State *L, const char *fmt, ...);
LUAI_FUNC void luaO_chunkid (char *out, const char *source, size_t len);

#endif
