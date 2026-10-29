#define ltable_c
#define LUA_CORE

#include "lprefix.h"

#include <float.h>
#include <math.h>
#include <string.h>
#include <limits.h>

#include "lua.h"

#include "ldebug.h"
#include "ldo.h"
#include "lgc.h"
#include "lmem.h"
#include "lobject.h"
#include "lstate.h"
#include "lstring.h"
#include "ltable.h"
#include "lvm.h"

#define MAXABITS	cast_int(sizeof(int) * CHAR_BIT - 1)
#define MAXASIZE	(1u << MAXABITS)

#define MAXHBITS	(MAXABITS - 1)

#define hashpow2(t,n)		(gnode(t, lmod((n), sizenode(t))))

#define hashstr(t,str)		hashpow2(t, (str)->hash)
#define hashboolean(t,p)	hashpow2(t, p)
#define hashint(t,i)		hashpow2(t, i)

#define hashmod(t,n)	(gnode(t, ((n) % ((sizenode(t)-1)|1))))

#define hashpointer(t,p)	hashmod(t, point2int(p))

#define dummynode		(&dummynode_)

#define isdummy(n)		((n) == dummynode)

static const Node dummynode_ = {
  {NILCONSTANT},
  {{NILCONSTANT, 0}}
};

static int numisinteger (lua_Number x, lua_Integer *p) {
  if ((x) == l_floor(x))
    return lua_numbertointeger(x, p);
  else return 0;
}

static Node *hashfloat (const Table *t, lua_Number n) {
  int i;
  n = l_mathop(frexp)(n, &i) * cast_num(INT_MAX - DBL_MAX_EXP);
  i += cast_int(n);
  if (i < 0) {
    if (cast(unsigned int, i) == 0u - i)
      i = 0;
    i = -i;
  }
  return hashmod(t, i);
}

static Node *mainposition (const Table *t, const TValue *key) {
  switch (ttype(key)) {
    case LUA_TNUMINT:
      return hashint(t, ivalue(key));
    case LUA_TNUMFLT:
      return hashfloat(t, fltvalue(key));
    case LUA_TSHRSTR:
      return hashstr(t, tsvalue(key));
    case LUA_TLNGSTR: {
      TString *s = tsvalue(key);
      if (s->extra == 0) {
        s->hash = luaS_hash(getstr(s), s->len, s->hash);
        s->extra = 1;
      }
      return hashstr(t, tsvalue(key));
    }
    case LUA_TBOOLEAN:
      return hashboolean(t, bvalue(key));
    case LUA_TLIGHTUSERDATA:
      return hashpointer(t, pvalue(key));
    case LUA_TLCF:
      return hashpointer(t, fvalue(key));
    default:
      return hashpointer(t, gcvalue(key));
  }
}

static unsigned int arrayindex (const TValue *key) {
  if (ttisinteger(key)) {
    lua_Integer k = ivalue(key);
    if (0 < k && (lua_Unsigned)k <= MAXASIZE)
      return cast(unsigned int, k);
  }
  return 0;
}

static unsigned int findindex (lua_State *L, Table *t, StkId key) {
  unsigned int i;
  if (ttisnil(key)) return 0;
  i = arrayindex(key);
  if (i != 0 && i <= t->sizearray)
    return i;
  else {
    int nx;
    Node *n = mainposition(t, key);
    for (;;) {

      if (luaV_rawequalobj(gkey(n), key) ||
            (ttisdeadkey(gkey(n)) && iscollectable(key) &&
             deadvalue(gkey(n)) == gcvalue(key))) {
        i = cast_int(n - gnode(t, 0));

        return (i + 1) + t->sizearray;
      }
      nx = gnext(n);
      if (nx == 0)
        luaG_runerror(L, "invalid key to 'next'");
      else n += nx;
    }
  }
}

int luaH_next (lua_State *L, Table *t, StkId key) {
  unsigned int i = findindex(L, t, key);
  for (; i < t->sizearray; i++) {
    if (!ttisnil(&t->array[i])) {
      setivalue(key, i + 1);
      setobj2s(L, key+1, &t->array[i]);
      return 1;
    }
  }
  for (i -= t->sizearray; cast_int(i) < sizenode(t); i++) {
    if (!ttisnil(gval(gnode(t, i)))) {
      setobj2s(L, key, gkey(gnode(t, i)));
      setobj2s(L, key+1, gval(gnode(t, i)));
      return 1;
    }
  }
  return 0;
}

static unsigned int computesizes (unsigned int nums[], unsigned int *narray) {
  int i;
  unsigned int twotoi;
  unsigned int a = 0;
  unsigned int na = 0;
  unsigned int n = 0;
  for (i = 0, twotoi = 1; twotoi/2 < *narray; i++, twotoi *= 2) {
    if (nums[i] > 0) {
      a += nums[i];
      if (a > twotoi/2) {
        n = twotoi;
        na = a;
      }
    }
    if (a == *narray) break;
  }
  *narray = n;
  lua_assert(*narray/2 <= na && na <= *narray);
  return na;
}

static int countint (const TValue *key, unsigned int *nums) {
  unsigned int k = arrayindex(key);
  if (k != 0) {
    nums[luaO_ceillog2(k)]++;
    return 1;
  }
  else
    return 0;
}

static unsigned int numusearray (const Table *t, unsigned int *nums) {
  int lg;
  unsigned int ttlg;
  unsigned int ause = 0;
  unsigned int i = 1;

  for (lg = 0, ttlg = 1; lg <= MAXABITS; lg++, ttlg *= 2) {
    unsigned int lc = 0;
    unsigned int lim = ttlg;
    if (lim > t->sizearray) {
      lim = t->sizearray;
      if (i > lim)
        break;
    }

    for (; i <= lim; i++) {
      if (!ttisnil(&t->array[i-1]))
        lc++;
    }
    nums[lg] += lc;
    ause += lc;
  }
  return ause;
}

static int numusehash (const Table *t, unsigned int *nums,
                       unsigned int *pnasize) {
  int totaluse = 0;
  int ause = 0;
  int i = sizenode(t);
  while (i--) {
    Node *n = &t->node[i];
    if (!ttisnil(gval(n))) {
      ause += countint(gkey(n), nums);
      totaluse++;
    }
  }
  *pnasize += ause;
  return totaluse;
}

static void setarrayvector (lua_State *L, Table *t, unsigned int size) {
  unsigned int i;
  luaM_reallocvector(L, t->array, t->sizearray, size, TValue);
  for (i=t->sizearray; i<size; i++)
     setnilvalue(&t->array[i]);
  t->sizearray = size;
}

static void setnodevector (lua_State *L, Table *t, unsigned int size) {
  int lsize;
  if (size == 0) {
    t->node = cast(Node *, dummynode);
    lsize = 0;
  }
  else {
    int i;
    lsize = luaO_ceillog2(size);
    if (lsize > MAXHBITS)
      luaG_runerror(L, "table overflow");
    size = twoto(lsize);
    t->node = luaM_newvector(L, size, Node);
    for (i = 0; i < (int)size; i++) {
      Node *n = gnode(t, i);
      gnext(n) = 0;
      setnilvalue(wgkey(n));
      setnilvalue(gval(n));
    }
  }
  t->lsizenode = cast_byte(lsize);
  t->lastfree = gnode(t, size);
}

void luaH_resize (lua_State *L, Table *t, unsigned int nasize,
                                          unsigned int nhsize) {
  unsigned int i;
  int j;
  unsigned int oldasize = t->sizearray;
  int oldhsize = t->lsizenode;
  Node *nold = t->node;
  if (nasize > oldasize)
    setarrayvector(L, t, nasize);

  setnodevector(L, t, nhsize);
  if (nasize < oldasize) {
    t->sizearray = nasize;

    for (i=nasize; i<oldasize; i++) {
      if (!ttisnil(&t->array[i]))
        luaH_setint(L, t, i + 1, &t->array[i]);
    }

    luaM_reallocvector(L, t->array, oldasize, nasize, TValue);
  }

  for (j = twoto(oldhsize) - 1; j >= 0; j--) {
    Node *old = nold + j;
    if (!ttisnil(gval(old))) {

      setobjt2t(L, luaH_set(L, t, gkey(old)), gval(old));
    }
  }
  if (!isdummy(nold))
    luaM_freearray(L, nold, cast(size_t, twoto(oldhsize)));
}

void luaH_resizearray (lua_State *L, Table *t, unsigned int nasize) {
  int nsize = isdummy(t->node) ? 0 : sizenode(t);
  luaH_resize(L, t, nasize, nsize);
}

static void rehash (lua_State *L, Table *t, const TValue *ek) {
  unsigned int nasize, na;
  unsigned int nums[MAXABITS + 1];
  int i;
  int totaluse;
  for (i = 0; i <= MAXABITS; i++) nums[i] = 0;
  nasize = numusearray(t, nums);
  totaluse = nasize;
  totaluse += numusehash(t, nums, &nasize);

  nasize += countint(ek, nums);
  totaluse++;

  na = computesizes(nums, &nasize);

  luaH_resize(L, t, nasize, totaluse - na);
}

Table *luaH_new (lua_State *L) {
  GCObject *o = luaC_newobj(L, LUA_TTABLE, sizeof(Table));
  Table *t = gco2t(o);
  t->metatable = NULL;
  t->flags = cast_byte(~0);
  t->array = NULL;
  t->sizearray = 0;
  setnodevector(L, t, 0);
  return t;
}

void luaH_free (lua_State *L, Table *t) {
  if (!isdummy(t->node))
    luaM_freearray(L, t->node, cast(size_t, sizenode(t)));
  luaM_freearray(L, t->array, t->sizearray);
  luaM_free(L, t);
}

static Node *getfreepos (Table *t) {
  while (t->lastfree > t->node) {
    t->lastfree--;
    if (ttisnil(gkey(t->lastfree)))
      return t->lastfree;
  }
  return NULL;
}

TValue *luaH_newkey (lua_State *L, Table *t, const TValue *key) {
  Node *mp;
  TValue aux;
  if (ttisnil(key)) luaG_runerror(L, "table index is nil");
  else if (ttisfloat(key)) {
    lua_Number n = fltvalue(key);
    lua_Integer k;
    if (luai_numisnan(n))
      luaG_runerror(L, "table index is NaN");
    if (numisinteger(n, &k)) {
      setivalue(&aux, k);
      key = &aux;
    }
  }
  mp = mainposition(t, key);
  if (!ttisnil(gval(mp)) || isdummy(mp)) {
    Node *othern;
    Node *f = getfreepos(t);
    if (f == NULL) {
      rehash(L, t, key);

      return luaH_set(L, t, key);
    }
    lua_assert(!isdummy(f));
    othern = mainposition(t, gkey(mp));
    if (othern != mp) {

      while (othern + gnext(othern) != mp)
        othern += gnext(othern);
      gnext(othern) = cast_int(f - othern);
      *f = *mp;
      if (gnext(mp) != 0) {
        gnext(f) += cast_int(mp - f);
        gnext(mp) = 0;
      }
      setnilvalue(gval(mp));
    }
    else {

      if (gnext(mp) != 0)
        gnext(f) = cast_int((mp + gnext(mp)) - f);
      else lua_assert(gnext(f) == 0);
      gnext(mp) = cast_int(f - mp);
      mp = f;
    }
  }
  setnodekey(L, &mp->i_key, key);
  luaC_barrierback(L, t, key);
  lua_assert(ttisnil(gval(mp)));
  return gval(mp);
}

const TValue *luaH_getint (Table *t, lua_Integer key) {

  if (l_castS2U(key - 1) < t->sizearray)
    return &t->array[key - 1];
  else {
    Node *n = hashint(t, key);
    for (;;) {
      if (ttisinteger(gkey(n)) && ivalue(gkey(n)) == key)
        return gval(n);
      else {
        int nx = gnext(n);
        if (nx == 0) break;
        n += nx;
      }
    };
    return luaO_nilobject;
  }
}

const TValue *luaH_getstr (Table *t, TString *key) {
  Node *n = hashstr(t, key);
  lua_assert(key->tt == LUA_TSHRSTR);
  for (;;) {
    const TValue *k = gkey(n);
    if (ttisshrstring(k) && eqshrstr(tsvalue(k), key))
      return gval(n);
    else {
      int nx = gnext(n);
      if (nx == 0) break;
      n += nx;
    }
  };
  return luaO_nilobject;
}

const TValue *luaH_get (Table *t, const TValue *key) {
  switch (ttype(key)) {
    case LUA_TSHRSTR: return luaH_getstr(t, tsvalue(key));
    case LUA_TNUMINT: return luaH_getint(t, ivalue(key));
    case LUA_TNIL: return luaO_nilobject;
    case LUA_TNUMFLT: {
      lua_Integer k;
      if (numisinteger(fltvalue(key), &k))
        return luaH_getint(t, k);

    }
    default: {
      Node *n = mainposition(t, key);
      for (;;) {
        if (luaV_rawequalobj(gkey(n), key))
          return gval(n);
        else {
          int nx = gnext(n);
          if (nx == 0) break;
          n += nx;
        }
      };
      return luaO_nilobject;
    }
  }
}

TValue *luaH_set (lua_State *L, Table *t, const TValue *key) {
  const TValue *p = luaH_get(t, key);
  if (p != luaO_nilobject)
    return cast(TValue *, p);
  else return luaH_newkey(L, t, key);
}

void luaH_setint (lua_State *L, Table *t, lua_Integer key, TValue *value) {
  const TValue *p = luaH_getint(t, key);
  TValue *cell;
  if (p != luaO_nilobject)
    cell = cast(TValue *, p);
  else {
    TValue k;
    setivalue(&k, key);
    cell = luaH_newkey(L, t, &k);
  }
  setobj2t(L, cell, value);
}

static int unbound_search (Table *t, unsigned int j) {
  unsigned int i = j;
  j++;

  while (!ttisnil(luaH_getint(t, j))) {
    i = j;
    if (j > cast(unsigned int, MAX_INT)/2) {

      i = 1;
      while (!ttisnil(luaH_getint(t, i))) i++;
      return i - 1;
    }
    j *= 2;
  }

  while (j - i > 1) {
    unsigned int m = (i+j)/2;
    if (ttisnil(luaH_getint(t, m))) j = m;
    else i = m;
  }
  return i;
}

int luaH_getn (Table *t) {
  unsigned int j = t->sizearray;
  if (j > 0 && ttisnil(&t->array[j - 1])) {

    unsigned int i = 0;
    while (j - i > 1) {
      unsigned int m = (i+j)/2;
      if (ttisnil(&t->array[m - 1])) j = m;
      else i = m;
    }
    return i;
  }

  else if (isdummy(t->node))
    return j;
  else return unbound_search(t, j);
}

#if defined(LUA_DEBUG)

Node *luaH_mainposition (const Table *t, const TValue *key) {
  return mainposition(t, key);
}

int luaH_isdummy (Node *n) { return isdummy(n); }

#endif
