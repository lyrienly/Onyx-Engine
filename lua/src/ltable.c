#include <math.h>
#include <string.h>
#include <stdio.h>

#define ltable_c
#define LUA_CORE

#include "lua.h"

#include "ldebug.h"
#include "ldo.h"
#include "lgc.h"
#include "lmem.h"
#include "lobject.h"
#include "lstate.h"
#include "ltable.h"
#include "lnum.h"

#if LUAI_BITSINT > 26
#define MAXBITS		26
#else
#define MAXBITS		(LUAI_BITSINT-2)
#endif

#define MAXASIZE	(1 << MAXBITS)

#define hashpow2(t,n)      (gnode(t, lmod((n), sizenode(t))))

#define hashstr(t,str)  hashpow2(t, (str)->tsv.hash)
#define hashboolean(t,p)        hashpow2(t, p)

#ifdef LUA_TINT
# define hashint(t,i)    hashpow2(t,i)
#endif

#define hashmod(t,n)	(gnode(t, ((n) % ((sizenode(t)-1)|1))))

#define hashpointer(t,p)	hashmod(t, IntPoint(p))

#define dummynode		(&dummynode_)

static const Node dummynode_ = {
  {{NULL}, LUA_TNIL},
  {{{NULL}, LUA_TNIL, NULL}}
};

#ifndef LNUM_LDOUBLE

# define NUM_INTS (sizeof(lua_Number)/sizeof(int))
#else
# if defined(__x86_64) || defined(__i386__)

#  ifdef LNUM_COMPLEX
#   define NUM_INTS 2
#  else
#   define NUM_INTS 3
#  endif
# else

#  define NUM_INTS ((sizeof(lua_Number)/sizeof(int))-1)
# endif
#endif

static Node *hashnum (const Table *t, const lua_Number v) {
  unsigned int i,sum;
#ifdef NO_STRICT_ALIASING

  const unsigned int *a= cast(const unsigned int*, &v);
  sum= a[0]; for (i = 1; i < NUM_INTS; i++) sum += a[i];
#else

  union {
    lua_Number v;
    unsigned int a[NUM_INTS];
  } u;
  lua_assert( sizeof(u)==sizeof(v) );
  u.v= v;
  sum= u.a[0]; for (i = 1; i < NUM_INTS; i++) sum += u.a[i];
#endif
  return hashmod(t, sum);
}

static Node *mainposition (const Table *t, const TValue *key) {
  switch (ttype(key)) {
#ifdef LUA_TINT
    case LUA_TINT:
      return hashint(t,ivalue(key));
#endif
    case LUA_TNUMBER: {
#ifdef LUA_TINT
      lua_Integer i;
      if (tt_integer_valued(key,&i))
        return hashint(t, i);
# ifdef LNUM_COMPLEX

      if (nvalue_img_fast(key)!=0 && luai_numeq(nvalue_fast(key),0))
        return gnode(t, 0);
# endif
#else
      if (luai_numeq(nvalue(key),0)) return gnode(t, 0);
#endif
      return hashnum(t,nvalue_fast(key));
    }
    case LUA_TSTRING:
      return hashstr(t, rawtsvalue(key));
    case LUA_TBOOLEAN:
      return hashboolean(t, bvalue(key));
    case LUA_TLIGHTUSERDATA:
      return hashpointer(t, pvalue(key));
    default:
      return hashpointer(t, gcvalue(key));
  }
}

static int arrayindex (const TValue *key, int max) {
  lua_Integer i;
  switch( ttype(key) ) {
#ifdef LUA_TINT
    case LUA_TINT:      i= ivalue(key); break;
#endif
    case LUA_TNUMBER:   if (tt_integer_valued(key,&i)) break;
    default:            return -1;
  }
  return (i <= max) ? cast_int(i) : -1;
}

static int findindex (lua_State *L, Table *t, StkId key) {
  int i;
  if (ttisnil(key)) return -1;
  i = arrayindex(key, t->sizearray);
  if (i>0)
    return i-1;
  else {
    Node *n = mainposition(t, key);
    do {

      if (luaO_rawequalObj(key2tval(n), key) ||
            (ttype(gkey(n)) == LUA_TDEADKEY && iscollectable(key) &&
             gcvalue(gkey(n)) == gcvalue(key))) {
        i = cast_int(n - gnode(t, 0));

        return i + t->sizearray;
      }
      else n = gnext(n);
    } while (n);
    luaG_runerror(L, "invalid key to " LUA_QL("next"));
    return 0;
  }
}

int luaH_next (lua_State *L, Table *t, StkId key) {
  int i = findindex(L, t, key);
  for (i++; i < t->sizearray; i++) {
    if (!ttisnil(&t->array[i])) {
      setivalue(key, i+1);
      setobj2s(L, key+1, &t->array[i]);
      return 1;
    }
  }
  for (i -= t->sizearray; i < sizenode(t); i++) {
    if (!ttisnil(gval(gnode(t, i)))) {
      setobj2s(L, key, key2tval(gnode(t, i)));
      setobj2s(L, key+1, gval(gnode(t, i)));
      return 1;
    }
  }
  return 0;
}

static int computesizes (int nums[], int *narray) {
  int i;
  int twotoi;
  int a = 0;
  int na = 0;
  int n = 0;
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

static int countint (const TValue *key, int *nums) {
  int k = arrayindex(key,MAXASIZE);
  if (k>0) {
    nums[ceillog2( cast(unsigned int,k) )]++;
    return 1;
  }
  else
    return 0;
}

static int numusearray (const Table *t, int *nums) {
  int lg;
  int ttlg;
  int ause = 0;
  int i = 1;
  for (lg=0, ttlg=1; lg<=MAXBITS; lg++, ttlg*=2) {
    int lc = 0;
    int lim = ttlg;
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

static int numusehash (const Table *t, int *nums, int *pnasize) {
  int totaluse = 0;
  int ause = 0;
  int i = sizenode(t);
  while (i--) {
    Node *n = &t->node[i];
    if (!ttisnil(gval(n))) {
      ause += countint(key2tval(n), nums);
      totaluse++;
    }
  }
  *pnasize += ause;
  return totaluse;
}

static void setarrayvector (lua_State *L, Table *t, int size) {
  int i;
  luaM_reallocvector(L, t->array, t->sizearray, size, TValue);
  for (i=t->sizearray; i<size; i++)
     setnilvalue(&t->array[i]);
  t->sizearray = size;
}

static void setnodevector (lua_State *L, Table *t, int size) {
  int lsize;
  if (size == 0) {
    t->node = cast(Node *, dummynode);
    lsize = 0;
  }
  else {
    int i;
    lsize = ceillog2(size);
    if (lsize > MAXBITS)
      luaG_runerror(L, "table overflow");
    size = twoto(lsize);
    t->node = luaM_newvector(L, size, Node);
    for (i=0; i<size; i++) {
      Node *n = gnode(t, i);
      gnext(n) = NULL;
      setnilvalue(gkey(n));
      setnilvalue(gval(n));
    }
  }
  t->lsizenode = cast_byte(lsize);
  t->lastfree = gnode(t, size);
}

static void resize (lua_State *L, Table *t, int nasize, int nhsize) {
  int i;
  int oldasize = t->sizearray;
  int oldhsize = t->lsizenode;
  Node *nold = t->node;
  if (nasize > oldasize)
    setarrayvector(L, t, nasize);

  setnodevector(L, t, nhsize);
  if (nasize < oldasize) {
    t->sizearray = nasize;

    for (i=nasize; i<oldasize; i++) {
      if (!ttisnil(&t->array[i]))
        setobjt2t(L, luaH_setint(L, t, i+1), &t->array[i]);
    }

    luaM_reallocvector(L, t->array, oldasize, nasize, TValue);
  }

  for (i = twoto(oldhsize) - 1; i >= 0; i--) {
    Node *old = nold+i;
    if (!ttisnil(gval(old)))
      setobjt2t(L, luaH_set(L, t, key2tval(old)), gval(old));
  }
  if (nold != dummynode)
    luaM_freearray(L, nold, twoto(oldhsize), Node);
}

void luaH_resizearray (lua_State *L, Table *t, int nasize) {
  int nsize = (t->node == dummynode) ? 0 : sizenode(t);
  resize(L, t, nasize, nsize);
}

static void rehash (lua_State *L, Table *t, const TValue *ek) {
  int nasize, na;
  int nums[MAXBITS+1];
  int i;
  int totaluse;
  for (i=0; i<=MAXBITS; i++) nums[i] = 0;
  nasize = numusearray(t, nums);
  totaluse = nasize;
  totaluse += numusehash(t, nums, &nasize);

  nasize += countint(ek, nums);
  totaluse++;

  na = computesizes(nums, &nasize);

  resize(L, t, nasize, totaluse - na);
}

Table *luaH_new (lua_State *L, int narray, int nhash) {
  Table *t = luaM_new(L, Table);
  luaC_link(L, obj2gco(t), LUA_TTABLE);
  t->metatable = NULL;
  t->flags = cast_byte(~0);

  t->array = NULL;
  t->sizearray = 0;
  t->lsizenode = 0;
  t->node = cast(Node *, dummynode);
  setarrayvector(L, t, narray);
  setnodevector(L, t, nhash);
  return t;
}

void luaH_free (lua_State *L, Table *t) {
  if (t->node != dummynode)
    luaM_freearray(L, t->node, sizenode(t), Node);
  luaM_freearray(L, t->array, t->sizearray, TValue);
  luaM_free(L, t);
}

static Node *getfreepos (Table *t) {
  while (t->lastfree-- > t->node) {
    if (ttisnil(gkey(t->lastfree)))
      return t->lastfree;
  }
  return NULL;
}

static TValue *newkey (lua_State *L, Table *t, const TValue *key) {
  Node *mp = mainposition(t, key);
  if (!ttisnil(gval(mp)) || mp == dummynode) {
    Node *othern;
    Node *n = getfreepos(t);
    if (n == NULL) {
      rehash(L, t, key);
      return luaH_set(L, t, key);
    }
    lua_assert(n != dummynode);
    othern = mainposition(t, key2tval(mp));
    if (othern != mp) {

      while (gnext(othern) != mp) {
        othern = gnext(othern);
        lua_assert(othern);
      }
      gnext(othern) = n;
      *n = *mp;
      gnext(mp) = NULL;
      setnilvalue(gval(mp));
    }
    else {

      gnext(n) = gnext(mp);
      gnext(mp) = n;
      mp = n;
    }
  }
  gkey(mp)->value = key->value; gkey(mp)->tt = key->tt;
  luaC_barriert(L, t, key);
  lua_assert(ttisnil(gval(mp)));
  return gval(mp);
}

const TValue *luaH_getint (Table *t, int key) {

  if (cast(unsigned int, key-1) < cast(unsigned int, t->sizearray))
    return &t->array[key-1];
  else {
#ifdef LUA_TINT
    Node *n = hashint(t, key);
    do {
      if (ttisint(gkey(n)) && (ivalue(gkey(n)) == key))
#else
    lua_Number key_d= cast_num(key);
    Node *n = hashnum(t, key_d);
    do {
      if (ttisnumber(gkey(n)) && luai_numeq(nvalue(gkey(n)), key_d))
#endif
        return gval(n);
      n = gnext(n);
    } while (n);
    return luaO_nilobject;
  }
}

const TValue *luaH_getstr (Table *t, TString *key) {
  Node *n = hashstr(t, key);
  do {
    if (ttisstring(gkey(n)) && rawtsvalue(gkey(n)) == key)
      return gval(n);
    else n = gnext(n);
  } while (n);
  return luaO_nilobject;
}

const TValue *luaH_get (Table *t, const TValue *key) {
  Node *n;
  switch (ttype(key)) {
    case LUA_TNIL: return luaO_nilobject;
    case LUA_TSTRING: return luaH_getstr(t, rawtsvalue(key));

#ifdef LUA_TINT
    case LUA_TINT: {
      int i= cast_int( ivalue(key) );
# ifdef LNUM_INT64
      if (i != ivalue(key)) break;
# endif
      return luaH_getint(t,i);
#endif
    }
    case LUA_TNUMBER: {
      lua_Integer j;
      if (!tt_integer_valued(key,&j)) break;
# ifdef LNUM_INT64
      if (cast_int(j) != j) break;
# endif
      return luaH_getint(t,cast_int(j));
    }
  }

  n = mainposition(t, key);
  do {
    if (luaO_rawequalObj(key2tval(n), key))
      return gval(n);
    else n = gnext(n);
  } while (n);
  return luaO_nilobject;
}

TValue *luaH_set (lua_State *L, Table *t, const TValue *key) {
  const TValue *p = luaH_get(t, key);
  t->flags = 0;
  if (p != luaO_nilobject)
    return cast(TValue *, p);
  else {
    if (ttisnil(key)) luaG_runerror(L, "table index is nil");
    else if (ttype(key)==LUA_TNUMBER) {
#ifdef LUA_TINT

      lua_Integer i;
      if (tt_integer_valued(key,&i)) {
# ifdef LNUM_INT64
        if (cast_int(i) != i) {
          TValue k;
          setivalue(&k, i);
          return newkey(L, t, &k);
        }
# endif
        return luaH_setint(L, t, cast_int(i));
      }
#endif
      if (luai_numisnan(nvalue_fast(key)))
        luaG_runerror(L, "table index is NaN");
    }
    return newkey(L, t, key);
  }
}

TValue *luaH_setint (lua_State *L, Table *t, int key) {
  const TValue *p = luaH_getint(t, key);
  if (p != luaO_nilobject)
    return cast(TValue *, p);
  else {
    TValue k;
    setivalue(&k, key);
    return newkey(L, t, &k);
  }
}

TValue *luaH_setstr (lua_State *L, Table *t, TString *key) {
  const TValue *p = luaH_getstr(t, key);
  if (p != luaO_nilobject)
    return cast(TValue *, p);
  else {
    TValue k;
    setsvalue(L, &k, key);
    return newkey(L, t, &k);
  }
}

static int unbound_search (Table *t, unsigned int j) {
  unsigned int i = j;
  j++;

  while (!ttisnil(luaH_getint(t, j))) {
    i = j;
    j *= 2;
    if (j > cast(unsigned int, MAX_INT)) {

      i = 1;
      while (!ttisnil(luaH_getint(t, i))) i++;
      return i - 1;
    }
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

  else if (t->node == dummynode)
    return j;
  else return unbound_search(t, j);
}

#if defined(LUA_DEBUG)

Node *luaH_mainposition (const Table *t, const TValue *key) {
  return mainposition(t, key);
}

int luaH_isdummy (Node *n) { return n == dummynode; }

#endif
