#define lstrlib_c
#define LUA_LIB

#include "lprefix.h"

#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lua.h"

#include "lauxlib.h"
#include "lualib.h"

#if !defined(LUA_MAXCAPTURES)
#define LUA_MAXCAPTURES		32
#endif

#define uchar(c)	((unsigned char)(c))

#define MAXSIZE  \
	(sizeof(size_t) < sizeof(int) ? (~(size_t)0) : (size_t)(INT_MAX))

static int str_len (lua_State *L) {
  size_t l;
  luaL_checklstring(L, 1, &l);
  lua_pushinteger(L, (lua_Integer)l);
  return 1;
}

static lua_Integer posrelat (lua_Integer pos, size_t len) {
  if (pos >= 0) return pos;
  else if (0u - (size_t)pos > len) return 0;
  else return (lua_Integer)len + pos + 1;
}

static int str_sub (lua_State *L) {
  size_t l;
  const char *s = luaL_checklstring(L, 1, &l);
  lua_Integer start = posrelat(luaL_checkinteger(L, 2), l);
  lua_Integer end = posrelat(luaL_optinteger(L, 3, -1), l);
  if (start < 1) start = 1;
  if (end > (lua_Integer)l) end = l;
  if (start <= end)
    lua_pushlstring(L, s + start - 1, (size_t)(end - start + 1));
  else lua_pushliteral(L, "");
  return 1;
}

static int str_reverse (lua_State *L) {
  size_t l, i;
  luaL_Buffer b;
  const char *s = luaL_checklstring(L, 1, &l);
  char *p = luaL_buffinitsize(L, &b, l);
  for (i = 0; i < l; i++)
    p[i] = s[l - i - 1];
  luaL_pushresultsize(&b, l);
  return 1;
}

static int str_lower (lua_State *L) {
  size_t l;
  size_t i;
  luaL_Buffer b;
  const char *s = luaL_checklstring(L, 1, &l);
  char *p = luaL_buffinitsize(L, &b, l);
  for (i=0; i<l; i++)
    p[i] = tolower(uchar(s[i]));
  luaL_pushresultsize(&b, l);
  return 1;
}

static int str_upper (lua_State *L) {
  size_t l;
  size_t i;
  luaL_Buffer b;
  const char *s = luaL_checklstring(L, 1, &l);
  char *p = luaL_buffinitsize(L, &b, l);
  for (i=0; i<l; i++)
    p[i] = toupper(uchar(s[i]));
  luaL_pushresultsize(&b, l);
  return 1;
}

static int str_rep (lua_State *L) {
  size_t l, lsep;
  const char *s = luaL_checklstring(L, 1, &l);
  lua_Integer n = luaL_checkinteger(L, 2);
  const char *sep = luaL_optlstring(L, 3, "", &lsep);
  if (n <= 0) lua_pushliteral(L, "");
  else if (l + lsep < l || l + lsep > MAXSIZE / n)
    return luaL_error(L, "resulting string too large");
  else {
    size_t totallen = (size_t)n * l + (size_t)(n - 1) * lsep;
    luaL_Buffer b;
    char *p = luaL_buffinitsize(L, &b, totallen);
    while (n-- > 1) {
      memcpy(p, s, l * sizeof(char)); p += l;
      if (lsep > 0) {
        memcpy(p, sep, lsep * sizeof(char));
        p += lsep;
      }
    }
    memcpy(p, s, l * sizeof(char));
    luaL_pushresultsize(&b, totallen);
  }
  return 1;
}

static int str_byte (lua_State *L) {
  size_t l;
  const char *s = luaL_checklstring(L, 1, &l);
  lua_Integer posi = posrelat(luaL_optinteger(L, 2, 1), l);
  lua_Integer pose = posrelat(luaL_optinteger(L, 3, posi), l);
  int n, i;
  if (posi < 1) posi = 1;
  if (pose > (lua_Integer)l) pose = l;
  if (posi > pose) return 0;
  n = (int)(pose -  posi + 1);
  if (posi + n <= pose)
    return luaL_error(L, "string slice too long");
  luaL_checkstack(L, n, "string slice too long");
  for (i=0; i<n; i++)
    lua_pushinteger(L, uchar(s[posi+i-1]));
  return n;
}

static int str_char (lua_State *L) {
  int n = lua_gettop(L);
  int i;
  luaL_Buffer b;
  char *p = luaL_buffinitsize(L, &b, n);
  for (i=1; i<=n; i++) {
    lua_Integer c = luaL_checkinteger(L, i);
    luaL_argcheck(L, uchar(c) == c, i, "value out of range");
    p[i - 1] = uchar(c);
  }
  luaL_pushresultsize(&b, n);
  return 1;
}

static int writer (lua_State *L, const void *b, size_t size, void *B) {
  (void)L;
  luaL_addlstring((luaL_Buffer *) B, (const char *)b, size);
  return 0;
}

static int str_dump (lua_State *L) {
  luaL_Buffer b;
  int strip = lua_toboolean(L, 2);
  luaL_checktype(L, 1, LUA_TFUNCTION);
  lua_settop(L, 1);
  luaL_buffinit(L,&b);
  if (lua_dump(L, writer, &b, strip) != 0)
    return luaL_error(L, "unable to dump given function");
  luaL_pushresult(&b);
  return 1;
}

#define CAP_UNFINISHED	(-1)
#define CAP_POSITION	(-2)

typedef struct MatchState {
  int matchdepth;
  const char *src_init;
  const char *src_end;
  const char *p_end;
  lua_State *L;
  int level;
  struct {
    const char *init;
    ptrdiff_t len;
  } capture[LUA_MAXCAPTURES];
} MatchState;

static const char *match (MatchState *ms, const char *s, const char *p);

#if !defined(MAXCCALLS)
#define MAXCCALLS	200
#endif

#define L_ESC		'%'
#define SPECIALS	"^$*+?.([%-"

static int check_capture (MatchState *ms, int l) {
  l -= '1';
  if (l < 0 || l >= ms->level || ms->capture[l].len == CAP_UNFINISHED)
    return luaL_error(ms->L, "invalid capture index %%%d", l + 1);
  return l;
}

static int capture_to_close (MatchState *ms) {
  int level = ms->level;
  for (level--; level>=0; level--)
    if (ms->capture[level].len == CAP_UNFINISHED) return level;
  return luaL_error(ms->L, "invalid pattern capture");
}

static const char *classend (MatchState *ms, const char *p) {
  switch (*p++) {
    case L_ESC: {
      if (p == ms->p_end)
        luaL_error(ms->L, "malformed pattern (ends with '%%')");
      return p+1;
    }
    case '[': {
      if (*p == '^') p++;
      do {
        if (p == ms->p_end)
          luaL_error(ms->L, "malformed pattern (missing ']')");
        if (*(p++) == L_ESC && p < ms->p_end)
          p++;
      } while (*p != ']');
      return p+1;
    }
    default: {
      return p;
    }
  }
}

static int match_class (int c, int cl) {
  int res;
  switch (tolower(cl)) {
    case 'a' : res = isalpha(c); break;
    case 'c' : res = iscntrl(c); break;
    case 'd' : res = isdigit(c); break;
    case 'g' : res = isgraph(c); break;
    case 'l' : res = islower(c); break;
    case 'p' : res = ispunct(c); break;
    case 's' : res = isspace(c); break;
    case 'u' : res = isupper(c); break;
    case 'w' : res = isalnum(c); break;
    case 'x' : res = isxdigit(c); break;
    case 'z' : res = (c == 0); break;
    default: return (cl == c);
  }
  return (islower(cl) ? res : !res);
}

static int matchbracketclass (int c, const char *p, const char *ec) {
  int sig = 1;
  if (*(p+1) == '^') {
    sig = 0;
    p++;
  }
  while (++p < ec) {
    if (*p == L_ESC) {
      p++;
      if (match_class(c, uchar(*p)))
        return sig;
    }
    else if ((*(p+1) == '-') && (p+2 < ec)) {
      p+=2;
      if (uchar(*(p-2)) <= c && c <= uchar(*p))
        return sig;
    }
    else if (uchar(*p) == c) return sig;
  }
  return !sig;
}

static int singlematch (MatchState *ms, const char *s, const char *p,
                        const char *ep) {
  if (s >= ms->src_end)
    return 0;
  else {
    int c = uchar(*s);
    switch (*p) {
      case '.': return 1;
      case L_ESC: return match_class(c, uchar(*(p+1)));
      case '[': return matchbracketclass(c, p, ep-1);
      default:  return (uchar(*p) == c);
    }
  }
}

static const char *matchbalance (MatchState *ms, const char *s,
                                   const char *p) {
  if (p >= ms->p_end - 1)
    luaL_error(ms->L, "malformed pattern (missing arguments to '%%b')");
  if (*s != *p) return NULL;
  else {
    int b = *p;
    int e = *(p+1);
    int cont = 1;
    while (++s < ms->src_end) {
      if (*s == e) {
        if (--cont == 0) return s+1;
      }
      else if (*s == b) cont++;
    }
  }
  return NULL;
}

static const char *max_expand (MatchState *ms, const char *s,
                                 const char *p, const char *ep) {
  ptrdiff_t i = 0;
  while (singlematch(ms, s + i, p, ep))
    i++;

  while (i>=0) {
    const char *res = match(ms, (s+i), ep+1);
    if (res) return res;
    i--;
  }
  return NULL;
}

static const char *min_expand (MatchState *ms, const char *s,
                                 const char *p, const char *ep) {
  for (;;) {
    const char *res = match(ms, s, ep+1);
    if (res != NULL)
      return res;
    else if (singlematch(ms, s, p, ep))
      s++;
    else return NULL;
  }
}

static const char *start_capture (MatchState *ms, const char *s,
                                    const char *p, int what) {
  const char *res;
  int level = ms->level;
  if (level >= LUA_MAXCAPTURES) luaL_error(ms->L, "too many captures");
  ms->capture[level].init = s;
  ms->capture[level].len = what;
  ms->level = level+1;
  if ((res=match(ms, s, p)) == NULL)
    ms->level--;
  return res;
}

static const char *end_capture (MatchState *ms, const char *s,
                                  const char *p) {
  int l = capture_to_close(ms);
  const char *res;
  ms->capture[l].len = s - ms->capture[l].init;
  if ((res = match(ms, s, p)) == NULL)
    ms->capture[l].len = CAP_UNFINISHED;
  return res;
}

static const char *match_capture (MatchState *ms, const char *s, int l) {
  size_t len;
  l = check_capture(ms, l);
  len = ms->capture[l].len;
  if ((size_t)(ms->src_end-s) >= len &&
      memcmp(ms->capture[l].init, s, len) == 0)
    return s+len;
  else return NULL;
}

static const char *match (MatchState *ms, const char *s, const char *p) {
  if (ms->matchdepth-- == 0)
    luaL_error(ms->L, "pattern too complex");
  init:
  if (p != ms->p_end) {
    switch (*p) {
      case '(': {
        if (*(p + 1) == ')')
          s = start_capture(ms, s, p + 2, CAP_POSITION);
        else
          s = start_capture(ms, s, p + 1, CAP_UNFINISHED);
        break;
      }
      case ')': {
        s = end_capture(ms, s, p + 1);
        break;
      }
      case '$': {
        if ((p + 1) != ms->p_end)
          goto dflt;
        s = (s == ms->src_end) ? s : NULL;
        break;
      }
      case L_ESC: {
        switch (*(p + 1)) {
          case 'b': {
            s = matchbalance(ms, s, p + 2);
            if (s != NULL) {
              p += 4; goto init;
            }
            break;
          }
          case 'f': {
            const char *ep; char previous;
            p += 2;
            if (*p != '[')
              luaL_error(ms->L, "missing '[' after '%%f' in pattern");
            ep = classend(ms, p);
            previous = (s == ms->src_init) ? '\0' : *(s - 1);
            if (!matchbracketclass(uchar(previous), p, ep - 1) &&
               matchbracketclass(uchar(*s), p, ep - 1)) {
              p = ep; goto init;
            }
            s = NULL;
            break;
          }
          case '0': case '1': case '2': case '3':
          case '4': case '5': case '6': case '7':
          case '8': case '9': {
            s = match_capture(ms, s, uchar(*(p + 1)));
            if (s != NULL) {
              p += 2; goto init;
            }
            break;
          }
          default: goto dflt;
        }
        break;
      }
      default: dflt: {
        const char *ep = classend(ms, p);

        if (!singlematch(ms, s, p, ep)) {
          if (*ep == '*' || *ep == '?' || *ep == '-') {
            p = ep + 1; goto init;
          }
          else
            s = NULL;
        }
        else {
          switch (*ep) {
            case '?': {
              const char *res;
              if ((res = match(ms, s + 1, ep + 1)) != NULL)
                s = res;
              else {
                p = ep + 1; goto init;
              }
              break;
            }
            case '+':
              s++;

            case '*':
              s = max_expand(ms, s, p, ep);
              break;
            case '-':
              s = min_expand(ms, s, p, ep);
              break;
            default:
              s++; p = ep; goto init;
          }
        }
        break;
      }
    }
  }
  ms->matchdepth++;
  return s;
}

static const char *lmemfind (const char *s1, size_t l1,
                               const char *s2, size_t l2) {
  if (l2 == 0) return s1;
  else if (l2 > l1) return NULL;
  else {
    const char *init;
    l2--;
    l1 = l1-l2;
    while (l1 > 0 && (init = (const char *)memchr(s1, *s2, l1)) != NULL) {
      init++;
      if (memcmp(init, s2+1, l2) == 0)
        return init-1;
      else {
        l1 -= init-s1;
        s1 = init;
      }
    }
    return NULL;
  }
}

static void push_onecapture (MatchState *ms, int i, const char *s,
                                                    const char *e) {
  if (i >= ms->level) {
    if (i == 0)
      lua_pushlstring(ms->L, s, e - s);
    else
      luaL_error(ms->L, "invalid capture index %%%d", i + 1);
  }
  else {
    ptrdiff_t l = ms->capture[i].len;
    if (l == CAP_UNFINISHED) luaL_error(ms->L, "unfinished capture");
    if (l == CAP_POSITION)
      lua_pushinteger(ms->L, ms->capture[i].init - ms->src_init + 1);
    else
      lua_pushlstring(ms->L, ms->capture[i].init, l);
  }
}

static int push_captures (MatchState *ms, const char *s, const char *e) {
  int i;
  int nlevels = (ms->level == 0 && s) ? 1 : ms->level;
  luaL_checkstack(ms->L, nlevels, "too many captures");
  for (i = 0; i < nlevels; i++)
    push_onecapture(ms, i, s, e);
  return nlevels;
}

static int nospecials (const char *p, size_t l) {
  size_t upto = 0;
  do {
    if (strpbrk(p + upto, SPECIALS))
      return 0;
    upto += strlen(p + upto) + 1;
  } while (upto <= l);
  return 1;
}

static int str_find_aux (lua_State *L, int find) {
  size_t ls, lp;
  const char *s = luaL_checklstring(L, 1, &ls);
  const char *p = luaL_checklstring(L, 2, &lp);
  lua_Integer init = posrelat(luaL_optinteger(L, 3, 1), ls);
  if (init < 1) init = 1;
  else if (init > (lua_Integer)ls + 1) {
    lua_pushnil(L);
    return 1;
  }

  if (find && (lua_toboolean(L, 4) || nospecials(p, lp))) {

    const char *s2 = lmemfind(s + init - 1, ls - (size_t)init + 1, p, lp);
    if (s2) {
      lua_pushinteger(L, s2 - s + 1);
      lua_pushinteger(L, s2 - s + lp);
      return 2;
    }
  }
  else {
    MatchState ms;
    const char *s1 = s + init - 1;
    int anchor = (*p == '^');
    if (anchor) {
      p++; lp--;
    }
    ms.L = L;
    ms.matchdepth = MAXCCALLS;
    ms.src_init = s;
    ms.src_end = s + ls;
    ms.p_end = p + lp;
    do {
      const char *res;
      ms.level = 0;
      lua_assert(ms.matchdepth == MAXCCALLS);
      if ((res=match(&ms, s1, p)) != NULL) {
        if (find) {
          lua_pushinteger(L, s1 - s + 1);
          lua_pushinteger(L, res - s);
          return push_captures(&ms, NULL, 0) + 2;
        }
        else
          return push_captures(&ms, s1, res);
      }
    } while (s1++ < ms.src_end && !anchor);
  }
  lua_pushnil(L);
  return 1;
}

static int str_find (lua_State *L) {
  return str_find_aux(L, 1);
}

static int str_match (lua_State *L) {
  return str_find_aux(L, 0);
}

static int gmatch_aux (lua_State *L) {
  MatchState ms;
  size_t ls, lp;
  const char *s = lua_tolstring(L, lua_upvalueindex(1), &ls);
  const char *p = lua_tolstring(L, lua_upvalueindex(2), &lp);
  const char *src;
  ms.L = L;
  ms.matchdepth = MAXCCALLS;
  ms.src_init = s;
  ms.src_end = s+ls;
  ms.p_end = p + lp;
  for (src = s + (size_t)lua_tointeger(L, lua_upvalueindex(3));
       src <= ms.src_end;
       src++) {
    const char *e;
    ms.level = 0;
    lua_assert(ms.matchdepth == MAXCCALLS);
    if ((e = match(&ms, src, p)) != NULL) {
      lua_Integer newstart = e-s;
      if (e == src) newstart++;
      lua_pushinteger(L, newstart);
      lua_replace(L, lua_upvalueindex(3));
      return push_captures(&ms, src, e);
    }
  }
  return 0;
}

static int gmatch (lua_State *L) {
  luaL_checkstring(L, 1);
  luaL_checkstring(L, 2);
  lua_settop(L, 2);
  lua_pushinteger(L, 0);
  lua_pushcclosure(L, gmatch_aux, 3);
  return 1;
}

static void add_s (MatchState *ms, luaL_Buffer *b, const char *s,
                                                   const char *e) {
  size_t l, i;
  lua_State *L = ms->L;
  const char *news = lua_tolstring(L, 3, &l);
  for (i = 0; i < l; i++) {
    if (news[i] != L_ESC)
      luaL_addchar(b, news[i]);
    else {
      i++;
      if (!isdigit(uchar(news[i]))) {
        if (news[i] != L_ESC)
          luaL_error(L, "invalid use of '%c' in replacement string", L_ESC);
        luaL_addchar(b, news[i]);
      }
      else if (news[i] == '0')
          luaL_addlstring(b, s, e - s);
      else {
        push_onecapture(ms, news[i] - '1', s, e);
        luaL_tolstring(L, -1, NULL);
        lua_remove(L, -2);
        luaL_addvalue(b);
      }
    }
  }
}

static void add_value (MatchState *ms, luaL_Buffer *b, const char *s,
                                       const char *e, int tr) {
  lua_State *L = ms->L;
  switch (tr) {
    case LUA_TFUNCTION: {
      int n;
      lua_pushvalue(L, 3);
      n = push_captures(ms, s, e);
      lua_call(L, n, 1);
      break;
    }
    case LUA_TTABLE: {
      push_onecapture(ms, 0, s, e);
      lua_gettable(L, 3);
      break;
    }
    default: {
      add_s(ms, b, s, e);
      return;
    }
  }
  if (!lua_toboolean(L, -1)) {
    lua_pop(L, 1);
    lua_pushlstring(L, s, e - s);
  }
  else if (!lua_isstring(L, -1))
    luaL_error(L, "invalid replacement value (a %s)", luaL_typename(L, -1));
  luaL_addvalue(b);
}

static int str_gsub (lua_State *L) {
  size_t srcl, lp;
  const char *src = luaL_checklstring(L, 1, &srcl);
  const char *p = luaL_checklstring(L, 2, &lp);
  int tr = lua_type(L, 3);
  lua_Integer max_s = luaL_optinteger(L, 4, srcl + 1);
  int anchor = (*p == '^');
  lua_Integer n = 0;
  MatchState ms;
  luaL_Buffer b;
  luaL_argcheck(L, tr == LUA_TNUMBER || tr == LUA_TSTRING ||
                   tr == LUA_TFUNCTION || tr == LUA_TTABLE, 3,
                      "string/function/table expected");
  luaL_buffinit(L, &b);
  if (anchor) {
    p++; lp--;
  }
  ms.L = L;
  ms.matchdepth = MAXCCALLS;
  ms.src_init = src;
  ms.src_end = src+srcl;
  ms.p_end = p + lp;
  while (n < max_s) {
    const char *e;
    ms.level = 0;
    lua_assert(ms.matchdepth == MAXCCALLS);
    e = match(&ms, src, p);
    if (e) {
      n++;
      add_value(&ms, &b, src, e, tr);
    }
    if (e && e>src)
      src = e;
    else if (src < ms.src_end)
      luaL_addchar(&b, *src++);
    else break;
    if (anchor) break;
  }
  luaL_addlstring(&b, src, ms.src_end-src);
  luaL_pushresult(&b);
  lua_pushinteger(L, n);
  return 2;
}

#define MAX_ITEM	512

#define FLAGS	"-+ #0"

#define MAX_FORMAT	(sizeof(FLAGS) + 2 + 10)

static void addquoted (lua_State *L, luaL_Buffer *b, int arg) {
  size_t l;
  const char *s = luaL_checklstring(L, arg, &l);
  luaL_addchar(b, '"');
  while (l--) {
    if (*s == '"' || *s == '\\' || *s == '\n') {
      luaL_addchar(b, '\\');
      luaL_addchar(b, *s);
    }
    else if (*s == '\0' || iscntrl(uchar(*s))) {
      char buff[10];
      if (!isdigit(uchar(*(s+1))))
        sprintf(buff, "\\%d", (int)uchar(*s));
      else
        sprintf(buff, "\\%03d", (int)uchar(*s));
      luaL_addstring(b, buff);
    }
    else
      luaL_addchar(b, *s);
    s++;
  }
  luaL_addchar(b, '"');
}

static const char *scanformat (lua_State *L, const char *strfrmt, char *form) {
  const char *p = strfrmt;
  while (*p != '\0' && strchr(FLAGS, *p) != NULL) p++;
  if ((size_t)(p - strfrmt) >= sizeof(FLAGS)/sizeof(char))
    luaL_error(L, "invalid format (repeated flags)");
  if (isdigit(uchar(*p))) p++;
  if (isdigit(uchar(*p))) p++;
  if (*p == '.') {
    p++;
    if (isdigit(uchar(*p))) p++;
    if (isdigit(uchar(*p))) p++;
  }
  if (isdigit(uchar(*p)))
    luaL_error(L, "invalid format (width or precision too long)");
  *(form++) = '%';
  memcpy(form, strfrmt, (p - strfrmt + 1) * sizeof(char));
  form += p - strfrmt + 1;
  *form = '\0';
  return p;
}

static void addlenmod (char *form, const char *lenmod) {
  size_t l = strlen(form);
  size_t lm = strlen(lenmod);
  char spec = form[l - 1];
  strcpy(form + l - 1, lenmod);
  form[l + lm - 1] = spec;
  form[l + lm] = '\0';
}

static int str_format (lua_State *L) {
  int top = lua_gettop(L);
  int arg = 1;
  size_t sfl;
  const char *strfrmt = luaL_checklstring(L, arg, &sfl);
  const char *strfrmt_end = strfrmt+sfl;
  luaL_Buffer b;
  luaL_buffinit(L, &b);
  while (strfrmt < strfrmt_end) {
    if (*strfrmt != L_ESC)
      luaL_addchar(&b, *strfrmt++);
    else if (*++strfrmt == L_ESC)
      luaL_addchar(&b, *strfrmt++);
    else {
      char form[MAX_FORMAT];
      char *buff = luaL_prepbuffsize(&b, MAX_ITEM);
      int nb = 0;
      if (++arg > top)
        luaL_argerror(L, arg, "no value");
      strfrmt = scanformat(L, strfrmt, form);
      switch (*strfrmt++) {
        case 'c': {
          nb = sprintf(buff, form, (int)luaL_checkinteger(L, arg));
          break;
        }
        case 'd': case 'i':
        case 'o': case 'u': case 'x': case 'X': {
          lua_Integer n = luaL_checkinteger(L, arg);
          addlenmod(form, LUA_INTEGER_FRMLEN);
          nb = sprintf(buff, form, n);
          break;
        }
#if defined(LUA_USE_AFORMAT)
        case 'a': case 'A':
#endif
        case 'e': case 'E': case 'f':
        case 'g': case 'G': {
          addlenmod(form, LUA_NUMBER_FRMLEN);
          nb = sprintf(buff, form, luaL_checknumber(L, arg));
          break;
        }
        case 'q': {
          addquoted(L, &b, arg);
          break;
        }
        case 's': {
          size_t l;
          const char *s = luaL_tolstring(L, arg, &l);
          if (!strchr(form, '.') && l >= 100) {

            luaL_addvalue(&b);
            break;
          }
          else {
            nb = sprintf(buff, form, s);
            lua_pop(L, 1);
            break;
          }
        }
        default: {
          return luaL_error(L, "invalid option '%%%c' to 'format'",
                               *(strfrmt - 1));
        }
      }
      luaL_addsize(&b, nb);
    }
  }
  luaL_pushresult(&b);
  return 1;
}

#if !defined(LUA_PACKPADBYTE)
#define LUA_PACKPADBYTE		0x00
#endif

#define MAXINTSIZE	16

#define NB	CHAR_BIT

#define MC	((1 << NB) - 1)

#define SZINT	((int)sizeof(lua_Integer))

static const union {
  int dummy;
  char little;
} nativeendian = {1};

struct cD {
  char c;
  union { double d; void *p; lua_Integer i; lua_Number n; } u;
};

#define MAXALIGN	(offsetof(struct cD, u))

typedef union Ftypes {
  float f;
  double d;
  lua_Number n;
  char buff[5 * sizeof(lua_Number)];
} Ftypes;

typedef struct Header {
  lua_State *L;
  int islittle;
  int maxalign;
} Header;

typedef enum KOption {
  Kint,
  Kuint,
  Kfloat,
  Kchar,
  Kstring,
  Kzstr,
  Kpadding,
  Kpaddalign,
  Knop
} KOption;

static int digit (int c) { return '0' <= c && c <= '9'; }

static int getnum (const char **fmt, int df) {
  if (!digit(**fmt))
    return df;
  else {
    int a = 0;
    do {
      a = a*10 + (*((*fmt)++) - '0');
    } while (digit(**fmt) && a <= ((int)MAXSIZE - 9)/10);
    return a;
  }
}

static int getnumlimit (Header *h, const char **fmt, int df) {
  int sz = getnum(fmt, df);
  if (sz > MAXINTSIZE || sz <= 0)
    luaL_error(h->L, "integral size (%d) out of limits [1,%d]",
                     sz, MAXINTSIZE);
  return sz;
}

static void initheader (lua_State *L, Header *h) {
  h->L = L;
  h->islittle = nativeendian.little;
  h->maxalign = 1;
}

static KOption getoption (Header *h, const char **fmt, int *size) {
  int opt = *((*fmt)++);
  *size = 0;
  switch (opt) {
    case 'b': *size = sizeof(char); return Kint;
    case 'B': *size = sizeof(char); return Kuint;
    case 'h': *size = sizeof(short); return Kint;
    case 'H': *size = sizeof(short); return Kuint;
    case 'l': *size = sizeof(long); return Kint;
    case 'L': *size = sizeof(long); return Kuint;
    case 'j': *size = sizeof(lua_Integer); return Kint;
    case 'J': *size = sizeof(lua_Integer); return Kuint;
    case 'T': *size = sizeof(size_t); return Kuint;
    case 'f': *size = sizeof(float); return Kfloat;
    case 'd': *size = sizeof(double); return Kfloat;
    case 'n': *size = sizeof(lua_Number); return Kfloat;
    case 'i': *size = getnumlimit(h, fmt, sizeof(int)); return Kint;
    case 'I': *size = getnumlimit(h, fmt, sizeof(int)); return Kuint;
    case 's': *size = getnumlimit(h, fmt, sizeof(size_t)); return Kstring;
    case 'c':
      *size = getnum(fmt, -1);
      if (*size == -1)
        luaL_error(h->L, "missing size for format option 'c'");
      return Kchar;
    case 'z': return Kzstr;
    case 'x': *size = 1; return Kpadding;
    case 'X': return Kpaddalign;
    case ' ': break;
    case '<': h->islittle = 1; break;
    case '>': h->islittle = 0; break;
    case '=': h->islittle = nativeendian.little; break;
    case '!': h->maxalign = getnumlimit(h, fmt, MAXALIGN); break;
    default: luaL_error(h->L, "invalid format option '%c'", opt);
  }
  return Knop;
}

static KOption getdetails (Header *h, size_t totalsize,
                           const char **fmt, int *psize, int *ntoalign) {
  KOption opt = getoption(h, fmt, psize);
  int align = *psize;
  if (opt == Kpaddalign) {
    if (**fmt == '\0' || getoption(h, fmt, &align) == Kchar || align == 0)
      luaL_argerror(h->L, 1, "invalid next option for option 'X'");
  }
  if (align <= 1 || opt == Kchar)
    *ntoalign = 0;
  else {
    if (align > h->maxalign)
      align = h->maxalign;
    if ((align & (align - 1)) != 0)
      luaL_argerror(h->L, 1, "format asks for alignment not power of 2");
    *ntoalign = (align - (int)(totalsize & (align - 1))) & (align - 1);
  }
  return opt;
}

static void packint (luaL_Buffer *b, lua_Unsigned n,
                     int islittle, int size, int neg) {
  char *buff = luaL_prepbuffsize(b, size);
  int i;
  buff[islittle ? 0 : size - 1] = (char)(n & MC);
  for (i = 1; i < size; i++) {
    n >>= NB;
    buff[islittle ? i : size - 1 - i] = (char)(n & MC);
  }
  if (neg && size > SZINT) {
    for (i = SZINT; i < size; i++)
      buff[islittle ? i : size - 1 - i] = (char)MC;
  }
  luaL_addsize(b, size);
}

static void copywithendian (volatile char *dest, volatile const char *src,
                            int size, int islittle) {
  if (islittle == nativeendian.little) {
    while (size-- != 0)
      *(dest++) = *(src++);
  }
  else {
    dest += size - 1;
    while (size-- != 0)
      *(dest--) = *(src++);
  }
}

static int str_pack (lua_State *L) {
  luaL_Buffer b;
  Header h;
  const char *fmt = luaL_checkstring(L, 1);
  int arg = 1;
  size_t totalsize = 0;
  initheader(L, &h);
  lua_pushnil(L);
  luaL_buffinit(L, &b);
  while (*fmt != '\0') {
    int size, ntoalign;
    KOption opt = getdetails(&h, totalsize, &fmt, &size, &ntoalign);
    totalsize += ntoalign + size;
    while (ntoalign-- > 0)
     luaL_addchar(&b, LUA_PACKPADBYTE);
    arg++;
    switch (opt) {
      case Kint: {
        lua_Integer n = luaL_checkinteger(L, arg);
        if (size < SZINT) {
          lua_Integer lim = (lua_Integer)1 << ((size * NB) - 1);
          luaL_argcheck(L, -lim <= n && n < lim, arg, "integer overflow");
        }
        packint(&b, (lua_Unsigned)n, h.islittle, size, (n < 0));
        break;
      }
      case Kuint: {
        lua_Integer n = luaL_checkinteger(L, arg);
        if (size < SZINT)
          luaL_argcheck(L, (lua_Unsigned)n < ((lua_Unsigned)1 << (size * NB)),
                           arg, "unsigned overflow");
        packint(&b, (lua_Unsigned)n, h.islittle, size, 0);
        break;
      }
      case Kfloat: {
        volatile Ftypes u;
        char *buff = luaL_prepbuffsize(&b, size);
        lua_Number n = luaL_checknumber(L, arg);
        if (size == sizeof(u.f)) u.f = (float)n;
        else if (size == sizeof(u.d)) u.d = (double)n;
        else u.n = n;

        copywithendian(buff, u.buff, size, h.islittle);
        luaL_addsize(&b, size);
        break;
      }
      case Kchar: {
        size_t len;
        const char *s = luaL_checklstring(L, arg, &len);
        luaL_argcheck(L, len == (size_t)size, arg, "wrong length");
        luaL_addlstring(&b, s, size);
        break;
      }
      case Kstring: {
        size_t len;
        const char *s = luaL_checklstring(L, arg, &len);
        luaL_argcheck(L, size >= (int)sizeof(size_t) ||
                         len < ((size_t)1 << (size * NB)),
                         arg, "string length does not fit in given size");
        packint(&b, (lua_Unsigned)len, h.islittle, size, 0);
        luaL_addlstring(&b, s, len);
        totalsize += len;
        break;
      }
      case Kzstr: {
        size_t len;
        const char *s = luaL_checklstring(L, arg, &len);
        luaL_argcheck(L, strlen(s) == len, arg, "string contains zeros");
        luaL_addlstring(&b, s, len);
        luaL_addchar(&b, '\0');
        totalsize += len + 1;
        break;
      }
      case Kpadding: luaL_addchar(&b, LUA_PACKPADBYTE);
      case Kpaddalign: case Knop:
        arg--;
        break;
    }
  }
  luaL_pushresult(&b);
  return 1;
}

static int str_packsize (lua_State *L) {
  Header h;
  const char *fmt = luaL_checkstring(L, 1);
  size_t totalsize = 0;
  initheader(L, &h);
  while (*fmt != '\0') {
    int size, ntoalign;
    KOption opt = getdetails(&h, totalsize, &fmt, &size, &ntoalign);
    size += ntoalign;
    luaL_argcheck(L, totalsize <= MAXSIZE - size, 1,
                     "format result too large");
    totalsize += size;
    switch (opt) {
      case Kstring:
      case Kzstr:
        luaL_argerror(L, 1, "variable-length format");
        break;
      default:  break;
    }
  }
  lua_pushinteger(L, (lua_Integer)totalsize);
  return 1;
}

static lua_Integer unpackint (lua_State *L, const char *str,
                              int islittle, int size, int issigned) {
  lua_Unsigned res = 0;
  int i;
  int limit = (size  <= SZINT) ? size : SZINT;
  for (i = limit - 1; i >= 0; i--) {
    res <<= NB;
    res |= (lua_Unsigned)(unsigned char)str[islittle ? i : size - 1 - i];
  }
  if (size < SZINT) {
    if (issigned) {
      lua_Unsigned mask = (lua_Unsigned)1 << (size*NB - 1);
      res = ((res ^ mask) - mask);
    }
  }
  else if (size > SZINT) {
    int mask = (!issigned || (lua_Integer)res >= 0) ? 0 : MC;
    for (i = limit; i < size; i++) {
      if ((unsigned char)str[islittle ? i : size - 1 - i] != mask)
        luaL_error(L, "%d-byte integer does not fit into Lua Integer", size);
    }
  }
  return (lua_Integer)res;
}

static int str_unpack (lua_State *L) {
  Header h;
  const char *fmt = luaL_checkstring(L, 1);
  size_t ld;
  const char *data = luaL_checklstring(L, 2, &ld);
  size_t pos = (size_t)posrelat(luaL_optinteger(L, 3, 1), ld) - 1;
  int n = 0;
  luaL_argcheck(L, pos <= ld, 3, "initial position out of string");
  initheader(L, &h);
  while (*fmt != '\0') {
    int size, ntoalign;
    KOption opt = getdetails(&h, pos, &fmt, &size, &ntoalign);
    if ((size_t)ntoalign + size > ~pos || pos + ntoalign + size > ld)
      luaL_argerror(L, 2, "data string too short");
    pos += ntoalign;

    luaL_checkstack(L, 2, "too many results");
    n++;
    switch (opt) {
      case Kint:
      case Kuint: {
        lua_Integer res = unpackint(L, data + pos, h.islittle, size,
                                       (opt == Kint));
        lua_pushinteger(L, res);
        break;
      }
      case Kfloat: {
        volatile Ftypes u;
        lua_Number num;
        copywithendian(u.buff, data + pos, size, h.islittle);
        if (size == sizeof(u.f)) num = (lua_Number)u.f;
        else if (size == sizeof(u.d)) num = (lua_Number)u.d;
        else num = u.n;
        lua_pushnumber(L, num);
        break;
      }
      case Kchar: {
        lua_pushlstring(L, data + pos, size);
        break;
      }
      case Kstring: {
        size_t len = (size_t)unpackint(L, data + pos, h.islittle, size, 0);
        luaL_argcheck(L, pos + len + size <= ld, 2, "data string too short");
        lua_pushlstring(L, data + pos + size, len);
        pos += len;
        break;
      }
      case Kzstr: {
        size_t len = (int)strlen(data + pos);
        lua_pushlstring(L, data + pos, len);
        pos += len + 1;
        break;
      }
      case Kpaddalign: case Kpadding: case Knop:
        n--;
        break;
    }
    pos += size;
  }
  lua_pushinteger(L, pos + 1);
  return n + 1;
}

static const luaL_Reg strlib[] = {
  {"byte", str_byte},
  {"char", str_char},
  {"dump", str_dump},
  {"find", str_find},
  {"format", str_format},
  {"gmatch", gmatch},
  {"gsub", str_gsub},
  {"len", str_len},
  {"lower", str_lower},
  {"match", str_match},
  {"rep", str_rep},
  {"reverse", str_reverse},
  {"sub", str_sub},
  {"upper", str_upper},
  {"pack", str_pack},
  {"packsize", str_packsize},
  {"unpack", str_unpack},
  {NULL, NULL}
};

static void createmetatable (lua_State *L) {
  lua_createtable(L, 0, 1);
  lua_pushliteral(L, "");
  lua_pushvalue(L, -2);
  lua_setmetatable(L, -2);
  lua_pop(L, 1);
  lua_pushvalue(L, -2);
  lua_setfield(L, -2, "__index");
  lua_pop(L, 1);
}

LUAMOD_API int luaopen_string (lua_State *L) {
  luaL_newlib(L, strlib);
  createmetatable(L);
  return 1;
}
