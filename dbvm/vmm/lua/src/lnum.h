#ifndef lnum_h
#define lnum_h

#include "lobject.h"

#define luai_numadd(a,b)	((a)+(b))
#define luai_numsub(a,b)	((a)-(b))
#define luai_nummul(a,b)	((a)*(b))
#define luai_numdiv(a,b)	((a)/(b))
#define luai_nummod(a,b)	((a) - _LF(floor)((a)/(b))*(b))
#define luai_numpow(a,b)	(_LF(pow)(a,b))
#define luai_numunm(a)		(-(a))
#define luai_numeq(a,b)	    ((a)==(b))
#define luai_numlt(a,b)	    ((a)<(b))
#define luai_numle(a,b)	    ((a)<=(b))

#ifdef __FAST_MATH__
# define luai_numisnan(a) (0)
#elif (defined __STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)

#else
# define luai_numisnan(a) (!luai_numeq((a), (a)))
#endif

#ifdef LUA_TINT
  int try_addint( lua_Integer *r, lua_Integer ib, lua_Integer ic );
  int try_subint( lua_Integer *r, lua_Integer ib, lua_Integer ic );
  int try_mulint( lua_Integer *r, lua_Integer ib, lua_Integer ic );
  int try_divint( lua_Integer *r, lua_Integer ib, lua_Integer ic );
  int try_modint( lua_Integer *r, lua_Integer ib, lua_Integer ic );
  int try_powint( lua_Integer *r, lua_Integer ib, lua_Integer ic );
  int try_unmint( lua_Integer *r, lua_Integer ib );
#endif

#ifdef LNUM_COMPLEX
  static inline lua_Complex luai_vectunm( lua_Complex a ) { return -a; }
  static inline lua_Complex luai_vectadd( lua_Complex a, lua_Complex b ) { return a+b; }
  static inline lua_Complex luai_vectsub( lua_Complex a, lua_Complex b ) { return a-b; }
  static inline lua_Complex luai_vectmul( lua_Complex a, lua_Complex b ) { return a*b; }
  static inline lua_Complex luai_vectdiv( lua_Complex a, lua_Complex b ) { return a/b; }

  static inline
  lua_Complex luai_vectpow( lua_Complex a, lua_Complex b )
  {
    lua_Number ar= _LF(creal)(a), ai= _LF(cimag)(a);
    lua_Number br= _LF(creal)(b), bi= _LF(cimag)(b);

    if (ai==0 && bi==0) {
        return luai_numpow( ar, br );
    }

    int br_int= (int)br;

    if ( ai!=0 && bi==0 && br_int==br && br_int!=0 && br_int!=INT_MIN ) {

        lua_Number k= luai_numpow( _LF(sqrt) (ar*ar + ai*ai), br );
        lua_Number cos_z, sin_z;

      int br_int_abs = br_int<0 ? -br_int:br_int;

      switch( (br_int_abs%4) * (br_int<0 ? -1:1) * (ai<0 ? -1:1) ) {
        case 0:             cos_z=1, sin_z=0; break;
        case 2: case -2:    cos_z=-1, sin_z=0; break;
        case 1: case -3:    cos_z=0, sin_z=1; break;
        case 3: case -1:    cos_z=0, sin_z=-1; break;
        default:            lua_assert(0); return 0;
      }
      return k*cos_z + (k*sin_z)*I;
    }
    return _LF(cpow) ( a, b );
  }
#endif

LUAI_FUNC int luaO_str2d (const char *s, lua_Number *res1, lua_Integer *res2);
LUAI_FUNC void luaO_num2buf( char *s, const TValue *o );

LUAI_FUNC int  tt_integer_valued( const TValue *o, lua_Integer *ref );

#endif
