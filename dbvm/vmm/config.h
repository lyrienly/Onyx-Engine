#ifndef CONFIG_H
#define CONFIG_H

#define DISTORM_VER 0x01071e
#define SUPPORT_64BIT_OFFSET 1

#define DARKBYTESFUCKEDUPCROSSCOMPILER 1

#ifdef DARKBYTESFUCKEDUPCROSSCOMPILER
typedef signed char int8_t;
typedef short int int16_t;
typedef int int32_t;
typedef long long int int64_t;
typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long int uint64_t;
#endif

#include "common.h"

#ifdef __GNUC__

#ifndef DARKBYTESFUCKEDUPCROSSCOMPILER
#include <stdint.h>
#endif

#define _PACKED_ __attribute__((__packed__))
#define _DLLEXPORT_
#define _FASTCALL_
#define _INLINE_ static __inline__

#ifdef __BIG_ENDIAN__
	#define BE_SYSTEM
#endif

#elif __WATCOMC__

#include <stdint.h>

#define _PACKED_
#define _DLLEXPORT_
#define _FASTCALL_
#define _INLINE_ __inline

#elif __DMC__

#include <stdint.h>

#define _PACKED_
#define _DLLEXPORT_
#define _FASTCALL_
#define _INLINE_ static __inline

#elif __TINYC__

#include <stdint.h>

#define _PACKED_
#define _DLLEXPORT_
#define _FASTCALL_
#define _INLINE_ static

#elif _MSC_VER

typedef signed __int64		int64_t;
typedef unsigned __int64	uint64_t;
typedef signed __int32		int32_t;
typedef unsigned __int32	uint32_t;
typedef signed __int16		int16_t;
typedef unsigned __int16	uint16_t;
typedef signed __int8		int8_t;
typedef unsigned __int8		uint8_t;

#define _PACKED_
#define _DLLEXPORT_ __declspec(dllexport)
#define _FASTCALL_ __fastcall
#define _INLINE_ static __inline

#ifndef _M_IX86
	#define BE_SYSTEM
#endif

#endif

#ifdef SUPPORT_64BIT_OFFSET
	#define OFFSET_INTEGER uint64_t
#else
	#define OFFSET_INTEGER uint32_t
#endif

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#ifndef _DLL
#undef _DLLEXPORT_
#define _DLLEXPORT_
#endif

#ifdef BE_SYSTEM

_INLINE_ int16_t RSHORT(const uint8_t *s)
{
	return s[0] | (s[1] << 8);
}
_INLINE_ uint16_t RUSHORT(const uint8_t *s)
{
	return s[0] | (s[1] << 8);
}
_INLINE_ int32_t RLONG(const uint8_t *s)
{
	return s[0] | (s[1] << 8) | (s[2] << 16) | (s[3] << 24);
}
_INLINE_ uint32_t RULONG(const uint8_t *s)
{
	return s[0] | (s[1] << 8) | (s[2] << 16) | (s[3] << 24);
}
#else

#define RSHORT(x) *(int16_t *)x
#define RUSHORT(x) *(uint16_t *)x
#define RLONG(x) *(int32_t *)x
#define RULONG(x) *(uint32_t *)x
#endif

#endif
