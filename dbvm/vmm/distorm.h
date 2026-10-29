#ifndef DISTORM_H
#define DISTORM_H

#include "config.h"

#ifndef __TINYC__

    #ifndef SUPPORT_64BIT_OFFSET
	    #define SUPPORT_64BIT_OFFSET
    #endif
#endif

#ifdef SUPPORT_64BIT_OFFSET
	#ifdef _MSC_VER
		#define OFFSET_INTEGER unsigned __int64
	#else
    #ifndef DARKBYTESFUCKEDUPCROSSCOMPILER
      #include <stdint.h>
    #endif
		#define OFFSET_INTEGER uint64_t
	#endif
#else

	#define OFFSET_INTEGER unsigned long
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {Decode16Bits = 0, Decode32Bits = 1, Decode64Bits = 2} _DecodeType;

typedef OFFSET_INTEGER _OffsetType;

#define MAX_TEXT_SIZE (60)
typedef struct {
	unsigned int length;
	unsigned char p[MAX_TEXT_SIZE];
} _WString;

typedef struct {
	_WString mnemonic;
	_WString operands;
	_WString instructionHex;
	unsigned int size;
	_OffsetType offset;
} _DecodedInst;

typedef enum {DECRES_NONE, DECRES_SUCCESS, DECRES_MEMORYERR, DECRES_INPUTERR} _DecodeResult;

#ifdef SUPPORT_64BIT_OFFSET
	_DecodeResult distorm_decode64(_OffsetType codeOffset, const unsigned char* code, int codeLen, _DecodeType dt, _DecodedInst result[], unsigned int maxInstructions, unsigned int* usedInstructionsCount);
	#define distorm_decode distorm_decode64
#else
	_DecodeResult distorm_decode32(_OffsetType codeOffset, const unsigned char* code, int codeLen, _DecodeType dt, _DecodedInst result[], unsigned int maxInstructions, unsigned int* usedInstructionsCount);
	#define distorm_decode distorm_decode32
#endif

unsigned int distorm_version();

#ifdef __cplusplus
}
#endif

#endif
