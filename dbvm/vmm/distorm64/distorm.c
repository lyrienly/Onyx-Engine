#include "../config.h"
#include "decoder.h"
#include "x86defs.h"

#ifdef SUPPORT_64BIT_OFFSET
	_DLLEXPORT_ _DecodeResult distorm_decode64(_OffsetType codeOffset, const unsigned char* code, int codeLen, _DecodeType dt, _DecodedInst result[], unsigned int maxInstructions, unsigned int* usedInstructionsCount)
#else
	_DLLEXPORT_ _DecodeResult distorm_decode32(_OffsetType codeOffset, const unsigned char* code, int codeLen, _DecodeType dt, _DecodedInst result[], unsigned int maxInstructions, unsigned int* usedInstructionsCount)
#endif
{
	*usedInstructionsCount = 0;

	if (codeLen < 0) {
		return DECRES_INPUTERR;
	}

	if ((dt != Decode16Bits) && (dt != Decode32Bits) && (dt != Decode64Bits)) {
		return DECRES_INPUTERR;
	}

	if (code == NULL || result == NULL) {
		return DECRES_INPUTERR;
	}

	if (codeLen == 0) {
		return DECRES_SUCCESS;
	}

	if (maxInstructions < INST_MAXIMUM_SIZE) {
		return DECRES_MEMORYERR;
	}

	return internal_decode(codeOffset, code, codeLen, dt, result, maxInstructions, usedInstructionsCount);
}

_DLLEXPORT_ unsigned int distorm_version()
{
	return DISTORM_VER;
}
