#ifndef PREFIX_H
#define PREFIX_H

#include "../config.h"

#include "decoder.h"
#include "wstring.h"

typedef struct {
	unsigned int unusedCount, specialPrefixesSize, isREXPrefixValid;
	_iflags totalPrefixes, usedPrefixes;
	const uint8_t *lokrepPos, *segovrdPos, *opsizePos, *addrsizePos, *rexpos, *start, *last;
} _PrefixState;

typedef enum {PRE_NONE = -1, PRE_LOKREP, PRE_SEGOVRD, PRE_OPSIZE, PRE_ADDRSIZE, PRE_REX} _PrefixType;

typedef struct {
	_iflags flag;
	_PrefixType type;
} _PrefixInfo;

#define MAX_PREFIXES (5)

int is_prefix(unsigned int ch, _DecodeType dt);
void decode_prefixes(const uint8_t* code, int codeLen, _PrefixState* ps, _DecodeType dt);
void get_unused_prefixes_list(uint8_t unusedList[MAX_PREFIXES], _PrefixState* ps);

void str_seg_text(_WString* s, _PrefixState* ps, _DecodeType dt);

#endif
