#include "prefix.h"

#include "textdefs.h"
#include "x86defs.h"
#include "instructions.h"

int is_prefix(unsigned int ch, _DecodeType dt)
{
	switch (ch) {

		case 0x40:
		case 0x41:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0x45:
		case 0x46:
		case 0x47:
		case 0x48:
		case 0x49:
		case 0x4a:
		case 0x4b:
		case 0x4c:
		case 0x4d:
		case 0x4e:
		case 0x4f: return (dt == Decode64Bits);
		case PREFIX_LOCK: return TRUE;
		case PREFIX_REPNZ: return TRUE;
		case PREFIX_REP: return TRUE;
		case PREFIX_CS: return TRUE;
		case PREFIX_SS: return TRUE;
		case PREFIX_DS: return TRUE;
		case PREFIX_ES: return TRUE;
		case PREFIX_FS: return TRUE;
		case PREFIX_GS: return TRUE;
		case PREFIX_OP_SIZE: return TRUE;
		case PREFIX_ADDR_SIZE: return TRUE;
	}
	return FALSE;
}

static const uint8_t* PREFIX_MIN(const uint8_t* a, const uint8_t* b, const uint8_t* c, const uint8_t* d, const uint8_t* def)
{

	if (!a && !b && !c && !d) return def;
	if (!a) a = (const uint8_t*)~0;
	if (!b) b = (const uint8_t*)~0;
	if (!c) c = (const uint8_t*)~0;
	if (!d) d = (const uint8_t*)~0;

	if (b < a) a = b;
	if (c < a) a = c;
	if (d < a) a = d;
	return a == (const uint8_t*)~0 ? def : a;
}

void get_prefix_flag(unsigned int ch, _PrefixInfo* pi, _DecodeType dt)
{
	pi->flag = INST_FLAGS_NONE;
	pi->type = PRE_NONE;

	switch (ch)
	{

		case 0x40:
		case 0x41:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0x45:
		case 0x46:
		case 0x47:
		case 0x48:
		case 0x49:
		case 0x4a:
		case 0x4b:
		case 0x4c:
		case 0x4d:
		case 0x4e:
		case 0x4f:
			if (dt == Decode64Bits) {
				pi->flag = INST_PRE_REX;
				pi->type = PRE_REX;
			}
		break;

		case PREFIX_LOCK: pi->flag = INST_PRE_LOCK; pi->type = PRE_LOKREP; break;
		case PREFIX_REPNZ: pi->flag = INST_PRE_REPNZ; pi->type = PRE_LOKREP; break;
		case PREFIX_REP: pi->flag = INST_PRE_REP; pi->type = PRE_LOKREP; break;

		case PREFIX_CS: pi->flag = INST_PRE_CS; pi->type = PRE_SEGOVRD; break;
		case PREFIX_SS: pi->flag = INST_PRE_SS; pi->type = PRE_SEGOVRD; break;
		case PREFIX_DS: pi->flag = INST_PRE_DS; pi->type = PRE_SEGOVRD; break;
		case PREFIX_ES: pi->flag = INST_PRE_ES; pi->type = PRE_SEGOVRD; break;
		case PREFIX_FS: pi->flag = INST_PRE_FS; pi->type = PRE_SEGOVRD; break;
		case PREFIX_GS: pi->flag = INST_PRE_GS; pi->type = PRE_SEGOVRD; break;

		case PREFIX_OP_SIZE: pi->flag = INST_PRE_OP_SIZE; pi->type = PRE_OPSIZE; break;

		case PREFIX_ADDR_SIZE: pi->flag = INST_PRE_ADDR_SIZE; pi->type = PRE_ADDRSIZE; break;
	}
}

void decode_prefixes(const uint8_t* code, int codeLen, _PrefixState* ps, _DecodeType dt)
{

	_PrefixInfo pi;
	ps->start = code;

	while ((--codeLen >= 0) || (code - ps->start >= INST_MAXIMUM_SIZE)) {

		get_prefix_flag(*code, &pi, dt);
		if (pi.flag == INST_FLAGS_NONE) break;

		switch (pi.type)
		{
			case PRE_LOKREP:
				if ((ps->totalPrefixes & INST_PRE_LOKREP_MASK) != 0) {

					ps->totalPrefixes &= ~INST_PRE_LOKREP_MASK;

					if (ps->segovrdPos && ps->segovrdPos < ps->lokrepPos) {

						ps->totalPrefixes &= ~INST_PRE_SEGOVRD_MASK;
						ps->segovrdPos = NULL;
					}
					if (ps->opsizePos && ps->opsizePos < ps->lokrepPos) {
						ps->totalPrefixes &= ~INST_PRE_OP_SIZE;
						ps->opsizePos = NULL;
					}
					if (ps->addrsizePos && ps->addrsizePos < ps->lokrepPos) {
						ps->totalPrefixes &= ~INST_PRE_ADDR_SIZE;
						ps->addrsizePos = NULL;
					}
					if (ps->rexpos && ps->rexpos < ps->lokrepPos) {
						ps->totalPrefixes &= ~INST_PRE_REX;
						ps->rexpos = NULL;
					}

					ps->lokrepPos = code;

					ps->start = PREFIX_MIN(ps->segovrdPos, ps->opsizePos, ps->addrsizePos, ps->rexpos, ps->lokrepPos);
				} else {

					ps->lokrepPos = code;
				}

				ps->totalPrefixes |= pi.flag;
			break;
			case PRE_SEGOVRD:
				if ((ps->totalPrefixes & INST_PRE_SEGOVRD_MASK) != 0) {
					ps->totalPrefixes &= ~INST_PRE_SEGOVRD_MASK;

					if (ps->lokrepPos && ps->lokrepPos < ps->segovrdPos) {
						ps->totalPrefixes &= ~INST_PRE_LOKREP_MASK;
						ps->lokrepPos = NULL;
					}
					if (ps->opsizePos && ps->opsizePos < ps->segovrdPos) {
						ps->totalPrefixes &= ~INST_PRE_OP_SIZE;
						ps->opsizePos = NULL;
					}
					if (ps->addrsizePos && ps->addrsizePos < ps->segovrdPos) {
						ps->totalPrefixes &= ~INST_PRE_ADDR_SIZE;
						ps->addrsizePos = NULL;
					}
					if (ps->rexpos && ps->rexpos < ps->segovrdPos) {
						ps->totalPrefixes &= ~INST_PRE_REX;
						ps->rexpos = NULL;
					}
					ps->segovrdPos = code;
					ps->start = PREFIX_MIN(ps->lokrepPos, ps->opsizePos, ps->addrsizePos, ps->rexpos, ps->segovrdPos);
				} else {
					ps->segovrdPos = code;
				}
				ps->totalPrefixes |= pi.flag;
			break;
			case PRE_OPSIZE:
				if (ps->totalPrefixes & pi.flag) {
					if (ps->lokrepPos && ps->lokrepPos < ps->opsizePos) {
						ps->totalPrefixes &= ~INST_PRE_LOKREP_MASK;
						ps->lokrepPos =	NULL;
					}
					if (ps->segovrdPos && ps->segovrdPos < ps->opsizePos) {
						ps->totalPrefixes &= ~INST_PRE_SEGOVRD_MASK;
						ps->segovrdPos = NULL;
					}
					if (ps->addrsizePos && ps->addrsizePos < ps->opsizePos) {
						ps->totalPrefixes &= ~INST_PRE_ADDR_SIZE;
						ps->addrsizePos = NULL;
					}
					if (ps->rexpos && ps->rexpos < ps->opsizePos) {
						ps->totalPrefixes &= ~INST_PRE_REX;
						ps->rexpos = NULL;
					}
					ps->opsizePos = code;
					ps->start = PREFIX_MIN(ps->lokrepPos, ps->segovrdPos, ps->addrsizePos, ps->rexpos, ps->opsizePos);
				} else {
					ps->totalPrefixes |= pi.flag;
					ps->opsizePos = code;
				}
			break;
			case PRE_ADDRSIZE:
				if (ps->totalPrefixes & pi.flag) {
					if (ps->lokrepPos && ps->lokrepPos < ps->addrsizePos) {
						ps->totalPrefixes &= ~INST_PRE_LOKREP_MASK;
						ps->lokrepPos = NULL;
					}
					if (ps->segovrdPos && ps->segovrdPos < ps->addrsizePos) {
						ps->totalPrefixes &= ~INST_PRE_SEGOVRD_MASK;
						ps->segovrdPos = NULL;
					}
					if (ps->opsizePos && ps->opsizePos < ps->addrsizePos) {
						ps->totalPrefixes &= ~INST_PRE_OP_SIZE;
						ps->opsizePos = NULL;
					}
					if (ps->rexpos && ps->rexpos < ps->addrsizePos) {
						ps->totalPrefixes &= ~INST_PRE_REX;
						ps->rexpos = NULL;
					}
					ps->addrsizePos = code;
					ps->start = PREFIX_MIN(ps->lokrepPos, ps->segovrdPos, ps->opsizePos, ps->rexpos, ps->addrsizePos);
				} else {
					ps->totalPrefixes |= pi.flag;
					ps->addrsizePos = code;
				}
			break;
			case PRE_REX:
				if (ps->totalPrefixes & pi.flag) {
					if (ps->lokrepPos && ps->lokrepPos < ps->rexpos) {
						ps->totalPrefixes &= ~INST_PRE_LOKREP_MASK;
						ps->lokrepPos = NULL;
					}
					if (ps->segovrdPos && ps->segovrdPos < ps->rexpos) {
						ps->totalPrefixes &= ~INST_PRE_SEGOVRD_MASK;
						ps->segovrdPos = NULL;
					}
					if (ps->opsizePos && ps->opsizePos < ps->rexpos) {
						ps->totalPrefixes &= ~INST_PRE_OP_SIZE;
						ps->opsizePos = NULL;
					}
					if (ps->addrsizePos && ps->addrsizePos < ps->rexpos) {
						ps->totalPrefixes &= ~INST_PRE_ADDR_SIZE;
						ps->addrsizePos = NULL;
					}
					ps->rexpos = code;
					ps->start = PREFIX_MIN(ps->lokrepPos, ps->segovrdPos, ps->opsizePos, ps->addrsizePos, ps->rexpos);
				} else {
					ps->totalPrefixes |= pi.flag;
					ps->rexpos = code;
				}
				break;
				default: return;
		}
		code++;
	}

	ps->last = code;
}

void get_unused_prefixes_list(uint8_t unusedList[MAX_PREFIXES], _PrefixState* ps)
{

	const uint8_t* ptrs[MAX_PREFIXES] = {0};

	unsigned int i, j;
	const uint8_t* tmp = NULL;

	memset(unusedList, 0, MAX_PREFIXES);

	if (ps->rexpos != NULL) {
		ps->totalPrefixes |= INST_PRE_REX;

		if ((ps->opsizePos != NULL) && (*ps->rexpos & PREFIX_REX_W)) ps->totalPrefixes |= INST_PRE_OP_SIZE;
	}

	if ((ps->segovrdPos != NULL) && ((ps->totalPrefixes & (INST_PRE_SEGOVRD_MASK)) == 0)) {

		ps->totalPrefixes |= INST_PRE_CS;
	}

	ps->totalPrefixes &= ~ps->usedPrefixes;

	ps->unusedCount = 0;

	if (ps->totalPrefixes == ps->usedPrefixes) return ;

	if (ps->totalPrefixes & INST_PRE_OP_SIZE) ptrs[ps->unusedCount++] = ps->opsizePos;
	if (ps->totalPrefixes & INST_PRE_ADDR_SIZE) ptrs[ps->unusedCount++] = ps->addrsizePos;
	if (ps->totalPrefixes & INST_PRE_LOKREP_MASK) ptrs[ps->unusedCount++] = ps->lokrepPos;
	if (ps->totalPrefixes & INST_PRE_SEGOVRD_MASK) ptrs[ps->unusedCount++] = ps->segovrdPos;
	if (ps->totalPrefixes & INST_PRE_REX) ptrs[ps->unusedCount++] = ps->rexpos;

	for (i = 0; i < ps->unusedCount; i++) {
		for (j = 0; j < ps->unusedCount; j++) {
			if (ptrs[j] > ptrs[i]) {
				tmp = ptrs[j];
				ptrs[j] = ptrs[i];
				ptrs[i] = tmp;
			}
		}
	}

	for (i = 0; i < ps->unusedCount; i++)
		unusedList[i] = *ptrs[i];
}

void str_seg_text(_WString* s, _PrefixState* ps, _DecodeType dt)
{
	_iflags flags = ps->totalPrefixes & INST_PRE_SEGOVRD_MASK;

	if (flags == 0) return;

	if (dt != Decode64Bits) {
		switch (flags)
		{
			case INST_PRE_CS:
				ps->usedPrefixes |= INST_PRE_CS;
				strcat_WSN(s, PREFIX_CS_TEXT);
				chrcat_WS(s, SEG_OFF_CHR);
			return;
			case INST_PRE_SS:
				ps->usedPrefixes |= INST_PRE_SS;
				strcat_WSN(s, PREFIX_SS_TEXT);
				chrcat_WS(s, SEG_OFF_CHR);
			return;
			case INST_PRE_DS:
				ps->usedPrefixes |= INST_PRE_DS;
				strcat_WSN(s, PREFIX_DS_TEXT);
				chrcat_WS(s, SEG_OFF_CHR);
			return;
			case INST_PRE_ES:
				ps->usedPrefixes |= INST_PRE_ES;
				strcat_WSN(s, PREFIX_ES_TEXT);
				chrcat_WS(s, SEG_OFF_CHR);
			return;
		}
	}
	switch (flags)
	{
		case INST_PRE_FS:
			ps->usedPrefixes |= INST_PRE_FS;
			strcat_WSN(s, PREFIX_FS_TEXT);
			chrcat_WS(s, SEG_OFF_CHR);
		return;
		case INST_PRE_GS:
			ps->usedPrefixes |= INST_PRE_GS;
			strcat_WSN(s, PREFIX_GS_TEXT);
			chrcat_WS(s, SEG_OFF_CHR);
		return;
	}
}
