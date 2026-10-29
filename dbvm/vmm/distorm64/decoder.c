#include "decoder.h"

#include "prefix.h"
#include "textdefs.h"
#include "x86defs.h"
#include "operands.h"

_DecodeType ADDR_SIZE_AFFECT(_DecodeType dt, _iflags totalPrefixes)
{

	if (totalPrefixes & INST_PRE_ADDR_SIZE) {
		switch (dt)
		{
			case Decode16Bits:
				dt = Decode32Bits;
			break;
			case Decode32Bits:
				dt = Decode16Bits;
			break;
			case Decode64Bits:
				dt = Decode32Bits;
			break;
		}
	}

	return dt;
}

_DecodeType OP_SIZE_AFFECT(_DecodeType dt, _iflags totalPrefixes, unsigned int rex, _iflags instFlags)
{
	switch (dt)
	{
		case Decode16Bits:
			if (totalPrefixes & INST_PRE_OP_SIZE) dt = Decode32Bits;
		break;
		case Decode32Bits:
			if (totalPrefixes & INST_PRE_OP_SIZE) dt = Decode16Bits;
		break;
		case Decode64Bits:

			if (totalPrefixes & INST_PRE_OP_SIZE) dt = Decode16Bits;

			else if (((instFlags & (INST_64BITS | INST_PRE_REX)) == INST_64BITS) ||

			         ((totalPrefixes & INST_PRE_REX) && (rex & PREFIX_REX_W))) dt = Decode64Bits;
			else dt = Decode32Bits;
		break;
	}
	return dt;
}

static int decode_inst(const uint8_t* code, int codeLen, _OffsetType codeOffset,
                       _PrefixState* ps, _DecodeType dt, _DecodedInst* di)
{

	unsigned int modrm = 0;

	unsigned int rex = 0;

	_OffsetType lastCodeOffset = codeOffset;
	const uint8_t* lastCode = code;

	_InstInfo* ii = NULL;

	unsigned int cmpType = 0;

	_ExOpRCType rc = EO_HALT;

	int lockable = 0;

	int dummyLockable;

	int retCode = TRUE;

	_CodeInfo ci;

	memset(di, 0, sizeof(_DecodedInst));

	ii = locate_inst(&code, &codeLen, &codeOffset, &di->instructionHex, ps, dt);

	if (ii && (dt == Decode64Bits) && (ii->flags & INST_INVALID_64BITS)) ii = NULL;

	if (ii && (dt != Decode64Bits) && (ii->flags & INST_64BITS_FETCH)) ii = NULL;

	if (ii && (ii->d != OT_NONE) && (ii->d != OT_DUMMY) && (ii->flags & INST_INCLUDE_MODRM)) {
		modrm = *code;
		str_hex_b(&di->instructionHex, modrm);

		if (--codeLen < 0) ii = NULL;
		code++;
		codeOffset++;

		if (ii && (ii->flags & INST_MODRR) && (modrm < INST_DIVIDED_MODRM)) ii = NULL;
	}

	if (ps->isREXPrefixValid) rex = *ps->rexpos;

	if (ii == &II_90) {
		if ((dt != Decode64Bits) || (~rex & PREFIX_REX_B)) ii = &II_nop;
		if (rex & PREFIX_REX_W) ps->usedPrefixes |= INST_PRE_REX;
	}

	if (ii == &II_8D) ps->totalPrefixes &= ~(INST_PRE_SEGOVRD_MASK);

	ci.code = code;
	ci.codeLen = codeLen;
	ci.codeOffset = codeOffset;

	if (ii && (ii->d != OT_NONE) && (ii->d != OT_DUMMY)) {
		rc = extract_operand(&ci, &di->instructionHex, &di->operands, (_OpType)ii->d, (_OpType)ii->s, ONT_1, ii->flags, modrm, ps, dt, &lockable);
		if (rc == EO_HALT) ii = NULL;
	}

	if (ii && (ii->s != OT_NONE) && (ii->s != OT_DUMMY)) {
		strcat_WSN(&di->operands, SEP_STR);
		rc = extract_operand(&ci, &di->instructionHex, &di->operands, (_OpType)ii->s, (_OpType)ii->d, ONT_2, ii->flags, modrm, ps, dt, &dummyLockable);
		if (rc == EO_HALT) ii = NULL;
	}

	if (ii && (ii->flags & INST_USE_OP3) && (((_InstInfoEx*)ii)->op3 != OT_NONE) && (((_InstInfoEx*)ii)->op3 != OT_DUMMY)) {
		strcat_WSN(&di->operands, SEP_STR);
		rc = extract_operand(&ci, &di->instructionHex, &di->operands, (_OpType)((_InstInfoEx*)ii)->op3, OT_NONE, ONT_3, ii->flags, modrm, ps, dt, &dummyLockable);
		if (rc == EO_HALT) ii = NULL;
	}

	if (ii && (ii->flags & INST_USE_OP4)) {
		strcat_WSN(&di->operands, SEP_STR);
		rc = extract_operand(&ci, &di->instructionHex, &di->operands, (_OpType)((_InstInfoEx*)ii)->op4, OT_NONE, ONT_4, ii->flags, modrm, ps, dt, &dummyLockable);
		if (rc == EO_HALT) ii = NULL;
	}

	if ((di->operands.pos >= 2) && (di->operands.p[di->operands.pos-2] == SEP_CHR)) {
		di->operands.p[di->operands.pos-2] = '\0';
		di->operands.pos -= 2;
	}

	if (ii && ii->flags & INST_3DNOW_FETCH) ii = locate_3dnow_inst(&ci, &di->instructionHex);

	code = ci.code;
	codeLen = ci.codeLen;
	codeOffset = ci.codeOffset;

	if ((code - ps->start) > INST_MAXIMUM_SIZE) ii = NULL;

	if (ii && (ii->flags & INST_PSEUDO_OPCODE)) {
		cmpType = *code;

		if (cmpType >= INST_CMP_MAX_RANGE) ii = NULL;
		else str_hex_b(&di->instructionHex, cmpType);

		if (--codeLen < 0) ii = NULL;
		code++;
		codeOffset++;
	}

	if (ii) {

		strclear_WS(&di->mnemonic);

		if ((lockable == 1) && (ii->flags & INST_PRE_LOCK)) {
			ps->usedPrefixes |= INST_PRE_LOCK;

			strcpy_WSN(&di->mnemonic, PREFIX_LOCK_TEXT);
		} else if ((ii->flags & INST_PRE_REPNZ) && (ps->totalPrefixes & INST_PRE_REPNZ)) {
			ps->usedPrefixes |= INST_PRE_REPNZ;

			strcpy_WS(&di->mnemonic, PREFIX_REPNZ_TEXT);
		} else if ((ii->flags & INST_PRE_REP) && (ps->totalPrefixes & INST_PRE_REP)) {
			ps->usedPrefixes |= INST_PRE_REP;

			strcpy_WSN(&di->mnemonic, PREFIX_REP_TEXT);
		}

		if ((ii->flags & (INST_PRE_ADDR_SIZE | INST_USE_EXMNEMONIC)) == (INST_PRE_ADDR_SIZE | INST_USE_EXMNEMONIC)) {
			ps->usedPrefixes |= (ps->totalPrefixes & INST_PRE_ADDR_SIZE);
			if (ADDR_SIZE_AFFECT(dt, ps->totalPrefixes) == Decode16Bits) strcatlen_WS(&di->mnemonic, &ii->mnemonic[1], ii->mnemonic[0]);
			else if (ADDR_SIZE_AFFECT(dt, ps->totalPrefixes) == Decode32Bits) strcatlen_WS(&di->mnemonic, &((_InstInfoEx*)ii)->mnemonic2[1], ((_InstInfoEx*)ii)->mnemonic2[0]);

			else  strcatlen_WS(&di->mnemonic, &((_InstInfoEx*)ii)->mnemonic3[1], ((_InstInfoEx*)ii)->mnemonic3[0]);
		}

		else if ((ii->flags & (INST_PRE_ADDR_SIZE | INST_NATIVE)) == (INST_PRE_ADDR_SIZE | INST_NATIVE)) {
			strcpylen_WS(&di->mnemonic, &ii->mnemonic[1], ii->mnemonic[0]);

			if (ps->totalPrefixes & INST_PRE_ADDR_SIZE) {
				ps->usedPrefixes |= (ps->totalPrefixes & INST_PRE_ADDR_SIZE);
				if (ADDR_SIZE_AFFECT(dt, ps->totalPrefixes) == Decode16Bits) chrcat_WS(&di->mnemonic, SUFFIX_SIZE_WORD);
				else if (ADDR_SIZE_AFFECT(dt, ps->totalPrefixes) == Decode32Bits) chrcat_WS(&di->mnemonic, SUFFIX_SIZE_DWORD);
				else  chrcat_WS(&di->mnemonic, SUFFIX_SIZE_QWORD);
			}
		}

		else if (OP_SIZE_AFFECT(dt, ps->totalPrefixes, rex, ii->flags) == Decode16Bits) {

			if ((ii->flags & INST_USE_EXMNEMONIC) && ((ii->flags & (INST_32BITS | INST_64BITS)) == 0)) ps->usedPrefixes |= (ps->totalPrefixes & INST_PRE_OP_SIZE);
			strcatlen_WS(&di->mnemonic, &ii->mnemonic[1], ii->mnemonic[0]);

			if (rc == EO_SUFFIX) {

				if (ii->flags & INST_16BITS) chrcat_WS(&di->mnemonic, SUFFIX_SIZE_WORD);
				else chrcat_WS(&di->mnemonic, SUFFIX_SIZE_BYTE);
			}

			if ((ii->flags & INST_NATIVE) && (ps->totalPrefixes & INST_PRE_OP_SIZE)) {
				ps->usedPrefixes |= INST_PRE_OP_SIZE;

				chrcat_WS(&di->mnemonic, SUFFIX_SIZE_WORD);
			}
		} else if (OP_SIZE_AFFECT(dt, ps->totalPrefixes, rex, ii->flags) == Decode32Bits) {

			if (ii->flags & INST_USE_EXMNEMONIC) {
				ps->usedPrefixes |= (ps->totalPrefixes & INST_PRE_OP_SIZE);

				if (ii->flags & INST_MODRM_BASED) {
					if (modrm >= INST_DIVIDED_MODRM) strcatlen_WS(&di->mnemonic, &ii->mnemonic[1], ii->mnemonic[0]);
					else strcatlen_WS(&di->mnemonic, &((_InstInfoEx*)ii)->mnemonic2[1], ((_InstInfoEx*)ii)->mnemonic2[0]);
				}

				else if (ii->flags & INST_PSEUDO_OPCODE) {

					strcpylen_WS(&di->mnemonic, &ii->mnemonic[1], ii->mnemonic[0]);
					str_x86def(&di->mnemonic, &_CONDITIONS_PSEUDO[cmpType]);
					strcatlen_WS(&di->mnemonic, &((_InstInfoEx*)ii)->mnemonic2[1], ((_InstInfoEx*)ii)->mnemonic2[0]);

				} else strcatlen_WS(&di->mnemonic, &((_InstInfoEx*)ii)->mnemonic2[1], ((_InstInfoEx*)ii)->mnemonic2[0]);
			} else strcatlen_WS(&di->mnemonic, &ii->mnemonic[1], ii->mnemonic[0]);

			if (rc == EO_SUFFIX) {

				if (ii->flags & INST_16BITS) chrcat_WS(&di->mnemonic, SUFFIX_SIZE_DWORD);
				else chrcat_WS(&di->mnemonic, SUFFIX_SIZE_BYTE);
			}

			if ((ii->flags & INST_NATIVE) && (ps->totalPrefixes & INST_PRE_OP_SIZE)) {
				ps->usedPrefixes |= INST_PRE_OP_SIZE;

				chrcat_WS(&di->mnemonic, SUFFIX_SIZE_DWORD);
			}
		} else {

			if (ii->flags & (INST_USE_EXMNEMONIC | INST_USE_EXMNEMONIC2)) {

				if (ii->flags & INST_MODRM_BASED) {
					if (modrm >= INST_DIVIDED_MODRM) strcatlen_WS(&di->mnemonic, &ii->mnemonic[1], ii->mnemonic[0]);
					else strcatlen_WS(&di->mnemonic, &((_InstInfoEx*)ii)->mnemonic2[1], ((_InstInfoEx*)ii)->mnemonic2[0]);
				}

				else if (ii->flags & INST_PSEUDO_OPCODE) {

					strcpylen_WS(&di->mnemonic, &ii->mnemonic[1], ii->mnemonic[0]);
					str_x86def(&di->mnemonic, &_CONDITIONS_PSEUDO[cmpType]);
					strcatlen_WS(&di->mnemonic, &((_InstInfoEx*)ii)->mnemonic2[1], ((_InstInfoEx*)ii)->mnemonic2[0]);
				} else
					if ((ii->flags & INST_USE_EXMNEMONIC2) && (ps->isREXPrefixValid) && (rex & PREFIX_REX_W)) {
						ps->usedPrefixes |= INST_PRE_REX;
						strcatlen_WS(&di->mnemonic, &((_InstInfoEx*)ii)->mnemonic3[1], ((_InstInfoEx*)ii)->mnemonic3[0]);
					} else strcatlen_WS(&di->mnemonic, &((_InstInfoEx*)ii)->mnemonic2[1], ((_InstInfoEx*)ii)->mnemonic2[0]);
			} else strcatlen_WS(&di->mnemonic, &ii->mnemonic[1], ii->mnemonic[0]);

			if (rc == EO_SUFFIX) {

				if (ii->flags & INST_16BITS) {
					if (ii->flags & INST_64BITS) {
						ps->usedPrefixes |= INST_PRE_REX;
						chrcat_WS(&di->mnemonic, SUFFIX_SIZE_QWORD);
					}
					else chrcat_WS(&di->mnemonic, SUFFIX_SIZE_DWORD);
				}
				else chrcat_WS(&di->mnemonic, SUFFIX_SIZE_BYTE);
			}

			if (ii->flags & INST_NATIVE) {
				if (ps->totalPrefixes & INST_PRE_OP_SIZE) {
					ps->usedPrefixes |= INST_PRE_OP_SIZE;
					chrcat_WS(&di->mnemonic, SUFFIX_SIZE_WORD);
				}

				else if ((ps->totalPrefixes & INST_PRE_REX) && (rex & PREFIX_REX_W) && ((ii->flags & (INST_64BITS | INST_PRE_REX)) == (INST_64BITS | INST_PRE_REX))) {

					ps->usedPrefixes |= INST_PRE_REX;
					chrcat_WS(&di->mnemonic, SUFFIX_SIZE_QWORD);
				}
			}
		}
	}
	else {
		strclear_WS(&di->operands);

		if (*lastCode == WAIT_INSTRUCTION_CODE) {
			codeOffset = lastCodeOffset + 1;
			strcpy_WS(&di->instructionHex, get_hex_b(WAIT_INSTRUCTION_CODE));
			strcpy_WSN(&di->mnemonic, WAIT_INSTRUCTION_MNEMONIC);
			ps->usedPrefixes = 0;
		} else {

			codeOffset = lastCodeOffset + 1;
			strcpy_WS(&di->instructionHex, get_hex_b(*lastCode));

			strcpy_WSN(&di->mnemonic, BYTE_UNDEFINED);
			str_code_sp_hb(&di->mnemonic, *lastCode);

			ps->usedPrefixes = 0;

			retCode = FALSE;
		}
	}

	di->size = (unsigned int)(codeOffset - lastCodeOffset);
	return retCode;
}

_DecodeResult internal_decode(_OffsetType codeOffset, const uint8_t* code, int codeLen, _DecodeType dt, _DecodedInst result[], unsigned int maxResultCount, unsigned int* usedInstructionsCount)
{
	_PrefixState ps;
	unsigned int prefixSize;

	_OffsetType startCodeOffset = 0;

	_WString hex;
	int isInstructionPopped = FALSE;
	uint8_t unusedPrefixesList[MAX_PREFIXES];
	const uint8_t* p;
	unsigned int i;

	unsigned int nextPos = 0;
	_DecodedInst *pdi = NULL, di;

	*usedInstructionsCount = 0;

	while (codeLen > 0) {

		startCodeOffset = codeOffset;

		strclear_WS(&hex);

		memset(&ps, 0, sizeof(_PrefixState));
		ps.start = code;
		ps.last = code;
		prefixSize = 0;

		if (is_prefix(*code, dt)) {
			decode_prefixes(code, codeLen, &ps, dt);

			prefixSize = (int)(ps.last - ps.start);

			if (ps.start != code) {

				if (nextPos + (ps.start - code) > maxResultCount) return DECRES_MEMORYERR;

				for (p = code; p < ps.start; p++, codeOffset++, codeLen--, code++) {

					pdi = &result[nextPos++];

					strcpy_WSN(&pdi->mnemonic, BYTE_UNDEFINED);
					str_code_sp_hb(&pdi->mnemonic, *p);
					strclear_WS(&pdi->operands);
					strcpy_WS(&pdi->instructionHex, get_hex_b(*p));
					pdi->size = 1;
					pdi->offset = codeOffset;
				}
				*usedInstructionsCount = nextPos;

				startCodeOffset = codeOffset;
			}

			codeLen -= prefixSize;

			if (codeLen <= 0) {

				if (nextPos + (ps.last - code) > maxResultCount) return DECRES_MEMORYERR;

				for (p = code; p < ps.last; p++, startCodeOffset++) {

					pdi = &result[nextPos++];

					strcpy_WSN(&pdi->mnemonic, BYTE_UNDEFINED);
					str_code_sp_hb(&pdi->mnemonic, *p);
					strclear_WS(&pdi->operands);
					strcpy_WS(&pdi->instructionHex, get_hex_b(*p));
					pdi->size = 1;
					pdi->offset = startCodeOffset;
				}
				*usedInstructionsCount = nextPos;
				break;
			}
			code += prefixSize;
			codeOffset += prefixSize;

		}

		if (dt == Decode64Bits) {
			if (ps.totalPrefixes & INST_PRE_REX) {
				if (ps.rexpos != (code-1)) ps.totalPrefixes &= ~INST_PRE_REX;
				else {
					ps.isREXPrefixValid = 1;

					if (*ps.rexpos & PREFIX_REX_W) ps.totalPrefixes &= ~INST_PRE_OP_SIZE;
				}
			}

			ps.totalPrefixes &= ~(INST_PRE_CS | INST_PRE_SS | INST_PRE_DS | INST_PRE_ES);
		}

		if (nextPos + 1 > maxResultCount) return DECRES_MEMORYERR;

		if (prefixSize > 0) {

			pdi = &result[nextPos++];
			isInstructionPopped = FALSE;
			if (decode_inst(code, codeLen, codeOffset, &ps, dt, pdi)) {

				for (p = ps.start; p < ps.last; p++) {
					str_hex_b(&hex, *p);
					chrcat_WS(&hex, SP_CHR);
				}

				get_unused_prefixes_list(unusedPrefixesList, &ps);

				if (ps.unusedCount > 0) {
					if (nextPos + ps.unusedCount > maxResultCount) return DECRES_MEMORYERR;

					memcpy(&di, pdi, sizeof(_DecodedInst));
					isInstructionPopped = TRUE;
					nextPos--;

					for (i = 0; i < ps.unusedCount; i++) {

						pdi = &result[nextPos++];

						strcpy_WSN(&pdi->mnemonic, BYTE_UNDEFINED);
						str_code_sp_hb(&pdi->mnemonic, unusedPrefixesList[i]);
						strclear_WS(&pdi->operands);
						strcpy_WS(&pdi->instructionHex, get_hex_b(unusedPrefixesList[i]));
						pdi->size = 1;
						pdi->offset = startCodeOffset;
					}
				}

			} else {

				ps.last += ps.specialPrefixesSize;

				if (ps.last - ps.start > 0) {
					if (nextPos + (ps.last - ps.start) > maxResultCount) return DECRES_MEMORYERR;

					memcpy(&di, pdi, sizeof(_DecodedInst));
					isInstructionPopped = TRUE;
					nextPos--;

					for (p = ps.start; p < ps.last; p++, startCodeOffset++) {

						pdi = &result[nextPos++];

						strcpy_WSN(&pdi->mnemonic, BYTE_UNDEFINED);
						str_code_sp_hb(&pdi->mnemonic, *p);
						strclear_WS(&pdi->operands);
						strcpy_WS(&pdi->instructionHex, get_hex_b(*p));
						pdi->size = 1;
						pdi->offset = startCodeOffset;
					}
					prefixSize = 0;
					*usedInstructionsCount = nextPos;
				}
			}

			if (isInstructionPopped) {

				pdi = &result[nextPos++];
				memcpy(pdi, &di, sizeof(_DecodedInst));
			}

			codeLen -= pdi->size;
			codeOffset += pdi->size;
			code += pdi->size;

			pdi->size += prefixSize;
			pdi->offset = startCodeOffset;

			strcatlen_WS(&hex, (const int8_t*)pdi->instructionHex.p, pdi->instructionHex.pos);
			memcpy(&pdi->instructionHex.p, &hex.p, hex.pos + 1);

		} else {

			pdi = &result[nextPos++];
			decode_inst(code, codeLen, codeOffset, &ps, dt, pdi);
			pdi->offset = startCodeOffset;

			codeLen -= pdi->size;
			codeOffset += pdi->size;
			code += pdi->size;
		}

		*usedInstructionsCount = nextPos;
	}

	return DECRES_SUCCESS;
}
