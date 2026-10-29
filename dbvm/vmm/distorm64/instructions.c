#include "instructions.h"

#include "insts.h"
#include "prefix.h"
#include "textdefs.h"
#include "x86defs.h"
#include "wstring.h"

static _InstInfo* locate_raw_inst(const uint8_t** code0, int* codeLen0, _OffsetType* codeOffset0, _WString* instructionHex, int isREXPrefixValid, _DecodeType dt)
{
	const uint8_t* code = *code0;
	int codeLen = *codeLen0;
	_OffsetType codeOffset = *codeOffset0;

	unsigned int tmpIndex0 = 0, tmpIndex1 = 0, tmpIndex2 = 0, tmpIndex3 = 0;
	_InstNode* in = NULL;
	_InstInfo* ii = NULL;

	if (codeLen <= 0) return NULL;

	tmpIndex0 = *code;

	in = (_InstNode*)Instructions.list[Instructions.ids[tmpIndex0]];
	if (in == NULL) return NULL;

	if (in->type == INT_INFO) {
		str_hex_b(instructionHex, tmpIndex0);

		codeLen -= 1;
		if (codeLen < 0) return NULL;
		code += 1;
		codeOffset += 1;
		*code0 = code;
		*codeLen0 = codeLen;
		*codeOffset0 = codeOffset;

		if (tmpIndex0 == INST_ARPL_INDEX) return ((dt == Decode64Bits) ? (_InstInfo*)&II_movsxd : &II_arpl);

		return (_InstInfo*)in;
	}

	if (in->type == INT_LIST_GROUP) {
		str_hex_b(instructionHex, tmpIndex0);

		codeLen -= 1;
		if (codeLen <= 0) return NULL;
		code += 1;
		codeOffset += 1;
		*code0 = code;
		*codeLen0 = codeLen;
		*codeOffset0 = codeOffset;
		return (_InstInfo*)in->list[in->ids[(*code >> 3) & 7]];
	}

	if (in->type == INT_LIST_DIVIDED) {
		str_hex_b(instructionHex, tmpIndex0);

		codeLen -= 1;
		if (codeLen <= 0) return NULL;
		code += 1;
		codeOffset += 1;

		tmpIndex1 = *code;

		if (tmpIndex1 < INST_DIVIDED_MODRM) {

			tmpIndex1 = (tmpIndex1 >> 3) & 7;
		} else {
			str_hex_b(instructionHex, tmpIndex1);

			codeLen -= 1;
			if (codeLen < 0) return NULL;
			code += 1;
			codeOffset += 1;

			tmpIndex1 -= INST_DIVIDED_MODRM - 8;
		}

		*code0 = code;
		*codeLen0 = codeLen;
		*codeOffset0 = codeOffset;
		return (_InstInfo*)in->list[in->ids[tmpIndex1]];
	}

	if (in->type == INT_LIST_FULL) {
		str_hex_b(instructionHex, tmpIndex0);

		if (isREXPrefixValid) {

			codeLen -= 1;
			if (codeLen <= 0) return NULL;
			code += 1;
			codeOffset += 1;
			str_hex_sp_b(instructionHex, *code);
			chrcat_WS(instructionHex, SP_CHR);
		}

		codeLen -= 1;
		if (codeLen <= 0) return NULL;
		code += 1;
		codeOffset += 1;

		tmpIndex1 = *code;
		in = (_InstNode*)in->list[in->ids[tmpIndex1]];

		if (in == NULL) return NULL;

		if ((tmpIndex0 == _3DNOW_ESCAPE_BYTE) && (tmpIndex1 == _3DNOW_ESCAPE_BYTE)) {
			str_hex_b(instructionHex, tmpIndex1);
			chrcat_WS(instructionHex, SP_CHR);

			codeLen -= 1;
			if (codeLen < 0) return NULL;
			code += 1;
			codeOffset += 1;

			*code0 = code;
			*codeLen0 = codeLen;
			*codeOffset0 = codeOffset;
			return &II_3dnow;
		}

		if (in->type == INT_INFO) {
			str_hex_b(instructionHex, tmpIndex1);

			codeLen -= 1;
			if (codeLen < 0) return NULL;
			code += 1;
			codeOffset += 1;

			*code0 = code;
			*codeLen0 = codeLen;
			*codeOffset0 = codeOffset;
			return (_InstInfo*)in;
		}

		if (in->type == INT_LIST_GROUP) {
			str_hex_b(instructionHex, tmpIndex1);

			codeLen -= 1;
			if (codeLen <= 0) return NULL;
			code += 1;
			codeOffset += 1;

			*code0 = code;
			*codeLen0 = codeLen;
			*codeOffset0 = codeOffset;
			return (_InstInfo*)in->list[in->ids[(*code >> 3) & 7]];
		}

		if (in->type == INT_LIST_DIVIDED) {
			str_hex_b(instructionHex, tmpIndex1);

			codeLen -= 1;
			if (codeLen <= 0) return NULL;
			code += 1;
			codeOffset += 1;

			tmpIndex2 = *code;
			ii = (_InstInfo*)in->list[in->ids[(tmpIndex2 >> 3) & 7]];

			if ((ii != NULL) && ((ii->flags & INST_NOT_DIVIDED) || (tmpIndex2 < INST_DIVIDED_MODRM))) ii = (_InstInfo*)in->list[in->ids[(tmpIndex2 >> 3) & 7]];
			else if (tmpIndex2 >= INST_DIVIDED_MODRM) ii = (_InstInfo*)in->list[in->ids[tmpIndex2 - INST_DIVIDED_MODRM + 8]];

			if ((ii != NULL) && ((ii->flags & INST_INCLUDE_MODRM) == 0)) {
				str_hex_b(instructionHex, tmpIndex2);

				codeLen -= 1;
				if (codeLen < 0) return NULL;
				code += 1;
				codeOffset += 1;
			}

			*code0 = code;
			*codeLen0 = codeLen;
			*codeOffset0 = codeOffset;
			return ii;
		}

		if (in->type == INT_LIST_FULL) {
			str_hex_b(instructionHex, tmpIndex1);

			codeLen -= 1;
			if (codeLen < 0) return NULL;
			code += 1;
			codeOffset += 1;

			tmpIndex2 = *code;

			in = (_InstNode*)in->list[in->ids[tmpIndex2]];

			if (in == NULL) return NULL;

			if (in->type == INT_INFO) {
				str_hex_b(instructionHex, tmpIndex2);

				codeLen -= 1;
				if (codeLen < 0) return NULL;
				code += 1;
				codeOffset += 1;

				*code0 = code;
				*codeLen0 = codeLen;
				*codeOffset0 = codeOffset;
				return (_InstInfo*)in;
			}

			if (in->type == INT_LIST_GROUP) {
				str_hex_b(instructionHex, tmpIndex2);

				codeLen -= 1;
				if (codeLen <= 0) return NULL;
				code += 1;
				codeOffset += 1;

				*code0 = code;
				*codeLen0 = codeLen;
				*codeOffset0 = codeOffset;
				return (_InstInfo*)in->list[in->ids[(*code >> 3) & 7]];
			}

			if (in->type == INT_LIST_FULL) {
				str_hex_b(instructionHex, tmpIndex2);

				codeLen -= 1;
				if (codeLen < 0) return NULL;
				code += 1;
				codeOffset += 1;
				tmpIndex3 = *code;

				in = (_InstNode*)in->list[in->ids[tmpIndex3]];

				if (in == NULL) return NULL;

				if (in->type == INT_INFO) {
					str_hex_b(instructionHex, tmpIndex3);

					codeLen -= 1;
					if (codeLen < 0) return NULL;
					code += 1;
					codeOffset += 1;

					*code0 = code;
					*codeLen0 = codeLen;
					*codeOffset0 = codeOffset;
					return (_InstInfo*)in;
				}
			}
		}
	}

	return NULL;
}

_InstInfo* locate_inst(const uint8_t** code,  int* codeLen, _OffsetType* codeOffset, _WString* instructionHex, _PrefixState* ps, _DecodeType dt)
{
	_InstInfo* ii = NULL;

	unsigned int lastCodeLen = *codeLen;
	_OffsetType lastCodeOffset = *codeOffset;
	const uint8_t* lastCode = *code;

	unsigned int lastBC = 0;

	if (ps->start < ps->last) {

		if (ps->isREXPrefixValid && (ps->start <= ps->last - 2)) lastBC = *(ps->last - 2);
		else lastBC = *(ps->last-1);
	}

	if ((lastBC == PREFIX_REP) || (lastBC == PREFIX_REPNZ) || (lastBC == PREFIX_OP_SIZE)) {

		if (ps->isREXPrefixValid) {
			(*code) -= 2;
			(*codeLen) += 2;
			(*codeOffset) -= 2;
		} else {
			(*code)--;
			(*codeLen)++;
			(*codeOffset)--;
		}
		ii = locate_raw_inst(code, codeLen, codeOffset, instructionHex, ps->isREXPrefixValid, dt);
		if (ii) {

			if (ps->isREXPrefixValid) {
				ps->last -= 2;
				ps->specialPrefixesSize = 2;
			}
			else {
				ps->last--;
				ps->specialPrefixesSize = 1;
			}

			switch (lastBC)
			{
				case PREFIX_REP: ps->totalPrefixes &= ~INST_PRE_LOKREP_MASK; ps->lokrepPos = NULL; break;
				case PREFIX_REPNZ: ps->totalPrefixes &= ~INST_PRE_LOKREP_MASK; ps->lokrepPos = NULL; break;
				case PREFIX_OP_SIZE: ps->totalPrefixes &= ~INST_PRE_OP_SIZE; ps->opsizePos = NULL; break;
			}
		} else {

			strclear_WS(instructionHex);
			*code = lastCode;
			*codeLen = lastCodeLen;
			*codeOffset = lastCodeOffset;
		}
	}

	if (ii == NULL) ii = locate_raw_inst(code, codeLen, codeOffset, instructionHex, 0, dt);
	return ii;
}

_InstInfo II_3dnow = {INT_INFO, ISCT_3DNOW, OT_MM64, OT_MM, (int8_t*) "\x0a" "_3DNow! II", INST_32BITS | INST_INCLUDE_MODRM | INST_3DNOW_FETCH};

_InstInfo* locate_3dnow_inst(_CodeInfo* ci, _WString* instructionHex)
{
	unsigned int tmpIndex2 = *ci->code;

	_InstNode* in = &Table_0F_0F;

	in = (_InstNode*)in->list[in->ids[tmpIndex2]];

	if ((in != NULL) && (in->type == INT_INFO)) {
		str_hex_sp_b(instructionHex, tmpIndex2);

		ci->codeLen -= 1;
		if (ci->codeLen < 0) return NULL;
		ci->code += 1;
		ci->codeOffset += 1;

		return (_InstInfo*)in;
	}

	return NULL;
}

void str_indirection_text(_WString* s, _OperandSizeType opSize)
{
	switch (opSize)
	{
		case OPERAND_SIZE_NONE: break;
		case OPERAND_SIZE8: strcat_WSN(s, TEXT_8_BITS); break;
		case OPERAND_SIZE16: strcat_WSN(s, TEXT_16_BITS); break;
		case OPERAND_SIZE32: strcat_WSN(s, TEXT_32_BITS); break;
		case OPERAND_SIZE64: strcat_WSN(s, TEXT_64_BITS); break;
		case OPERAND_SIZE80: strcat_WSN(s, TEXT_80_BITS); break;
		case OPERAND_SIZE128: strcat_WSN(s, TEXT_128_BITS); break;
	}
}
