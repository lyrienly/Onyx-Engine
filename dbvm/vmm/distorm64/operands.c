#include "../config.h"

#include "operands.h"
#include "x86defs.h"

static int extract_sib(const uint8_t** code, int* codeLen, _OffsetType* codeOffset,
                       _WString* instructionHex, _WString* operandText,
                       _PrefixState* ps,_DecodeType dt,
                       unsigned int mod, unsigned int sib, _OperandSizeType opSize)
{
	unsigned int scale = 0, index = 0, base = 0, rex = 0;

	const uint8_t* code0 = *code;
	_iflags totalPrefixes = ps->totalPrefixes;

	scale = (sib >> 6) & 3;
	index = (sib >> 3) & 7;
	base = sib & 7;

	if (ps->isREXPrefixValid) rex = *ps->rexpos;

	str_indirection_text(operandText, opSize);
	str_seg_text(operandText, ps, dt);
	chrcat_WS(operandText, OPEN_CHR);

	if (base != 5) {
		if (rex & PREFIX_REX_B) ps->usedPrefixes |= INST_PRE_REX;
		if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode64Bits) str_x86def(operandText, &_BASE64[base + ((rex & PREFIX_REX_B) == PREFIX_REX_B ? REX_GPR_BASE : 0)]);
		else str_x86def(operandText, &_BASE32[base + ((rex & PREFIX_REX_B) == PREFIX_REX_B ? REX_GPR_BASE : 0)]);
	} else if (mod != 0) {

		if (rex & PREFIX_REX_B) ps->usedPrefixes |= INST_PRE_REX;
		if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode64Bits) str_x86def(operandText, &_BASE64[5 + ((rex & PREFIX_REX_B) == PREFIX_REX_B ? REX_GPR_BASE : 0)]);
		else str_x86def(operandText, &_BASE32[5 + ((rex & PREFIX_REX_B) == PREFIX_REX_B ? REX_GPR_BASE : 0)]);
	}

	if (rex & PREFIX_REX_X) {
		ps->usedPrefixes |= INST_PRE_REX;
		index += REX_GPR_BASE;
	}
	if (index != 4) {

		if ((mod != 0) || (base != 5)) chrcat_WS(operandText, PLUS_DISP_CHR);
		if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode64Bits) str_x86def(operandText, &_INDEX64[index]);
		else str_x86def(operandText, &_INDEX32[index]);
		str_x86def(operandText, &_SCALE32[scale]);
	}

	switch (mod)
	{
		case 0:

			if (base == 5) {

				*codeLen -= sizeof(int32_t);
				if (*codeLen < 0) return FALSE;
				str_hex_sp_dw(instructionHex, RULONG(code0));

				if (index != 4) {

					chrcat_WS(operandText, (RLONG(code0) >= 0) ? PLUS_DISP_CHR : MINUS_DISP_CHR);
					str_code_hdw(operandText, abs(RLONG(code0)));
				} else {
					str_code_hdw(operandText, RULONG(code0));
				}

				*code += sizeof(int32_t);
				*codeOffset += sizeof(int32_t);
			}
		break;
		case 1:

			*codeLen -= sizeof(int8_t);
			if (*codeLen < 0) return FALSE;
			str_hex_sp_b(instructionHex, *code0);

			chrcat_WS(operandText, (*(int8_t*)code0 >= 0) ? PLUS_DISP_CHR : MINUS_DISP_CHR);
			str_code_hb(operandText, abs(*(int8_t*)code0));

			*code += sizeof(int8_t);
			*codeOffset += sizeof(int8_t);
		break;
		case 2:

			*codeLen -= sizeof(int32_t);
			if (*codeLen < 0) return FALSE;
			str_hex_sp_dw(instructionHex, RULONG(code0));

			chrcat_WS(operandText, (RLONG(code0) >= 0) ? PLUS_DISP_CHR : MINUS_DISP_CHR);
			str_code_hdw(operandText, abs(RLONG(code0)));

			*code += sizeof(int32_t);
			*codeOffset += sizeof(int32_t);
		break;

	}

	chrcat_WS(operandText, CLOSE_CHR);
	return TRUE;
}

static int extract_modrm(_CodeInfo* ci,
                         _WString* instructionHex, _WString* operandText, _OpType type,
                         _OperandNumberType opNum, _PrefixState* ps, _DecodeType dt,
                         int* lockableInstruction, unsigned int mod, unsigned int rm,
                         _iflags instFlags, _OperandSizeType opSize)
{
	unsigned int sib = 0, rex = 0;

	const uint8_t* code = ci->code;
	int codeLen = ci->codeLen;
	_OffsetType codeOffset = ci->codeOffset;

	_iflags totalPrefixes = ps->totalPrefixes;

	if (ps->isREXPrefixValid) rex = *ps->rexpos;

	if (mod == 3)	{
		switch(type)
		{
			case OT_RFULL_M16:
			case OT_RM_FULL:
				switch (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags))
				{
					case Decode16Bits:
						ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);
						if (rex & PREFIX_REX_B) {
							ps->usedPrefixes |= INST_PRE_REX;
							rm += REX_GPR_BASE;
						}
						str_x86def(operandText, &_REGS16[rm]);
					break;
					case Decode32Bits:
						ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);
						if (rex & PREFIX_REX_B) {
							ps->usedPrefixes |= INST_PRE_REX;
							rm += REX_GPR_BASE;
						}
						str_x86def(operandText, &_REGS32[rm]);
					break;
					case Decode64Bits:

						if (type == OT_RFULL_M16) ps->usedPrefixes |= (totalPrefixes & INST_PRE_REX);

						if (instFlags & INST_PRE_REX) ps->usedPrefixes |= INST_PRE_REX;

						if (rex & PREFIX_REX_B) {
							ps->usedPrefixes |= INST_PRE_REX;
							rm += REX_GPR_BASE;
						}
						str_x86def(operandText, &_REGS64[rm]);
					break;
				}
			break;
			case OT_RM32:
				if (rex & PREFIX_REX_B) {
					ps->usedPrefixes |= INST_PRE_REX;
					rm += REX_GPR_BASE;
				}
				str_x86def(operandText, &_REGS32[rm]);
			break;

			case OT_R32_64_M8:

			case OT_R32_64_M16:

			case OT_RM32_64:
				if (rex & PREFIX_REX_B) {
					ps->usedPrefixes |= INST_PRE_REX;
					rm += REX_GPR_BASE;
				}

				if ((dt == Decode64Bits) && ((instFlags & (INST_64BITS | INST_PRE_REX)) == INST_64BITS)) {
					str_x86def(operandText, &_REGS64[rm]);
					break;
				}

				if (rex & PREFIX_REX_W) {
					ps->usedPrefixes |= INST_PRE_REX;
					str_x86def(operandText, &_REGS64[rm]);
				} else str_x86def(operandText, &_REGS32[rm]);
			break;
			case OT_RM16_32:
				if (rex & PREFIX_REX_B) {
					ps->usedPrefixes |= INST_PRE_REX;
					rm += REX_GPR_BASE;
				}

				if (ps->totalPrefixes & INST_PRE_OP_SIZE) {
					ps->usedPrefixes |= INST_PRE_OP_SIZE;
					str_x86def(operandText, &_REGS16[rm]);
				} else str_x86def(operandText, &_REGS32[rm]);
			break;
			case OT_RM16:
				if (rex & PREFIX_REX_B) {
					ps->usedPrefixes |= INST_PRE_REX;
					rm += REX_GPR_BASE;
				}
				str_x86def(operandText, &_REGS16[rm]);
			break;
			case OT_RM8:
				if (ps->isREXPrefixValid) {
					ps->usedPrefixes |= INST_PRE_REX;
					str_x86def(operandText, &_REGS8_REX[rm + ((rex & PREFIX_REX_B) == PREFIX_REX_B ? REX_GPR_BASE : 0)]);
				} else str_x86def(operandText, &_REGS8[rm]);
			break;
			case OT_MM32:
			case OT_MM64:

				str_x86def(operandText, &_REGSMMX[rm]);
			break;
			case OT_XMM16:
			case OT_XMM32:
			case OT_XMM64:
			case OT_XMM128:
				if (rex & PREFIX_REX_B) {
					ps->usedPrefixes |= INST_PRE_REX;
					rm += REX_GPR_BASE;
				}
				str_x86def(operandText, &_REGSSSE[rm]);
			break;
			case OT_R32_M8:

			case OT_R32_M16:
				if (rex & PREFIX_REX_B) {
					ps->usedPrefixes |= INST_PRE_REX;
					rm += REX_GPR_BASE;
				}
				if (dt == Decode16Bits) str_x86def(operandText, &_REGS16[rm]);
				else str_x86def(operandText, &_REGS32[rm]);
			break;
			default: return FALSE;
		}

		ci->code = code;
		ci->codeLen = codeLen;
		ci->codeOffset = codeOffset;

		return TRUE;
	}

	if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode16Bits) {

		switch (mod)
		{
			case 0x00:
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_ADDR_SIZE);
				if ((opNum == ONT_1) && (totalPrefixes & INST_PRE_LOCK)) *lockableInstruction = 1;

				if (rm == 6) {

					codeLen -= sizeof(int16_t);
					if (codeLen < 0) return FALSE;
					str_hex_sp_w(instructionHex, RUSHORT(code));

					str_indirection_text(operandText, opSize);
					str_seg_text(operandText, ps, dt);
					chrcat_WS(operandText, OPEN_CHR);
					str_code_hw(operandText, RUSHORT(code));
					chrcat_WS(operandText, CLOSE_CHR);

					code += sizeof(int16_t);
					codeOffset += sizeof(int16_t);
				} else {
					str_indirection_text(operandText, opSize);
					str_seg_text(operandText, ps, dt);
					str_x86def(operandText, &_MODS16[rm]);
					chrcat_WS(operandText, CLOSE_CHR);
				}
			break;
			case 0x01:
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_ADDR_SIZE);
				if ((opNum == ONT_1) && (totalPrefixes & INST_PRE_LOCK)) *lockableInstruction = 1;

				codeLen -= sizeof(int8_t);
				if (codeLen < 0) return FALSE;
				str_hex_sp_b(instructionHex, *code);

				str_indirection_text(operandText, opSize);
				str_seg_text(operandText, ps, dt);
				str_x86def(operandText, &_MODS16[rm]);

				chrcat_WS(operandText, (*(int8_t*)code >= 0) ? PLUS_DISP_CHR : MINUS_DISP_CHR);
				str_code_hb(operandText, abs(*(int8_t*)code));
				chrcat_WS(operandText, CLOSE_CHR);

				code += sizeof(int8_t);
				codeOffset += sizeof(int8_t);
			break;
			case 0x02:
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_ADDR_SIZE);
				if ((opNum == ONT_1) && (totalPrefixes & INST_PRE_LOCK)) *lockableInstruction = 1;

				codeLen -= sizeof(int16_t);
				if (codeLen < 0) return FALSE;
				str_hex_sp_w(instructionHex, RUSHORT(code));

				str_indirection_text(operandText, opSize);
				str_seg_text(operandText, ps, dt);
				str_x86def(operandText, &_MODS16[rm]);

				chrcat_WS(operandText, (RSHORT(code) >= 0) ? PLUS_DISP_CHR : MINUS_DISP_CHR);
				str_code_hw(operandText, abs(RSHORT(code)));
				chrcat_WS(operandText, CLOSE_CHR);

				code += sizeof(int16_t);
				codeOffset += sizeof(int16_t);
			break;
		}
	} else {

		switch (mod)
		{
			case 0x00:
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_ADDR_SIZE);
				if ((opNum == ONT_1) && (totalPrefixes & INST_PRE_LOCK)) *lockableInstruction = 1;

				if (rm == 4) {

					if (--codeLen < 0) return FALSE;
					sib = *code;
					str_hex_b(instructionHex, sib);

					code += sizeof(int8_t);
					codeOffset += sizeof(int8_t);

					if (!extract_sib(&code, &codeLen, &codeOffset, instructionHex, operandText, ps, dt, mod, sib, opSize)) return FALSE;
				} else if (rm == 5) {
					ps->usedPrefixes |= (totalPrefixes & INST_PRE_ADDR_SIZE);

					codeLen -= sizeof(int32_t);
					if (codeLen < 0) return FALSE;
					str_hex_sp_dw(instructionHex, RULONG(code));

					str_indirection_text(operandText, opSize);
					str_seg_text(operandText, ps, dt);
					chrcat_WS(operandText, OPEN_CHR);
					if (dt == Decode64Bits) {

						strcat_WSN(operandText, REG_RIP_TEXT);

						chrcat_WS(operandText, (RLONG(code) >= 0) ? PLUS_DISP_CHR : MINUS_DISP_CHR);
						str_code_hdw(operandText, abs(RLONG(code)));
					} else {

						str_code_hdw(operandText, RULONG(code));
					}
					chrcat_WS(operandText, CLOSE_CHR);

					code += sizeof(int32_t);
					codeOffset += sizeof(int32_t);
				} else {
					str_indirection_text(operandText, opSize);
					str_seg_text(operandText, ps, dt);
					if (rex & PREFIX_REX_B) {
						ps->usedPrefixes |= INST_PRE_REX;
						rm += REX_GPR_BASE;
					}
					if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode64Bits) str_x86def(operandText, &_MODS64[rm]);
					else str_x86def(operandText, &_MODS32[rm]);
					chrcat_WS(operandText, CLOSE_CHR);
				}
			break;
			case 0x01:
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_ADDR_SIZE);
				if ((opNum == ONT_1) && (totalPrefixes & INST_PRE_LOCK)) *lockableInstruction = 1;

				if (rm == 4) {

					if (--codeLen < 0) return FALSE;
					sib = *code;
					str_hex_b(instructionHex, sib);

					code += sizeof(int8_t);
					codeOffset += sizeof(int8_t);
					if (!extract_sib(&code, &codeLen, &codeOffset, instructionHex, operandText, ps, dt, mod, sib, opSize)) return FALSE;
				} else {
					codeLen -= sizeof(int8_t);
					if (codeLen < 0) return FALSE;
					str_hex_sp_b(instructionHex, *code);

					str_indirection_text(operandText, opSize);
					str_seg_text(operandText, ps, dt);
					if (rex & PREFIX_REX_B) {
						ps->usedPrefixes |= INST_PRE_REX;
						rm += REX_GPR_BASE;
					}
					if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode64Bits) str_x86def(operandText, &_MODS64[rm]);
					else str_x86def(operandText, &_MODS32[rm]);
					chrcat_WS(operandText, (*(int8_t*)code >= 0) ? PLUS_DISP_CHR : MINUS_DISP_CHR);
					str_code_hb(operandText, abs(*(int8_t*)code));
					chrcat_WS(operandText, CLOSE_CHR);

					code += sizeof(int8_t);
					codeOffset += sizeof(int8_t);
				}
			break;
			case 0x02:
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_ADDR_SIZE);
				if ((opNum == ONT_1) && (totalPrefixes & INST_PRE_LOCK)) *lockableInstruction = 1;

				if (rm == 4) {

					if (--codeLen < 0) return FALSE;
					sib = *code;
					str_hex_b(instructionHex, sib);

					code += sizeof(int8_t);
					codeOffset += sizeof(int8_t);
					if (!extract_sib(&code, &codeLen, &codeOffset, instructionHex, operandText, ps, dt, mod, sib, opSize)) return FALSE;
				} else {
					codeLen -= sizeof(int32_t);
					if (codeLen < 0) return FALSE;
					str_hex_sp_dw(instructionHex, RULONG(code));

					str_indirection_text(operandText, opSize);
					str_seg_text(operandText, ps, dt);
					if (rex & PREFIX_REX_B) {
						ps->usedPrefixes |= INST_PRE_REX;
						rm += REX_GPR_BASE;
					}
					if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode64Bits)str_x86def(operandText, &_MODS64[rm]);
					else str_x86def(operandText, &_MODS32[rm]);

					chrcat_WS(operandText, (RLONG(code) >= 0) ? PLUS_DISP_CHR : MINUS_DISP_CHR);
					str_code_hdw(operandText, abs(RLONG(code)));
					chrcat_WS(operandText, CLOSE_CHR);

					code += sizeof(int32_t);
					codeOffset += sizeof(int32_t);
				}
			break;
			default: return FALSE;
		}
	}

	ci->code = code;
	ci->codeLen = codeLen;
	ci->codeOffset = codeOffset;

	return TRUE;
}

_ExOpRCType extract_operand(_CodeInfo* ci,
                            _WString* instructionHex, _WString* operandText, _OpType type, _OpType op2,
                            _OperandNumberType opNum, _iflags instFlags, unsigned int modrm,
                            _PrefixState* ps, _DecodeType dt, int* lockableInstruction)
{
	unsigned int mod = 0, reg = 0, rm = 0;

	_iflags tmpPrefixes = 0;
	_iflags totalPrefixes = ps->totalPrefixes;

	const uint8_t* code = ci->code;
	int codeLen = ci->codeLen;
	_OffsetType codeOffset = ci->codeOffset;

	int32_t joff = 0;
	_OffsetType reloff = 0;

	unsigned int rex = 0;

	_OperandSizeType opSize = OPERAND_SIZE_NONE;

	*lockableInstruction = 0;

	mod = (modrm >> 6) & 3;
	reg = (modrm >> 3) & 7;
	rm = modrm & 7;

	if (ps->isREXPrefixValid) rex = *ps->rexpos;

	switch (type)
	{
		case OT_IMM8:
			codeLen -= sizeof(int8_t);
			if (codeLen < 0) return EO_HALT;
			str_hex_sp_b(instructionHex, *code);

			str_code_hb(operandText, *code);
			code += sizeof(int8_t);
			codeOffset += sizeof(int8_t);
		break;
		case OT_IMM_FULL:
			if (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode16Bits) {
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);

		case OT_IMM16:
			codeLen -= sizeof(int16_t);
			if (codeLen < 0) return EO_HALT;
			str_hex_sp_w(instructionHex, RUSHORT(code));

			str_code_hw(operandText, RUSHORT(code));
			code += sizeof(int16_t);
			codeOffset += sizeof(int16_t);
		break;

			} else if ((OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode64Bits) &&
				        ((instFlags & (INST_64BITS | INST_PRE_REX)) == (INST_64BITS | INST_PRE_REX))) {
				ps->usedPrefixes |= INST_PRE_REX;

				codeLen -= sizeof(int32_t)*2;
				if (codeLen < 0) return EO_HALT;
				str_hex_sp_qw(instructionHex, (uint8_t*)code);

				str_code_hqw(operandText, (uint8_t*)code);
				code += sizeof(int32_t)*2;
				codeOffset += sizeof(int32_t)*2;
				break;
			} else ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);

		case OT_IMM32:
			codeLen -= sizeof(int32_t);
			if (codeLen < 0) return EO_HALT;
			str_hex_sp_dw(instructionHex, RULONG(code));

			if (dt == Decode64Bits) {

				if (RLONG(code) < 0) chrcat_WS(operandText, MINUS_DISP_CHR);
				str_code_hdw(operandText, abs(RLONG(code)));
			} else {
				str_code_hdw(operandText, RULONG(code));
			}

			code += sizeof(int32_t);
			codeOffset += sizeof(int32_t);
		break;
		case OT_IMM_AADM:
			codeLen -= sizeof(int8_t);
			if (codeLen < 0) return EO_HALT;
			str_hex_sp_b(instructionHex, *code);

			if (*code != 0xa) str_code_hb(operandText, *code);
			code += sizeof(int8_t);
			codeOffset += sizeof(int8_t);
		break;
		case OT_SEIMM8:
			codeLen -= sizeof(int8_t);
			if (codeLen < 0) return EO_HALT;
			str_hex_sp_b(instructionHex, *code);

			if ((instFlags & INST_PRE_OP_SIZE) && (totalPrefixes & INST_PRE_OP_SIZE)) {
				ps->usedPrefixes |= INST_PRE_OP_SIZE;
				switch (dt)
				{
					case Decode16Bits:
						strcat_WSN(operandText, LARGE_OPERAND);
					break;
					case Decode32Bits:
					case Decode64Bits:
						strcat_WSN(operandText, SMALL_OPERAND);
					break;
				}
			}

			if (*(int8_t*)code < 0) chrcat_WS(operandText, MINUS_DISP_CHR);
			str_code_hb(operandText, abs(*(int8_t*)code));

			code += sizeof(int8_t);
			codeOffset += sizeof(int8_t);
		break;
		case OT_REG8:
			if (ps->isREXPrefixValid) {

				ps->usedPrefixes |= INST_PRE_REX;
				str_x86def(operandText, &_REGS8_REX[reg + ((rex & PREFIX_REX_R) == PREFIX_REX_R ? REX_GPR_BASE : 0)]);
			} else str_x86def(operandText, &_REGS8[reg]);
		break;
		case OT_REG16:
			if (rex & PREFIX_REX_R) {
				ps->usedPrefixes |= INST_PRE_REX;
				reg += REX_GPR_BASE;
			}
			str_x86def(operandText, &_REGS16[reg]);
		break;
		case OT_REG_FULL:
			switch (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags))
			{
				case Decode16Bits:
					ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);
					if (rex & PREFIX_REX_R) {
						ps->usedPrefixes |= INST_PRE_REX;
						reg += REX_GPR_BASE;
					}
					str_x86def(operandText, &_REGS16[reg]);
				break;
				case Decode32Bits:
					if (rex & PREFIX_REX_R) {
						ps->usedPrefixes |= INST_PRE_REX;
						reg += REX_GPR_BASE;
					} else ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);
					str_x86def(operandText, &_REGS32[reg]);
				break;
				case Decode64Bits:
					ps->usedPrefixes |= INST_PRE_REX;
					str_x86def(operandText, &_REGS64[reg + ((rex & PREFIX_REX_R) == PREFIX_REX_R ? REX_GPR_BASE : 0)]);
				break;
			}
		break;
		case OT_REG32:
			if (rex & PREFIX_REX_R) {
				ps->usedPrefixes |= INST_PRE_REX;
				reg += REX_GPR_BASE;
			}
			str_x86def(operandText, &_REGS32[reg]);
		break;
		case OT_REG32_64:
			if (rex & PREFIX_REX_R) {
				ps->usedPrefixes |= INST_PRE_REX;
				reg += REX_GPR_BASE;
			}

			if ((dt == Decode64Bits) && ((instFlags & (INST_64BITS | INST_PRE_REX)) == INST_64BITS)) {
				str_x86def(operandText, &_REGS64[reg]);
				break;
			}

			if (rex & PREFIX_REX_W) {
				ps->usedPrefixes |= INST_PRE_REX;
				str_x86def(operandText, &_REGS64[reg]);
			} else str_x86def(operandText, &_REGS32[reg]);
		break;
		case OT_REG64:

			if (rex & PREFIX_REX_R) {
				ps->usedPrefixes |= INST_PRE_REX;
				reg += REX_GPR_BASE;
			}
			str_x86def(operandText, &_REGS64[reg]);
		break;
		case OT_REG32_RM:
			if (rex & PREFIX_REX_B) {
				ps->usedPrefixes |= INST_PRE_REX;
				rm += REX_GPR_BASE;
			}
			str_x86def(operandText, &_REGS32[rm]);
		break;
		case OT_FREG32_64_RM:
			if (rex & PREFIX_REX_B) {
				ps->usedPrefixes |= INST_PRE_REX;
				rm += REX_GPR_BASE;
			}
			if (dt == Decode64Bits) str_x86def(operandText, &_REGS64[rm]);
			else str_x86def(operandText, &_REGS32[rm]);
		break;
		case OT_MM:
			str_x86def(operandText, &_REGSMMX[reg]);
		break;
		case OT_MM_RM:
			str_x86def(operandText, &_REGSMMX[rm]);
		break;
		case OT_XMM:
			if (rex & PREFIX_REX_R) {
				ps->usedPrefixes |= INST_PRE_REX;
				reg += REX_GPR_BASE;
			}
			str_x86def(operandText, &_REGSSSE[reg]);
		break;
		case OT_XMM_RM:
			if (rex & PREFIX_REX_B) {
				ps->usedPrefixes |= INST_PRE_REX;
				rm += REX_GPR_BASE;
			}
			str_x86def(operandText, &_REGSSSE[rm]);
		break;
		case OT_REGXMM0:
			str_x86def(operandText, &_REGSSSE[0]);
		break;

		case OT_MEM64_128:

			if ((opNum == ONT_1) && (totalPrefixes & INST_PRE_LOCK)) *lockableInstruction = 1;
			if (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode64Bits) {
				ps->usedPrefixes |= INST_PRE_REX;
				opSize = OPERAND_SIZE128;
			} else opSize = OPERAND_SIZE64;
		goto _FilterMod;
		case OT_MEM32: opSize = OPERAND_SIZE32; goto _FilterMod;
		case OT_MEM64: opSize = OPERAND_SIZE64; goto _FilterMod;
		case OT_MEM128: opSize = OPERAND_SIZE128; goto _FilterMod;
		case OT_MEM16_FULL:
			switch (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags))
			{
				case Decode16Bits:
					ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);
					opSize = OPERAND_SIZE16;
				break;
				case Decode32Bits:
					ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);
					opSize = OPERAND_SIZE32;
				break;
				case Decode64Bits:

					if ((instFlags & (INST_64BITS | INST_PRE_REX)) == (INST_64BITS | INST_PRE_REX)) ps->usedPrefixes |= INST_PRE_REX;
					opSize = OPERAND_SIZE64;
				break;
			}
		goto _FilterMod;
		case OT_MEM16_3264:
			if (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode64Bits) {

				if ((instFlags & INST_64BITS) == 0) ps->usedPrefixes |= INST_PRE_REX;
				opSize = OPERAND_SIZE64;
			} else {
				opSize = OPERAND_SIZE32;
			}
		goto _FilterMod;
		case OT_FPUM16: opSize = OPERAND_SIZE16; goto _FilterMod;
		case OT_FPUM32: opSize = OPERAND_SIZE32; goto _FilterMod;
		case OT_FPUM64: opSize = OPERAND_SIZE64; goto _FilterMod;
		case OT_FPUM80: opSize = OPERAND_SIZE80;
		case OT_MEM32_64:
		case OT_MEM:
_FilterMod:

			if (mod == 0x3) {
				*lockableInstruction = 0;
				return EO_HALT;
			}
			goto _ExtractModRM;
		case OT_RM8:
			if (op2 == OT_NONE || op2 == OT_IMM8 || op2 == OT_IMM_FULL || op2 == OT_IMM32 ||
			    op2 == OT_SEIMM8 || op2 == OT_REGCL || op2 == OT_CONST1 ||
			    (op2 == OT_REG_FULL && mod != 3) || op2 == OT_REG32_64) opSize = OPERAND_SIZE8;
			goto _ExtractModRM;
		case OT_RM_FULL:
			if (op2 == OT_NONE || op2 == OT_IMM8 || op2 == OT_IMM_FULL || op2 == OT_IMM32 ||
			    op2 == OT_SEIMM8 || op2 == OT_REGCL || op2 == OT_CONST1 || op2 == OT_REG32_64) {
				ps->usedPrefixes |= (ps->totalPrefixes & INST_PRE_OP_SIZE);

				if (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode32Bits) {
					opSize = OPERAND_SIZE32;
					goto _ExtractModRM;
				} else if (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode64Bits) {

					if ((instFlags & INST_64BITS) == 0) ps->usedPrefixes |= INST_PRE_REX;
					opSize = OPERAND_SIZE64;
					goto _ExtractModRM;
				}
			} else goto _ExtractModRM;

		case OT_RM16:
			if (op2 == OT_NONE || op2 == OT_IMM8 || op2 == OT_IMM_FULL || op2 == OT_IMM32 ||
			    op2 == OT_SEIMM8 || op2 == OT_REGCL || op2 == OT_CONST1 || op2 == OT_REG32_64) {

				if (type != OT_RM16) ps->usedPrefixes |= (ps->totalPrefixes & INST_PRE_OP_SIZE);
				opSize = OPERAND_SIZE16;
			}
			goto _ExtractModRM;
		case OT_RM32:
			if (op2 == OT_NONE || op2 == OT_IMM8 || op2 == OT_IMM_FULL || op2 == OT_IMM32 ||
			    op2 == OT_SEIMM8 || op2 == OT_REGCL || op2 == OT_CONST1) {
				opSize = OPERAND_SIZE32;
			}
			goto _ExtractModRM;
		case OT_RM32_64:

			if (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode64Bits) {
				opSize = OPERAND_SIZE64;

				if ((instFlags & (INST_64BITS | INST_PRE_REX)) == (INST_64BITS | INST_PRE_REX)) {
					ps->usedPrefixes |= INST_PRE_REX;
				}
			}
			else opSize = OPERAND_SIZE32;
			goto _ExtractModRM;
		case OT_RM16_32:

			if (ps->totalPrefixes & INST_PRE_OP_SIZE) {
				ps->usedPrefixes |= INST_PRE_OP_SIZE;
				opSize = OPERAND_SIZE16;
			}
			else opSize = OPERAND_SIZE_NONE;
			goto _ExtractModRM;
		case OT_R32_M8: opSize = OPERAND_SIZE8; goto _ExtractModRM;
		case OT_R32_M16: opSize = OPERAND_SIZE16; goto _ExtractModRM;
		case OT_R32_64_M8: opSize = OPERAND_SIZE8; goto _ExtractModRM;
		case OT_R32_64_M16: opSize = OPERAND_SIZE16; goto _ExtractModRM;
		case OT_RFULL_M16: ps->usedPrefixes |= (ps->totalPrefixes & INST_PRE_OP_SIZE); opSize = OPERAND_SIZE16; goto _ExtractModRM;
		case OT_MM32: opSize = OPERAND_SIZE32; goto _ExtractModRM;
		case OT_MM64: opSize = OPERAND_SIZE64; goto _ExtractModRM;
		case OT_XMM16: opSize = OPERAND_SIZE16; goto _ExtractModRM;
		case OT_XMM32: opSize = OPERAND_SIZE32; goto _ExtractModRM;
		case OT_XMM64: opSize = OPERAND_SIZE64; goto _ExtractModRM;
		case OT_XMM128: opSize = OPERAND_SIZE128;

_ExtractModRM:
			ci->code = code;
			ci->codeLen = codeLen;
			ci->codeOffset = codeOffset;
			if (!extract_modrm(ci, instructionHex,
				operandText, type, opNum,
				ps, dt, lockableInstruction, mod, rm, instFlags, opSize)) return EO_HALT;
		return EO_CONTINUE;
		case OT_CREG:

			if (rex & PREFIX_REX_R) {
				ps->usedPrefixes |= INST_PRE_REX;
				reg += REX_GPR_BASE;
			} else if ((dt == Decode32Bits) && (ps->totalPrefixes & INST_PRE_LOCK)) {

				reg += REX_GPR_BASE;
				ps->usedPrefixes |= INST_PRE_LOCK;
			}
			if (reg >= CREGS_MAX) return EO_HALT;
			if (_CREGS[reg].size == 0) return EO_HALT;
			str_x86def(operandText, &_CREGS[reg]);
		break;
		case OT_DREG:

			if ((reg == 4) || (reg == 5)) return EO_HALT;
			str_x86def(operandText, &_DREGS[reg]);
		break;
		case OT_SREG:
			if ((opNum == ONT_1) && (reg == 1)) return EO_HALT;

			if (reg <= SEG_REGS_MAX-1) str_x86def(operandText, &_SREGS[reg]);
			else return EO_HALT;
		break;
		case OT_SEG:

			if (totalPrefixes & INST_PRE_OP_SIZE) {
				ps->usedPrefixes |= INST_PRE_OP_SIZE;
				if (dt == Decode16Bits) strcat_WSN(operandText, TEXT_32_BITS);
				else strcat_WSN(operandText, TEXT_16_BITS);
			}
			switch (instFlags & INST_PRE_SEGOVRD_MASK)
			{
				case INST_PRE_CS: strcat_WSN(operandText, PREFIX_CS_TEXT); break;
				case INST_PRE_SS: strcat_WSN(operandText, PREFIX_SS_TEXT); break;
				case INST_PRE_DS: strcat_WSN(operandText, PREFIX_DS_TEXT); break;
				case INST_PRE_ES: strcat_WSN(operandText, PREFIX_ES_TEXT); break;
				case INST_PRE_FS: strcat_WSN(operandText, PREFIX_FS_TEXT); break;
				case INST_PRE_GS: strcat_WSN(operandText, PREFIX_GS_TEXT); break;
			}
		break;
		case OT_ACC8:
			str_x86def(operandText, &_REGS8[0]);
		break;
		case OT_ACC16:
			str_x86def(operandText, &_REGS16[0]);
		break;
		case OT_ACC_FULL_NOT64:
			rex &= ~PREFIX_REX_W;
		case OT_ACC_FULL:
			if (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode16Bits) {
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);
				str_x86def(operandText, &_REGS16[0]);
			} else if (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode32Bits) {
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);
				str_x86def(operandText, &_REGS32[0]);
			} else {

				if (~instFlags & INST_64BITS) {
					ps->usedPrefixes |= (totalPrefixes & INST_PRE_REX);
				}
				str_x86def(operandText, &_REGS64[0]);
			}
		break;
		case OT_PTR16_FULL:

			if (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode16Bits) {
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);
				codeLen -= sizeof(int16_t)*2;
				if (codeLen < 0) return EO_HALT;
				str_hex_sp_w(instructionHex, RUSHORT(code));
				str_hex_sp_w(instructionHex, RUSHORT((code+sizeof(int16_t))));

				if (totalPrefixes & INST_PRE_OP_SIZE) strcat_WSN(operandText, SMALL_OPERAND);

				str_code_hw(operandText, RUSHORT((code+sizeof(int16_t))));
				chrcat_WS(operandText, SEG_OFF_CHR);
				str_code_hw(operandText, RUSHORT(code));

				code += sizeof(int16_t)*2;
				codeOffset += sizeof(int16_t)*2;
			} else {
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);
				codeLen -= sizeof(int32_t) + sizeof(int16_t);
				if (codeLen < 0) return EO_HALT;
				str_hex_sp_dw(instructionHex, RULONG(code));
				str_hex_sp_w(instructionHex, RUSHORT((code+sizeof(int32_t))));

				if (totalPrefixes & INST_PRE_OP_SIZE) strcat_WSN(operandText, LARGE_OPERAND);

				str_code_hw(operandText, RUSHORT((code+sizeof(int32_t))));
				chrcat_WS(operandText, SEG_OFF_CHR);
				str_code_hdw(operandText, RULONG(code));

				code += sizeof(int32_t) + sizeof(int16_t);
				codeOffset += sizeof(int32_t) + sizeof(int16_t);
			}
		break;
		case OT_RELCB:
			codeLen -= sizeof(int8_t);
			if (codeLen < 0) return EO_HALT;
			joff = *(int8_t*)code;
			str_hex_sp_b(instructionHex, (uint8_t)joff);

			reloff = ((joff < 0) ? (codeOffset - abs(joff) + 1) : (codeOffset + joff + 1));
#ifdef SUPPORT_64BIT_OFFSET
			str_off64(operandText, reloff);
#else
			str_code_hdw(operandText, (_OffsetType)reloff);
#endif

			code += sizeof(int8_t);
			codeOffset += sizeof(int8_t);
		break;
		case OT_RELC_FULL:

			if (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode16Bits) {
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);

				codeLen -= sizeof(int16_t);
				if (codeLen < 0) return EO_HALT;
				joff = RSHORT(code);
				str_hex_sp_w(instructionHex, (uint16_t)joff);

				if (totalPrefixes & INST_PRE_OP_SIZE) strcat_WSN(operandText, SMALL_OPERAND);
				reloff = ((joff < 0) ? (codeOffset - abs(joff) + 2) : (codeOffset + joff + 2));

				str_code_hw(operandText, (uint16_t)((joff < 0) ? (codeOffset - abs(joff) + 2) : (codeOffset + joff + 2)));

				code += sizeof(int16_t);
				codeOffset += sizeof(int16_t);
			} else {
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);

				codeLen -= sizeof(int32_t);
				if (codeLen < 0) return EO_HALT;
				joff = RLONG(code);
				str_hex_sp_dw(instructionHex, RULONG(code));

				if (totalPrefixes & INST_PRE_OP_SIZE) strcat_WSN(operandText, LARGE_OPERAND);

				reloff = ((joff < 0) ? (codeOffset - abs(joff) + 4) : (codeOffset + joff + 4));
#ifdef SUPPORT_64BIT_OFFSET
				str_off64(operandText, reloff);
#else
				str_code_hdw(operandText, (_OffsetType)reloff);
#endif

				code += sizeof(int32_t);
				codeOffset += sizeof(int32_t);
			}
		break;
		case OT_MOFFS:

			if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode16Bits) {
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_ADDR_SIZE);

				codeLen -= sizeof(int16_t);
				if (codeLen < 0) return EO_HALT;
				str_hex_sp_w(instructionHex, RUSHORT(code));

				str_seg_text(operandText, ps, dt);
				chrcat_WS(operandText, OPEN_CHR);
				str_code_hw(operandText, RUSHORT(code));
				chrcat_WS(operandText, CLOSE_CHR);

				code += sizeof(int16_t);
				codeOffset += sizeof(int16_t);
			} else if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode32Bits) {
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_ADDR_SIZE);

				codeLen -= sizeof(int32_t);
				if (codeLen < 0) return EO_HALT;
				str_hex_sp_dw(instructionHex, RULONG(code));

				str_seg_text(operandText, ps, dt);
				chrcat_WS(operandText, OPEN_CHR);
				str_code_hdw(operandText, RULONG(code));
				chrcat_WS(operandText, CLOSE_CHR);

				code += sizeof(int32_t);
				codeOffset += sizeof(int32_t);
			} else {
				codeLen -= sizeof(int32_t)*2;
				if (codeLen < 0) return EO_HALT;
				str_hex_sp_qw(instructionHex, (uint8_t*)code);

				str_seg_text(operandText, ps, dt);
				chrcat_WS(operandText, OPEN_CHR);
				str_code_hqw(operandText, (uint8_t*)code);
				chrcat_WS(operandText, CLOSE_CHR);

				code += sizeof(int32_t)*2;
				codeOffset += sizeof(int32_t)*2;
			}
		break;
		case OT_CONST1:
			strcat_WSN(operandText, ONE_CONST_TEXT);
		break;
		case OT_REGCL:
			str_x86def(operandText, &_REGS8[1]);
		break;

		case OT_FPU_SI:

			reg = *(code-1) & 7;
			strcat_WSN(operandText, FPU_STACK_TEXT);
			chrcat_WS(operandText, OPEN_CHR0);
			chrcat_WS(operandText, (int8_t)reg + 0x30);
			chrcat_WS(operandText, CLOSE_CHR0);
		break;
		case OT_FPU_SSI:
			reg = *(code-1) & 7;
			strcat_WSN(operandText, FPU_STACK_TEXT);
			strcat_WSN(operandText, SEP_STR);
			strcat_WSN(operandText, FPU_STACK_TEXT);
			chrcat_WS(operandText, OPEN_CHR0);
			chrcat_WS(operandText, (int8_t)reg + 0x30);
			chrcat_WS(operandText, CLOSE_CHR0);
		break;
		case OT_FPU_SIS:
			reg = *(code-1) & 7;
			strcat_WSN(operandText, FPU_STACK_TEXT);
			chrcat_WS(operandText, OPEN_CHR0);
			chrcat_WS(operandText, (int8_t)reg + 0x30);
			chrcat_WS(operandText, CLOSE_CHR0);
			strcat_WSN(operandText, SEP_STR);
			strcat_WSN(operandText, FPU_STACK_TEXT);
		break;

		case OT_IB_RB:

			reg = *(code-1) & 7;
			if (rex & PREFIX_REX_B) {
				ps->usedPrefixes |= INST_PRE_REX;
				str_x86def(operandText, &_REGS8_REX[reg + REX_GPR_BASE]);
			} else if (ps->isREXPrefixValid) {
				ps->usedPrefixes |= INST_PRE_REX;
				str_x86def(operandText, &_REGS8_REX[reg]);
			} else str_x86def(operandText, &_REGS8[reg]);
		break;
		case OT_IB_R_DW_QW:
			totalPrefixes &= ~INST_PRE_OP_SIZE;
		case OT_IB_R_FULL:
			reg = *(code-1) & 7;
			switch (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags))
			{
				case Decode16Bits:
					ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);
					if (rex & PREFIX_REX_B) {
						ps->usedPrefixes |= INST_PRE_REX;
						reg += REX_GPR_BASE;
					}
					str_x86def(operandText, &_REGS16[reg]);
				break;
				case Decode32Bits:
					if (rex & PREFIX_REX_B) {
						ps->usedPrefixes |= INST_PRE_REX;
						str_x86def(operandText, &_REGS32[reg + REX_GPR_BASE]);
					} else {
						ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);
						str_x86def(operandText, &_REGS32[reg]);
					}
				break;
				case Decode64Bits:

					if ((instFlags & INST_64BITS) && ((instFlags & INST_PRE_REX) == 0)) {
						if (rex & PREFIX_REX_B) {
							ps->usedPrefixes |= INST_PRE_REX;
							reg += REX_GPR_BASE;
						}
						str_x86def(operandText, &_REGS64[reg]);
					} else {
						ps->usedPrefixes |= INST_PRE_REX;
						str_x86def(operandText, &_REGS64[reg + ((rex & PREFIX_REX_B) == PREFIX_REX_B ? REX_GPR_BASE : 0)]);
					}
				break;
			}
		break;

		case OT_REGI_ESI:
			tmpPrefixes = totalPrefixes & (INST_PRE_SEGOVRD_MASK | INST_PRE_OP_SIZE | INST_PRE_ADDR_SIZE | INST_PRE_REPS);

			if ((instFlags & INST_PRE_REPS) == 0) return EO_SUFFIX;

			ps->usedPrefixes |= (tmpPrefixes & INST_PRE_ADDR_SIZE);

			if (instFlags & INST_16BITS) {
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_OP_SIZE);

				if ((tmpPrefixes & INST_PRE_OP_SIZE) == tmpPrefixes) return EO_SUFFIX;
				if ((tmpPrefixes & (INST_PRE_OP_SIZE | (instFlags & INST_PRE_REPS))) == tmpPrefixes) return EO_SUFFIX;

				if (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode16Bits) strcat_WSN(operandText, TEXT_16_BITS);
				else if ((OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode64Bits) && (instFlags & INST_64BITS)) {
					ps->usedPrefixes |= INST_PRE_REX;
					strcat_WSN(operandText, TEXT_64_BITS);
				} else strcat_WSN(operandText, TEXT_32_BITS);
			} else {

				if ((tmpPrefixes & INST_PRE_OP_SIZE) == tmpPrefixes) return EO_SUFFIX;
				if ((tmpPrefixes & (INST_PRE_OP_SIZE | (instFlags & INST_PRE_REPS))) == tmpPrefixes) return EO_SUFFIX;

				strcat_WSN(operandText, TEXT_8_BITS);
			}

			str_seg_text(operandText, ps, dt);
			chrcat_WS(operandText, OPEN_CHR);

			if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode16Bits) str_x86def(operandText, &_REGS16[6]);
			else if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode32Bits) str_x86def(operandText, &_REGS32[6]);
			else str_x86def(operandText, &_REGS64[6]);
			chrcat_WS(operandText, CLOSE_CHR);
		break;
		case OT_REGI_EDI:
			tmpPrefixes = totalPrefixes & (INST_PRE_SEGOVRD_MASK | INST_PRE_OP_SIZE | INST_PRE_ADDR_SIZE | INST_PRE_REPS);

			if ((instFlags & INST_PRE_REPS) == 0) return EO_SUFFIX;

			ps->usedPrefixes |= (tmpPrefixes & INST_PRE_ADDR_SIZE);

			if (instFlags & INST_16BITS) {
				ps->usedPrefixes |= (tmpPrefixes & INST_PRE_OP_SIZE);

				if ((tmpPrefixes & INST_PRE_OP_SIZE) == tmpPrefixes) return EO_SUFFIX;
				if ((tmpPrefixes & (INST_PRE_OP_SIZE | INST_PRE_REPS)) == tmpPrefixes) return EO_SUFFIX;

				if (OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode16Bits) strcat_WSN(operandText, TEXT_16_BITS);
				else if ((OP_SIZE_AFFECT(dt, totalPrefixes, rex, instFlags) == Decode64Bits) && (instFlags & INST_64BITS)) {
					ps->usedPrefixes |= INST_PRE_REX;
					strcat_WSN(operandText, TEXT_64_BITS);
				} else strcat_WSN(operandText, TEXT_32_BITS);
			} else {

				if ((tmpPrefixes & INST_PRE_OP_SIZE) == tmpPrefixes) return EO_SUFFIX;
				if ((tmpPrefixes & (INST_PRE_OP_SIZE | (instFlags & INST_PRE_REPS))) == tmpPrefixes) return EO_SUFFIX;

				strcat_WSN(operandText, TEXT_8_BITS);
			}

			str_seg_text(operandText, ps, dt);
			chrcat_WS(operandText, OPEN_CHR);

			if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode16Bits) str_x86def(operandText, &_REGS16[7]);
			else if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode32Bits) str_x86def(operandText, &_REGS32[7]);
			else str_x86def(operandText, &_REGS64[7]);
			chrcat_WS(operandText, CLOSE_CHR);
		break;

		case OT_REGDX:

			if ((instFlags & INST_PRE_REPS) == 0) {
				str_x86def(operandText, &_REGS16[2]);
			} else {

				if ((totalPrefixes & (INST_PRE_OP_SIZE | INST_PRE_REPS)) == totalPrefixes) return EO_SUFFIX;

				if ((totalPrefixes & (INST_PRE_SEGOVRD_MASK | INST_PRE_OP_SIZE | INST_PRE_ADDR_SIZE)) == 0) return EO_SUFFIX;
				str_x86def(operandText, &_REGS16[2]);
			}
		break;

		case OT_REGECX:
			str_x86def(operandText, &_REGS32[1]);
		break;

		case OT_REGI_EBXAL:

			if ((totalPrefixes & (INST_PRE_SEGOVRD_MASK | INST_PRE_ADDR_SIZE)) == 0) return EO_SUFFIX;

			ps->usedPrefixes |= (totalPrefixes & INST_PRE_ADDR_SIZE);

			strcat_WSN(operandText, TEXT_8_BITS);
			str_seg_text(operandText, ps, dt);
			chrcat_WS(operandText, OPEN_CHR);

			if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode16Bits) str_x86def(operandText, &_REGS16[3]);
			else if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode32Bits) str_x86def(operandText, &_REGS32[3]);
			else {
				ps->usedPrefixes |= INST_PRE_REX;
				str_x86def(operandText, &_REGS64[3]);
			}

			chrcat_WS(operandText, PLUS_DISP_CHR);
			str_x86def(operandText, &_REGS8[0]);
			chrcat_WS(operandText, CLOSE_CHR);
		break;
		case OT_REGI_EAX:

			chrcat_WS(operandText, OPEN_CHR);
			if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode64Bits) {
				str_x86def(operandText, &_REGS64[0]);
			} else if (ADDR_SIZE_AFFECT(dt, totalPrefixes) == Decode32Bits) {
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_ADDR_SIZE);
				str_x86def(operandText, &_REGS32[0]);
			} else {
				ps->usedPrefixes |= (totalPrefixes & INST_PRE_ADDR_SIZE);
				str_x86def(operandText, &_REGS16[0]);
			}
			chrcat_WS(operandText, CLOSE_CHR);
		break;
		default: return EO_HALT;
	}

	ci->code = code;
	ci->codeLen = codeLen;
	ci->codeOffset = codeOffset;

	return EO_CONTINUE;
}
