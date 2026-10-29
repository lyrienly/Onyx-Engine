#ifndef OPERANDS_H
#define OPERANDS_H

#include "../config.h"

#include "decoder.h"
#include "prefix.h"
#include "wstring.h"
#include "instructions.h"

typedef enum {EO_HALT, EO_CONTINUE, EO_SUFFIX} _ExOpRCType;

_ExOpRCType extract_operand(_CodeInfo* ci,
                           _WString* instructionHex, _WString* operandText, _OpType type, _OpType op2,
                           _OperandNumberType opNum, _iflags instFlags, unsigned int modrm,
                           _PrefixState* ps, _DecodeType dt, int* lockableInstruction);

#endif
