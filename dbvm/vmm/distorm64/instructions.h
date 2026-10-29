#ifndef INSTRUCTIONS_H
#define INSTRUCTIONS_H

#include "../config.h"

#include "decoder.h"
#include "prefix.h"

typedef enum OpType {

	OT_NONE = 0,

	OT_IMM8,

	OT_IMM16,

	OT_IMM_FULL,

	OT_IMM32,

	OT_IMM_AADM,

	OT_SEIMM8,

	OT_REG8,

	OT_REG16,

	OT_REG_FULL,

	OT_REG32,

	OT_REG64,

	OT_REG32_64,

	OT_REG32_RM,

	OT_FREG32_64_RM,

	OT_RM8,

	OT_RM16,

	OT_RM_FULL,

	OT_RM32,

	OT_RM32_64,

	OT_RM16_32,

	OT_FPUM16,

	OT_FPUM32,

	OT_FPUM64,

	OT_FPUM80,

	OT_R32_M8,

	OT_R32_M16,

	OT_R32_64_M8,

	OT_R32_64_M16,

	OT_RFULL_M16,

	OT_CREG,

	OT_DREG,

	OT_SREG,

	OT_SEG,

	OT_ACC8,

	OT_ACC16,

	OT_ACC_FULL,

	OT_ACC_FULL_NOT64,

	OT_MEM16_FULL,

	OT_PTR16_FULL,

	OT_MEM16_3264,

	OT_RELCB,

	OT_RELC_FULL,

	OT_MEM,
	OT_MEM32,

	OT_MEM32_64,
	OT_MEM64,
	OT_MEM128,

	OT_MEM64_128,

	OT_MOFFS,

	OT_CONST1,

	OT_REGCL,

	OT_IB_RB,

	OT_IB_R_DW_QW,

	OT_IB_R_FULL,

	OT_REGI_ESI,

	OT_REGI_EDI,

	OT_REGI_EBXAL,

	OT_REGI_EAX,

	OT_REGDX,

	OT_REGECX,

	OT_FPU_SI,
	OT_FPU_SSI,
	OT_FPU_SIS,

	OT_MM,

	OT_MM_RM,

	OT_MM32,

	OT_MM64,

	OT_XMM,

	OT_XMM_RM,

	OT_XMM16,

	OT_XMM32,

	OT_XMM64,

	OT_XMM128,

	OT_REGXMM0,

	OT_DUMMY
} _OpType;

#define INST_FLAGS_NONE ((_iflags)-1)

#define INST_EXCLUDE_MODRM (0)

#define INST_INCLUDE_MODRM (1)

#define INST_NOT_DIVIDED (1 << 1)

#define INST_16BITS (1 << 2)

#define INST_32BITS (1 << 3)

#define INST_PRE_LOCK (1 << 4)

#define INST_PRE_REPNZ (1 << 5)

#define INST_PRE_REP (1 << 6)

#define INST_PRE_CS (1 << 7)

#define INST_PRE_SS (1 << 8)

#define INST_PRE_DS (1 << 9)

#define INST_PRE_ES (1 << 10)

#define INST_PRE_FS (1 << 11)

#define INST_PRE_GS (1 << 12)

#define INST_PRE_OP_SIZE (1 << 13)

#define INST_PRE_ADDR_SIZE (1 << 14)

#define INST_NATIVE (1 << 15)

#define INST_USE_EXMNEMONIC (1 << 16)

#define INST_USE_OP3 (1 << 17)

#define INST_USE_OP4 (1 << 18)

#define INST_MODRM_BASED (1 << 19)

#define INST_MODRR (1 << 20)

#define INST_3DNOW_FETCH (1 << 21)

#define INST_PSEUDO_OPCODE (1 << 22)

#define INST_INVALID_64BITS (1 << 23)

#define INST_64BITS (1 << 24)

#define INST_PRE_REX (1 << 25)

#define INST_USE_EXMNEMONIC2 (1 << 26)

#define INST_64BITS_FETCH (1 << 27)

#define INST_PRE_REPS (INST_PRE_REPNZ | INST_PRE_REP)
#define INST_PRE_LOKREP_MASK (INST_PRE_LOCK | INST_PRE_REPNZ | INST_PRE_REP)
#define INST_PRE_SEGOVRD_MASK (INST_PRE_CS | INST_PRE_SS | INST_PRE_DS | INST_PRE_ES | INST_PRE_FS | INST_PRE_GS)

#define ISCT_INTEGER 1

#define ISCT_FPU 2

#define ISCT_P6 3

#define ISCT_MMX 4

#define ISCT_SSE 5

#define ISCT_SSE2 6

#define ISCT_SSE3 7

#define ISCT_SSSE3 8

#define ISCT_SSE4_1 9

#define ISCT_SSE4_2 10

#define ISCT_SSE4_A 11

#define ISCT_3DNOW 12

#define ISCT_3DNOWEXT 13

#define ISCT_VMX 14

#define ISCT_SVM 15

typedef enum {ONT_NONE = -1, ONT_1, ONT_2, ONT_3, ONT_4} _OperandNumberType;

#define MAX_MNEMONIC_LENGTH (32)

#ifdef _MSC_VER
 #pragma pack(push, 1)
#endif

typedef struct _PACKED_ {
	uint8_t type;
	uint8_t isc;
	uint8_t s, d;
	int8_t* mnemonic;
	_iflags flags;
} _InstInfo;

typedef struct _PACKED_ {
	uint8_t type;
	uint8_t isc;
	uint8_t s, d;
	int8_t* mnemonic;
	_iflags flags;
	uint8_t op3, op4;
	int8_t* mnemonic2;
	int8_t* mnemonic3;
} _InstInfoEx;

typedef enum {
	INT_NOTEXISTS = -1,
	INT_NONE,
	INT_INFO,
	INT_LIST_GROUP,
	INT_LIST_FULL,
	INT_LIST_DIVIDED
} _InstNodeType;

typedef struct _PACKED_ InstNode{
	uint8_t type;
	uint8_t* ids;
	_InstInfo** list;
} _InstNode;

#ifdef _MSC_VER
 #pragma pack(pop)
#endif

typedef enum {OPERAND_SIZE_NONE = 0, OPERAND_SIZE8, OPERAND_SIZE16, OPERAND_SIZE32, OPERAND_SIZE64, OPERAND_SIZE80, OPERAND_SIZE128} _OperandSizeType;

extern _InstInfo II_3dnow;

_InstInfo* locate_inst(const uint8_t** code, int* codeLen, _OffsetType* codeOffset, _WString* instructionHex, _PrefixState* ps, _DecodeType dt);
_InstInfo* locate_3dnow_inst(_CodeInfo* ci, _WString* instructionHex);

void str_indirection_text(_WString* s, _OperandSizeType opSize);

#endif
