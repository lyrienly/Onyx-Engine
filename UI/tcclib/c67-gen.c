#ifdef TARGET_DEFS_ONLY

#define NB_REGS            24

#define RC_INT     0x0001
#define RC_FLOAT   0x0002
#define RC_EAX     0x0004
#define RC_ST0     0x0008
#define RC_ECX     0x0010
#define RC_EDX     0x0020
#define RC_INT_BSIDE  0x00000040
#define RC_C67_A4     0x00000100
#define RC_C67_A5     0x00000200
#define RC_C67_B4     0x00000400
#define RC_C67_B5     0x00000800
#define RC_C67_A6     0x00001000
#define RC_C67_A7     0x00002000
#define RC_C67_B6     0x00004000
#define RC_C67_B7     0x00008000
#define RC_C67_A8     0x00010000
#define RC_C67_A9     0x00020000
#define RC_C67_B8     0x00040000
#define RC_C67_B9     0x00080000
#define RC_C67_A10    0x00100000
#define RC_C67_A11    0x00200000
#define RC_C67_B10    0x00400000
#define RC_C67_B11    0x00800000
#define RC_C67_A12    0x01000000
#define RC_C67_A13    0x02000000
#define RC_C67_B12    0x04000000
#define RC_C67_B13    0x08000000
#define RC_IRET    RC_C67_A4
#define RC_IRE2    RC_C67_A5
#define RC_FRET    RC_C67_A4

enum {
    TREG_EAX = 0,
    TREG_ECX,
    TREG_EDX,
    TREG_ST0,
    TREG_C67_A4,
    TREG_C67_A5,
    TREG_C67_B4,
    TREG_C67_B5,
    TREG_C67_A6,
    TREG_C67_A7,
    TREG_C67_B6,
    TREG_C67_B7,
    TREG_C67_A8,
    TREG_C67_A9,
    TREG_C67_B8,
    TREG_C67_B9,
    TREG_C67_A10,
    TREG_C67_A11,
    TREG_C67_B10,
    TREG_C67_B11,
    TREG_C67_A12,
    TREG_C67_A13,
    TREG_C67_B12,
    TREG_C67_B13,
};

#define REG_IRET TREG_C67_A4
#define REG_IRE2 TREG_C67_A5
#define REG_FRET TREG_C67_A4

#define PTR_SIZE 4

#define LDOUBLE_SIZE  12
#define LDOUBLE_ALIGN 4

#define MAX_ALIGN     8

#else

#define USING_GLOBALS
#include "tcc.h"

ST_DATA const char *target_machine_defs =
    "__C67__\0"
    ;

ST_DATA const int reg_classes[NB_REGS] = {
     RC_INT | RC_FLOAT | RC_EAX,

     RC_INT | RC_ECX,
     RC_INT | RC_INT_BSIDE | RC_FLOAT | RC_EDX,

     RC_INT | RC_INT_BSIDE | RC_ST0,
     RC_C67_A4,
     RC_C67_A5,
     RC_C67_B4,
     RC_C67_B5,
     RC_C67_A6,
     RC_C67_A7,
     RC_C67_B6,
     RC_C67_B7,
     RC_C67_A8,
     RC_C67_A9,
     RC_C67_B8,
     RC_C67_B9,
     RC_C67_A10,
     RC_C67_A11,
     RC_C67_B10,
     RC_C67_B11,
     RC_C67_A10,
     RC_C67_A11,
     RC_C67_B10,
     RC_C67_B11
};

#define NoCallArgsPassedOnStack 10
int NoOfCurFuncArgs;
int TranslateStackToReg[NoCallArgsPassedOnStack];
int ParamLocOnStack[NoCallArgsPassedOnStack];
int TotalBytesPushedOnStack;

#ifndef FALSE
# define FALSE 0
# define TRUE 1
#endif

#undef BOOL
#define BOOL int

#define ALWAYS_ASSERT(x) \
do {\
   if (!(x))\
       tcc_error("internal compiler error file at %s:%d", __FILE__, __LINE__);\
} while (0)

static unsigned long func_sub_sp_offset;
static int func_ret_sub;

static BOOL C67_invert_test;
static int C67_compare_reg;

#ifdef ASSEMBLY_LISTING_C67
FILE *f = NULL;
#endif

void C67_g(int c)
{
    int ind1;
    if (nocode_wanted)
        return;
#ifdef ASSEMBLY_LISTING_C67
    fprintf(f, " %08X", c);
#endif
    ind1 = ind + 4;
    if (ind1 > (int) cur_text_section->data_allocated)
	section_realloc(cur_text_section, ind1);
    cur_text_section->data[ind] = c & 0xff;
    cur_text_section->data[ind + 1] = (c >> 8) & 0xff;
    cur_text_section->data[ind + 2] = (c >> 16) & 0xff;
    cur_text_section->data[ind + 3] = (c >> 24) & 0xff;
    ind = ind1;
}

void gsym_addr(int t, int a)
{
    int n, *ptr;
    while (t) {
	ptr = (int *) (cur_text_section->data + t);
	{
	    Sym *sym;

	    n = ((*ptr >> 7) & 0xffff);
	    n |= ((*(ptr + 1) >> 7) & 0xffff) << 16;

	    sym = get_sym_ref(&char_pointer_type, cur_text_section, a, 0);
	    greloc(cur_text_section, sym, t, R_C60LO16);
	    greloc(cur_text_section, sym, t + 4, R_C60HI16);

	    *ptr &= ~(0xffff << 7);
	    *(ptr + 1) &= ~(0xffff << 7);
	}
	t = n;
    }
}

#define C67_A0 105
#define C67_SP 106
#define C67_B3 107
#define C67_FP 108
#define C67_B2 109
#define C67_CREG_ZERO -1

int ConvertRegToRegClass(int r)
{

    return RC_C67_A4 << (r - TREG_C67_A4);
}

int C67_map_regn(int r)
{
    if (r == 0)
	return 0x2;
    else if (r == 1)
	return 3;
    else if (r == 2)
	return 0;
    else if (r == 3)
	return 1;
    else if (r >= TREG_C67_A4 && r <= TREG_C67_B13)
	return (((r & 0xfffffffc) >> 1) | (r & 1)) + 2;
    else if (r == C67_A0)
	return 0;
    else if (r == C67_B2)
	return 2;
    else if (r == C67_B3)
	return 3;
    else if (r == C67_SP)
	return 15;
    else if (r == C67_FP)
	return 15;
    else if (r == C67_CREG_ZERO)
	return 0;
    else
	ALWAYS_ASSERT(FALSE);

    return 0;
}

int C67_map_regc(int r)
{
    if (r == 0)
	return 0x5;
    else if (r == 2)
	return 0x1;
    else if (r == 3)
	return 0x2;
    else if (r == C67_B2)
	return 0x3;
    else if (r == C67_CREG_ZERO)
	return 0;
    else
	ALWAYS_ASSERT(FALSE);

    return 0;
}

int C67_map_regs(int r)
{
    if (r == 0)
	return 0x0;
    else if (r == 1)
	return 0x0;
    else if (r == 2)
	return 0x1;
    else if (r == 3)
	return 0x1;
    else if (r >= TREG_C67_A4 && r <= TREG_C67_B13)
	return (r & 2) >> 1;
    else if (r == C67_A0)
	return 0;
    else if (r == C67_B2)
	return 1;
    else if (r == C67_B3)
	return 1;
    else if (r == C67_SP)
	return 0x1;
    else if (r == C67_FP)
	return 0x0;
    else
	ALWAYS_ASSERT(FALSE);

    return 0;
}

int C67_map_S12(char *s)
{
    if (strstr(s, ".S1") != NULL)
	return 0;
    else if (strcmp(s, ".S2"))
	return 1;
    else
	ALWAYS_ASSERT(FALSE);

    return 0;
}

int C67_map_D12(char *s)
{
    if (strstr(s, ".D1") != NULL)
	return 0;
    else if (strcmp(s, ".D2"))
	return 1;
    else
	ALWAYS_ASSERT(FALSE);

    return 0;
}

void C67_asm(char *s, int a, int b, int c)
{
    BOOL xpath;

#ifdef ASSEMBLY_LISTING_C67
    if (!f) {
	f = fopen("TCC67_out.txt", "wt");
    }
    fprintf(f, "%04X ", ind);
#endif

    if (strstr(s, "MVKL") == s) {
	C67_g((C67_map_regn(b) << 23) |
	      ((a & 0xffff) << 7) | (0x0a << 2) | (C67_map_regs(b) << 1));
    } else if (strstr(s, "MVKH") == s) {
	C67_g((C67_map_regn(b) << 23) |
	      (((a >> 16) & 0xffff) << 7) |
	      (0x1a << 2) | (C67_map_regs(b) << 1));
    } else if (strstr(s, "STW.D SP POST DEC") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (2 << 13) |
	      (0xa << 9) |
	      (0 << 8) |
	      (1 << 7) |
	      (7 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "STB.D *+SP[A0]") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (0 << 13) |
	      (5 << 9) |
	      (0 << 8) |
	      (0 << 7) |
	      (3 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "STH.D *+SP[A0]") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (0 << 13) |
	      (5 << 9) |
	      (0 << 8) |
	      (0 << 7) |
	      (5 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "STB.D *+SP[A0]") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (0 << 13) |
	      (5 << 9) |
	      (0 << 8) |
	      (0 << 7) |
	      (3 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "STH.D *+SP[A0]") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (0 << 13) |
	      (5 << 9) |
	      (0 << 8) |
	      (0 << 7) |
	      (5 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "STW.D *+SP[A0]") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (0 << 13) |
	      (5 << 9) |
	      (0 << 8) |
	      (0 << 7) |
	      (7 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "STW.D *") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (C67_map_regn(b) << 18) |
	      (0 << 13) |
	      (1 << 9) |
	      (0 << 8) |
	      (C67_map_regs(b) << 7) |
	      (7 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "STH.D *") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (C67_map_regn(b) << 18) |
	      (0 << 13) |
	      (1 << 9) |
	      (0 << 8) |
	      (C67_map_regs(b) << 7) |
	      (5 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "STB.D *") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (C67_map_regn(b) << 18) |
	      (0 << 13) |
	      (1 << 9) |
	      (0 << 8) |
	      (C67_map_regs(b) << 7) |
	      (3 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "STW.D +*") == s) {
	ALWAYS_ASSERT(c < 32);
	C67_g((C67_map_regn(a) << 23) |
	      (C67_map_regn(b) << 18) |
	      (c << 13) |
	      (1 << 9) |
	      (0 << 8) |
	      (C67_map_regs(b) << 7) |
	      (7 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDW.D SP PRE INC") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (2 << 13) |
	      (9 << 9) |
	      (0 << 8) |
	      (1 << 7) |
	      (6 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDDW.D SP PRE INC") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (1 << 13) |
	      (9 << 9) |
	      (1 << 8) |
	      (1 << 7) |
	      (6 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDW.D *+SP[A0]") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (0 << 13) |
	      (5 << 9) |
	      (0 << 8) |
	      (0 << 7) |
	      (6 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDDW.D *+SP[A0]") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (0 << 13) |
	      (5 << 9) |
	      (1 << 8) |
	      (0 << 7) |
	      (6 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDH.D *+SP[A0]") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (0 << 13) |
	      (5 << 9) |
	      (0 << 8) |
	      (0 << 7) |
	      (4 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDB.D *+SP[A0]") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (0 << 13) |
	      (5 << 9) |
	      (0 << 8) |
	      (0 << 7) |
	      (2 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDHU.D *+SP[A0]") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (0 << 13) |
	      (5 << 9) |
	      (0 << 8) |
	      (0 << 7) |
	      (0 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDBU.D *+SP[A0]") == s) {
	C67_g((C67_map_regn(a) << 23) |
	      (15 << 18) |
	      (0 << 13) |
	      (5 << 9) |
	      (0 << 8) |
	      (0 << 7) |
	      (1 << 4) |
	      (1 << 2) |
	      (C67_map_regs(a) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDW.D *") == s) {
	C67_g((C67_map_regn(b) << 23) |
	      (C67_map_regn(a) << 18) |
	      (0 << 13) |
	      (1 << 9) |
	      (0 << 8) |
	      (C67_map_regs(a) << 7) |
	      (6 << 4) |
	      (1 << 2) |
	      (C67_map_regs(b) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDDW.D *") == s) {
	C67_g((C67_map_regn(b) << 23) |
	      (C67_map_regn(a) << 18) |
	      (0 << 13) |
	      (1 << 9) |
	      (1 << 8) |
	      (C67_map_regs(a) << 7) |
	      (6 << 4) |
	      (1 << 2) |
	      (C67_map_regs(b) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDH.D *") == s) {
	C67_g((C67_map_regn(b) << 23) |
	      (C67_map_regn(a) << 18) |
	      (0 << 13) |
	      (1 << 9) |
	      (0 << 8) |
	      (C67_map_regs(a) << 7) |
	      (4 << 4) |
	      (1 << 2) |
	      (C67_map_regs(b) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDB.D *") == s) {
	C67_g((C67_map_regn(b) << 23) |
	      (C67_map_regn(a) << 18) |
	      (0 << 13) |
	      (1 << 9) |
	      (0 << 8) |
	      (C67_map_regs(a) << 7) |
	      (2 << 4) |
	      (1 << 2) |
	      (C67_map_regs(b) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDHU.D *") == s) {
	C67_g((C67_map_regn(b) << 23) |
	      (C67_map_regn(a) << 18) |
	      (0 << 13) |
	      (1 << 9) |
	      (0 << 8) |
	      (C67_map_regs(a) << 7) |
	      (0 << 4) |
	      (1 << 2) |
	      (C67_map_regs(b) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDBU.D *") == s) {
	C67_g((C67_map_regn(b) << 23) |
	      (C67_map_regn(a) << 18) |
	      (0 << 13) |
	      (1 << 9) |
	      (0 << 8) |
	      (C67_map_regs(a) << 7) |
	      (1 << 4) |
	      (1 << 2) |
	      (C67_map_regs(b) << 1) |
	      (0 << 0));
    } else if (strstr(s, "LDW.D +*") == s) {
	C67_g((C67_map_regn(b) << 23) |
	      (C67_map_regn(a) << 18) |
	      (1 << 13) |
	      (1 << 9) |
	      (0 << 8) |
	      (C67_map_regs(a) << 7) |
	      (6 << 4) |
	      (1 << 2) |
	      (C67_map_regs(b) << 1) |
	      (0 << 0));
    } else if (strstr(s, "CMPLTSP") == s) {
	xpath = C67_map_regs(a) ^ C67_map_regs(b);
	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x3a << 6) |
	      (0x8 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "CMPGTSP") == s) {
	xpath = C67_map_regs(a) ^ C67_map_regs(b);
	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x39 << 6) |
	      (0x8 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "CMPEQSP") == s) {
	xpath = C67_map_regs(a) ^ C67_map_regs(b);
	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x38 << 6) |
	      (0x8 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    }

    else if (strstr(s, "CMPLTDP") == s) {
	xpath = C67_map_regs(a) ^ C67_map_regs(b);
	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x2a << 6) |
	      (0x8 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "CMPGTDP") == s) {
	xpath = C67_map_regs(a) ^ C67_map_regs(b);
	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x29 << 6) |
	      (0x8 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "CMPEQDP") == s) {
	xpath = C67_map_regs(a) ^ C67_map_regs(b);
	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x28 << 6) |
	      (0x8 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "CMPLT") == s) {
	xpath = C67_map_regs(a) ^ C67_map_regs(b);
	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x57 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "CMPGT") == s) {
	xpath = C67_map_regs(a) ^ C67_map_regs(b);
	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x47 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "CMPEQ") == s) {
	xpath = C67_map_regs(a) ^ C67_map_regs(b);
	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x53 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "CMPLTU") == s) {
	xpath = C67_map_regs(a) ^ C67_map_regs(b);
	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x5f << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "CMPGTU") == s) {
	xpath = C67_map_regs(a) ^ C67_map_regs(b);
	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x4f << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "B DISP") == s) {
	C67_g((0 << 29) |
	      (0 << 28) |
	      (a << 7) |
	      (0x4 << 2) |
	      (0 << 1) |
	      (0 << 0));
    } else if (strstr(s, "B.") == s) {
	xpath = C67_map_regs(c) ^ 1;

	C67_g((C67_map_regc(b) << 29) |
	      (a << 28) |
	      (0 << 23) |
	      (C67_map_regn(c) << 18) |
	      (0 << 13) |
	      (xpath << 12) |
	      (0xd << 6) |
	      (0x8 << 2) |
	      (1 << 1) |
	      (0 << 0));
    } else if (strstr(s, "MV.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (0 << 13) |
	      (xpath << 12) |
	      (0x2 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "SPTRUNC.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (0 << 13) |
	      (xpath << 12) |
	      (0xb << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "DPTRUNC.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      ((C67_map_regn(b) + 1) << 18) |
	      (0 << 13) |
	      (xpath << 12) |
	      (0x1 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "INTSP.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (0 << 13) |
	      (xpath << 12) |
	      (0x4a << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "INTSPU.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (0 << 13) |
	      (xpath << 12) |
	      (0x49 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "INTDP.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (0 << 13) |
	      (xpath << 12) |
	      (0x39 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "INTDPU.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      ((C67_map_regn(b) + 1) << 18) |
	      (0 << 13) |
	      (xpath << 12) |
	      (0x3b << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "SPDP.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (0 << 13) |
	      (xpath << 12) |
	      (0x2 << 6) |
	      (0x8 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "DPSP.L") == s) {
	ALWAYS_ASSERT(C67_map_regs(b) == C67_map_regs(c));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      ((C67_map_regn(b) + 1) << 18) |
	      (0 << 13) |
	      (0 << 12) |
	      (0x9 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "ADD.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(a) == C67_map_regs(c));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x3 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "SUB.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(a) == C67_map_regs(c));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x7 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "OR.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(a) == C67_map_regs(c));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x7f << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "AND.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(a) == C67_map_regs(c));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x7b << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "XOR.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(a) == C67_map_regs(c));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x6f << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "ADDSP.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(a) == C67_map_regs(c));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x10 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "ADDDP.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(a) == C67_map_regs(c));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x18 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "SUBSP.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(a) == C67_map_regs(c));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x11 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "SUBDP.L") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(a) == C67_map_regs(c));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x19 << 5) |
	      (0x6 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "MPYSP.M") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(a) == C67_map_regs(c));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x1c << 7) |
	      (0x0 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "MPYDP.M") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(a) == C67_map_regs(c));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x0e << 7) |
	      (0x0 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "MPYI.M") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(a) == C67_map_regs(c));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x4 << 7) |
	      (0x0 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "SHR.S") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x37 << 6) |
	      (0x8 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "SHRU.S") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x27 << 6) |
	      (0x8 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "SHL.S") == s) {
	xpath = C67_map_regs(b) ^ C67_map_regs(c);

	ALWAYS_ASSERT(C67_map_regs(c) == C67_map_regs(a));

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(c) << 23) |
	      (C67_map_regn(b) << 18) |
	      (C67_map_regn(a) << 13) |
	      (xpath << 12) |
	      (0x33 << 6) |
	      (0x8 << 2) |
	      (C67_map_regs(c) << 1) |
	      (0 << 0));
    } else if (strstr(s, "||ADDK") == s) {
	xpath = 0;

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(b) << 23) |
	      (a << 07) |
	      (0x14 << 2) |
	      (C67_map_regs(b) << 1) |
	      (1 << 0));
    } else if (strstr(s, "ADDK") == s) {
	xpath = 0;

	C67_g((0 << 29) |
	      (0 << 28) |
	      (C67_map_regn(b) << 23) |
	      (a << 07) |
	      (0x14 << 2) |
	      (C67_map_regs(b) << 1) |
	      (0 << 0));
    } else if (strstr(s, "NOP") == s) {
	C67_g(((a - 1) << 13) |
	      (0 << 0));
    } else
	ALWAYS_ASSERT(FALSE);

#ifdef ASSEMBLY_LISTING_C67
    fprintf(f, " %s %d %d %d\n", s, a, b, c);
#endif

}

void C67_MVKL(int r, int fc)
{
    C67_asm("MVKL.", fc, r, 0);
}

void C67_MVKH(int r, int fc)
{
    C67_asm("MVKH.", fc, r, 0);
}

void C67_STB_SP_A0(int r)
{
    C67_asm("STB.D *+SP[A0]", r, 0, 0);
}

void C67_STH_SP_A0(int r)
{
    C67_asm("STH.D *+SP[A0]", r, 0, 0);
}

void C67_STW_SP_A0(int r)
{
    C67_asm("STW.D *+SP[A0]", r, 0, 0);
}

void C67_STB_PTR(int r, int r2)
{
    C67_asm("STB.D *", r, r2, 0);
}

void C67_STH_PTR(int r, int r2)
{
    C67_asm("STH.D *", r, r2, 0);
}

void C67_STW_PTR(int r, int r2)
{
    C67_asm("STW.D *", r, r2, 0);
}

void C67_STW_PTR_PRE_INC(int r, int r2, int n)
{
    C67_asm("STW.D +*", r, r2, n);
}

void C67_PUSH(int r)
{
    C67_asm("STW.D SP POST DEC", r, 0, 0);
}

void C67_LDW_SP_A0(int r)
{
    C67_asm("LDW.D *+SP[A0]", r, 0, 0);
}

void C67_LDDW_SP_A0(int r)
{
    C67_asm("LDDW.D *+SP[A0]", r, 0, 0);
}

void C67_LDH_SP_A0(int r)
{
    C67_asm("LDH.D *+SP[A0]", r, 0, 0);
}

void C67_LDB_SP_A0(int r)
{
    C67_asm("LDB.D *+SP[A0]", r, 0, 0);
}

void C67_LDHU_SP_A0(int r)
{
    C67_asm("LDHU.D *+SP[A0]", r, 0, 0);
}

void C67_LDBU_SP_A0(int r)
{
    C67_asm("LDBU.D *+SP[A0]", r, 0, 0);
}

void C67_LDW_PTR(int r, int r2)
{
    C67_asm("LDW.D *", r, r2, 0);
}

void C67_LDDW_PTR(int r, int r2)
{
    C67_asm("LDDW.D *", r, r2, 0);
}

void C67_LDH_PTR(int r, int r2)
{
    C67_asm("LDH.D *", r, r2, 0);
}

void C67_LDB_PTR(int r, int r2)
{
    C67_asm("LDB.D *", r, r2, 0);
}

void C67_LDHU_PTR(int r, int r2)
{
    C67_asm("LDHU.D *", r, r2, 0);
}

void C67_LDBU_PTR(int r, int r2)
{
    C67_asm("LDBU.D *", r, r2, 0);
}

void C67_LDW_PTR_PRE_INC(int r, int r2)
{
    C67_asm("LDW.D +*", r, r2, 0);
}

void C67_POP(int r)
{
    C67_asm("LDW.D SP PRE INC", r, 0, 0);
}

void C67_POP_DW(int r)
{
    C67_asm("LDDW.D SP PRE INC", r, 0, 0);
}

void C67_CMPLT(int s1, int s2, int dst)
{
    C67_asm("CMPLT.L1", s1, s2, dst);
}

void C67_CMPGT(int s1, int s2, int dst)
{
    C67_asm("CMPGT.L1", s1, s2, dst);
}

void C67_CMPEQ(int s1, int s2, int dst)
{
    C67_asm("CMPEQ.L1", s1, s2, dst);
}

void C67_CMPLTU(int s1, int s2, int dst)
{
    C67_asm("CMPLTU.L1", s1, s2, dst);
}

void C67_CMPGTU(int s1, int s2, int dst)
{
    C67_asm("CMPGTU.L1", s1, s2, dst);
}

void C67_CMPLTSP(int s1, int s2, int dst)
{
    C67_asm("CMPLTSP.S1", s1, s2, dst);
}

void C67_CMPGTSP(int s1, int s2, int dst)
{
    C67_asm("CMPGTSP.S1", s1, s2, dst);
}

void C67_CMPEQSP(int s1, int s2, int dst)
{
    C67_asm("CMPEQSP.S1", s1, s2, dst);
}

void C67_CMPLTDP(int s1, int s2, int dst)
{
    C67_asm("CMPLTDP.S1", s1, s2, dst);
}

void C67_CMPGTDP(int s1, int s2, int dst)
{
    C67_asm("CMPGTDP.S1", s1, s2, dst);
}

void C67_CMPEQDP(int s1, int s2, int dst)
{
    C67_asm("CMPEQDP.S1", s1, s2, dst);
}

void C67_IREG_B_REG(int inv, int r1, int r2)
{
    C67_asm("B.S2", inv, r1, r2);
}

void C67_B_DISP(int disp)
{

    C67_asm("B DISP", disp + ((ind & 31) >> 2), 0, 0);
}

void C67_NOP(int n)
{
    C67_asm("NOP", n, 0, 0);
}

void C67_ADDK(int n, int r)
{
    ALWAYS_ASSERT(abs(n) < 32767);

    C67_asm("ADDK", n, r, 0);
}

void C67_ADDK_PARALLEL(int n, int r)
{
    ALWAYS_ASSERT(abs(n) < 32767);

    C67_asm("||ADDK", n, r, 0);
}

void C67_Adjust_ADDK(int *inst, int n)
{
    ALWAYS_ASSERT(abs(n) < 32767);

    *inst = (*inst & (~(0xffff << 7))) | ((n & 0xffff) << 7);
}

void C67_MV(int r, int v)
{
    C67_asm("MV.L", 0, r, v);
}

void C67_DPTRUNC(int r, int v)
{
    C67_asm("DPTRUNC.L", 0, r, v);
}

void C67_SPTRUNC(int r, int v)
{
    C67_asm("SPTRUNC.L", 0, r, v);
}

void C67_INTSP(int r, int v)
{
    C67_asm("INTSP.L", 0, r, v);
}

void C67_INTDP(int r, int v)
{
    C67_asm("INTDP.L", 0, r, v);
}

void C67_INTSPU(int r, int v)
{
    C67_asm("INTSPU.L", 0, r, v);
}

void C67_INTDPU(int r, int v)
{
    C67_asm("INTDPU.L", 0, r, v);
}

void C67_SPDP(int r, int v)
{
    C67_asm("SPDP.L", 0, r, v);
}

void C67_DPSP(int r, int v)
{
    C67_asm("DPSP.L", 0, r, v);
}

void C67_ADD(int r, int v)
{
    C67_asm("ADD.L", v, r, v);
}

void C67_SUB(int r, int v)
{
    C67_asm("SUB.L", v, r, v);
}

void C67_AND(int r, int v)
{
    C67_asm("AND.L", v, r, v);
}

void C67_OR(int r, int v)
{
    C67_asm("OR.L", v, r, v);
}

void C67_XOR(int r, int v)
{
    C67_asm("XOR.L", v, r, v);
}

void C67_ADDSP(int r, int v)
{
    C67_asm("ADDSP.L", v, r, v);
}

void C67_SUBSP(int r, int v)
{
    C67_asm("SUBSP.L", v, r, v);
}

void C67_MPYSP(int r, int v)
{
    C67_asm("MPYSP.M", v, r, v);
}

void C67_ADDDP(int r, int v)
{
    C67_asm("ADDDP.L", v, r, v);
}

void C67_SUBDP(int r, int v)
{
    C67_asm("SUBDP.L", v, r, v);
}

void C67_MPYDP(int r, int v)
{
    C67_asm("MPYDP.M", v, r, v);
}

void C67_MPYI(int r, int v)
{
    C67_asm("MPYI.M", v, r, v);
}

void C67_SHL(int r, int v)
{
    C67_asm("SHL.S", r, v, v);
}

void C67_SHRU(int r, int v)
{
    C67_asm("SHRU.S", r, v, v);
}

void C67_SHR(int r, int v)
{
    C67_asm("SHR.S", r, v, v);
}

void load(int r, SValue * sv)
{
    int v, t, ft, fc, fr, size = 0, element;
    BOOL Unsigned = FALSE;
    SValue v1;

    fr = sv->r;
    ft = sv->type.t;
    fc = sv->c.i;

    v = fr & VT_VALMASK;
    if (fr & VT_LVAL) {
	if (v == VT_LLOCAL) {
	    v1.type.t = VT_INT;
	    v1.r = VT_LOCAL | VT_LVAL;
	    v1.c.i = fc;
	    load(r, &v1);
	    fr = r;
	} else if ((ft & VT_BTYPE) == VT_LDOUBLE) {
	    tcc_error("long double not supported");
	} else if ((ft & VT_TYPE) == VT_BYTE) {
	    size = 1;
	} else if ((ft & VT_TYPE) == (VT_BYTE | VT_UNSIGNED)) {
	    size = 1;
	    Unsigned = TRUE;
	} else if ((ft & VT_TYPE) == VT_SHORT) {
	    size = 2;
	} else if ((ft & VT_TYPE) == (VT_SHORT | VT_UNSIGNED)) {
	    size = 2;
	    Unsigned = TRUE;
	} else if ((ft & VT_BTYPE) == VT_DOUBLE) {
	    size = 8;
	} else {
	    size = 4;
	}

	if (v == VT_LOCAL && fc > 0) {
	    int stack_pos = 8;

	    for (t = 0; t < NoCallArgsPassedOnStack; t++) {
		if (fc == stack_pos)
		    break;

		stack_pos += TranslateStackToReg[t];
	    }

	    fc = ParamLocOnStack[t] - 8;
	}

	if ((fr & VT_VALMASK) < VT_CONST)
	{
	    if (size == 1) {
		if (Unsigned)
		    C67_LDBU_PTR(v, r);
		else
		    C67_LDB_PTR(v, r);
	    } else if (size == 2) {
		if (Unsigned)
		    C67_LDHU_PTR(v, r);
		else
		    C67_LDH_PTR(v, r);
	    } else if (size == 4) {
		C67_LDW_PTR(v, r);
	    } else if (size == 8) {
		C67_LDDW_PTR(v, r);
	    }

	    C67_NOP(4);
	    return;
	} else if (fr & VT_SYM) {
	    greloc(cur_text_section, sv->sym, ind, R_C60LO16);
	    greloc(cur_text_section, sv->sym, ind + 4, R_C60HI16);

	    C67_MVKL(C67_A0, fc);
	    C67_MVKH(C67_A0, fc);

	    if (size == 1) {
		if (Unsigned)
		    C67_LDBU_PTR(C67_A0, r);
		else
		    C67_LDB_PTR(C67_A0, r);
	    } else if (size == 2) {
		if (Unsigned)
		    C67_LDHU_PTR(C67_A0, r);
		else
		    C67_LDH_PTR(C67_A0, r);
	    } else if (size == 4) {
		C67_LDW_PTR(C67_A0, r);
	    } else if (size == 8) {
		C67_LDDW_PTR(C67_A0, r);
	    }

	    C67_NOP(4);
	    return;
	} else {
	    element = size;

	    C67_MVKL(C67_A0, (fc / element) + 8 / element);
	    C67_MVKH(C67_A0, (fc / element) + 8 / element);

	    if (size == 1) {
		if (Unsigned)
		    C67_LDBU_SP_A0(r);
		else
		    C67_LDB_SP_A0(r);
	    } else if (size == 2) {
		if (Unsigned)
		    C67_LDHU_SP_A0(r);
		else
		    C67_LDH_SP_A0(r);
	    } else if (size == 4) {
		C67_LDW_SP_A0(r);
	    } else if (size == 8) {
		C67_LDDW_SP_A0(r);
	    }

	    C67_NOP(4);
	    return;
	}
    } else {
	if (v == VT_CONST) {
	    if (fr & VT_SYM) {
		greloc(cur_text_section, sv->sym, ind, R_C60LO16);
		greloc(cur_text_section, sv->sym, ind + 4, R_C60HI16);
	    }
	    C67_MVKL(r, fc);
	    C67_MVKH(r, fc);
	} else if (v == VT_LOCAL) {
	    C67_MVKL(r, fc + 8);
	    C67_MVKH(r, fc + 8);
	    C67_ADD(C67_FP, r);
	} else if (v == VT_CMP) {
	    C67_MV(C67_compare_reg, r);
	} else if (v == VT_JMP || v == VT_JMPI) {
	    t = v & 1;
	    C67_B_DISP(4);
	    C67_MVKL(r, t);
	    C67_NOP(4);
	    gsym(fc);
	    C67_MVKL(r, t ^ 1);
	} else if (v != r) {
	    C67_MV(v, r);

	    if ((ft & VT_BTYPE) == VT_DOUBLE)
		C67_MV(v + 1, r + 1);
	}
    }
}

void store(int r, SValue * v)
{
    int fr, bt, ft, fc, size, t, element;

    ft = v->type.t;
    fc = v->c.i;
    fr = v->r & VT_VALMASK;
    bt = ft & VT_BTYPE;

    if (bt == VT_LDOUBLE) {
	tcc_error("long double not supported");
    } else {
	if (bt == VT_SHORT)
	    size = 2;
	else if (bt == VT_BYTE)
	    size = 1;
	else if (bt == VT_DOUBLE)
	    size = 8;
	else
	    size = 4;

	if ((v->r & VT_VALMASK) == VT_CONST) {

	    if (v->r & VT_SYM) {
		greloc(cur_text_section, v->sym, ind, R_C60LO16);
		greloc(cur_text_section, v->sym, ind + 4, R_C60HI16);
	    }
	    C67_MVKL(C67_A0, fc);
	    C67_MVKH(C67_A0, fc);

	    if (size == 1)
		C67_STB_PTR(r, C67_A0);
	    else if (size == 2)
		C67_STH_PTR(r, C67_A0);
	    else if (size == 4 || size == 8)
		C67_STW_PTR(r, C67_A0);

	    if (size == 8)
		C67_STW_PTR_PRE_INC(r + 1, C67_A0, 1);
	} else if ((v->r & VT_VALMASK) == VT_LOCAL) {

	    if (fc > 0)
	    {

		int stack_pos = 8;

		for (t = 0; t < NoCallArgsPassedOnStack; t++) {
		    if (fc == stack_pos)
			break;

		    stack_pos += TranslateStackToReg[t];
		}

		fc = ParamLocOnStack[t] - 8;
	    }

	    if (size == 8)
		element = 4;
	    else
		element = size;

	    C67_MVKL(C67_A0, (fc / element) + 8 / element);
	    C67_MVKH(C67_A0, (fc / element) + 8 / element);

	    if (size == 1)
		C67_STB_SP_A0(r);
	    else if (size == 2)
		C67_STH_SP_A0(r);
	    else if (size == 4 || size == 8)
		C67_STW_SP_A0(r);

	    if (size == 8) {
		C67_ADDK(1, C67_A0);
		C67_STW_SP_A0(r + 1);
	    }
	} else {
	    if (size == 1)
		C67_STB_PTR(r, fr);
	    else if (size == 2)
		C67_STH_PTR(r, fr);
	    else if (size == 4 || size == 8)
		C67_STW_PTR(r, fr);

	    if (size == 8) {
		C67_STW_PTR_PRE_INC(r + 1, fr, 1);
	    }
	}
    }
}

static void gcall_or_jmp(int is_jmp)
{
    int r;
    Sym *sym;

    if ((vtop->r & (VT_VALMASK | VT_LVAL)) == VT_CONST) {

	if (vtop->r & VT_SYM) {

	    greloc(cur_text_section, vtop->sym, ind, R_C60LO16);
	    greloc(cur_text_section, vtop->sym, ind + 4, R_C60HI16);

	    C67_MVKL(C67_A0, 0);
	    C67_MVKH(C67_A0, 0);
	    C67_IREG_B_REG(0, C67_CREG_ZERO, C67_A0);

	    if (is_jmp) {
		C67_NOP(5);
	    } else {

		sym = get_sym_ref(&char_pointer_type, cur_text_section, ind + 12, 0);
		greloc(cur_text_section, sym, ind, R_C60LO16);
		greloc(cur_text_section, sym, ind + 4, R_C60HI16);
		C67_MVKL(C67_B3, 0);
		C67_MVKH(C67_B3, 0);
		C67_NOP(3);
	    }
	} else {

	    ALWAYS_ASSERT(FALSE);
	}
    } else {

	r = gv(RC_INT);
	C67_IREG_B_REG(0, C67_CREG_ZERO, r);

	if (is_jmp) {
	    C67_NOP(5);
	} else {

	    sym = get_sym_ref(&char_pointer_type, cur_text_section, ind + 12, 0);
	    greloc(cur_text_section, sym, ind, R_C60LO16);
	    greloc(cur_text_section, sym, ind + 4, R_C60HI16);
	    C67_MVKL(C67_B3, 0);
	    C67_MVKH(C67_B3, 0);
	    C67_NOP(3);
	}
    }
}

ST_FUNC int gfunc_sret(CType *vt, int variadic, CType *ret, int *ret_align, int *regsize) {
    *ret_align = 1;
    return 0;
}

void gfunc_call(int nb_args)
{
    int i, r, size = 0;
    int args_sizes[NoCallArgsPassedOnStack];

    if (nb_args > NoCallArgsPassedOnStack) {
	tcc_error("more than 10 function params not currently supported");

    }

    for (i = 0; i < nb_args; i++) {
	if ((vtop->type.t & VT_BTYPE) == VT_STRUCT) {
	    ALWAYS_ASSERT(FALSE);
	} else {

	    if ((vtop->type.t & VT_BTYPE) == VT_LLONG) {
		tcc_error("long long not supported");
	    } else if ((vtop->type.t & VT_BTYPE) == VT_LDOUBLE) {
		tcc_error("long double not supported");
	    } else if ((vtop->type.t & VT_BTYPE) == VT_DOUBLE) {
		size = 8;
	    } else {
		size = 4;
	    }

	    r = gv(RC_C67_A4 << (2 * i));

	    C67_PUSH(r);

	    if (size == 8) {
		C67_STW_PTR_PRE_INC(r + 1, C67_SP, 3);
	    }
	    args_sizes[i] = size;
	}
	vtop--;
    }

    for (i = nb_args - 1; i >= 0; i--) {

	if (args_sizes[i] == 8)
	    C67_POP_DW(TREG_C67_A4 + i * 2);
	else
	    C67_POP(TREG_C67_A4 + i * 2);
    }
    gcall_or_jmp(0);
    vtop--;
}

void gfunc_prolog(Sym *func_sym)
{
    CType *func_type = &func_sym->type;
    int addr, align, size, func_call, i;
    Sym *sym;
    CType *type;

    sym = func_type->ref;
    func_call = sym->f.func_call;
    addr = 8;

    if ((func_vt.t & VT_BTYPE) == VT_STRUCT) {
	func_vc = addr;
	addr += 4;
    }

    NoOfCurFuncArgs = 0;

    while ((sym = sym->next) != NULL) {
	type = &sym->type;
	sym_push(sym->v & ~SYM_FIELD, type, VT_LOCAL | VT_LVAL, addr);
	size = type_size(type, &align);
	size = (size + 3) & ~3;

	TranslateStackToReg[NoOfCurFuncArgs] = size;
	NoOfCurFuncArgs++;

#ifdef FUNC_STRUCT_PARAM_AS_PTR

	if ((type->t & VT_BTYPE) == VT_STRUCT) {
	    size = 4;
	}
#endif
	addr += size;
    }
    func_ret_sub = 0;

    if (func_call == FUNC_STDCALL)
	func_ret_sub = addr - 8;

    C67_MV(C67_FP, C67_A0);
    C67_MV(C67_SP, C67_FP);

    loc = 0;
    for (i = 0; i < NoOfCurFuncArgs; i++) {

	ParamLocOnStack[i] = loc;
	loc += -8;

	C67_PUSH(TREG_C67_A4 + i * 2);

	if (TranslateStackToReg[i] == 8) {
	    C67_STW_PTR_PRE_INC(TREG_C67_A4 + i * 2 + 1, C67_SP, 3);
	}
    }

    TotalBytesPushedOnStack = -loc;

    func_sub_sp_offset = ind;
    C67_ADDK(0, C67_SP);

    C67_PUSH(C67_A0);
    C67_PUSH(C67_B3);
}

void gfunc_epilog(void)
{
    {
	int local = (-loc + 7) & -8;
	C67_POP(C67_B3);
	C67_NOP(4);
	C67_IREG_B_REG(0, C67_CREG_ZERO, C67_B3);
	C67_POP(C67_FP);
	C67_ADDK(local, C67_SP);
	C67_Adjust_ADDK((int *) (cur_text_section->data +
				 func_sub_sp_offset),
			-local + TotalBytesPushedOnStack);
	C67_NOP(3);
    }
}

ST_FUNC void gen_fill_nops(int bytes)
{
    if ((bytes & 3))
      tcc_error("alignment of code section not multiple of 4");
    while (bytes > 0) {
	C67_NOP(4);
	bytes -= 4;
    }
}

int gjmp(int t)
{
    int ind1 = ind;
    if (nocode_wanted)
        return t;

    C67_MVKL(C67_A0, t);
    C67_MVKH(C67_A0, t);
    C67_IREG_B_REG(0, C67_CREG_ZERO, C67_A0);
    C67_NOP(5);
    return ind1;
}

void gjmp_addr(int a)
{
    Sym *sym;

    sym = get_sym_ref(&char_pointer_type, cur_text_section, a, 0);
    greloc(cur_text_section, sym, ind, R_C60LO16);
    greloc(cur_text_section, sym, ind + 4, R_C60HI16);

    gjmp(0);
}

ST_FUNC int gjmp_cond(int op, int t)
{
        int ind1;
        int inv = op & 1;
        if (nocode_wanted)
            return t;

	ind1 = ind;
	C67_MVKL(C67_A0, t);
	C67_MVKH(C67_A0, t);

	if (C67_compare_reg != TREG_EAX &&
	    C67_compare_reg != TREG_EDX &&
	    C67_compare_reg != TREG_ST0 && C67_compare_reg != C67_B2) {
	    C67_MV(C67_compare_reg, C67_B2);
	    C67_compare_reg = C67_B2;
	}

	C67_IREG_B_REG(C67_invert_test ^ inv, C67_compare_reg, C67_A0);
	C67_NOP(5);
	t = ind1;

        return t;
}

ST_FUNC int gjmp_append(int n0, int t)
{
    if (n0) {
            int n = n0, *p;

	    while (n != 0) {
		p = (int *) (cur_text_section->data + n);

		n = ((*p >> 7) & 0xffff);
		n |= ((*(p + 1) >> 7) & 0xffff) << 16;
	    }
	    *p |= (t & 0xffff) << 7;
	    *(p + 1) |= ((t >> 16) & 0xffff) << 7;
	    t = n0;
    }
    return t;
}

void gen_opi(int op)
{
    int r, fr, opc, t;

    switch (op) {
    case '+':
    case TOK_ADDC1:
	opc = 0;
      gen_op8:

	if (op >= TOK_ULT && op <= TOK_GT)
	    gv2(RC_INT_BSIDE, RC_INT);
	else
	    gv2(RC_INT, RC_INT);

	r = vtop[-1].r;
	fr = vtop[0].r;

	C67_compare_reg = C67_B2;

	if (op == TOK_LT) {
	    C67_CMPLT(r, fr, C67_B2);
	    C67_invert_test = FALSE;
	} else if (op == TOK_GE) {
	    C67_CMPLT(r, fr, C67_B2);
	    C67_invert_test = TRUE;
	} else if (op == TOK_GT) {
	    C67_CMPGT(r, fr, C67_B2);
	    C67_invert_test = FALSE;
	} else if (op == TOK_LE) {
	    C67_CMPGT(r, fr, C67_B2);
	    C67_invert_test = TRUE;
	} else if (op == TOK_EQ) {
	    C67_CMPEQ(r, fr, C67_B2);
	    C67_invert_test = FALSE;
	} else if (op == TOK_NE) {
	    C67_CMPEQ(r, fr, C67_B2);
	    C67_invert_test = TRUE;
	} else if (op == TOK_ULT) {
	    C67_CMPLTU(r, fr, C67_B2);
	    C67_invert_test = FALSE;
	} else if (op == TOK_UGE) {
	    C67_CMPLTU(r, fr, C67_B2);
	    C67_invert_test = TRUE;
	} else if (op == TOK_UGT) {
	    C67_CMPGTU(r, fr, C67_B2);
	    C67_invert_test = FALSE;
	} else if (op == TOK_ULE) {
	    C67_CMPGTU(r, fr, C67_B2);
	    C67_invert_test = TRUE;
	} else if (op == '+')
	    C67_ADD(fr, r);
	else if (op == '-')
	    C67_SUB(fr, r);
	else if (op == '&')
	    C67_AND(fr, r);
	else if (op == '|')
	    C67_OR(fr, r);
	else if (op == '^')
	    C67_XOR(fr, r);
	else
	    ALWAYS_ASSERT(FALSE);

	vtop--;
	if (op >= TOK_ULT && op <= TOK_GT)
            vset_VT_CMP(0x80);
	break;
    case '-':
    case TOK_SUBC1:
	opc = 5;
	goto gen_op8;
    case TOK_ADDC2:
	opc = 2;
	goto gen_op8;
    case TOK_SUBC2:
	opc = 3;
	goto gen_op8;
    case '&':
	opc = 4;
	goto gen_op8;
    case '^':
	opc = 6;
	goto gen_op8;
    case '|':
	opc = 1;
	goto gen_op8;
    case '*':
    case TOK_UMULL:
	gv2(RC_INT, RC_INT);
	r = vtop[-1].r;
	fr = vtop[0].r;
	vtop--;
	C67_MPYI(fr, r);
	C67_NOP(8);
	break;
    case TOK_SHL:
	gv2(RC_INT_BSIDE, RC_INT_BSIDE);
	r = vtop[-1].r;
	fr = vtop[0].r;
	vtop--;
	C67_SHL(fr, r);
	break;

    case TOK_SHR:
	gv2(RC_INT_BSIDE, RC_INT_BSIDE);
	r = vtop[-1].r;
	fr = vtop[0].r;
	vtop--;
	C67_SHRU(fr, r);
	break;

    case TOK_SAR:
	gv2(RC_INT_BSIDE, RC_INT_BSIDE);
	r = vtop[-1].r;
	fr = vtop[0].r;
	vtop--;
	C67_SHR(fr, r);
	break;

    case '/':
	t = TOK__divi;
      call_func:
	vswap();

	vpush_helper_func(t);
	vrott(3);
	gfunc_call(2);
	vpushi(0);
	vtop->r = REG_IRET;
	vtop->r2 = VT_CONST;
	break;
    case TOK_UDIV:
    case TOK_PDIV:
	t = TOK__divu;
	goto call_func;
    case '%':
	t = TOK__remi;
	goto call_func;
    case TOK_UMOD:
	t = TOK__remu;
	goto call_func;

    default:
	opc = 7;
	goto gen_op8;
    }
}

void gen_opf(int op)
{
    int ft, fc, fr, r;

    if (op >= TOK_ULT && op <= TOK_GT)
	gv2(RC_EDX, RC_EAX);
    else
	gv2(RC_FLOAT, RC_FLOAT);

    ft = vtop->type.t;
    fc = vtop->c.i;
    r = vtop->r;
    fr = vtop[-1].r;

    if ((ft & VT_BTYPE) == VT_LDOUBLE)
	tcc_error("long doubles not supported");

    if (op >= TOK_ULT && op <= TOK_GT) {

	r = vtop[-1].r;
	fr = vtop[0].r;

	C67_compare_reg = C67_B2;

	if (op == TOK_LT) {
	    if ((ft & VT_BTYPE) == VT_DOUBLE)
		C67_CMPLTDP(r, fr, C67_B2);
	    else
		C67_CMPLTSP(r, fr, C67_B2);

	    C67_invert_test = FALSE;
	} else if (op == TOK_GE) {
	    if ((ft & VT_BTYPE) == VT_DOUBLE)
		C67_CMPLTDP(r, fr, C67_B2);
	    else
		C67_CMPLTSP(r, fr, C67_B2);

	    C67_invert_test = TRUE;
	} else if (op == TOK_GT) {
	    if ((ft & VT_BTYPE) == VT_DOUBLE)
		C67_CMPGTDP(r, fr, C67_B2);
	    else
		C67_CMPGTSP(r, fr, C67_B2);

	    C67_invert_test = FALSE;
	} else if (op == TOK_LE) {
	    if ((ft & VT_BTYPE) == VT_DOUBLE)
		C67_CMPGTDP(r, fr, C67_B2);
	    else
		C67_CMPGTSP(r, fr, C67_B2);

	    C67_invert_test = TRUE;
	} else if (op == TOK_EQ) {
	    if ((ft & VT_BTYPE) == VT_DOUBLE)
		C67_CMPEQDP(r, fr, C67_B2);
	    else
		C67_CMPEQSP(r, fr, C67_B2);

	    C67_invert_test = FALSE;
	} else if (op == TOK_NE) {
	    if ((ft & VT_BTYPE) == VT_DOUBLE)
		C67_CMPEQDP(r, fr, C67_B2);
	    else
		C67_CMPEQSP(r, fr, C67_B2);

	    C67_invert_test = TRUE;
	} else {
	    ALWAYS_ASSERT(FALSE);
	}
        vset_VT_CMP(0x80);
    } else {
	if (op == '+') {
	    if ((ft & VT_BTYPE) == VT_DOUBLE) {
		C67_ADDDP(r, fr);
		C67_NOP(6);
	    } else {
		C67_ADDSP(r, fr);
		C67_NOP(3);
	    }
	    vtop--;
	} else if (op == '-') {
	    if ((ft & VT_BTYPE) == VT_DOUBLE) {
		C67_SUBDP(r, fr);
		C67_NOP(6);
	    } else {
		C67_SUBSP(r, fr);
		C67_NOP(3);
	    }
	    vtop--;
	} else if (op == '*') {
	    if ((ft & VT_BTYPE) == VT_DOUBLE) {
		C67_MPYDP(r, fr);
		C67_NOP(9);
	    } else {
		C67_MPYSP(r, fr);
		C67_NOP(3);
	    }
	    vtop--;
	} else if (op == '/') {
	    if ((ft & VT_BTYPE) == VT_DOUBLE) {

		vswap();

		vpush_helper_func(TOK__divd);
		vrott(3);
		gfunc_call(2);
		vpushi(0);
		vtop->r = REG_FRET;
		vtop->r2 = REG_IRE2;

	    } else {

		vswap();

		vpush_helper_func(TOK__divf);
		vrott(3);
		gfunc_call(2);
		vpushi(0);
		vtop->r = REG_FRET;
		vtop->r2 = VT_CONST;
	    }
	} else
	    ALWAYS_ASSERT(FALSE);

    }
}

void gen_cvt_itof(int t)
{
    int r;

    gv(RC_INT);
    r = vtop->r;

    if ((t & VT_BTYPE) == VT_DOUBLE) {
	if (t & VT_UNSIGNED)
	    C67_INTDPU(r, r);
	else
	    C67_INTDP(r, r);

	C67_NOP(4);
	vtop->type.t = VT_DOUBLE;
    } else {
	if (t & VT_UNSIGNED)
	    C67_INTSPU(r, r);
	else
	    C67_INTSP(r, r);
	C67_NOP(3);
	vtop->type.t = VT_FLOAT;
    }

}

void gen_cvt_ftoi(int t)
{
    int r;

    gv(RC_FLOAT);
    r = vtop->r;

    if (t != VT_INT)
	tcc_error("long long not supported");
    else {
	if ((vtop->type.t & VT_BTYPE) == VT_DOUBLE) {
	    C67_DPTRUNC(r, r);
	    C67_NOP(3);
	} else {
	    C67_SPTRUNC(r, r);
	    C67_NOP(3);
	}

	vtop->type.t = VT_INT;

    }
}

void gen_cvt_ftof(int t)
{
    int r, r2;

    if ((vtop->type.t & VT_BTYPE) == VT_DOUBLE &&
	(t & VT_BTYPE) == VT_FLOAT) {

	gv(RC_FLOAT);

	r = vtop->r;

	C67_DPSP(r, r);
	C67_NOP(3);

	vtop->type.t = VT_FLOAT;
	vtop->r2 = VT_CONST;
    } else if ((vtop->type.t & VT_BTYPE) == VT_FLOAT &&
	       (t & VT_BTYPE) == VT_DOUBLE) {

	gv(RC_FLOAT);

	r = vtop->r;

	if (r == TREG_EAX) {
	    r2 = get_reg(RC_ECX);
	} else if (r == TREG_EDX) {
	    r2 = get_reg(RC_ST0);
	} else {
	    ALWAYS_ASSERT(FALSE);
            r2 = 0;
        }

	C67_SPDP(r, r);
	C67_NOP(1);

	vtop->type.t = VT_DOUBLE;
	vtop->r2 = r2;
    } else {
	ALWAYS_ASSERT(FALSE);
    }
}

void ggoto(void)
{
    gcall_or_jmp(1);
    vtop--;
}

ST_FUNC void gen_vla_sp_save(int addr) {
    tcc_error("variable length arrays unsupported for this target");
}

ST_FUNC void gen_vla_sp_restore(int addr) {
    tcc_error("variable length arrays unsupported for this target");
}

ST_FUNC void gen_vla_alloc(CType *type, int align) {
    tcc_error("variable length arrays unsupported for this target");
}

#endif
