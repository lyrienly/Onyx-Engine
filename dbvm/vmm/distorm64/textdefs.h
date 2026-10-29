#ifndef TEXTDEFS_H
#define TEXTDEFS_H

#include "../config.h"

#include "wstring.h"

#define PLUS_DISP_CHR '+'
#define MINUS_DISP_CHR '-'

#define OPEN_CHR0 '('
#define CLOSE_CHR0 ')'
#define OPEN_CHR '['
#define CLOSE_CHR ']'
extern int8_t SEP_STR[3];
#define SEP_CHR ','
#define SP_CHR ' '
#define SEG_OFF_CHR ':'

extern int8_t TextBTable[256][4];

_INLINE_ int8_t* get_hex_b(unsigned int x)
{
	return &TextBTable[x & 255][1];
}

void _FASTCALL_ str_hex_b(_WString* s, unsigned int x);
void _FASTCALL_ str_code_hb(_WString* s, unsigned int x);

void _FASTCALL_ str_hex_sp_b(_WString* s, unsigned int x);
void _FASTCALL_ str_code_sp_hb(_WString* s, unsigned int x);

void _FASTCALL_ str_hex_sp_w(_WString* s, unsigned int x);
void _FASTCALL_ str_code_hw(_WString* s, unsigned int x);

void _FASTCALL_ str_hex_sp_dw(_WString* s, uint32_t x);
void _FASTCALL_ str_code_hdw(_WString* s, uint32_t x);

void _FASTCALL_ str_hex_sp_qw(_WString* s, uint8_t src[8]);
void _FASTCALL_ str_code_hqw(_WString* s, uint8_t src[8]);

#ifdef SUPPORT_64BIT_OFFSET
void _FASTCALL_ str_off64(_WString* s, OFFSET_INTEGER x);
#endif

#endif
