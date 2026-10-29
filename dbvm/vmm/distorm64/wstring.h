#ifndef WSTRING_H
#define WSTRING_H

#include "../config.h"

#define MAX_TEXT_SIZE (60)

typedef struct {
	unsigned int pos;
	int8_t p[MAX_TEXT_SIZE];
} _WString;

#define strcat_WSN(s, t) strcatlen_WS((s), (t), sizeof((t))-1)
#define strcpy_WSN(s, t) strcpylen_WS((s), (t), sizeof((t))-1)

void _FASTCALL_ strcpy_WS(_WString* s, const int8_t* buf);
void _FASTCALL_ strcpylen_WS(_WString* s, const int8_t* buf, unsigned int len);
void _FASTCALL_ strcatlen_WS(_WString* s, const int8_t* buf, unsigned int len);

_INLINE_ void strclear_WS(_WString* s)
{
	s->p[0] = '\0';
	s->pos = 0;
}

_INLINE_ void chrcat_WS(_WString* s, uint8_t ch)
{
	s->p[s->pos] = ch;
	s->p[s->pos + 1] = '\0';
	s->pos += 1;
}

#endif
