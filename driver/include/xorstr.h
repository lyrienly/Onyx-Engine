#ifndef ONYX_XORSTR_H
#define ONYX_XORSTR_H

#include <ntddk.h>

/*
 * High-grade compile-time string encryption and stack decryption for Kernel Mode.
 * Ensures zero plaintext strings in .rdata / PE binary image.
 */

#define ONYX_XOR_KEY_1 0x5A
#define ONYX_XOR_KEY_2 0x3C

// Decrypts an encrypted byte buffer into a caller-provided stack buffer and null-terminates
FORCEINLINE PCHAR OnyxDecryptA(PCHAR Dst, const UCHAR* Src, SIZE_T Len, UCHAR Key)
{
    SIZE_T i;
    for (i = 0; i < Len; i++) {
        Dst[i] = (CHAR)(Src[i] ^ (Key + (UCHAR)(i % 7)));
    }
    Dst[Len] = '\0';
    return Dst;
}

FORCEINLINE PWCHAR OnyxDecryptW(PWCHAR Dst, const USHORT* Src, SIZE_T Len, USHORT Key)
{
    SIZE_T i;
    for (i = 0; i < Len; i++) {
        Dst[i] = (WCHAR)(Src[i] ^ (Key + (USHORT)(i % 7)));
    }
    Dst[Len] = L'\0';
    return Dst;
}

FORCEINLINE VOID OnyxSecureZero(PVOID Buffer, SIZE_T Size)
{
    volatile UCHAR* p = (volatile UCHAR*)Buffer;
    while (Size--) {
        *p++ = 0;
    }
}

#endif // ONYX_XORSTR_H
