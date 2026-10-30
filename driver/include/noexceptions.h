#ifndef NOEXCEPTIONS_H
#define NOEXCEPTIONS_H

#include <ntifs.h>
#include <wdm.h>
#include <windef.h>

#include "interruptHook.h"
#include "OnyxFunc.h"

typedef struct
{
	KIRQL entryIRQL;
	PINT_VECTOR NoExceptionVectorList;
	IDT OriginalIDT;
	IDT ModdedIDT;
} CPUSTATE, *PCPUSTATE;

BOOL NoExceptions_Enter();
int  NoExceptions_CopyMemory(PVOID Destination, PVOID Source, int size);
void NoExceptions_Leave();

void NoExceptions_Cleanup();

void NoException14_ErrorHandler();

#endif
