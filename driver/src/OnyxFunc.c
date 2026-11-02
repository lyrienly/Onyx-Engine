#pragma warning( disable: 4103)

#include <ntifs.h>
#include <ntddk.h>
#include "OnyxFunc.h"
#include "vmxhelper.h"
#include "xorstr.h"

/*
 * OnyxEngine Kernel Driver - Modular Architecture
 * Domain subsystems separated into modular components.
 */

#include "cpu.c"
#include "physmem.c"
#include "callbacks.c"
#include "stealth.c"
#include "dkom.c"
#include "proof.c"
