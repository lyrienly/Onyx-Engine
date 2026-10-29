#ifndef VMM_NPHANDLER_H_
#define VMM_NPHANDLER_H_

#include "common.h"
#include "vmmhelper.h"

QWORD NPMapPhysicalMemory(pcpuinfo currentcpuinfo, QWORD physicalAddress, int forcesmallpage);
VMSTATUS handleNestedPagingFault(pcpuinfo currentcpuinfo, VMRegisters *vmregisters UNUSED, PFXSAVE64 fxsave UNUSED);

void NPMode1CloakSetState(pcpuinfo currentcpuinfo, int state);

#endif
