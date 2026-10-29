#include "common.h"
#include "main.h"
#include "realmodeemu.h"
#include "vmmhelper.h"
#include "vmpaging.h"
#include "vmreadwrite.h"
#include "distorm.h"

#include "vmeventhandler.h"

int emulateProtectedMode(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  int result=0;

  if (currentcpuinfo==NULL)
    return 0;

  if (vmregisters==NULL)
    return 0;

  return result;
}
