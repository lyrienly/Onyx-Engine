#ifndef VMM_VMXEMU_H_
#define VMM_VMXEMU_H_

#include "vmmhelper.h"

typedef struct _instruction_info_vm
{
  union{
    unsigned long instructioninfo;
    struct {
      unsigned scaling    :2;
      unsigned reserved1  :1;
      unsigned reg1       :4;
      unsigned addressSize:3;
      unsigned usesreg    :1;
      unsigned undefined  :4;
      unsigned segmentReg :3;
      unsigned indexReg   :4;
      unsigned indexRegInvalid :1;
      unsigned baseReg    :4;
      unsigned baseRegInvalid :1;
      unsigned reg2       :4;
    };
  };
} __attribute__((__packed__)) instruction_info_vm,*pinstruction_info_vm;

int handleIntelVMXInstruction(pcpuinfo currentcpuinfo, VMRegisters *vmregisters);
int emulateVMExit(pcpuinfo currentcpuinfo, VMRegisters *vmregisters);
extern int emulatevmx;

int handleAMDVMRUNInstruction(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, FXSAVE64 *fxsave);

#endif
