#ifndef VMEVENTHANDLER_H_
#define VMEVENTHANDLER_H_

#include "main.h"
#include "vmmhelper.h"

#define SSR_HANDLEWATCH 1
#define SSR_HANDLECLOAK 2
#define SSR_HANDLESOFTWAREBREAKPOINT 3
#define SSR_STEPANDBREAK 4
#define SSR_STEPTILLINTERUPTABLE 5

typedef struct

{
  unsigned char Transmitter_Holding_Buffer;
  unsigned char Receiver_Buffer;
  unsigned char Devisor_Latch_Low;

  unsigned char Interrupt_Enable_Register;
  unsigned char Devisor_Latch_High;

  unsigned char Interrupt_Identification_Register;
  unsigned char FIFO_Control_Register;

  unsigned char Line_Control_Register;
  unsigned char Modem_Control_Register;

  unsigned char Line_Status_Register;
  unsigned char Modem_Status_Register;

  unsigned char Scratch_Register;
} FakeCOMport, *PFakeCOMport;
FakeCOMport fakecom1;

int DidHLT;

typedef struct
{
  union {
    ULONG Exit_Qualification;
    struct {
      ULONG size      : 3;
      ULONG direction : 1;
      ULONG isstring  : 1;
      ULONG hasrep    : 1;
      ULONG opperand  : 1;
      ULONG reserved  : 9;
      ULONG portnr    : 16;
    };
  };
} __attribute__((__packed__)) IOExit_Qualification;

int handleVMEvent(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, FXSAVE64 *fxsave);

void setRegister(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, int general_purpose_register, UINT64 value);
UINT64 getRegister(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, int general_purpose_register);

ULONG getSegmentLimit(PGDT_ENTRY gdt, PGDT_ENTRY ldt, ULONG selector);
ULONG getSegmentBase(PGDT_ENTRY gdt, PGDT_ENTRY ldt, ULONG selector);
UINT64 getSegmentBaseEx(PGDT_ENTRY gdt, PGDT_ENTRY ldt, ULONG selector, int expandto80bit);
void setDescriptorAccessedFlag(PGDT_ENTRY gdt, PGDT_ENTRY ldt, ULONG selector);
ULONG getSegmentAccessRights(PGDT_ENTRY gdt, PGDT_ENTRY ldt, ULONG selector);
ULONG getSegmentAttrib(PGDT_ENTRY gdt, PGDT_ENTRY ldt, ULONG selector);

int handle_rdtsc(pcpuinfo currentcpuinfo, VMRegisters *vmregisters);
BOOL handleSoftwareBreakpoint(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, FXSAVE64 *fxsave);

int setVM_CR0(pcpuinfo currentcpuinfo, UINT64 newcr0);
int setVM_CR3(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, UINT64 newcr3);
int setVM_CR4(pcpuinfo currentcpuinfo, UINT64 newcr4);

int handleSingleStep(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, FXSAVE64 *fxsave);
int handleRealModeInt0x15(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, int instructionsize);
int raisePMI();
int raiseNMI(void);
int raiseGeneralProtectionFault(UINT64 errorcode);

int emulateExceptionInterrupt(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, unsigned int cs, UINT64 rip, int haserrorcode, UINT64 errorcode, int isFault);

WORD convertSegmentAccessRightsToSegmentAttrib(ULONG accessrights);

extern volatile QWORD globalTSC;
extern volatile QWORD lowestTSC;

extern criticalSection CR3ValueLogCS;
extern QWORD *CR3ValueLog;
extern int CR3ValuePos;

extern int adjustTimestampCounters;
extern int adjustTimestampCounterTimeout;

extern int useSpeedhack;

void speedhack_setspeed(double speed);

void incrementRIP(int count);

#endif
