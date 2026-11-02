#include "vmpaging.h"
#include "vmeventhandler.h"
#include "vmmhelper.h"
#include "neward.h"

#include "vmevent_invalidstate.h"
#include "realmodeemu.h"
#include "main.h"
#include "mm.h"
#include "common.h"
#include "vmcall.h"

#include "realmodeemu.h"
#include "msrnames.h"
#include "vmxcontrolstructures.h"
#include "ultimap.h"
#include "vmxemu.h"
#include "epthandler.h"
#include "vmxsetup.h"
#include "displaydebug.h"

#ifndef DEBUG
#define sendstringf(s,x...)
#define sendstring(s)
#endif

criticalSection CR3ValueLogCS={.name="CR3ValueLogCS", .debuglevel=2};
QWORD *CR3ValueLog;
int CR3ValuePos;

volatile QWORD globalTSC;
volatile QWORD lowestTSC=0;

int adjustTimestampCounters=1;
int adjustTimestampCounterTimeout=2000;

int useSpeedhack=0;
double speedhackSpeed=1.0f;
QWORD speedhackInitialOffset=0;
QWORD speedhackInitialTime=0;

criticalSection TSCCS={.name="TSCCS", .debuglevel=2};

int handle_rdtsc(pcpuinfo currentcpuinfo, VMRegisters *vmregisters);

void incrementRIP(int count)
{
  if (!isAMD)
  {
    QWORD newRIP=vmread(vm_guest_rip)+count;

    if (!IS64BITCODE(getcpuinfo()))
      newRIP=newRIP & 0xffffffff;

    vmwrite(vm_guest_rip,newRIP);
    vmwrite(vm_guest_interruptability_state, vmread(vm_guest_interruptability_state) & 0xfffffffc);
  }
}

int raiseNMI(void)
{
  VMEntry_interruption_information newintinfo;
  sendstring("Raising NMI\n\r");

  newintinfo.interruption_information=0;
  newintinfo.interruptvector=2;
  newintinfo.type=2;
  newintinfo.haserrorcode=0;
  newintinfo.valid=1;

  vmwrite(vm_entry_interruptioninfo, newintinfo.interruption_information);
  vmwrite(vm_entry_exceptionerrorcode, 0);
  vmwrite(vm_entry_instructionlength, vmread(vm_exit_instructionlength));
  return 0;
}

int raisePMI()
{

  int interruptvector;
  DWORD LVT_Perfmon_Counter_Register;
  VMEntry_interruption_information newintinfo;

  if (readMSR(IA32_APICBASE_MSR) & (1<<10))
  {
    LVT_Perfmon_Counter_Register=readMSR(IA32_X2APIC_LVT_PMI_MSR);

    writeMSR(IA32_X2APIC_LVT_PMI_MSR, LVT_Perfmon_Counter_Register | (1<<16));
  }
  else
  {
    LVT_Perfmon_Counter_Register=*(volatile DWORD *)(IA32_APIC_BASE+0x340);

    *(volatile DWORD *)(IA32_APIC_BASE+0x340)=LVT_Perfmon_Counter_Register | (1 << 16);
  }

  interruptvector=LVT_Perfmon_Counter_Register & 0xff;

  sendstringf("Raising PMI (Vector %d)\n",interruptvector);

  newintinfo.interruption_information=0;
  newintinfo.interruptvector=interruptvector;
  newintinfo.type=itExternal;
  newintinfo.haserrorcode=0;
  newintinfo.valid=1;

  vmwrite(vm_entry_interruptioninfo, newintinfo.interruption_information);
  vmwrite(vm_entry_exceptionerrorcode, 0);
  vmwrite(vm_entry_instructionlength, vmread(vm_exit_instructionlength));
  return 0;
}

int raiseGeneralProtectionFault(UINT64 errorcode)
{
  VMEntry_interruption_information newintinfo;

  sendstring("Raising GPF\n\r");

  if (isAMD)
  {
    pcpuinfo c=getcpuinfo();

    c->vmcb->inject_Type=3;
    c->vmcb->inject_Vector=13;
    c->vmcb->inject_Valid=1;
    c->vmcb->inject_EV=1;
    c->vmcb->inject_ERRORCODE=errorcode;
  }
  else
  {

    newintinfo.interruption_information=0;
    newintinfo.interruptvector=13;
    newintinfo.type=3;
    newintinfo.haserrorcode=1;
    newintinfo.valid=1;

    vmwrite(vm_entry_interruptioninfo, newintinfo.interruption_information);
    vmwrite(vm_entry_exceptionerrorcode, errorcode);
    vmwrite(vm_entry_instructionlength, vmread(vm_exit_instructionlength));
  }
  return 0;
}

int emulateExceptionInterrupt(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, unsigned int cs, UINT64 rip, int haserrorcode, UINT64 errorcode, int isFault)
{

  PGDT_ENTRY gdt=NULL,ldt=NULL;
  UINT64 gdtbase=isAMD?currentcpuinfo->vmcb->gdtr_base:vmread(vm_guest_gdtr_base);
  UINT64 gdtlimit=isAMD?currentcpuinfo->vmcb->gdtr_limit:vmread(vm_guest_gdt_limit);
  ULONG ldtselector=isAMD?currentcpuinfo->vmcb->ldtr_selector:vmread(vm_guest_ldtr);
  Access_Rights old_csaccessrights, new_csaccessrights;
  Segment_Attribs  new_csattribs;
  int privilege_level_changed=0;
  void *_TSS=NULL;

  sendstring("Emulation\n");
  if ((isAMD?currentcpuinfo->vmcb->cs_selector:vmread(vm_guest_cs))==0x10)
  {
    sendstring("!!!!!FROM KERNELMODE (assuming it\'s windows 64)!!!!!\n");
  }

  ULONG original_ss=isAMD?currentcpuinfo->vmcb->ss_selector:vmread(vm_guest_ss);
  UINT64 original_rsp=isAMD?currentcpuinfo->vmcb->RSP:vmread(vm_guest_rsp);
  ULONG original_cs=isAMD?currentcpuinfo->vmcb->cs_selector:vmread(vm_guest_cs);
  UINT64 original_rip=isAMD?currentcpuinfo->vmcb->RIP:vmread(vm_guest_rip);
  ULONG newSS=0;
  UINT64 newRSP=original_rsp;
  UINT64 rflags=isAMD?currentcpuinfo->vmcb->RFLAGS:vmread(vm_guest_rflags);
  PRFLAGS prflags=(PRFLAGS)&rflags;

  sendstringf("cs:rip=%x:%6\n", original_cs,original_rip);
  sendstringf("ss:rsp=%x:%6\n", original_ss,original_rsp);

  sendstringf("cpunr=%d\n",currentcpuinfo->cpunr);

  int notpaged=0;

  sendstring("Mapping the gdt\n");
  sendstringf("gdtbase=%6\n",gdtbase);

  gdt=mapVMmemory(currentcpuinfo, gdtbase, gdtlimit, NULL, NULL);
  if (gdt==NULL)
  {
    nosendchar[getAPICID()]=0;
    sendstring("For some messed up reason the gdt is paged out...");
    return 1;
  }

  ULONG ldtlimit;

  if (ldtselector)
  {
    ULONG ldtbase;

    nosendchar[getAPICID()]=0;
    sendstring("ldt is valid, so getting the information\n\r");

    ldtbase=(gdt[(ldtselector >> 3)].Base24_31 << 24) | gdt[(ldtselector >> 3)].Base0_23;
    ldtlimit=(gdt[(ldtselector >> 3)].Limit16_19 << 16) | gdt[(ldtselector >> 3)].Limit0_15;
    ldt=(PGDT_ENTRY)mapVMmemory(currentcpuinfo, ldtbase, ldtlimit, NULL,NULL);

    sendstringf("ldt=%8\n\r",(UINT64)ldt);
  }

  if (IS64BITPAGING(currentcpuinfo))
  {
    sendstring("IS64BITPAGING=1\n");

  }

  sendstringf("old cs=%x\n",original_cs);
  sendstringf("new cs=%x\n",cs);
  sendstringf("old ss=%x\n",original_ss);

  if (!isAMD)
  {
    old_csaccessrights.AccessRights=vmread(vm_guest_cs_access_rights);
    new_csaccessrights.AccessRights=getSegmentAccessRights(gdt,ldt,cs);

    sendstringf("old_cs accessrights=%x\n",old_csaccessrights.AccessRights);
    sendstringf("new_cs accessrights=%x\n",new_csaccessrights.AccessRights);
    privilege_level_changed=(old_csaccessrights.DPL != new_csaccessrights.DPL);
  }
  else
  {

    new_csattribs.SegmentAttrib=getSegmentAttrib(gdt, ldt, cs);

    sendstringf("new_cs attribs=%x\n",new_csattribs.SegmentAttrib);
    privilege_level_changed=(currentcpuinfo->vmcb->CPL != new_csattribs.DPL);

    sendstringf("new_csattribs.DPL=%d\n", new_csattribs.DPL);
  }

  sendstringf("privilege_level_changed=%d\n",privilege_level_changed);

  QWORD TSSBase=isAMD?currentcpuinfo->vmcb->tr_base:vmread(vm_guest_tr_base);
  QWORD TSSLimit=isAMD?currentcpuinfo->vmcb->tr_limit:vmread(vm_guest_tr_limit);

   _TSS=mapVMmemory(currentcpuinfo, TSSBase, TSSLimit, NULL, NULL);
  if (_TSS==NULL)
  {
    nosendchar[getAPICID()]=0;
    sendstring("TSS PAGING FAULT\n");

    if (gdt)
      unmapVMmemory(gdt,gdtlimit);

    if (ldt)
      unmapVMmemory(ldt, ldtlimit);
    return 1;

  }
  sendstringf("Mapped TSS(vma=%6) at vmma=%6\n\r",TSSBase, (UINT64)_TSS);

  if (isAMD)
  {
    currentcpuinfo->vmcb->CPL=new_csattribs.DPL;
    currentcpuinfo->vmcb->VMCB_CLEAN_BITS&=~(1 << 8);

    new_csaccessrights.DPL=currentcpuinfo->vmcb->CPL;
  }

  if (privilege_level_changed)
  {
    if (IS64BITPAGING(currentcpuinfo))
    {

      PTSS64 TSS=_TSS;

      sendstring("64-bit interrupt handling and privilege change\n");

      if (new_csaccessrights.DPL==0)
      {
        sendstringf("New DPL is 0. Setting RSP to RSP0 = %6\n", TSS->RSP0);
        newRSP=TSS->RSP0;

      }

      if (new_csaccessrights.DPL==1)
        newRSP=TSS->RSP1;

      if (new_csaccessrights.DPL==2)
        newRSP=TSS->RSP2;

    }
    else
    {

      PTSS TSS=_TSS;

      sendstring("32-bit interrupt handling\n\r");

      if (new_csaccessrights.DPL==0)
      {
        newRSP=TSS->ESP0;
        newSS=TSS->SS0;
      }

      if (new_csaccessrights.DPL==1)
      {
        newRSP=TSS->ESP1;
        newSS=TSS->SS1;
      }

      if (new_csaccessrights.DPL==2)
      {
        newRSP=TSS->ESP2;
        newSS=TSS->SS2;
      }

    }
  }

  sendstringf("newSS=%6\n", newSS);
  sendstringf("newRSP=%6\n", newRSP);

  if (isFault)
    prflags->RF=1;

  if (IS64BITPAGING(currentcpuinfo))
  {

    UINT64 rsp=newRSP;
    UINT64 *stack;
    int stackpos=0;

    sendstringf("Setting the stack for 64-bit. RSP=%6\n\r",rsp);

    if (!privilege_level_changed)
    {

      rsp=rsp & 0xfffffffffffffff0ULL;
      sendstringf("After alignment RSP=%6\n", rsp);
    }

    rsp-=5*8;
    if (haserrorcode)
    {
      sendstring("Has errorcode\n");
      rsp-=8;
    }
    sendstringf("After adjusting rsp for the pushes RSP=%6\n",rsp);

    stack=mapVMmemory(currentcpuinfo, rsp, 6*8, NULL, NULL);

    if (stack==NULL)
    {
      nosendchar[getAPICID()]=0;
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");

      sendstringf("SF-cs:rip=%x:%6\n", original_cs,original_rip);
      sendstringf("SF-ss:rsp=%x:%6\n", original_ss,original_rsp);
      sendstringf("SF-cr2=%6\n", getCR2());
      sendstringf("Errorcode=%6\n", errorcode);
      sendstringf("Mapped TSS(vma=%6) at vmma=%6\n\r",TSSBase, (UINT64)_TSS);

      sendvmstate(currentcpuinfo, vmregisters);

      if (gdt)
        unmapVMmemory(gdt,gdtlimit);

      if (ldt)
        unmapVMmemory(ldt, ldtlimit);

      if (_TSS)
        unmapVMmemory(_TSS, TSSLimit);

      return 1;
    }

    if (haserrorcode)
      stack[stackpos++]=errorcode;

    stack[stackpos++]=original_rip;
    stack[stackpos++]=original_cs;
    stack[stackpos++]=rflags;
    stack[stackpos++]=original_rsp;
    stack[stackpos++]=original_ss;

    if (isAMD)
      currentcpuinfo->vmcb->RSP=rsp;
    else
      vmwrite(vm_guest_rsp,rsp);

    sendstringf("[%6]=%6\n", rsp,stack[0]);
    sendstringf("[%6]=%6\n", rsp+8,stack[1]);
    sendstringf("[%6]=%6\n", rsp+2*8,stack[2]);
    sendstringf("[%6]=%6\n", rsp+3*8,stack[3]);
    sendstringf("[%6]=%6\n", rsp+4*8,stack[4]);
    if (haserrorcode)
    {
      sendstringf("[%6]=%6\n", rsp+5*8,stack[5]);
    }

    if (stack)
      unmapVMmemory(stack, 6*8);
  }
  else
  {

    ULONG esp=newRSP;
    ULONG *stack;
    int stackpos=0;
    sendstring("Setting the stack for 32-bit\n\r");

    esp=esp-3*4;
    if (haserrorcode)
      esp-=4;

    if (privilege_level_changed)
      esp-=2*4;

    stack=mapVMmemory(currentcpuinfo, esp, 6*4, NULL, NULL);

    if (notpaged)
    {
      nosendchar[getAPICID()]=0;
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");
      sendstring("STACK FAILURE\n");

      sendstringf("SF-cs:rip=%x:%6\n", original_cs,original_rip);
      sendstringf("SF-ss:rsp=%x:%6\n", original_ss,original_rsp);
      sendstringf("SF-cr2=%6\n", getCR2());
      sendstringf("Errorcode=%6\n", errorcode);
      sendstringf("Mapped TSS(vma=%6) at vmma=%6\n\r",TSSBase, (UINT64)_TSS);

      sendvmstate(currentcpuinfo, vmregisters);

      if (gdt)
        unmapVMmemory(gdt,gdtlimit);

      if (ldt)
        unmapVMmemory(ldt, ldtlimit);

      if (_TSS)
        unmapVMmemory(_TSS, TSSLimit);

      return 1;

    }

    if (haserrorcode)
      stack[stackpos++]=errorcode;

    stack[stackpos++]=original_rip;
    stack[stackpos++]=original_cs;
    stack[stackpos++]=rflags;

    if (privilege_level_changed)
    {
      stack[stackpos++]=original_rsp;
      stack[stackpos++]=original_ss;
    }

    if (isAMD)
      currentcpuinfo->vmcb->RSP=esp;
    else
      vmwrite(vm_guest_rsp,esp);

    if (stack)
      unmapVMmemory(stack, 6*4);
  }

  prflags->TF=0;
  prflags->IF=0;
  prflags->VM=0;
  prflags->RF=0;
  prflags->NT=0;

  if (isAMD)
    currentcpuinfo->vmcb->RFLAGS=2;
  else
    vmwrite(vm_guest_rflags,2);

  if (privilege_level_changed)
  {
    if (IS64BITPAGING(currentcpuinfo))
    {

      if (isAMD)
      {
        currentcpuinfo->vmcb->ss_selector=0;
        currentcpuinfo->vmcb->ss_base=0;
        currentcpuinfo->vmcb->ss_limit=0;
        currentcpuinfo->vmcb->ss_attrib=0;
      }
      else
      {
        vmwrite(vm_guest_ss,0);
        vmwrite(vm_guest_ss_base,getSegmentBase(gdt,ldt,0));
        vmwrite(vm_guest_ss_limit,getSegmentLimit(gdt,ldt,0));
        vmwrite(vm_guest_ss_access_rights,getSegmentAccessRights(gdt,ldt,0));
      }
    }
    else
    {

      if (isAMD)
      {
        currentcpuinfo->vmcb->ss_selector=newSS;
        currentcpuinfo->vmcb->ss_base=getSegmentBase(gdt,ldt,newSS);
        currentcpuinfo->vmcb->ss_limit=getSegmentLimit(gdt,ldt,newSS);
        currentcpuinfo->vmcb->ss_attrib=getSegmentAttrib(gdt,ldt,newSS);
        setDescriptorAccessedFlag(gdt,ldt,newSS);
      }
      else
      {
        vmwrite(vm_guest_ss,newSS);
        vmwrite(vm_guest_ss_base,getSegmentBase(gdt,ldt,newSS));
        vmwrite(vm_guest_ss_limit,getSegmentLimit(gdt,ldt,newSS));
        setDescriptorAccessedFlag(gdt,ldt,newSS);
        vmwrite(vm_guest_ss_access_rights,getSegmentAccessRights(gdt,ldt,newSS));
      }
    }

  }

  sendstringf("Setting cs to %x\n\r", cs);
  if (isAMD)
  {
    currentcpuinfo->vmcb->cs_selector=cs;
    currentcpuinfo->vmcb->cs_base=getSegmentBase(gdt,ldt,cs);
    currentcpuinfo->vmcb->cs_limit=getSegmentLimit(gdt,ldt,cs);
    currentcpuinfo->vmcb->cs_attrib=getSegmentAttrib(gdt,ldt,cs);

    sendstringf("currentcpuinfo->vmcb->cs_selector=%x\n", currentcpuinfo->vmcb->cs_selector);
    sendstringf("currentcpuinfo->vmcb->cs_base=%x\n", currentcpuinfo->vmcb->cs_base);
    sendstringf("currentcpuinfo->vmcb->cs_limit=%x\n", currentcpuinfo->vmcb->cs_limit);
    sendstringf("currentcpuinfo->vmcb->cs_attrib=%x\n", currentcpuinfo->vmcb->cs_attrib);

    setDescriptorAccessedFlag(gdt,ldt,cs);

  }
  else
  {
    vmwrite(vm_guest_cs, cs);
    vmwrite(vm_guest_cs_limit, getSegmentLimit(gdt, ldt, cs));
    vmwrite(vm_guest_cs_base, getSegmentBase(gdt, ldt, cs));
    setDescriptorAccessedFlag(gdt, ldt, cs);
    vmwrite(vm_guest_cs_access_rights, getSegmentAccessRights(gdt, ldt, cs));
  }

  sendstringf("Setting rip to %6\n\r", rip);

  if (isAMD)
    currentcpuinfo->vmcb->RIP=rip;
  else
    vmwrite(vm_guest_rip,rip);

  sendstringf("Returning\n\r");

  if (gdt)
    unmapVMmemory(gdt,gdtlimit);

  if (ldt)
    unmapVMmemory(ldt, ldtlimit);

  if (_TSS)
    unmapVMmemory(_TSS, TSSLimit);

  return 0;
}

void returnToRealmode(pcpuinfo currentcpuinfo)

{

  if (hasUnrestrictedSupport==0)
  {
    Access_Rights reg_csaccessrights;
    RFLAGS guestrflags=(RFLAGS)vmread(vm_guest_rflags);

    if (ISREALMODE(currentcpuinfo))
    {
      reg_csaccessrights.AccessRights=0;
      reg_csaccessrights.Segment_type=3;
      reg_csaccessrights.S=1;
      reg_csaccessrights.DPL=3;
      reg_csaccessrights.P=1;
      reg_csaccessrights.G=0;
      reg_csaccessrights.D_B=0;
      reg_csaccessrights.AVL=0;
      vmwrite(0x4814,(ULONG)reg_csaccessrights.AccessRights);
      vmwrite(0x4816,(ULONG)reg_csaccessrights.AccessRights);
      vmwrite(0x4818,(ULONG)reg_csaccessrights.AccessRights);
      vmwrite(0x481a,(ULONG)reg_csaccessrights.AccessRights);
      vmwrite(0x481c,(ULONG)reg_csaccessrights.AccessRights);
      vmwrite(0x481e,(ULONG)reg_csaccessrights.AccessRights);

      vmwrite(0x4800,(ULONG)0xffff);
      vmwrite(0x4802,(ULONG)0xffff);
      vmwrite(0x4804,(ULONG)0xffff);
      vmwrite(0x4806,(ULONG)0xffff);
      vmwrite(0x4808,(ULONG)0xffff);
      vmwrite(0x480a,(ULONG)0xffff);

      vmwrite(0x800,vmread(0x6806) >> 4);
      vmwrite(0x802,vmread(vm_guest_cs_base) >> 4);
      vmwrite(0x804,vmread(vm_guest_ss_base) >> 4);
      vmwrite(0x806,vmread(0x680c) >> 4);
      vmwrite(0x808,vmread(0x680e) >> 4);
      vmwrite(0x80a,vmread(0x6810) >> 4);

      guestrflags.VM=1;
      guestrflags.TF=0;
      guestrflags.RF=0;
      guestrflags.IOPL=3;
      guestrflags.IF=currentcpuinfo->hasIF;
      vmwrite(vm_guest_rflags,guestrflags.value);

    }
    else
    {
      nosendchar[getAPICID()]=0;
      sendstringf("ERROR: Guest doesn't WANT to be in realmode\n\r");
    }
  }
}

int handleINIT(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  UINT64 a,b,c,d;
  zeromemory(vmregisters,sizeof(VMRegisters));

  a=1;
  _cpuid(&a,&b,&c,&d);
  vmregisters->rdx=a;

  setup8086WaitForSIPI(currentcpuinfo,0);

  vmwrite(vm_guest_rip,0x0);

  vmwrite(vm_guest_activity_state,(UINT64)3);

  return 0;
}

int handleSIPI(void)
{
  UINT64 newcs,newcsbase,newip;

  sendstringf("Handling SIPI\n\r");

  newcs=(QWORD)(vmread(vm_exit_qualification)) << 8;
  newcsbase=newcs << 4;
  newip=0;

  vmwrite(0x802,newcs);

  vmwrite(vm_guest_cs_base,newcsbase);

  vmwrite(vm_guest_rip,newip);
  vmwrite(vm_guest_activity_state,(ULONG)0);

  return 0;
}

int handle_cr3_callback(pcpuinfo currentcpuinfo,VMRegisters *vmregisters)
{
  PGDT_ENTRY gdt=NULL,ldt=NULL;
  UINT64 gdtbase=vmread(0x6816);
  UINT64 gdtlimit=vmread(vm_guest_gdt_limit);
  ULONG ldtselector=vmread(0x80c);

  nosendchar[getAPICID()]=0;
  sendstringf("Handling cr3 edit. Is %x wants to set it to %x:\n\r", vmread(0x6802), currentcpuinfo->guestCR3);
  sendstring("Also, currently not implemented so no idea how this happened\n\r");

  ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);
  while (1) outportb(0x80,0xd4);

  if (currentcpuinfo->cr3_callback.called_callback)
  {

    vmwrite(0x6802, currentcpuinfo->guestCR3);
    vmwrite(vm_guest_rip, vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));

    currentcpuinfo->guestCR3 = currentcpuinfo->cr3_callback.newcr3;
    return 0;
  }

  currentcpuinfo->cr3_callback.newcr3 = currentcpuinfo->guestCR3;

  currentcpuinfo->cr3_callback.rax=vmregisters->rax;
  currentcpuinfo->cr3_callback.rbx=vmregisters->rbx;
  currentcpuinfo->cr3_callback.rcx=vmregisters->rcx;
  currentcpuinfo->cr3_callback.rdx=vmregisters->rdx;
  currentcpuinfo->cr3_callback.rsi=vmregisters->rsi;
  currentcpuinfo->cr3_callback.rdi=vmregisters->rdi;
  currentcpuinfo->cr3_callback.rbp=vmregisters->rbp;
  currentcpuinfo->cr3_callback.r8=vmregisters->r8;
  currentcpuinfo->cr3_callback.r9=vmregisters->r9;
  currentcpuinfo->cr3_callback.r10=vmregisters->r10;
  currentcpuinfo->cr3_callback.r11=vmregisters->r11;
  currentcpuinfo->cr3_callback.r12=vmregisters->r12;
  currentcpuinfo->cr3_callback.r13=vmregisters->r13;
  currentcpuinfo->cr3_callback.r14=vmregisters->r14;
  currentcpuinfo->cr3_callback.r15=vmregisters->r15;

  currentcpuinfo->cr3_callback.es_selector=vmread(0x800);
  currentcpuinfo->cr3_callback.cs_selector=vmread(0x802);
  currentcpuinfo->cr3_callback.ss_selector=vmread(0x804);
  currentcpuinfo->cr3_callback.ds_selector=vmread(0x806);
  currentcpuinfo->cr3_callback.fs_selector=vmread(0x808);
  currentcpuinfo->cr3_callback.gs_selector=vmread(0x80a);

  currentcpuinfo->cr3_callback.es_limit=vmread(0x4800);
  currentcpuinfo->cr3_callback.cs_limit=vmread(0x4802);
  currentcpuinfo->cr3_callback.ss_limit=vmread(0x4804);
  currentcpuinfo->cr3_callback.ds_limit=vmread(0x4806);
  currentcpuinfo->cr3_callback.fs_limit=vmread(0x4808);
  currentcpuinfo->cr3_callback.gs_limit=vmread(0x480a);

  currentcpuinfo->cr3_callback.es_base=vmread(0x6806);
  currentcpuinfo->cr3_callback.cs_base=vmread(vm_guest_cs_base);
  currentcpuinfo->cr3_callback.ss_base=vmread(vm_guest_ss_base);
  currentcpuinfo->cr3_callback.ds_base=vmread(0x680c);
  currentcpuinfo->cr3_callback.fs_base=vmread(0x680e);
  currentcpuinfo->cr3_callback.gs_base=vmread(0x6810);

  currentcpuinfo->cr3_callback.es_accessrights=vmread(0x4814);
  currentcpuinfo->cr3_callback.cs_accessrights=vmread(0x4816);
  currentcpuinfo->cr3_callback.ss_accessrights=vmread(0x4818);
  currentcpuinfo->cr3_callback.ds_accessrights=vmread(0x481a);
  currentcpuinfo->cr3_callback.fs_accessrights=vmread(0x481c);
  currentcpuinfo->cr3_callback.gs_accessrights=vmread(0x481e);

  currentcpuinfo->cr3_callback.rsp=vmread(vm_guest_rsp);

  currentcpuinfo->cr3_callback.rip=vmread(vm_guest_rip)+vmread(vm_exit_instructionlength);

  currentcpuinfo->cr3_callback.rflags=vmread(vm_guest_rflags);

  currentcpuinfo->cr3_callback.interruptability_state=vmread(vm_guest_interruptability_state);

  gdt=mapVMmemory(currentcpuinfo, gdtbase, gdtlimit, NULL, NULL);
  ULONG ldtlimit;

  if (ldtselector)
  {
    ULONG ldtbase;

    ldtbase=(gdt[(ldtselector >> 3)].Base24_31 << 24) + gdt[(ldtselector >> 3)].Base0_23;
    ldtlimit=(gdt[(ldtselector >> 3)].Limit16_19 << 16) + gdt[(ldtselector >> 3)].Limit0_15;

    ldt=mapVMmemory(currentcpuinfo, ldtbase, ldtlimit, NULL, NULL);
  }

  vmwrite(0x802,currentcpuinfo->cr3_callback.callback_cs);
  vmwrite(0x804,currentcpuinfo->cr3_callback.callback_ss);
  vmwrite(0x4800,getSegmentLimit(gdt,ldt,currentcpuinfo->cr3_callback.callback_cs));
  vmwrite(0x4802,getSegmentLimit(gdt,ldt,currentcpuinfo->cr3_callback.callback_ss));
  vmwrite(vm_guest_cs_base,getSegmentBase(gdt,ldt,currentcpuinfo->cr3_callback.callback_cs));
  vmwrite(vm_guest_ss_base,getSegmentBase(gdt,ldt,currentcpuinfo->cr3_callback.callback_ss));
  setDescriptorAccessedFlag(gdt,ldt,currentcpuinfo->cr3_callback.callback_cs);
  setDescriptorAccessedFlag(gdt,ldt,currentcpuinfo->cr3_callback.callback_ss);
  vmwrite(0x4816,getSegmentAccessRights(gdt,ldt,currentcpuinfo->cr3_callback.callback_cs));
  vmwrite(0x4818,getSegmentAccessRights(gdt,ldt,currentcpuinfo->cr3_callback.callback_ss));

  if (gdt)
    unmapVMmemory(gdt, gdtlimit);

  if (ldt)
    unmapVMmemory(ldt, ldtlimit);

  if (currentcpuinfo->cr3_callback.calling_convention==0)
  {

    ULONG *stack;

    stack=mapVMmemory(currentcpuinfo, currentcpuinfo->cr3_callback.callback_rsp-12, 12, NULL, NULL);

    stack[0]=vmread(vm_guest_rip);
    stack[1]=vmread(0x6802);
    stack[2]=currentcpuinfo->guestCR3;

    vmwrite(vm_guest_rsp, currentcpuinfo->cr3_callback.callback_rsp-12);

    unmapVMmemory(stack,12);

  }
  else
  {

    currentcpuinfo->cr3_callback.rdi=vmread(0x6802);
    currentcpuinfo->cr3_callback.rsi=currentcpuinfo->guestCR3;

    UINT64 *stack;
    stack=mapVMmemory(currentcpuinfo, currentcpuinfo->cr3_callback.callback_rsp-8, 8,  NULL, NULL);
    stack[0]=vmread(vm_guest_rip);

    vmwrite(vm_guest_rsp, currentcpuinfo->cr3_callback.callback_rsp-8);
    unmapVMmemory(stack,8);
  }

  vmwrite(vm_guest_interruptability_state, (1<<3));

  currentcpuinfo->Previous_CLI=(vmread(vm_guest_rflags) >> 9) & 1;
  vmwrite(vm_guest_rflags,vmread(vm_guest_rflags) & 0xFFFFFFFFFFFFFDFF);

  vmwrite(vm_guest_rip, currentcpuinfo->cr3_callback.callback_rip);

  currentcpuinfo->cr3_callback.called_callback=1;

  return 0;

}

int handleHLT(pcpuinfo currentcpuinfo)
{
  nosendchar[getAPICID()]=0;
  sendstringf("Handling HLT instruction\n\r");

  if (hasUnrestrictedSupport==0)
  {

    if (ISREALMODE(currentcpuinfo))
    {
      ULONG guestrflags=0;
      PRFLAGS pguestrflags=(PRFLAGS)&guestrflags;

      if (currentcpuinfo->hasIF)
      {
        vmwrite(vm_execution_controls_pin,vmread(vm_execution_controls_pin) | 1);

      }
      else
      {
        nosendchar[getAPICID()]=0;
        sendstringf("WARNING: HLT with IF=0\n\r");
      }

      guestrflags=vmread(vm_guest_rflags);
      pguestrflags->VM=0;
      pguestrflags->TF=0;
      pguestrflags->IOPL=0;
      pguestrflags->RF=0;
      pguestrflags->IF=currentcpuinfo->hasIF;

      sendstringf("settings guesteflags to %x\n\r",guestrflags);
      vmwrite(vm_guest_rflags,(ULONG)guestrflags);

    }
    else
    {
      sendstringf("HLT in protected mode\n\r");

    }
  }

  vmwrite(vm_guest_activity_state,1);

  vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));

  return 0;
}

ULONG getSegmentLimit(PGDT_ENTRY gdt, PGDT_ENTRY ldt, ULONG selector)
{

  unsigned int TI=(selector >> 2) & 1;
  unsigned int index=(selector >> 3);
  PGDT_ENTRY usedtable=TI ? ldt : gdt;
  unsigned int limit;

  if (usedtable==NULL || selector==0)
    return 0;

  limit=((QWORD)usedtable[index].Limit16_19 << 16) | usedtable[index].Limit0_15;
  if (usedtable[index].G)
    limit=(limit+1)*4096-1;

  return limit;
}

UINT64 getSegmentBaseEx(PGDT_ENTRY gdt, PGDT_ENTRY ldt, ULONG selector, int expandto80bit)
{

  unsigned int TI=(selector >> 2) & 1;
  unsigned int index=(selector >> 3);
  PGDT_ENTRY usedtable=TI ? ldt : gdt;

  if ((usedtable==NULL) || (selector==0))
    return 0;

  if (expandto80bit)
  {

    UINT64 temp;
    ULONG *upperbase=(ULONG *)&usedtable[index];
    temp=upperbase[2];
    temp=((QWORD)temp << 32) | ((QWORD)usedtable[index].Base24_31 << 24) | ((QWORD)usedtable[index].Base0_23);
    return temp;
  }
  else
  {
    return (usedtable[index].Base24_31 << 24) + usedtable[index].Base0_23;
  }
}

ULONG getSegmentBase(PGDT_ENTRY gdt, PGDT_ENTRY ldt, ULONG selector)
{
  return (ULONG)getSegmentBaseEx(gdt,ldt,selector,0);

}

void setDescriptorAccessedFlag(PGDT_ENTRY gdt, PGDT_ENTRY ldt, ULONG selector)
{

  unsigned int TI=(selector >> 2) & 1;
  unsigned int index=(selector >> 3);
  PGDT_ENTRY usedtable=TI ? ldt : gdt;

  if ((usedtable==NULL) || (selector==0))
    return;

  usedtable[index].Type=usedtable[index].Type | 1;
}

ULONG getSegmentAccessRights(PGDT_ENTRY gdt, PGDT_ENTRY ldt, ULONG selector)
{

  unsigned int TI=(selector >> 2) & 1;
  unsigned int index=(selector >> 3);
  PGDT_ENTRY usedtable=TI ? ldt : gdt;

  if ((usedtable==NULL) || (selector==0))
    return 0x10000;

  return (ULONG)((*(unsigned long long *)(&usedtable[index]) >> 40) & 0xe0ff);
}

WORD convertSegmentAccessRightsToSegmentAttrib(ULONG accessrights)
{
  Access_Rights ar;
  Segment_Attribs sa;

  ar.AccessRights=accessrights;

  if (ar.unusable)
    return 0;

  sa.Segment_type=ar.Segment_type;
  sa.S=ar.S;
  sa.DPL=ar.DPL;
  sa.P=ar.P;
  sa.AVL=ar.AVL;
  sa.L=ar.L;
  sa.D_B=ar.D_B;
  sa.G=ar.G;

  return sa.SegmentAttrib;
}

ULONG getSegmentAttrib(PGDT_ENTRY gdt, PGDT_ENTRY ldt, ULONG selector)
{
  return convertSegmentAccessRightsToSegmentAttrib(getSegmentAccessRights(gdt, ldt, selector));
}

int handleTaskswitch(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  sendstring("Handling taskswitch, can be done in 32-bit only\n\r");

  ULONG  exitqualification=vmread(vm_exit_qualification);
  ULONG  TScause=exitqualification>>30;
  UINT64 gdtbase=vmread(0x6816);
  DWORD gdtlimit=vmread(vm_guest_gdt_limit);
  ULONG  newTSSselector=exitqualification & 0xffff;
  ULONG  oldTSSselector=vmread(0x80e);

  PGDT_ENTRY gdt=NULL,ldt=NULL;

  PTSS oldTSS,newTSS;
  UINT64 oldTSSaddress;
  UINT64 newTSSaddress;

  RFLAGS guestrflags=(RFLAGS)vmread(vm_guest_rflags);

  int newsize;
  unsigned int oldTSSdescriptorEntry,newTSSdescriptorEntry;

  gdt=mapVMmemory(currentcpuinfo, gdtbase, gdtlimit, NULL, NULL);

  oldTSSdescriptorEntry=oldTSSselector >> 3;
  newTSSdescriptorEntry=newTSSselector >> 3;

  if ((gdt[newTSSdescriptorEntry].Type==0xb) && (TScause!=1))
  {
    sendstring("TARGET TSS IS STILL BUSY. Should raise GP\n\r");
    unmapVMmemory(gdt, gdtlimit);
    return 1;
  }

  if (TScause==1 || TScause==2)
    gdt[oldTSSdescriptorEntry].Type=0x9;
  else
  {
    if (gdt[oldTSSdescriptorEntry].Type != 0xb)
    {
      sendstring("The old descriptor was not set busy!!!\n\r");

      unmapVMmemory(gdt, gdtlimit);
      return 1;
    }

    gdt[oldTSSdescriptorEntry].Type=0xb;
  }

  gdt[newTSSdescriptorEntry].Type=0xb;

  newTSSaddress=(gdt[newTSSdescriptorEntry].Base24_31 << 24) + gdt[newTSSdescriptorEntry].Base0_23;
  oldTSSaddress=vmread(0x6814);

  int oldsize=vmread(vm_guest_tr_limit);
  newsize=(gdt[newTSSdescriptorEntry].Limit16_19 << 16) + gdt[newTSSdescriptorEntry].Limit0_15;

  oldTSS=mapVMmemory(currentcpuinfo, oldTSSaddress, oldsize, NULL, NULL);
  newTSS=mapVMmemory(currentcpuinfo, newTSSaddress, newsize, NULL, NULL);

  oldTSS->EAX=(ULONG)vmregisters->rax;

  oldTSS->ECX=(ULONG)vmregisters->rcx;
  oldTSS->EDX=(ULONG)vmregisters->rdx;
  oldTSS->EBX=(ULONG)vmregisters->rbx;
  oldTSS->EBP=(ULONG)vmregisters->rbp;
  oldTSS->ESI=(ULONG)vmregisters->rsi;
  oldTSS->EDI=(ULONG)vmregisters->rdi;

  oldTSS->ES=vmread(0x800);
  oldTSS->CS=vmread(0x802);
  oldTSS->SS=vmread(0x804);
  oldTSS->DS=vmread(0x806);
  oldTSS->FS=vmread(0x808);
  oldTSS->GS=vmread(0x80a);

  oldTSS->ESP=vmread(vm_guest_rsp);
  oldTSS->EIP=vmread(vm_guest_rip)+vmread(vm_exit_instructionlength);

  if ((TScause==3) && ((vmread(0x4408) >> 31)==1))
  {

    VMExit_idt_vector_information idtvectorinfo;
    idtvectorinfo.idtvector_info=vmread(0x4408);

    if (idtvectorinfo.type!=4)
      oldTSS->EIP=vmread(vm_guest_rip);
  }

  if (TScause==1)
    guestrflags.NT=0;

  oldTSS->EFLAGS=guestrflags.value;

  sendstringf("Setting newTSS state (%x:%8)\n\r", newTSS->CS, newTSS->EIP);

  if (TScause==0 || TScause==3)
    newTSS->Previous_Task_Link=oldTSSselector;

  vmregisters->rax=newTSS->EAX;
  vmregisters->rcx=newTSS->ECX;
  vmregisters->rdx=newTSS->EDX;
  vmregisters->rbx=newTSS->EBX;
  vmregisters->rbp=newTSS->EBP;
  vmregisters->rsi=newTSS->ESI;
  vmregisters->rdi=newTSS->EDI;

  vmwrite(0x800,newTSS->ES);
  vmwrite(0x802,newTSS->CS);
  vmwrite(0x804,newTSS->SS);
  vmwrite(0x806,newTSS->DS);
  vmwrite(0x808,newTSS->FS);
  vmwrite(0x80a,newTSS->GS);
  vmwrite(0x80c,newTSS->LDTss);
  vmwrite(0x80e,newTSSselector);

  ULONG ldtlimit;
  if (newTSS->LDTss)
  {
    ULONG ldtbase;

    ldtbase=(gdt[(newTSS->LDTss >> 3)].Base24_31 << 24) + gdt[(newTSS->LDTss >> 3)].Base0_23;
    ldtlimit=(gdt[(newTSS->LDTss >> 3)].Limit16_19 << 16) + gdt[(newTSS->LDTss >> 3)].Limit0_15;
    ldt=mapVMmemory(currentcpuinfo, ldtbase, ldtlimit, NULL, NULL);
  }

  vmwrite(0x4800,getSegmentLimit(gdt,ldt,newTSS->ES));
  vmwrite(0x4802,getSegmentLimit(gdt,ldt,newTSS->CS));
  vmwrite(0x4804,getSegmentLimit(gdt,ldt,newTSS->SS));
  vmwrite(0x4806,getSegmentLimit(gdt,ldt,newTSS->DS));
  vmwrite(0x4808,getSegmentLimit(gdt,ldt,newTSS->FS));
  vmwrite(0x480a,getSegmentLimit(gdt,ldt,newTSS->GS));
  vmwrite(0x480c,getSegmentLimit(gdt,ldt,newTSS->LDTss));
  vmwrite(0x480e,newsize);

  vmwrite(0x6806,getSegmentBase(gdt,ldt,newTSS->ES));
  vmwrite(vm_guest_cs_base,getSegmentBase(gdt,ldt,newTSS->CS));
  vmwrite(vm_guest_ss_base,getSegmentBase(gdt,ldt,newTSS->SS));
  vmwrite(0x680c,getSegmentBase(gdt,ldt,newTSS->DS));
  vmwrite(0x680e,getSegmentBase(gdt,ldt,newTSS->FS));
  vmwrite(0x6810,getSegmentBase(gdt,ldt,newTSS->GS));
  vmwrite(0x6812,getSegmentBase(gdt,ldt,newTSS->LDTss));
  vmwrite(0x6814,newTSSaddress);

  setDescriptorAccessedFlag(gdt,ldt,newTSS->ES);
  setDescriptorAccessedFlag(gdt,ldt,newTSS->CS);
  setDescriptorAccessedFlag(gdt,ldt,newTSS->SS);
  setDescriptorAccessedFlag(gdt,ldt,newTSS->DS);
  setDescriptorAccessedFlag(gdt,ldt,newTSS->FS);
  setDescriptorAccessedFlag(gdt,ldt,newTSS->GS);
  setDescriptorAccessedFlag(gdt,ldt,newTSS->LDTss);
  setDescriptorAccessedFlag(gdt,ldt,newTSSselector);

  vmwrite(0x4814,getSegmentAccessRights(gdt,ldt,newTSS->ES));
  vmwrite(0x4816,getSegmentAccessRights(gdt,ldt,newTSS->CS));
  vmwrite(0x4818,getSegmentAccessRights(gdt,ldt,newTSS->SS));
  vmwrite(0x481a,getSegmentAccessRights(gdt,ldt,newTSS->DS));
  vmwrite(0x481c,getSegmentAccessRights(gdt,ldt,newTSS->FS));
  vmwrite(0x481e,getSegmentAccessRights(gdt,ldt,newTSS->GS));
  vmwrite(0x4820,getSegmentAccessRights(gdt,ldt,newTSS->LDTss));
  vmwrite(0x4822,getSegmentAccessRights(gdt,ldt,newTSSselector));

  guestrflags.value=newTSS->EFLAGS;

  if (TScause==0 || TScause==3)
    guestrflags.NT=1;

  guestrflags.RF=1;
  vmwrite(vm_guest_rflags,guestrflags.value);
  vmwrite(vm_guest_rip,newTSS->EIP);
  vmwrite(vm_guest_rsp,newTSS->ESP);

  currentcpuinfo->guestCR3=newTSS->CR3;

  if ((vmread(vm_cr0_read_shadow) & 0x80000001) == 0x80000001)
    emulatePaging(currentcpuinfo);

  vmwrite(vm_cr0_read_shadow, vmread(0x6004) | 0x8);
  vmwrite(vm_guest_cr0, vmread(vm_guest_cr0) | 0x8);

  regDR7 DR7;
  DR7.DR7=vmread(vm_guest_dr7);
  DR7.L0=0;
  DR7.L1=0;
  DR7.L2=0;
  DR7.L3=0;
  DR7.LE=0;
  vmwrite(vm_guest_dr7,DR7.DR7);

  if (gdt)
    unmapVMmemory(gdt, gdtlimit);

  if (ldt)
    unmapVMmemory(ldt, ldtlimit);

  if (oldTSS)
    unmapVMmemory(oldTSS, oldsize);

  if (newTSS)
    unmapVMmemory(newTSS, newsize);

  return 0;

}

int handleIOAccess(VMRegisters *vmregisters UNUSED)
{
#if (defined SERIALPORT) && (SERIALPORT != 0)

  IOExit_Qualification iodata;
  iodata.Exit_Qualification=vmread(vm_exit_qualification);

  char dlab=fakecom1.Line_Control_Register >> 7;

  ULONG value8=vmregisters->rax & 0xff;

  if ( (iodata.isstring==0) && (iodata.hasrep==0) )
    vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));
  else
  {
    nosendchar[getAPICID()]=0;
    sendstringf("isstring or hasrep is set\n\r");
    return 1;
  }

  if (iodata.size>0)
  {
    nosendchar[getAPICID()]=0;
    sendstringf("iodata.size is bigger than 0. Not supported yet\n\r");
    return 1;
  }

  vmregisters->rax=vmregisters->rax | 0xff;
  return 0;

  switch (iodata.portnr)
  {

    case SERIALPORT:
    {

      if (iodata.direction==0)
      {

        if (dlab)
        {

          fakecom1.Devisor_Latch_Low=value8;
        }
        else
        {

          char x;
          x=inportb(SERIALPORT+5);
          while ((x & 0x20) != 0x20)
            x=inportb(SERIALPORT+5);

          outportb(SERIALPORT,value8);
        }
      }
      else
      {
        if (dlab)
        {

          vmregisters->rax=(vmregisters->rax & 0xffffffffffffff00) + fakecom1.Devisor_Latch_Low;
        }
        else
        {

          vmregisters->rax=(vmregisters->rax & 0xffffffffffffff00) + inportb(SERIALPORT);
        }
      }

      return 0;
    }

    case SERIALPORT+1:
    {

      if (iodata.direction==0)
      {
        if (dlab)
        {
          fakecom1.Devisor_Latch_High=value8;
        }
        else
        {
          fakecom1.Interrupt_Enable_Register=value8;
        }
      }
      else
      {
        if (dlab)
        {
          vmregisters->rax=(vmregisters->rax & 0xffffffffffffff00) + fakecom1.Devisor_Latch_High;
        }
        else
        {
          vmregisters->rax=(vmregisters->rax & 0xffffffffffffff00) + fakecom1.Interrupt_Enable_Register;
        }
      }
      return 0;
    }

    case SERIALPORT+2:
    {

      if (iodata.direction==0)
      {
        fakecom1.FIFO_Control_Register=value8;
      }
      else
      {
        vmregisters->rax=(vmregisters->rax & 0xffffffffffffff00) + fakecom1.Interrupt_Identification_Register;
      }

      return 0;
    }

    case SERIALPORT+3:
    {

      if (iodata.direction==0)
      {
        fakecom1.Line_Control_Register=value8;
      }
      else
      {
        vmregisters->rax=(vmregisters->rax & 0xffffffffffffff00) + fakecom1.Line_Control_Register;
      }

      return 0;
    }

    case SERIALPORT+4:
    {

      if (iodata.direction==0)
      {
        fakecom1.Modem_Control_Register=value8;
      }
      else
      {
        vmregisters->rax=(vmregisters->rax & 0xffffffffffffff00) + fakecom1.Modem_Control_Register;
      }

      return 0;
    }

    case SERIALPORT+5:
    {

      if (iodata.direction==1)
      {
        vmregisters->rax=(vmregisters->rax & 0xffffffffffffff00) + inportb(SERIALPORT+5);
      }

      return 0;
    }

    case SERIALPORT+6:
    {

      if (iodata.direction==1)
      {
        vmregisters->rax=(vmregisters->rax & 0xffffffffffffff00) + inportb(SERIALPORT+6);
      }

      return 0;

    }

    case SERIALPORT+7:
    {
      if (iodata.direction==0)
      {
        fakecom1.Scratch_Register=value8;
      }
      else
      {
        vmregisters->rax=(vmregisters->rax & 0xffffffffffffff00) + fakecom1.Scratch_Register;
      }

      return 0;
    }

    default:
    {
      if (iodata.direction==0)
      {

        outportb(iodata.portnr,value8);
        return 0;
      }

      break;

    }

  }
  sendstring("Not supported port break\n\r");
  return 0;
#else
  return 0;
#endif

}

int handleWRMSR(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  unsigned long long newvalue=((unsigned long long)vmregisters->rdx << 32)+vmregisters->rax;
  unsigned int msr=vmregisters->rcx;
  int error=0;
  int exceptionnr;

  sendstringf("emulating WRMSR(%x,%6)\n\r", msr, newvalue);

  switch (msr)
  {
    case IA32_TIME_STAMP_COUNTER:
      writeMSR(msr, newvalue);

      currentcpuinfo->lowestTSC=0;
      globalTSC=newvalue;
      currentcpuinfo->lastTSCTouch=newvalue;

      lowestTSC=0;

      break;

    case IA32_FEATURE_CONTROL_MSR:
      return raiseGeneralProtectionFault(0);
      break;

    case IA32_TSC_ADJUST:
      writeMSR(msr, newvalue);
      globalTSC=_rdtsc();
      currentcpuinfo->lasttsc=_rdtsc();
      currentcpuinfo->lastTSCTouch=globalTSC;
      currentcpuinfo->lowestTSC=0;
      lowestTSC=0;
      break;

    case 0x174:
      currentcpuinfo->sysenter_CS=newvalue;
      if (!currentcpuinfo->hidden_sysenter_modification)
      {
        currentcpuinfo->actual_sysenter_CS=newvalue;
        vmwrite(vm_guest_IA32_SYSENTER_CS,currentcpuinfo->actual_sysenter_CS);
      }
      break;

    case 0x175:
      currentcpuinfo->sysenter_ESP=newvalue;
      if (!currentcpuinfo->hidden_sysenter_modification)
      {
        currentcpuinfo->actual_sysenter_ESP=newvalue;
        vmwrite(vm_guest_IA32_SYSENTER_ESP,currentcpuinfo->actual_sysenter_ESP);
      }
      break;

    case 0x176:
      currentcpuinfo->sysenter_EIP=newvalue;
      if (!currentcpuinfo->hidden_sysenter_modification)
      {
        currentcpuinfo->actual_sysenter_EIP=newvalue;
        vmwrite(vm_guest_IA32_SYSENTER_EIP,currentcpuinfo->actual_sysenter_EIP);
      }
      break;

    case IA32_DEBUGCTL_MSR:
    {
      ultimap_handleMSRWrite(currentcpuinfo, msr, newvalue);
      break;
    }

    case IA32_DS_AREA:
    {
      ultimap_handleMSRWrite(currentcpuinfo, msr, newvalue);
      break;
    }

    case 0xc0000080:
      {

        sendstringf("EFER edit. New value=%8\n\r",newvalue);
        currentcpuinfo->efer=newvalue & 0xfffffffffffffbff;

        if (hasUnrestrictedSupport)
        {
          vmwrite(vm_guest_IA32_EFER, newvalue);
        }
        else
          writeMSR(0xc0000080,currentcpuinfo->efer | (1<<8) | (1<<10));

        if ((currentcpuinfo->efer >> 8) & 1)
        {

          sendstring("LME has been set to 1\n\r");

          if ((currentcpuinfo->guestCR0 & 0x80000001)==0x80000001)
          {

            sendstring("Paging is enabled, so setting LMS\n\r");
            vmwrite(vm_entry_controls, vmread(vm_entry_controls) | (1<<9));
            emulatePaging(currentcpuinfo);
          }
          else
          {

            sendstring("In realmode or nonpaged mode. Don\'t enable yet\n\r");
            vmwrite(vm_entry_controls, vmread(vm_entry_controls) & 0xfffffffffffffdff);
          }
        }
        else
        {

          vmwrite(vm_entry_controls, vmread(vm_entry_controls) & 0xfffffffffffffdff);
          sendstring("LME is 0\n\r");
        }

        break;
      }

    default:

      nosendchar[getAPICID()]=0;
      sendstringf("Unexpected MSR write (%x,%6)\n",msr, newvalue);

      try
      {
        writeMSR(msr, newvalue);
      }
      except
      {
        error=1;
        exceptionnr=lastexception & 0xff;
      }
      tryend

      if (error)
      {
        nosendchar[getAPICID()]=0;
        sendstringf("Exception during MSR write (interrupt %d)\n",exceptionnr);
        return raiseGeneralProtectionFault(0);
      }

      if ((currentcpuinfo->guestCR0 & 0x80000001)==0x80000001)
        emulatePaging(currentcpuinfo);

      break;

  }

  vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));
  return 0;

}

int RDMSRcounter=0;

int handleRDMSR(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{

  int error=0;
  int exceptionnr;

  sendstring("emulating RDMSR\n\r");
  RDMSRcounter++;

  unsigned long long result;
  unsigned int msr=vmregisters->rcx;

  sendstringf("msr=%x\n", msr);

  switch (msr)
  {
    case IA32_TIME_STAMP_COUNTER:
      return handle_rdtsc(currentcpuinfo, vmregisters);

	  case IA32_FEATURE_CONTROL_MSR:
	    result=readMSRSafe(IA32_FEATURE_CONTROL_MSR);
	    result=result | FEATURE_CONTROL_LOCK;

	    result=result & ~(FEATURE_CONTROL_VMXON_SMX);

	    if (emulatevmx==0)
	      result=result & ~(FEATURE_CONTROL_VMXON);
	    break;

    case 0x174:
      result=currentcpuinfo->sysenter_CS;
      break;

    case 0x175:
      result=currentcpuinfo->sysenter_ESP;
      break;

    case 0x176:
      result=currentcpuinfo->sysenter_EIP;
      break;

    case IA32_DEBUGCTL_MSR:
      result=ultimap_handleMSRRead(currentcpuinfo, msr);
      break;

    case IA32_DS_AREA:
      result=ultimap_handleMSRRead(currentcpuinfo, msr);
      break;

    case 0xc0000080:
    {

      if (hasUnrestrictedSupport)
        result=vmread(vm_guest_IA32_EFER);
      else
        result=currentcpuinfo->efer;

      if (((result >> 8)&1)==1)
      {
        if ((currentcpuinfo->guestCR0 & 0x80000001)==0x80000001)
          result=result | (1<<10);
        else
          result=result & (~(QWORD)(1<<10));
      }

      sendstringf("read efer. Returning %x\n\r",result);

      break;
    }

    case IA32_RTIT_CTL_MSR:
    {
      sendstringf("Exit for IA32_RTIT_CTL_MSR\n");
      result=readMSRSafe(IA32_RTIT_CTL_MSR);

      result=result & 0x00000000ffffffffULL;
      break;
    }

    default:
      sendstringf("MSR read event for msr that wasn\'t supposed to cause an exit (%x)!!!\n\r",msr);

      try
      {
        result=readMSR(msr);
        sendstringf("Unexpected MSR %x returned %6\n", msr, result);
      }
      except
      {
        error=1;
        exceptionnr=lastexception & 0xff;
      }
      tryend

      if (error)
      {

        sendstringf("Exception(%d) during MSR %x read.  Emulating GPF(0)", exceptionnr, msr);
        return raiseGeneralProtectionFault(0);
      }

      break;
  }

  vmregisters->rax=(ULONG)result;
  vmregisters->rdx=(ULONG)(result >> 32);

  vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));
  return 0;

}

criticalSection cpuidsourcesCS={.name="cpuidsourcesCS", .debuglevel=2};

int handleCPUID(VMRegisters *vmregisters)
{

  RFLAGS flags;
  flags.value=vmread(vm_guest_rflags);

  if (flags.TF==1)
  {
    vmwrite(vm_pending_debug_exceptions,0x4000);
  }

  _cpuid(&(vmregisters->rax),&(vmregisters->rbx),&(vmregisters->rcx),&(vmregisters->rdx));

  incrementRIP(vmread(vm_exit_instructionlength));

  getcpuinfo()->lastTSCTouch=_rdtsc();
  return 0;

}

void setRegister(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, int general_purpose_register, UINT64 value)
{
  if (!IS64BITCODE(currentcpuinfo))
    value=value & 0xffffffff;

	switch (general_purpose_register)
  {
    case 0:
      if (isAMD)
        currentcpuinfo->vmcb->RAX=value;
      else
        vmregisters->rax=value;
      break;

    case 1:
      vmregisters->rcx=value;
      break;

    case 2:
      vmregisters->rdx=value;
      break;

    case 3:
      vmregisters->rbx=value;
      break;

    case 4:
      if (isAMD)
        currentcpuinfo->vmcb->RSP=value;
      else
        vmwrite(vm_guest_rsp,value);
      break;

    case 5:
      vmregisters->rbp=value;
      break;

    case 6:
      vmregisters->rsi=value;
      break;

    case 7:
      vmregisters->rdi=value;
      break;

    case 8:
      vmregisters->r8=value;
      break;

    case 9:
      vmregisters->r9=value;
      break;

    case 10:
      vmregisters->r10=value;
      break;

    case 11:
      vmregisters->r11=value;
      break;

    case 12:
      vmregisters->r12=value;
      break;

    case 13:
      vmregisters->r13=value;
      break;

    case 14:
      vmregisters->r14=value;
      break;

    case 15:
      vmregisters->r15=value;
      break;

  }

}

UINT64 getRegister(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, int general_purpose_register)

{

	switch (general_purpose_register)
  {
  	case 0:
  	  if (isAMD)
  	    return currentcpuinfo->vmcb->RAX;
  	  else
  	    return vmregisters->rax;

    case 1:
      return vmregisters->rcx;

    case 2:
      return vmregisters->rdx;

    case 3:
			return vmregisters->rbx;

    case 4:
      if (isAMD)
        return currentcpuinfo->vmcb->RSP;
      else
        return vmread(vm_guest_rsp);

    case 5:
      return vmregisters->rbp;

    case 6:
      return vmregisters->rsi;

    case 7:
      return vmregisters->rdi;

    case 8:
      return vmregisters->r8;

    case 9:
      return vmregisters->r9;

    case 10:
      return vmregisters->r10;

    case 11:
      return vmregisters->r11;

    case 12:
      return vmregisters->r12;

    case 13:
      return vmregisters->r13;

    case 14:
      return vmregisters->r14;

    case 15:
      return vmregisters->r15;
	}

  return 0;

}

int setVM_CR0(pcpuinfo currentcpuinfo, UINT64 newcr0)
{
  QWORD cr4=vmread(vm_guest_cr4);
  UINT64 oldcr0=currentcpuinfo->guestCR0;

  if (hasUnrestrictedSupport)
  {
    sendstring("setVM_CR0 in unrestricted mode\n");
    currentcpuinfo->efer=vmread(vm_guest_IA32_EFER);
  }

  newcr0=newcr0 | 0x10;

  if ((cr4 & CR4_PCIDE) && ((newcr0 & CR0_PG)==0))
  {
    raiseGeneralProtectionFault(0);
    return 2;
  }

  if (hasCETSupport && ((cr4 & CR4_CET) && ((newcr0 & CR0_WP)==0)))
  {
    raiseGeneralProtectionFault(0);
    return 2;
  }

  currentcpuinfo->guestCR0=newcr0;

  if (hasUnrestrictedSupport==0)
  {
    vmwrite(vm_cr0_read_shadow,newcr0);

    if ((oldcr0 & 0x80000001) != (currentcpuinfo->guestCR0 & 0x80000001))
    {
      sendstring("ia32e check: protectedmode or paging bit changed\n\r");

      if  (((currentcpuinfo->guestCR0 & 0x80000001)==0x80000001)
          &&
          ((currentcpuinfo->efer >> 8) & 1))
      {

        sendstring("New state has paging and protectedmode and LME=1, switching to ia32e mode\n\r");

        vmwrite(vm_entry_controls, vmread(vm_entry_controls) | VMENTRYC_IA32E_MODE_GUEST);

      }
      else
      {
        sendstring("New state doesn't have paging and protectedmode, or LME=0, setting ia32e mode to disabled\n\r");

        vmwrite(vm_entry_controls, vmread(vm_entry_controls) & (~(VMENTRYC_IA32E_MODE_GUEST)));

        if (hasUnrestrictedSupport)
        {
          sendstring("unrestricted guest, so turning of EFER.LMA\n");
          currentcpuinfo->efer=currentcpuinfo->efer & (~(1<<10));
          vmwrite(vm_guest_IA32_EFER, currentcpuinfo->efer);

        }

      }

    }
  }

  if (hasUnrestrictedSupport)
  {
    QWORD ActualFixed0=IA32_VMX_CR0_FIXED0&0xFFFFFFFF7FFFFFFEULL;
    vmwrite(vm_guest_cr0, newcr0 | ActualFixed0);

    vpid_invalidate();
    ept_invalidate();

    if ((vmread(vm_guest_cr0) & 0x80000001)==0x80000001)
    {

      if ((vmread(vm_guest_IA32_EFER) >> 8)&1)
      {
        vmwrite(vm_entry_controls, vmread(vm_entry_controls) | VMENTRYC_IA32E_MODE_GUEST);
        vmwrite(vm_guest_IA32_EFER, vmread(vm_guest_IA32_EFER) | (1 << 10));
      }

    }

    vmwrite(vm_cr0_read_shadow,newcr0 & vmread(vm_cr0_guest_host_mask) );

    return 0;
  }

  sendstringf("Guest wants to set CR0 to %8 (from %8)\n\r",newcr0,oldcr0);

  if ((IA32_VMX_CR0_FIXED1 & newcr0) != newcr0)
  {
    sendstringf("THE GUEST OS WANTS TO SET A BIT THAT SHOULD STAY 0\n\r");
    raiseGeneralProtectionFault(0);
    return 2;
  }

  sendstringf("oldcr0=%8\n\r",oldcr0);
  sendstringf("newcr0=%8\n\r",newcr0);

  if (((newcr0 & 1)==1) && ((oldcr0 & 1)==0))
  {

    sendstring("Switching from realmode to protectedmode\n\r");

    vmwrite(vm_execution_controls_cpu, vmread(vm_execution_controls_cpu) & (~HLT_EXITING));

    sendstringf("IA32_VMX_PROCBASED_CTLS=%8\n\r",IA32_VMX_PROCBASED_CTLS);

    Access_Rights reg_tempcsaccessrights,tempaccessrights;
    UINT64 guestrflags;
    PRFLAGS pguestrflags=(PRFLAGS)&guestrflags;

    vmwrite(vm_guest_tr_access_rights,currentcpuinfo->TSaccessRights);
    vmwrite(vm_guest_tr_limit,currentcpuinfo->TSlimit);
    vmwrite(vm_guest_tr_base,currentcpuinfo->TSbase);
    vmwrite(vm_guest_tr,currentcpuinfo->TSsegment);

    reg_tempcsaccessrights.AccessRights=0;

    reg_tempcsaccessrights.Segment_type=15;
    reg_tempcsaccessrights.S=1;
    reg_tempcsaccessrights.DPL=0;
    reg_tempcsaccessrights.P=1;
    reg_tempcsaccessrights.G=0;
    reg_tempcsaccessrights.D_B=0;
    reg_tempcsaccessrights.unusable=0;
    vmwrite(vm_guest_cs_access_rights,(ULONG)reg_tempcsaccessrights.AccessRights);
    vmwrite(vm_guest_cs,vmread(vm_guest_cs) & 0xfffc);

    tempaccessrights.AccessRights=0;
    tempaccessrights.Segment_type=3;
    tempaccessrights.S=1;
    tempaccessrights.DPL=3;
    tempaccessrights.P=1;
    tempaccessrights.G=0;
    tempaccessrights.D_B=0;
    tempaccessrights.unusable=0;

    vmwrite(vm_guest_es_access_rights,(ULONG)tempaccessrights.AccessRights);
    vmwrite(vm_guest_ds_access_rights,(ULONG)tempaccessrights.AccessRights);
    vmwrite(vm_guest_fs_access_rights,(ULONG)tempaccessrights.AccessRights);
    vmwrite(vm_guest_gs_access_rights,(ULONG)tempaccessrights.AccessRights);

    tempaccessrights.DPL=vmread(vm_guest_ss) & 3;
    vmwrite(vm_guest_ss_access_rights,(ULONG)tempaccessrights.AccessRights);

    guestrflags=vmread(vm_guest_rflags);

    if ((pguestrflags->IF) || (currentcpuinfo->hasIF))
    {
      nosendchar[getAPICID()]=0;
      sendstringf("IF is not 0 when switching to protected mode\n\r");
      ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);
      while (1) outportb(0x80,0xd4);
    }

    pguestrflags->VM=0;
    pguestrflags->TF=0;
    pguestrflags->IF=currentcpuinfo->hasIF;
    pguestrflags->IOPL=0;
    vmwrite(vm_guest_rflags,(ULONG)guestrflags);

    vmwrite(vm_guest_gdtr_base, currentcpuinfo->RealMode.GDTBase);
    vmwrite(vm_guest_gdt_limit, currentcpuinfo->RealMode.GDTLimit);
    vmwrite(vm_guest_idtr_base, currentcpuinfo->RealMode.IDTBase);
    vmwrite(vm_guest_idt_limit, currentcpuinfo->RealMode.IDTLimit);

    if (newcr0 & (1<<31))
    {
      sendstringf("Emulating paging because the page bit is 1 as well\n\r");
      emulatePaging(currentcpuinfo);
      vmwrite(vm_guest_cr4,vmread(0x6006) | readMSR(0x488));
    }
    else
    {
      setupNonPagedPaging(currentcpuinfo);
      vmwrite(vm_guest_cr4,vmread(0x6006) | readMSR(0x488) | (1 << 4) | ( 1 << 5));
    }

  }
  else
  if (((oldcr0 & 1)==1) && ((newcr0 & 1)==0))
  {

    RFLAGS guestrflags=(RFLAGS)(UINT64)0;

    sendstring("Switching from protected mode to real mode.  \n\r");

    vmwrite(vm_execution_controls_cpu,vmread(vm_execution_controls_cpu) | HLT_EXITING  );

    currentcpuinfo->TSaccessRights=vmread(0x4822);
    currentcpuinfo->TSlimit=vmread(0x480e);
    currentcpuinfo->TSbase=vmread(0x6814);
    currentcpuinfo->TSsegment=vmread(0x80e);

    guestrflags=(RFLAGS)vmread(vm_guest_rflags);

#ifdef DEBUG
    if ((guestrflags.IF) || (currentcpuinfo->hasIF))
    {
      nosendchar[getAPICID()]=0;
      sendstringf("IF is not 0 when switching to protected mode\n\r");
      while (1) outportb(0x80,0xd5);
    }
#endif

    guestrflags.IOPL=3;
    guestrflags.VM=1;
    currentcpuinfo->hasIF=guestrflags.IF;
    vmwrite(vm_guest_rflags,guestrflags.value);

    currentcpuinfo->RealMode.GDTBase=vmread(vm_guest_gdtr_base);
    currentcpuinfo->RealMode.GDTLimit=vmread(vm_guest_gdt_limit);
    currentcpuinfo->RealMode.IDTBase=vmread(vm_guest_idtr_base);
    currentcpuinfo->RealMode.IDTLimit=vmread(vm_guest_idt_limit);

    vmwrite(vm_guest_cr0,(ULONG)IA32_VMX_CR0_FIXED0 |  vmread(0x6004));

    vmwrite(vm_guest_cr4,(ULONG)IA32_VMX_CR4_FIXED0 | CR4_VME | CR4_PSE | CR4_PAE | vmread(vm_cr4_read_shadow));
    setupRealModePaging(currentcpuinfo);
    return 0;

  }

  if ((newcr0 & (1<<31)) && (!(oldcr0 & (1<<31))))
  {
    sendstring("Switching from nonpaged mode to paged mode\n\r");
    if ((newcr0 & 1)==1)
    {
      sendstring("In protected mode so enable paging\n\r");

      emulatePaging(currentcpuinfo);

      vmwrite(vm_guest_cr4,(ULONG)IA32_VMX_CR4_FIXED0 | vmread(0x6006));
    }
    else
    {
      sendstring("Error we arn\'t in protected mode yet.\n\r");
    }

  }
  else
  if ((oldcr0 & (1<<31)) && (!(newcr0 & (1<<31))))
  {
    sendstring("Switching from pagedmode to nonpaged mode\n\r");
    if ((newcr0 & 1)==1)
    {
      Access_Rights reg_ssAccessRights, reg_csAccessRights;
      sendstring("In protected mode so disable paging\n\r");

      setupNonPagedPaging(currentcpuinfo);
      vmwrite(vm_guest_cr4,vmread(vm_guest_cr4) | (1 << 4) | ( 1 << 5));

      reg_ssAccessRights.AccessRights=vmread(vm_guest_ss_access_rights);

      if (reg_ssAccessRights.unusable==1)
      {
        reg_ssAccessRights.unusable=0;
        reg_ssAccessRights.Segment_type=3;
        reg_ssAccessRights.S=1;
        reg_ssAccessRights.DPL=0;
        reg_ssAccessRights.P=1;
        reg_ssAccessRights.G=1;
        reg_ssAccessRights.D_B=1;
        reg_ssAccessRights.unusable=0;
        vmwrite(vm_guest_ss,8);
        vmwrite(vm_guest_ss_base,0);
        vmwrite(vm_guest_ss_limit,0xffffffff);

        vmwrite(vm_guest_ss_access_rights,reg_ssAccessRights.AccessRights);

        reg_csAccessRights.AccessRights=vmread(vm_guest_cs_access_rights);
        reg_csAccessRights.L=0;
        vmwrite(vm_guest_cs_access_rights,reg_csAccessRights.AccessRights);
      }

    }
    else
    {
      sendstring("Error we arn\'t in protected mode yet.\n\r");
    }

  }

  newcr0=IA32_VMX_CR0_FIXED0 | newcr0 ;
  vmwrite(vm_guest_cr0,newcr0);

  sendstringf("fake cr0 has been set to %8\n\r",vmread(0x6004));
  sendstringf("real cr0 has been set to %8 (%8)\n\r",newcr0,vmread(vm_guest_cr0));

  if  ((vmread(0x6004) & 0x80000001)==0x80000001)
  {
    ULONG difference = oldcr0 ^ vmread(0x6004);
    if (
        (difference & (1<<16)) ||
        (difference & (1<<29)) ||
        (difference & (1<<30))
       )
    {
      emulatePaging(currentcpuinfo);
    }

  }

  sendstringf("CS-base=%x\n\r",vmread(vm_guest_cs_base));
  sendstringf("SS-base=%x\n\r",vmread(vm_guest_ss_base));
  sendstringf("DS-base=%x\n\r",vmread(vm_guest_ds_base));
  sendstringf("ES-base=%x\n\r",vmread(vm_guest_es_base));
  sendstringf("FS-base=%x\n\r",vmread(vm_guest_fs_base));
  sendstringf("GS-base=%x\n\r",vmread(vm_guest_gs_base));

  return 0;

}

int setVM_CR3(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, UINT64 newcr3)

{
  int shouldInvalidate=hasVPIDSupport || isAMD;
  sendstringf("setVM_CR3: Setting CR3 (%6)\n\r", newcr3);

  currentcpuinfo->lowestTSC=_rdtsc();
  currentcpuinfo->lastTSCTouch=0;

  if ((currentcpuinfo->Ultimap.Active) && (!isAMD))
    ultimap_handleCR3Change(currentcpuinfo, currentcpuinfo->guestCR3, newcr3);

  QWORD cr4=isAMD?currentcpuinfo->vmcb->CR4:vmread(vm_guest_cr4);

  sendstringf("cr4=%6\n", cr4);

  if ((cr4 & CR4_PCIDE) && (newcr3 & 0x8000000000000000ULL))
  {
    sendstringf("CR4_PCIDE is enabled and CR3 bit 63 has been set\n");
    newcr3=newcr3&0x7FFFFFFFFFFFFFFFULL;

    shouldInvalidate=0;

    sendstringf("Skipping the cache invalidating\n");
  }

  if (newcr3 & ~MAXPHYADDRMASK)
  {

    sendstringf("Tried to set %6.  (Bits violating MAXPHYADDRMASK=%6)\n", newcr3, newcr3 & ~MAXPHYADDRMASK);
    raiseGeneralProtectionFault(3);
    return 0;
  }

  if (CR3ValueLog)
  {
    csEnter(&CR3ValueLogCS);
    if ((CR3ValueLog) && (CR3ValuePos<512))
    {
      int i;
      int found=0;
      for (i=0; i<CR3ValuePos; i++)
      {
        if (CR3ValueLog[i]==newcr3)
        {
          found=1;
          break;
        }
      }
      if (found==0)
      {
        CR3ValueLog[CR3ValuePos]=newcr3;
        CR3ValuePos++;
      }
    }
    csLeave(&CR3ValueLogCS);
  }

  currentcpuinfo->guestCR3=newcr3;

  if (!IS64BITPAGING(currentcpuinfo))
    currentcpuinfo->guestCR3=currentcpuinfo->guestCR3 & 0xffffffff;

  if ((hasUnrestrictedSupport) || (isAMD))
  {
    if (isAMD)
    {
      currentcpuinfo->vmcb->CR3=newcr3;
      currentcpuinfo->vmcb->VMCB_CLEAN_BITS&=~(1 << 5);
    }
    else
      vmwrite(vm_guest_cr3,newcr3);

    if (shouldInvalidate)
    {
      if (isAMD)
      {
        currentcpuinfo->vmcb->TLB_CONTROL=1;
      }
      else
      {
        int type=3;
        INVVPIDDESCRIPTOR desc;
        desc.LinearAddress=0;
        desc.zero=0;
        desc.VPID=1;

        if (has_VPID_INVVPIDSingleContextRetainingGlobals)
          type=3;
        else
        if (has_VPID_INVVPIDSingleContext)
          type=2;
        else
          type=1;

        _invvpid(type, &desc);
      }
    }
    return 0;
  }

  if (!isAMD)
  {
    if (vmread(vm_cr0_read_shadow) & (1<<31))
    {
      if (currentcpuinfo->cr3_callback.cr3_change_callback)
        return handle_cr3_callback(currentcpuinfo,vmregisters);

      sendstringf("Paging is enabled, so emulate the pagetable update\n\r");

      emulatePaging(currentcpuinfo);
    }
    else
    {
      sendstringf("paging isn't enabled , so don't apply the update yet\n\r");
    }

    sendstringf("guestCR3=%8\n\r",currentcpuinfo->guestCR3);
    sendstringf("realguestCR3=%8\n\r",vmread(vm_guest_cr3));
  }

  return 0;
}

int setVM_CR4(pcpuinfo currentcpuinfo, UINT64 newcr4)
{

  UINT64 oldCR4=(vmread(vm_guest_cr4) & (~vmread(vm_cr4_guest_host_mask))) | (vmread(vm_cr4_read_shadow) & vmread(vm_cr4_guest_host_mask));
  UINT64 newCR4=newcr4;
  UINT64 IA32_VMX_CR4_FIXED0=readMSR(0x488);
  UINT64 IA32_VMX_CR4_FIXED1=readMSR(0x489);

  nosendchar[getAPICID()]=0;

  if (!IS64BITCODE(currentcpuinfo))
    newCR4=newCR4 & 0xffffffff;

  if ((IA32_VMX_CR4_FIXED1 & newCR4) != newCR4)
  {
    sendstringf("CR4: THE GUEST OS WANTS TO SET A BIT THAT SHOULD STAY 0\n\r");
    return 1;
  }

  if (hasCETSupport)
  {
    UINT64 CR0=vmread(vm_guest_cr0);
    if ((newCR4 & CR4_CET) && ((CR0 & CR0_WP)==0))
      raiseGeneralProtectionFault(0);

    return 2;
  }

  if (hasVPIDSupport & (((newCR4 & (CR4_PGE))) != ((oldCR4 & (CR4_PGE)))))
  {

	  INVVPIDDESCRIPTOR desc;
	  desc.LinearAddress=0;
	  desc.zero=0;
	  desc.VPID=1;
	  _invvpid(1,&desc);
  }

  if (((newCR4 & (CR4_PCIDE))) && ((oldCR4 & (CR4_PCIDE))==0))
  {

    QWORD CR3;
    QWORD EFER;
    if (hasUnrestrictedSupport)
    {
      CR3=vmread(vm_guest_cr3);
      EFER=vmread(vm_guest_IA32_EFER);
    }
    else
    {
      CR3=currentcpuinfo->guestCR3;
      EFER=currentcpuinfo->efer;
    }

    if (((EFER & (1<<10))==0) || (CR3 & 0xfff))
    {
      raiseGeneralProtectionFault(0);
      return 2;
    }
  }

  if (hasUnrestrictedSupport)
    vmwrite(vm_cr4_read_shadow,newCR4 & vmread(vm_cr4_guest_host_mask) );
  else
    vmwrite(vm_cr4_read_shadow,newCR4);

  newCR4=IA32_VMX_CR4_FIXED0 | newCR4;

  if (hasUnrestrictedSupport)
  {
    vmwrite(vm_guest_cr4, newCR4);
    return 0;
  }

  if (vmread(vm_cr0_read_shadow) & CR0_PG)
  {

    if ((oldCR4 & CR4_PAE) && ((newCR4 & CR4_PAE)==0))
    {

      sendstringf("PAE flag got changed, restart paging\n\r");
      emulatePaging(currentcpuinfo);
    }

  }
  else
  {

    sendstring("cr4 change, but paging is off");
    newCR4=newCR4 | CR4_PAE | CR4_PSE;
  }

  if ((vmread(vm_cr0_read_shadow) & 1)==0)
    newCR4=newCR4 | (1<<4) | (1<<5);

  if (ISREALMODE(currentcpuinfo))
  {
    sendstringf("Inside realmode, so set VME\n\r");
    newCR4=newCR4 | 1;
  }
  else
  {
    sendstringf("Not in realmode\n\r");
  }

  if (ISPAGING(currentcpuinfo)==0)
  {
    sendstringf("No paging yet: vmread(vm_cr0_fakeread)=%x \n", vmread(vm_cr0_read_shadow));
    newCR4=newCR4 & 0xFFCFFFFF;
  }

  sendstringf("Setting real CR4 to %x\n\r",newCR4);
  vmwrite(vm_guest_cr4,newCR4);

  if ((vmread(vm_cr0_read_shadow) & 0x80000001) == 0x80000001)
  {

    UINT64 difference=oldCR4 ^ vmread(vm_cr4_read_shadow);

    if (
        (difference & (1<<4)) ||
        (difference & (1<<5))
       )
    {
      sendstring("Paging bits changed\n\r");

      emulatePaging(currentcpuinfo);
    }

  }
  else
  {
    setupNonPagedPaging(currentcpuinfo);
  }

  return 0;

}

int handleCRaccess(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  int result;

	ULONG exit_qualification=vmread(vm_exit_qualification);
  unsigned char CR_number=exit_qualification & 0xf;
  unsigned char accesstype=(exit_qualification >> 4) & 3;

  unsigned char general_purpose_register=(exit_qualification >> 8) & 0xf;
  unsigned char LMSW_sourcedata=(exit_qualification >> 16) & 0xFFFF;

  sendstringf("Handling control register access (CR_number=%d)\n\r",CR_number);

  switch (CR_number)
  {

    case 0:
    {

      switch (accesstype)
      {

	      case 0:
        case 2:
        case 3:
        {

		      UINT64 newcr0;
          UINT64 oldcr0;
          oldcr0=currentcpuinfo->guestCR0;

          if (accesstype==2)
          {

            sendstring("CLTS\n\r");
            newcr0=(oldcr0 & 0xFFFFFFFFFFFFFFF7ULL);
            sendstringf("PUTTING THE VALUE OF %8 INTO CR0\n\r", newcr0);
          }

          else
          if (accesstype==3)
          {
            sendstringf("LMSW\n\r");

            newcr0=(oldcr0 & 0xFFFFFFFFFFFFFFF0ULL) | (LMSW_sourcedata & 0xf);

            sendstringf("PUTTING THE VALUE OF %8 INTO CR0\n\r", newcr0);
          }
          else
          {
            sendstringf("0:PUTTING THE VALUE OF REGISTER %d INTO CR0\n\r", general_purpose_register);
					  newcr0=getRegister(currentcpuinfo, vmregisters,general_purpose_register);
            if (!IS64BITCODE(currentcpuinfo))
              newcr0=newcr0 & 0xffffffff;
          }

          result=setVM_CR0(currentcpuinfo, newcr0);

          if (result==0)
            vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));

          sendstringf("new eip=%x\n\r",vmread(vm_guest_rip));
          return 0;
        }

        case 1:
        {
          sendstringf("THE OS REQUESTED CR0 INTO REGISTER %d \n\r",general_purpose_register);

					setRegister(currentcpuinfo, vmregisters,general_purpose_register,vmread(0x6004));

          vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));
          return 0;
        }

        default:
        {
          sendstring("Unknown CR0 access\n\r");
          return 1;
        }
      }

      break;

    }

    case 3:
    {

      sendstringf("Handling CR3 access\n\r");
      switch (accesstype)
      {
        case 0:
        {

          result = setVM_CR3(currentcpuinfo, vmregisters, getRegister(currentcpuinfo, vmregisters,general_purpose_register));
          if (result==0)
          {
            vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));
          }

					return 0;
        }

        case 1:
        {
          sendstringf("THE OS REQUESTED CR3 INTO REGISTER %d \n\r",general_purpose_register);
          if (hasUnrestrictedSupport)
            setRegister(currentcpuinfo, vmregisters,general_purpose_register,vmread(vm_guest_cr3));
          else
            setRegister(currentcpuinfo, vmregisters,general_purpose_register,currentcpuinfo->guestCR3);
          vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));

          return 0;
        }

        default:
        {
          sendstring("Unknown CR3 access\n\r");
          return 1;
        }

      }

      break;
    }

    case 4:
    {

      sendstringf("Handling CR4 access\n\r");
      switch (accesstype)
      {
        case 0:
        {

          UINT64 newCR4=getRegister(currentcpuinfo, vmregisters,general_purpose_register);

          sendstringf("PUTTING THE VALUE OF REGISTER %d INTO CR4 (%8)\n\r", general_purpose_register,newCR4);
          result=setVM_CR4(currentcpuinfo, newCR4);

          if (result==0)
            vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));

					return 0;
        }

        case 1:
        {
          sendstringf("THE OS REQUESTED CR4 INTO REGISTER %d \n\r",general_purpose_register);
					setRegister(currentcpuinfo, vmregisters,general_purpose_register,vmread(0x6004));
          vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));
          return 0;
        }

        default:
        {
          sendstring("Unknown CR4 access\n\r");
          return 1;
        }

      }

      break;
    }

    default:
    {
      sendstringf("CR_number=%x. Not supported!\n\r",CR_number);
      return 1;
    }

  }

  return 1;
}

int ex=0;

int isBenignInterrupt(int interrupt)
{
  switch (interrupt)
  {
    case 1 ... 7:
    case 9:
    case 16 ... 19:
      return 1;

  }

  return 0;
}

int isContributoryInterrupt(int interrupt)
{
  switch (interrupt)
  {
    case 0:
    case 10 ... 13:
      return 1;
  }

  return 0;
}

int handleRealModeInt0x15(pcpuinfo currentcpuinfo UNUSED, VMRegisters *vmregisters, int instructionsize)
{
  sendstring("Int 15h software interrupt\n\r");

  if (ARDcount==0)
    initARDcount();

  if (((WORD)(vmregisters->rax) & 0xff00)==0x8800)
  {

    sendstringf("Handling int 15h, AH=88 . instructionsize=%d\n\r", instructionsize);

    vmregisters->rax=(vmregisters->rax & 0xffffffff00000000ULL)+0xfc00;

    vmwrite(vm_guest_rip,vmread(vm_guest_rip)+instructionsize);
    vmwrite(vm_guest_rflags,vmread(vm_guest_rflags) & 0xFFFFFFFFFFFFFFFEULL);
    return 0;
  }

  if (((ULONG)(vmregisters->rax) & 0xffff)==(ULONG)0xe801)
  {
    int i;

    DWORD between1and16MB=0;
    DWORD above16MB=0;

    nosendchar[getAPICID()]=0;
    sendstringf("Handling int 15h, AH=e801. ARDcount=%d \n\r",ARDcount);

    for (i=0; i<ARDcount; i++)
    {
      sendstringf("i=%d\n",i);
      sendstringf("between1and16MB=%x\n",between1and16MB);
      sendstringf("above16MB=%x\n",above16MB);

      if (fakeARD[i].BaseAddrHigh>0)
        continue;

      if ((fakeARD[i].Type==1) && ((fakeARD[i].BaseAddrLow+fakeARD[i].LengthLow)>0x100000))
      {

        DWORD start=fakeARD[i].BaseAddrLow;
        DWORD stop=fakeARD[i].BaseAddrLow+fakeARD[i].LengthLow;

        if (start<0x100000)
          start=0x100000;

        if (start<0x1000000)
        {
          DWORD tempstop=stop;
          if (tempstop>0x1000000)
            tempstop=0x1000000;

          between1and16MB+=tempstop-start;
          start=tempstop;
        }

        if (start>=0x1000000)
          above16MB+=stop-start;

      }
    }

    sendstringf("After for loop\n");
    sendstringf("between1and16MB=%x\n",between1and16MB);
    sendstringf("above16MB=%x\n",above16MB);

    vmregisters->rax=(vmregisters->rax & 0xffffffffffff0000ULL) + (between1and16MB / 1024);
    vmregisters->rbx=(vmregisters->rbx & 0xffffffffffff0000ULL) + (above16MB / (64*1024));
    vmregisters->rcx=(vmregisters->rcx & 0xffffffffffff0000ULL) + (between1and16MB / 1024);
    vmregisters->rdx=(vmregisters->rdx & 0xffffffffffff0000ULL) + (above16MB / (64*1024));

    vmwrite(vm_guest_rip,vmread(vm_guest_rip)+instructionsize);
    vmwrite(vm_guest_rflags,vmread(vm_guest_rflags) & 0xFFFFFFFFFFFFFFFEULL);
    return 0;

  }

  if (((ULONG)vmregisters->rax & 0xffff)==(ULONG)0xe820)
  {
    int startindex=(ULONG)vmregisters->rbx;

    nosendchar[getAPICID()]=0;

    sendstringf("Handling int 15h, ax=E820 (maxindex=%d)\n\r",ARDcount-1);
    sendstringf("startindex=%d vmregisters->rcx=%d\n\r",startindex,vmregisters->rcx);

    if (((ULONG)vmregisters->rcx >= 20) && ((ULONG)vmregisters->rdx==0x534D4150) && (startindex<ARDcount))
    {

      PARD output=(PARD)(vmread(vm_guest_es_base)+(vmregisters->rdi & 0xffff));
      int totalentries=(ULONG)vmregisters->rcx/20;
      int o,i;
      vmregisters->rax=(vmregisters->rax & 0xffffffff00000000ULL) + 0x534D4150;

      sendstringf("totalentries=%d\n\r",totalentries);

      i=startindex;
      o=0;
      while ((o<totalentries) && (i<ARDcount) )
      {
        output[o]=fakeARD[i];
        if (output[o].Type==255)
          output[o].Type=2;

        o++;
        i++;
      }

      if (i>=ARDcount)
      {
        vmregisters->rbx=(vmregisters->rbx & 0xffffffff00000000ULL) + 0;
      }
      else
      {
        vmregisters->rbx=(vmregisters->rbx & 0xffffffff00000000ULL) + i;
      }

      vmregisters->rcx=(vmregisters->rcx & 0xffffffff00000000ULL) + (o*20);
      vmwrite(vm_guest_rip,vmread(vm_guest_rip)+instructionsize);
      vmwrite(vm_guest_rflags,vmread(vm_guest_rflags) & 0xFFFFFFFFFFFFFFFEULL);

      sendstringf("Handled int15h ax=e820. ECX=%8 \n\r",(ULONG)vmregisters->rcx);
      return 0;
    }
    else
    {

      sendstringf("Returning error\n\r");
      vmwrite(vm_guest_rip,vmread(vm_guest_rip)+instructionsize);
      vmwrite(vm_guest_rflags,vmread(vm_guest_rflags) | 1);
      return 0;
    }

  }

  if (((ULONG)vmregisters->rax & 0xffff)==(ULONG)0xe881)
  {
    nosendchar[getAPICID()]=0;
    sendstring("int 0x15:ax=0xe881 is being used\n");
  }

  return 1;
}

int handleInterruptRealMode(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{

  VMExit_idt_vector_information idtvectorinfo;

  idtvectorinfo.idtvector_info=vmread(vm_idtvector_information);

  if (idtvectorinfo.valid)
  {

    DWORD issoftware;

    sendstringf("currentcpuinfo=%6\n\r", (UINT64)currentcpuinfo);
    sendstringf("currentcpuinfo->RealMode.IDTBase=%6\n\r", (UINT64)currentcpuinfo->RealMode.IDTBase);

    if (idtvectorinfo.type==4)
    {
      sendstringf("idtvectorinfo.type==4\n\r");
      issoftware=vmread(vm_exit_instructionlength);
      if (issoftware!=2)
      {
        unsigned char firstbyte=0;

        ReadVMMemory(currentcpuinfo,vmread(vm_guest_cs_base)+vmread(vm_guest_rip),&firstbyte,1);
        if (firstbyte==0xcd)
        {
          sendstring("BOCHS BUG. Instruction is CD xx, so size IS 2\n");
          issoftware=2;
        }

      }

    }
    else
      issoftware=0;

    if ((idtvectorinfo.interruptvector==0x15) && issoftware )
    {
      int r=handleRealModeInt0x15(currentcpuinfo, vmregisters, issoftware);

      if (r==0)
        return r;
    }

    vmwrite(vm_guest_rip, vmread(vm_guest_rip)+issoftware);

    return emulateRMinterrupt(currentcpuinfo, vmregisters, idtvectorinfo.interruptvector);
  }
  else
  {

    emulateRealMode(currentcpuinfo, vmregisters);

    return 0;
  }
}

int handleInterruptProtectedMode(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{

  VMExit_interruption_information intinfo;
  VMExit_idt_vector_information idtvectorinfo;

  int doublefault=0;
  int isFault=1;

  intinfo.interruption_information=vmread(vm_exit_interruptioninfo);

  idtvectorinfo.idtvector_info=vmread(vm_idtvector_information);

  sendstring("protected mode interrupt handling\n\r");

  if (intinfo.interruptvector==1)
  {

    regDR7 dr7;
    dr7.DR7=vmread(vm_guest_dr7);

    regDR6 dr6;
    int orig=nosendchar[getAPICID()];

    isFault=0;

    nosendchar[getAPICID()]=0;
    sendstring("Interrupt 1:\n");

    dr6.DR6=getDR6();

    regDR6 dr6_exit_qualification;
    dr6_exit_qualification.DR6=vmread(vm_exit_qualification);

    dr6.DR6&= ~(0xf);

    dr6.DR6 |= dr6_exit_qualification.DR6 & 0x600f;
    dr6.RTM=~dr6_exit_qualification.RTM;

    setDR6(dr6.DR6);

    if (currentcpuinfo->Ultimap.Active)
      ultimap_handleDB(currentcpuinfo);
    else
      vmwrite(vm_guest_IA32_DEBUGCTL, vmread(vm_guest_IA32_DEBUGCTL) & ~1);

    dr7.GD=0;
    vmwrite(vm_guest_dr7,dr7.DR7);

    nosendchar[getAPICID()]=orig;

    if (int1redirection_idtbypass==0)
    {

      sendstring("Normal\n\r");
      intinfo.interruptvector=int1redirection;
      currentcpuinfo->int1happened=(int1redirection!=1);
    }
    else
    {
      int r;

      nosendchar[getAPICID()]=1;
      r=emulateExceptionInterrupt(currentcpuinfo, vmregisters,
          int1redirection_idtbypass_cs, int1redirection_idtbypass_rip,
          intinfo.haserrorcode, vmread(vm_exit_interruptionerror), isFault);

      nosendchar[getAPICID()]=orig;

      if (r==0)
        return 0;

    }
  }
  else
  if (intinfo.interruptvector == 3)
  {

      nosendchar[getAPICID()]=0;
      sendstring("Int3 bp\n");

      sendvmstate(currentcpuinfo, vmregisters);

      isFault=0;
      if (int3redirection_idtbypass == 0)
      {

        sendstring("Normal\n\r");
        intinfo.interruptvector=int3redirection;
        currentcpuinfo->int3happened=(int3redirection!=3);
      }
      else
      {
        nosendchar[getAPICID()]=0;
        sendstring("int 3\n");

        vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));

        int r=emulateExceptionInterrupt(currentcpuinfo, vmregisters,
            int3redirection_idtbypass_cs, int3redirection_idtbypass_rip,
            intinfo.haserrorcode, vmread(vm_exit_interruptionerror), 0);

        if (r==0)
          return 0;
      }
  }
  else
  if (intinfo.interruptvector == 14)
  {

      if ((currentcpuinfo->IgnorePageFaults.Active) && (vmread(vm_exit_interruptionerror) <=0xf ) )
      {
        currentcpuinfo->IgnorePageFaults.LastIgnoredPageFault=vmread(vm_exit_qualification);
        vmwrite(vm_guest_rip, vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));
        return 0;
      }

      setCR2(vmread(vm_exit_qualification));

      if (int14redirection_idtbypass == 0)
      {

        sendstring("Normal\n\r");
        intinfo.interruptvector=int14redirection;
        currentcpuinfo->int14happened=(int14redirection!=14);
      }
      else
      {
        int r;

        if (intinfo.haserrorcode==0)
        {
          nosendchar[getAPICID()]=0;
          sendstring("int 14 without errorcode\n");
        }

        if (idtvectorinfo.valid)
        {
          nosendchar[getAPICID()]=0;
          sendstring("int 14 from an IDT\n");
        }

        if (idtvectorinfo.type!=0)
        {
          nosendchar[getAPICID()]=0;
          sendstringf("int 14 type is %d instead of 3\n", idtvectorinfo.type);
        }

        sendstring("Interrupt 14:");

        r=1;
        if (intinfo.haserrorcode)
        {
          int errorcode=vmread(vm_exit_interruptionerror);
          if ((errorcode & 0x15)==0x15)
          {

            nosendchar[getAPICID()]=0;

            sendstringf("Errorcode=%x\n", vmread(vm_exit_interruptionerror));
            sendstringf("CR2=%x\n", vmread(vm_exit_qualification));

            r=emulateExceptionInterrupt(currentcpuinfo, vmregisters,
                int14redirection_idtbypass_cs, int14redirection_idtbypass_rip,
                intinfo.haserrorcode, errorcode, 1);
          }

        }

        if (r==0)
        {
          sendstring("r==0, returning\n");
          return 0;
        }

        intinfo.interruptvector=int14redirection;
        currentcpuinfo->int14happened=(int14redirection!=14);
      }
   }

  sendstringf("idtvectorinfo.valid=%d\n\r",idtvectorinfo.valid);
  sendstringf("idtvectorinfo.type=%d\n\r",idtvectorinfo.type);
  sendstringf("idtvectorinfo.interruptvector=%d\n\r",idtvectorinfo.interruptvector);

  sendstringf("intinfo.valid=%d\n\r",intinfo.valid);
  sendstringf("intinfo.type=%d\n\r",intinfo.type);
  sendstringf("intinfo.interruptvector=%d\n\r",intinfo.interruptvector);

  if (idtvectorinfo.valid)
  {
    nosendchar[getAPICID()]=0;
    sendstring("idtvectorinfo is VALID\n");
    sendstringf("idtvectorinfo.type=%d\n",idtvectorinfo.type);

    if (idtvectorinfo.type==3)
    {
      sendstring("idtvectorinfo.type==3\n");
      if (idtvectorinfo.interruptvector==8)
      {
        nosendchar[getAPICID()]=0;
        sendstring("TRIPPLEFAULT TRIPPLEFAULT!!! OMGWTF?\n");
        sendvmstate(currentcpuinfo, vmregisters);
        displayPreviousStates();
        ShowCurrentInstructions(currentcpuinfo);

        while (1)
        {
          outportb(0x80,0xd6);
          ddDrawRectangle(0,DDVerticalResolution-100,100,100,_rdtsc() & 0xffffff);
        }

      }

      doublefault=1;

      if (isBenignInterrupt(idtvectorinfo.interruptvector))
      {
        sendstring("idtvector is benign\n");
        doublefault=0;
      }
      else
      if (isBenignInterrupt(intinfo.interruptvector))
      {
        sendstring("intvector is benign");
        doublefault=0;
      }

      if (intinfo.interruptvector==14)
      {
        sendstring("intvector is 14");
        if (isContributoryInterrupt(idtvectorinfo.interruptvector))
        {
          sendstring("idtvector is contributory\n");
          doublefault=0;
        }
      }

      if (doublefault)
      {

        doublefault=0;

        sendstring("Likely a doublefault\n");

        if ((isContributoryInterrupt(idtvectorinfo.interruptvector)) &&
            (isContributoryInterrupt(intinfo.interruptvector)))
        {

          sendstring("BOTH are contributory\n");
          doublefault=1;
        }

        if (idtvectorinfo.interruptvector==14)
        {

          sendstring("idtvector=14\n");

          if (isContributoryInterrupt(intinfo.interruptvector))
          {
            sendstring("is contributory\n");
            doublefault=1;
          }

          if (intinfo.interruptvector==14)
          {
            sendstring("intvector=14\n");
            doublefault=1;
          }

        }

      }
    }
    else
    {

    }

  }

  VMEntry_interruption_information newintinfo;
  newintinfo.interruption_information=0;

  if (doublefault)
  {

    nosendchar[getAPICID()]=0;

    newintinfo.interruptvector=8;
    newintinfo.type=3;
    newintinfo.haserrorcode=1;
    newintinfo.valid=1;
    vmwrite(vm_entry_exceptionerrorcode, 0);

    sendstring("DOUBLEFAULT RAISED\n\r");
  }
  else
  {

    sendstring("Passing original interrupt to guest\n");
    newintinfo.interruptvector=intinfo.interruptvector;
    newintinfo.type=intinfo.type;
    newintinfo.haserrorcode=intinfo.haserrorcode;
    newintinfo.valid=intinfo.valid;
    vmwrite(vm_entry_exceptionerrorcode, vmread(vm_exit_interruptionerror));

    if (newintinfo.type==0)
      return 0;
  }

  sendstringf("CS:EIP=0x%x:0x%x",vmread(vm_guest_cs),vmread(vm_guest_rip));

  sendstringf("newintinfo.interruptvector=%d\n\r",newintinfo.interruptvector);
  sendstringf("newintinfo.type=%d\n\r",newintinfo.type);
  sendstringf("newintinfo.haserrorcode=%d\n\r",newintinfo.haserrorcode);
  if (newintinfo.haserrorcode)
  {
    sendstringf("newintinfo.errorcode=%x\n\r",vmread(0x4018));
  }

  sendstringf("newintinfo.valid=%d\n\r",newintinfo.valid);

  if (newintinfo.type!=5)
  {
    vmwrite(vm_entry_interruptioninfo, newintinfo.interruption_information);
    vmwrite(0x401a, vmread(vm_exit_instructionlength));
  }
  else
  {

    vmwrite(vm_pending_debug_exceptions, vmread(vm_pending_debug_exceptions) | (1<<14) );
    vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));
  }

  if (isFault)
  {

    UINT64 rflags=vmread(vm_guest_rflags);
    PRFLAGS prflags=(PRFLAGS)&rflags;
    prflags->RF=1;
    vmwrite(vm_guest_rflags,rflags);
  }

  sendstringf("Protected mode interrupt handled\n\r");
  return 0;
}

BOOL handleHardwareBreakpoint(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, FXSAVE64 *fxsave)
{

  sendstringf("Hardware breakpoint\n");
  if (hasEPTsupport || hasNPsupport)
  {
    if (ept_handleHardwareBreakpoint(currentcpuinfo, vmregisters, fxsave))
      return TRUE;
  }

  return FALSE;
}

BOOL handleSoftwareBreakpoint(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, FXSAVE64 *fxsave)
{

  nosendchar[getAPICID()]=0;

  if (hasEPTsupport || hasNPsupport)
  {
    if (ept_handleSoftwareBreakpoint(currentcpuinfo, vmregisters, fxsave))
    {

      return TRUE;
    }
  }

  nosendchar[getAPICID()]=0;
  sendstringf("Unhandled Software breakpoint\n");
  return FALSE;
}

VMSTATUS handleInterrupt(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, FXSAVE64 *fxsave)
{

  UINT64 fakeCR0=(vmread(vm_guest_cr0) & (~vmread(vm_cr0_guest_host_mask))) | (vmread(vm_cr0_read_shadow) & vmread(vm_cr0_guest_host_mask));

  VMExit_interruption_information intinfo;

  intinfo.interruption_information=vmread(vm_exit_interruptioninfo);

  if ((intinfo.interruptvector==1) && (intinfo.type==itHardwareException))
  {
    if (handleHardwareBreakpoint(currentcpuinfo, vmregisters, fxsave))
      return VM_OK;
  }

  if ((intinfo.interruptvector==3) && (intinfo.type==itSoftwareException))
  {
    if (handleSoftwareBreakpoint(currentcpuinfo, vmregisters, fxsave))
      return VM_OK;
  }

  if ((fakeCR0 & 1)==0)
    return handleInterruptRealMode(currentcpuinfo, vmregisters);
  else
    return handleInterruptProtectedMode(currentcpuinfo, vmregisters);
}

#pragma GCC push_options
#pragma GCC optimize ("O0")
int handleXSETBV(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  unsigned long long value=((unsigned long long)vmregisters->rdx << 32)+vmregisters->rax;
  int success=0;

  sendstring("handleXSETBV\n\r");

  currentcpuinfo->LastInterrupt=0;
  currentcpuinfo->OnInterrupt.RIP=(QWORD)((volatile void *)(&&InterruptFired));
  currentcpuinfo->OnInterrupt.RSP=getRSP();

  if (vmread(vm_guest_cr4) & CR4_OSXSAVE)
  {
    sendstring("Guest has OSXSAVE enabled\n\r");
    setCR4(getCR4() | CR4_OSXSAVE);
  }
  else
  {
    sendstring("Guest doesn't have OSXSAVE enabled\n\r");
    setCR4(getCR4() & (~CR4_OSXSAVE));
  }

  sendstring("Calling _xsetbv\n");

  _xsetbv(vmregisters->rcx, value);

  sendstring("Returned without exception\n");
  success=1;

InterruptFired:
  currentcpuinfo->OnInterrupt.RIP=0;

  if (!success)
  {
    sendstringf("Exception happened. Interrupt=%d\n\r", currentcpuinfo->LastInterrupt);
    if (currentcpuinfo->LastInterrupt==13)
      raiseGeneralProtectionFault(0);

    if (currentcpuinfo->LastInterrupt==6)
      raiseInvalidOpcodeException(currentcpuinfo);

  }
  else
  {
    vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));
  }
  return 0;
}

int handleSingleStep(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, FXSAVE64 *fxsave)
{

  sendstringf("%d: handleSingleStep.  currentcpuinfo->singleStepping.ReasonsPos=%d\n", currentcpuinfo->cpunr, currentcpuinfo->singleStepping.ReasonsPos);

  while (currentcpuinfo->singleStepping.ReasonsPos)
  {
    int i=currentcpuinfo->singleStepping.ReasonsPos-1;
    int r=0;
    sendstringf("%d:  ID %d Reason %d\n", currentcpuinfo->cpunr, i, currentcpuinfo->singleStepping.Reasons[i].Reason);

    switch (currentcpuinfo->singleStepping.Reasons[i].Reason)
    {
      case SSR_HANDLEWATCH: r=ept_handleWatchEventAfterStep(currentcpuinfo, currentcpuinfo->singleStepping.Reasons[i].ID); break;
      case SSR_HANDLECLOAK: r=ept_handleCloakEventAfterStep(currentcpuinfo, (PCloakedPageData)currentcpuinfo->singleStepping.Reasons[i].Data); break;
      case SSR_HANDLESOFTWAREBREAKPOINT: r=ept_handleSoftwareBreakpointAfterStep(currentcpuinfo, currentcpuinfo->singleStepping.Reasons[i].ID); break;

      case SSR_STEPANDBREAK: r=ept_handleStepAndBreak(currentcpuinfo, vmregisters, fxsave, currentcpuinfo->singleStepping.Reasons[i].ID); break;
      default:
      {
        nosendchar[getAPICID()]=0;

        sendstringf("singleStepping memory corruption\n");
        r=1;
      }

    }

    if (r)
    {
      nosendchar[getAPICID()]=0;
      sendstringf("handleSingleStep: r=%d\n",r);
      ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);
      while (1) outportb(0x80,0xd7);
    }
    currentcpuinfo->singleStepping.ReasonsPos--;
  }

  sendstring("vmx_disableSingleStepMode\n");
  vmx_disableSingleStepMode();

  sendstringf("return from handleSingleStep.  currentcpuinfo->singleStepping.ReasonsPos=%d\n", currentcpuinfo->singleStepping.ReasonsPos);

  return 0;
}

void speedhack_setspeed(double speed)
{
  if (TSCHooked)
  {
    QWORD currentTime=_rdtsc();

    QWORD initialoffset=(currentTime-speedhackInitialTime)*speedhackSpeed+speedhackInitialOffset;
    speedhackInitialTime=currentTime;

    if (initialoffset<lowestTSC)
      initialoffset=lowestTSC+1000;

    lowestTSC=initialoffset;
    speedhackInitialOffset=initialoffset;
    speedhackSpeed=speed;

    useSpeedhack=1;
  }
}

int handle_rdtsc(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  QWORD t;
  QWORD lTSC=lowestTSC;
  QWORD realtime;

  if (lTSC<currentcpuinfo->lowestTSC)
    lTSC=currentcpuinfo->lowestTSC;

  realtime=_rdtsc();

  if (currentcpuinfo->lowestTSC==0)
    currentcpuinfo->lowestTSC=realtime;

  if (useSpeedhack)
  {
    t=(realtime-speedhackInitialTime)*speedhackSpeed+speedhackInitialOffset;

  }
  else
    t=realtime;

  if (lTSC==0)
    lTSC=t;

  if (t<lTSC)
  {
    /* HETEROGENEOUS P/E-CORE FIX:
     * When threads migrate between P-cores and E-cores, or if core clock skews exist,
     * time must never travel backward. Clamping forward guarantees strict monotonicity.
     */
    t=lTSC+1;
  }
  else
  {
    lTSC=t;
  }

  if (adjustTimestampCounters)
  {
    if ((realtime-currentcpuinfo->lastTSCTouch)<(QWORD)adjustTimestampCounterTimeout)
    {

      int off=20+(realtime & 0xf);

      t=currentcpuinfo->lowestTSC+off;

      currentcpuinfo->lowestTSC=t;

    }
    else
    {
      if (lowestTSC<t)
        lowestTSC=t;
      currentcpuinfo->lowestTSC=t;
    }
  }

  if (isAMD)
    currentcpuinfo->vmcb->RAX = t & 0xffffffff;
  else
    vmregisters->rax=t & 0xffffffff;

  vmregisters->rdx=t >> 32;

  if (lowestTSC<t)
  {
    QWORD curLowest = lowestTSC;
    while (t > curLowest)
    {
      if (__sync_bool_compare_and_swap(&lowestTSC, curLowest, t))
        break;
      curLowest = lowestTSC;
    }
  }

  if (isAMD)
  {
    if (AMD_hasNRIPS)
    {
      currentcpuinfo->vmcb->RIP=currentcpuinfo->vmcb->nRIP;
    }
    else
    {
      int i,error;
      UINT64 pagefaultaddress;

      unsigned char *bytes=(unsigned char *)mapVMmemory(currentcpuinfo, currentcpuinfo->vmcb->cs_base+currentcpuinfo->vmcb->RIP, 15, &error, &pagefaultaddress);
      if (!bytes)
          bytes=mapVMmemory(currentcpuinfo, currentcpuinfo->vmcb->cs_base+currentcpuinfo->vmcb->RIP, pagefaultaddress-currentcpuinfo->vmcb->cs_base+currentcpuinfo->vmcb->RIP, &error, &pagefaultaddress);

      for (i=0; i<15; i++)
      {
        sendstringf("%x ", bytes[i]);
        if (bytes[i]==0x0f)
        {
          sendstringf("%x ", bytes[i+1]);
          sendstringf("%x ", bytes[i+2]);
          sendstringf("%x ", bytes[i+3]);
          currentcpuinfo->vmcb->RIP+=i+2;
          break;
        }
      }

      unmapVMmemory(bytes,15);
    }

  }
  else
  {
    vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));

    RFLAGS flags;
    flags.value=vmread(vm_guest_rflags);

    if (flags.TF==1)
      vmwrite(vm_pending_debug_exceptions,0x4000);
  }

  return 0;
}

#pragma GCC pop_options

int handleVMEvent_internal(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, FXSAVE64 *fxsave)
{
  int result;
  int exit_reason=currentcpuinfo->guest_error?currentcpuinfo->guest_error:vmread(vm_exit_reason) & 0x7fffffff;

#ifdef STATISTICS
  if (exit_reason<=55)
    currentcpuinfo->eventcounter[exit_reason]++;
#endif

  if (currentcpuinfo->eptUpdated==1)
  {
    currentcpuinfo->eptUpdated=0;
    ept_invalidate();
  }

  if (hasUnrestrictedSupport && canToggleCR3Exit)
    currentcpuinfo->guestCR3=vmread(vm_guest_cr3);

  switch (exit_reason)
  {
    case 0:
    {
      int result;

      result=handleInterrupt(currentcpuinfo, vmregisters, fxsave);

      return result;
    }

    case 1:
    {
      sendstring("received external interrupt\n\r");
      if (vmread(vm_guest_activity_state)==1)
      {
        sendstring("In HLT mode so become active and disable external event watching\n\r");
        vmwrite(vm_execution_controls_pin,vmread(0x4000) & 0xFFFFFFFE);

        vmwrite(vm_guest_activity_state,(ULONG)0);
        while (1) outportb(0x80,0xd8);

        if (ISREALMODE(currentcpuinfo))
        {
          sendstring("Guest is in realmode so go back to realmode\n\r");
          returnToRealmode(currentcpuinfo);
        }

        return 0;
      }
      else
      {
        sendstringf("External event received but not in HLT state\n\r");
        result=handleInterrupt(currentcpuinfo, vmregisters, fxsave);
        return result;

      }

    }

    case 2:
    {

      nosendchar[getAPICID()]=0;
      sendstring("A TRIPPLE FAULT HAPPENED. NORMALLY THE SYSTEM WOULD REBOOT NOW\n\r");

      while (1) outportb(0x80,0xd7);

      return 1;
    }

    case 3:
    {

      sendstring("Received an INIT signal\n\r");
      handleINIT(currentcpuinfo, vmregisters);
      return VM_OK;
    }

    case vm_exit_sipi:
    {
      if (currentcpuinfo->vmxdata.insideVMXRootMode==1)
        return 0;
      else
        return handleSIPI();
    }

    case 5:
    {
      sendstring("I/O system-management interrupt (SMI)\n\r");
      return 1;
    }

    case 6:
    {
      sendstring("An SMI arrived and caused an SMM VM exit (see Section 24.16.2) but not immediately after retirement of an I/O instruction.\n\r");
      return 1;
    }

    case 7:
    {
      if ((currentcpuinfo->singleStepping.ReasonsPos) && (currentcpuinfo->singleStepping.Method==2))
      {
        sendstring("Interrupt window event... And I am in single stepping mode\n");

        return handleSingleStep(currentcpuinfo, vmregisters, fxsave);
      }
      else
      {
        nosendchar[getAPICID()]=0;
        sendstring("Interrupt window event... I did NOT ask for this\n\r");
        sendstringf("vm_execution_controls_cpu=%6\n", vmread(vm_execution_controls_cpu));

#ifndef DEBUG
        ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);
        while (1) outportb(0x80,0xd8);
#endif
      }
      return 0;
    }

    case 8:
    {
      sendstring("NMI Window");
      if (currentcpuinfo->NMIOccured)
        raiseNMI();

      vmx_disableNMIWindowExiting();

      return 0;
    }

    case 9:
    {
      ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);
      while (1) outportb(0x80,0xd9);
      return handleTaskswitch(currentcpuinfo, vmregisters);
    }

    case 10:
    {
      result=handleCPUID(vmregisters);

      return result;
    }

    case 11:
    {

      ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);

      sendstring("GETSEC\n\r");
      raiseInvalidOpcodeException(currentcpuinfo);
      return 0;
    }

    case 12:
    {
      result=handleHLT(currentcpuinfo);

      return result;
    }

    case 13:
    {
      nosendchar[getAPICID()]=0;
      sendstring("INVD called\n\r");

      vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));
      _wbinvd();

      return 0;
    }

    case 14:
    {

      sendstring("Calling handleINVLPG(currentcpuinfo)\n\r");
      result = handleINVLPG(currentcpuinfo);

      sendstringf("Returned from handleINVLPG : %d\n\r",result);
      return result;

    }

    case 15:
    {
      sendstring("RDPMC called\n\r");
      return 1;
    }

    case 16:
    {

      int r;

      r=handle_rdtsc(currentcpuinfo, vmregisters);
      currentcpuinfo->lastTSCTouch=_rdtsc();
      return r;
    }

    case 17:
    {
      sendstring("RSM called\n\r");
      return 1;
    }

    case 18:
    {

      nosendchar[getAPICID()]=0;

      result = handleVMCall(currentcpuinfo, vmregisters);

      return result;
    }

    case 19 ... 27 :
    case 0xce00:
    case 0xce01:
    {
      ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);

      sendstring("VMX instruction called...\n\r");
      return handleIntelVMXInstruction(currentcpuinfo, vmregisters);

    }

    case 28:
    {
      int result;

      result=handleCRaccess(currentcpuinfo, vmregisters);

      return result;
    }

    case 29:
    {
      sendstring("The debug registers got accesses\n\r");

      return 1;
    }

    case 30:
    {

      result=handleIOAccess(vmregisters);

      return result;
    }

    case 31:
    {
      result=handleRDMSR(currentcpuinfo, vmregisters);

      return result;
    }

  case 32:
    {
      result=handleWRMSR(currentcpuinfo, vmregisters);
      return result;
    }

  case 33:
    {
      ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);
      sendstringf("VM-Entry failure due to invalid guest\n\r");
      result=handleInvalidEntryState(currentcpuinfo, vmregisters);

      if (result)
      {
        nosendchar[getAPICID()]=0;
        sendstringf("Unhandled invalid state\n");
        sendvmstate(currentcpuinfo, vmregisters);
      }

      return result;

    }

    case 34:
    {
      sendstringf("VM-Entry failure due to MSR loading\n\r");
      return 1;
    }

    case 36:
    {
      sendstringf("MWAIT occured and mwait exiting=1\n\r");
      return 1;
    }

    case vm_exit_monitor_trap_flag:
    {
      if ((currentcpuinfo->singleStepping.ReasonsPos) && (currentcpuinfo->singleStepping.Method==1))
        return handleSingleStep(currentcpuinfo, vmregisters, fxsave);

      nosendchar[getAPICID()]=0;
      sendstring("(Un)expected monitor trap flag\n\r");
#ifndef DEBUG
      ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);
      while (1) outportb(0x80,0xda);
#else
      return handleSingleStep(currentcpuinfo, vmregisters, fxsave);

#endif

    }

    case 39:
    {
      sendstringf("MONITOR occured and MONITOR Exiting=1\n\r");
      return 1;
    }

    case 40:
    {
      sendstringf("PAUSE occured and PAUSE Exiting=1\n\r");
      return 1;
    }

    case 41:
    {
      sendstring("MACHINE CHECK ERROR!!!!!!!!!!!!!!!!!!!!!!!!1\n\r");
      return 1;
    }

    case 43:
    {
      sendstring("TPR below threshold and TPR threshold set\n\r");
      return 1;
    }

    case 44:
    {
      sendstring("APIC access\n\r");
      return 1;
    }

    case 45:
    {
      sendstring("Virtualized EOI\n\r");
      return 1;
    }

    case 46:
    {
      sendstring("GDT/IDT access\n\r");
      return 1;
    }

    case 47:
    {
      sendstring("LDTR/TR access\n\r");
      return 1;
    }

    case 48:
    {

      int r;

      sendstring("EPT violation\n\r");
      r=handleEPTViolation(currentcpuinfo, vmregisters, (PFXSAVE64)fxsave);

      ept_invalidate();

      return r;
    }

    case 49:
    {
      sendstring("EPT misconfig\n\r");
      return handleEPTMisconfig(currentcpuinfo, vmregisters);
    }

    case 50:
    {
      sendstring("INVEPT\n\r");
      return handleIntelVMXInstruction(currentcpuinfo, vmregisters);

    }

    case 51:
    {
      QWORD t;

      int r=handle_rdtsc(currentcpuinfo, vmregisters);
      currentcpuinfo->lastTSCTouch=_rdtsc();

      vmregisters->rcx=readMSR(IA32_TSC_AUX_MSR);
      return r;
    }

    case vm_exit_vmx_preemptiontimer_reachedzero:
    {
      nosendchar[getAPICID()]=0;

      /* Provide stable VMM preemption quantum across heterogeneous P/E-cores */
      QWORD quantum = 25000ULL;
      vmwrite(vm_preemption_timer_value, quantum);

#if DISPLAYDEBUG==1
      ddDrawRectangle(0,0,100,100,_rdtsc());
#endif
      return 0;
    }

    case vm_exit_invvpid:
    {
      sendstring("INVVPID\n\r");
      return handleIntelVMXInstruction(currentcpuinfo, vmregisters);

#ifdef DEBUG
      ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);
      while (1) outportb(0x80,0xdb);
#endif

    }

    case vm_exit_invpcid:
    {
      ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);
      while(1);
      return 1;
    }

    case 54:
    {
      sendstring("WBINVD\n\r");
      return 1;
    }

    case 55:
    {
      sendstring("XSETBV\n\r");
      return handleXSETBV(currentcpuinfo, vmregisters);
    }

    default:
    {
      sendstring("The OMGWTF event happened. Please bury your head in the sand to avoid the nuclear blast\n\r");
      return 1;
    }

  }

  return 1;
}

int reached7c00=0;
int counter;

criticalSection bla;

int handleVMEvent(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, FXSAVE64 *fxsave)
{

  int result;
  VMExit_idt_vector_information idtvectorinfo;

  currentcpuinfo->lastExitReason=vmread(vm_exit_reason);
  if (currentcpuinfo->vmxdata.runningvmx)
  {
    int show=1;
    int r;
    int er=vmread(vm_exit_reason) & 0xff;
    currentcpuinfo->lastExitWasWithRunningVMX=1;

    nosendchar[getAPICID()]=0;

    switch (er)
    {
      case vm_exit_cpuid:
      case vm_exit_io_access:
      case vm_exit_externalinterupt:
      case vm_exit_interrupt_window:
      case vm_exit_apic_access:
      case vm_exit_mwait:
      case vm_exit_monitor:
      case vm_exit_ept_violation:
      case vm_exit_ept_misconfiguration:
      case vm_exit_vmx_preemptiontimer_reachedzero:
        show=0;
        break;
    }

    counter++;
    if (counter % 8192==0)
      show=1;

    if (show)
      sendstringf("%d:%x:%6: event=%d (%s)  esi=%6 edi=%6 ecx=%6\n", currentcpuinfo->cpunr, vmread(vm_guest_cs), vmread(vm_guest_rip),  vmread(vm_exit_reason), getVMExitReassonString(), vmregisters->rsi, vmregisters->rdi, vmregisters->rcx);

    r=emulateVMExit(currentcpuinfo, vmregisters);

    if (currentcpuinfo->vmxdata.runningvmx)
    {
      sendstringf("handleByGuest did not handle it...\n");
      while(1);
    }

    return r;
  }

  currentcpuinfo->lastExitWasWithRunningVMX=0;

  idtvectorinfo.idtvector_info=vmread(vm_idtvector_information);

  result=handleVMEvent_internal(currentcpuinfo, vmregisters, fxsave);

  if (idtvectorinfo.valid)
  {
    VMExit_interruption_information intinfo;
    intinfo.interruption_information=vmread(vm_entry_interruptioninfo);

    if ((intinfo.valid==0) || (intinfo.interruptvector!=idtvectorinfo.interruptvector) )
    {
      nosendchar[getAPICID()]=0;
      sendstringf("Here's one reason why you're crashing.  A pending interrupt never got respawned.  (Was supposed to spawn int %d) \n",intinfo.interruptvector);
      while (1);

    }
  }

  return result;
}
