#include "vmxsetup.h"
#include "vmreadwrite.h"
#include "msrnames.h"
#include "vmxcontrolstructures.h"
#include "main.h"
#include "mm.h"
#include "vmmhelper.h"
#include "offloados.h"
#include "vmpaging.h"
#include "vmeventhandler.h"

#include "epthandler.h"
#include "neward.h"
#include "displaydebug.h"
#include "common.h"

criticalSection setupVMX_lock={.name="setupVMX_lock", .debuglevel=2};

volatile unsigned char *MSRBitmap;
volatile unsigned char *IOBitmap;

volatile unsigned char *VMREADBitmap;
volatile unsigned char *VMWRITEBitmap;

int hasEPTsupport=0;
int TSCHooked=0;
int hasNPsupport=1;

int canToggleCR3Exit=0;

#ifdef USENMIFORWAIT
int canExitOnNMI=0;
#endif

int hasMTRRsupport;
MTRRCAP MTRRCapabilities;
MTRRDEF MTRRDefType;

int has_EPT_1GBsupport;
int has_EPT_2MBSupport;
int has_EPT_ExecuteOnlySupport;
int has_EPT_INVEPTSingleContext;
int has_EPT_INVEPTAllContext;

int hasUnrestrictedSupport;
int hasVPIDSupport;
int canToggleCR3Exit;
int hasVMCSShadowingSupport;
int hasCETSupport;

int has_VPID_INVVPIDIndividualAddress;
int has_VPID_INVVPIDSingleContext;
int has_VPID_INVVPIDAllContext;
int has_VPID_INVVPIDSingleContextRetainingGlobals;

int has_VGIFSupport;
int has_NP_1GBsupport;
int has_NP_2MBsupport;

extern void realmode_inthooks();
extern void realmode_inthooks_end();

extern void realmode_inthook_new12();
extern void realmode_inthook_new15();

void realmode_inthook_calladdress();

extern DWORD realmode_inthook_original12;
extern DWORD realmode_inthook_original15;
extern WORD realmode_inthook_conventional_memsize;

void setupVMX_AMD(pcpuinfo currentcpuinfo)
{
  UINT64 eax, ebx, ecx,edx;

  Segment_Attribs reg_csaccessrights;
  Segment_Attribs reg_traccessrights UNUSED;

  if (currentcpuinfo->cpunr!=0)
  {
    sendstringf("setupVMX_AMD for AP cpu\n");
  }

#ifdef AMDNP

  currentcpuinfo->vmcb->NP_ENABLE=1;
  currentcpuinfo->vmcb->G_PAT=readMSR(0x277);

  volatile PPML4 pml4=(PPML4)malloc(4096);
  zeromemory((volatile void*)pml4,4096);

  currentcpuinfo->vmcb->N_CR3=VirtualToPhysical((void*)pml4);
  sendstringf("Setup nCR3 at %6\n", currentcpuinfo->vmcb->N_CR3);

  has_NP_1GBsupport=1;
  has_NP_2MBsupport=1;

  PPML4 newpml4=(PPML4)malloc(4096);
  copymem(newpml4, pml4table, 4096);

  sendstringf("Created new PML4 table at %6 (PA %6)\n", newpml4, VirtualToPhysical((void*)newpml4));

  *(QWORD*)(&newpml4[510])=currentcpuinfo->vmcb->N_CR3;
  newpml4[510].P=1;
  newpml4[510].RW=1;

  *(QWORD*)(&newpml4[511])=VirtualToPhysical((void*)newpml4);
  newpml4[511].P=1;
  newpml4[511].RW=1;

  asm volatile ("": : :"memory");

  setCR3(VirtualToPhysical((void*)newpml4));

  sendstringf("Set CR3 to %6 . It is now %6\n", VirtualToPhysical((void*)newpml4), getCR3() );

  _invlpg(0xffffff0000000000ULL);

#endif

  currentcpuinfo->vmcb_pending[0]=0;
  currentcpuinfo->vmcb_pending[1]=0;
  currentcpuinfo->vmcb_pending[2]=0;
  currentcpuinfo->vmcb_pending[3]=0;
  currentcpuinfo->vmcb_pending[4]=0;
  currentcpuinfo->vmcb_pending[5]=0;
  currentcpuinfo->vmcb_pending[6]=0;
  currentcpuinfo->vmcb_pending[7]=0;
  currentcpuinfo->vmcb_pending[8]=0;
  currentcpuinfo->vmcb_pending[9]=0;
  currentcpuinfo->vmcb_pending[10]=0;
  currentcpuinfo->vmcb_pending[11]=0;
  currentcpuinfo->vmcb_pending[12]=0;
  currentcpuinfo->vmcb_pending[13]=0;
  currentcpuinfo->vmcb_pending[14]=0;
  currentcpuinfo->vmcb_pending[15]=0;

  currentcpuinfo->vmcb_GIF=1;
  currentcpuinfo->vmcb->InterceptVMRUN=1;

  eax=0x8000000a;
  _cpuid(&eax, &ebx, &ecx,&edx);

  if (edx & (1<<16))
  {
    sendstringf("Supports Virtualized GIF\n");
    has_VGIFSupport=1;
    currentcpuinfo->vmcb->V_GIF=1;
    currentcpuinfo->vmcb->V_GIF_ENABLED=1;
  }
  else
  {
    currentcpuinfo->vmcb->InterceptCLGI=1;
    currentcpuinfo->vmcb->InterceptSTGI=1;
  }

  currentcpuinfo->vmcb->GuestASID=1;

  currentcpuinfo->vmcb->EFER=0x1500 | (1<<8) | (1<<10);

  reg_traccessrights.SegmentAttrib=0;
  reg_traccessrights.Segment_type=11;
  reg_traccessrights.S=0;
  reg_traccessrights.DPL=0;
  reg_traccessrights.P=1;
  reg_traccessrights.G=0;
  reg_traccessrights.D_B=1;

  reg_csaccessrights.SegmentAttrib=0;
  reg_csaccessrights.Segment_type=11;
  reg_csaccessrights.S=1;
  reg_csaccessrights.DPL=0;
  reg_csaccessrights.P=1;
  reg_csaccessrights.L=1;
  reg_csaccessrights.G=0;
  reg_csaccessrights.D_B=0;

  currentcpuinfo->vmcb->CR4=getCR4();
  currentcpuinfo->vmcb->CR3=getCR3();
  currentcpuinfo->vmcb->CR0=getCR0();

  currentcpuinfo->guestCR3=getCR3();
  currentcpuinfo->guestCR0=getCR0();
  currentcpuinfo->hasIF=0;

  currentcpuinfo->vmcb->gdtr_base=getGDTbase();
  currentcpuinfo->vmcb->idtr_base=getIDTbase();

  currentcpuinfo->vmcb->gdtr_limit=0x58;
  currentcpuinfo->vmcb->idtr_limit=8*256;

  currentcpuinfo->vmcb->cs_selector=80;

  currentcpuinfo->vmcb->cs_attrib=(WORD)reg_csaccessrights.SegmentAttrib;

  currentcpuinfo->vmcb->ds_selector=8;
  currentcpuinfo->vmcb->es_selector=8;
  currentcpuinfo->vmcb->ss_selector=8;
  currentcpuinfo->vmcb->fs_selector=8;
  currentcpuinfo->vmcb->gs_selector=8;
  currentcpuinfo->vmcb->ldtr_selector=0;
  currentcpuinfo->vmcb->tr_selector=64;

  sendstringf("cs_attrib(%x)  set to %x\n", ((UINT64)&currentcpuinfo->vmcb->cs_attrib-(UINT64)currentcpuinfo->vmcb), currentcpuinfo->vmcb->cs_attrib);
  sendstringf("gdtr_limit(%x)  set to %x\n", ((UINT64)&currentcpuinfo->vmcb->gdtr_limit-(UINT64)currentcpuinfo->vmcb), currentcpuinfo->vmcb->gdtr_limit);

  currentcpuinfo->vmcb->DR7=0x400;

  currentcpuinfo->vmcb->RSP=((UINT64)malloc(4096))+0x1000-0x28;
  currentcpuinfo->vmcb->RFLAGS=getRFLAGS();

  if (currentcpuinfo->cpunr==0)
    currentcpuinfo->vmcb->RIP=(UINT64)reboot;
  else
    currentcpuinfo->vmcb->RIP=(UINT64)apentryvmx;

  if (!loadedOS)
    currentcpuinfo->vmcb->InterceptINT=1;

  currentcpuinfo->vmcb->InterceptShutdown=1;
  currentcpuinfo->vmcb->InterceptVMMCALL=1;
  currentcpuinfo->vmcb->MSR_PROT=1;

  currentcpuinfo->vmcb->InterceptExceptions=(1<<1) | (1<<3);

  if (MSRBitmap==NULL)
  {
    int i;

    MSRBitmap=allocateContiguousMemory(2);

    if (MSRBitmap==NULL)
    {
      sendstringf("allocateContiguousMemory failed. MSRBitmap=NULL\n");
      while(1);
    }

    for (i=0; i<4096*2; i++)
      MSRBitmap[i]=0;

    MSRBitmap[0x1000+(0x0117*2)/8]|=3 << ((0x0117*2) % 8);

    MSRBitmap[0x1000+(0x0115*2)/8]|=3 << ((0x0115*2) % 8);

    MSRBitmap[0x800+(0x80*2)/8]|=3 << ((0x80*2) % 8);
  }
  currentcpuinfo->vmcb->MSRPM_BASE_PA=VirtualToPhysical((void *)MSRBitmap);

  currentcpuinfo->guest_VM_HSAVE_PA=0;

  globals_have_been_configured=1;

  SaveExtraHostState(currentcpuinfo->vmcb_PA);

  if (loadedOS)
  {
    POriginalState originalstate=(POriginalState)mapPhysicalMemory(loadedOS, sizeof(OriginalState));;
    PGDT_ENTRY gdt=NULL,ldt=NULL;
    ULONG ldtselector=originalstate->ldt;
    int notpaged;

    sendstringf("Setting up guest based on loadedOS settings\n");

    sendstringf("originalstate=%6\n", originalstate);
    sendstringf("originalstate->cpucount(%x)=%d\n",&originalstate->cpucount, originalstate->cpucount);
    sendstringf("originalstate->cr0=%6\n",originalstate->cr0);
    sendstringf("originalstate->cr2=%6\n",originalstate->cr2);
    sendstringf("originalstate->cr3=%6\n",originalstate->cr3);
    sendstringf("originalstate->cr4=%6\n",originalstate->cr4);
    sendstringf("originalstate->rip(%x)=%6\n",&originalstate->rip, originalstate->rip);
    sendstringf("originalstate->cs=%x\n",originalstate->cs);
    sendstringf("originalstate->ss=%x\n",originalstate->ss);
    sendstringf("originalstate->ds=%x\n",originalstate->ds);
    sendstringf("originalstate->es=%x\n",originalstate->es);
    sendstringf("originalstate->fs=%x\n",originalstate->fs);
    sendstringf("originalstate->gs=%x\n",originalstate->gs);
    sendstringf("originalstate->ldt=%x\n",originalstate->ldt);
    sendstringf("originalstate->tr=%x\n",originalstate->tr);

    sendstringf("originalstate->dr7(%x)=%6\n",&originalstate->dr7, originalstate->dr7);
    sendstringf("originalstate->gdtbase=%6\n",originalstate->gdtbase);
    sendstringf("originalstate->gdtlimit=%x\n",originalstate->gdtlimit);
    sendstringf("originalstate->idtbase=%6\n",originalstate->idtbase);
    sendstringf("originalstate->idtlimit=%x\n",originalstate->idtlimit);
    sendstringf("originalstate->originalLME=%x\n",originalstate->originalLME);
    sendstringf("originalstate->rflags=%6\n",originalstate->rflags);

    sendstringf("originalstate->rax=%6\n",originalstate->rax);
    sendstringf("originalstate->rbx=%6\n",originalstate->rbx);
    sendstringf("originalstate->rcx=%6\n",originalstate->rcx);
    sendstringf("originalstate->rdx=%6\n",originalstate->rdx);
    sendstringf("originalstate->rsi=%6\n",originalstate->rsi);
    sendstringf("originalstate->rdi=%6\n",originalstate->rdi);
    sendstringf("originalstate->rbp=%6\n",originalstate->rbp);
    sendstringf("originalstate->rsp=%6\n",originalstate->rsp);
    sendstringf("originalstate->r8=%6\n",originalstate->r8);
    sendstringf("originalstate->r9=%6\n",originalstate->r9);
    sendstringf("originalstate->r10=%6\n",originalstate->r10);
    sendstringf("originalstate->r11=%6\n",originalstate->r11);
    sendstringf("originalstate->r12=%6\n",originalstate->r12);
    sendstringf("originalstate->r13=%6\n",originalstate->r13);
    sendstringf("originalstate->r14=%6\n",originalstate->r14);
    sendstringf("originalstate->r15=%6\n",originalstate->r15);

    sendstringf("originalstate->fsbase=%6\n",originalstate->fsbase);
    sendstringf("originalstate->gsbase=%6\n",originalstate->gsbase);

    currentcpuinfo->vmcb->CR4=originalstate->cr4;
    currentcpuinfo->vmcb->CR3=originalstate->cr3;
    currentcpuinfo->vmcb->CR0=originalstate->cr0;
    currentcpuinfo->vmcb->RFLAGS=originalstate->rflags;

    currentcpuinfo->efer=originalstate->originalEFER;
    currentcpuinfo->vmcb->EFER=currentcpuinfo->efer | (1<<12);

    currentcpuinfo->vmcb->gdtr_base=(UINT64)originalstate->gdtbase;
    currentcpuinfo->vmcb->gdtr_limit=(UINT64)originalstate->gdtlimit;

    currentcpuinfo->vmcb->idtr_base=(UINT64)originalstate->idtbase;
    currentcpuinfo->vmcb->idtr_limit=(UINT64)originalstate->idtlimit;

    gdt=(PGDT_ENTRY)(UINT64)mapPhysicalMemory(getPhysicalAddressVM(currentcpuinfo, originalstate->gdtbase, &notpaged), originalstate->gdtlimit);

    ULONG ldtlimit;
    if ((UINT64)originalstate->ldt)
    {
      UINT64 ldtbase;

      sendstring("ldt is valid, so getting the information\n\r");

      ldtbase=(gdt[(ldtselector >> 3)].Base24_31 << 24) + gdt[(ldtselector >> 3)].Base0_23;
      ldtlimit=(gdt[(ldtselector >> 3)].Limit16_19 << 16) + gdt[(ldtselector >> 3)].Limit0_15;
      ldt=(PGDT_ENTRY)(UINT64)mapPhysicalMemory(getPhysicalAddressVM(currentcpuinfo, ldtbase, &notpaged), ldtlimit);
    }

    currentcpuinfo->vmcb->es_selector=originalstate->es;
    currentcpuinfo->vmcb->es_attrib=convertSegmentAccessRightsToSegmentAttrib(originalstate->es_AccessRights);
    currentcpuinfo->vmcb->es_limit=originalstate->es_Limit;

    currentcpuinfo->vmcb->cs_selector=originalstate->cs;
    currentcpuinfo->vmcb->cs_attrib=convertSegmentAccessRightsToSegmentAttrib(originalstate->cs_AccessRights);
    currentcpuinfo->vmcb->cs_limit=originalstate->cs_Limit;

    currentcpuinfo->vmcb->ss_selector=originalstate->ss;
    currentcpuinfo->vmcb->ss_attrib=convertSegmentAccessRightsToSegmentAttrib(originalstate->ss_AccessRights);
    currentcpuinfo->vmcb->ss_limit=originalstate->ss_Limit;

    currentcpuinfo->vmcb->ds_selector=originalstate->ds;
    currentcpuinfo->vmcb->ds_attrib=convertSegmentAccessRightsToSegmentAttrib(originalstate->ds_AccessRights);
    currentcpuinfo->vmcb->ds_limit=originalstate->ds_Limit;

    currentcpuinfo->vmcb->fs_selector=originalstate->fs;
    currentcpuinfo->vmcb->fs_attrib=convertSegmentAccessRightsToSegmentAttrib(originalstate->fs_AccessRights);
    currentcpuinfo->vmcb->fs_limit=originalstate->fs_Limit;

    currentcpuinfo->vmcb->gs_selector=originalstate->gs;
    currentcpuinfo->vmcb->gs_attrib=convertSegmentAccessRightsToSegmentAttrib(originalstate->gs_AccessRights);
    currentcpuinfo->vmcb->gs_limit=originalstate->gs_Limit;

    currentcpuinfo->vmcb->ldtr_selector=originalstate->ldt;
    currentcpuinfo->vmcb->tr_selector=originalstate->tr;

    if (originalstate->originalLME)
    {

      currentcpuinfo->vmcb->cs_base=0;
      currentcpuinfo->vmcb->ss_base=0;
      currentcpuinfo->vmcb->ds_base=0;
      currentcpuinfo->vmcb->es_base=0;
      currentcpuinfo->vmcb->fs_base=originalstate->fsbase;
      currentcpuinfo->vmcb->gs_base=originalstate->gsbase;
      currentcpuinfo->vmcb->tr_base=getSegmentBaseEx(gdt,ldt,originalstate->tr, 1);
    }
    else
    {

      currentcpuinfo->vmcb->cs_base=getSegmentBase(gdt, ldt, originalstate->cs);
      currentcpuinfo->vmcb->ss_base=getSegmentBase(gdt, ldt, originalstate->ss);
      currentcpuinfo->vmcb->ds_base=getSegmentBase(gdt, ldt, originalstate->ds);
      currentcpuinfo->vmcb->es_base=getSegmentBase(gdt, ldt, originalstate->es);
      currentcpuinfo->vmcb->fs_base=getSegmentBase(gdt, ldt, originalstate->fs);
      currentcpuinfo->vmcb->gs_base=getSegmentBase(gdt, ldt, originalstate->gs);
      currentcpuinfo->vmcb->tr_base=getSegmentBase(gdt, ldt, originalstate->tr);
    }
    currentcpuinfo->vmcb->ldtr_limit=getSegmentLimit(gdt, ldt, originalstate->ldt);
    if (originalstate->tr==0)
      currentcpuinfo->vmcb->tr_limit=0xffff;
    else
      currentcpuinfo->vmcb->tr_limit=getSegmentLimit(gdt, ldt, originalstate->tr);

    currentcpuinfo->vmcb->ldtr_base=getSegmentBase(gdt, ldt, originalstate->ldt);
    currentcpuinfo->vmcb->ldtr_attrib=getSegmentAttrib(gdt,ldt,originalstate->ldt);

    if (originalstate->tr)
      currentcpuinfo->vmcb->tr_attrib=getSegmentAttrib(gdt,ldt,originalstate->tr);
    else
      currentcpuinfo->vmcb->tr_attrib=0x8b;

    currentcpuinfo->vmcb->SYSENTER_CS=(UINT64)readMSR(IA32_SYSENTER_CS_MSR);
    currentcpuinfo->vmcb->SYSENTER_ESP=(UINT64)readMSR(IA32_SYSENTER_ESP_MSR);
    currentcpuinfo->vmcb->SYSENTER_EIP=(UINT64)readMSR(IA32_SYSENTER_EIP_MSR);

    currentcpuinfo->actual_sysenter_CS=currentcpuinfo->vmcb->SYSENTER_CS;
    currentcpuinfo->actual_sysenter_ESP=currentcpuinfo->vmcb->SYSENTER_ESP;
    currentcpuinfo->actual_sysenter_EIP=currentcpuinfo->vmcb->SYSENTER_EIP;

    currentcpuinfo->vmcb->DR7=originalstate->dr7;

    if (originalstate->originalLME)
    {

      currentcpuinfo->vmcb->RSP=originalstate->rsp;
      currentcpuinfo->vmcb->RAX=originalstate->rax;
      currentcpuinfo->vmcb->RIP=originalstate->rip;

    }
    else
    {

      currentcpuinfo->vmcb->RSP=(ULONG)originalstate->rsp;
      currentcpuinfo->vmcb->RAX=(ULONG)originalstate->rax;
      currentcpuinfo->vmcb->RIP=(ULONG)originalstate->rip;
    }

    if (gdt)
      unmapPhysicalMemory(gdt, originalstate->gdtlimit);

    if (ldt)
      unmapPhysicalMemory(ldt, ldtlimit);

    if (originalstate)
      unmapPhysicalMemory(originalstate, sizeof(OriginalState));
  }
  else
  {

  }

  sendstringf("Configured cpu %d\n", currentcpuinfo->cpunr);
  currentcpuinfo->vmxsetup=1;
  csLeave(&setupVMX_lock);

}

int vmx_enableProcBasedFeature(DWORD PBF)
{
  if (((IA32_VMX_PROCBASED_CTLS >> 32) & PBF) == PBF)
  {
    vmwrite(vm_execution_controls_cpu, vmread(vm_execution_controls_cpu) | PBF);
    return 1;
  }
  else
    return 0;
}

int vmx_disableProcBasedFeature(DWORD PBF)
{
  QWORD PBCTLS=IA32_VMX_PROCBASED_CTLS;

  if (IA32_VMX_BASIC.default1canbe0)
    PBCTLS=readMSR(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

  if (PBCTLS & PBF)
    return 0;
  else
  {
    vmwrite(vm_execution_controls_cpu, vmread(vm_execution_controls_cpu) & (~PBF));
    return 1;
  }
}

int vmx_enablePinBasedFeature(DWORD PINBF)
{
  if (((IA32_VMX_PINBASED_CTLS >> 32) & PINBF) == PINBF)
  {
    vmwrite(vm_execution_controls_pin, vmread(vm_execution_controls_pin) | PINBF);
    return 1;
  }
  else
    return 0;
}

int vmx_disablePinBasedFeature(DWORD PINBF)
{
  QWORD PINBCTLS=IA32_VMX_PINBASED_CTLS;

  if (IA32_VMX_BASIC.default1canbe0)
    PINBCTLS=readMSR(IA32_VMX_TRUE_PINBASED_CTLS_MSR);

  if (PINBCTLS & PINBF)
    return 0;
  else
  {
    vmwrite(vm_execution_controls_pin, vmread(vm_execution_controls_pin) & (~PINBF));
    return 1;
  }
}

int vmx_enableNMIWindowExiting(void)
{
  if (vmx_enableProcBasedFeature(PBEF_NMI_WINDOW_EXITING))
  {

    if (vmx_enablePinBasedFeature(PINBEF_VIRTUAL_NMIS))
    {

      if (vmx_enablePinBasedFeature(PINBEF_NMI_EXITING))
        return 1;

      vmx_disablePinBasedFeature(PINBEF_VIRTUAL_NMIS);
    }

    vmx_disableProcBasedFeature(PBEF_NMI_WINDOW_EXITING);
  }

  return 0;
}

int vmx_disableNMIWindowExiting(void)
{
  int a,b,c;
  a=vmx_disableProcBasedFeature(PBEF_NMI_WINDOW_EXITING);
  b=vmx_disablePinBasedFeature(PINBEF_VIRTUAL_NMIS);
  c=vmx_disablePinBasedFeature(PINBEF_NMI_EXITING);

  return (a+b+c==3);
}

int vmx_addSingleSteppingReasonEx(pcpuinfo currentcpuinfo, int reason, void *data)
{
  if (currentcpuinfo->singleStepping.ReasonsPos>=currentcpuinfo->singleStepping.ReasonsLength)
  {
    currentcpuinfo->singleStepping.ReasonsLength=(currentcpuinfo->singleStepping.ReasonsLength+2)*2;
    currentcpuinfo->singleStepping.Reasons=realloc(currentcpuinfo->singleStepping.Reasons, currentcpuinfo->singleStepping.ReasonsLength * sizeof(SingleStepReason));
  }

  if (currentcpuinfo->singleStepping.ReasonsPos>=1)
  {
    sendstringf("Multiple single stepping reasons\n");
  }

  currentcpuinfo->singleStepping.Reasons[currentcpuinfo->singleStepping.ReasonsPos].Reason=reason;
  currentcpuinfo->singleStepping.Reasons[currentcpuinfo->singleStepping.ReasonsPos].Data=data;
  currentcpuinfo->singleStepping.ReasonsPos++;

  return currentcpuinfo->singleStepping.ReasonsPos-1;

}

int vmx_addSingleSteppingReason(pcpuinfo currentcpuinfo, int reason, int ID)
{
  if (currentcpuinfo->singleStepping.ReasonsPos>=currentcpuinfo->singleStepping.ReasonsLength)
  {
    currentcpuinfo->singleStepping.ReasonsLength=(currentcpuinfo->singleStepping.ReasonsLength+2)*2;
    currentcpuinfo->singleStepping.Reasons=realloc(currentcpuinfo->singleStepping.Reasons, currentcpuinfo->singleStepping.ReasonsLength * sizeof(SingleStepReason));
  }

  if (currentcpuinfo->singleStepping.ReasonsPos>=1)
  {
    sendstringf("Multiple single stepping reasons\n");
  }

  currentcpuinfo->singleStepping.Reasons[currentcpuinfo->singleStepping.ReasonsPos].Reason=reason;
  currentcpuinfo->singleStepping.Reasons[currentcpuinfo->singleStepping.ReasonsPos].ID=ID;
  currentcpuinfo->singleStepping.ReasonsPos++;

  return currentcpuinfo->singleStepping.ReasonsPos-1;
}

int vmx_enableSingleStepMode(void)
{
  pcpuinfo c=getcpuinfo();

  if (isAMD)
  {

    c->vmcb->InterceptVINTR=1;
    c->vmcb->InterceptINTR=1;
    c->vmcb->InterceptExceptions=0x0000ffff;

    c->vmcb->VMCB_CLEAN_BITS&=~(1<<0);
    c->vmcb->VMCB_CLEAN_BITS=0;

    RFLAGS v;
    v.value=c->vmcb->RFLAGS;

    if (c->singleStepping.ReasonsPos==0)
      c->singleStepping.PreviousTFState=v.TF;

    v.TF=1;
    v.RF=1;
    if (v.IF)
      c->vmcb->INTERRUPT_SHADOW=1;

    c->vmcb->RFLAGS=v.value;
    c->singleStepping.Method=3;

    if (c->singleStepping.ReasonsPos==0)
    {
      c->singleStepping.PreviousEFER=c->vmcb->EFER;
      c->singleStepping.PreviousFMASK=c->vmcb->SFMASK;
      c->singleStepping.LastInstructionWasSyscall=0;

      c->vmcb->EFER&=0xfffffffffffffffeULL;
      c->vmcb->VMCB_CLEAN_BITS&=~(1<< 5);
    }

    return 1;

  }
  else
  {
    sendstring("\n");

    if (vmx_enableProcBasedFeature(PBEF_MONITOR_TRAP_FLAG))
    {
      sendstring("Using the monitor trap flag\n");
      c->singleStepping.Method=1;
      return 1;
    }
    else
    {
      c->singleStepping.Method=2;
      if (vmx_enableProcBasedFeature(PBEF_INTERRUPT_WINDOW_EXITING))
      {
        if ((vmread(vm_entry_interruptioninfo) >> 31)==0)
          vmwrite(vm_guest_interruptability_state,2);

        sendstring("Using the interrupt window\n");
        return 1;
      }
    }
  }

  return 0;
}

int vmx_disableSingleStepMode(void)
{
  int r=0;
  pcpuinfo c=getcpuinfo();

  sendstringf("%d Disabling single step mode\n", c->cpunr);

  if (isAMD)
  {

    sendstringf("%d RFLAGS was %x\n", c->cpunr, c->vmcb->RFLAGS);

    RFLAGS v;
    v.value=c->vmcb->RFLAGS;
    v.TF=c->singleStepping.PreviousTFState;

    c->vmcb->RFLAGS=v.value;
    sendstringf("%d RFLAGS is %x\n", c->cpunr, c->vmcb->RFLAGS);

    c->singleStepping.Method=0;

    c->vmcb->InterceptVINTR=0;
    c->vmcb->InterceptINTR=0;
    c->vmcb->InterceptExceptions=(1<<1) | (1<<3);

    sendstringf("b c->vmcb->VMCB_CLEAN_BITS=%6\n",c->vmcb->VMCB_CLEAN_BITS);
    c->vmcb->VMCB_CLEAN_BITS&=~(1<<0);
    c->vmcb->VMCB_CLEAN_BITS=0;
    sendstringf("a c->vmcb->VMCB_CLEAN_BITS=%6\n",c->vmcb->VMCB_CLEAN_BITS);

    c->vmcb->EFER=c->singleStepping.PreviousEFER;
    c->vmcb->SFMASK=c->singleStepping.PreviousFMASK;
    c->singleStepping.LastInstructionWasSyscall=0;

    c->vmcb->VMCB_CLEAN_BITS&=~(1<< 5);

    return 1;
  }
  else
  {
    if (c->singleStepping.Method==1)
      r=vmx_disableProcBasedFeature(PBEF_MONITOR_TRAP_FLAG);

    if (c->singleStepping.Method==2)
      r=vmx_disableProcBasedFeature(PBEF_INTERRUPT_WINDOW_EXITING);
  }
  return r;
}

int setupEPT(pcpuinfo currentcpuinfo)
{

  QWORD IA32_VMX_PROCBASED_CTLS=readMSR(IA32_VMX_PROCBASED_CTLS_MSR);

  sendstring("setupEPT\n");

  hasEPTsupport=0;

  if (IA32_VMX_PROCBASED_CTLS >> 63)
  {

    QWORD IA32_VMX_SECONDARY_PROCBASED_CTLS=readMSR(IA32_VMX_PROCBASED_CTLS2_MSR);
    DWORD old_vm_execution_controls_cpu=vmread(vm_execution_controls_cpu);
    DWORD new_vm_execution_controls_cpu=old_vm_execution_controls_cpu | SECONDARY_EXECUTION_CONTROLS;

    sendstringf("old_vm_execution_controls_cpu=%x  Want to set it to %6\n",old_vm_execution_controls_cpu, new_vm_execution_controls_cpu);
    vmwrite(vm_execution_controls_cpu, new_vm_execution_controls_cpu);

    DWORD current_vm_execution_controls_cpu=vmread(vm_execution_controls_cpu);
    sendstringf("new_vm_execution_controls_cpu=%x\n",current_vm_execution_controls_cpu);

    if (current_vm_execution_controls_cpu != new_vm_execution_controls_cpu)
    {
      sendstringf("Meh...\n");
      while(1);
    }

    sendstringf("IA32_VMX_SECONDARY_PROCBASED_CTLS=%6\n", IA32_VMX_SECONDARY_PROCBASED_CTLS);

    if ((IA32_VMX_SECONDARY_PROCBASED_CTLS>>32) & SPBEF_ENABLE_EPT)
    {
      DWORD secondarycontrols=vmread(vm_execution_controls_cpu_secondary);

      sendstringf("SPBEF_ENABLE_EPT can be set\n");
      secondarycontrols=secondarycontrols | SPBEF_ENABLE_EPT;

      if ((IA32_VMX_SECONDARY_PROCBASED_CTLS>>32) & SPBEF_ENABLE_VPID)
      {
    	  sendstringf("SPBEF_ENABLE_VPID can also be set\n");
    	  secondarycontrols=secondarycontrols | SPBEF_ENABLE_VPID;
    	  vmwrite(vm_vpid,1);

    	  hasVPIDSupport=1;
      }

      vmwrite(vm_execution_controls_cpu_secondary, secondarycontrols);

      PEPT_PML4E pml4map=malloc2(4096);
      if (pml4map==NULL)
      {
        sendstringf("failure allocating pml4map");
        return 0;
      }
      else
        zeromemory(pml4map,4096);

      QWORD pml4mapPA=VirtualToPhysical(pml4map);
      currentcpuinfo->EPTPML4=pml4mapPA;

      sendstringf("pml4map is at %6\n", pml4mapPA);

      TIA32_VMX_VPID_EPT_CAP eptinfo;
      eptinfo.IA32_VMX_VPID_EPT_CAP=readMSR(IA32_VMX_EPT_VPID_CAP_MSR);

      QWORD eptp=pml4mapPA;
      PEPTP x=(PEPTP)&eptp;
      x->PAGEWALKLENGTH=3;

      if (eptinfo.EPT_writeBackSupport)
        x->MEMTYPE=6;
      else
        x->MEMTYPE=0;

      vmwrite(vm_eptpointer, eptp);

      has_EPT_1GBsupport=eptinfo.EPT_1GBSupport;
      has_EPT_2MBSupport=eptinfo.EPT_2MBSupport;
      has_EPT_ExecuteOnlySupport=eptinfo.EPT_executeOnlySupport;

      has_EPT_INVEPTSingleContext=eptinfo.EPT_INVEPTSingleContext;
      has_EPT_INVEPTAllContext=eptinfo.EPT_INVEPTAllContext;

      has_VPID_INVVPIDIndividualAddress=eptinfo.VPID_INVVPIDIndividualAddress;
      has_VPID_INVVPIDSingleContext=eptinfo.VPID_INVVPIDSingleContext;
      has_VPID_INVVPIDAllContext=eptinfo.VPID_INVVPIDAllContext;
      has_VPID_INVVPIDSingleContextRetainingGlobals=eptinfo.VPID_INVVPIDAllContext;

      QWORD rax=1,rbx=0,rcx=0,rdx=0;
      _cpuid(&rax, &rbx, &rcx, &rdx);

      if (rdx & (1 << 12))
      {
        hasMTRRsupport=1;

        MTRRCapabilities.Value=readMSR(IA32_MTRRCAP_MSR);
        MTRRDefType.Value=readMSR(IA32_MTRR_DEF_TYPE_MSR);

        initMemTypeRanges();
      }

      return 1;
    }
    else
      sendstring("That means that SPBEF_ENABLE_EPT(bit 1) can not be set\n");

  }
  else
  {
    sendstring("This cpu does not support secondary procbased controls\n");
  }

  return 0;
}

void setup8086WaitForSIPI(pcpuinfo currentcpuinfo, int setupvmcontrols)
{

  Access_Rights reg_csaccessrights,reg_segaccessrights;
  DWORD gdtbase, idtbase;

  sendstringf("entering sleepmode for ap cpu\n");

  if (hasUnrestrictedSupport)
  {
    reg_csaccessrights.AccessRights=0;
    reg_csaccessrights.Segment_type=11;
    reg_csaccessrights.S=1;
    reg_csaccessrights.DPL=0;
    reg_csaccessrights.P=1;
    reg_csaccessrights.G=0;
    reg_csaccessrights.D_B=0;
    reg_csaccessrights.L=0;
    reg_csaccessrights.unusable=0;

    reg_segaccessrights.AccessRights=0;
    reg_segaccessrights.Segment_type=3;
    reg_segaccessrights.S=1;
    reg_segaccessrights.DPL=0;
    reg_segaccessrights.P=1;
    reg_segaccessrights.G=0;
    reg_segaccessrights.D_B=0;
    reg_segaccessrights.unusable=0;

  }
  else
  {
    gdtbase=VirtualToPhysical((void *)getGDTbase());
    idtbase=VirtualToPhysical(idttable32);

    reg_csaccessrights.AccessRights=0;
    reg_csaccessrights.Segment_type=3;
    reg_csaccessrights.S=1;
    reg_csaccessrights.DPL=3;
    reg_csaccessrights.P=1;
    reg_csaccessrights.G=0;
    reg_csaccessrights.D_B=0;
    reg_csaccessrights.unusable=0;

    reg_segaccessrights=reg_csaccessrights;
  }

  currentcpuinfo->guestCR3=0;
  currentcpuinfo->guestCR0=0;
  currentcpuinfo->hasIF=0;

  if (setupvmcontrols)
  {
    DWORD new_vm_execution_controls_cpu=vmread(vm_execution_controls_cpu) | (UINT64)IA32_VMX_PROCBASED_CTLS | USE_IO_BITMAPS | USE_MSR_BITMAPS;

    if ((IA32_VMX_PROCBASED_CTLS >> 32) & (1<<31))
      new_vm_execution_controls_cpu=new_vm_execution_controls_cpu | (1<<31);

    vmwrite(vm_execution_controls_cpu, new_vm_execution_controls_cpu);
    if ((new_vm_execution_controls_cpu >> 31) & 1)
    {

      QWORD secondarycpu=vmread(vm_execution_controls_cpu_secondary);

      if ((IA32_VMX_SECONDARY_PROCBASED_CTLS >> 32) & SPBEF_ENABLE_RDTSCP)
      {
        sendstringf("Enabling rdtscp\n");
        secondarycpu|=SPBEF_ENABLE_RDTSCP;
      }

      if ((IA32_VMX_SECONDARY_PROCBASED_CTLS >> 32) & SPBEF_ENABLE_XSAVES)
      {
        sendstringf("Enabling xsaves\n");
        secondarycpu|=SPBEF_ENABLE_XSAVES;
      }

      if ((IA32_VMX_SECONDARY_PROCBASED_CTLS >> 32) & SPBEF_ENABLE_INVPCID)
      {
        sendstringf("Enabling INVPCID\n");
        secondarycpu|=SPBEF_ENABLE_INVPCID;
      }

      if ((IA32_VMX_SECONDARY_PROCBASED_CTLS >> 32) & SPBEF_USER_WAIT_AND_PAUSE)
      {
        sendstringf("Enabling xsaves\n");
        secondarycpu|=SPBEF_USER_WAIT_AND_PAUSE;
      }

      vmwrite(vm_execution_controls_cpu_secondary, secondarycpu);

    }

    vmwrite(vm_entry_controls,vmread(vm_entry_controls) | (UINT64)IA32_VMX_ENTRY_CTLS );

    vmwrite(vm_cr0_read_shadow,0x10);
    vmwrite(vm_cr4_read_shadow,(UINT64)0);
    vmwrite(vm_cr3_targetvalue0,(UINT64)0xffffffffffffffffULL);
  }

  if (hasUnrestrictedSupport)
  {
    vmwrite(vm_guest_cr3, 0);
    vmwrite(vm_guest_cr0, 0x10 | (IA32_VMX_CR0_FIXED0 & 0xFFFFFFFF7FFFFFFEULL));
    vmwrite(vm_guest_cr4, IA32_VMX_CR4_FIXED0);

    vmwrite(vm_guest_gdtr_base, 0);
    vmwrite(vm_guest_gdt_limit, 0xffff);
    vmwrite(vm_guest_idtr_base, 0);
    vmwrite(vm_guest_idt_limit, 0xffff);
  }
  else
  {
    vmwrite(vm_guest_cr0,(UINT64)IA32_VMX_CR0_FIXED0 | CR0_WP);
    vmwrite(vm_guest_cr4,(UINT64)IA32_VMX_CR4_FIXED0 | CR4_VME | CR4_PSE | CR4_PAE);
    vmwrite(vm_guest_gdtr_base, gdtbase);
    vmwrite(vm_guest_gdt_limit, getGDTsize());
    vmwrite(vm_guest_idtr_base, idtbase);
    vmwrite(vm_guest_idt_limit, 256*8);

  }

  vmwrite(vm_guest_es,(UINT64)0);
  vmwrite(vm_guest_es_limit,(UINT64)0xffff);
  vmwrite(vm_guest_es_base,(UINT64)0);
  vmwrite(vm_guest_es_access_rights,(UINT64)reg_segaccessrights.AccessRights);

  vmwrite(vm_guest_ss,(UINT64)0);
   vmwrite(vm_guest_ss_limit,(UINT64)0xffff);
   vmwrite(vm_guest_ss_base,(UINT64)0);
   vmwrite(vm_guest_ss_access_rights,(UINT64)reg_segaccessrights.AccessRights);

   vmwrite(vm_guest_ds,(UINT64)0);
   vmwrite(vm_guest_ds_limit,(UINT64)0xffff);
   vmwrite(vm_guest_ds_base,(UINT64)0);
   vmwrite(vm_guest_ds_access_rights,(UINT64)reg_segaccessrights.AccessRights);

   vmwrite(vm_guest_fs,(UINT64)0);
   vmwrite(vm_guest_fs_limit,(UINT64)0xffff);
   vmwrite(vm_guest_fs_base,(UINT64)0);
   vmwrite(vm_guest_fs_access_rights,(UINT64)reg_segaccessrights.AccessRights);

   vmwrite(vm_guest_gs,(UINT64)0);
   vmwrite(vm_guest_gs_limit,(UINT64)0xffff);
   vmwrite(vm_guest_gs_base,(UINT64)0);
   vmwrite(vm_guest_gs_access_rights,(UINT64)reg_segaccessrights.AccessRights);

  vmwrite(vm_guest_cs,(UINT64)0);
  vmwrite(vm_guest_cs_limit,(UINT64)0xffff);
  if (hasUnrestrictedSupport)
    vmwrite(vm_guest_cs_base,(UINT64)0xffff0000);
  else
    vmwrite(vm_guest_cs_base,(UINT64)0xf0000);
  vmwrite(vm_guest_cs_access_rights,(UINT64)reg_segaccessrights.AccessRights);

  vmwrite(vm_guest_ldtr,(UINT64)0);
  if (hasUnrestrictedSupport)
    vmwrite(vm_guest_ldtr_limit,(UINT64)0xffff);
  else
    vmwrite(vm_guest_ldtr_limit,(UINT64)0);
  vmwrite(vm_guest_ldtr_base,(UINT64)0);
  if (hasUnrestrictedSupport)
    vmwrite(vm_guest_ldtr_access_rights,0x82);
  else
    vmwrite(vm_guest_ldtr_access_rights,(UINT64)(1<<16));

  vmwrite(vm_guest_tr,0);

  if (hasUnrestrictedSupport)
    vmwrite(vm_guest_tr_limit,0xffff);
  else
    vmwrite(vm_guest_tr_limit,(ULONG)sizeof(TSS)+32+8192+1);

  if (hasUnrestrictedSupport)
    vmwrite(vm_guest_tr_base,0);
  else
    vmwrite(vm_guest_tr_base,(UINT64)VirtualToPhysical(VirtualMachineTSS_V8086));

  vmwrite(vm_guest_tr_access_rights,0x8b);

  currentcpuinfo->efer=0;
  vmwrite(vm_entry_controls, vmread(vm_entry_controls) & (~VMENTRYC_IA32E_MODE_GUEST));
  vmwrite(vm_guest_IA32_EFER, vmread(vm_guest_IA32_EFER) & ~(1<<8));
  vmwrite(vm_guest_IA32_EFER, vmread(vm_guest_IA32_EFER) & ~(1<<10));

  currentcpuinfo->RealMode.IDTBase=0;
  currentcpuinfo->RealMode.GDTBase=0;
  currentcpuinfo->RealMode.IDTLimit=0x400;
  currentcpuinfo->RealMode.GDTBase=0;

  vmwrite(vm_guest_IA32_SYSENTER_CS,(UINT64)0);
  vmwrite(vm_guest_IA32_SYSENTER_ESP,(UINT64)0);
  vmwrite(vm_guest_IA32_SYSENTER_EIP,(UINT64)0);

  vmwrite(vm_guest_dr7,(UINT64)0x400);

  RFLAGS guestrflags;

  vmwrite(vm_guest_rsp,(UINT64)0);
  vmwrite(vm_guest_rip,(UINT64)0);

  guestrflags.value=0;
  guestrflags.reserved1=1;
  if (hasUnrestrictedSupport==0)
  {
    guestrflags.IOPL=3;
    guestrflags.VM=1;

    setupNonPagedPaging(currentcpuinfo);
  }
  else
  {
    vmwrite(vm_guest_cr3,0);
  }

  vmwrite(vm_guest_rflags,guestrflags.value );
  vmwrite(vm_guest_activity_state,(UINT64)3);
}

void vmx_setMSRReadExit(DWORD msrValue)
{
  if (isAMD)
  {

    if (msrValue<=0x1fff)
    {
      MSRBitmap[(msrValue*2)/8]|=1 << ((msrValue*2) % 8);
      return;
    }

    if ((msrValue>=0xc0000000) && (msrValue<=0xc0001fff))
    {
      msrValue=msrValue-0xc0000000;
      MSRBitmap[0x800+(msrValue*2)/8]|=1 << ((msrValue*2) % 8);
      return;
    }

    if ((msrValue>=0xc0010000) && (msrValue<=0xc0011fff))
    {
      msrValue=msrValue-0xc0010000;
      MSRBitmap[0x800+(msrValue*2)/8]|=1 << ((msrValue*2) % 8);
      return;
    }
  }
  else
  {
    if (msrValue<0xc0000000)
      MSRBitmap[msrValue/8]|=1 << (msrValue % 8);
    else
    {
      msrValue=msrValue-0xc0000000;
      MSRBitmap[1024+msrValue/8]|=1 << (msrValue % 8);
    }
  }
}

void vmx_removeMSRReadExit(DWORD msrValue)
{
  if (isAMD)
  {
    if (msrValue<=0x1fff)
    {
      MSRBitmap[(msrValue*2)/8]&=~(1 << ((msrValue*2) % 8));
      return;
    }

    if ((msrValue>=0xc0000000) && (msrValue<=0xc0001fff))
    {
      msrValue=msrValue-0xc0000000;
      MSRBitmap[0x800+(msrValue*2)/8]&=~(1 << ((msrValue*2) % 8));
      return;
    }

    if ((msrValue>=0xc0010000) && (msrValue<=0xc0011fff))
    {
      msrValue=msrValue-0xc0010000;
      MSRBitmap[0x800+(msrValue*2)/8]&=~(1 << ((msrValue*2) % 8));
      return;
    }
  }
  else
  {
    if (msrValue<0xc0000000)
      MSRBitmap[msrValue/8]&=~(1 << (msrValue % 8));
    else
    {
      msrValue=msrValue-0xc0000000;
      MSRBitmap[1024+msrValue/8]&=~(1 << (msrValue % 8));
    }
  }
}

void vmx_setMSRWriteExit(DWORD msrValue)
{
  if (isAMD)
  {
    if (msrValue<=0x1fff)
    {
      MSRBitmap[(msrValue*2)/8]|=2 << ((msrValue*2) % 8);
      return;
    }

    if ((msrValue>=0xc0000000) && (msrValue<=0xc0001fff))
    {
      msrValue=msrValue-0xc0000000;
      MSRBitmap[0x800+(msrValue*2)/8]|=2 << ((msrValue*2) % 8);
      return;
    }

    if ((msrValue>=0xc0010000) && (msrValue<=0xc0011fff))
    {
      msrValue=msrValue-0xc0010000;
      MSRBitmap[0x800+(msrValue*2)/8]|=2 << ((msrValue*2) % 8);
      return;
    }
  }
  else
  {
    if (msrValue<0xc0000000)
      MSRBitmap[2048+msrValue/8]|=1 << (msrValue % 8);
    else
    {
      msrValue=msrValue-0xc0000000;
      MSRBitmap[3072+msrValue/8]|=1 << (msrValue % 8);
    }
  }
}

void vmx_removeMSRWriteExit(DWORD msrValue)
{
  if (isAMD)
  {
    if (msrValue<=0x1fff)
    {
      MSRBitmap[(msrValue*2)/8]&=~(2 << ((msrValue*2) % 8));
      return;
    }

    if ((msrValue>=0xc0000000) && (msrValue<=0xc0001fff))
    {
      msrValue=msrValue-0xc0000000;
      MSRBitmap[0x800+(msrValue*2)/8]&=~(2 << ((msrValue*2) % 8));
      return;
    }

    if ((msrValue>=0xc0010000) && (msrValue<=0xc0011fff))
    {
      msrValue=msrValue-0xc0010000;
      MSRBitmap[0x800+(msrValue*2)/8]&=~(2 << ((msrValue*2) % 8));
      return;
    }
  }
  else
  {
    if (msrValue<0xc0000000)
      MSRBitmap[2048+msrValue/8]&=~(1 << (msrValue % 8));
    else
    {
      msrValue=msrValue-0xc0000000;
      MSRBitmap[3072+msrValue/8]&=~(1 << (msrValue % 8));
    }
  }
}

void vmx_enableTSCHook(pcpuinfo currentcpuinfo)
{
  if (isAMD)
  {
    currentcpuinfo->vmcb->InterceptRDTSC=1;
    currentcpuinfo->vmcb->InterceptRDTSCP=1;
  }
  else
  {
    if ((readMSR(IA32_VMX_PROCBASED_CTLS_MSR)>>32) & RDTSC_EXITING)
      vmwrite(vm_execution_controls_cpu, vmread(vm_execution_controls_cpu) | RDTSC_EXITING);

  }

  vmx_setMSRReadExit(IA32_TIME_STAMP_COUNTER);
  vmx_setMSRWriteExit(IA32_TIME_STAMP_COUNTER);
  vmx_setMSRWriteExit(IA32_TSC_ADJUST);

  TSCHooked=1;
}

void vmx_disableTSCHook(pcpuinfo currentcpuinfo)
{
  if (useSpeedhack==0)
  {
    if (isAMD)
    {
      currentcpuinfo->vmcb->InterceptRDTSC=0;
    }
    else
    {
      if ((readMSR(IA32_VMX_PROCBASED_CTLS_MSR)>>32) & RDTSC_EXITING)
        vmwrite(vm_execution_controls_cpu, vmread(vm_execution_controls_cpu) & (QWORD)~(QWORD)RDTSC_EXITING);
    }

    vmx_removeMSRReadExit(IA32_TIME_STAMP_COUNTER);
    vmx_removeMSRWriteExit(IA32_TIME_STAMP_COUNTER);
    vmx_removeMSRWriteExit(IA32_TSC_ADJUST);

    TSCHooked=0;
  }
}

void setupVMX(pcpuinfo currentcpuinfo)
{

  Access_Rights reg_csaccessrights,reg_traccessrights;

  reg_traccessrights.AccessRights=0;
  reg_traccessrights.Segment_type=11;
  reg_traccessrights.S=0;
  reg_traccessrights.DPL=0;
  reg_traccessrights.P=1;
  reg_traccessrights.G=0;
  reg_traccessrights.D_B=1;

  csEnter(&setupVMX_lock);

  char *eptcsname=malloc(32);
  snprintf(eptcsname,64,"EPTPML4CS %d", currentcpuinfo->cpunr);

  currentcpuinfo->EPTPML4CS.name=eptcsname;

  if (isAMD)
    return setupVMX_AMD(currentcpuinfo);

  if (MSRBitmap==NULL)
  {

    MSRBitmap=malloc(4096);
    zeromemory(MSRBitmap,4096);

    vmx_setMSRReadExit(0x174);
    vmx_setMSRReadExit(0x175);
    vmx_setMSRReadExit(0x176);

    vmx_setMSRWriteExit(0x174);
    vmx_setMSRWriteExit(0x175);
    vmx_setMSRWriteExit(0x176);

    vmx_setMSRReadExit(0xc0000080);
    vmx_setMSRWriteExit(0xc0000080);

    vmx_setMSRReadExit(IA32_FEATURE_CONTROL_MSR);
    vmx_setMSRWriteExit(IA32_FEATURE_CONTROL_MSR);

  }

  SetPageToWriteThrough((void *)MSRBitmap);

  if (IOBitmap==NULL)
  {

    sendstring("Allocating IOBitmap\n\r");
    IOBitmap=malloc(4096*2);
    zeromemory(IOBitmap,4096*2);

    #ifdef DEBUG
      #if (defined SERIALPORT) && (SERIALPORT != 0)

      #endif
    #endif
  }

  if (globals_have_been_configured==0)
  {
    sendstringf("before setupTSS8086. rsp=%6\n\r",getRSP());
    setupTSS8086();
    sendstringf("after setupTSS8086. rsp=%6\n\r",getRSP());

    sendstringf("Before configuring global VMX capability vars (%6)\n\r",getRSP());
    IA32_VMX_BASIC.IA32_VMX_BASIC=readMSR(0x480);
    IA32_VMX_PINBASED_CTLS=readMSR(IA32_VMX_PINBASED_CTLS_MSR);
    IA32_VMX_PROCBASED_CTLS=readMSR(0x482);
    if (IA32_VMX_PROCBASED_CTLS >> 63)
    {
      sendstringf("Has secondary procbased_ctls\n");
      IA32_VMX_SECONDARY_PROCBASED_CTLS=readMSR(0x48b);
    }
    else
    {
      sendstringf("Doesn't have secondary procbased_ctls\n");
    }

    IA32_VMX_EXIT_CTLS=readMSR(0x483);
    IA32_VMX_ENTRY_CTLS=readMSR(0x484);
    IA32_VMX_MISC.IA32_VMX_MISC=readMSR(0x485);
    sendstringf("After configuring global VMX capability vars (%6)\n\r",getRSP());

#ifdef DEBUG

    setCursorPos(0,1);
    zeromemory(&fakecom1,sizeof(fakecom1));
    fakecom1.Interrupt_Identification_Register=1;
#endif
  }

  sendstringf("after \"if (globals_have_been_configured==0)\" rsp=%6\n\r",getRSP());

  if (currentcpuinfo->cpunr==0)
  {
    displayline("IA32_VMX_BASIC=%6\n\r",IA32_VMX_BASIC.IA32_VMX_BASIC);
    displayline("IA32_VMX_PINBASED_CTLS=%6\n\r",IA32_VMX_PINBASED_CTLS);
    displayline("IA32_VMX_PROCBASED_CTLS=%6\n\r",IA32_VMX_PROCBASED_CTLS);
    displayline("IA32_VMX_SECONDARY_PROCBASED_CTLS=%6\n\r",IA32_VMX_SECONDARY_PROCBASED_CTLS);
    displayline("IA32_VMX_EXIT_CTLS=%6\n\r",IA32_VMX_EXIT_CTLS);
    displayline("IA32_VMX_ENTRY_CTLS=%6\n\r",IA32_VMX_ENTRY_CTLS);
    displayline("IA32_VMX_MISC=%6\n\r",IA32_VMX_MISC.IA32_VMX_MISC);
  }

  if ((IA32_VMX_PINBASED_CTLS >> 32) & (1<<1))
    IA32_VMX_PINBASED_CTLS|=(1<<1);

  if ((IA32_VMX_PINBASED_CTLS >> 32) & (1<<2))
    IA32_VMX_PINBASED_CTLS|=(1<<2);

  if ((IA32_VMX_PINBASED_CTLS >> 32) & (1<<4))
    IA32_VMX_PINBASED_CTLS|=(1<<4);

  if ((IA32_VMX_PROCBASED_CTLS >> 32) & (1<<1))
    IA32_VMX_PROCBASED_CTLS|=(1<<1);
  else
  {
    sendstring("Fail1\n");
  }

  if (((IA32_VMX_PROCBASED_CTLS >> 32) & (7<<4)) ==(7<<4))
      IA32_VMX_PROCBASED_CTLS|=(7<<4);
  else
  {
      sendstring("Fail2\n");
  }

  if ((IA32_VMX_PROCBASED_CTLS >> 32) & (1<<8))
    IA32_VMX_PROCBASED_CTLS|=(1<<8);
  else
  {
    sendstring("Fail3\n");
  }

  if (((IA32_VMX_PROCBASED_CTLS >> 32) & (0xf<<13)) ==(0xf<<13))
      IA32_VMX_PROCBASED_CTLS|=(0xf<<13);
  else
  {
    sendstring("Fail4\n");
  }

  if ((IA32_VMX_PROCBASED_CTLS >> 32) & (1<<26))
    IA32_VMX_PROCBASED_CTLS|=(1<<26);
  else
  {
    sendstring("Fail5\n");
  }

  sendstringf("%d: Initializing vmcs region for launch\n\r",currentcpuinfo->cpunr);

  vmwrite(vm_execution_controls_pin,(ULONG)IA32_VMX_PINBASED_CTLS);

  sendstringf("Set vm_execution_controls_pin to %8 (became %8)\n", (ULONG)IA32_VMX_PINBASED_CTLS, (DWORD)vmread(vm_execution_controls_pin));

#if DISPLAYDEBUG==1

  {
    ULONG usablepinbasedBits=(IA32_VMX_PINBASED_CTLS >> 32);
    if (usablepinbasedBits & ACTIVATE_VMX_PREEMPTION_TIMER)
    {
      displayline("Preemption is possible\n");
      vmwrite(vm_execution_controls_pin,vmread(vm_execution_controls_pin) | ACTIVATE_VMX_PREEMPTION_TIMER);
      vmwrite(vm_preemption_timer_value,10000);
    }
  }
#endif

  globalTSC=_rdtsc();

  vmwrite(vm_exception_bitmap,(UINT64)0xffff);

  vmwrite(0x4006,(UINT64)0);
  vmwrite(0x4008,(UINT64)0);
  vmwrite(0x400a,(UINT64)1);

  DWORD new_vm_exit_controls=(DWORD)IA32_VMX_EXIT_CTLS;

  sendstringf("IA32_VMX_EXIT_CTLS=%6\n", IA32_VMX_EXIT_CTLS);

  if ((IA32_VMX_EXIT_CTLS >> 32) & VMEXITC_HOST_ADDRESS_SPACE_SIZE)
    new_vm_exit_controls|=VMEXITC_HOST_ADDRESS_SPACE_SIZE;
  else
  {
    sendstring("<<<<<<WARNING: This system does not support HOST_ADDRESS_SPACE_SIZE>>>>>>\n");
  }

  if ((IA32_VMX_EXIT_CTLS >> 32) & VMEXITC_ACKNOWLEDGE_INTERRUPT_ON_EXIT)
    new_vm_exit_controls|=VMEXITC_ACKNOWLEDGE_INTERRUPT_ON_EXIT;
  else
  {
    sendstring("<<<<<<WARNING: This system does not support acknowledge interrupt on exit>>>>>>\n");
  }

  if ((IA32_VMX_EXIT_CTLS >> 32) & VMEXITC_SAVE_DEBUG_CONTROLS)
    new_vm_exit_controls|=VMEXITC_SAVE_DEBUG_CONTROLS;
  else
  {
    sendstring("<<<<<<WARNING: This system does not support saving debug controls>>>>>>\n");
  }

  vmwrite(vm_exit_controls, new_vm_exit_controls);

  sendstringf("Set vm_exit_controls to %8 (became %8)\n", new_vm_exit_controls, (DWORD)vmread(vm_exit_controls));

  vmwrite(0x400e,(UINT64)0);
  vmwrite(0x4010,(UINT64)0);

  vmwrite(0x4014,(UINT64)0);
  vmwrite(vm_entry_interruptioninfo,(UINT64)0);
  vmwrite(0x4018,(UINT64)0);
  vmwrite(0x401a,(UINT64)0);
  vmwrite(0x401c,(UINT64)0);

  vmwrite(vm_iobitmap_a,(UINT64)VirtualToPhysical((void *)IOBitmap));
  vmwrite(vm_iobitmap_b,(UINT64)VirtualToPhysical((void *)&(IOBitmap[4096])));
  vmwrite(0x2004,(UINT64)VirtualToPhysical((void *)MSRBitmap));
  vmwrite(0x2006,(UINT64)0xffffffffffffffff);
  vmwrite(0x2008,(UINT64)0xffffffffffffffff);
  vmwrite(0x200a,(UINT64)0xffffffffffffffff);
  vmwrite(0x200c,(UINT64)0xffffffffffffffff);
  vmwrite(0x2010,(UINT64)0);
  vmwrite(0x2012,(UINT64)0xffffffffffffffff);

  vmwrite(0x6000,(UINT64)0xffffffffffffffff);
  vmwrite(0x6002,(UINT64)0xffffffffffffffff);

  vmwrite(0x600a,(UINT64)0);
  vmwrite(0x600c,(UINT64)0);
  vmwrite(0x600e,(UINT64)0);

  {
    QWORD a=7,b=0,c=0,d=0;
    _cpuid(&a,&b,&c,&d);

    hasCETSupport=c & (1 << 7);
  }

  hasEPTsupport=setupEPT(currentcpuinfo);

  if (hasEPTsupport)
  {

    if ( ((IA32_VMX_SECONDARY_PROCBASED_CTLS>>32) & SPBEF_ENABLE_UNRESTRICTED ) &&
         ((readMSR(IA32_VMX_ENTRY_CTLS_MSR) >> 32) & VMENTRYC_LOAD_IA32_EFER) &&
         ((readMSR(IA32_VMX_EXIT_CTLS_MSR) >> 32) & VMEXITC_SAVE_IA32_EFER) &&
         ((readMSR(IA32_VMX_EXIT_CTLS_MSR) >> 32) & VMEXITC_LOAD_IA32_EFER) )
    {

      sendstringf("Enabling unrestricted guest\n");
      hasUnrestrictedSupport=1;
      vmwrite(vm_execution_controls_cpu_secondary, vmread(vm_execution_controls_cpu_secondary) | SPBEF_ENABLE_UNRESTRICTED);

      vmwrite(vm_entry_controls, vmread(vm_entry_controls) | VMENTRYC_LOAD_IA32_EFER );
      vmwrite(vm_exit_controls, vmread(vm_exit_controls) | VMEXITC_SAVE_IA32_EFER );
      vmwrite(vm_exit_controls, vmread(vm_exit_controls) | VMEXITC_LOAD_IA32_EFER );

      vmwrite(vm_host_IA32_EFER, readMSR(EFER_MSR));

      MSRBitmap[1024+0x80/8]&=~(1 << (0x80 % 8));
      MSRBitmap[3072+0x80/8]&=~(1 << (0x80 % 8));

      vmwrite(vm_cr0_guest_host_mask,(UINT64)0xFFFFFFFF7FFFFFFEULL);
      vmwrite(vm_cr4_guest_host_mask,(UINT64)IA32_VMX_CR4_FIXED0);

#ifdef USENMIFORWAIT
      vmwrite(vm_exception_bitmap,  (1<<1) | (1<<2) | (1<<3));
#else
      vmwrite(vm_exception_bitmap,  (1<<1) | (1<<3));
#endif

      sendstringf("Checking if it supports CR3 access exit to 0\n");

      QWORD procbasedcapabilities;
      if (readMSR(IA32_VMX_BASIC_MSR) & ((QWORD)1<<55))
        procbasedcapabilities=readMSR(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);
      else
        procbasedcapabilities=readMSR(IA32_VMX_PROCBASED_CTLS_MSR);

      sendstringf("procbasedcapabilities=%6\n", procbasedcapabilities);

      canToggleCR3Exit=((procbasedcapabilities & (PPBEF_CR3LOAD_EXITING | PPBEF_CR3STORE_EXITING))==0);

      sendstringf("canToggleCR3Exit=%d\n", canToggleCR3Exit);

      if (canToggleCR3Exit)
        IA32_VMX_PROCBASED_CTLS = IA32_VMX_PROCBASED_CTLS & (QWORD)(~(PPBEF_CR3LOAD_EXITING | PPBEF_CR3STORE_EXITING));

      if ((IA32_VMX_SECONDARY_PROCBASED_CTLS>>32) & SPBEF_ENABLE_VMCS_SHADOWING )
      {
        sendstringf("Supports VMCS shadowing\n");

        hasVMCSShadowingSupport=1;

        if (VMREADBitmap==NULL)
        {
          VMREADBitmap=malloc2(4096);
          VMWRITEBitmap=malloc2(4096);

          zeromemory(VMREADBitmap, 4096);
          zeromemory(VMWRITEBitmap, 4096);

        }

        vmwrite(vm_vmread_bitmap_address, VirtualToPhysical(VMREADBitmap));
        vmwrite(vm_vmwrite_bitmap_address, VirtualToPhysical(VMWRITEBitmap));

      }
    }
    else
    {
      sendstringf("Unrestricted guest is not supported\n");
      hasUnrestrictedSupport=0;
    }
  }

#ifdef USENMIFORWAIT
  canExitOnNMI=vmx_enablePinBasedFeature(PINBEF_NMI_EXITING);
#endif

  if (loadedOS)
  {
    sendstring("loadedos is set\n");
    sendstringf("APStartsInSIPI=%d\n", APStartsInSIPI);
    sendstringf("currentcpuinfo->cpunr=%d\n", currentcpuinfo->cpunr);

    if ((APStartsInSIPI==0) || (currentcpuinfo->cpunr==0))
    {

      POriginalState originalstate=(POriginalState)mapPhysicalMemory(loadedOS,sizeof(OriginalState));
      PGDT_ENTRY gdt=NULL,ldt=NULL;
      ULONG ldtselector=originalstate->ldt;
      int notpaged;
      RFLAGS rflags;

      sendstringf("Setting up guest based on loadedOS settings\n");

      sendstringf("originalstate->cpucount=%d\n",originalstate->cpucount);
      sendstringf("originalstate->cr0=%6\n",originalstate->cr0);
      sendstringf("originalstate->cr2=%6\n",originalstate->cr2);
      sendstringf("originalstate->cr3=%6\n",originalstate->cr3);
      sendstringf("originalstate->cr4=%6\n",originalstate->cr4);
      sendstringf("originalstate->rip=%6\n",originalstate->rip);
      sendstringf("originalstate->cs=%x\n",originalstate->cs);
      sendstringf("originalstate->ss=%x\n",originalstate->ss);
      sendstringf("originalstate->ds=%x\n",originalstate->ds);
      sendstringf("originalstate->es=%x\n",originalstate->es);
      sendstringf("originalstate->fs=%x\n",originalstate->fs);
      sendstringf("originalstate->gs=%x\n",originalstate->gs);
      sendstringf("originalstate->ldt=%x\n",originalstate->ldt);
      sendstringf("originalstate->tr=%x\n",originalstate->tr);

      sendstringf("originalstate->dr7=%6\n",originalstate->dr7);
      sendstringf("originalstate->gdtbase=%6\n",originalstate->gdtbase);
      sendstringf("originalstate->gdtlimit=%x\n",originalstate->gdtlimit);
      sendstringf("originalstate->idtbase=%6\n",originalstate->idtbase);
      sendstringf("originalstate->idtlimit=%x\n",originalstate->idtlimit);
      sendstringf("originalstate->originalLME=%x\n",originalstate->originalLME);
      sendstringf("originalstate->rflags=%6\n",originalstate->rflags);

      sendstringf("originalstate->rax=%6\n",originalstate->rax);
      sendstringf("originalstate->rbx=%6\n",originalstate->rbx);
      sendstringf("originalstate->rcx=%6\n",originalstate->rcx);
      sendstringf("originalstate->rdx=%6\n",originalstate->rdx);
      sendstringf("originalstate->rsi=%6\n",originalstate->rsi);
      sendstringf("originalstate->rdi=%6\n",originalstate->rdi);
      sendstringf("originalstate->rbp=%6\n",originalstate->rbp);
      sendstringf("originalstate->rsp=%6\n",originalstate->rsp);
      sendstringf("originalstate->r8=%6\n",originalstate->r8);
      sendstringf("originalstate->r9=%6\n",originalstate->r9);
      sendstringf("originalstate->r10=%6\n",originalstate->r10);
      sendstringf("originalstate->r11=%6\n",originalstate->r11);
      sendstringf("originalstate->r12=%6\n",originalstate->r12);
      sendstringf("originalstate->r13=%6\n",originalstate->r13);
      sendstringf("originalstate->r14=%6\n",originalstate->r14);
      sendstringf("originalstate->r15=%6\n",originalstate->r15);

      currentcpuinfo->guestCR3=originalstate->cr3;
      currentcpuinfo->guestCR0=originalstate->cr0;

      rflags.value=originalstate->rflags;
      currentcpuinfo->hasIF=rflags.IF;

      DWORD new_vm_execution_controls_cpu=vmread(vm_execution_controls_cpu) | (DWORD)IA32_VMX_PROCBASED_CTLS | USE_IO_BITMAPS | USE_MSR_BITMAPS;

      if (IA32_VMX_PROCBASED_CTLS & INVLPG_EXITING)
        new_vm_execution_controls_cpu|=INVLPG_EXITING;

      if ((IA32_VMX_PROCBASED_CTLS >> 32) & (1<<31))
        new_vm_execution_controls_cpu=new_vm_execution_controls_cpu | (1<<31);

      vmwrite(vm_execution_controls_cpu, new_vm_execution_controls_cpu);
      sendstringf("Set vm_execution_controls_cpu to %8 (became %8)\n", new_vm_execution_controls_cpu, (DWORD)vmread(vm_execution_controls_cpu));

      if ((new_vm_execution_controls_cpu >> 31) & 1)
      {

        QWORD secondarycpu=vmread(vm_execution_controls_cpu_secondary);

        if ((IA32_VMX_SECONDARY_PROCBASED_CTLS >> 32) & SPBEF_ENABLE_RDTSCP)
        {
          sendstringf("Enabling rdtscp\n");
          secondarycpu|=SPBEF_ENABLE_RDTSCP;
        }

        if ((IA32_VMX_SECONDARY_PROCBASED_CTLS >> 32) & SPBEF_ENABLE_XSAVES)
        {
          sendstringf("Enabling xsaves\n");
          secondarycpu|=SPBEF_ENABLE_XSAVES;
        }

        if ((IA32_VMX_SECONDARY_PROCBASED_CTLS >> 32) & SPBEF_ENABLE_INVPCID)
        {
          sendstringf("Enabling INVPCID\n");
          secondarycpu|=SPBEF_ENABLE_INVPCID;
        }

        vmwrite(vm_execution_controls_cpu_secondary, secondarycpu);

      }

      currentcpuinfo->efer=originalstate->originalEFER;

      if (hasUnrestrictedSupport)
        vmwrite(vm_guest_IA32_EFER, originalstate->originalEFER);

      DWORD new_vm_entry_controls=vmread(vm_entry_controls);

      if (originalstate->originalLME)
      {
        sendstringf("guest is 64bit\n");
        currentcpuinfo->efer|=(1<<8) | (1<<10);
        new_vm_entry_controls=new_vm_entry_controls | (DWORD)IA32_VMX_ENTRY_CTLS | VMENTRYC_RESTORE_DEBUG_CONTROLS | VMENTRYC_IA32E_MODE_GUEST;
      }
      else
        new_vm_entry_controls=new_vm_entry_controls | (DWORD)IA32_VMX_ENTRY_CTLS | VMENTRYC_RESTORE_DEBUG_CONTROLS;

      vmwrite(vm_entry_controls, new_vm_entry_controls);
      sendstringf("Set vm_entry_controls to %8 (became %8)\n", new_vm_entry_controls, (DWORD)vmread(vm_entry_controls));

      if (hasUnrestrictedSupport)
      {

        vmwrite(vm_cr0_read_shadow,originalstate->cr0 & vmread(vm_cr0_guest_host_mask));
        vmwrite(vm_cr4_read_shadow,originalstate->cr4 & vmread(vm_cr4_guest_host_mask));
      }
      else
      {
        vmwrite(vm_cr0_read_shadow,originalstate->cr0);
        vmwrite(vm_cr4_read_shadow,originalstate->cr4);
      }
      vmwrite(vm_cr3_targetvalue0,0xffffffffffffffffULL);

      currentcpuinfo->guestCR0=originalstate->cr0;
      currentcpuinfo->guestCR3=originalstate->cr3;

      vmwrite(vm_guest_cr0, (ULONG)IA32_VMX_CR0_FIXED0 | originalstate->cr0);
      vmwrite(vm_guest_cr3, originalstate->cr3);
      vmwrite(vm_guest_cr4, (ULONG)IA32_VMX_CR4_FIXED0 | originalstate->cr4);

      if (vmread(vm_guest_cr0)!=((ULONG)IA32_VMX_CR0_FIXED0 | originalstate->cr0))
      {
        sendstringf("vm_guest_cr0 = %6\n", vmread(vm_guest_cr0));
        while (1);
      }

      vmwrite(vm_guest_gdtr_base, (UINT64)originalstate->gdtbase);
      vmwrite(vm_guest_gdt_limit, (UINT64)originalstate->gdtlimit);
      vmwrite(vm_guest_idtr_base, (UINT64)originalstate->idtbase);
      vmwrite(vm_guest_idt_limit, (UINT64)originalstate->idtlimit);

      gdt=(PGDT_ENTRY)(UINT64)mapPhysicalMemory(getPhysicalAddressVM(currentcpuinfo, originalstate->gdtbase, &notpaged), originalstate->gdtlimit);

      ULONG ldtlimit;
      if ((UINT64)originalstate->ldt)
      {
        UINT64 ldtbase;

        sendstring("ldt is valid, so getting the information\n\r");

        ldtbase=(gdt[(ldtselector >> 3)].Base24_31 << 24) + gdt[(ldtselector >> 3)].Base0_23;
        ldtlimit=(gdt[(ldtselector >> 3)].Limit16_19 << 16) + gdt[(ldtselector >> 3)].Limit0_15;
        ldt=(PGDT_ENTRY)(UINT64)mapPhysicalMemory(getPhysicalAddressVM(currentcpuinfo, ldtbase, &notpaged), ldtlimit);
      }

      vmwrite(vm_guest_es,(UINT64)originalstate->es);
      vmwrite(vm_guest_es_access_rights,originalstate->es_AccessRights);
      vmwrite(vm_guest_es_limit,originalstate->es_Limit);

      vmwrite(vm_guest_cs,(UINT64)originalstate->cs);
      vmwrite(vm_guest_cs_access_rights,originalstate->cs_AccessRights);
      vmwrite(vm_guest_cs_limit,originalstate->cs_Limit);

      vmwrite(vm_guest_ss,(UINT64)originalstate->ss);
      vmwrite(vm_guest_ss_access_rights,originalstate->ss_AccessRights);
      vmwrite(vm_guest_ss_limit,originalstate->ss_Limit);

      vmwrite(vm_guest_ds,(UINT64)originalstate->ds);
      vmwrite(vm_guest_ds_access_rights,originalstate->ds_AccessRights);
      vmwrite(vm_guest_ds_limit,originalstate->ds_Limit);

      vmwrite(vm_guest_fs,(UINT64)originalstate->fs);
      vmwrite(vm_guest_fs_access_rights,originalstate->fs_AccessRights);
      vmwrite(vm_guest_fs_limit,originalstate->fs_Limit);

      vmwrite(vm_guest_gs,(UINT64)originalstate->gs);
      vmwrite(vm_guest_gs_access_rights,originalstate->gs_AccessRights);
      vmwrite(vm_guest_gs_limit,originalstate->gs_Limit);

      vmwrite(vm_guest_ldtr,(UINT64)originalstate->ldt);
      vmwrite(vm_guest_tr,(UINT64)originalstate->tr);

      if (originalstate->originalLME)
      {
        sendstringf("64-bit\n");
        vmwrite(vm_guest_cs_base,0);
        vmwrite(vm_guest_ss_base,0);
        vmwrite(vm_guest_ds_base,0);
        vmwrite(vm_guest_es_base,0);
        vmwrite(vm_guest_fs_base,originalstate->fsbase);
        vmwrite(vm_guest_gs_base,originalstate->gsbase);

        sendstringf("originalstate->fsbase=%6\n", originalstate->fsbase);
        sendstringf("originalstate->gsbase=%6\n", originalstate->gsbase);
        sendstringf("Have set fs base to %6 and gs base to %6\n",vmread(vm_guest_fs_base),vmread(vm_guest_gs_base));

        vmwrite(vm_guest_tr_base,getSegmentBaseEx(gdt,ldt,originalstate->tr, 1));
      }
      else
      {
        sendstringf("32-bit\n");
        vmwrite(vm_guest_cs_base,getSegmentBase(gdt,ldt,originalstate->cs));
        vmwrite(vm_guest_ss_base,getSegmentBase(gdt,ldt,originalstate->ss));
        vmwrite(vm_guest_ds_base,getSegmentBase(gdt,ldt,originalstate->ds));
        vmwrite(vm_guest_es_base,getSegmentBase(gdt,ldt,originalstate->es));
        vmwrite(vm_guest_fs_base,getSegmentBase(gdt,ldt,originalstate->fs));
        vmwrite(vm_guest_gs_base,getSegmentBase(gdt,ldt,originalstate->gs));
        vmwrite(vm_guest_tr_base,getSegmentBase(gdt,ldt,originalstate->tr));
      }

      vmwrite(vm_guest_ldtr_limit,getSegmentLimit(gdt,ldt,originalstate->ldt));
      if (originalstate->tr==0)
        vmwrite(vm_guest_tr_limit,0xffff);
      else
        vmwrite(vm_guest_tr_limit,getSegmentLimit(gdt,ldt,originalstate->tr));

      vmwrite(vm_guest_ldtr_base,getSegmentBase(gdt,ldt,originalstate->ldt));
      vmwrite(vm_guest_ldtr_access_rights,getSegmentAccessRights(gdt,ldt,originalstate->ldt));

      if (originalstate->tr)
        vmwrite(vm_guest_tr_access_rights,getSegmentAccessRights(gdt,ldt,originalstate->tr));
      else
        vmwrite(vm_guest_tr_access_rights,0x8b);

      vmwrite(vm_guest_IA32_SYSENTER_CS,(UINT64)readMSR(IA32_SYSENTER_CS_MSR));
      vmwrite(vm_guest_IA32_SYSENTER_ESP,(UINT64)readMSR(IA32_SYSENTER_ESP_MSR));
      vmwrite(vm_guest_IA32_SYSENTER_EIP,(UINT64)readMSR(IA32_SYSENTER_EIP_MSR));

      currentcpuinfo->actual_sysenter_CS=vmread(vm_guest_IA32_SYSENTER_CS);
      currentcpuinfo->actual_sysenter_ESP=vmread(vm_guest_IA32_SYSENTER_ESP);
      currentcpuinfo->actual_sysenter_EIP=vmread(vm_guest_IA32_SYSENTER_EIP);

      vmwrite(vm_guest_dr7,(UINT64)originalstate->dr7);
      vmwrite(vm_guest_activity_state,(UINT64)0);
      if (originalstate->originalLME)
      {
        vmwrite(vm_guest_rsp,(UINT64)originalstate->rsp);
        vmwrite(vm_guest_rip,(UINT64)originalstate->rip);
      }
      else
      {

        vmwrite(vm_guest_rsp,(ULONG)originalstate->rsp);
        vmwrite(vm_guest_rip,(ULONG)originalstate->rip);
      }
      vmwrite(vm_guest_rflags,(UINT64)(UINT64)originalstate->rflags);

      if (gdt)
        unmapPhysicalMemory(gdt, originalstate->gdtlimit);

      if (ldt)
        unmapPhysicalMemory(ldt, ldtlimit);

      if (originalstate)
        unmapPhysicalMemory(originalstate, sizeof(OriginalState));
    }
    else
    {
      setup8086WaitForSIPI(currentcpuinfo, 1);
    }

  }
  else
  {
    sendstringf("booted of a disk, without UEFI, load os manually");

    if (currentcpuinfo->cpunr==0)
    {

      sendstringf("manually load for cpu 0\n");

      reg_csaccessrights.AccessRights=0;
      reg_csaccessrights.Segment_type=11;
      reg_csaccessrights.S=1;
      reg_csaccessrights.DPL=0;
      reg_csaccessrights.P=1;
      reg_csaccessrights.L=1;
      reg_csaccessrights.G=0;
      reg_csaccessrights.D_B=0;

      currentcpuinfo->guestCR3=getCR3();
      currentcpuinfo->guestCR0=getCR0();
      currentcpuinfo->hasIF=0;

      DWORD new_vm_execution_controls_cpu=vmread(vm_execution_controls_cpu) | (DWORD)IA32_VMX_PROCBASED_CTLS;

      if ((IA32_VMX_PROCBASED_CTLS >> 32) & HLT_EXITING)
        new_vm_execution_controls_cpu|=HLT_EXITING;
      else
      {
        sendstring("<<<<<<WARNING: This system does not support HLT_EXITING>>>>>>\n");
      }

      if (IA32_VMX_PROCBASED_CTLS & INVLPG_EXITING)
        new_vm_execution_controls_cpu|=INVLPG_EXITING;

      if ((IA32_VMX_PROCBASED_CTLS >> 32) & USE_MSR_BITMAPS)
        new_vm_execution_controls_cpu|=USE_MSR_BITMAPS;
      else
      {
        sendstring("<<<<<<WARNING: This system does not support USE_MSR_BITMAPS>>>>>>\n");
      }

      if ((IA32_VMX_PROCBASED_CTLS >> 32) & (1<<31))
        new_vm_execution_controls_cpu=new_vm_execution_controls_cpu | (1<<31);

      vmwrite(vm_execution_controls_cpu, new_vm_execution_controls_cpu);
      sendstringf("Set vm_execution_controls_cpu to %8 (became %8)\n", new_vm_execution_controls_cpu, (DWORD)vmread(vm_execution_controls_cpu));

      if ((new_vm_execution_controls_cpu >> 31) & 1)
      {

        QWORD secondarycpu=vmread(vm_execution_controls_cpu_secondary);

        if ((IA32_VMX_SECONDARY_PROCBASED_CTLS >> 32) & SPBEF_ENABLE_RDTSCP)
        {
          sendstringf("Enabling rdtscp\n");
          secondarycpu|=SPBEF_ENABLE_RDTSCP;
        }

        if ((IA32_VMX_SECONDARY_PROCBASED_CTLS >> 32) & SPBEF_ENABLE_XSAVES)
        {
          sendstringf("Enabling xsaves\n");
          secondarycpu|=SPBEF_ENABLE_XSAVES;
        }

        if ((IA32_VMX_SECONDARY_PROCBASED_CTLS >> 32) & SPBEF_ENABLE_INVPCID)
        {
          sendstringf("Enabling INVPCID\n");
          secondarycpu|=SPBEF_ENABLE_INVPCID;
        }

        vmwrite(vm_execution_controls_cpu_secondary, secondarycpu);

      }

      DWORD new_vm_entry_controls=vmread(vm_entry_controls) |  (DWORD)IA32_VMX_ENTRY_CTLS;

      if ((IA32_VMX_ENTRY_CTLS >> 32) & VMENTRYC_IA32E_MODE_GUEST)
        new_vm_entry_controls|=VMENTRYC_IA32E_MODE_GUEST;
      else
      {
        sendstring("<<<<<<WARNING: This system does not support IA32E_MODE_GUEST>>>>>>\n");
      }

      if ((IA32_VMX_ENTRY_CTLS >> 32) & VMENTRYC_RESTORE_DEBUG_CONTROLS)
        new_vm_entry_controls|=VMENTRYC_RESTORE_DEBUG_CONTROLS;
      else
      {
        sendstring("<<<<<<WARNING: This system does not support the RESTORE_DEBUG_CONTROLS vm_entry control option>>>>>>\n");
      }

      vmwrite(vm_entry_controls,new_vm_entry_controls);
      sendstringf("Set vm_entry_controls to %8 (became %8)\n", new_vm_entry_controls, (DWORD)vmread(vm_entry_controls));

      vmwrite(vm_cr0_read_shadow,(UINT64)getCR0());
      vmwrite(vm_cr4_read_shadow,(UINT64)getCR4());
      vmwrite(vm_cr3_targetvalue0,(UINT64)getCR3());

      vmwrite(vm_guest_gdtr_base,(UINT64)getGDTbase());
      vmwrite(vm_guest_idtr_base,(UINT64)getIDTbase());
      vmwrite(vm_guest_gdt_limit,(UINT64)88);
      vmwrite(vm_guest_idt_limit,(UINT64)8*256);

      vmwrite(vm_guest_cr0,getCR0());
      vmwrite(vm_guest_cr3,getCR3());
      vmwrite(vm_guest_cr4,getCR4() |(UINT64)IA32_VMX_CR4_FIXED0 | 1 | (1 << 4) | ( 1 << 5) | (1<<0));

      vmwrite(vm_guest_es,(UINT64)8);
      vmwrite(vm_guest_cs,(UINT64)80);
      vmwrite(vm_guest_ss,(UINT64)8);
      vmwrite(vm_guest_ds,(UINT64)8);
      vmwrite(vm_guest_fs,(UINT64)8);
      vmwrite(vm_guest_gs,(UINT64)8);
      vmwrite(vm_guest_ldtr,(UINT64)0);
      vmwrite(vm_guest_tr,(UINT64)64);

      vmwrite(vm_guest_es_limit,(UINT64)0);
      vmwrite(vm_guest_cs_limit,(UINT64)0);
      vmwrite(vm_guest_ss_limit,(UINT64)0);
      vmwrite(vm_guest_ds_limit,(UINT64)0);
      vmwrite(vm_guest_fs_limit,(UINT64)0);
      vmwrite(vm_guest_gs_limit,(UINT64)0);
      vmwrite(vm_guest_ldtr_limit,(UINT64)0);
      vmwrite(vm_guest_tr_limit,(UINT64)sizeof(TSS)+32+8192+1);

      vmwrite(vm_guest_es_base,(UINT64)0);
      vmwrite(vm_guest_cs_base,(UINT64)0);
      vmwrite(vm_guest_ss_base,(UINT64)0);
      vmwrite(vm_guest_ds_base,(UINT64)0);
      vmwrite(vm_guest_fs_base,(UINT64)0);
      vmwrite(vm_guest_gs_base,(UINT64)0);
      vmwrite(vm_guest_ldtr_base,(UINT64)0);
      vmwrite(vm_guest_tr_base,(UINT64)mainTSS);

      vmwrite(vm_guest_es_access_rights,(UINT64)(1<<16));
      vmwrite(vm_guest_cs_access_rights,(UINT64)reg_csaccessrights.AccessRights);
      vmwrite(vm_guest_ss_access_rights,(UINT64)(1<<16));
      vmwrite(vm_guest_ds_access_rights,(UINT64)(1<<16));
      vmwrite(vm_guest_fs_access_rights,(UINT64)(1<<16));
      vmwrite(vm_guest_gs_access_rights,(UINT64)(1<<16));
      vmwrite(vm_guest_ldtr_access_rights,(UINT64)(1<<16));
      vmwrite(vm_guest_tr_access_rights,(UINT64)reg_traccessrights.AccessRights);

      vmwrite(vm_guest_IA32_SYSENTER_CS,(UINT64)0);
      vmwrite(vm_guest_IA32_SYSENTER_ESP,(UINT64)0);
      vmwrite(vm_guest_IA32_SYSENTER_EIP,(UINT64)0);

      vmwrite(vm_guest_dr7,(UINT64)0x400);

      vmwrite(vm_guest_activity_state,(UINT64)0);

      vmwrite(vm_guest_rsp,((UINT64)malloc(4096))+0x1000-0x28);
      vmwrite(vm_guest_rip,(UINT64)reboot);
      vmwrite(vm_guest_rflags,(UINT64)getRFLAGS());

      if (hasUnrestrictedSupport)
      {
        vmwrite(vm_guest_IA32_EFER, readMSR(EFER_MSR));
        vmwrite(vm_guest_tr,0);
        vmwrite(vm_guest_tr_limit,0);
        vmwrite(vm_guest_tr_base, 0);
        vmwrite(vm_guest_tr_access_rights,0x8b);

        QWORD size=(QWORD)&realmode_inthooks_end-(QWORD)&realmode_inthooks;
        if (size<=0x800)
          size=0x800;
        else
        {
          size+=0x800;
          size=size & 0xFFFFFFFFFFFFF800ULL;
        }

        QWORD hookaddress;
        int i,lowregion=-1;
        for (i=0; fakeARD[i].Type != 255; i++)
        {
          if ((fakeARD[i].BaseAddrHigh==0) && (fakeARD[i].BaseAddrLow<(0x100000-size)) && (fakeARD[i].Type==1))
          {
            lowregion=i;
          }
        }

        if (lowregion==-1)
        {
          nosendchar[getAPICID()]=0;
          sendstringf("No low region:\n");
          sendARD();
          ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);
          while (1) outportb(0x80,0xde);
        }

        hookaddress=fakeARD[lowregion].BaseAddrLow+((QWORD)(fakeARD[lowregion].LengthHigh)<<32)+fakeARD[lowregion].LengthLow;
        if (hookaddress>=0x100000)
        {

          fakeARD_InsertRange(0x98000,size, 2);
        }
        else
        {
          hookaddress=hookaddress-0x800;
          fakeARD_InsertRange(hookaddress,size, 2);
        }

        RMIDT *idt=mapPhysicalMemory(0, 0x3ff);

        realmode_inthook_original12=*(DWORD*)&idt[0x12];
        realmode_inthook_original15=*(DWORD*)&idt[0x15];

        realmode_inthook_conventional_memsize=fakeARD_getConventionalMemory() / 1024;

        void *mappedhookaddress=mapPhysicalMemory(hookaddress, size);

        copymem(mappedhookaddress, realmode_inthooks, (QWORD)realmode_inthooks_end-(QWORD)realmode_inthooks);
        unmapPhysicalMemory(mappedhookaddress,size);

        QWORD new12=hookaddress+(QWORD)realmode_inthook_new12-(QWORD)realmode_inthooks;
        QWORD new15=hookaddress+(QWORD)realmode_inthook_new15-(QWORD)realmode_inthooks;

        realmode_inthook_calladdressPA=hookaddress+(QWORD)realmode_inthook_calladdress-(QWORD)realmode_inthooks;

        sendstringf("new12=%8\n", new12);
        sendstringf("new15=%6\n", new15);

        idt[0x12].segment=((new12 & 0xfff00) >> 4);
        idt[0x12].offset=(new12 & 0x000ff);

        idt[0x15].segment=((new15 & 0xfff00) >> 4);
        idt[0x15].offset=(new15 & 0x000ff);

        unmapPhysicalMemory(idt, 0x3ff);

        QWORD Real_IA32_VMX_PROCBASED_CTLS=IA32_VMX_PROCBASED_CTLS;

        if (IA32_VMX_BASIC.default1canbe0)
          Real_IA32_VMX_PROCBASED_CTLS=readMSR(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

        if ((Real_IA32_VMX_PROCBASED_CTLS & HLT_EXITING)==0)
        {
          sendstring("Disable HLT exiting\n");
          vmwrite(vm_execution_controls_cpu, vmread(vm_execution_controls_cpu) & (~HLT_EXITING));
        }
      }
    }
    else
    {

      setup8086WaitForSIPI(currentcpuinfo, 1);
    }
  }

  vmwrite(0x2800,(UINT64)0xffffffffffffffff);
  vmwrite(0x2802,(UINT64)0);

  vmwrite(vm_guest_interruptability_state,(UINT64)0);

  vmwrite(0x4828,(UINT64)0);

  vmwrite(0x6822,(UINT64)0);

  sendstringf("Guest is setup to start at %x:%6\n",vmread(vm_guest_cs),vmread(vm_guest_rip));
  sendstring("host setup\n\r");
  vmwrite(vm_host_es,(UINT64)8);
  vmwrite(vm_host_cs,(UINT64)80);
  vmwrite(vm_host_ss,(UINT64)8);
  vmwrite(vm_host_ds,(UINT64)8);
  vmwrite(vm_host_fs,(UINT64)8);
  vmwrite(vm_host_gs,(UINT64)8);
  vmwrite(vm_host_tr,(UINT64)96);

  vmwrite(vm_host_IA32_SYSENTER_CS,(UINT64)readMSR(IA32_SYSENTER_CS_MSR));
  vmwrite(vm_host_IA32_SYSENTER_ESP,(UINT64)readMSR(IA32_SYSENTER_ESP_MSR));
  vmwrite(vm_host_IA32_SYSENTER_EIP,(UINT64)readMSR(IA32_SYSENTER_EIP_MSR));

  vmwrite(vm_host_cr0,(UINT64)getCR0());
  vmwrite(vm_host_cr3,(UINT64)getCR3());
  vmwrite(vm_host_cr4,(UINT64)getCR4());
  vmwrite(vm_host_fs_base,(UINT64)readMSR(0xc0000100));
  vmwrite(vm_host_gs_base,(UINT64)readMSR(0xc0000101));
  vmwrite(vm_host_tr_base,(UINT64)ownTSS);
  vmwrite(vm_host_gdtr_base,(UINT64)getGDTbase());
  vmwrite(vm_host_idtr_base,(UINT64)getIDTbase());

  sendstring("Finished configuring\n\r");

  globals_have_been_configured=1;
  currentcpuinfo->vmxsetup=1;

  csLeave(&setupVMX_lock);
}
