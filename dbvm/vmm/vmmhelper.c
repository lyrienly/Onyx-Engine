#include "common.h"
#include "vmmhelper.h"
#include "main.h"
#include "neward.h"
#include "mm.h"

#include "vmcall.h"
#include "vmpaging.h"
#include "vmeventhandler.h"
#include "vmreadwrite.h"
#include "msrnames.h"
#include "vmxcontrolstructures.h"

#include "distorm.h"
#include "realmodeemu.h"
#include "multicore.h"
#include "offloados.h"

#include "vmeventhandler_amd.h"
#include "vmxsetup.h"
#include "epthandler.h"
#include "exports.h"
#include "luahandler.h"

#include "displaydebug.h"
#include "interrupthandler.h"
#include "test.h"

#include "apic.h"

#ifndef DEBUG
#define sendstringf(s,x...)
#define sendstring(s)
#endif

DBVM_PLUGIN_EXIT_PRE *dbvm_plugin_exit_pre;
DBVM_PLUGIN_EXIT_POST *dbvm_plugin_exit_post;

int ISPAGING(pcpuinfo currentcpuinfo)
{
  if (isAMD)
  {
    regCR0 cr0;
    cr0.CR0=currentcpuinfo->vmcb->CR0;
    return cr0.PG==1;
  }
  else
  {
    if (hasUnrestrictedSupport)
      return (vmread(vm_guest_cr0) & CR0_PG)==0;
    else
      return (vmread(vm_cr0_read_shadow) & CR0_PG)==1;
  }
}

int ISREALMODE(pcpuinfo currentcpuinfo)
{
  if (isAMD)
  {
    regCR0 cr0;
    cr0.CR0=currentcpuinfo->vmcb->CR0;
    return cr0.PE==0;
  }
  else
  {
    if (hasUnrestrictedSupport)
      return (vmread(vm_guest_cr0) & 1)==0;
    else
      return (vmread(vm_cr0_read_shadow) & 1)==0;
  }
}

int IS64BITPAGING(pcpuinfo currentcpuinfo)
{
  if (isAMD)
  {
    return (currentcpuinfo->vmcb->EFER & (1<<10))==(1<<10);
  }
  else
    return ((vmread(vm_entry_controls) & VMENTRYC_IA32E_MODE_GUEST) != 0);
}

int IS64BITCODE(pcpuinfo currentcpuinfo)
{
  if (isAMD)
  {
    Segment_Attribs cs;
    cs.SegmentAttrib=currentcpuinfo->vmcb->cs_attrib;
    return cs.L;
  }
  else
    return IS64BITPAGING(currentcpuinfo) && ((vmread(vm_guest_cs_access_rights) >> 13) & 1);
}

int isDebugFault(QWORD dr6, QWORD dr7)

{
  regDR6 d6;
  regDR7 d7;

  d6.DR6=dr6;
  d7.DR7=dr7;

  if ((d6.BD) && (d7.GD))
    return 1;
  else
    return 0;

}

char * getVMExitReassonString(void)
{
  int i=vmread(vm_exit_reason) & 0x7fffffff;
  switch (i)
  {
	  case 0: return "Exception or NMI";
	  case 1: return "External interrupt";
	  case 2: return "Triple fault";
	  case 3: return "INIT Signal";
	  case 4: return "Start-up IPI (SIPI)";
	  case 5: return "SMI interrupt";
	  case 6: return "Other SMI";
	  case 7: return "Interrupt window";
	  case 8: return "NMI window";
	  case 9: return "Task switch";
	  case 10: return "CPUID";
	  case 14: return "INVLPG";
	  case 16: return "RDTSC";
	  case 17: return "VMREAD";
	  case 18: return "VMCALL";
	  case 19: return "VMCLEAR";
	  case 20: return "VMLAUNCH";
	  case 21: return "VMPTRLD";
	  case 23: return "VMREAD";
    case 24: return "VMRESUME";
	  case 25: return "VMWRITE";
	  case vm_exit_vmxoff: return "VMXOFF";
	  case vm_exit_vmxon: return "VMXON";
	  case 28: return "Controlregister access";
	  case vm_exit_io_access: return "IO Access";

	  case 31: return "RDMSR";
	  case 32: return "WRMSR";
	  case 33: return "Invalid guest state";
	  case 36: return "MWAIT";
	  case 37: return "Monitor trap flag";
	  case 39: return "MONITOR";
	  case 44: return "APIC Access";
	  case vm_exit_ept_violation: return "EPT Violation";
	  case vm_exit_ept_misconfiguration: return "EPT Misconfiguration";
	  case 50: return "INVEPT";
	  case 51: return "RDTSCP";
	  case 52: return "Preemption timer";
	  case 53: return "INVVPID";
	  case 55: return "XSETBV";
	  default :return "NYI";
  }
}

char * getVMInstructionErrorString(void)

{
  int i=vmread(0x4400) & 0x1f;
  char *result;
  switch (i)
  {
    case 0: result="No error"; break;
    case 1: result="VMCALL executed in VMX root operation"; break;
    case 2: result="VMCLEAR with invalid physical address"; break;
    case 3: result="VMCLEAR with VMXON pointer"; break;
    case 4: result="VMLAUNCH with non-clear VMCS"; break;
    case 5: result="VMRESUME with non-launched VMCS"; break;
    case 6: result="VMRESUME with a corrupted VMCS"; break;
    case 7: result="VM entry with invalid fields"; break;
    case 8: result="VM entry with invalid host-state fields"; break;
    case 9: result="VMPTRLD with invalid physical address"; break;
    case 10: result="VMPTRLD with VMXON pointer"; break;
    case 11: result="VMPTRLD with incorrect VMCS revision identifier"; break;
    case 12: result="VMREAD/VMWRITE from/to unsupported VMCS component"; break;
    case 13: result="VMWRITE to read-only VMCS component"; break;
    case 15: result="VMXON executed in VMX root operation"; break;
    case 16: result="VM entry with invalid executive-VMCS pointer"; break;
    case 17: result="VM entry with non-launched executive-VMCS pointer"; break;
    case 18: result="VM entry with executive-VMCS pointer but not VMXON pointer"; break;
    case 19: result="VMCALL with non-clear VMCS"; break;
    case 20: result="VMCALL with invalid VM-exit control fields"; break;
    case 22: result="VMCALL with incorrect MSEG revision number"; break;
    case 23: result="VMXOFF under dual-monitor treatment of SMIs and SMM"; break;
    case 24: result="VMCALL with invalid SMM-monitor features"; break;
    case 25: result="VM entry with invalid VM-execution control fields in executive VMCS"; break;
    case 26: result="VM entry with events blocked by MOV SS"; break;

    default: result="Undefined"; break;
  }

  return result;
}

void setTrap(void)
{
  UINT64 guestrflags=vmread(vm_guest_rflags);
  PRFLAGS pguestrflags=(PRFLAGS)&guestrflags;
  pguestrflags->TF=1;
  vmwrite(vm_guest_rflags,(UINT64)guestrflags);
}

void setResumeFlag(void)
{
  UINT64 guestrflags=vmread(vm_guest_rflags);
  PRFLAGS pguestrflags=(PRFLAGS)&guestrflags;
  pguestrflags->RF=1;
  vmwrite(vm_guest_rflags,(UINT64)guestrflags);
}

void setupTSS8086(void)

{
  unsigned char *c;
  sendstring("Seting up TSS (for VM8086)\n\r");

  VirtualMachineTSS_V8086->Previous_Task_Link=0;
  VirtualMachineTSS_V8086->Reserved1=0;
  VirtualMachineTSS_V8086->ESP0=(ULONG)VirtualToPhysical((void *)((UINT64)RealmodeRing0Stack+4096-16));
  VirtualMachineTSS_V8086->SS0=8;
  VirtualMachineTSS_V8086->Reserved2=0;
  VirtualMachineTSS_V8086->ESP1=0;
  VirtualMachineTSS_V8086->SS1=0;
  VirtualMachineTSS_V8086->Reserved3=0;
  VirtualMachineTSS_V8086->ESP2=0;
  VirtualMachineTSS_V8086->SS2=0;
  VirtualMachineTSS_V8086->Reserved4=0;
  VirtualMachineTSS_V8086->CR3=(ULONG)VirtualToPhysical(nonpagedEmulationPagedir);
  VirtualMachineTSS_V8086->EIP=0;
  VirtualMachineTSS_V8086->EFLAGS=0x33000;
  VirtualMachineTSS_V8086->EAX=0;
  VirtualMachineTSS_V8086->ECX=0;
  VirtualMachineTSS_V8086->EDX=0;
  VirtualMachineTSS_V8086->EBX=0;
  VirtualMachineTSS_V8086->ESP=0xfff0;
  VirtualMachineTSS_V8086->EBP=0;
  VirtualMachineTSS_V8086->ESI=0;
  VirtualMachineTSS_V8086->EDI=0;
  VirtualMachineTSS_V8086->ES=0;
  VirtualMachineTSS_V8086->Reserved5=0;
  VirtualMachineTSS_V8086->CS=0;
  VirtualMachineTSS_V8086->Reserved6=0;
  VirtualMachineTSS_V8086->SS=0;
  VirtualMachineTSS_V8086->Reserved7=0;
  VirtualMachineTSS_V8086->DS=0;
  VirtualMachineTSS_V8086->Reserved8=0;
  VirtualMachineTSS_V8086->FS=0;
  VirtualMachineTSS_V8086->Reserved9=0;
  VirtualMachineTSS_V8086->GS=0;
  VirtualMachineTSS_V8086->Reserved10=0;
  VirtualMachineTSS_V8086->LDTss=0;
  VirtualMachineTSS_V8086->Reserved11=0;
  VirtualMachineTSS_V8086->Trap=0;
  VirtualMachineTSS_V8086->Reserved12=0;
  VirtualMachineTSS_V8086->IOBASE=sizeof(TSS)+32;

  zeromemory((void *)((UINT64)VirtualMachineTSS_V8086+ sizeof(TSS)),32);

  *(ULONG *)(VirtualMachineTSS_V8086+ sizeof(TSS))=0x200000;

  zeromemory((void *)((UINT64)VirtualMachineTSS_V8086+ sizeof(TSS)+31),8193);

  c=(unsigned char *)(VirtualMachineTSS_V8086);

  c[sizeof(TSS)+32+8192]=0xff;

  c[sizeof(TSS)+2]=0x20;
}

void StoreVirtualMachineState(pcpuinfo currentcpuinfo UNUSED, VMRegisters *registers UNUSED)
{
#ifdef DEBUG
  vmstates[vmstates_pos].registers=*registers;
  vmstates[vmstates_pos].rsp=vmread(vm_guest_rsp);
  vmstates[vmstates_pos].rip=vmread(vm_guest_rip);
  vmstates[vmstates_pos].rflags=vmread(vm_guest_rflags);

  vmstates[vmstates_pos].efer=currentcpuinfo->efer;

  vmstates[vmstates_pos].es=vmread(vm_guest_es);
  vmstates[vmstates_pos].cs=vmread(vm_guest_cs);
  vmstates[vmstates_pos].ss=vmread(vm_guest_ss);
  vmstates[vmstates_pos].ds=vmread(vm_guest_ds);
  vmstates[vmstates_pos].fs=vmread(vm_guest_fs);
  vmstates[vmstates_pos].gs=vmread(vm_guest_gs);
  vmstates[vmstates_pos].ldtr=vmread(vm_guest_ldtr);
  vmstates[vmstates_pos].tr=vmread(vm_guest_tr);

  vmstates[vmstates_pos].es_base=vmread(vm_guest_es_base);
  vmstates[vmstates_pos].cs_base=vmread(vm_guest_cs_base);
  vmstates[vmstates_pos].ss_base=vmread(vm_guest_ss_base);
  vmstates[vmstates_pos].ds_base=vmread(vm_guest_ds_base);
  vmstates[vmstates_pos].fs_base=vmread(vm_guest_fs_base);
  vmstates[vmstates_pos].gs_base=vmread(vm_guest_gs_base);
  vmstates[vmstates_pos].ldtr_base=vmread(vm_guest_ldtr_base);
  vmstates[vmstates_pos].tr_base=vmread(vm_guest_tr_base);

  vmstates[vmstates_pos].exit_reason=vmread(vm_exit_reason);
  vmstates[vmstates_pos].exit_interruptioninfo=vmread(vm_exit_interruptioninfo);
  vmstates[vmstates_pos].exit_interruptionerror=vmread(vm_exit_interruptionerror);
  vmstates[vmstates_pos].idtvector_information=vmread(vm_idtvector_information);
  vmstates[vmstates_pos].idtvector_error=vmread(vm_idtvector_error);

  vmstates_pos++;
  vmstates_pos=vmstates_pos % 4;
#endif
}

void displayPreviousStates(void)
{
#ifdef DEBUG

  int previous_state=(vmstates_pos+2) % 4;
  int current_state=(vmstates_pos+3) % 4;
  int itterator;

  sendstringf("vmstates_pos=%d\n",vmstates_pos);
  sendstringf("previous_state=%d\n",previous_state);

  for (itterator=0; itterator<4; itterator++)
  {
    sendstringf("%s%d: CS:RIP=%x:%6 (base=%6)\n", ((itterator==previous_state)?"*":""), itterator, vmstates[itterator].cs, vmstates[itterator].rip, vmstates[itterator].cs_base);
    sendstringf("%s%d: SS:RSP=%x:%6 (base=%6)\n", ((itterator==previous_state)?"*":""), itterator, vmstates[itterator].ss, vmstates[itterator].rsp, vmstates[itterator].ss_base);
    sendstringf("%s%d: RFLAGS=%x\n", ((itterator==previous_state)?"*":""), itterator, vmstates[vmstates_pos].rflags);
    sendstringf("%s%d: RAX=%x\n", ((itterator==previous_state)?"*":""), itterator, vmstates[itterator].registers.rax);
    sendstringf("%s%d: Exit reason=%8 (%d) \n\r", ((itterator==previous_state)?"*":""),itterator, vmstates[itterator].exit_reason,vmstates[itterator].exit_reason & 0x0fffffff);

    sendstringf("%s%d: VM-exit interruption information=%x\n\r", ((itterator==previous_state)?"*":""), itterator, vmstates[itterator].exit_interruptioninfo);

    sendstringf("%s%d: VM-exit interruption error code=%x\n\r", ((itterator==previous_state)?"*":""), itterator, vmstates[itterator].exit_interruptionerror);
    sendstringf("%s%d: IDT-vectoring information field=%x\n\r", ((itterator==previous_state)?"*":""), itterator,vmstates[itterator].idtvector_information);
    sendstringf("%s%d: IDT-vectoring error code=%x\n\r", ((itterator==previous_state)?"*":""), itterator,vmstates[itterator].idtvector_error);

    if (itterator!=current_state)
    {
      sendstringf("%s%d:---exit---\n", ((itterator==previous_state)?"*":""), itterator);
      sendstringf("%s%d: CS:RIP=%x:%6 (base=%6)\n", ((itterator==previous_state)?"*":""), itterator, vmstates[itterator].exit_cs, vmstates[itterator].exit_rip, vmstates[itterator].exit_cs_base);
      sendstringf("%s%d: SS:RSP=%x:%6 (base=%6)\n", ((itterator==previous_state)?"*":""), itterator, vmstates[itterator].exit_ss, vmstates[itterator].exit_rsp, vmstates[itterator].exit_ss_base);
      sendstringf("%s%d: RFLAGS=%x\n", ((itterator==previous_state)?"*":""), itterator, vmstates[vmstates_pos].exit_rflags);

    }
  }
#endif
}

void sendvmstate(pcpuinfo currentcpuinfo UNUSED, VMRegisters *registers UNUSED)
{

#ifdef DEBUG
  if (isAMD)
  {
    UINT64 rflags=currentcpuinfo->vmcb->RFLAGS;

    PRFLAGS prflags=(PRFLAGS)&rflags;

    sendstringf("GuestASID=%d", currentcpuinfo->vmcb->GuestASID);
    sendstringf("CPL=%d\n", currentcpuinfo->vmcb->CPL);

    if (has_VGIFSupport)
      sendstringf("V_GIF=%d\n", currentcpuinfo->vmcb->V_GIF);
    else
      sendstringf("GIF=%d\n", currentcpuinfo->vmcb_GIF);

    if (registers)
    {
      UINT64 *fsbase=(UINT64 *)((UINT64)(&registers->rax)+8);
      sendstringf("saved FS_BASE_MSR=%6\n", *fsbase);
    }
    sendstringf("FS_BASE_MSR=%6\n", readMSR(IA32_FS_BASE_MSR));
    sendstringf("GS_BASE_MSR=%6\n", readMSR(IA32_GS_BASE_MSR));

    if (registers)
    {
      sendstringf("RAX=%6 RBX=%6   R8=%6\n\r", currentcpuinfo->vmcb->RAX, registers->rbx, registers->r8);
      sendstringf("RCX=%6 RDX=%6   R9=%6\n\r", registers->rcx, registers->rdx, registers->r9);
      sendstringf("RSI=%6 RDI=%6  R10=%6\n\r",registers->rsi, registers->rdi,  registers->r10);
      sendstringf("RBP=%6                       R11=%6\n\r",registers->rbp, registers->r11);

    }
    else
      sendstring("\n...no registers...\n\n");

    sendstringf("RSP=%6                       R12=%6\n\r",currentcpuinfo->vmcb->RSP, registers?registers->r12:0);
    sendstringf("RIP=%6                       R13=%6\n\r",currentcpuinfo->vmcb->RIP, registers?registers->r13:0);
    sendstringf("                                           R14=%6\n\r", registers?registers->r14:0);
    sendstringf("                                           R15=%6\n\r", registers?registers->r15:0);

    sendstringf("rflags=%6 (VM=%d RF=%d IOPL=%d NT=%d)\n\r",rflags,prflags->VM, prflags->RF, prflags->IOPL, prflags->NT);
    sendstringf("(CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d)\n\r\n\r", prflags->CF, prflags->PF, prflags->AF, prflags->ZF, prflags->SF, prflags->TF, prflags->IF, prflags->DF, prflags->OF);

    sendstringf("cs=%8  (base=%6 , limit=%8, AT=%8)\n\r",currentcpuinfo->vmcb->cs_selector, currentcpuinfo->vmcb->cs_base, currentcpuinfo->vmcb->cs_limit, currentcpuinfo->vmcb->cs_attrib);
    sendstringf("ss=%8  (base=%6 , limit=%8, AT=%8)\n\r",currentcpuinfo->vmcb->ss_selector, currentcpuinfo->vmcb->ss_base, currentcpuinfo->vmcb->ss_limit, currentcpuinfo->vmcb->ss_attrib);
    sendstringf("ds=%8  (base=%6 , limit=%8, AT=%8)\n\r",currentcpuinfo->vmcb->ds_selector, currentcpuinfo->vmcb->ds_base, currentcpuinfo->vmcb->ds_limit, currentcpuinfo->vmcb->ds_attrib);
    sendstringf("es=%8  (base=%6 , limit=%8, AT=%8)\n\r",currentcpuinfo->vmcb->es_selector, currentcpuinfo->vmcb->es_base, currentcpuinfo->vmcb->es_limit, currentcpuinfo->vmcb->es_attrib);
    sendstringf("fs=%8  (base=%6 , limit=%8, AT=%8)\n\r",currentcpuinfo->vmcb->fs_selector, currentcpuinfo->vmcb->fs_base, currentcpuinfo->vmcb->fs_limit, currentcpuinfo->vmcb->fs_attrib);
    sendstringf("gs=%8  (base=%6 , limit=%8, AT=%8)\n\r",currentcpuinfo->vmcb->gs_selector, currentcpuinfo->vmcb->gs_base, currentcpuinfo->vmcb->gs_limit, currentcpuinfo->vmcb->gs_attrib);
    sendstringf("ldt=%8 (base=%6 , limit=%8, AT=%8)\n\r",currentcpuinfo->vmcb->ldtr_selector, currentcpuinfo->vmcb->ldtr_base, currentcpuinfo->vmcb->ldtr_limit, currentcpuinfo->vmcb->ldtr_attrib);
    sendstringf("tr=%8  (base=%6 , limit=%8, AT=%8)\n\r",currentcpuinfo->vmcb->tr_selector, currentcpuinfo->vmcb->tr_base, currentcpuinfo->vmcb->tr_limit, currentcpuinfo->vmcb->tr_attrib);
    sendstringf("\n\r");
    sendstringf("gdt: base=%6 limit=%x\n\r",currentcpuinfo->vmcb->gdtr_base, currentcpuinfo->vmcb->gdtr_limit);
    sendstringf("idt: base=%6 limit=%x\n\r",currentcpuinfo->vmcb->idtr_base, currentcpuinfo->vmcb->idtr_limit);

    sendstringf("cr0=%6 cr3=%6 cr4=%6 cr8=%6 V_TPR=%d\n\r",currentcpuinfo->vmcb->CR0, currentcpuinfo->vmcb->CR3, currentcpuinfo->vmcb->CR4, getCR8(), currentcpuinfo->vmcb->V_TPR);

  }
  else
  {
    UINT64 rflags=vmread(vm_guest_rflags);
    PRFLAGS prflags=(PRFLAGS)&rflags;

    sendstringf("cpunr=%d\n\r", currentcpuinfo->cpunr);
    sendstringf("getTaskRegister()=%x\n",getTaskRegister());

    sendstringf("Activity state : %d      interruptibility state : %d \n\r",vmread(vm_guest_activity_state), vmread(vm_guest_interruptability_state));

    sendstringf("IS64BITPAGING=%d IS64BITCODE=%d ISREALMODE=%d\n\r", IS64BITPAGING(currentcpuinfo), IS64BITCODE(currentcpuinfo), ISREALMODE(currentcpuinfo));
    if (hasUnrestrictedSupport)
      sendstringf("efer=%x\n\r",vmread(vm_guest_IA32_EFER));
    else
      sendstringf("efer=%x (%x)\n\r",currentcpuinfo->efer, vmread(vm_guest_IA32_EFER));

    sendstringf("ia32e mode guest=%d\n",((vmread(vm_entry_controls) & VMENTRYC_IA32E_MODE_GUEST) != 0) );

    sendstringf("IA32_SYSENTER_CS=%x IA32_SYSENTER_EIP=%x IA32_SYSENTER_ESP=%x\n",vmread(vm_guest_IA32_SYSENTER_CS), vmread(vm_guest_IA32_SYSENTER_EIP), vmread(vm_guest_IA32_SYSENTER_ESP) );

    if (registers)
    {
      sendstringf("RAX=%6 RBX=%6   R8=%6\n\r", registers->rax, registers->rbx, registers->r8);
      sendstringf("RCX=%6 RDX=%6   R9=%6\n\r", registers->rcx, registers->rdx, registers->r9);
      sendstringf("RSI=%6 RDI=%6  R10=%6\n\r",registers->rsi, registers->rdi,  registers->r10);
      sendstringf("RBP=%6                       R11=%6\n\r",registers->rbp, registers->r11);

    }
    else
      sendstring("\n...no registers...\n\n");

    sendstringf("RSP=%6                       R12=%6\n\r",vmread(vm_guest_rsp), registers?registers->r12:0);
    sendstringf("RIP=%6                       R13=%6\n\r",vmread(vm_guest_rip), registers?registers->r13:0);
    sendstringf("                                           R14=%6\n\r", registers?registers->r14:0);
    sendstringf("                                           R15=%6\n\r", registers?registers->r15:0);

    sendstringf("rflags=%6 (VM=%d RF=%d IOPL=%d NT=%d)\n\r",rflags,prflags->VM, prflags->RF, prflags->IOPL, prflags->NT);
    sendstringf("(CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d)\n\r\n\r", prflags->CF, prflags->PF, prflags->AF, prflags->ZF, prflags->SF, prflags->TF, prflags->IF, prflags->DF, prflags->OF);

    if (currentcpuinfo->invalidcs)
    {
      sendstring("Invalid cs...\n\r");
    }

    sendstringf("cs=%8  (base=%6 , limit=%8, AR=%8)\n\r",vmread(0x802),vmread(vm_guest_cs_base),vmread(vm_guest_cs_limit), vmread(0x4816));
    sendstringf("ss=%8  (base=%6 , limit=%8, AR=%8)\n\r",vmread(0x804),vmread(vm_guest_ss_base),vmread(vm_guest_ss_limit), vmread(0x4818));
    sendstringf("ds=%8  (base=%6 , limit=%8, AR=%8)\n\r",vmread(0x806),vmread(0x680c),vmread(0x4806), vmread(0x481a));
    sendstringf("es=%8  (base=%6 , limit=%8, AR=%8)\n\r",vmread(0x800),vmread(0x6806),vmread(0x4800), vmread(0x4814));
    sendstringf("fs=%8  (base=%6 , limit=%8, AR=%8)\n\r",vmread(0x808),vmread(0x680e),vmread(0x4808), vmread(0x481c));
    sendstringf("gs=%8  (base=%6 , limit=%8, AR=%8)\n\r",vmread(0x80a),vmread(0x6810),vmread(0x480a), vmread(0x481e));
    sendstringf("ldt=%8 (base=%6 , limit=%8, AR=%8)\n\r",vmread(0x80c),vmread(0x6812),vmread(0x480c), vmread(0x4820));
    sendstringf("tr=%8  (base=%6 , limit=%8, AR=%8)\n\r",vmread(0x80e),vmread(0x6814),vmread(0x480e), vmread(0x4822));

    sendstringf("\n\r");
    sendstringf("gdt: base=%6 limit=%x\n\r",vmread(vm_guest_gdtr_base), vmread(vm_guest_gdt_limit));
    sendstringf("idt: base=%6 limit=%x\n\r",vmread(vm_guest_idtr_base), vmread(vm_guest_idt_limit));

    if (ISREALMODE(currentcpuinfo))
    {
      sendstringf("RM gdt: base=%6 limit=%x\n\r",currentcpuinfo->RealMode.GDTBase, currentcpuinfo->RealMode.GDTLimit);
      sendstringf("RM idt: base=%6 limit=%x\n\r",currentcpuinfo->RealMode.IDTBase, currentcpuinfo->RealMode.IDTLimit);
    }

    regDR7 dr7;
    dr7.DR7=vmread(vm_guest_dr7);
    sendstringf("guest: dr0=%6 dr1=%6 dr2=%6 \n\r       dr3=%6 dr6=%6 dr7=%6\n\r",getDR0(), getDR1(), getDR2(), getDR3(), getDR6(), dr7.DR7);
    if (dr7.DR7 != 0x400)
    {
      sendstringf("dr7:");
      if (dr7.G0)
        sendstringf("G0 ");

      if (dr7.L0)
        sendstringf("L0 ");

      if (dr7.G1)
        sendstringf("G1 ");

      if (dr7.L1)
        sendstringf("L1 ");

      if (dr7.G2)
        sendstringf("G2 ");

      if (dr7.L2)
          sendstringf("L2 ");

      if (dr7.G3)
        sendstringf("G3 ");

      if (dr7.L3)
          sendstringf("L3 ");

      if (dr7.LE)
        sendstringf("LE ");

      if (dr7.GE)
        sendstringf("GE ");

      if (dr7.RW0)
        sendstringf("RW0 ");

      if (dr7.LEN0)
        sendstringf("LEN0 ");

      if (dr7.RW1)
        sendstringf("RW1 ");

      if (dr7.LEN1)
        sendstringf("LEN1 ");

      if (dr7.RW2)
        sendstringf("RW2 ");

      if (dr7.LEN2)
        sendstringf("LEN2 ");

      if (dr7.RW3)
        sendstringf("RW3 ");

      if (dr7.LEN3)
        sendstringf("LEN3 ");

    }

    sendstringf("host dr7=%6\n\r", getDR7());
    sendstringf("cr2=%6\n\r",getCR2());

    sendstringf("real:\n\r");
    sendstringf("cr0=%6 cr3=%6 cr4=%6\n\r",vmread(vm_guest_cr0), vmread(vm_guest_cr3), vmread(vm_guest_cr4));

    sendstringf("fake (what vm sees):\n\r");

    QWORD fakeCR0=(vmread(vm_guest_cr0) & (~vmread(vm_cr0_guest_host_mask))) | (vmread(vm_cr0_read_shadow) & vmread(vm_cr0_guest_host_mask));
    QWORD fakeCR4=(vmread(vm_guest_cr4) & (~vmread(vm_cr4_guest_host_mask))) | (vmread(vm_cr4_read_shadow) & vmread(vm_cr4_guest_host_mask));
    if (hasUnrestrictedSupport)
    {
      sendstringf("vm_cr0_guest_host_mask=%6 vm_cr0_read_shadow=%6\n", vmread(vm_cr0_guest_host_mask), vmread(vm_cr0_read_shadow));
      sendstringf("vm_cr4_guest_host_mask=%6 vm_cr4_read_shadow=%6\n", vmread(vm_cr4_guest_host_mask), vmread(vm_cr4_read_shadow));
      sendstringf("cr0=%6 cr3=%6 cr4=%6\n\r",fakeCR0, currentcpuinfo->guestCR3, fakeCR4);
    }
    else
      sendstringf("cr0=%6 cr3=%6 cr4=%6\n\r",vmread(vm_cr0_read_shadow), currentcpuinfo->guestCR3, vmread(vm_cr4_read_shadow));

  }

  if (currentcpuinfo->vmxdata.insideVMXRootMode)
  {
    sendstringf("VMXON=%6\n\r", currentcpuinfo->vmxdata.guest_vmxonaddress);
    sendstringf("VMCS=%6\n\r", currentcpuinfo->vmxdata.guest_activeVMCS);
    sendstringf("running=%d\n\r", currentcpuinfo->vmxdata.runningvmx);
  }

#endif

  sendstringf("Pending interrupts:");
  ShowPendingInterrupts();
  sendstringf("\n\r");

  if (isAMD==0)
  {
    sendstringf("vm_execution_controls_cpu=%6\n", vmread(vm_execution_controls_cpu));
    if (vmread(vm_execution_controls_cpu) & SECONDARY_EXECUTION_CONTROLS)
    {
      sendstringf("vm_execution_controls_cpu_secondary=%6 (unrestricted=%d)\n", vmread(vm_execution_controls_cpu_secondary), (vmread(vm_execution_controls_cpu_secondary) & SPBEF_ENABLE_UNRESTRICTED)!=0);
    }
  }
}

void sendvmstateFull(pcpuinfo currentcpuinfo UNUSED, VMRegisters *registers UNUSED)
{
  sendvmstate(currentcpuinfo, registers);

  sendstring("----------------------------------------\n");
  sendstring("|                 HOST                 |\n");
  sendstring("----------------------------------------\n");

  sendstringf("ES=%x\n", vmread(vm_host_es));
  sendstringf("CS=%x\n", vmread(vm_host_cs));
  sendstringf("SS=%x\n", vmread(vm_host_ss));
  sendstringf("DS=%x\n", vmread(vm_host_ds));
  sendstringf("FS=%x\n", vmread(vm_host_fs));
  sendstringf("GS=%x\n", vmread(vm_host_gs));
  sendstringf("TR=%x\n", vmread(vm_host_tr));

  sendstringf("IA32_PAT=%6\n", vmread(vm_host_IA32_PAT));
  sendstringf("IA32_EFER=%6\n", vmread(vm_host_IA32_EFER));
  sendstringf("IA32_PERF_GLOBAL_CTRL=%6\n", vmread(vm_host_IA32_PERF_GLOBAL_CTRL));

  sendstringf("IA32_SYSENTER_CS=%x\n", vmread(vm_host_IA32_SYSENTER_CS));

  sendstringf("cr0=%6\n", vmread(vm_host_cr0));
  sendstringf("cr3=%6\n", vmread(vm_host_cr3));
  sendstringf("cr4=%6\n", vmread(vm_host_cr4));

  sendstringf("fs_base=%6\n", vmread(vm_host_fs_base));
  sendstringf("gs_base=%6\n", vmread(vm_host_gs_base));
  sendstringf("tr_base=%6\n", vmread(vm_host_tr_base));
  sendstringf("gdt_base=%6\n", vmread(vm_host_gdtr_base));
  sendstringf("idt_base=%6\n", vmread(vm_host_idtr_base));
  sendstringf("IA32_SYSENTER_ESP=%6\n", vmread(vm_host_IA32_SYSENTER_ESP));
  sendstringf("IA32_SYSENTER_EIP=%6\n", vmread(vm_host_IA32_SYSENTER_EIP));
  sendstringf("vm_host_rsp=%6\n", vmread(vm_host_rsp));
  sendstringf("vm_host_rip=%6\n", vmread(vm_host_rip));

  if (currentcpuinfo->vmxdata.runningvmx)
  {
    sendstring("-----------------------------------------\n");
    sendstring("|               GUESTHOST               |\n");
    sendstring("-----------------------------------------\n");

    sendstringf("ES=%x\n", currentcpuinfo->vmxdata.originalhoststate.ES);
    sendstringf("CS=%x\n", currentcpuinfo->vmxdata.originalhoststate.CS);
    sendstringf("SS=%x\n", currentcpuinfo->vmxdata.originalhoststate.SS);
    sendstringf("DS=%x\n", currentcpuinfo->vmxdata.originalhoststate.DS);
    sendstringf("FS=%x\n", currentcpuinfo->vmxdata.originalhoststate.FS);
    sendstringf("GS=%x\n", currentcpuinfo->vmxdata.originalhoststate.GS);
    sendstringf("TR=%x\n", currentcpuinfo->vmxdata.originalhoststate.TR);

    sendstringf("IA32_PAT=%6\n", currentcpuinfo->vmxdata.originalhoststate.IA32_PAT);
    sendstringf("IA32_EFER=%6\n", currentcpuinfo->vmxdata.originalhoststate.IA32_EFER);
    sendstringf("IA32_PERF_GLOBAL_CTRL=%6\n", currentcpuinfo->vmxdata.originalhoststate.IA32_PERF_GLOBAL_CTRL);

    sendstringf("IA32_SYSENTER_CS=%x\n", currentcpuinfo->vmxdata.originalhoststate.IA32_SYSENTER_CS);

    sendstringf("cr0=%6\n", currentcpuinfo->vmxdata.originalhoststate.CR0);
    sendstringf("cr3=%6\n", currentcpuinfo->vmxdata.originalhoststate.CR3);
    sendstringf("cr4=%6\n", currentcpuinfo->vmxdata.originalhoststate.CR4);

    sendstringf("fs_base=%6\n", currentcpuinfo->vmxdata.originalhoststate.FS_BASE);
    sendstringf("gs_base=%6\n", currentcpuinfo->vmxdata.originalhoststate.GS_BASE);
    sendstringf("tr_base=%6\n", currentcpuinfo->vmxdata.originalhoststate.TR_BASE);
    sendstringf("gdt_base=%6\n", currentcpuinfo->vmxdata.originalhoststate.GDTR_BASE);
    sendstringf("idt_base=%6\n", currentcpuinfo->vmxdata.originalhoststate.IDTR_BASE);
    sendstringf("IA32_SYSENTER_ESP=%6\n", currentcpuinfo->vmxdata.originalhoststate.IA32_SYSENTER_ESP);
    sendstringf("IA32_SYSENTER_EIP=%6\n", currentcpuinfo->vmxdata.originalhoststate.IA32_SYSENTER_EIP);
    sendstringf("vm_host_rsp=%6\n", currentcpuinfo->vmxdata.originalhoststate.RSP);
    sendstringf("vm_host_rip=%6\n", currentcpuinfo->vmxdata.originalhoststate.RIP);

    sendstring("-----------------------------------------\n");
    sendstring("|               DBVM                    |\n");
    sendstring("-----------------------------------------\n");

    sendstringf("ES=%x\n", currentcpuinfo->vmxdata.dbvmhoststate.ES);
    sendstringf("CS=%x\n", currentcpuinfo->vmxdata.dbvmhoststate.CS);
    sendstringf("SS=%x\n", currentcpuinfo->vmxdata.dbvmhoststate.SS);
    sendstringf("DS=%x\n", currentcpuinfo->vmxdata.dbvmhoststate.DS);
    sendstringf("FS=%x\n", currentcpuinfo->vmxdata.dbvmhoststate.FS);
    sendstringf("GS=%x\n", currentcpuinfo->vmxdata.dbvmhoststate.GS);
    sendstringf("TR=%x\n", currentcpuinfo->vmxdata.dbvmhoststate.TR);

    sendstringf("IA32_PAT=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.IA32_PAT);
    sendstringf("IA32_EFER=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.IA32_EFER);
    sendstringf("IA32_PERF_GLOBAL_CTRL=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.IA32_PERF_GLOBAL_CTRL);

    sendstringf("IA32_SYSENTER_CS=%x\n", currentcpuinfo->vmxdata.dbvmhoststate.IA32_SYSENTER_CS);

    sendstringf("cr0=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.CR0);
    sendstringf("cr3=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.CR3);
    sendstringf("cr4=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.CR4);

    sendstringf("fs_base=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.FS_BASE);
    sendstringf("gs_base=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.GS_BASE);
    sendstringf("tr_base=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.TR_BASE);
    sendstringf("gdt_base=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.GDTR_BASE);
    sendstringf("idt_base=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.IDTR_BASE);
    sendstringf("IA32_SYSENTER_ESP=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.IA32_SYSENTER_ESP);
    sendstringf("IA32_SYSENTER_EIP=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.IA32_SYSENTER_EIP);
    sendstringf("vm_host_rsp=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.RSP);
    sendstringf("vm_host_rip=%6\n", currentcpuinfo->vmxdata.dbvmhoststate.RIP);

  }

}

int twister=0;

#if DISPLAYDEBUG==1
int verbosity=10;
#else
int verbosity=0;
#endif
int rotations=0;
int cpu2=0;

int vmeventcount=0;
criticalSection vmexitlock={.name="vmexitlock", .debuglevel=0};

int vmexit_amd(pcpuinfo currentcpuinfo, UINT64 *registers, void *fxsave UNUSED)
{

  int result=0;
  currentcpuinfo->insideHandler=1;

  nosendchar[getAPICID()]=1;

  if (readMSR(IA32_FS_BASE_MSR)==0)
  {
    nosendchar[getAPICID()]=0;
    sendstringf("Invalid FS base during exception (currentcpuinfo=%6 vmeventcount=%d)\n", currentcpuinfo, vmeventcount);
    ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);
    while (1) outportb(0x80,0xc5);
  }
  vmeventcount++;

#ifdef DEBUG
  csEnter(&vmexitlock);

  if ((int)(vmexitlock.apicid-1)!=(int)(currentcpuinfo->apicid))
  {
    nosendchar[getAPICID()]=0;
    while (1)
    {
      sendstringf("lockcount inconsistency 3.  %d != %d  (%d)\n",vmexitlock.apicid,currentcpuinfo->apicid, getAPICID() );
    }
  }

#endif

  if (dbvm_plugin_exit_pre)
  {
    BOOL r=dbvm_plugin_exit_pre(exportlist, currentcpuinfo, registers, fxsave);
    if (r)
    {
      sendstring("dbvm_plugin_exit_pre returned TRUE");
#ifdef DEBUG
      csLeave(&vmexitlock);
#endif
      currentcpuinfo->insideHandler=0;
      return 0;
    }
  }

  result=handleVMEvent_amd(currentcpuinfo, (VMRegisters*)registers, fxsave);

  if (dbvm_plugin_exit_post)
    dbvm_plugin_exit_post(exportlist, currentcpuinfo, registers, fxsave, &result);

#ifdef DEBUG
  if (vmexitlock.lockcount>1)
  {
    nosendchar[getAPICID()]=0;
    while (1)
    {
      sendstringf("lockcount inconsistency");
    }

  }
  csLeave(&vmexitlock);
#endif

  currentcpuinfo->insideHandler=0;

  if ((vmexitlock.lockcount>0) && ((int)(vmexitlock.apicid-1)==(int)(currentcpuinfo->apicid)))
  {
    nosendchar[getAPICID()]=0;
    while (1)
    {
      sendstringf("lockcount inconsistency 2");
    }

  }

  return result;
}

#ifdef debuglastexits
int lastexits[10];
int lastexitsindex=0;

criticalSection lastexitsCS={.name="lastexitsCS", .debuglevel=1};
#endif

#ifdef DEBUG

QWORD lastbeat=0;

int vmexit2(pcpuinfo currentcpuinfo, UINT64 *registers, void *fxsave);

int vmexit(pcpuinfo currentcpuinfo, UINT64 *registers, void *fxsave)
{
  int result;

  if (_rdtsc()>(lastbeat+100000000ULL))
  {
	  nosendchar[getAPICID()]=0;
	  enableserial();

	  lastbeat=_rdtsc();
  }

#ifdef USENMIFORWAIT
  if (vmread(vm_exit_reason)==0)
  {
    VMExit_interruption_information intinfo;
    intinfo.interruption_information=vmread(vm_exit_interruptioninfo);

    if ((intinfo.interruptvector==2) && (intinfo.type==itNMI) && (currentcpuinfo->WaitTillDone))
    {
      nosendchar[getAPICID()]=0;
      sendstringf("NMI %d waiting till done\n", currentcpuinfo->cpunr);
      currentcpuinfo->WaitingTillDone=1;

      while (currentcpuinfo->WaitTillDone) _pause();

      sendstringf("NMI %d done waiting\n", currentcpuinfo->cpunr);

      if (currentcpuinfo->eptUpdated)
        ept_invalidate();

      return 0;
    }
  }
#endif

  csEnter(&vmexitlock);
  int used_vmstates_pos=vmstates_pos;

  StoreVirtualMachineState(currentcpuinfo, (VMRegisters*)registers);

  result=vmexit2(currentcpuinfo, registers, fxsave);

  vmstates[used_vmstates_pos].exit_cs=vmread(vm_guest_cs);
  vmstates[used_vmstates_pos].exit_cs_base=vmread(vm_guest_cs_base);
  vmstates[used_vmstates_pos].exit_ss=vmread(vm_guest_ss);
  vmstates[used_vmstates_pos].exit_ss_base=vmread(vm_guest_ss_base);

  vmstates[used_vmstates_pos].exit_rip=vmread(vm_guest_rip);
  vmstates[used_vmstates_pos].exit_rsp=vmread(vm_guest_rsp);
  vmstates[used_vmstates_pos].exit_rflags=vmread(vm_guest_rflags);

  if ((result) && ((result >> 8)!=0xce))
  {
    nosendchar[getAPICID()]=0;
    sendvmstate(currentcpuinfo, (VMRegisters*)registers);
  }

  csLeave(&vmexitlock);

  return result;
}

int vmexit2(pcpuinfo currentcpuinfo, UINT64 *registers, void *fxsave)
#else

int showlife=0;

int vmexit(pcpuinfo currentcpuinfo, UINT64 *registers, void *fxsave)
#endif
{

  int haspending=0;
  VMExit_idt_vector_information idtvectorinfo;
  idtvectorinfo.idtvector_info=vmread(vm_idtvector_information);

#ifdef USENMIFORWAIT
  if (vmread(vm_exit_reason)==0)
  {
    VMExit_interruption_information intinfo;
    intinfo.interruption_information=vmread(vm_exit_interruptioninfo);
    if ((intinfo.interruptvector==2) && (intinfo.type==itNMI) && (currentcpuinfo->WaitTillDone))
    {
      currentcpuinfo->WaitingTillDone=1;
      while (currentcpuinfo->WaitTillDone) _pause();

      if (currentcpuinfo->eptUpdated)
        ept_invalidate();

      return 0;
    }
  }
#endif

#ifdef debuglastexits
  csEnter(&lastexitscs);
  lastexits[lastexitsindex]=vmread(vm_exit_reason);
  lastexitsindex++;
  lastexitsindex=lastexitsindex % 10;
  csLease(&lastexitscs);

  {
    ddDrawRectangle(0,DDVerticalResolution-10,10,10,0x0000ff);
  }
#endif

#ifdef CHECKAPICID
  if (currentcpuinfo)
  {
    if (getAPICID()!=currentcpuinfo->apicid)
    {
      sendstring("FUCK\n");
      while(1);
    }

  }
  else
  {
    sendstring("WTFOMG\n");
    while (1);
  }
#endif

  if (dbvm_plugin_exit_pre)
  {
    BOOL r=dbvm_plugin_exit_pre(exportlist, currentcpuinfo, registers, fxsave);
    if (r)
    {
      ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);
      return 0;
    }
  }

  if (currentcpuinfo==NULL)
  {
    nosendchar[getAPICID()]=0;
    sendstringf("currentcpuinfo==NULL");

    ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);

    while (1) outportb(0x80,0xdc);
  }

  if (currentcpuinfo->vmxdata.runningvmx)
  {
    nosendchar[getAPICID()]=0;
    int r=handleVMEvent(currentcpuinfo, (VMRegisters*)registers, fxsave);

    if (dbvm_plugin_exit_post)
      dbvm_plugin_exit_post(exportlist, currentcpuinfo, registers, fxsave, &r);

    ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);

    return r;
  }

  if (hasUnrestrictedSupport)
  {

    currentcpuinfo->guestCR0=vmread(vm_guest_cr0);

  }

  int skip=0;
  vmeventcount++;

  int result;

#ifndef DEBUG
  volatile int wait=1;

  result=handleVMEvent(currentcpuinfo, (VMRegisters*)registers, fxsave);

  if (dbvm_plugin_exit_post)
    dbvm_plugin_exit_post(exportlist, currentcpuinfo, registers, fxsave, &result);

  if (currentcpuinfo->NMIOccured==2)
  {
    ddDrawRectangle(0,DDVerticalResolution-100,100,100,0x0000ff);

    currentcpuinfo->NMIOccured=0;
    return raiseNMI();
  }

  {
    ddDrawRectangle(0,DDVerticalResolution-10,10,10,0x00ff00);
  }

  showlife++;

  if ((result!=0) && ((result >> 8) != 0xce)  )
  {
    ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);
    while (wait) ;

    if ((vmread(vm_exit_reason) & 0x7fffffff)==vm_exit_invalid_guest_state)
      return raiseGeneralProtectionFault(0);
    else
      return raiseInvalidOpcodeException(currentcpuinfo);
  }
  else
  {
    if (result)
    {
      ddDrawRectangle(0,DDVerticalResolution-100,100,100,0xff0000);

    }
    return result;
  }

#else

#endif

  UINT64 initialcount UNUSED;

  int userbreak=0;

  nosendchar[getAPICID()]=0;

  initialcount=1;

  if (vmread(vm_pending_debug_exceptions))
    userbreak=1;

  if (IntHandlerDebug==0)
  {
    enableserial();

    char b=getchar();
    if (b=='b')
      userbreak=1;
  }

  char command;

  if (userbreak)
  {
    sendstring("user wants to break\n\r");
    verbosity=10;
  }
  else
  if ((vmread(vm_exit_reason)==0) && ((vmread(vm_exit_interruptioninfo) & 0x8000000f)==0x80000001) )
  {

  }
  else

  {

    switch (vmread(vm_exit_reason))
    {

      case vm_exit_vmxon:
        skip=1;
        break;

      case vm_exit_vmxoff:
        skip=1;
        break;

      case vm_exit_vmptrld:
        skip=1;
        break;

      case vm_exit_vmclear:
        skip=1;
        break;

      case vm_exit_vmlaunch:
        skip=1;
        break;

      case vm_exit_vmresume:
        skip=1;
        break;

      case vm_exit_vmcall:

        skip=1;
    	break;

      case vm_exit_vmread:
        skip=1;
        break;

      case vm_exit_vmwrite:
        skip=1;
        break;

      case vm_exit_invept:
        skip=1;
        break;

      case vm_exit_invvpid:
        skip=1;
        break;

      case vm_exit_cpuid:
        skip=2;
        break;

      case vm_exit_vmx_preemptiontimer_reachedzero:
        break;

      case vm_exit_invlpg:

        break;

      case vm_exit_io_access:

        break;

      case vm_exit_ept_violation:
      {

        skip=1;
        break;
      }

      case vm_exit_monitor_trap_flag:
      {
        skip=1;
        break;
      }

      case vm_exit_interrupt:
      {
        switch (vmread(vm_exit_interruptioninfo))
        {
          case 0x80000300:

            break;

          case 0x80000301:
            skip=1;
            break;

          case 0x80000307:

            break;

          case 0x80000b0e:

             skip=1;
            break;

          case 0x80000603:

        	  skip=1;

            break;

          case 0x80000306:

            break;

          case 0x80000b0d:

            break;

        }
      }

      case vm_exit_cr_access:
      {

        {
          skip=1;
        }

        break;
      }

      case vm_exit_sipi:
      {

        skip=1;

        break;
      }

      case vm_exit_rdmsr:
      {
    	  VMRegisters* r=(VMRegisters*)registers;
        switch (r->rcx)
        {
          case 0x10:
          case 0x176:
          case 0x175:
          case 0x174:
          case 0x3a:
          case 0xc0000080:
        	  skip=1;
        	  break;

        }

        skip=1;

        break;

      }

      case vm_exit_wrmsr:
      {
      	VMRegisters* r=(VMRegisters*)registers;
        switch (r->rcx)
        {
          case 0x10:
          case 0x3a:
          case 0xc0000080:
            skip=1;
          break;

        }

        skip=1;

        break;
      }

      case vm_exit_xsetbv:
        skip=1;
        break;

      case vm_exit_rdtsc:
        skip=1;
        break;

      case vm_exit_invalid_guest_state:
      {

        nosendchar[getAPICID()]=0;
        sendstringf("invalid guest\n");

        skip=verbosity;

        break;
      }

    }

    skip-=verbosity;

    if (skip>0)
    {
      nosendchar[getAPICID()]=1;

      result=handleVMEvent(currentcpuinfo, (VMRegisters*)registers, fxsave);

      if (currentcpuinfo->NMIOccured==2)
      {
        currentcpuinfo->NMIOccured=0;
        return raiseNMI();
      }

      if ((result==0) || ((result >> 8)==0xce))
      {
        if (debugmode)
          setTrap();

        return result;
      }

      nosendchar[getAPICID()]=0;

      sendstringf("ERROR: handleVMEvent returned %d\n", result);
    }

  }

  while (IntHandlerDebug) ;

  nosendchar[getAPICID()]=0;

  enableserial();
  sendstringf("\n\r------------(%d)------------------\n\r",vmeventcount);
  sendstringf("Hello from vmexit-(cpunr=%d skip=%d)\n",currentcpuinfo->cpunr, skip);

  sendstringf("currentcpuinfo = %6  : APICID=%d  :  RSP=%6\n\r",(UINT64)currentcpuinfo, getAPICID(), getRSP());

  sendstringf("VM error code=%x\n\r",vmread(vm_errorcode));
  sendstringf("Exit reason=%8 (%d=%s) \n\r",vmread(vm_exit_reason),(vmread(vm_exit_reason) & 0x0fffffff), getVMExitReassonString());
  sendstringf("VM-exit interruption information=%x\n\r",vmread(vm_exit_interruptioninfo));

  sendstringf("VM-exit interruption error code=%x\n\r",vmread(vm_exit_interruptionerror));
  sendstringf("IDT-vectoring information field=%x\n\r",vmread(vm_idtvector_information));
  sendstringf("IDT-vectoring error code=%x\n\r",vmread(vm_idtvector_error));
  sendstringf("VM-exit instruction length=%x\n\r",vmread(vm_exit_instructionlength));
  sendstringf("VMX-instruction information=%x\n\r",vmread(vm_instruction_information));

  sendstringf("Exit qualification=%6\n\r",vmread(vm_exit_qualification));

  sendstringf("Pending debug exceptions = %x\n\r",vmread(vm_pending_debug_exceptions));
  sendstringf("Guest linear   address=%6\n\r",vmread(vm_guest_linear_address));
  sendstringf("Guest physical address=%6\n\r",vmread(vm_guest_physical_address));

  RFLAGS rflags;
  rflags.value=vmread(vm_guest_rflags);

  sendstringf("rflags=%x (IF=%d TF=%d RF=%d)\n",rflags.value, rflags.IF, rflags.TF, rflags.RF);

  sendstringf("csbase=%6\n",vmread(vm_guest_cs_base));
  sendstringf("rip=%6\n",vmread(vm_guest_rip));

  {
    UINT64 ripaddress UNUSED=vmread(vm_guest_cs_base)+vmread(vm_guest_rip);
    sendstringf("ripaddress=%x\n", ripaddress);

    sendstringf("Rip=%6", vmread(vm_guest_cs_base)+vmread(vm_guest_rip));

  }

  sendstringf("guest cs=%8\n\r",vmread(vm_guest_cs));

  if (IS64BITCODE(currentcpuinfo))
  {
	  sendstringf("guest rip=%6\n\r",vmread(vm_guest_rip));
  }
  else
  {
	  sendstringf("guest eip=%8\n\r",vmread(vm_guest_rip));
  }
  sendstring("Instruction = ");
  ShowCurrentInstruction(currentcpuinfo);

  while (1)
  {

    sendstring("/-----------------VM-EXIT --------------\\\n\r");
    sendstring("|   1: resume virtual machine           |\n\r");
    sendstring("|   2: show state of virtual machine    |\n\r");
    sendstring("|   3: show memory of virtual machine   |\n\r");
    sendstringf("|   4: increase verbosity (%d)          |\n\r", verbosity);
    sendstringf("|   5: decrease verbosity (%d)          |\n\r", verbosity);
    sendstring("|   6: show instruction memory          |\n\r");
    sendstringf("|   7: toggle debugmode (%d)             |\n\r",debugmode);
    sendstring("|   8: set breakpoint                   |\n\r");
    sendstring("|   9: display physical memory          |\n\r");
    sendstring("|   l: Lua Engine                       |\n\r");
    sendstring("|   0: quit virtual machine             |\n\r");
    sendstring("|   d: test if inside another dbvm      |\n\r");
    sendstring("\\---------------------------------------/\n\r");
    sendstring("Your command:");

#ifdef DELAYEDSERIAL
    if (!useserial)
      command='1';
    else
#endif
    command=waitforchar();
    sendstring("\n\r");

    switch (command)
    {
      case  '1' :
        result=handleVMEvent(currentcpuinfo, (VMRegisters*)registers, fxsave);

        if (dbvm_plugin_exit_post)
          dbvm_plugin_exit_post(exportlist, currentcpuinfo, registers, fxsave, &result);

        if (currentcpuinfo->NMIOccured==2)
        {
          currentcpuinfo->NMIOccured=0;
          return raiseNMI();
        }

        if (currentcpuinfo->cpunr)
        {

        }

        if ((result!=0) && ((result >> 8)!=0xce))
        {
          sendstring("EVENT DID NOT GET HANDLED\n");

        }

        return result;

      case  '2' :
  	sendvmstate(currentcpuinfo, (VMRegisters*)registers);
  	break;

      case  '3' :
        displayVMmemory(currentcpuinfo);
  	break;

      case  '4' :
        verbosity++;
        break;

      case '5':
        verbosity--;
        break;

      case  '6' :
      {
        sendstring("Going to show the instruction:\n\r");
        ShowCurrentInstructions(currentcpuinfo);

        break;
      }

      case  '7' :
        debugmode=!debugmode;
        break;

      case  '8' :
      {
        char temps[17];
        UINT64 BreakAddress;

        regDR7 dr7;
        dr7.DR7=vmread(vm_guest_dr7);

        sendstring("Startaddress:");
        readstring(temps,16,16);
        sendstring("\n\r");
        BreakAddress=atoi2(temps,16,NULL);
        setDR0(BreakAddress);

        dr7.L0=1;
        dr7.G0=1;
        dr7.RW0=0;
        dr7.LEN0=0;
        vmwrite(vm_guest_dr7,(UINT64)dr7.DR7);

        breakpointset=1;
        break;
      }

      case  'W' :
      {
        char temps[17];
        UINT64 BreakAddress;

        regDR7 dr7;
        dr7.DR7=vmread(vm_guest_dr7);

        sendstring("Startaddress:");
        readstring(temps,16,16);
        sendstring("\n\r");
        BreakAddress=atoi2(temps,16,NULL);
        setDR0(BreakAddress);

        dr7.L0=1;
        dr7.G0=1;
        dr7.RW0=1;
        dr7.LEN0=0;
        vmwrite(vm_guest_dr7,(UINT64)dr7.DR7);

        breakpointset=1;
        break;
      }

      case  '9' :
      {
        displayPhysicalMemory();
        break;

      }

  		case  '0' :
        sendstringf("Leaving vmm mode (RSP=%x)\n\r",getRSP());

        sendstring("Returning 1\n\r");
  			return 1;

      case  'a' :
      {

        char temps[17];
        int bits;
        UINT64 address;
        int size;
        int err1,err2,err3;
        _DecodedInst disassembled[16];
        _DecodeType dt=Decode16Bits;
        int i;
        unsigned int used=0;

        Access_Rights cs_accessright;
        cs_accessright.AccessRights=vmread(vm_guest_cs_access_rights);
        if (cs_accessright.D_B==0)
          dt=Decode16Bits;
        else
          dt=Decode32Bits;

        if (IS64BITPAGING(currentcpuinfo))
          dt=Decode32Bits;

        if (IS64BITCODE(currentcpuinfo))
          dt=Decode64Bits;

        if (ISREALMODE(currentcpuinfo))
          dt=Decode16Bits;

        sendstring("Bitmode(");
        if (dt==Decode16Bits)
        {
          sendstring("16):");
        }
        else
        if (dt==Decode32Bits)
        {
          sendstring("32):");
        }
        else
        if (dt==Decode64Bits)
        {
          sendstring("64):");
        }

        readstring(temps,2,16);
        bits=atoi2(temps,10,&err1);

        if (bits==16)
          dt=Decode16Bits;
        else
        if (bits==32)
          dt=Decode32Bits;
        else
        if (bits==64)
          dt=Decode64Bits;
        else
        {
          sendstring("default bits");
        }

        sendstring("\n\rAddress:");
        readstring(temps,16,17);
        sendstringf("Address= %s \n",temps);
        address=atoi2(temps,16,&err2);

        sendstring("\n\rNumber of bytes:");
        readstring(temps,16,17);
        size=atoi2(temps,10,&err3);

        sendstringf("\naddress=%6, size=%d: (e1=%d e2=%d e3=%d)\n", address, size,err1,err2,err3);

        {
          int readable=0;
          int disassemblecount=0;
          int oldcurrentaddress;

          unsigned char buf[size];
          readable=ReadVMMemory(currentcpuinfo, address,buf,size);
          if (readable)
          {
            UINT64 currentaddress=address;

            while ((UINT64)currentaddress<(UINT64)((UINT64)address+(UINT64)size))
            {
              used=0;
              distorm_decode(currentaddress,&buf[disassemblecount], size, dt, disassembled, 16, &used);

              if (used)
              {

                for (i=0; (unsigned)i<used; i++)
                {
                  sendstringf("%8 : %s - %s %s\n\r",
                        disassembled[i].offset,
                        disassembled[i].instructionHex.p,
                        disassembled[i].mnemonic.p,
                        disassembled[i].operands.p);
                }

                oldcurrentaddress=currentaddress;

                currentaddress=(UINT64)disassembled[used-1].offset+(UINT64)disassembled[used-1].size;

                disassemblecount+=(currentaddress-oldcurrentaddress);
                sendstringf("(debug)currentaddress=%x\n\r",currentaddress);
              }
              else
              {
                sendstring("Disassemble failed\n\r");
                break;
              }
            }

          }
          else
          {
        	sendstring("\n\rError reading memory\n\r");
          }
        }

        break;

      }

      case  'c' :
      {
        CheckCRCValues();
        break;
      }

      case 'd':
      {
        int v=getDBVMVersion();
        if (v)
          sendstringf("Yes: %x\n",v);
        else
          sendstring("No\n");

        break;
      }

      case 'l' :
      {
#if (defined SERIALPORT) && (SERIALPORT != 0)
        enterLuaConsole();
#endif
        break;
      }

#ifdef DEBUG
      case  'p' :
      {
        displayPreviousStates();
        break;

      }
#endif

      case  'r' :
      {
        sendstring("retry\n\r");

        return 0;
      }

      case  'i' :
      {

        break;
      }

      case  's' :
      {
        vmx_enableSingleStepMode();

        break;
      }

      case 'm':
      {
        ept_hideDBVMPhysicalAddressesAllCPUs();
        break;
      }

#ifdef USENMIFORWAIT
      case 'n':
      {
        pcpuinfo c=firstcpuinfo;
        while (c)
        {
          if (c!=currentcpuinfo)
          {
            c->WaitingTillDone=0;
            c->WaitTillDone=1;
            apic_sendWaitInterrupt(c->apicid-1);
            while (c->WaitingTillDone==0) _pause();

            sendstringf("%d paused %d\n", currentcpuinfo->cpunr, c->cpunr);

            c->WaitTillDone=0;
          }
          c=c->next;
        }
        break;
      }
#endif

      default:
        sendstring("Unknown command\n\r");
        break;
  	}
  }

  return 1;
}

void launchVMX_AMD(pcpuinfo currentcpuinfo, POriginalState originalstate)
{
  int result;

  displayline("Calling vmxloop_amd with currentcpuinfo=%6\n\r",(UINT64)currentcpuinfo);

  sendvmstate(currentcpuinfo, NULL);

  nosendchar[getAPICID()]=0;
  sendstring("Starting...:\n");

  writeMSR(IA32_GS_BASE_MSR, (UINT64)0xcece);

  void *hoststate=malloc(4096);

  if (originalstate)
    result=vmxloop_amd(currentcpuinfo, currentcpuinfo->vmcb_PA, VirtualToPhysical(hoststate), &originalstate->rax);
  else
    result=vmxloop_amd(currentcpuinfo, currentcpuinfo->vmcb_PA, VirtualToPhysical(hoststate), NULL);

  nosendchar[getAPICID()]=0;
  sendstringf("Returned from vmxloop_amd. Result=%d\n\r", result);

  while (1);

}

void launchVMX(pcpuinfo currentcpuinfo)
{

  int result;
  OriginalState os;
  POriginalState originalstate=NULL;
  int restorestate=((loadedOS) && ((currentcpuinfo->isboot) || (APStartsInSIPI==0)));

  if (restorestate)
  {
    POriginalState pos=(POriginalState)mapPhysicalMemory(loadedOS,sizeof(OriginalState));
    os=*pos;
    originalstate=&os;
    unmapPhysicalMemory(pos, sizeof(OriginalState));
  }

  outportb(0x80,0x01);

  if (isAMD)
    return launchVMX_AMD(currentcpuinfo, originalstate);

  displayline("Calling vmxloop with currentcpuinfo=%6\n\r",(UINT64)currentcpuinfo);

  sendstring("Right before entering the loop:\n");

  if (currentcpuinfo->cpunr==0)
  {
    sendvmstate(currentcpuinfo,NULL);
    displayline("Last display before entering vmx\n");

  }

  outportb(0x80,0x02);

  if (restorestate)
    result=vmxloop(currentcpuinfo, &originalstate->rax);
  else
    result=vmxloop(currentcpuinfo, NULL);

  outportb(0x80,0xCF);

  displayline("VMXLOOP EXIT: APICID=%d\n\r",getAPICID());
  nosendchar[getAPICID()]=0;
  if (result==0)
    displayline("%d: vmxloop was successfull and returned normal (as in it quit the loop)\n\r", currentcpuinfo->cpunr);
  else
  if (result==1)
    displayline("%d: vmxloop returned 1, meaning vmlaunch failed completly\n\r", currentcpuinfo->cpunr);
  else
  if (result==2)
  {
    displayline("%d: vmxloop returned 2, meaning vmlaunch only failed half\n\r", currentcpuinfo->cpunr);
  }
  else
    displayline("%d: vmxloop returned %d. WEIRD ERROR!\n\r", currentcpuinfo->cpunr,result);

  displayline("%d: VM error code=%8\n\r", currentcpuinfo->cpunr, vmread(vm_errorcode));
  displayline("%d: Exit reason=%8\n\r", currentcpuinfo->cpunr, vmread(vm_exit_reason));
  displayline("%d: currentcpuinfo=%6\n\r", currentcpuinfo->cpunr, (UINT64)currentcpuinfo);

  if (vmread(vm_errorcode)==7)
  {
    sendstringf("Invalid control fields\n");
    QWORD VMX_BASIC UNUSED=readMSR(IA32_VMX_BASIC_MSR);
    QWORD VMX_PINBASED_CTLS UNUSED=readMSR(IA32_VMX_PINBASED_CTLS_MSR);
    QWORD VMX_PROCBASED_CTLS UNUSED=readMSR(IA32_VMX_PROCBASED_CTLS_MSR);

    QWORD VMX_EXIT_CTLS UNUSED=readMSR(IA32_VMX_EXIT_CTLS_MSR);
    QWORD VMX_ENTRY_CTLS UNUSED=readMSR(IA32_VMX_ENTRY_CTLS_MSR);
    QWORD VMX_MISC UNUSED=readMSR(IA32_VMX_MISC_CTLS_MSR);

    DWORD ctrl_pin UNUSED=vmread(vm_execution_controls_pin);
    sendstringf("VMX_PINBASED_CTLS=%6 ctrl_pin=%8\n", VMX_PINBASED_CTLS, ctrl_pin);

    DWORD ctrl_cpu UNUSED=vmread(vm_execution_controls_cpu);
    sendstringf("VMX_PROCBASED_CTLS=%6 ctrl_cpu=%8\n", VMX_PROCBASED_CTLS, ctrl_cpu);

    DWORD ctrl_entry UNUSED=vmread(vm_entry_controls);
    sendstringf("VMX_ENTRY_CTLS=%6 ctrl_entry=%8\n", VMX_ENTRY_CTLS, ctrl_entry);

    DWORD ctrl_exit UNUSED=vmread(vm_exit_controls);
    sendstringf("VMX_EXIT_CTLS=%6 ctrl_exit=%8\n", VMX_EXIT_CTLS, ctrl_exit);

  }

}

void displayVMmemory(pcpuinfo currentcpuinfo)
{
  char temps[17];
  UINT64 StartAddress;
  int nrofbytes;
  int i,j;
  unsigned char buf[17];
  int err=0;
#ifdef DEBUG

  int notpaged=0;
#endif

  sendstring("Startaddress:");
  readstring(temps,16,17);
  sendstring("\n\r");
  StartAddress=atoi2(temps,16,&err);

  sendstringf("%6(%s) has physical address %6\n\r",StartAddress,temps, getPhysicalAddressVM(currentcpuinfo, StartAddress, &notpaged));

  if (err)
  {
    sendstringf("err=%d\n");
  }

  sendstring("Number of bytes:");
  readstring(temps,8,8);
  sendstring("\n\r");
  nrofbytes=atoi2(temps,10,NULL);

  for (i=0; i<nrofbytes; i+=16)
  {

    if (ReadVMMemory(currentcpuinfo, StartAddress+i,buf,16)==0)
    {
      sendstringf("Read error\n\r");
      return;
    }

    sendstringf("%6 : ",StartAddress+i);
    for (j=i; j<(i+16) && (j<nrofbytes); j++)
      sendstringf("%2 ",buf[j%16]);

    if ((i+16)>nrofbytes)
    {

      int currentcol=11+3*(nrofbytes-i);
      int wantedcol=11+3*16;
      for (j=0; j<(wantedcol-currentcol); j++)
        sendstring(" ");
    }

    for (j=i; j<(i+16) && (j<nrofbytes); j++)
    {
      unsigned char tempc=buf[j%16];
      if (tempc<32)
        tempc='.';

      sendstringf("%c",tempc);
    }

    sendstring("\n\r");
  }

}

void ShowPendingInterrupts()
{
  int i,j;

  for (i=0; i<8; i++)
  {
    DWORD v=ReadAPICRegister(0x20+i);
    if (v!=0)
    {
      int startint=i*32;
      for (j=0; j<32; j++)
      {
        if (v & (1<<j))
          sendstringf("%2 ", startint+j);
      }
    }
  }
}

void ShowCurrentInstruction(pcpuinfo currentcpuinfo)
{
  unsigned char buf[60];
  int is64bit=IS64BITCODE(currentcpuinfo);
  QWORD address;

  if (isAMD)
  {
    if (is64bit)
      address=currentcpuinfo->vmcb->RIP;
    else
      address=currentcpuinfo->vmcb->cs_base+currentcpuinfo->vmcb->RIP;
  }
  else
  {
    if (is64bit)
      address=vmread(vm_guest_rip);
    else
      address=vmread(vm_guest_cs_base)+vmread(vm_guest_rip);
  }

  int br=ReadVMMemory(currentcpuinfo, address, buf, 60);

  if (br)
  {

    _DecodedInst disassembled[22];
    _DecodeType dt=Decode16Bits;
    Access_Rights cs_accessright;
    unsigned int used=0;

    if (isAMD)
    {
      Segment_Attribs csa;
      csa.SegmentAttrib=currentcpuinfo->vmcb->cs_attrib;
      cs_accessright.D_B=csa.D_B;
    }
    else
      cs_accessright.AccessRights=vmread(vm_guest_cs_access_rights);

    if (cs_accessright.D_B==0)
      dt=Decode16Bits;
    else
      dt=Decode32Bits;

    if (IS64BITPAGING(currentcpuinfo))
      dt=Decode32Bits;

    if (IS64BITCODE(currentcpuinfo))
      dt=Decode64Bits;

    if (ISREALMODE(currentcpuinfo))
      dt=Decode16Bits;

    distorm_decode(address,buf, 60, dt, disassembled, 22, &used);
    if (used)
    {
      sendstringf("%6 : %s - %s %s\n\r",
                    disassembled[0].offset,
                    disassembled[0].instructionHex.p,
                    disassembled[0].mnemonic.p,
                    disassembled[0].operands.p);

    }

  }
  else
  {
    sendstring("Unreadable memory\n");
  }
}

void ShowCurrentInstructions(pcpuinfo currentcpuinfo)
{
#define BUFSIZE 120
  unsigned char buf[BUFSIZE];
  int     readable;
  int     is64bit=IS64BITCODE(currentcpuinfo);
  UINT64 address;

  if (isAMD)
  {
    if (is64bit)
      address=currentcpuinfo->vmcb->RIP;
    else
      address=currentcpuinfo->vmcb->cs_base+currentcpuinfo->vmcb->RIP;
  }
  else
  {
    if (is64bit)
      address=vmread(vm_guest_rip);
    else
      address=vmread(vm_guest_cs_base)+vmread(vm_guest_rip);
  }

  int bytesinfront=BUFSIZE / 2;
  UINT64 startaddress=address-bytesinfront;

  readable=ReadVMMemory(currentcpuinfo, startaddress,buf,BUFSIZE);

  while (!readable)
  {
    startaddress=address-bytesinfront;
    readable=ReadVMMemory(currentcpuinfo, startaddress,buf,BUFSIZE);
    if (!readable)
    {
      if (bytesinfront==0)
      {

        sendstringf("%6 is unreadable\n\r",address);
        break;
      }
      bytesinfront=bytesinfront / 2;
    }
  }

  if (readable)
  {

    _DecodedInst disassembled[BUFSIZE/2];
    _DecodeType dt=Decode16Bits;
    Access_Rights cs_accessright;
    unsigned int i;
    unsigned int used=0;

    if (isAMD)
    {
      Segment_Attribs csa;
      csa.SegmentAttrib=currentcpuinfo->vmcb->cs_attrib;
      cs_accessright.D_B=csa.D_B;
    }
    else
      cs_accessright.AccessRights=vmread(vm_guest_cs_access_rights);

    if (cs_accessright.D_B==0)
      dt=Decode16Bits;
    else
      dt=Decode32Bits;

    if (IS64BITPAGING(currentcpuinfo))
      dt=Decode32Bits;

    if (IS64BITCODE(currentcpuinfo))
      dt=Decode64Bits;

    if (ISREALMODE(currentcpuinfo))
      dt=Decode16Bits;

    distorm_decode64(startaddress,buf, BUFSIZE, dt, disassembled, BUFSIZE / 2, &used);

    if (used)
    {
      for (i=0; i<used; i++)
      {
        if (disassembled[i].offset==address)
        {
          sendstring(">>");
        }

        sendstringf("%6 : %s - %s %s\n\r",
              disassembled[i].offset,
              disassembled[i].instructionHex.p,
              disassembled[i].mnemonic.p,
              disassembled[i].operands.p);
      }
    }
    else
    {
    	sendstring("Disassemble failed\n\r");
    }

  }
}

void displayPhysicalMemory(void)
{
  unsigned int i;
  char temps[17];
  UINT64 StartAddress;
  unsigned int nrofbytes;

  sendstring("Startaddress:");
  readstring(temps,16,17);
  sendstring("\n\r");
  temps[16]=0;
  StartAddress=atoi2(temps,16,NULL);
  sendstringf("Startaddress=%6\n\r",StartAddress);

  sendstring("Number of bytes:");
  readstring(temps,8,17);
  sendstring("\n\r");
  nrofbytes=atoi2(temps,10,NULL);

  sendstringf("Going to show the memory region %6 to %6 \n\r",StartAddress,StartAddress+nrofbytes);

  unsigned char *memory=(unsigned char *)mapPhysicalMemory(StartAddress, nrofbytes);
  for (i=0; i<nrofbytes; i+=16)
  {
    int j;
    unsigned char bt;
    sendstringf("%6 : ",StartAddress+i);
    for (j=0; j<16; j++)
    {
      bt=memory[i+j];
      sendstringf("%2 ",bt);
    }

    sendstring("  ");

    for (j=0; j<16; j++)
    {
      bt=memory[i+j];
      if ((bt<32) || (bt>0x80) )
        bt='.';
      sendstringf("%c",bt);
    }

    sendstring("\n\r");
  }
  unmapPhysicalMemory(memory, nrofbytes);
}
