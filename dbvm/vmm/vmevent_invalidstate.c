#include "vmevent_invalidstate.h"
#include "realmodeemu.h"
#include "pmodeemu.h"
#include "vmreadwrite.h"
#include "mm.h"
#include "vmxsetup.h"

int fixInterruptabilityState(void)
{
  DWORD is=vmread(vm_guest_interruptability_state);
  DWORD originalis=is;
  RFLAGS guestrflags;
  VMEntry_interruption_information entryinterrupt;
  guestrflags.value=vmread(vm_guest_rflags);

  int handled=0;

  is=is & 0x1f;

  if ((guestrflags.IF==0) && (is & (1<<0)))
    is=is & 0x1e;

  if ((is & 3)==3)

    is=is & 0x1e;

  entryinterrupt.interruption_information=vmread(vm_entry_interruptioninfo);
  if (entryinterrupt.valid)
  {
    if (entryinterrupt.type==0)
      is = is & 0x1c;

    if (entryinterrupt.type==2)
      is = is & 0x1d;
  }

  vmwrite(vm_guest_interruptability_state, is);

  return is!=originalis;
}

VMSTATUS handleInvalidEntryState(pcpuinfo currentcpuinfo,VMRegisters *vmregisters)
{
  RFLAGS guestrflags;
  guestrflags.value=vmread(vm_guest_rflags);

  outportb(0x80,0xce);

#ifdef DELAYEDSERIAL
  useserial=1;
#endif

  outportb(0x80,0xc0);
  enableserial();

  nosendchar[getAPICID()]=0;

  sendstring("Handling invalid entry state\n\r");

  if (((guestrflags.TF) || (vmread(vm_guest_IA32_DEBUGCTL) & (1<<1))) && ((vmread(vm_pending_debug_exceptions) & (1<<14))==0))
  {

    sendstring("Setting pending debug exception\n\r");
    vmwrite(vm_pending_debug_exceptions, vmread(vm_pending_debug_exceptions) | (1<<14) );
    return VM_OK;
  }

  if (fixInterruptabilityState())
  {

    return VM_OK;
  }

  if (!IS64BITCODE(currentcpuinfo))
  {
    if (vmread(vm_guest_rip)>0xffffffff)
    {
      vmwrite(vm_guest_rip,vmread(vm_guest_rip)&0xffffffff);
      return VM_OK;
    }
  }

  if (ISREALMODE(currentcpuinfo))
  {
    int result;

    outportb(0x80,0xc5);

    sendstring("Inside realmode. Trying to emulate instructions\n\r");
    result=emulateRealMode(currentcpuinfo, vmregisters)==0;

    sendstringf("emulateRealMode(...) returned %d\n\r",result);

    if (result==TRUE)
    {

      sendstring("emulation was handled properly\n");

      return VM_OK;
    }
    else
      sendstring("emulation was a total failure. Not one instruction got emulated. Trying to fix the state");

    if (ISREALMODE(currentcpuinfo))
    {
      if (hasUnrestrictedSupport)
      {

        QWORD cr0=vmread(vm_guest_cr0);
        if (cr0 & CR0_PG)
        {
          sendstringf("paging on in realmode\n");
          while (1) outportb(0x80,0xe0);
        }

        if (cr0 & CR0_PE)
        {
          sendstringf("protected mode in realmode\n");
          while (1) outportb(0x80,0xe0);
        }

        if (vmread(vm_entry_controls) & VMENTRYC_IA32E_MODE_GUEST)
        {
          sendstringf("ia32e mode entry in realmode\n");
          while (1) outportb(0x80,0xe1);
        }

        RFLAGS rflags;
        rflags.value=(QWORD)vmread(vm_guest_rflags);
        if (rflags.VM) while (1) outportb(0x80,0xe2);
        if (rflags.VIF) while (1) outportb(0x80,0xe2);
        if (rflags.VIP) while (1) outportb(0x80,0xe2);
        if (vmread(vm_guest_tr) & (1 << 2)) while (1) outportb(0x80,0xe3);

        Access_Rights ar;
        Access_Rights ss;
        QWORD limit;
        ss.AccessRights=vmread(vm_guest_ss_access_rights);
        ar.AccessRights=vmread(vm_guest_ldtr_access_rights);
        if ((!ar.unusable) && (vmread(vm_guest_ldtr) & (1<<2))) while (1) outportb(0x80,0xe4);

        ar.AccessRights=vmread(vm_guest_cs_access_rights);
        switch (ar.Segment_type)
        {
          case 3:
          case 9:
          case 11:
          case 13:
          case 15:
            break;

          default:
            while (1) outportb(0x80,0xe5);
        }
        if (ar.S==0) while (1) outportb(0x80,0xe8);
        if (ar.P==0) while (1) outportb(0x80,0xed);
        if (ar.reserved || ar.reserved_2) while (1) outportb(0x80,0xee);
        if ((ar.Segment_type==3) && (ar.DPL!=0)) while (1) outportb(0x80,0xe9);
        if (((ar.Segment_type==9) || (ar.Segment_type==11)) && (ar.DPL!=ss.DPL)) while (1) outportb(0x80,0xea);
        if (((ar.Segment_type==13) || (ar.Segment_type==15)) && (ar.DPL>ss.DPL)) while (1) outportb(0x80,0xeb);

        limit=(QWORD)vmread(vm_guest_cs_limit);
        if (((limit & 0xfff)!=0xfff) && (ar.G!=0)) while (1) outportb(0x80,0xef);
        if ((limit & 0xFFF00000) && (ar.G==0)) while (1) outportb(0x80,0xf0);

        if (!ss.unusable)
        {
          switch (ss.Segment_type)
          {
            case 3:
            case 7:
              break;

            default:
              while (1) outportb(0x80,0xe6);
          }

          if (ss.S==0) while (1) outportb(0x80,0xe8);
          if (ss.P==0) while (1) outportb(0x80,0xed);
          if (ss.reserved || ss.reserved_2) while (1) outportb(0x80,0xee);
          if (ss.DPL!=0) while (1) outportb(0x80,0xec);

          limit=(QWORD)vmread(vm_guest_ss_limit);
          if (((limit & 0xfff)!=0xfff) && (ss.G!=0)) while (1) outportb(0x80,0xef);
          if ((limit & 0xFFF00000) && (ss.G==0)) while (1) outportb(0x80,0xf0);

        }

        ar.AccessRights=vmread(vm_guest_ds_access_rights);
        if (!ar.unusable)
        {
          if ((ar.Segment_type & 1)==0) while (1) outportb(0x80,0xe7);
          if ((ar.Segment_type & (1<<3)) && (((ar.Segment_type & (1<<1))==0))) while (1) outportb(0x80,0xe7);
          if (ar.S==0) while (1) outportb(0x80,0xe8);
          if (ar.P==0) while (1) outportb(0x80,0xed);
          if (ar.reserved || ar.reserved_2) while (1) outportb(0x80,0xee);

          limit=(QWORD)vmread(vm_guest_ds_limit);
          if (((limit & 0xfff)!=0xfff) && (ar.G!=0)) while (1) outportb(0x80,0xef);
          if ((limit & 0xFFF00000) && (ar.G==0)) while (1) outportb(0x80,0xf0);
        }

        ar.AccessRights=vmread(vm_guest_es_access_rights);
        if (!ar.unusable)
        {
          if ((ar.Segment_type & 1)==0) while (1) outportb(0x80,0xe7);
          if ((ar.Segment_type & (1<<3)) && (((ar.Segment_type & (1<<1))==0))) while (1) outportb(0x80,0xe7);
          if (ar.S==0) while (1) outportb(0x80,0xe8);
          if (ar.P==0) while (1) outportb(0x80,0xed);
          if (ar.reserved || ar.reserved_2) while (1) outportb(0x80,0xee);

          limit=(QWORD)vmread(vm_guest_es_limit);
          if (((limit & 0xfff)!=0xfff) && (ar.G!=0)) while (1) outportb(0x80,0xef);
          if ((limit & 0xFFF00000) && (ar.G==0)) while (1) outportb(0x80,0xf0);
        }

        ar.AccessRights=vmread(vm_guest_fs_access_rights);
        if (!ar.unusable)
        {
          if ((ar.Segment_type & 1)==0) while (1) outportb(0x80,0xe7);
          if ((ar.Segment_type & (1<<3)) && (((ar.Segment_type & (1<<1))==0))) while (1) outportb(0x80,0xe7);
          if (ar.S==0) while (1) outportb(0x80,0xe8);
          if (ar.P==0) while (1) outportb(0x80,0xed);
          if (ar.reserved || ar.reserved_2) while (1) outportb(0x80,0xee);

          limit=(QWORD)vmread(vm_guest_fs_limit);
          if (((limit & 0xfff)!=0xfff) && (ar.G!=0)) while (1) outportb(0x80,0xef);
          if ((limit & 0xFFF00000) && (ar.G==0)) while (1) outportb(0x80,0xf0);
        }

        ar.AccessRights=vmread(vm_guest_gs_access_rights);
        if (!ar.unusable)
        {
          if ((ar.Segment_type & 1)==0) while (1) outportb(0x80,0xe7);
          if ((ar.Segment_type & (1<<3)) && (((ar.Segment_type & (1<<1))==0))) while (1) outportb(0x80,0xe7);
          if (ar.S==0) while (1) outportb(0x80,0xe8);
          if (ar.P==0) while (1) outportb(0x80,0xed);
          if (ar.reserved || ar.reserved_2) while (1) outportb(0x80,0xee);

          limit=(QWORD)vmread(vm_guest_gs_limit);
          if (((limit & 0xfff)!=0xfff) && (ar.G!=0)) while (1) outportb(0x80,0xef);
          if ((limit & 0xFFF00000) && (ar.G==0)) while (1) outportb(0x80,0xf0);
        }

        ar.AccessRights=vmread(vm_guest_tr_access_rights);
        if ((ar.Segment_type!=3) && (ar.Segment_type!=11)) while (1) outportb(0x80,0xf1);
        if (ar.S!=0) while (1) outportb(0x80,0xf2);
        if (ar.P!=1) while (1) outportb(0x80,0xf3);
        if (ar.reserved || ar.reserved_2) while (1) outportb(0x80,0xf4);
        limit=(QWORD)vmread(vm_guest_tr_limit);
        if (((limit & 0xfff)!=0xfff) && (ar.G!=0)) while (1) outportb(0x80,0xf5);
        if ((limit & 0xFFF00000) && (ar.G==0)) while (1) outportb(0x80,0xf6);
        if (ar.unusable)  while (1) outportb(0x80,0xf7);

        ar.AccessRights=vmread(vm_guest_ldtr_access_rights);
        if (ar.unusable==0)
        {
          if (ar.Segment_type!=2) while (1) outportb(0x80,0xf8);
          if (ar.S!=0) while (1) outportb(0x80,0xf9);
          if (ar.P!=1) while (1) outportb(0x80,0xfa);
          limit=(QWORD)vmread(vm_guest_ldtr_access_rights);
          if (((limit & 0xfff)!=0xfff) && (ar.G!=0)) while (1) outportb(0x80,0xfb);
          if ((limit & 0xFFF00000) && (ar.G==0)) while (1) outportb(0x80,0xfc);
        }

        if (vmread(vm_guest_idt_limit)>65536) while (1) outportb(0x80,0xfd);

        if (vmread(vm_guest_rip)>(QWORD)0xffffffff) while (1) outportb(0x80,0xfe);

        QWORD rf=vmread(vm_guest_rflags);
        if (((rf & (1<<1))==0) || (rf & (1<<3)) || (rf & (1<<5)) || (rf & (1<<15)) || (rf & 0xFFFFFFFFFFC00000ULL) )  while (1) outportb(0x80,0xff);

        int activitystate=vmread(vm_guest_activity_state);

        int interruptability_state=vmread(vm_guest_interruptability_state);
        if (activitystate>3) while (1) outportb(0x80,0x10);
        if ((activitystate==1) && (ss.DPL!=0)) while (1) outportb(0x80,0x11);

        if ((interruptability_state & 3) && (activitystate!=0)) while (1) outportb(0x80,0x12);

        VMEntry_interruption_information ii;
        ii.interruption_information=vmread(vm_entry_interruptioninfo);
        if (ii.valid) while (1) outportb(0x80,0x13);

        if (interruptability_state & 0xFFFFFFE0) while (1) outportb(0x80,0x14);
        if ((interruptability_state & 3)==3) while (1) outportb(0x80,0x15);

        if ((rflags.IF==0) && (interruptability_state & 1))  while (1) outportb(0x80,0x16);

        if (interruptability_state & (1<<2)) while (1) outportb(0x80,0x17);

        cr0=(QWORD)vmread(vm_guest_cr0);
        QWORD cr0fixed0=(QWORD)readMSR(0x486);
        QWORD cr0fixed1=(QWORD)readMSR(0x487);

        cr0fixed0&=(QWORD)0xFFFFFFFF7FFFFFFE;
        if ((cr0 & cr0fixed0)!=cr0fixed0) while (1) outportb(0x80,0x18);
        if ((cr0 & cr0fixed1)!=cr0) while (1) outportb(0x80,0x19);

        if ((cr0 & (1<<29)) && ((cr0 & (1<<30))==0))  while (1) outportb(0x80,0x19);

        QWORD cr4=(QWORD)vmread(vm_guest_cr4);
        QWORD cr4fixed0=(QWORD)readMSR(0x488);
        QWORD cr4fixed1=(QWORD)readMSR(0x489);

        if ((cr4 & cr4fixed0)!=cr4fixed0) while (1) outportb(0x80,0x20);
        if ((cr4 & cr4fixed1)!=cr4) while (1) outportb(0x80,0x21);

        if (cr4 & (1<<23))  while (1) outportb(0x80,0x22);

        if (cr4 & (1<<17)) while (1) outportb(0x80,0x26);
        if ((cr4 & (1<<13))==0) while (1) outportb(0x80,0x27);

        if (vmread(vm_pending_debug_exceptions)) while (1) outportb(0x80,0x23);

        if ((QWORD)vmread(vm_vmcs_link_pointer) != (QWORD)0xffffffffffffffffULL) while (1) outportb(0x80,0x24);

        if ((QWORD)vmread(vm_guest_IA32_DEBUGCTL))  while (1) outportb(0x80,0x25);

        if (activitystate==3)
        {
          QWORD secproc=(QWORD)vmread(vm_execution_controls_cpu_secondary);
          if ((secproc & (1<<7))==0) while (1) outportb(0x80,0x27);
          if ((secproc & (1<<1))==0) while (1) outportb(0x80,0x28);

          while (1) outportb(0x80,0x26);
        }

        while (1)
        {
          if (rflags.IF==1)
            outportb(0x80,0x00);
          else
          {
            if (currentcpuinfo->cpunr==0)
              outportb(0x80,0x01);
            else
              outportb(0x80,vmread(vm_guest_rip));
          }
        }

      }
      else
      {
        Access_Rights reg_rmaccessrights,reg_traccessrights;
        RFLAGS guestrflags;
        DWORD gdtbase, idtbase;
        guestrflags.value=0;

        gdtbase=VirtualToPhysical((void *)getGDTbase());
        idtbase=VirtualToPhysical(idttable32);

        sendstring("Still in realmode, enabling VMx86 mode if not already in it and fixing possible other bugs\n\r");

        vmwrite(vm_guest_gdtr_base, gdtbase);
        vmwrite(vm_guest_gdt_limit, getGDTsize());
        vmwrite(vm_guest_idtr_base, idtbase);
        vmwrite(vm_guest_idt_limit, 256*8);
        setupTSS8086();
        vmwrite(vm_guest_tr_base,(UINT64)VirtualToPhysical(VirtualMachineTSS_V8086));
        vmwrite(vm_guest_tr_limit,(ULONG)sizeof(TSS)+32+8192+1);
        vmwrite(vm_guest_tr,64);

  #ifdef DEBUG
        UINT64 idtbase2, gdtbase2;
        gdtbase2=vmread(vm_guest_gdtr_base);
        idtbase2=vmread(vm_guest_idtr_base);

        sendstringf("Set vm_guest_gdtr_base to %6 while I wanted to set it to %6\n\r",gdtbase2, gdtbase);
        sendstringf("Set vm_guest_idtr_base to %6 while I wanted to set it to %6\n\r",idtbase2, idtbase);
  #endif

        reg_rmaccessrights.AccessRights=0;
        reg_rmaccessrights.Segment_type=3;
        reg_rmaccessrights.S=1;
        reg_rmaccessrights.DPL=3;
        reg_rmaccessrights.P=1;
        reg_rmaccessrights.G=0;
        reg_rmaccessrights.D_B=0;

        reg_traccessrights.AccessRights=0;
        reg_traccessrights.Segment_type=11;
        reg_traccessrights.S=0;
        reg_traccessrights.DPL=0;
        reg_traccessrights.P=1;
        reg_traccessrights.G=0;
        reg_traccessrights.D_B=1;
        vmwrite(vm_guest_es_access_rights,(ULONG)reg_rmaccessrights.AccessRights);
        vmwrite(vm_guest_cs_access_rights,(ULONG)reg_rmaccessrights.AccessRights);
        vmwrite(vm_guest_ss_access_rights,(ULONG)reg_rmaccessrights.AccessRights);
        vmwrite(vm_guest_ds_access_rights,(ULONG)reg_rmaccessrights.AccessRights);
        vmwrite(vm_guest_fs_access_rights,(ULONG)reg_rmaccessrights.AccessRights);
        vmwrite(vm_guest_gs_access_rights,(ULONG)reg_rmaccessrights.AccessRights);
        vmwrite(vm_guest_ldtr_access_rights,(ULONG)(1<<16));
        vmwrite(vm_guest_tr_access_rights,(ULONG)reg_traccessrights.AccessRights);

        vmwrite(vm_guest_es,(ULONG)vmread(vm_guest_es_base) >> 4);
        vmwrite(vm_guest_cs,(ULONG)vmread(vm_guest_cs_base) >> 4);
        vmwrite(vm_guest_ss,(ULONG)vmread(vm_guest_ss_base) >> 4);
        vmwrite(vm_guest_ds,(ULONG)vmread(vm_guest_ds_base) >> 4);
        vmwrite(vm_guest_fs,(ULONG)vmread(vm_guest_fs_base) >> 4);
        vmwrite(vm_guest_gs,(ULONG)vmread(vm_guest_gs_base) >> 4);
        vmwrite(vm_guest_ldtr,(ULONG)0);
        vmwrite(vm_guest_tr,(ULONG)0);

        vmwrite(vm_guest_es_limit,(ULONG)0xffff);
        vmwrite(vm_guest_cs_limit,(ULONG)0xffff);
        vmwrite(vm_guest_ss_limit,(ULONG)0xffff);
        vmwrite(vm_guest_ds_limit,(ULONG)0xffff);
        vmwrite(vm_guest_fs_limit,(ULONG)0xffff);
        vmwrite(vm_guest_gs_limit,(ULONG)0xffff);

        guestrflags.value=vmread(vm_guest_rflags);
        guestrflags.IOPL=3;
        guestrflags.VM=1;

        vmwrite(vm_guest_rflags,guestrflags.value);
      }

      return VM_OK;
    }
  }
  else
  {
    WORD segment,segment2;
    Access_Rights tempAR;
    int handled=0;

    while (1)
      outportb(0x80,0xf0);

    sendstring("Not in realmode and in an invalid entry state\n");
    sendstring("Emulating instruction\n");
    handled=emulateProtectedMode(currentcpuinfo, vmregisters);

    if (handled)
      return VM_OK;

    sendstring("Emulation failed, trying to force state to be valid\n");

    tempAR.AccessRights=vmread(vm_guest_cs_access_rights);
    if ((tempAR.Segment_type & 1)==0)
    {
      sendstringf("Code segment was usable but not accessed (Let me guess, it's Bochs?)\n");
      tempAR.Segment_type=tempAR.Segment_type | 1;
      vmwrite(vm_guest_cs_access_rights, tempAR.AccessRights);
      handled=1;
    }

    tempAR.AccessRights=vmread(vm_guest_ds_access_rights);
    if ((tempAR.unusable==0) && ((tempAR.Segment_type & 1)==0))
    {
      sendstringf("DS segment was usable but not accessed\n");
      tempAR.Segment_type=tempAR.Segment_type | 1;
      vmwrite(vm_guest_ds_access_rights, tempAR.AccessRights);
      handled=1;
    }

    tempAR.AccessRights=vmread(vm_guest_es_access_rights);
    if ((tempAR.unusable==0) && ((tempAR.Segment_type & 1)==0))
    {
      sendstringf("ES segment was usable but not accessed\n");
      tempAR.Segment_type=tempAR.Segment_type | 1;
      vmwrite(vm_guest_es_access_rights, tempAR.AccessRights);
      handled=1;
    }

    tempAR.AccessRights=vmread(vm_guest_fs_access_rights);
    if ((tempAR.unusable==0) && ((tempAR.Segment_type & 1)==0))
    {
      sendstringf("FS segment was usable but not accessed\n");
      tempAR.Segment_type=tempAR.Segment_type | 1;
      vmwrite(vm_guest_fs_access_rights, tempAR.AccessRights);
      handled=1;
    }

    tempAR.AccessRights=vmread(vm_guest_gs_access_rights);
    if ((tempAR.unusable==0) && ((tempAR.Segment_type & 1)==0))
    {
      sendstringf("GS segment was usable but not accessed\n");
      tempAR.Segment_type=tempAR.Segment_type | 1;
      vmwrite(vm_guest_gs_access_rights, tempAR.AccessRights);
      handled=1;
    }

    segment=vmread(vm_guest_ss);
    segment2=vmread(vm_guest_cs);

    if ((segment & 3) != (segment2 & 3))
    {
      sendstringf("SS(%x).rpl != CS(%x).rpl\n",segment,segment2);
      segment=(segment & 0xfffc) | (segment2 & 3);
      sendstringf("Setting SS to %x\n",segment);
      vmwrite(vm_guest_ss, segment);

      tempAR.AccessRights=vmread(vm_guest_ss_access_rights);
      tempAR.DPL=(segment & 3);
      vmwrite(vm_guest_ss_access_rights, tempAR.AccessRights);
      handled=1;
    }

    UINT64 oldcr0,newcr0;
    UINT64 oldcr4,newcr4;

    oldcr0=vmread(vm_guest_cr0);
    oldcr4=vmread(vm_guest_cr4);

    newcr0=(oldcr0 | (UINT64)IA32_VMX_CR0_FIXED0) & (UINT64)IA32_VMX_CR0_FIXED1;

    if (newcr0!=oldcr0)
    {
      sendstringf("old CR0 was %6 new CR0 is %6\n",oldcr0,newcr0);

      vmwrite(vm_guest_cr0, newcr0);
      handled=1;
    }

    newcr4=(oldcr4 | (UINT64)IA32_VMX_CR4_FIXED0) & (UINT64)IA32_VMX_CR4_FIXED1;
    if (newcr4!=oldcr4)
    {
      sendstringf("old CR4 was %6 new CR4 is %6\n",oldcr4,newcr4);
      vmwrite(vm_guest_cr4, newcr4);
      handled=1;
    }

    if (handled==1)
    {

      UINT64 rflags=vmread(vm_guest_rflags);
      PRFLAGS prflags=(PRFLAGS)&rflags;
      prflags->RF=1;
      vmwrite(vm_guest_rflags,rflags);
    }

    return (handled==0);

  }

  outportb(0x80,0xcc);
  while (1);
  return 0;
}
