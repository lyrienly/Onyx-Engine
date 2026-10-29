#include "common.h"
#include "main.h"
#include "realmodeemu.h"
#include "vmmhelper.h"
#include "vmpaging.h"
#include "vmreadwrite.h"
#include "distorm.h"

#include "vmeventhandler.h"
#include "vmcall.h"

#ifndef DEBUG
#define sendstringf(s,x...)
#define sendstring(s)
#endif

ULONG handleMODRM(VMRegisters *vmregisters, PINSTRUCTIONDATA id);
int getOpperand(PINSTRUCTIONDATA id);
int setSegment(int segmentnr, WORD value);
UINT64 getOpperandValue(VMRegisters *vmregisters, int opperand, _registerType registerType);
int emulateRMinterrupt(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, int intnr);
int emulateHLT(pcpuinfo currentcpuinfo, VMRegisters *vmregisters);
int getparityflag(unsigned char value);

int opcode_CALLE8(pcpuinfo currentcpuinfo, PINSTRUCTIONDATA id)
{
  int error;
  UINT64 pagefaultaddress;

  WORD newip;

  if (!id->opperandsize)
  {
    WORD *stack=(WORD *)mapVMmemory(currentcpuinfo, vmread(vm_guest_ss_base)+(vmread(vm_guest_rsp) & 0xffff)-2, 2, &error, &pagefaultaddress);
    signed short int offset=*(signed short int *)&id->instruction[id->size];
    sendstringf("%x:%x CALL near relative offset=%d\n\r",vmread(vm_guest_cs), vmread(vm_guest_rip), offset);
    id->size+=2;

    stack[0]=vmread(vm_guest_rip)+id->size;

    vmwrite(vm_guest_rsp, (vmread(vm_guest_rsp) & 0xffff0000) + (WORD)(vmread(vm_guest_rsp)-2));

    newip=vmread(vm_guest_rip);
    newip+=id->size;
    newip+=offset;

    vmwrite(vm_guest_rip,newip);

    id->size=0;

    unmapVMmemory(stack,2);
    return 2;
  }
  else
    return 1;

}

int opcode_HLTF4(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{

	sendstringf("opcode_HLTF4. HLT emu");
    vmwrite(vm_guest_rip,vmread(vm_guest_rip)+1);
    id->size=0;

    vmwrite(vm_guest_interruptability_state,0);

    emulateHLT(currentcpuinfo, vmregisters);

    return 2;
}

int opcode_INTCD(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{
  sendstringf("INT (CD).   Size=%d\n", id->size);
  if (id->size == 1)
  {

    vmwrite(vm_guest_rip, vmread(vm_guest_rip)+id->size+1);
    emulateRMinterrupt(currentcpuinfo, vmregisters, *(BYTE*)(&id->instruction[id->size]));
    return 2;
  }
  else
    return 1;

}

int opcode_JMPE9(pcpuinfo currentcpuinfo UNUSED, PINSTRUCTIONDATA id)
{
  if (!id->opperandsize)
  {

    WORD newip;
    WORD offset=*(WORD *)&id->instruction[id->size];
    sendstringf("%x:%x JMP near relative offset=%d\n\r",vmread(vm_guest_cs), vmread(vm_guest_rip), offset);
    id->size+=2;

    newip=vmread(vm_guest_rip);
    newip+=id->size;
    newip+=offset;

    vmwrite(vm_guest_rip,newip);

    id->size=0;
    return 2;
  }
  else
    return 1;

}

int opcode_JMPEA(PINSTRUCTIONDATA id)
{
  WORD newcodesegment;
  DWORD neweip;
  sendstring("JMP far\n\r");

  if (!id->opperandsize)
  {

    neweip=*(WORD *)&id->instruction[id->size];
    newcodesegment=*(WORD *)&id->instruction[id->size+2];
    id->size+=4;
  }
  else
  {

    neweip=*(DWORD *)&id->instruction[id->size];
    newcodesegment=*(WORD *)&id->instruction[id->size+2];
    id->size+=6;
  }

  vmwrite(vm_guest_rip, neweip);
  vmwrite(vm_guest_cs, newcodesegment);
  vmwrite(vm_guest_cs_base, newcodesegment << 4);
  vmwrite(vm_guest_cs_limit, 0xffff);

  id->size=0;
  return 2;
}

int opcode_JMPEB(PINSTRUCTIONDATA id)
{
  signed char offset=*(signed char *)&id->instruction[id->size];
  WORD newip;

  sendstringf("%x:%x JMP short offset=%d\n\r",vmread(vm_guest_cs), vmread(vm_guest_rip), offset);
  id->size+=1;
  newip=vmread(vm_guest_rip);
  newip+=id->size;
  newip+=offset;

  vmwrite(vm_guest_rip,newip);

  id->size=0;
  return 2;

}

int opcode_LGDT(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{
  sendstring("LGDT\n\r");

  handleMODRM(vmregisters, id);
  if (id->error)
    return 1;

  sendstringf("For address %x\n\r",id->address);

  BYTE *address=(BYTE *)mapVMmemory(currentcpuinfo, id->address, 16, NULL, NULL);
  WORD gdtlimit=*(WORD*)&address[0];
  DWORD gdtbase=*(DWORD*)&address[2];

  if (!id->opperandsize)
     gdtbase=gdtbase & 0x00FFFFFF;

  currentcpuinfo->RealMode.GDTBase=gdtbase;
  currentcpuinfo->RealMode.GDTLimit=gdtlimit;

  unmapVMmemory(address,16);
  return 0;
}

int opcode_LIDT(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{
  sendstring("LIDT\n\r");

  handleMODRM(vmregisters, id);
  if (id->error)
    return 1;

  sendstringf("For address %x\n\r",id->address);

  BYTE *address=(BYTE *)mapVMmemory(currentcpuinfo, id->address, 16, NULL, NULL);
  WORD idtlimit=*(WORD*)&address[0];
  DWORD idtbase=*(DWORD*)&address[2];

  if (!id->opperandsize)
     idtbase=idtbase & 0x00FFFFFF;

  currentcpuinfo->RealMode.IDTBase=idtbase;
  currentcpuinfo->RealMode.IDTLimit=idtlimit;

  unmapVMmemory(address,16);
  return 0;
}

int opcode_LMSW(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{

  int error;
  UINT64 pagefaultaddress;

  sendstring("LMSW\n\r");

  handleMODRM(vmregisters, id);
  if (id->error)
    return 1;

  if (id->opperand2==-1)
  {

    WORD *address=(WORD *)mapVMmemory(currentcpuinfo, id->address, 16, &error, &pagefaultaddress);

    sendstringf("id->address=%x\n\r",id->address);

    if (error)
    {
      sendstringf("Failure mapping memory %6\n\r", pagefaultaddress);
      return 1;
    }

    int r=setVM_CR0(currentcpuinfo, (vmread(vm_cr0_read_shadow) & 0xffff0000) | *address);

    unmapVMmemory(address, 16);
    return r;
  }
  else
  {

    switch (id->opperand2)
    {
      case 0: return setVM_CR0(currentcpuinfo, (vmread(vm_cr0_read_shadow) & 0xffff0000) | ( vmregisters->rax & 0xffff) );
      case 1: return setVM_CR0(currentcpuinfo, (vmread(vm_cr0_read_shadow) & 0xffff0000) | ( vmregisters->rcx & 0xffff) );
      case 2: return setVM_CR0(currentcpuinfo, (vmread(vm_cr0_read_shadow) & 0xffff0000) | ( vmregisters->rdx & 0xffff) );
      case 3: return setVM_CR0(currentcpuinfo, (vmread(vm_cr0_read_shadow) & 0xffff0000) | ( vmregisters->rbx & 0xffff) );
      case 4: return setVM_CR0(currentcpuinfo, (vmread(vm_cr0_read_shadow) & 0xffff0000) | ( vmread(vm_guest_rsp) & 0xffff) );
      case 5: return setVM_CR0(currentcpuinfo, (vmread(vm_cr0_read_shadow) & 0xffff0000) | ( vmregisters->rbp & 0xffff) );
      case 6: return setVM_CR0(currentcpuinfo, (vmread(vm_cr0_read_shadow) & 0xffff0000) | ( vmregisters->rsi & 0xffff) );
      case 7: return setVM_CR0(currentcpuinfo, (vmread(vm_cr0_read_shadow) & 0xffff0000) | ( vmregisters->rdi & 0xffff) );
    }

  }

  return 1;
}

int opcode_MOV0F20(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{

  sendstring("MOV 0F 20\n\r");

  handleMODRM(vmregisters, id);
  if (id->error)
    return 1;

  switch (id->opperand)
  {
    case 0:
      switch (id->opperand2)
      {
        case 0:
          vmregisters->rax=vmread(vm_cr0_read_shadow);
          return 0;

        case 1:
          vmregisters->rcx=vmread(vm_cr0_read_shadow);
          return 0;

        case 2:
          vmregisters->rdx=vmread(vm_cr0_read_shadow);
          return 0;

        case 3:
          vmregisters->rbx=vmread(vm_cr0_read_shadow);
          return 0;

        case 4:
          vmwrite(vm_guest_rsp,vmread(vm_cr0_read_shadow));
          return 0;

        case 5:
          vmregisters->rbx=vmread(vm_cr0_read_shadow);
          return 0;

        case 6:
          vmregisters->rsi=vmread(vm_cr0_read_shadow);
          return 0;

        case 7:
          vmregisters->rdi=vmread(vm_cr0_read_shadow);
          return 0;
      }

      break;

    case 3:
      switch (id->opperand2)
      {
        case 0:
          vmregisters->rax=currentcpuinfo->guestCR3;
          return 0;

        case 1:
          vmregisters->rcx=currentcpuinfo->guestCR3;
          return 0;

        case 2:
          vmregisters->rdx=currentcpuinfo->guestCR3;
          return 0;

        case 3:
          vmregisters->rbx=currentcpuinfo->guestCR3;
          return 0;

        case 4:
          vmwrite(vm_guest_rsp,currentcpuinfo->guestCR3);
          return 0;

        case 5:
          vmregisters->rbx=currentcpuinfo->guestCR3;
          return 0;

        case 6:
          vmregisters->rsi=currentcpuinfo->guestCR3;
          return 0;

        case 7:
          vmregisters->rdi=currentcpuinfo->guestCR3;
          return 0;
      }

      break;

    case 4:
      switch (id->opperand2)
      {
        case 0:
          vmregisters->rax=vmread(vm_cr4_read_shadow);
          return 0;

        case 1:
          vmregisters->rcx=vmread(vm_cr4_read_shadow);
          return 0;

        case 2:
          vmregisters->rdx=vmread(vm_cr4_read_shadow);
          return 0;

        case 3:
          vmregisters->rbx=vmread(vm_cr4_read_shadow);
          return 0;

        case 4:
          vmwrite(vm_guest_rsp,vmread(vm_cr4_read_shadow));
          return 0;

        case 5:
          vmregisters->rbx=vmread(vm_cr4_read_shadow);
          return 0;

        case 6:
          vmregisters->rsi=vmread(vm_cr4_read_shadow);
          return 0;

        case 7:
          vmregisters->rdi=vmread(vm_cr4_read_shadow);
          return 0;
      }

      break;

  }

  return 1;
}

int opcode_MOV0F22(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{

  sendstring("MOV 0F 22\n\r");

  handleMODRM(vmregisters, id);
  if (id->error)
    return 1;

  switch (id->opperand)
  {
    case 0:
      sendstringf("old CR0=%8\n\r", vmread(vm_guest_cr0));
      switch (id->opperand2)
      {
        case 0: return setVM_CR0(currentcpuinfo, vmregisters->rax);
        case 1: return setVM_CR0(currentcpuinfo, vmregisters->rcx);
        case 2: return setVM_CR0(currentcpuinfo, vmregisters->rdx);
        case 3: return setVM_CR0(currentcpuinfo, vmregisters->rbx);
        case 4: return setVM_CR0(currentcpuinfo, vmread(vm_guest_rsp));
        case 5: return setVM_CR0(currentcpuinfo, vmregisters->rbp);
        case 6: return setVM_CR0(currentcpuinfo, vmregisters->rsi);
        case 7: return setVM_CR0(currentcpuinfo, vmregisters->rdi);
      }
      break;

    case 1:
      break;

    case 2:
      break;

    case 3:
      switch (id->opperand2)
      {
        case 0: return setVM_CR3(currentcpuinfo, vmregisters, vmregisters->rax);
        case 1: return setVM_CR3(currentcpuinfo, vmregisters, vmregisters->rcx);
        case 2: return setVM_CR3(currentcpuinfo, vmregisters, vmregisters->rdx);
        case 3: return setVM_CR3(currentcpuinfo, vmregisters, vmregisters->rbx);
        case 4: return setVM_CR3(currentcpuinfo, vmregisters, vmread(vm_guest_rsp));
        case 5: return setVM_CR3(currentcpuinfo, vmregisters, vmregisters->rbp);
        case 6: return setVM_CR3(currentcpuinfo, vmregisters, vmregisters->rsi);
        case 7: return setVM_CR3(currentcpuinfo, vmregisters, vmregisters->rdi);
      }
      break;

    case 4:
      switch (id->opperand2)
      {
        case 0: return setVM_CR4(currentcpuinfo, vmregisters->rax);
        case 1: return setVM_CR4(currentcpuinfo, vmregisters->rcx);
        case 2: return setVM_CR4(currentcpuinfo, vmregisters->rdx);
        case 3: return setVM_CR4(currentcpuinfo, vmregisters->rbx);
        case 4: return setVM_CR4(currentcpuinfo, vmread(vm_guest_rsp));
        case 5: return setVM_CR4(currentcpuinfo, vmregisters->rbp);
        case 6: return setVM_CR4(currentcpuinfo, vmregisters->rsi);
        case 7: return setVM_CR4(currentcpuinfo, vmregisters->rdi);
      }
      break;

  }

  return 1;
}

int opcode_MOV8B(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{
  sendstring("MOV 8B  (r,r or r,m) \n\r");

  handleMODRM(vmregisters, id);
  if (id->error)
  {
    sendstring("id->error\n");
    return 1;
  }

  if (id->opperandsize==0)
  {
    WORD value;

    switch (id->opperand2)
    {
      case -1:
      {
        int error=0;
        QWORD pagefaultaddress;
        WORD *v=mapVMmemory(currentcpuinfo, id->address, 2, &error, &pagefaultaddress);
        value=*(WORD *)v;
        unmapVMmemory(v,2);
        break;
      }

      case 0:
        value=vmregisters->rax & 0xffff;
        break;

      case 1:
        value=vmregisters->rcx & 0xffff;
        break;

      case 2:
        value=vmregisters->rdx & 0xffff;
        break;

      case 3:
        value=vmregisters->rbx & 0xffff;
        break;

      case 4:
        value=vmread(vm_guest_rsp) & 0xffff;
        break;

      case 5:
        value=vmregisters->rbp & 0xffff;
        break;

      case 6:
        value=vmregisters->rsi & 0xffff;
        break;

      case 7:
        value=vmregisters->rdi & 0xffff;
        break;

      default:
        return 0;
    }

    sendstringf("Value = %8\n", value);

    switch (id->opperand)
    {
      case 0:
        vmregisters->rax=(vmregisters->rax & 0xffffffffffff0000ULL)+ value;
        break;

      case 1:
        vmregisters->rcx=(vmregisters->rcx & 0xffffffffffff0000ULL)+ value;
        break;

      case 2:
        vmregisters->rdx=(vmregisters->rdx & 0xffffffffffff0000ULL)+ value;
        break;

      case 3:
        vmregisters->rbx=(vmregisters->rbx & 0xffffffffffff0000ULL)+ value;
        break;

      case 4:
        vmwrite(vm_guest_rsp, (vmread(vm_guest_rsp) & 0xffffffffffff0000ULL) + value );
        break;

      case 5:
        vmregisters->rbp=(vmregisters->rbp & 0xffffffffffff0000ULL)+ value;
        break;

      case 6:
        vmregisters->rsi=(vmregisters->rsi & 0xffffffffffff0000ULL)+ value;
        break;

      case 7:
        vmregisters->rdi=(vmregisters->rdi & 0xffffffffffff0000ULL)+ value;
        break;

      default:
        sendstringf("FAILURE. opperand=%d", id->opperand);
        break;

    }
    return 0;

  }

  return 1;

}

int opcode_MOV8E(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{
  sendstring("MOV 8E\n\r");

  handleMODRM(vmregisters, id);
  if (id->error)
  {
    sendstring("id->error\n");
    return 1;
  }

  sendstringf("operand=%d operand2=%d\n\r",id->opperand, id->opperand2);

  if (id->opperand==1)
  {
	  emulateRMinterrupt(currentcpuinfo, vmregisters, 6);
	  return 2;
  }

  if (id->opperand2==-1)
  {
    int error=0;
    QWORD pagefaultaddress;
    WORD *address=(WORD *)mapVMmemory(currentcpuinfo, id->address, 2, &error, &pagefaultaddress);

    setSegment(id->opperand, *address);
    unmapVMmemory(address, 2);
    return 0;
  }
  else
  {
    setSegment(id->opperand, getOpperandValue(vmregisters, id->opperand2, Register16Bit));
    return 0;
  }
}

int opcode_MOVSA5(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{
  UINT64 guestrflags=vmread(vm_guest_rflags);
  PRFLAGS pguestrflags=(PRFLAGS)&guestrflags;

  int moves=(id->rep)?vmregisters->rcx:1;
  int bytespermove=(id->opperandsize)?4:2;
  int error;
  UINT64 pagefaultaddress;

  if (moves==0)
    return 0;

  if (id->addresssize)
  {

    int mapsize=bytespermove*moves;

    if (vmregisters->rdi < vmmstart)
    {

      if (pguestrflags->DF==0)
      {
        WORD *destination=(WORD *)mapVMmemory(currentcpuinfo, vmregisters->rdi, bytespermove*moves, &error, &pagefaultaddress);
        WORD *source=(WORD *)mapVMmemory(currentcpuinfo, vmregisters->rsi, bytespermove*moves, &error, &pagefaultaddress);

        copymem(destination,source,bytespermove*moves);
        vmregisters->rdi+=bytespermove*moves;
        vmregisters->rsi+=bytespermove*moves;
        vmregisters->rcx=0;

        unmapVMmemory(destination,mapsize);
        unmapVMmemory(source,mapsize);

      }
      else
      {
        WORD *destination=(WORD *)mapVMmemory(currentcpuinfo, vmregisters->rdi-bytespermove*(moves-1), bytespermove*moves, &error, &pagefaultaddress);
        WORD *source=(WORD *)mapVMmemory(currentcpuinfo, vmregisters->rsi-bytespermove*(moves-1), bytespermove*moves, &error, &pagefaultaddress);

        copymem(destination,source,bytespermove*moves);
        vmregisters->rsi-=bytespermove*moves;
        vmregisters->rdi-=bytespermove*moves;
        vmregisters->rcx=0;

        unmapVMmemory(destination,mapsize);
        unmapVMmemory(source,mapsize);
      }

    }
    else
    {

      vmregisters->rsi+=vmregisters->rcx*bytespermove;
      vmregisters->rdi+=vmregisters->rcx*bytespermove;
      vmregisters->rcx=0;
    }

    return 0;

  }
  else
  {
    sendstring("16-bit addressing not handled yet\n");
    return 1;
  }

}

int opcode_MOVB0toB7(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id,int offset)
{

  sendstring("MOV B0 to B7\n");

  if (id->lock)
  {
    emulateRMinterrupt(currentcpuinfo, vmregisters, 6);
    return 2;
  }

  switch (offset)
  {
    case 0:
      vmregisters->rax=(vmregisters->rax & 0xffffffffffffff00ULL) + *(BYTE*)(&id->instruction[id->size]);
      break;

    case 1:
      vmregisters->rcx=(vmregisters->rcx & 0xffffffffffffff00ULL) + *(BYTE*)(&id->instruction[id->size]);
      break;

    case 2:
      vmregisters->rdx=(vmregisters->rdx & 0xffffffffffffff00ULL) + *(BYTE*)(&id->instruction[id->size]);
      break;

    case 3:
      vmregisters->rbx=(vmregisters->rbx & 0xffffffffffffff00ULL) + *(BYTE*)(&id->instruction[id->size]);
      break;

    case 4:
      vmregisters->rax=(vmregisters->rax & 0xffffffffffff00ffULL) + (*(BYTE*)(&id->instruction[id->size]) << 8);
      break;

    case 5:
      vmregisters->rcx=(vmregisters->rcx & 0xffffffffffff00ffULL) + (*(BYTE*)(&id->instruction[id->size]) << 8);
      break;

    case 6:
      vmregisters->rdx=(vmregisters->rdx & 0xffffffffffff00ffULL) + (*(BYTE*)(&id->instruction[id->size]) << 8);
      break;

    case 7:
      vmregisters->rdx=(vmregisters->rbx & 0xffffffffffff00ffULL) + (*(BYTE*)(&id->instruction[id->size]) << 8);
      break;
  }
  id->size+=1;

  return 0;
}

int opcode_MOVB8toBF(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id,int offset)
{

  sendstring("MOV B8 to BF\n");

  if (id->lock)
  {
    emulateRMinterrupt(currentcpuinfo, vmregisters, 6);
    return 2;
  }

  if (!id->opperandsize)
  {

    switch (offset)
    {
      case 0:
        vmregisters->rax=(vmregisters->rax & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
        break;

      case 1:
        vmregisters->rcx=(vmregisters->rcx & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
        break;

      case 2:
        vmregisters->rdx=(vmregisters->rdx & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
        break;

      case 3:
        vmregisters->rbx=(vmregisters->rbx & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
        break;

      case 4:
        vmwrite(vm_guest_rsp,(vmread(vm_guest_rsp) & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]));
        break;

      case 5:
        vmregisters->rbp=(vmregisters->rbp & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
        break;

      case 6:
        vmregisters->rsi=(vmregisters->rsi & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
        break;

      case 7:
        vmregisters->rdi=(vmregisters->rdi & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
        break;
    }
    id->size+=2;
  }
  else
  {

    switch (offset)
    {
      case 0:
        vmregisters->rax=(vmregisters->rax & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
        break;

      case 1:
        vmregisters->rcx=(vmregisters->rcx & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
        break;

      case 2:
        vmregisters->rdx=(vmregisters->rdx & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
        break;

      case 3:
        vmregisters->rbx=(vmregisters->rbx & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
        break;

      case 4:
        vmwrite(vm_guest_rsp,(vmread(vm_guest_rsp) & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]));
        break;

      case 5:
        vmregisters->rbp=(vmregisters->rbp & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
        break;

      case 6:
        vmregisters->rsi=(vmregisters->rsi & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
        break;

      case 7:
        vmregisters->rdi=(vmregisters->rdi & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
        break;
    }
    id->size+=4;
  }

  return 0;
}

int opcode_MOVC6(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{

  int error;
  UINT64 pagefaultaddress;

  sendstring("MOV C6 (rm8,imm8)\n\r");

  handleMODRM(vmregisters, id);
  if (id->error)
    return 1;

  if (id->opperand2==-1)
  {

    sendstringf("id->address=%x\n\r",id->address);
    sendstringf("id->size=%d\n\r", id->size);

    BYTE *address=(BYTE *)mapVMmemory(currentcpuinfo, id->address, 16, &error, &pagefaultaddress);

    if (error)
    {
      sendstring("Failure mapping memory\n\r");
      return 1;
    }

    *address=id->instruction[id->size];

    id->size+=1;
    unmapVMmemory(address,16);
  }
  else
  {

    switch (id->opperand2)
    {
      case 0:
        vmregisters->rax=(vmregisters->rax & 0xffffffffffffff00ULL) + id->instruction[id->size];
        break;

      case 1:
        vmregisters->rcx=(vmregisters->rcx & 0xffffffffffffff00ULL) + id->instruction[id->size];
        break;

      case 2:
        vmregisters->rdx=(vmregisters->rdx & 0xffffffffffffff00ULL) + id->instruction[id->size];
        break;

      case 3:
        vmregisters->rbx=(vmregisters->rbx & 0xffffffffffffff00ULL) + id->instruction[id->size];
        break;

      case 4:
        vmregisters->rax=(vmregisters->rax & 0xffffffffffff00ffULL) + id->instruction[id->size];
        break;

      case 5:
        vmregisters->rcx=(vmregisters->rcx & 0xffffffffffff00ffULL) + ((int)id->instruction[id->size] << 8);
        break;

      case 6:
        vmregisters->rdx=(vmregisters->rdx & 0xffffffffffff00ffULL) + ((int)id->instruction[id->size] << 8);
        break;

      case 7:
        vmregisters->rbx=(vmregisters->rbx & 0xffffffffffff00ffULL) + ((int)id->instruction[id->size] << 8);
        break;
    }

    id->size+=1;

  }

  return 0;
}

int opcode_MOVC7(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{

  int error;
  UINT64 pagefaultaddress;

  sendstring("MOV C7  (rm16,imm16 or rm32,imm32)\n\r");
  handleMODRM(vmregisters, id);
  if (id->error)
    return 1;

  if (id->opperand2==-1)
  {

    sendstringf("id->address=%x\n\r",id->address);
    sendstringf("id->size=%d\n\r", id->size);

    if (id->opperandsize)
    {

      DWORD *address=(DWORD *)mapVMmemory(currentcpuinfo, id->address, 16, &error, &pagefaultaddress);

      if (error)
      {
        sendstring("Failure mapping memory\n\r");
        return 1;
      }

      *address=*(DWORD *)&id->instruction[id->size];

      id->size+=4;
      unmapVMmemory(address,16);
    }
    else
    {

      WORD *address=(WORD *)mapVMmemory(currentcpuinfo, id->address, 16, &error, &pagefaultaddress);

      if (error)
      {
        sendstring("Failure mapping memory\n\r");
        return 1;
      }

      *address=*(WORD *)&id->instruction[id->size];
      unmapVMmemory(address,16);

      id->size+=2;
    }
  }
  else
  {
    if (!id->opperandsize)
    {

      switch (id->opperand2)
      {
        case 0:
          vmregisters->rax=(vmregisters->rax & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
          break;

        case 1:
          vmregisters->rcx=(vmregisters->rcx & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
          break;

        case 2:
          vmregisters->rdx=(vmregisters->rdx & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
          break;

        case 3:
          vmregisters->rbx=(vmregisters->rbx & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
          break;

        case 4:
          vmwrite(vm_guest_rsp,(vmread(vm_guest_rsp) & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]));
          break;

        case 5:
          vmregisters->rbp=(vmregisters->rbp & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
          break;

        case 6:
          vmregisters->rsi=(vmregisters->rsi & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
          break;

        case 7:
          vmregisters->rdi=(vmregisters->rdi & 0xffffffffffff0000ULL) + *(WORD*)(&id->instruction[id->size]);
          break;
      }
      id->size+=2;
    }
    else
    {

      switch (id->opperand2)
      {
        case 0:
          vmregisters->rax=(vmregisters->rax & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
          break;

        case 1:
          vmregisters->rcx=(vmregisters->rcx & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
          break;

        case 2:
          vmregisters->rdx=(vmregisters->rdx & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
          break;

        case 3:
          vmregisters->rbx=(vmregisters->rbx & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
          break;

        case 4:
          vmwrite(vm_guest_rsp,(vmread(vm_guest_rsp) & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]));
          break;

        case 5:
          vmregisters->rbp=(vmregisters->rbp & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
          break;

        case 6:
          vmregisters->rsi=(vmregisters->rsi & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
          break;

        case 7:
          vmregisters->rdi=(vmregisters->rdi & 0xffffffff00000000ULL) + *(DWORD*)(&id->instruction[id->size]);
          break;
      }
      id->size+=4;
    }
  }

  return 0;

}

int opcode_POP58to5F(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id,int offset)
{
  int error;
  UINT64 pagefaultaddress;

  sendstring("POP 58 to 5F\n");

  if (!id->opperandsize)
  {

    WORD *stack=(WORD *)mapVMmemory(currentcpuinfo, vmread(vm_guest_ss_base)+(vmread(vm_guest_rsp) & 0xffff), 2, &error, &pagefaultaddress);

    switch (offset)
    {
      case 0:
        vmregisters->rax=(vmregisters->rax & 0xffffffffffff0000ULL) + *stack;
        break;

      case 1:
        vmregisters->rcx=(vmregisters->rcx & 0xffffffffffff0000ULL) + *stack;
        break;

      case 2:
        vmregisters->rdx=(vmregisters->rdx & 0xffffffffffff0000ULL) + *stack;
        break;

      case 3:
        vmregisters->rbx=(vmregisters->rbx & 0xffffffffffff0000ULL) + *stack;
        break;

      case 4:
        vmwrite(vm_guest_rsp,(vmread(vm_guest_rsp) & 0xffffffffffff0000ULL) + *stack);
        break;

      case 5:
        vmregisters->rbp=(vmregisters->rbp & 0xffffffffffff0000ULL) + *stack;
        break;

      case 6:
        vmregisters->rsi=(vmregisters->rsi & 0xffffffffffff0000ULL) + *stack;
        break;

      case 7:
        vmregisters->rdi=(vmregisters->rdi & 0xffffffffffff0000ULL) + *stack;
        break;
    }

    vmwrite(vm_guest_rsp, (vmread(vm_guest_rsp) & 0xffffffffffff0000ULL) + (WORD)(vmread(vm_guest_rsp)+2));

    unmapVMmemory(stack,2);
  }
  else
  {

    DWORD *stack=(DWORD *)mapVMmemory(currentcpuinfo, vmread(vm_guest_ss_base)+(vmread(vm_guest_rsp) & 0xffff), 4, &error, &pagefaultaddress);

    switch (offset)
    {
      case 0:
        vmregisters->rax=(vmregisters->rax & 0xffffffff00000000ULL) + *stack;
        break;

      case 1:
        vmregisters->rcx=(vmregisters->rcx & 0xffffffff00000000ULL) + *stack;
        break;

      case 2:
        vmregisters->rdx=(vmregisters->rdx & 0xffffffff00000000ULL) + *stack;
        break;

      case 3:
        vmregisters->rbx=(vmregisters->rbx & 0xffffffff00000000ULL) + *stack;
        break;

      case 4:
        vmwrite(vm_guest_rsp,(vmread(vm_guest_rsp) & 0xffffffff00000000ULL) + *stack);
        break;

      case 5:
        vmregisters->rbp=(vmregisters->rbp & 0xffffffff00000000ULL) + *stack;
        break;

      case 6:
        vmregisters->rsi=(vmregisters->rsi & 0xffffffff00000000ULL) + *stack;
        break;

      case 7:
        vmregisters->rdi=(vmregisters->rdi & 0xffffffff00000000ULL) + *stack;
        break;
    }

    vmwrite(vm_guest_rsp, (vmread(vm_guest_rsp) & 0xffffffffffff0000ULL) + (WORD)(vmread(vm_guest_rsp)+4));
    unmapVMmemory(stack,4);
  }

  return 0;
}

int opcode_POPSegment(pcpuinfo currentcpuinfo, VMRegisters *vmregisters UNUSED, PINSTRUCTIONDATA id,int segment)
{
  int error;

  UINT64 pagefaultaddress;

  WORD *sv=mapVMmemory(currentcpuinfo, vmread(vm_guest_ss_base)+vmread(vm_guest_rsp), 2, &error, &pagefaultaddress);
  WORD segmentvalue=*sv;
  unmapVMmemory(sv,2);

  sendstring("POPSegment\n");

  if (!id->opperandsize)
  {

    vmwrite(vm_guest_rsp, (WORD)(vmread(vm_guest_rsp)+2));

  }
  else
  {

    vmwrite(vm_guest_rsp, (WORD)(vmread(vm_guest_rsp)+4));
  }

  setSegment(segment, segmentvalue);

  return 0;
}

int opcode_PUSH50to57(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id, int offset)
{
  int error;
  UINT64 pagefaultaddress;

  sendstring("PUSH 50 to 57\n");

  if (!id->opperandsize)
  {

	vmwrite(vm_guest_rsp, (vmread(vm_guest_rsp) & 0xffffffffffff0000ULL) + (WORD)(vmread(vm_guest_rsp)-2));

    WORD *stack=(WORD *)mapVMmemory(currentcpuinfo, vmread(vm_guest_ss_base)+(vmread(vm_guest_rsp) & 0xffff), 2, &error, &pagefaultaddress);

    switch (offset)
    {
      case 0:
        *stack=(WORD)vmregisters->rax;
        break;

      case 1:
    	*stack=(WORD)vmregisters->rcx;
        break;

      case 2:
    	*stack=(WORD)vmregisters->rdx;
        break;

      case 3:
    	*stack=(WORD)vmregisters->rbx;
        break;

      case 4:
    	*stack=(WORD)vmread(vm_guest_rsp)+2;
        break;

      case 5:
    	*stack=(WORD)vmregisters->rbp;
        break;

      case 6:
    	*stack=(WORD)vmregisters->rsi;
        break;

      case 7:
    	*stack=(WORD)vmregisters->rdi;
        break;
    }

    unmapVMmemory(stack, 2);

  }
  else
  {

  	vmwrite(vm_guest_rsp, (vmread(vm_guest_rsp) & 0xffffffffffff0000ULL) + (WORD)(vmread(vm_guest_rsp)-4));
    DWORD *stack=(DWORD *)mapVMmemory(currentcpuinfo, vmread(vm_guest_ss_base)+(vmread(vm_guest_rsp) & 0xffff), 4, &error, &pagefaultaddress);

    switch (offset)
    {
      case 0:
        *stack=(DWORD)vmregisters->rax;
        break;

      case 1:
    	  *stack=(DWORD)vmregisters->rcx;
        break;

      case 2:
    	  *stack=(DWORD)vmregisters->rdx;
        break;

      case 3:
    	  *stack=(DWORD)vmregisters->rbx;
        break;

      case 4:
    	  *stack=(DWORD)vmread(vm_guest_rsp)+4;
        break;

      case 5:
    	  *stack=(DWORD)vmregisters->rbp;
        break;

      case 6:
    	  *stack=(DWORD)vmregisters->rsi;
        break;

      case 7:
    	  *stack=(DWORD)vmregisters->rdi;
        break;
    }

    unmapVMmemory(stack, 4);

  }

  return 0;
}

int opcode_PUSHSegment(pcpuinfo currentcpuinfo, VMRegisters *vmregisters UNUSED, PINSTRUCTIONDATA id,int segment)
{
  int error;
  UINT64 pagefaultaddress;
  WORD segmentValue=vmread(vm_guest_es+(segment << 1));

  if (!id->opperandsize)
  {

    WORD sp=vmread(vm_guest_rsp)-2;
    WORD *stack=mapVMmemory(currentcpuinfo, vmread(vm_guest_ss_base)+sp, 2, &error, &pagefaultaddress);

    *stack=segmentValue;
    vmwrite(vm_guest_rsp, sp);

    unmapVMmemory(stack,2);

  }
  else
  {

    WORD sp=vmread(vm_guest_rsp)-4;
    DWORD *stack=mapVMmemory(currentcpuinfo, vmread(vm_guest_ss_base)+sp, 4, &error, &pagefaultaddress);
    *stack=segmentValue;
    vmwrite(vm_guest_rsp, sp);

    unmapVMmemory(stack,4);
  }

  return 0;
}

int opcode_PUSH68(pcpuinfo currentcpuinfo, VMRegisters *vmregisters UNUSED, PINSTRUCTIONDATA id)
{
  int error;
  UINT64 pagefaultaddress;
  DWORD value;

  sendstring("Push 68 : PUSH imm16/imm32\n\r");

  if (!id->opperandsize)
  {

    WORD sp=vmread(vm_guest_rsp)-2;
    WORD *stack=(WORD *)mapVMmemory(currentcpuinfo, vmread(vm_guest_ss_base)+sp, 2, &error, &pagefaultaddress);

    value=*(WORD *)&id->instruction[id->size];
    id->size+=2;

    sendstring("");

    *stack=value;
    vmwrite(vm_guest_rsp, sp);
    unmapVMmemory(stack,2);
  }
  else
  {

    WORD sp=vmread(vm_guest_rsp)-4;
    DWORD *stack=(DWORD *)mapVMmemory(currentcpuinfo, vmread(vm_guest_ss_base)+sp, 4, &error, &pagefaultaddress);

    value=*(DWORD *)&id->instruction[id->size];
    id->size+=4;

    *stack=value;
    vmwrite(vm_guest_rsp, sp);
    unmapVMmemory(stack, 4);
  }

  return 0;
}

int opcode_RDMSR0F32(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  DWORD MSR=vmregisters->rcx;
  sendstringf("Reading msr %x\n", MSR);
  QWORD value=readMSRSafe(MSR);

  if (currentcpuinfo->LastInterrupt)
  {
    emulateRMinterrupt(currentcpuinfo, vmregisters, currentcpuinfo->LastInterrupt);
    return 2;
  }

  vmregisters->rax=value & 0xffffffff;
  vmregisters->rdx=value >> 32;

  return 0;
}

int opcode_WRMSR0F30(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  DWORD MSR=vmregisters->rcx;
  QWORD value=(vmregisters->rdx << 32) | vmregisters->rax;
  sendstringf("Writing msr %x\n", MSR);
  writeMSRSafe(MSR, value);

  if (currentcpuinfo->LastInterrupt)
  {
    emulateRMinterrupt(currentcpuinfo, vmregisters, currentcpuinfo->LastInterrupt);
    return 2;
  }

  return 0;
}

int opcode_RETC3(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{
  int error;
  UINT64 pagefaultaddress;

  if (!id->opperandsize)
  {
    WORD retaddress;

    WORD sp=vmread(vm_guest_rsp);
    WORD *stack=(WORD *)mapVMmemory(currentcpuinfo, vmread(vm_guest_ss_base)+sp, 2, &error, &pagefaultaddress);
    sendstring("16 bit ret\n");

    retaddress=*stack;

    unmapVMmemory(stack,2);

    sendstringf("retaddress=%8\n", retaddress);

    sendstringf("sp was %8\n", sp);
    sp=sp+2;
    vmwrite(vm_guest_rsp, sp);
    sendstringf("sp becomes %8\n", sp);

    if (sp<=1)
    {
      sendstringf("sp (%8) causes an stack error\n", sp);
      emulateRMinterrupt(currentcpuinfo, vmregisters, 12);
      return 2;
    }

    retaddress=vmread(vm_guest_cs_base)+retaddress;

    vmwrite(vm_guest_rip, retaddress & 0xffff);

    return 2;
  }

  return 1;
}

int opcode_CLI(void)
{

  UINT64 guestrflags=vmread(vm_guest_rflags);
  PRFLAGS pguestrflags=(PRFLAGS)&guestrflags;

  pguestrflags->IF=0;
  vmwrite(0x6820,(UINT64)guestrflags);

  return 0;
}

int opcode_STI(void)
{

  UINT64 guestrflags=vmread(vm_guest_rflags);
  PRFLAGS pguestrflags=(PRFLAGS)&guestrflags;

  if (pguestrflags->IF==0)
  {

    int is=vmread(vm_guest_interruptability_state);
    if ((is & 1)==0)
    {
      is=is | 1;
      vmwrite(vm_guest_interruptability_state,is);
    }
  }

  pguestrflags->IF=1;
  vmwrite(0x6820,(UINT64)guestrflags);

  sendstringf("After STI. vm_guest_interruptability_state=%d", vmread(vm_guest_interruptability_state));

  return 0;
}

int opcode_CLD(pcpuinfo currentcpuinfo UNUSED)
{
  UINT64 guestrflags=vmread(vm_guest_rflags);
  PRFLAGS pguestrflags=(PRFLAGS)&guestrflags;

  pguestrflags->DF=0;
  vmwrite(0x6820,(UINT64)guestrflags);

  return 0;
}

int opcode_UD(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  emulateRMinterrupt(currentcpuinfo, vmregisters,6);
  return 2;
}

int opcode_WBINVD(void)
{
  asm("WBINVD");

  return 0;
}

int opcode_XOR31(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{

  int error;
  DWORD result=0;
  UINT64 guestrflags=vmread(vm_guest_rflags);
  PRFLAGS pguestrflags=(PRFLAGS)&guestrflags;

  UINT64 pagefaultaddress;
  UINT64 opperandvalue;

  sendstring("XOR 31\n");

  handleMODRM(vmregisters, id);
  if (id->error)
    return 1;

  if (!id->opperandsize)
    opperandvalue=getOpperandValue(vmregisters, id->opperand, Register16Bit);
  else
    opperandvalue=getOpperandValue(vmregisters, id->opperand, Register32Bit);

  sendstringf("Opperandvalue=%x\n",opperandvalue);

  if (id->opperand2==-1)
  {

    sendstringf("id->address=%x\n\r",id->address);
    sendstringf("id->size=%d\n\r", id->size);
    if (id->opperandsize)
    {

      DWORD *address=(DWORD *)mapVMmemory(currentcpuinfo, id->address, 16, &error, &pagefaultaddress);
      if (error)
      {
        sendstring("Failure mapping memory\n\r");
        return 1;
      }

      result=*address ^ opperandvalue;
      *address=result;

      unmapVMmemory(address,16);
    }
    else
    {

      WORD *address=(WORD *)mapVMmemory(currentcpuinfo, id->address, 16, &error, &pagefaultaddress);
      if (error)
      {
        sendstring("Failure mapping memory\n\r");
        return 1;
      }

      result=*address ^ opperandvalue;
      *address=result;
      unmapVMmemory(address,16);
    }
  }
  else
  {

    if (id->opperandsize)
    {

      switch (id->opperand2)
      {
        case 0:
          result=vmregisters->rax ^ opperandvalue;
          vmregisters->rax=(vmregisters->rax & 0xffffffff00000000ULL) + result;
          break;

        case 1:
          result=vmregisters->rcx ^ opperandvalue;
          vmregisters->rcx=(vmregisters->rcx & 0xffffffff00000000ULL) + result;
          break;

        case 2:
          result=vmregisters->rdx ^ opperandvalue;
          vmregisters->rdx=(vmregisters->rdx & 0xffffffff00000000ULL) + result;
          break;

        case 3:
          result=vmregisters->rbx ^ opperandvalue;
          vmregisters->rbx=(vmregisters->rbx & 0xffffffff00000000ULL) + result;
          break;

        case 4:
          result=vmread(vm_guest_rsp) ^ opperandvalue;
          vmwrite(vm_guest_rsp,(vmread(vm_guest_rsp) & 0xffffffff00000000ULL) + result);
          break;

        case 5:
          result=vmregisters->rbp ^ opperandvalue;
          vmregisters->rbp=(vmregisters->rbp & 0xffffffff00000000ULL) + result;
          break;

        case 6:
          result=vmregisters->rsi ^ opperandvalue;
          vmregisters->rsi=(vmregisters->rsi & 0xffffffff00000000ULL) + result;
          break;

        case 7:
          result=vmregisters->rdi ^ opperandvalue;
          vmregisters->rdi=(vmregisters->rdi & 0xffffffff00000000ULL) + result;
          break;
      }

      sendstring("Stripping extra bits 32-bit\n");
      result=result & 0xffffffff;

    }
    else
    {

      opperandvalue=opperandvalue & 0xffff;
      switch (id->opperand2)
      {
        case 0:
          result=vmregisters->rax ^ opperandvalue;
          vmregisters->rax=(vmregisters->rax & 0xffffffffffff0000ULL) + (WORD)result;
          break;

        case 1:
          result=vmregisters->rcx ^ opperandvalue;
          vmregisters->rcx=(vmregisters->rcx & 0xffffffffffff0000ULL) + (WORD)result;

          break;

        case 2:
          result=vmregisters->rdx ^ opperandvalue;
          vmregisters->rdx=(vmregisters->rdx & 0xffffffffffff0000ULL) + (WORD)result;
          break;

        case 3:
          result=vmregisters->rbx ^ opperandvalue;
          vmregisters->rbx=(vmregisters->rbx & 0xffffffffffff0000ULL) + (WORD)result;
          break;

        case 4:
          result=vmread(vm_guest_rsp) ^ opperandvalue;
          vmwrite(vm_guest_rsp, (vmread(vm_guest_rsp) & 0xffffffffffff0000ULL) + (WORD)result);
          break;

        case 5:
          result=vmregisters->rbp ^ opperandvalue;
          vmregisters->rbp=(vmregisters->rbp & 0xffffffffffff0000ULL) + (WORD)result;
          break;

        case 6:
          result=vmregisters->rsi ^ opperandvalue;
          vmregisters->rsi=(vmregisters->rsi & 0xffffffffffff0000ULL) + (WORD)result;
          break;

        case 7:
          result=vmregisters->rdi ^ opperandvalue;
          vmregisters->rdi=(vmregisters->rdi & 0xffffffffffff0000ULL) + (WORD)result;
          break;
      }

      sendstring("Stripping extra bits 16-bit\n");
      result=(WORD)result;
    }
  }

  sendstringf("result=%x\n",result);

  pguestrflags->OF=0;
  pguestrflags->CF=0;

  pguestrflags->SF=0;
  pguestrflags->ZF=result==0;
  pguestrflags->PF=getparityflag((unsigned char)result);
  sendstringf("Setting rflags to %x\n",guestrflags);

  vmwrite(vm_guest_rflags,guestrflags);

  return 0;
}

int getparityflag(unsigned char value)
{
  int count=0;
  unsigned char v=value;

  while (v)
  {
    if (value % 2)
      count++;

    v=v / 2;
  }
  return (count % 2 == 0);
}

int emulateRMinterrupt(pcpuinfo currentcpuinfo, VMRegisters *vmregisters UNUSED, int intnr)

{
  WORD neweip,newcs;
  DWORD *idtvector=(DWORD *)currentcpuinfo->RealMode.IDTBase;

  UINT64 guestrflags=vmread(vm_guest_rflags);
  PRFLAGS pguestrflags=(PRFLAGS)&guestrflags;
  WORD *stack=(WORD *)(vmread(vm_guest_ss_base)+(WORD)(vmread(vm_guest_rsp)-6));

  neweip=(WORD)idtvector[intnr];
  newcs=(WORD)(idtvector[intnr] >> 16);

  stack[0]=(WORD)(vmread(vm_guest_rip));
  stack[1]=(WORD)(vmread(vm_guest_cs));
  stack[2]=(WORD)(vmread(vm_guest_rflags));

  vmwrite(vm_guest_rsp,(WORD)(vmread(vm_guest_rsp)-6));
  vmwrite(vm_guest_rip, neweip);
  vmwrite(vm_guest_cs, newcs);
  vmwrite(vm_guest_cs_base, newcs<<4);

  pguestrflags->IF=0;
  pguestrflags->TF=0;
  pguestrflags->AC=0;
  pguestrflags->RF=0;
  vmwrite(vm_guest_rflags,(ULONG)guestrflags);

  sendstring("Emulating realmode interrupt");

  return 0;

}

int setSegment(int segmentnr, WORD value)
{
  sendstringf("Setting segment id %d to value %x\n\r",segmentnr,value);
  sendstringf("vm_guest_es+(segmentnr<<1)=%x\n\r",vm_guest_es+(segmentnr<<1));

  vmwrite(vm_guest_es+(segmentnr<<1),value);
  vmwrite(vm_guest_es_base+(segmentnr<<1),value << 4);
  vmwrite(vm_guest_es_limit+(segmentnr<<1),0xffff);
  vmwrite(vm_guest_es_access_rights+(segmentnr<<1),0xf3);

  if (segmentnr==2)
    vmwrite(vm_guest_interruptability_state, vmread(vm_guest_interruptability_state) | (1<<1));

  return 0;
}

UINT64 getOpperandValue(VMRegisters *vmregisters, int opperand, _registerType registerType)
{
  switch (registerType)
  {
    case Register8Bit:
      switch (opperand)
      {
        case 0: return vmregisters->rax & 0xff;
        case 1: return vmregisters->rcx & 0xff;
        case 2: return vmregisters->rdx & 0xff;
        case 3: return vmregisters->rbx & 0xff;
        case 4: return (vmregisters->rax >> 8) & 0xff;
        case 5: return (vmregisters->rcx >> 8) & 0xff;
        case 6: return (vmregisters->rdx >> 8) & 0xff;
        case 7: return (vmregisters->rbx >> 8) & 0xff;
      }
      break;

    case Register16Bit:
      switch (opperand)
      {
        case 0: return vmregisters->rax & 0xffff;
        case 1: return vmregisters->rcx & 0xffff;
        case 2: return vmregisters->rdx & 0xffff;
        case 3: return vmregisters->rbx & 0xffff;
        case 4: return vmread(vm_guest_rsp) & 0xffff;
        case 5: return vmregisters->rbp & 0xffff;
        case 6: return vmregisters->rsi & 0xffff;
        case 7: return vmregisters->rdi & 0xffff;
      }
      break;

    case Register32Bit:
      switch (opperand)
      {
        case 0: return vmregisters->rax & 0xffffffff;
        case 1: return vmregisters->rcx & 0xffffffff;
        case 2: return vmregisters->rdx & 0xffffffff;
        case 3: return vmregisters->rbx & 0xffffffff;
        case 4: return vmread(vm_guest_rsp) & 0xffffffff;
        case 5: return vmregisters->rbp & 0xffffffff;
        case 6: return vmregisters->rsi & 0xffffffff;
        case 7: return vmregisters->rdi & 0xffffffff;
      }
      break;

    case RegisterSreg:
      switch (opperand)
      {
        case 0: return vmread(vm_guest_es);
        case 1: return vmread(vm_guest_cs);
        case 2: return vmread(vm_guest_ss);
        case 3: return vmread(vm_guest_ds);
        case 4: return vmread(vm_guest_fs);
        case 5: return vmread(vm_guest_gs);
      }
      break;

    default:
      sendstring("Not handled yet \n\r");
      break;

  }

  return 1;
}

int getOpperand(PINSTRUCTIONDATA id)
{
  return ((PMODRM)(&id->instruction[id->size]))->RegOpcode;
}

ULONG getSIBBase(VMRegisters *vmregisters, PINSTRUCTIONDATA id, int MOD, int SIBBase)
{
  switch (SIBBase)
  {
    case 0: return vmregisters->rax & 0xffffffff;
    case 1: return vmregisters->rcx & 0xffffffff;
    case 2: return vmregisters->rdx & 0xffffffff;
    case 3: return vmregisters->rbx & 0xffffffff;
    case 4: return vmread(vm_guest_rsp) & 0xffffffff;
    case 5:
      switch (MOD)
      {
        case 0:
          id->address=(*(DWORD*)(&id->instruction[id->size]));
          id->size+=4;
          return id->address;

        case 1:
          id->address=(vmregisters->rbp & 0xffffffff);
          return id->address;

        case 2:
          id->address=(vmregisters->rbp & 0xffffffff);
          return id->address;
      }
      break;

    case 6: return vmregisters->rsi & 0xffffffff;
    case 7: return vmregisters->rdi & 0xffffffff;
  }

  sendstringf("getSIBBase error\n\r");
  id->error=1;
  return 0;
}

ULONG handleSIB(VMRegisters *vmregisters, PINSTRUCTIONDATA id, int MOD)
{
  PSIB sib= (PSIB)&id->instruction[id->size];
  ULONG SIBBase;
  id->size++;

  SIBBase=getSIBBase(vmregisters, id, MOD, sib->Base);

  switch (sib->Scale)
  {
    case 0:
      switch (sib->Index)
      {
        case 0: return (vmregisters->rax & 0xffffffff) + SIBBase;
        case 1: return (vmregisters->rcx & 0xffffffff) + SIBBase;
        case 2: return (vmregisters->rdx & 0xffffffff) + SIBBase;
        case 3: return (vmregisters->rbx & 0xffffffff) + SIBBase;
        case 4: return SIBBase;
        case 5: return (vmregisters->rsi & 0xffffffff) + SIBBase;
        case 6: return (vmregisters->rdi & 0xffffffff) + SIBBase;
      }
      break;

    case 1:
      switch (sib->Index)
      {
        case 0: return ((vmregisters->rax*2) & 0xffffffff) + SIBBase;
        case 1: return ((vmregisters->rcx*2) & 0xffffffff) + SIBBase;
        case 2: return ((vmregisters->rdx*2) & 0xffffffff) + SIBBase;
        case 3: return ((vmregisters->rbx*2) & 0xffffffff) + SIBBase;
        case 4: return SIBBase;
        case 5: return ((vmregisters->rsi*2) & 0xffffffff) + SIBBase;
        case 6: return ((vmregisters->rdi*2) & 0xffffffff) + SIBBase;
      }
      break;

    case 2:
      switch (sib->Index)
      {
        case 0: return ((vmregisters->rax*4) & 0xffffffff) + SIBBase;
        case 1: return ((vmregisters->rcx*4) & 0xffffffff) + SIBBase;
        case 2: return ((vmregisters->rdx*4) & 0xffffffff) + SIBBase;
        case 3: return ((vmregisters->rbx*4) & 0xffffffff) + SIBBase;
        case 4: return SIBBase;
        case 5: return ((vmregisters->rsi*4) & 0xffffffff) + SIBBase;
        case 6: return ((vmregisters->rdi*4) & 0xffffffff) + SIBBase;
      }
      break;

    case 3:
      switch (sib->Index)
      {
        case 0: return ((vmregisters->rax*8) & 0xffffffff) + SIBBase;
        case 1: return ((vmregisters->rcx*8) & 0xffffffff) + SIBBase;
        case 2: return ((vmregisters->rdx*8) & 0xffffffff) + SIBBase;
        case 3: return ((vmregisters->rbx*8) & 0xffffffff) + SIBBase;
        case 4: return SIBBase;
        case 5: return ((vmregisters->rsi*8) & 0xffffffff) + SIBBase;
        case 6: return ((vmregisters->rdi*8) & 0xffffffff) + SIBBase;
      }
      break;

  }

  id->error=1;
  return 0;
}

ULONG handleMODRM(VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{
  PMODRM modrm = (PMODRM)&id->instruction[id->size];
  id->opperand=modrm->RegOpcode;
  id->size++;

  switch (id->addresssize)
  {
    case 0:
      switch (modrm->MOD)
      {
        case 0:
          switch (modrm->RM)
          {
            case 0: return id->address=id->segmentbase+((vmregisters->rbx+vmregisters->rsi) & 0xffff);
            case 1: return id->address=id->segmentbase+((vmregisters->rbx+vmregisters->rdi) & 0xffff);
            case 2:
              id->segmentbase=vmread(vm_guest_ss_base);
              return id->address=id->segmentbase+((vmregisters->rbp+vmregisters->rsi) & 0xffff);
            case 3:
              id->segmentbase=vmread(vm_guest_ss_base);
              return id->address=id->segmentbase+((vmregisters->rbp+vmregisters->rdi) & 0xffff);
            case 4: return id->address=id->segmentbase+((vmregisters->rsi) & 0xffff);
            case 5: return id->address=id->segmentbase+((vmregisters->rdi) & 0xffff);
            case 6:
              id->size+=2;
              return id->address=id->segmentbase+(*(WORD*)(&id->instruction[id->size-2]));
            case 7: return id->address=id->segmentbase+((vmregisters->rbx) & 0xffff);

          }
          break;

        case 1:
          id->size++;
          switch (modrm->RM)
          {
            case 0: return id->address=id->segmentbase+(((vmregisters->rbx+vmregisters->rsi) + *(char*)(&id->instruction[id->size-1])) & 0xffff);
            case 1: return id->address=id->segmentbase+(((vmregisters->rbx+vmregisters->rdi) + *(char*)(&id->instruction[id->size-1])) & 0xffff);
            case 2:
              id->segmentbase=vmread(vm_guest_ss_base);
              return id->address=id->segmentbase+(((vmregisters->rbp+vmregisters->rsi) + *(char*)(&id->instruction[id->size-1])) & 0xffff);
            case 3:
              id->segmentbase=vmread(vm_guest_ss_base);
              return id->address=id->segmentbase+(((vmregisters->rbp+vmregisters->rdi) + *(char*)(&id->instruction[id->size-1])) & 0xffff);
            case 4: return id->address=id->segmentbase+(((vmregisters->rsi) + *(char*)(&id->instruction[id->size-1])) & 0xffff);
            case 5: return id->address=id->segmentbase+(((vmregisters->rdi) + *(char*)(&id->instruction[id->size-1])) & 0xffff);
            case 6: return id->address=id->segmentbase+(((vmregisters->rbp) + *(char*)(&id->instruction[id->size-1])) & 0xffff);
            case 7: return id->address=id->segmentbase+(((vmregisters->rbx) + *(char*)(&id->instruction[id->size-1])) & 0xffff);
          }
          break;

        case 2:
          id->size+=2;
          switch (modrm->RM)
          {
            case 0: return id->address=(id->segmentbase+((vmregisters->rbx+vmregisters->rsi) + *(short int*)(&id->instruction[id->size-2]))) & 0xffff;
            case 1: return id->address=(id->segmentbase+((vmregisters->rbx+vmregisters->rdi) + *(short int*)(&id->instruction[id->size-2]))) & 0xffff;
            case 2: return id->address=(id->segmentbase+((vmregisters->rbp+vmregisters->rsi) + *(short int*)(&id->instruction[id->size-2]))) & 0xffff;
            case 3: return id->address=(id->segmentbase+((vmregisters->rbp+vmregisters->rdi) + *(short int*)(&id->instruction[id->size-2]))) & 0xffff;
            case 4: return id->address=(id->segmentbase+((vmregisters->rsi) + *(short int*)(&id->instruction[id->size-2]))) & 0xffff;
            case 5: return id->address=(id->segmentbase+((vmregisters->rdi) + *(short int*)(&id->instruction[id->size-2]))) & 0xffff;
            case 6:
              id->segmentbase=vmread(vm_guest_ss_base);
              return id->address=(id->segmentbase+((vmregisters->rbp) + *(short int*)(&id->instruction[id->size-2]))) & 0xffff;
            case 7: return id->address=(id->segmentbase+((vmregisters->rbx) + *(short int*)(&id->instruction[id->size-2]))) & 0xffff;
          }
          break;

        case 3:
          id->opperand2=modrm->RM;
          return 0;

      }
      break;

    case 1:
      switch (modrm->MOD)
      {
        case 0:
          switch (modrm->RM)
          {
            case 0: return id->address=id->segmentbase+(vmregisters->rax & 0xffffffff);
            case 1: return id->address=id->segmentbase+(vmregisters->rcx & 0xffffffff);
            case 2: return id->address=id->segmentbase+(vmregisters->rdx & 0xffffffff);
            case 3: return id->address=id->segmentbase+(vmregisters->rbx & 0xffffffff);
            case 4: return id->address=handleSIB(vmregisters, id, 0);
            case 5:
              id->address=id->segmentbase+(*(DWORD*)(&id->instruction[id->size]));
              id->size+=4;
              return id->address;

            case 6: return id->address=id->segmentbase+(vmregisters->rsi & 0xffffffff);
            case 7: return id->address=id->segmentbase+(vmregisters->rdi & 0xffffffff);
          }
          break;

        case 1:
          switch (modrm->RM)
          {
            case 0:
              id->address=id->segmentbase+(vmregisters->rax & 0xffffffff) + *(char*)(&id->instruction[id->size]);
              id->size++;
              return id->address;

            case 1:
              id->address=id->segmentbase+(vmregisters->rcx & 0xffffffff) + *(char*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;

            case 2:
              id->address=id->segmentbase+(vmregisters->rdx & 0xffffffff) + *(char*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;

            case 3:
              id->address=id->segmentbase+(vmregisters->rbx & 0xffffffff) + *(char*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;

            case 4:
              id->address=handleSIB(vmregisters, id, 1);
              id->address+=*(char*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;

            case 5:
              id->address=id->segmentbase+(vmregisters->rbp & 0xffffffff) + *(char*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;

            case 6:
              id->address=id->segmentbase+(vmregisters->rsi & 0xffffffff) + *(char*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;

            case 7:
              id->address=id->segmentbase+(vmregisters->rdi & 0xffffffff) + *(char*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;
          }
          break;

        case 2:
          switch (modrm->RM)
          {
            case 0:
              id->address=id->segmentbase+(vmregisters->rax & 0xffffffff) + *(unsigned int*)(&id->instruction[id->size]);
              id->size++;
              return id->address;

            case 1:
              id->address=id->segmentbase+(vmregisters->rcx & 0xffffffff) + *(unsigned int*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;

            case 2:
              id->address=id->segmentbase+(vmregisters->rdx & 0xffffffff) + *(unsigned int*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;

            case 3:
              id->address=id->segmentbase+(vmregisters->rbx & 0xffffffff) + *(unsigned int*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;

            case 4:
              id->address=handleSIB(vmregisters, id, 2);
              id->address+=*(unsigned int*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;

            case 5:
              id->address=id->segmentbase+(vmregisters->rbp & 0xffffffff) + *(unsigned int*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;

            case 6:
              id->address=id->segmentbase+(vmregisters->rsi & 0xffffffff) + *(unsigned int*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;

            case 7:
              id->address=id->segmentbase+(vmregisters->rdi & 0xffffffff) + *(unsigned int*)(&id->instruction[id->size-1]);
              id->size++;
              return id->address;
          }
          break;

        case 3:
          id->opperand2=modrm->RM;
          return 0;
      }

      break;
  }

  id->error=1;
  sendstring("MODRM error\n\r");
  return 1;
}

int emulateRMinstruction2(pcpuinfo currentcpuinfo, VMRegisters *vmregisters, PINSTRUCTIONDATA id)
{
  unsigned char buf[30];
  unsigned int i=0;

  UINT64 address=(vmread(vm_guest_cs_base))+vmread(vm_guest_rip);

  sendstring("Emulating RealMode instruction\n\r");

  if (!ReadVMMemory(currentcpuinfo, address,buf,30))
  {
    nosendchar[getAPICID()]=0;
    sendstringf("Unable to read address %x\n\r",address);
    return 1;
  }

  int skip=0;
  id->segmentbase=vmread(vm_guest_ds_base);
  while (i<30)
  {
    skip=0;
    switch (buf[i])
    {
      case 0x26:
        id->segmentbase=vmread(vm_guest_es_base);

        skip=1;
        break;

      case 0x2e:
        id->segmentbase=vmread(vm_guest_cs_base);

        skip=1;
        break;

      case 0x36:
        id->segmentbase=vmread(vm_guest_ss_base);

        skip=1;
        break;

      case 0x3e:
        id->segmentbase=vmread(vm_guest_ds_base);

        skip=1;
        break;

      case 0x64:
        id->segmentbase=vmread(vm_guest_fs_base);

        skip=1;
        break;

      case 0x65:
        id->segmentbase=vmread(vm_guest_gs_base);
        skip=1;
        break;

      case 0x66:
        id->opperandsize=1;
        skip=1;
        break;

      case 0x67:
        id->addresssize=1;
        skip=1;
        break;

      case 0xf0:
        id->lock=1;
        skip=1;
        break;

      case 0xf2:
        id->repne=1;
        skip=1;
        break;

      case 0xf3:
        id->rep=1;
        skip=1;
        break;

    }

    if (skip)
      i++;
    else
      break;
  }

  id->size=i;
  id->instruction=buf;
  id->size++;
  sendstringf("buf[%d]=%2\n\r",i,buf[i]);
  sendstringf("rep=%d opperandsize=%d addresssize=%d segmentbase=%8\n", id->rep, id->opperandsize, id->addresssize, id->segmentbase);
  switch (buf[i])
  {

    case 0x0f:
      id->size++;

      switch (buf[i+1])
      {
        case 0x01:
          sendstring("0f 01\n\r");

          switch (getOpperand(id))
          {
            case 2:
              return opcode_LGDT(currentcpuinfo, vmregisters, id);

            case 3:
              return opcode_LIDT(currentcpuinfo, vmregisters, id);

            case 6:
              return opcode_LMSW(currentcpuinfo, vmregisters, id);

          }

          break;

        case 0x09:
          return opcode_WBINVD();

        case 0x20:
          return opcode_MOV0F20(currentcpuinfo, vmregisters, id);

        case 0x22:
          return opcode_MOV0F22(currentcpuinfo, vmregisters, id);

        case 0x30:
          return opcode_WRMSR0F30(currentcpuinfo, vmregisters);

        case 0x32:
          return opcode_RDMSR0F32(currentcpuinfo, vmregisters);

        case 0xa0:
          return opcode_PUSHSegment(currentcpuinfo, vmregisters, id, 4);

        case 0xa1:
          return opcode_POPSegment(currentcpuinfo, vmregisters, id, 4);

        case 0xa8:
          return opcode_PUSHSegment(currentcpuinfo, vmregisters, id, 5);

        case 0xa9:
          return opcode_POPSegment(currentcpuinfo, vmregisters, id, 5);

      }
      break;

    case 0x06: return opcode_PUSHSegment(currentcpuinfo, vmregisters, id, 0);
    case 0x07: return opcode_POPSegment(currentcpuinfo, vmregisters, id, 0);
    case 0x0e: return opcode_PUSHSegment(currentcpuinfo, vmregisters, id, 1);
    case 0x16: return opcode_PUSHSegment(currentcpuinfo, vmregisters, id, 2);
    case 0x17: return opcode_POPSegment(currentcpuinfo, vmregisters, id, 2);
    case 0x1e: return opcode_PUSHSegment(currentcpuinfo, vmregisters, id, 3);
    case 0x1f: return opcode_POPSegment(currentcpuinfo, vmregisters, id, 3);

    case 0x31: return opcode_XOR31(currentcpuinfo, vmregisters, id);
    case 0x50: return opcode_PUSH50to57(currentcpuinfo, vmregisters, id,0);
    case 0x51: return opcode_PUSH50to57(currentcpuinfo, vmregisters, id,1);
    case 0x52: return opcode_PUSH50to57(currentcpuinfo, vmregisters, id,2);
    case 0x53: return opcode_PUSH50to57(currentcpuinfo, vmregisters, id,3);
    case 0x54: return opcode_PUSH50to57(currentcpuinfo, vmregisters, id,4);
    case 0x55: return opcode_PUSH50to57(currentcpuinfo, vmregisters, id,5);
    case 0x56: return opcode_PUSH50to57(currentcpuinfo, vmregisters, id,6);
    case 0x57: return opcode_PUSH50to57(currentcpuinfo, vmregisters, id,7);
    case 0x58: return opcode_POP58to5F(currentcpuinfo, vmregisters, id,0);
    case 0x59: return opcode_POP58to5F(currentcpuinfo, vmregisters, id,1);
    case 0x5a: return opcode_POP58to5F(currentcpuinfo, vmregisters, id,2);
    case 0x5b: return opcode_POP58to5F(currentcpuinfo, vmregisters, id,3);
    case 0x5c: return opcode_POP58to5F(currentcpuinfo, vmregisters, id,4);
    case 0x5d: return opcode_POP58to5F(currentcpuinfo, vmregisters, id,5);
    case 0x5e: return opcode_POP58to5F(currentcpuinfo, vmregisters, id,6);
    case 0x5f: return opcode_POP58to5F(currentcpuinfo, vmregisters, id,7);

    case 0x68: return opcode_PUSH68(currentcpuinfo, vmregisters, id);

    case 0x8b: return opcode_MOV8B(currentcpuinfo, vmregisters, id);
    case 0x8e: return opcode_MOV8E(currentcpuinfo, vmregisters, id);
    case 0x90: return 0;
    case 0xa5: return opcode_MOVSA5(currentcpuinfo, vmregisters, id);
    case 0xb0: return opcode_MOVB0toB7(currentcpuinfo, vmregisters, id,0);
    case 0xb1: return opcode_MOVB0toB7(currentcpuinfo, vmregisters, id,1);
    case 0xb2: return opcode_MOVB0toB7(currentcpuinfo, vmregisters, id,2);
    case 0xb3: return opcode_MOVB0toB7(currentcpuinfo, vmregisters, id,3);
    case 0xb4: return opcode_MOVB0toB7(currentcpuinfo, vmregisters, id,4);
    case 0xb5: return opcode_MOVB0toB7(currentcpuinfo, vmregisters, id,5);
    case 0xb6: return opcode_MOVB0toB7(currentcpuinfo, vmregisters, id,6);
    case 0xb7: return opcode_MOVB0toB7(currentcpuinfo, vmregisters, id,7);
    case 0xb8: return opcode_MOVB8toBF(currentcpuinfo, vmregisters, id,0);
    case 0xb9: return opcode_MOVB8toBF(currentcpuinfo, vmregisters, id,1);
    case 0xba: return opcode_MOVB8toBF(currentcpuinfo, vmregisters, id,2);
    case 0xbb: return opcode_MOVB8toBF(currentcpuinfo, vmregisters, id,3);
    case 0xbc: return opcode_MOVB8toBF(currentcpuinfo, vmregisters, id,4);
    case 0xbd: return opcode_MOVB8toBF(currentcpuinfo, vmregisters, id,5);
    case 0xbe: return opcode_MOVB8toBF(currentcpuinfo, vmregisters, id,6);
    case 0xbf: return opcode_MOVB8toBF(currentcpuinfo, vmregisters, id,7);

    case 0xc3: return opcode_RETC3(currentcpuinfo, vmregisters, id);

    case 0xc6:
      switch (getOpperand(id))
      {
        case 0: return opcode_MOVC6(currentcpuinfo, vmregisters, id);
      }

      break;

    case 0xc7:
      switch (getOpperand(id))
      {
        case 0: return opcode_MOVC7(currentcpuinfo, vmregisters, id);
      }

      break;

    case 0xcd: return opcode_INTCD(currentcpuinfo, vmregisters, id);
    case 0xe8: return opcode_CALLE8(currentcpuinfo, id);
    case 0xe9: return opcode_JMPE9(currentcpuinfo, id);
    case 0xea: return opcode_JMPEA(id);
    case 0xeb: return opcode_JMPEB(id);
    case 0xf4: return opcode_HLTF4(currentcpuinfo, vmregisters, id);

    case 0xfa: return opcode_CLI();
    case 0xfb: return opcode_STI();
    case 0xfc: return opcode_CLD(currentcpuinfo);
  }

  sendstringf("Unhandled instruction\n\r",i,buf[i]);
  return 1;

}

int emulateRMinstruction(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  INSTRUCTIONDATA id;
  DWORD old_vm_guest_interruptability_state=vmread(vm_guest_interruptability_state);
  zeromemory(&id,sizeof(INSTRUCTIONDATA));
  id.opperand2=-1;

  int result=emulateRMinstruction2(currentcpuinfo, vmregisters, &id);

  if (result==0)
    vmwrite(vm_guest_rip,vmread(vm_guest_rip)+id.size);

  if (result==2)
    result=0;

  if (result==0)
  {

    if (old_vm_guest_interruptability_state)
    {
      sendstringf("Clearing the interuptability state.  old_vm_guest_interruptability_state=%d and vm_guest_interruptability_state=%d\n", old_vm_guest_interruptability_state, vmread(vm_guest_interruptability_state) );
    }

    vmwrite(vm_guest_interruptability_state, (~(old_vm_guest_interruptability_state & 3)) & vmread(vm_guest_interruptability_state));

    sendstringf("new interuptability state=%d\n", vmread(vm_guest_interruptability_state));
  }

  return result==0;
}

#pragma GCC push_options
#pragma GCC optimize ("O0")
int emulateHLT(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  volatile int result=2;
  sendstringf("emulateHLT:");
  UINT64 guestrflags=vmread(vm_guest_rflags);
  PRFLAGS pguestrflags=(PRFLAGS)&guestrflags;

  if (pguestrflags->IF)
  {
	  currentcpuinfo->OnInterrupt.RIP=(QWORD)(volatile void *)(&&InterruptFired);
	  currentcpuinfo->OnInterrupt.RSP=getRSP();
	  currentcpuinfo->OnInterrupt.RBP=getRBP();
	  asm volatile ("": : :"memory");

	  __asm("sti");
	  __asm("hlt");
	  __asm("cli");

	  sendstringf("emulateHLT returned without an interrupt! WTF!");
	  currentcpuinfo->OnInterrupt.RIP=0;
	  result=-1;
	  asm volatile ("": : :"memory");

InterruptFired:
    currentcpuinfo->OnInterrupt.RIP=0;
    currentcpuinfo->OnInterrupt.RSP=0;
    currentcpuinfo->OnInterrupt.RBP=0;

	  if (result==2)
	  {
		  sendstringf("emulateHLT caught interrupt %d", currentcpuinfo->LastInterrupt);

		  result=emulateRMinterrupt(currentcpuinfo, vmregisters, currentcpuinfo->LastInterrupt);

	  }
  }
  else
  {
	  sendstring("emulateHLT called in a state that will not work");
	  return 0;
  }

  return result;

}

int testRMinterrupt(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  volatile int result=2;

  if (ISREALMODE(currentcpuinfo))
  {
    UINT64 guestrflags=vmread(vm_guest_rflags);
    PRFLAGS pguestrflags=(PRFLAGS)&guestrflags;

    if ((pguestrflags->IF) && (vmread(vm_guest_interruptability_state)==0))
    {

      sendstringf("testRMinterrupt: Checking for interrupts. IF==%d and interuptabilitystate=%d\n", pguestrflags->IF, vmread(vm_guest_interruptability_state));

      bochsbp();

      currentcpuinfo->OnInterrupt.RIP=(QWORD)(volatile void *)(&&InterruptFired);
      currentcpuinfo->OnInterrupt.RSP=getRSP();

      __asm("sti");
      __asm("nop");
      __asm("nop");
      __asm("cli");

      currentcpuinfo->OnInterrupt.RIP=0;
      result=0;

      sendstring("No interrupt\n");

InterruptFired:

      if (result==2)
      {

        bochsbp();
        sendstringf("testRMinterrupt: Interruptnr=%d\n\r", currentcpuinfo->LastInterrupt);
        if (currentcpuinfo->LastInterruptHasErrorcode)
        {
          sendstringf("Errorcode=%x\n\r", currentcpuinfo->LastInterruptErrorcode);
        }
        else
        {
          sendstringf("Errorcode=No Errorcode\n\r");
        }

        sendstring("Emulating interrupt...\n\r");

        result=emulateRMinterrupt(currentcpuinfo, vmregisters, currentcpuinfo->LastInterrupt);
        return result;
      }
      else
      {

        return 0;
      }

    }
    else
    {
      sendstringf("testRMinterrupt: Inside real-mode but IF==%d and interuptabilitystate=%d\n", pguestrflags->IF, vmread(vm_guest_interruptability_state));
      return 0;
    }

  }
  else
  {
    sendstring("testRMinterrupt: Not inside real-mode\n");
    return 0;
  }

}

#pragma GCC pop_options

BOOL emulateRealMode(pcpuinfo currentcpuinfo, VMRegisters *vmregisters)
{
  unsigned char buf[30];
  _DecodedInst disassembled[16];
  UINT64 address;
  unsigned int used;
  char c;
  int result=TRUE;
  int success=FALSE;

  int skip;

#ifdef RMEMUONLYONE
  int i;
  for (i=0; i<=0; i++)
#else
  while ((ISREALMODE(currentcpuinfo)) && (result) )
#endif
  {
    #ifdef DEBUG
    skip=0;

    #else
    skip=1;
    #endif

    address=(vmread(vm_guest_cs_base))+vmread(vm_guest_rip);

    if (!ReadVMMemory(currentcpuinfo, address,buf,30))
    {
      nosendchar[getAPICID()]=0;
      sendstringf("Unable to read address %x\n\r",address);
      return FALSE;
    }

#ifdef DEBUG

    switch (address)
    {

      case 0xffff1:
        skip=1;
        break;
    }

#endif

    if (skip)
    {
      int oldstate;
      oldstate=nosendchar[getAPICID()];
      nosendchar[getAPICID()]=1;
      result=emulateRMinstruction(currentcpuinfo,vmregisters);
      if (result)
        success=TRUE;

      nosendchar[getAPICID()]=oldstate;
    }
    else
    {

      distorm_decode(address,buf, 30, Decode16Bits, disassembled, 16, &used);

      nosendchar[getAPICID()]=0;
      sendstringf("inside emulateRealMode for cpu %d\n\r", currentcpuinfo->cpunr );
      sendstringf("%x : %s - %s %s\n\r", disassembled[0].offset, disassembled[0].instructionHex.p, disassembled[0].mnemonic.p, disassembled[0].operands.p);
      sendstring("1: Emulate instructions\n\r");
      sendstring("2: Check state\n\r");
      sendstring("3: Check for int\n\r");

      sendstring("4: Show current instructions\n\r");
      sendstring("Your command:");

      result=FALSE;

      c=waitforchar();

      sendstringf("%c\n\r",c);

      switch (c)
      {
        case '1':
          result=emulateRMinstruction(currentcpuinfo,vmregisters);
          if (result)
            success=TRUE;
          break;

        case '3':

          testRMinterrupt(currentcpuinfo,vmregisters);
          result=TRUE;
          continue;
          break;

        case '2':
          sendvmstate(currentcpuinfo, vmregisters);
          result=TRUE;
          continue;
          break;

        case '4':
          ShowCurrentInstructions(currentcpuinfo);
          result=TRUE;
          continue;
          break;

        default:
          result=TRUE;
          continue;
          break;
      }
    }

    if (result)
    {

      nosendchar[getAPICID()]=1;
      testRMinterrupt(currentcpuinfo,vmregisters);

    }

  }

  sendstring("Ending realmode emulation\n\r");
  if (!(ISREALMODE(currentcpuinfo)))
  {
    sendstringf("because in protected mode \n\r");
  }

  sendstringf("eip=%x\n\r",vmread(0x681e));
  if (!result)
  {
    sendstring("Because of an error\n\r");
  }

  return success;
}
