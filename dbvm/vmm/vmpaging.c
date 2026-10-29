#include "vmpaging.h"
#include "vmmhelper.h"
#include "common.h"
#include "mm.h"
#include "multicore.h"
#include "main.h"
#include "vmreadwrite.h"
#include "msrnames.h"
#include "vmxsetup.h"

unsigned int pagetablesize;

volatile void *nonpagedInvalidEmulationPagedir;

void unmapVMmemory(void *address, int size)
{
    unmapPhysicalMemory(address, size);
}

void * mapVMmemory(pcpuinfo currentcpuinfo, UINT64 address, int size, int *error, UINT64 *pagefaultaddress)
{
  return mapVMmemoryEx(currentcpuinfo, address, size, error, pagefaultaddress,0);
}

void * mapVMmemoryEx(pcpuinfo currentcpuinfo, UINT64 address, int size, int *error, UINT64 *pagefaultaddress, int donotunmaponfail )
{

  if (size==0)
  {
    *error=3;
    *pagefaultaddress=0;
    return NULL;
  }

  unsigned int offset=address & 0xfff;

  if (currentcpuinfo==NULL)
    currentcpuinfo=getcpuinfo();

  int totalsize=size+offset;
  int pagecount=(totalsize / 4096);
  int pml4index;
  int pagedirptrindex;
  int pagedirindex;
  int pagetableindex;
  VirtualAddressToIndexes(address, &pml4index, &pagedirptrindex, &pagedirindex, &pagetableindex);

  if (totalsize % 4096)
      pagecount++;

  int pos=mmFindMapPositionForSize(currentcpuinfo, totalsize);

  if (pos==-1)
  {
    if (error)
      *error=1;

    if (pagefaultaddress)
      *pagefaultaddress=0;
    return 0;
  }

  int i;
  int notpaged=0;

  void *VirtualAddress=(void *)(getMappedMemoryBase()+pos*4096+offset);

  address=address & 0xfffffffffffff000ULL;
  QWORD CurrentVirtualAddress=(QWORD)VirtualAddress & 0xfffffffffffff000ULL;

  for (i=0; i<pagecount; i++)
  {

    QWORD PhysicalAddress=getPhysicalAddressVM(currentcpuinfo,address, &notpaged);

    if (notpaged)
    {

      if (donotunmaponfail==0)
        unmapVMmemory(VirtualAddress, i*4096-offset);

      if (pagefaultaddress)
        *pagefaultaddress=address;

      if (error)
        *error=2;

      if (donotunmaponfail==0)
        return 0;
      else
        return VirtualAddress;
    }

    *(QWORD*)(&currentcpuinfo->mappagetables[pos])=PhysicalAddress;
    currentcpuinfo->mappagetables[pos].P=1;
    currentcpuinfo->mappagetables[pos].RW=1;
    currentcpuinfo->mappagetables[pos].US=1;

    asm volatile ("": : :"memory");
    _invlpg(CurrentVirtualAddress);
    asm volatile ("": : :"memory");

    pos++;
    address+=4096;
    CurrentVirtualAddress+=4096;
  }

  if (error)
    *error=0;

  if (pagefaultaddress)
    *pagefaultaddress=0;

  return VirtualAddress;
}

UINT64 getPhysicalAddressVM(pcpuinfo currentcpuinfo, UINT64 address, int *notpaged)
{
  regCR4 usedCR4;
  DWORD cr0;
  if (isAMD)
  {
    usedCR4.CR4=currentcpuinfo->vmcb->CR4;
    cr0=currentcpuinfo->vmcb->CR0;
  }
  else
  {
    usedCR4.CR4=vmread(vm_guest_cr4);
    if (hasUnrestrictedSupport)
      cr0=vmread(vm_guest_cr0);
    else
      cr0=vmread(vm_cr0_read_shadow);

  }

  UINT64  pagebase;

  *notpaged=0;

  if (isAMD)
  {
    regCR0 usedCR0;
    usedCR0.CR0=cr0;

    if (usedCR0.PG)
    {

      pagebase=currentcpuinfo->vmcb->CR3;
    }
    else
    {

      pagebase=0;
      return address;
    }
  }
  else
  {
    if ((cr0 & 0x80000001) == 0x80000001)
    {

      pagebase=currentcpuinfo->guestCR3;

    }
    else
    {
      if (hasUnrestrictedSupport)
      {

        *notpaged=0;
        return address;
      }

      pagebase=vmread(vm_guest_cr3);
    }
  }
#ifdef DEBUG
  if (pagebase==0xffffffffffffffffULL)
  {
    nosendchar[getAPICID()]=0;
    sendstringf("getPhysicalAddressVM for with cr3 of 0xffffffffffffffff\n");
    jtagbp();
    while (1) outportb(0x80,0xdd);
  }
#endif

  pagebase=pagebase & MAXPHYADDRMASKPB;

  if (IS64BITPAGING(currentcpuinfo))
  {
    UINT64   pml4entry=(UINT64)address >> 39 & 0x1ff;
    PPDE_PAE realpml4table=(PPDE_PAE)mapPhysicalMemory((UINT64)pagebase,4096);

    if (realpml4table[pml4entry].P)
    {
      UINT64     pagedirptrentry=(UINT64)address >> 30 & 0x1ff;
      PPDE_PAE  realpagedirptrtable=(PPDE_PAE)mapPhysicalMemory(*(UINT64*)(&realpml4table[pml4entry]) & MAXPHYADDRMASKPB, 4096);

      if (realpagedirptrtable[pagedirptrentry].P)
      {
        PPDE_PAE realpagedirtable=(PPDE_PAE)mapPhysicalMemory(*(UINT64*)(&realpagedirptrtable[pagedirptrentry]) & MAXPHYADDRMASKPB,4096);
        UINT64    pagedirentry=(UINT64)address >> 21 & 0x1ff;

        if (realpagedirtable[pagedirentry].P)
        {

          if (realpagedirtable[pagedirentry].PS)
          {

            QWORD _address=(*(UINT64*)(&realpagedirtable[pagedirentry]) & MAXPHYADDRMASKPB )+ (UINT64)(address & 0x1FFFFF);
            unmapPhysicalMemory((void *)realpml4table, 4096);
            unmapPhysicalMemory((void *)realpagedirptrtable, 4096);
            unmapPhysicalMemory((void *)realpagedirtable, 4096);
            return _address;
          }
          else
          {
            UINT64    pagetableentry=address >> 12 & 0x1ff;
            PPTE_PAE realpagetable=(PPTE_PAE)mapPhysicalMemory(*(UINT64*)(&realpagedirtable[pagedirentry]) & MAXPHYADDRMASKPB,  4096);

            if (realpagetable[pagetableentry].P)
            {
              QWORD _address=(*(UINT64*)(&realpagetable[pagetableentry]) & MAXPHYADDRMASKPB)+ (UINT64)(address & 0xFFF);
              unmapPhysicalMemory((void *)realpml4table, 4096);
              unmapPhysicalMemory((void *)realpagedirptrtable, 4096);
              unmapPhysicalMemory((void *)realpagedirtable, 4096);
              unmapPhysicalMemory((void *)realpagetable, 4096);
              return _address;
            }
            unmapPhysicalMemory((void *)realpagetable, 4096);
          }
        }
        unmapPhysicalMemory((void *)realpagedirtable, 4096);
      }
      unmapPhysicalMemory((void *)realpagedirptrtable, 4096);
    }
    unmapPhysicalMemory((void *)realpml4table, 4096);
  }
  else
  if (usedCR4.PAE)
  {

    UINT64      pagedirptrentry=((UINT64)address >> 30) & 0x1ff;

    PPDPTE_PAE realpagedirptrtable=(PPDPTE_PAE)mapPhysicalMemory(pagebase,4096);

    if (realpagedirptrtable[pagedirptrentry].P)
    {
      UINT64    pagedirentry=((UINT64)address >> 21) & 0x1ff;
      PPDE_PAE realpagedirtable=(PPDE_PAE)mapPhysicalMemory(*(UINT64*)(&realpagedirptrtable[pagedirptrentry]) & MAXPHYADDRMASKPB,4096);

      if (realpagedirtable[pagedirentry].P)
      {

        if (realpagedirtable[pagedirentry].PS)
        {
          QWORD _address=(*(UINT64*)(&realpagedirtable[pagedirentry]) & MAXPHYADDRMASKPB) + ((UINT64)address & 0x1FFFFF);
          unmapPhysicalMemory((void *)realpagedirptrtable, 4096);
          unmapPhysicalMemory((void *)realpagedirtable, 4096);
          return _address;
        }
        else
        {
          UINT64    pagetableentry=(UINT64)address >> 12 & 0x1ff;

          PPTE_PAE realpagetable=(PPTE_PAE)mapPhysicalMemory(*(UINT64*)(&realpagedirtable[pagedirentry]) & MAXPHYADDRMASKPB, 4096);

          if (realpagetable[pagetableentry].P==1)
          {
            unmapPhysicalMemory((void *)realpagedirptrtable, 4096);
            unmapPhysicalMemory((void *)realpagedirtable, 4096);
            unmapPhysicalMemory((void *)realpagetable, 4096);
            return (*(UINT64*)(&realpagetable[pagetableentry]) & MAXPHYADDRMASKPB)+ (address & 0xFFF);
          }
          unmapPhysicalMemory((void *)realpagetable, 4096);
        }
      }
      unmapPhysicalMemory((void *)realpagedirtable, 4096);
    }
    unmapPhysicalMemory((void *)realpagedirptrtable, 4096);
  }
  else
  {

    ULONG pagedirentry=address >> 22;
    PPDE  realpagedirtable=(PPDE)mapPhysicalMemory(pagebase, 4096);
    sendstring("Non-PAE mode\n\r");

    if (realpagedirtable[pagedirentry].P)
    {
      if (realpagedirtable[pagedirentry].PS)
      {

        QWORD _address=(*(UINT64*)(&realpagedirtable[pagedirentry]) & MAXPHYADDRMASKPB)+ (address & 0x3FFFFF);
        unmapPhysicalMemory((void *)realpagedirtable, 4096);
        return _address;
      }
      else
      {
        ULONG pagetableentry=(UINT64)address >> 12 & 0x3ff;
        PPTE  realpagetable=(PPTE)mapPhysicalMemory(*(UINT64*)(&realpagedirtable[pagedirentry]) & MAXPHYADDRMASKPB, 4096);

        if (realpagetable[pagetableentry].P==1)
        {
          QWORD _address=(*(UINT64*)(&realpagetable[pagetableentry]) & MAXPHYADDRMASKPB)+ (address & 0xFFF);
          unmapPhysicalMemory((void *)realpagetable, 4096);
          return _address;
        }
        unmapPhysicalMemory((void *)realpagetable, 4096);
      }
    }
    unmapPhysicalMemory((void *)realpagedirtable, 4096);
  }

  sendstring("Not handled by anything\n\r");

  *notpaged=1;
  return 0;
}

int ReadBytesFromPage(pcpuinfo currentcpuinfo, UINT64 address, unsigned char *buf,int size)

{
  int i;
  int notpaged=0;
  QWORD physicalAddress;
  physicalAddress=getPhysicalAddressVM(currentcpuinfo, address, &notpaged);

  if (!notpaged)
  {

    unsigned char *tempbuf=(unsigned char *)mapPhysicalMemory(physicalAddress, 4096);
    int leftforthispage=0x1000-(address & 0xfff);

    if (leftforthispage>size)
      leftforthispage=size;

    for (i=0; i<leftforthispage; i++)
      buf[i]=tempbuf[i];

    unmapPhysicalMemory(tempbuf, 4096);

    return leftforthispage;
  }
  else
    return 0;

}

int ReadVMMemory(pcpuinfo currentcpuinfo, UINT64 address, unsigned char *buf,int size)

{
  int position=0;

  while (position<size)
  {
    int lastread;
    lastread=ReadBytesFromPage(currentcpuinfo, address+position, &buf[position], size-position);
    position+=lastread;

    if (lastread==0)
      break;
  }

  return position;
}

int handleINVLPG(pcpuinfo currentcpuinfo UNUSED)
{

  vmwrite(vm_guest_rip,vmread(vm_guest_rip)+vmread(vm_exit_instructionlength));
  return 0;
}

int emulatePaging(pcpuinfo currentcpuinfo)

{

  sendstring("emulatePaging\n");

  if  ((vmread(vm_cr0_read_shadow) & 0x80000001)==0x80000001)
  {
    if (currentcpuinfo->cr3_callback.changedcr3)
    {
      vmwrite(vm_guest_cr3, currentcpuinfo->cr3_callback.newcr3);
    }
    else
    {
      sendstringf("Changing the real CR3 from %6 to %6\n",vmread(vm_guest_cr3),currentcpuinfo->guestCR3);
      vmwrite(vm_guest_cr3, currentcpuinfo->guestCR3);
    }

    return 0;
  }
  else
  {
    sendstringf("Not in paging and protected mode. vm_cr0_fakeread=%6\n",vmread(vm_cr0_read_shadow));

  }

  return 0;

}

int setupRealModePaging(pcpuinfo currentcpuinfo)

{
  return setupNonPagedPaging(currentcpuinfo);
}

criticalSection setupNonPagedPagingCS={.name="setupNonPagedPagingCS", .debuglevel=2};
int setupNonPagedPaging(pcpuinfo currentcpuinfo)
{

  if (hasUnrestrictedSupport)
    return 0;

  int        is64bitpaging=IS64BITPAGING(currentcpuinfo);

	unsigned int i;

  if (nonpagedEmulationPagedir==NULL)
  {
    csEnter(&setupNonPagedPagingCS);
    if (nonpagedEmulationPagedir==NULL)
    {
      PPDPTE_PAE VirtualMachinePageDirPointer;
      PPDE_PAE   VirtualMachinePageDir;

      sendstringf("Setting up protected mode paging for nonpaged emu\n\r");

      nonpagedEmulationPagedir=malloc(4096+4096+4096*8);
      zeromemory(nonpagedEmulationPagedir,4096+4096+4096*8);

      PPDE_PAE pml4table=nonpagedEmulationPagedir;
      VirtualMachinePageDirPointer=(PPDPTE_PAE)(((QWORD)nonpagedEmulationPagedir)+0x1000);
      nonpagedEmulationPagedir32BitPAE=(void *)VirtualMachinePageDirPointer;

      *(QWORD *)(&pml4table[0])=VirtualToPhysical((void *)VirtualMachinePageDirPointer);
      pml4table[0].P=1;
      pml4table[0].RW=1;

      VirtualMachinePageDir=(PPDE_PAE)(((QWORD)VirtualMachinePageDirPointer)+0x1000);
      nonpagedEmulationPagedir32Bit=(void *)VirtualMachinePageDir;

      sendstringf("VirtualMachinePML4=%6\n\r",(UINT64)pml4table);
      sendstringf("VirtualMachinePageDirPointer=%6\n\r",(UINT64)VirtualMachinePageDirPointer);
      sendstringf("VirtualMachinePageDir=%6\n\r",(UINT64)VirtualMachinePageDir);

      for (i=0; i<8; i++)
      {
        *(QWORD*)(&VirtualMachinePageDirPointer[i])=VirtualToPhysical((void *)((UINT64)VirtualMachinePageDir+(i*4096)));
        VirtualMachinePageDirPointer[i].P=1;
        if (is64bitpaging)
          VirtualMachinePageDirPointer[i].RW=1;
      }

      for (i=0; i<4096; i++)
      {

        *(QWORD *)(&VirtualMachinePageDir[i])=i*0x00200000;
        VirtualMachinePageDir[i].P=1;
        VirtualMachinePageDir[i].A=0;
        VirtualMachinePageDir[i].RW=1;
        VirtualMachinePageDir[i].US=1;
        VirtualMachinePageDir[i].PS=1;

        VirtualMachinePageDir[i].PCD=0;
        VirtualMachinePageDir[i].PWT=0;
      }

      nonpagedEmulationPagedirPA=(UINT64)VirtualToPhysical((void *)nonpagedEmulationPagedir);
      nonpagedEmulationPagedir32BitPAEPA=(UINT64)VirtualToPhysical((void *)nonpagedEmulationPagedir32BitPAE);
      nonpagedEmulationPagedir32BitPA=(UINT64)VirtualToPhysical((void *)nonpagedEmulationPagedir32Bit);

    }
    csLeave(&setupNonPagedPagingCS);
  }
  sendstring("Setting up nonpaged paging for ");

  if (is64bitpaging)
  {
    sendstring("64-bit mode\n");
    vmwrite(vm_guest_cr3,nonpagedEmulationPagedirPA);
  }
  else
  {

    if (vmread(vm_guest_cr4) & CR4_PAE)
    {
      sendstring("32-bit PAE mode\n");
      vmwrite(vm_guest_cr3, nonpagedEmulationPagedir32BitPAEPA);
    }
    else
    {
      sendstring("32-bit mode\n");
      vmwrite(vm_guest_cr3,nonpagedEmulationPagedir32BitPA);
    }
  }

  return 0;
}

int setupNonPagedPaging_invalidstate_c0000(pcpuinfo currentcpuinfo, UINT64 cs_base)
{

  volatile PPDPTE_PAE VirtualMachinePageDirPointer;
  volatile PPDE_PAE   VirtualMachinePageDir;
  volatile PPTE_PAE   VirtualMachinePageTable;

  int        is64bitpaging=IS64BITPAGING(currentcpuinfo);
  int        orig=nosendchar[getAPICID()];

  nosendchar[getAPICID()]=0;

  sendstring("Setting up protected mode page for nonpaged emu (INVALID STATE)\n\r");

  if (is64bitpaging)
  {
    if (nonpagedInvalidEmulationPagedir==NULL)
      nonpagedInvalidEmulationPagedir=malloc(4096+4096+4096+4096);

    zeromemory(nonpagedInvalidEmulationPagedir,4096+4096+4096+4096);
  }
  else
  {
    if (nonpagedInvalidEmulationPagedir==NULL)
      nonpagedInvalidEmulationPagedir=malloc(4096+4096+4096);

    zeromemory(nonpagedInvalidEmulationPagedir,4096+4096+4096);
  }

  sendstringf("Allocated nonpagedInvalidEmulationPagedir at %6\n\r",(UINT64)nonpagedInvalidEmulationPagedir);

  if (is64bitpaging)
  {

    volatile PPDE_PAE pml4table=nonpagedInvalidEmulationPagedir;
    VirtualMachinePageDirPointer=nonpagedInvalidEmulationPagedir+0x1000;
    *(QWORD*)(&pml4table[0])=VirtualToPhysical((void *)nonpagedInvalidEmulationPagedir);
    pml4table[0].P=1;
    pml4table[0].RW=1;
    sendstring("in 64-bit mode paging, shouldn\'t be used, since it\'s only enabled when paging is on");
  }
  else
    VirtualMachinePageDirPointer=nonpagedInvalidEmulationPagedir;

  VirtualMachinePageDir=(void *)((UINT64)VirtualMachinePageDirPointer+0x1000);
  VirtualMachinePageTable=(void *)((UINT64)VirtualMachinePageDir+0x1000);

  sendstringf("VirtualMachinePageDirPointer=%6\n\r",(UINT64)VirtualMachinePageDirPointer);
  sendstringf("VirtualMachinePageDir=%6\n\r",(UINT64)VirtualMachinePageDir);

  *(QWORD*)(&VirtualMachinePageDirPointer[0])=VirtualToPhysical((void *)VirtualMachinePageDir);
  VirtualMachinePageDirPointer[0].P=1;
  if (is64bitpaging)
    VirtualMachinePageDirPointer[0].RW=1;

  *(QWORD*)(&VirtualMachinePageDir[0])=VirtualToPhysical((void *)VirtualMachinePageTable);
  VirtualMachinePageDir[0].P=1;
  VirtualMachinePageDir[0].A=0;
  VirtualMachinePageDir[0].RW=1;
  VirtualMachinePageDir[0].US=1;
  VirtualMachinePageDir[0].PS=0;
  VirtualMachinePageDir[0].PCD=0;
  VirtualMachinePageDir[0].PWT=0;

  *(QWORD*)(&VirtualMachinePageTable[0xc0])=cs_base;
  VirtualMachinePageTable[0xc0].P=1;
  VirtualMachinePageTable[0xc0].A=0;
  VirtualMachinePageTable[0xc0].RW=1;
  VirtualMachinePageTable[0xc0].US=1;
  VirtualMachinePageTable[0xc0].PCD=0;
  VirtualMachinePageTable[0xc0].PWT=0;

  vmwrite(vm_guest_cr3,(UINT64)VirtualToPhysical((void *)nonpagedInvalidEmulationPagedir));

  nosendchar[getAPICID()]=orig;

  return 0;
}
