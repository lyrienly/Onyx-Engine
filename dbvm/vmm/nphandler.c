#include "vmmhelper.h"
#include "vmxsetup.h"
#include "mm.h"
#include "nphandler.h"
#include "epthandler.h"
#include "main.h"
#include "common.h"

PPML4             np_pml4table=     (PPML4)0xffffffffffffe000ULL;
PPDPTE_PAE np_pagedirptrtables=(PPDPTE_PAE)0xffffffffffc00000ULL;
PPDE_PAE      np_pagedirtables=  (PPDE_PAE)0xffffffff80000000ULL;
PPTE_PAE         np_pagetables=  (PPTE_PAE)0xffffff0000000000ULL;

void NPMode1CloakRestoreCallback(QWORD address UNUSED, CloakedPageData *data)
{
  pcpuinfo c=getcpuinfo();
  *(QWORD *)(data->npentry[c->cpunr])=data->PhysicalAddressData;
  data->npentry[c->cpunr]->P=1;
  data->npentry[c->cpunr]->RW=1;
  data->npentry[c->cpunr]->US=1;

  data->npentry[c->cpunr]->EXB=1;
}

void NPMode1CloakSetState(pcpuinfo currentcpuinfo, int state)

{

  QWORD BaseAddress=currentcpuinfo->NP_Cloak.ActiveRegion->PhysicalAddressExecutable;

  int pml4index;
  int pagedirptrindex;
  int pagedirindex;
  int pagetableindex;
  VirtualAddressToIndexes(BaseAddress, &pml4index, &pagedirptrindex, &pagedirindex, &pagetableindex);

  UINT64 PageDirPtrIndexFull=(pml4index << 9)+pagedirptrindex;
  UINT64 PageDirIndexFull=(PageDirPtrIndexFull << 9)+pagedirindex;
  UINT64 PageTableIndexFull=(PageDirIndexFull << 9)+pagetableindex;

  csEnter(&currentcpuinfo->EPTPML4CS);

  int i;
  for (i=0; i<512; i++)
  {

    if (np_pml4table[i].P)
    {
      if (i==pml4index)
      {
        QWORD i2;
        QWORD i2s=(QWORD)pml4index << 9;

        for (i2=i2s; i2<i2s+512; i2++)
        {

          if (np_pagedirptrtables[i2].P)
          {
            if (i2==PageDirPtrIndexFull)
            {
              QWORD i3;
              QWORD i3s=((QWORD)PageDirPtrIndexFull << 9);
              for (i3=i3s; i3<i3s+512; i3++)
              {

                if (np_pagedirtables[i3].P)
                {
                  if (i3==PageDirIndexFull)
                  {
                    QWORD i4;
                    QWORD i4s=((QWORD)PageDirIndexFull << 9);
                    for (i4=i4s; i4<i4s+512; i4++)
                    {

                      if (np_pagetables[i4].P)
                      {
                        if (i4==PageTableIndexFull)
                          np_pagetables[i4].EXB=0;
                        else
                          np_pagetables[i4].EXB=state;
                      }
                    }
                  }
                  else
                    np_pagedirtables[i3].EXB=state;
                }
              }
            }
            else
              np_pagedirptrtables[i2].EXB=state;
          }
        }
      }
      else
        np_pml4table[i].EXB=state;
    }

  }

  if (state==0)
  {

    if (CloakedPagesMap)
    {
      map_foreach(CloakedPagesMap, (MAPCALLBACK)NPMode1CloakRestoreCallback);
    }
    else
    {
      int i;
      for (i=0; i<CloakedPagesList->size; i++)
        NPMode1CloakRestoreCallback(CloakedPagesList->list[i].address, CloakedPagesList->list[i].data);
    }

  }

  if (((PRFLAGS)(&currentcpuinfo->vmcb->RFLAGS))->IF)
    currentcpuinfo->vmcb->INTERRUPT_SHADOW=1;

  csLeave(&currentcpuinfo->EPTPML4CS);
}

QWORD NPMapPhysicalMemory(pcpuinfo currentcpuinfo, QWORD physicalAddress, int forcesmallpage)

{
  int pml4index;
  int pagedirptrindex;
  int pagedirindex;
  int pagetableindex;
  int swappedguesttables;
  int madepresent=0;
  VirtualAddressToIndexes(physicalAddress, &pml4index, &pagedirptrindex, &pagedirindex, &pagetableindex);

  if (getcpuinfo()!=currentcpuinfo)
  {

    *(QWORD*)(&pml4table[510])=currentcpuinfo->vmcb->N_CR3;
    pml4table[510].P=1;
    pml4table[510].RW=1;
    madepresent=1;
    swappedguesttables=1;
    setCR3(getCR3());
  }

  UINT64 PageDirPtrIndexFull=(pml4index << 9)+pagedirptrindex;
  UINT64 PageDirIndexFull=(PageDirPtrIndexFull << 9)+pagedirindex;
  UINT64 PageTableIndexFull=(PageDirIndexFull << 9)+pagetableindex;

  PPML4 pml4=NULL;
  PPDPTE_PAE_BS pagedirptr=NULL;
  PPDE_PAE pagedir=NULL;
  PPTE_PAE pagetable=NULL;

  QWORD pap;

  csEnter(&currentcpuinfo->EPTPML4CS);

  pml4=(PPML4)&np_pml4table[pml4index];
  if (swappedguesttables)
    _invlpg((QWORD)pml4);

  if (pml4->P==0)
  {

    void *temp=malloc2(4096);
    zeromemory(temp,4096);
    *(QWORD*)pml4=VirtualToPhysical(temp) & MAXPHYADDRMASKPB;
    pml4->P=1;
    pml4->RW=1;
    pml4->US=1;
    madepresent=1;
  }

  pagedirptr=(PPDPTE_PAE_BS)&np_pagedirptrtables[PageDirPtrIndexFull];
  if (madepresent)
    _invlpg((QWORD)pagedirptr);

  if (forcesmallpage && pagedirptr->P && (pagedirptr->PS))
    *(QWORD *)pagedirptr=0;

  if (pagedirptr->P==0)
  {

    if (has_NP_1GBsupport && (forcesmallpage==0))
    {
      QWORD GuestAddress1GBAlign=(physicalAddress & 0xFFFFFFFFC0000000ULL) & MAXPHYADDRMASKPB;

      *(QWORD*)(pagedirptr)=GuestAddress1GBAlign;
      pagedirptr->P=1;
      pagedirptr->RW=1;
      pagedirptr->US=1;
      pagedirptr->PS=1;

      csLeave(&currentcpuinfo->EPTPML4CS);

      pap=VirtualToPhysical((void*)pagedir);
      if (swappedguesttables)
      {

        *(QWORD*)(&pml4table[510])=getcpuinfo()->vmcb->N_CR3;
        pml4table[510].P=1;
        pml4table[510].RW=1;
      }
      return pap;
    }

    void *temp=malloc2(4096);
    zeromemory(temp,4096);
    *(QWORD*)pagedirptr=VirtualToPhysical(temp) & MAXPHYADDRMASKPB;
    pagedirptr->P=1;
    pagedirptr->RW=1;
    pagedirptr->US=1;
    madepresent=1;
  }

  pagedir=(PPDE_PAE)&np_pagedirtables[PageDirIndexFull];
  if (madepresent)
    _invlpg((QWORD)pagedir);

  if (forcesmallpage && pagedir->P && (pagedir->PS))
    *(QWORD *)pagedir=0;

  if (pagedir->P==0)
  {
    if (has_NP_2MBsupport && (forcesmallpage==0))
    {
      QWORD GuestAddress2MBAlign=(physicalAddress & 0xFFFFFFFFFFE00000ULL) & MAXPHYADDRMASKPB;

      *(QWORD*)pagedir=GuestAddress2MBAlign & MAXPHYADDRMASKPB;
      pagedir->P=1;
      pagedir->RW=1;
      pagedir->US=1;
      pagedir->PS=1;
      csLeave(&currentcpuinfo->EPTPML4CS);

      pap=VirtualToPhysical((void*)pagedir);
      if (swappedguesttables)
      {

        *(QWORD*)(&pml4table[510])=getcpuinfo()->vmcb->N_CR3;
        pml4table[510].P=1;
        pml4table[510].RW=1;
      }
      return pap;

    }

    void *temp=malloc2(4096);
    zeromemory(temp,4096);
    *(QWORD*)pagedir=VirtualToPhysical(temp) & MAXPHYADDRMASKPB;
    pagedir->P=1;
    pagedir->RW=1;
    pagedir->US=1;
    madepresent=1;
  }

  pagetable=&np_pagetables[PageTableIndexFull];
  if (madepresent)
    _invlpg((QWORD)pagetable);

  if (pagetable->P==0)
  {

    *(QWORD*)pagetable=physicalAddress & MAXPHYADDRMASKPB;
    pagetable->P=1;
    pagetable->RW=1;
    pagetable->US=1;
    pagetable->EXB=0;
  }
  else
  {

    sendstringf("This physical address (%6) was already mapped\n", physicalAddress);

    PCloakedPageData cloakdata;
    if (CloakedPagesMap)
      cloakdata=map_getEntry(CloakedPagesMap, physicalAddress & MAXPHYADDRMASKPB);
    else
      cloakdata=addresslist_find(CloakedPagesList, physicalAddress & MAXPHYADDRMASKPB);

    if (cloakdata==NULL)
    {

      if (currentcpuinfo->eptUpdated==0)
      {
        nosendchar[getAPICID()]=0;
        sendstringf("%d(%d): Not cloaked and the memorymap isn't updating. Restoring\n", getcpunr(), currentcpuinfo->cpunr);
        *(QWORD*)pagetable=physicalAddress & MAXPHYADDRMASKPB;
        pagetable->P=1;
        pagetable->RW=1;
        pagetable->US=1;
        pagetable->EXB=0;
      }
    }
  }

  csLeave(&currentcpuinfo->EPTPML4CS);

  pap=VirtualToPhysical((void*)pagetable);

  if (swappedguesttables)
  {

    *(QWORD*)(&pml4table[510])=getcpuinfo()->vmcb->N_CR3;
    pml4table[510].P=1;
    pml4table[510].RW=1;
    setCR3(getCR3());
  }

  return pap;
}

VMSTATUS handleNestedPagingFault(pcpuinfo currentcpuinfo, VMRegisters *vmregisters UNUSED, PFXSAVE64 fxsave UNUSED)
{

  nosendchar[getAPICID()]=1;
  QWORD PhysicalAddress=currentcpuinfo->vmcb->EXITINFO2;
  QWORD ErrorInfo=currentcpuinfo->vmcb->EXITINFO1;

  if (ept_handleWatchEvent(currentcpuinfo, vmregisters, fxsave, PhysicalAddress))
    return 0;

  if (ept_handleCloakEvent(currentcpuinfo, PhysicalAddress, 0))
    return 0;

  NPMapPhysicalMemory(currentcpuinfo, PhysicalAddress, 0);

  PEXITINTINFO eii=(PEXITINTINFO)&currentcpuinfo->vmcb->EXITINTINFO;

  if (eii->Valid)
  {

    currentcpuinfo->vmcb->EVENTINJ=currentcpuinfo->vmcb->EXITINTINFO;
  }

  currentcpuinfo->vmcb->VMCB_CLEAN_BITS&=~(1 << 4);

  return VM_OK;
}
