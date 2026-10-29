#ifndef VMM_EPTSTRUCTS_H_
#define VMM_EPTSTRUCTS_H_

#include "common.h"
#include "vmcallstructs.h"

typedef struct _EPT_PML4E
{
  unsigned RA        :  1;
  unsigned WA        :  1;
  unsigned XA        :  1;
  unsigned reserved  :  5;
  unsigned Accessed  :  1;
  unsigned ignored   :  1;
  unsigned XA_UM     :  1;
  unsigned ignored2  :  1;
  unsigned long long PFN       : 36;
  unsigned reserved2 :  4;
  unsigned reserved3 : 12;

} __attribute__((__packed__)) EPT_PML4E, *PEPT_PML4E;

typedef struct _EPT_PDPTE
{
  unsigned RA        :  1;
  unsigned WA        :  1;
  unsigned XA        :  1;
  unsigned MEMTYPE   :  3;
  unsigned PAT_IGNORE:  1;
  unsigned BIG       :  1;
  unsigned Accessed  :  1;
  unsigned Dirty     :  1;
  unsigned XA_UM     :  1;
  unsigned ignored2  :  1;
  unsigned long long PFN       : 36;
  unsigned reserved2 :  4;
  unsigned ignored3  : 11;
  unsigned VESupress :  1;
} __attribute__((__packed__)) EPT_PDPTE, *PEPT_PDPTE;

typedef struct _EPT_PDE
{
  unsigned RA        :  1;
  unsigned WA        :  1;
  unsigned XA        :  1;
  unsigned MEMTYPE   :  3;
  unsigned PAT_IGNORE:  1;
  unsigned BIG       :  1;
  unsigned Accessed  :  1;
  unsigned Dirty     :  1;
  unsigned XA_UM     :  1;
  unsigned ignored2  :  1;
  unsigned long long PFN       : 36;
  unsigned reserved2 :  4;
  unsigned ignored3  : 11;
  unsigned VESupress :  1;
} __attribute__((__packed__)) EPT_PDE, *PEPT_PDE;

typedef struct _EPT_PTE
{
  unsigned RA        :  1;
  unsigned WA        :  1;
  unsigned XA        :  1;
  unsigned MEMTYPE   :  3;
  unsigned PAT_IGNORE:  1;
  unsigned ignored   :  1;
  unsigned Accessed  :  1;
  unsigned Dirty     :  1;
  unsigned XA_UM     :  1;
  unsigned ignored2  :  1;
  unsigned long long PFN       : 36;
  unsigned reserved2 :  4;
  unsigned ignored3  : 11;
  unsigned VESupress :  1;
} __attribute__((__packed__)) EPT_PTE, *PEPT_PTE;

typedef struct _EPTP
{
  unsigned MEMTYPE        :  3;
  unsigned PAGEWALKLENGTH :  3;
  unsigned ACCESSFLAGS    :  1;
  unsigned reserved       :  5;
  unsigned long long PFN            : 36;
  unsigned reserved2      : 16;
} __attribute__((__packed__)) EPTP, *PEPTP;

typedef union _EPT_VIOLATION_INFO
{
  QWORD ExitQualification;
  struct{
    unsigned R        :  1;
    unsigned W        :  1;
    unsigned X        :  1;
    unsigned WasReadable   :  1;
    unsigned WasWritable   :  1;
    unsigned WasExecutable :  1;
    unsigned ANDb10   :  1;
    unsigned GuestLinearAddressValid: 1;
    unsigned AddressAccess: 1;

    unsigned supervisor     : 1;
    unsigned pagingreadonly : 1;
    unsigned XD             : 1;
    unsigned NMIUnblockedDueToIRET : 1;
    unsigned reserved1      : 19;
    DWORD reserved2;
  };
} __attribute__((__packed__)) EPT_VIOLATION_INFO, *PEPT_VIOLATION_INFO;

typedef union _NP_VIOLATION_INFO
{
  QWORD ErrorCode;
  struct{
    unsigned P        :  1;
    unsigned W        :  1;
    unsigned US       :  1;
    unsigned RSRVD    :  1;
    unsigned ID       :  1;
    unsigned reserved1: 27;
    unsigned gfa      :  1;
    unsigned gpt      :  1;
  };
} __attribute__((__packed__)) NP_VIOLATION_INFO, *PNP_VIOLATION_INFO;

typedef struct _fxsave64
{
  WORD FCW;
  WORD FSW;
  BYTE FTW;
  BYTE Reserved;
  WORD FOP;
  UINT64 FPU_IP;
  UINT64 FPU_DP;
  DWORD MXCSR;
  DWORD MXCSR_MASK;
  QWORD FP_MM0;
  QWORD FP_MM0_H;
  QWORD FP_MM1;
  QWORD FP_MM1_H;
  QWORD FP_MM2;
  QWORD FP_MM2_H;
  QWORD FP_MM3;
  QWORD FP_MM3_H;
  QWORD FP_MM4;
  QWORD FP_MM4_H;
  QWORD FP_MM5;
  QWORD FP_MM5_H;
  QWORD FP_MM6;
  QWORD FP_MM6_H;
  QWORD FP_MM7;
  QWORD FP_MM7_H;
  QWORD XMM0;
  QWORD XMM0_H;
  QWORD XMM1;
  QWORD XMM1_H;
  QWORD XMM2;
  QWORD XMM2_H;
  QWORD XMM3;
  QWORD XMM3_H;
  QWORD XMM4;
  QWORD XMM4_H;
  QWORD XMM5;
  QWORD XMM5_H;
  QWORD XMM6;
  QWORD XMM6_H;
  QWORD XMM7;
  QWORD XMM7_H;
  QWORD XMM8;
  QWORD XMM8_H;
  QWORD XMM9;
  QWORD XMM9_H;
  QWORD XMM10;
  QWORD XMM10_H;
  QWORD XMM11;
  QWORD XMM11_H;
  QWORD XMM12;
  QWORD XMM12_H;
  QWORD XMM13;
  QWORD XMM13_H;
  QWORD XMM14;
  QWORD XMM14_H;
  QWORD XMM15;
  QWORD XMM15_H;
  QWORD res1;
  QWORD res1_H;
  QWORD res2;
  QWORD res2_H;
  QWORD res3;
  QWORD res3_H;
  QWORD res4;
  QWORD res4_H;
  QWORD res5;
  QWORD res5_H;
  QWORD res6;
  QWORD res6_H;
} FXSAVE64, *PFXSAVE64;

typedef struct _pageevent_basic
{
  QWORD VirtualAddress;
  QWORD PhysicalAddress;
  QWORD CR3;
  QWORD FSBASE;
  QWORD GSBASE;
  QWORD GSBASE_KERNEL;
  QWORD FLAGS;
  QWORD RAX;
  QWORD RBX;
  QWORD RCX;
  QWORD RDX;
  QWORD RSI;
  QWORD RDI;
  QWORD R8;
  QWORD R9;
  QWORD R10;
  QWORD R11;
  QWORD R12;
  QWORD R13;
  QWORD R14;
  QWORD R15;
  QWORD RBP;
  QWORD RSP;
  QWORD RIP;
  QWORD DR0;
  QWORD DR1;
  QWORD DR2;
  QWORD DR3;
  QWORD DR6;
  QWORD DR7;
  WORD CS;
  WORD DS;
  WORD ES;
  WORD SS;
  WORD FS;
  WORD GS;
  DWORD Count;
} PageEventBasic, *PPageEventBasic;

typedef struct _pageevent_extended
{
  PageEventBasic basic;
  FXSAVE64 fpudata;
} PageEventExtended, *PPageEventExtended;

typedef struct _pageevent_basic_withstack
{
  PageEventBasic basic;
  unsigned char stack[4096];
} PageEventBasicWithStack, *PPageEventBasicWithStack;

typedef struct _pageevent_extended_withstack
{
  PageEventBasic basic;
  FXSAVE64 fpudata;
  unsigned char stack[4096];
} PageEventExtendedWithStack, *PPageEventExtendedWithStack;

#define PE_BASIC 0
#define PE_EXTENDED 1
#define PE_BASICSTACK 2
#define PE_EXTENDEDSTACK 3

typedef struct _pageeventlistdescriptor
{
  DWORD ID;
  DWORD maxNumberOfEntries;
  DWORD numberOfEntries;
  DWORD missedEntries;
  DWORD entryType;
  union
  {
    PageEventBasic basic[0];
    PageEventExtended extended[0];
    PageEventBasicWithStack basics[0];
    PageEventExtendedWithStack extendeds[0];
  } pe;

} PageEventListDescriptor, *PPageEventListDescriptor;

typedef struct
{
  QWORD PhysicalAddress;
  int Size;
  int Type;
  DWORD Options;
  QWORD LoopUserMode;
  QWORD LoopKernelMode;
  int Active;
  int CopyInProgress;
  PPageEventListDescriptor Log;
} EPTWatchEntry, *PEPTWatchEntry;

typedef struct
{
  QWORD PhysicalAddressExecutable;
  QWORD PhysicalAddressData;
  void *Data;
  void *Executable;
  QWORD CloakMode;
  union
  {
    PEPT_PTE eptentry[0];
    PPTE_PAE npentry[0];
  };

  BYTE InvokingCPU;
  BYTE LastWritingCPU;
} CloakedPageData, *PCloakedPageData;

typedef struct
{
  int Active;
  PCloakedPageData cloakdata;
  QWORD PhysicalAddress;
  unsigned char originalbyte;
  CHANGEREGONBPINFO changereginfo;
} ChangeRegBPEntry, *PChangeRegBPEntry;

typedef struct
{
  int triggered;
  QWORD triggeredcr3;
  QWORD triggeredfsbase;
  QWORD triggeredgsbase;
  int count;

  int shouldquit;
  int finished;
  QWORD PhysicalAddress;
  unsigned char originalbyte;
  PCloakedPageData cloakdata;

  int datatype;
  int numberOfEntries;
  union
  {
    PageEventBasic basic[0];
    PageEventExtended extended[0];
    PageEventBasicWithStack basics[0];
    PageEventExtendedWithStack extendeds[0];
  } pe;

} TraceOnBPEntry, *PTraceOnBPEntry;

typedef struct
{
  int inuse;
  int continueMethod;
  int watchid;

  QWORD UserModeLoop;
  QWORD KernelModeLoop;

  PageEventExtended state;
} BrokenThreadEntry, *PBrokenThreadEntry;

#endif
