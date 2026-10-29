#ifndef VMXOFFLOAD_H
#define VMXOFFLOAD_H

void cleanupDBVM();
void initializeDBVM(PCWSTR dbvmimgpath);
void vmxoffload(void);

void vmxoffload_override(CCHAR cpunr, PKDEFERRED_ROUTINE Dpc, PVOID DeferredContext, PVOID *SystemArgument1, PVOID *SystemArgument2);

VOID vmxoffload_dpc(
	__in struct _KDPC *Dpc,
	__in_opt PVOID DeferredContext,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2
	);

typedef struct _DBVMOffloadMemInfo
{
	UINT64 *List;
	int Count;
} DBVMOffloadMemInfo, *PDBVMOffloadMemInfo;

#pragma pack (1)
typedef struct _PTE
{
        unsigned P         :  1;
        unsigned RW        :  1;
        unsigned US        :  1;
        unsigned PWT       :  1;
        unsigned PCD       :  1;
        unsigned A         :  1;
        unsigned D         :  1;
        unsigned PAT       :  1;
        unsigned G         :  1;
        unsigned A1        :  1;
        unsigned A2        :  1;
        unsigned A3        :  1;
        unsigned PFN       : 20;
} *PPTE;

typedef struct _PDE
{
        unsigned P         :  1;
        unsigned RW        :  1;
        unsigned US        :  1;
        unsigned PWT       :  1;
        unsigned PCD       :  1;
        unsigned A         :  1;
        unsigned D         :  1;
        unsigned PS        :  1;
        unsigned G         :  1;
        unsigned A1        :  1;
        unsigned A2        :  1;
        unsigned A3        :  1;
        unsigned PFN       : 20;
} *PPDE;

typedef struct _PDE2MB
{
        unsigned P         :  1;
        unsigned RW        :  1;
        unsigned US        :  1;
        unsigned PWT       :  1;
        unsigned PCD       :  1;
        unsigned A         :  1;
        unsigned reserved1 :  1;
        unsigned PS        :  1;
        unsigned reserved3 :  1;
        unsigned A1        :  1;
        unsigned A2        :  1;
        unsigned A3        :  1;
        unsigned PFN       : 20;
} *PPDE2MB;

typedef struct _PTE_PAE
{
        unsigned P         :  1;
        unsigned RW        :  1;
        unsigned US        :  1;
        unsigned PWT       :  1;
        unsigned PCD       :  1;
        unsigned A         :  1;
        unsigned D         :  1;
        unsigned PAT       :  1;
        unsigned G         :  1;
        unsigned A1        :  1;
        unsigned A2        :  1;
        unsigned A3        :  1;
		unsigned PFN_LOW : 20;
		unsigned PFN_HIGH : 32;
} PTE_PAE, *PPTE_PAE;

typedef struct _PDE_PAE
{
        unsigned P         :  1;
        unsigned RW        :  1;
        unsigned US        :  1;
        unsigned PWT       :  1;
        unsigned PCD       :  1;
        unsigned A         :  1;
        unsigned D         :  1;
        unsigned PS        :  1;
        unsigned G         :  1;
        unsigned A1        :  1;
        unsigned A2        :  1;
        unsigned A3        :  1;
		unsigned PFN_LOW : 20;
		unsigned PFN_HIGH : 32;
} PDE_PAE, *PPDE_PAE;

typedef struct _PDE2MB_PAE
{
        unsigned P         :  1;
        unsigned RW        :  1;
        unsigned US        :  1;
        unsigned PWT       :  1;
        unsigned PCD       :  1;
        unsigned A         :  1;
        unsigned reserved1 :  1;
        unsigned PS        :  1;
        unsigned reserved3 :  1;
        unsigned A1        :  1;
        unsigned A2        :  1;
        unsigned A3        :  1;
        unsigned PAT       :  1;
		unsigned PFN_LOW : 19;
		unsigned PFN_HIGH : 32;
} *PPDE2MB_PAE;

typedef struct _PDPTE_PAE
{
        unsigned P         :  1;
        unsigned RW        :  1;
        unsigned US        :  1;
        unsigned PWT       :  1;
        unsigned PCD       :  1;
		unsigned reserved0 : 1;
		unsigned reserved1 : 1;
		unsigned reserved2 : 1;
		unsigned reserved3 : 1;
        unsigned A1        :  1;
        unsigned A2        :  1;
        unsigned A3        :  1;
		unsigned PFN_LOW : 20;
		unsigned PFN_HIGH : 32;
} *PPDPTE_PAE;

#endif
