#pragma warning( disable: 4103)

#include <ntifs.h>
#include <ntddk.h>
#include "DBKFunc.h"
#include "vmxhelper.h"

#ifdef TESTCOMPILE

void _enable() {}
void _disable() {}
#endif

void forEachCpuPassive(PF f, UINT_PTR param)

{
	CCHAR cpunr;
	KAFFINITY cpus, original;
	ULONG cpucount;

	cpucount=0;
	cpus=KeQueryActiveProcessors();
	original=cpus;
	while (cpus)
	{
		if (cpus % 2)
			cpucount++;

		cpus=cpus / 2;
	}

	cpus=KeQueryActiveProcessors();
	cpunr=0;
	while (cpus)
	{
		if (cpus % 2)
		{

#if (NTDDI_VERSION >= NTDDI_VISTA)
			KAFFINITY oldaffinity;
#endif
			KAFFINITY newaffinity;

			newaffinity=(KAFFINITY)(1 << cpunr);

#if (NTDDI_VERSION >= NTDDI_VISTA)
			oldaffinity=KeSetSystemAffinityThreadEx(newaffinity);
#else

			{
				LARGE_INTEGER delay;
				delay.QuadPart=-50;

				KeSetSystemAffinityThread(newaffinity);
				KeDelayExecutionThread(UserMode, FALSE, &delay);
			}
#endif

			f(param);

#if (NTDDI_VERSION >= NTDDI_VISTA)
			KeRevertToUserAffinityThreadEx(oldaffinity);
#endif

		}

		cpus=cpus / 2;
		cpunr++;
	}

#if (NTDDI_VERSION < NTDDI_VISTA)
	KeSetSystemAffinityThread(original);
#endif
}

void forOneCpu(CCHAR cpunr, PKDEFERRED_ROUTINE dpcfunction, PVOID DeferredContext, PVOID  SystemArgument1, PVOID  SystemArgument2, OPTIONAL PPREDPC_CALLBACK preDPCCallback)
{
	PKDPC dpc;

	if (preDPCCallback)
		preDPCCallback(cpunr, dpcfunction, DeferredContext, &SystemArgument1, &SystemArgument2);

	dpc = ExAllocatePoolWithTag(DBK_POOL_NX, sizeof(KDPC), 'kcpD');
	if (!dpc)
		return;
	KeInitializeDpc(dpc, dpcfunction, DeferredContext);
	KeSetTargetProcessorDpc(dpc, cpunr);
	KeInsertQueueDpc(dpc, SystemArgument1, SystemArgument2);
	KeFlushQueuedDpcs();

	ExFreePoolWithTag(dpc, 'kcpD');
}

void forEachCpu(PKDEFERRED_ROUTINE dpcfunction,  PVOID DeferredContext, PVOID  SystemArgument1, PVOID  SystemArgument2, OPTIONAL PPREDPC_CALLBACK preDPCCallback)

{
	CCHAR cpunr;
	KAFFINITY cpus;
	ULONG cpucount;
	PKDPC dpc;
	int dpcnr;

	cpucount=0;
	cpus=KeQueryActiveProcessors();
	while (cpus)
	{
		if (cpus % 2)
			cpucount++;

		cpus=cpus / 2;
	}

	dpc = (PKDPC)ExAllocatePoolWithTag(DBK_POOL_NX, sizeof(KDPC) * cpucount, 'kcpD');
	if (!dpc)
		return;

	cpus=KeQueryActiveProcessors();
	cpunr=0;
	dpcnr=0;
	while (cpus)
	{
		if (cpus % 2)
		{

			if (preDPCCallback)
				preDPCCallback(cpunr, dpcfunction, DeferredContext, &SystemArgument1, &SystemArgument2);

			KeInitializeDpc(&dpc[dpcnr], dpcfunction, DeferredContext);
			KeSetTargetProcessorDpc (&dpc[dpcnr], cpunr);
			KeInsertQueueDpc(&dpc[dpcnr], SystemArgument1, SystemArgument2);
			KeFlushQueuedDpcs();
			dpcnr++;
		}

		cpus=cpus / 2;
		cpunr++;
	}

	ExFreePoolWithTag(dpc, 'kcpD');
}

void forEachCpuAsync(PKDEFERRED_ROUTINE dpcfunction, PVOID DeferredContext, PVOID  SystemArgument1, PVOID  SystemArgument2, OPTIONAL PPREDPC_CALLBACK preDPCCallback)

{
	CCHAR cpunr;
	KAFFINITY cpus;
	ULONG cpucount;
	PKDPC dpc;
	int dpcnr;

	cpucount = 0;
	cpus = KeQueryActiveProcessors();
	while (cpus)
	{
		if (cpus % 2)
			cpucount++;

		cpus = cpus / 2;
	}

	dpc = (PKDPC)ExAllocatePoolWithTag(DBK_POOL_NX, sizeof(KDPC) * cpucount, 'kcpD');
	if (!dpc)
		return;

	cpus = KeQueryActiveProcessors();
	cpunr = 0;
	dpcnr = 0;
	while (cpus)
	{
		if (cpus % 2)
		{

			if (preDPCCallback)
				preDPCCallback(cpunr, dpcfunction, DeferredContext, &SystemArgument1, &SystemArgument2);

			KeInitializeDpc(&dpc[dpcnr], dpcfunction, DeferredContext);
			KeSetTargetProcessorDpc(&dpc[dpcnr], cpunr);
			KeInsertQueueDpc(&dpc[dpcnr], SystemArgument1, SystemArgument2);
			dpcnr++;
		}

		cpus = cpus / 2;
		cpunr++;
	}

	KeFlushQueuedDpcs();

	ExFreePoolWithTag(dpc, 'kcpD');
}

void spinlock(volatile LONG *lockvar)
{
	while (1)
	{

		if (_InterlockedExchange((volatile LONG *)lockvar, 1)==0)
			return;

		_mm_pause();

	}

}

void csEnter(PcriticalSection CS)
{
	EFLAGS oldstate=getEflags();

	if ((CS->locked) && (CS->cpunr==cpunr()))
	{

	    CS->lockcount++;
	    return;
	}

	disableInterrupts();

	spinlock(&(CS->locked));

	CS->lockcount=1;
	CS->cpunr=cpunr();
	CS->oldIFstate=oldstate.IF;
}

void csLeave(PcriticalSection CS)
{
	if ((CS->locked) && (CS->cpunr==cpunr()))
	{
	    CS->lockcount--;
	    if (CS->lockcount==0)
	    {

			if (CS->oldIFstate)
				enableInterrupts();

			CS->cpunr=-1;
			CS->locked=0;
		}
	}

}

int getCpuCount(void)
{
	KAFFINITY ap=KeQueryActiveProcessors();
	int count=0;
	while (ap>0)
	{
		if (ap % 2)
			count++;

		ap=ap / 2;
	}
	return count;
}

int isPrefix(unsigned char b)
{
	switch (b)
	{
		case 0x26:
		case 0x2e:
		case 0x36:
		case 0x3e:
		case 0x64:
		case 0x65:
		case 0x66:
		case 0x67:
		case 0xf0:
		case 0xf2:
		case 0xf3:
			return 1;

		default:
			return 0;

	}

}

UINT64 getDR7(void)
{
	return __readdr(7);

}

int cpunr(void)
{
	DWORD x[4];
	__cpuid(&x[0],1);

	return (x[1] >> 24)+1;

}

EFLAGS getEflags(void)
{
	UINT64 x=__getcallerseflags();
	PEFLAGS y = (PEFLAGS)&x;
	return *y;
}

UINT64 readMSR(DWORD msr)
{
	return __readmsr(msr);
}

void setCR0(UINT64 newcr0)
{
	__try
	{
		__writecr0(newcr0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("setCR0: interceptado pelo hipervisor/HVCI, modificacao de CR0 ignorada para evitar BSOD\n");
	}
}

UINT64 getCR0(void)
{
	return __readcr0();
}

UINT64 getCR2(void)
{
	return __readcr2();
}

void setCR3(UINT64 newCR3)
{
	__writecr3((UINT_PTR)newCR3);
}

UINT64 getCR3(void)
{
	return __readcr3();
}

void setCR4(UINT64 newcr4)
{
	__writecr4(newcr4);
}

UINT64 getCR4(void)
{
	return __readcr4();
}

void GetIDT(PIDT pIdt)
{
	__sidt(pIdt);
}

void enableInterrupts(void)
{
#ifdef AMD64
	_enable();
#else
	__asm{sti};
#endif
}

void disableInterrupts(void)
{
#ifdef AMD64
	_disable();
#else
	__asm{cli};
#endif
}

UINT64 getTSC(void)
{
	return __rdtsc();
}

#ifndef AMD64

_declspec( naked ) WORD getSS(void)
{
	__asm
	{
		mov ax,ss
		ret
	}
}

_declspec( naked ) WORD getCS(void)
{
	__asm
	{
		mov ax,cs
		ret
	}
}

_declspec( naked ) WORD getDS(void)
{
	__asm
	{
		mov ax,ds
		ret
	}
}

_declspec( naked ) WORD getES(void)
{
	__asm
	{
		mov ax,es
		ret
	}
}

_declspec( naked ) WORD getFS(void)
{
	__asm
	{
		mov ax,fs
		ret
	}
}

_declspec( naked ) WORD getGS(void)
{
	__asm
	{
		mov ax,gs
		ret
	}
}

_declspec( naked ) ULONG getRSP(void)
{
	__asm
	{
		mov eax,esp
		add eax,4
		ret
	}
}

_declspec( naked ) ULONG getRBP(void)
{
	__asm
	{
		mov eax,ebp
		ret
	}
}

_declspec( naked ) ULONG getRAX(void)
{
	__asm
	{
		mov eax,eax
		ret
	}
}
_declspec( naked ) ULONG getRBX(void)
{
	__asm
	{
		mov eax,ebx
		ret
	}
}
_declspec( naked ) ULONG getRCX(void)
{
	__asm
	{
		mov eax,ecx
		ret
	}
}
_declspec( naked ) ULONG getRDX(void)
{
	__asm
	{
		mov eax,edx
		ret
	}
}
_declspec( naked ) ULONG getRSI(void)
{
	__asm
	{
		mov eax,esi
		ret
	}
}
_declspec( naked ) ULONG getRDI(void)
{
	__asm
	{
		mov eax,edi
		ret
	}
}

_declspec( naked ) unsigned short GetTR(void)
{
	__asm{
		STR AX
		ret
	}
}

void GetGDT(PGDT pGdt)
{
	__asm
    {
		MOV EAX, [pGdt]
	    SGDT [EAX]
    }
}

_declspec( naked )WORD GetLDT()
{
	__asm
	{
		SLDT ax
		ret
	}
}

#endif

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Undefined5;
	PVOID SectionPointer;
	ULONG CheckSum;
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

VOID HideDriverFromLoadedModuleList(PDRIVER_OBJECT DriverObject)
{
	if (DriverObject && DriverObject->DriverSection)
	{
		PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
		if (entry->InLoadOrderLinks.Flink && entry->InLoadOrderLinks.Blink)
		{
			entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;
			entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;
			entry->InLoadOrderLinks.Flink = (PLIST_ENTRY)&entry->InLoadOrderLinks;
			entry->InLoadOrderLinks.Blink = (PLIST_ENTRY)&entry->InLoadOrderLinks;
		}
	}
}

typedef struct _SAFE_PHYSICAL_MEMORY_RANGE {
	ULONG64 BaseAddress;
	ULONG64 EndAddress;
} SAFE_PHYSICAL_MEMORY_RANGE;

static SAFE_PHYSICAL_MEMORY_RANGE g_SafePhysicalRanges[128];
static ULONG g_SafePhysicalRangeCount = 0;

VOID InitializeSafePhysicalRanges(VOID)
{
	PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
	if (!ranges)
		return;

	ULONG count = 0;
	for (ULONG i = 0; count < 128; i++)
	{
		if (ranges[i].BaseAddress.QuadPart == 0 && ranges[i].NumberOfBytes.QuadPart == 0)
			break;

		ULONG64 base = (ULONG64)ranges[i].BaseAddress.QuadPart;
		ULONG64 size = (ULONG64)ranges[i].NumberOfBytes.QuadPart;

		if (size > 0)
		{
			g_SafePhysicalRanges[count].BaseAddress = base;
			g_SafePhysicalRanges[count].EndAddress = base + size;
			count++;
		}
	}

	ExFreePool(ranges);
	g_SafePhysicalRangeCount = count;
}

BOOLEAN IsPhysicalAddressSafe(ULONG64 PhysAddr, SIZE_T Size)
{
	if (Size == 0)
		return FALSE;

	ULONG64 endAddr = PhysAddr + Size;
	if (endAddr < PhysAddr)
		return FALSE;

	if (g_SafePhysicalRangeCount == 0)
	{
		InitializeSafePhysicalRanges();
		if (g_SafePhysicalRangeCount == 0)
			return FALSE;
	}

	for (ULONG i = 0; i < g_SafePhysicalRangeCount; i++)
	{
		if (PhysAddr >= g_SafePhysicalRanges[i].BaseAddress && endAddr <= g_SafePhysicalRanges[i].EndAddress)
		{
			return TRUE;
		}
	}

	return FALSE;
}

static __inline BOOLEAN IsCanonicalVirtualAddress(ULONG64 va)
{
	ULONG64 highBits = va >> 47;
	return (highBits == 0 || highBits == 0x1FFFF);
}

typedef PVOID (*PFN_MmMapIoSpaceEx)(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, ULONG Protect);

static PVOID SafeMapPhysicalMemory(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T Size, ULONG Protect)
{
	static PFN_MmMapIoSpaceEx pfnMmMapIoSpaceEx = NULL;
	static BOOLEAN resolved = FALSE;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return NULL;

	if (!resolved)
	{
		UNICODE_STRING uRoutine;
		RtlInitUnicodeString(&uRoutine, L"MmMapIoSpaceEx");
		pfnMmMapIoSpaceEx = (PFN_MmMapIoSpaceEx)MmGetSystemRoutineAddress(&uRoutine);
		resolved = TRUE;
	}

	if (pfnMmMapIoSpaceEx != NULL)
	{
		return pfnMmMapIoSpaceEx(PhysicalAddress, Size, Protect);
	}
	else
	{
		MEMORY_CACHING_TYPE cacheType = (Protect == PAGE_READWRITE) ? MmCached : MmNonCached;
		PVOID mapped = MmMapIoSpace(PhysicalAddress, Size, cacheType);
		if (!mapped && cacheType == MmCached)
			mapped = MmMapIoSpace(PhysicalAddress, Size, MmNonCached);
		return mapped;
	}
}

static BOOLEAN WritePhysicalChunk(ULONG64 PhysAddr, PVOID Buffer, SIZE_T Size);
static BOOLEAN ReadPhysicalChunk(ULONG64 PhysAddr, PVOID Buffer, SIZE_T Size)
{
	if (!Buffer || Size == 0)
		return FALSE;

	if (!IsPhysicalAddressSafe(PhysAddr, Size))
		return FALSE;

	__try
	{
		MM_COPY_ADDRESS copyAddr;
		copyAddr.PhysicalAddress.QuadPart = (LONGLONG)PhysAddr;
		SIZE_T transferred = 0;
		NTSTATUS status = MmCopyMemory(Buffer, copyAddr, Size, MM_COPY_MEMORY_PHYSICAL, &transferred);
		if (NT_SUCCESS(status) && (transferred == Size))
			return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	if (KeGetCurrentIrql() <= APC_LEVEL)
	{
		PVOID mapped = NULL;
		BOOLEAN success = FALSE;
		__try
		{
			PHYSICAL_ADDRESS pa;
			pa.QuadPart = (LONGLONG)PhysAddr;

			mapped = SafeMapPhysicalMemory(pa, Size, PAGE_READONLY);
			if (mapped != NULL)
			{
				__try
				{
					RtlCopyMemory(Buffer, mapped, Size);
					success = TRUE;
				}
				__finally
				{
					MmUnmapIoSpace(mapped, Size);
					mapped = NULL;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (mapped != NULL)
			{
				MmUnmapIoSpace(mapped, Size);
				mapped = NULL;
			}
			success = FALSE;
		}
		return success;
	}

	return FALSE;
}

ULONG64 TranslateVirtualToPhysicalWithCr3(ULONG64 cr3, ULONG64 VirtualAddress)
{
	if (!cr3 || !IsCanonicalVirtualAddress(VirtualAddress))
		return 0;

	ULONG64 pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;
	if (!pml4_base || !IsPhysicalAddressSafe(pml4_base, sizeof(ULONG64)))
		return 0;

	ULONG64 pml4_idx  = (VirtualAddress >> 39) & 0x1FF;
	ULONG64 pdpt_idx  = (VirtualAddress >> 30) & 0x1FF;
	ULONG64 pd_idx    = (VirtualAddress >> 21) & 0x1FF;
	ULONG64 pt_idx    = (VirtualAddress >> 12) & 0x1FF;
	ULONG64 offset    = VirtualAddress & 0xFFF;

	__try
	{
		// 1. PML4 Level Validation
		ULONG64 pml4e = 0;
		if (!ReadPhysicalChunk(pml4_base + (pml4_idx * 8), &pml4e, sizeof(pml4e)) || !(pml4e & 1))
			return 0;

		// 2. PDPT Level Validation
		ULONG64 pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
		if (!pdpt_base || !IsPhysicalAddressSafe(pdpt_base, sizeof(ULONG64)))
			return 0;

		ULONG64 pdpte = 0;
		if (!ReadPhysicalChunk(pdpt_base + (pdpt_idx * 8), &pdpte, sizeof(pdpte)) || !(pdpte & 1))
			return 0;

		// 1GB Large Page (PS bit 7)
		if (pdpte & 0x80)
		{
			ULONG64 phys1gb = (pdpte & 0x000FFFFFC0000000ULL) | (VirtualAddress & 0x3FFFFFFFULL);
			return IsPhysicalAddressSafe(phys1gb, 1) ? phys1gb : 0;
		}

		// 3. PD Level Validation
		ULONG64 pd_base = pdpte & 0x000FFFFFFFFFF000ULL;
		if (!pd_base || !IsPhysicalAddressSafe(pd_base, sizeof(ULONG64)))
			return 0;

		ULONG64 pde = 0;
		if (!ReadPhysicalChunk(pd_base + (pd_idx * 8), &pde, sizeof(pde)) || !(pde & 1))
			return 0;

		// 2MB Large Page (PS bit 7)
		if (pde & 0x80)
		{
			ULONG64 phys2mb = (pde & 0x000FFFFFFFE00000ULL) | (VirtualAddress & 0x1FFFFFULL);
			return IsPhysicalAddressSafe(phys2mb, 1) ? phys2mb : 0;
		}

		// 4. PT Level Validation
		ULONG64 pt_base = pde & 0x000FFFFFFFFFF000ULL;
		if (!pt_base || !IsPhysicalAddressSafe(pt_base, sizeof(ULONG64)))
			return 0;

		ULONG64 pte = 0;
		if (!ReadPhysicalChunk(pt_base + (pt_idx * 8), &pte, sizeof(pte)) || !(pte & 1))
			return 0;

		ULONG64 phys4kb = (pte & 0x000FFFFFFFFFF000ULL) | offset;
		return IsPhysicalAddressSafe(phys4kb, 1) ? phys4kb : 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}
}

static ULONG g_DirectoryTableBaseOffset = 0;
static ULONG g_UserDirectoryTableBaseOffset = 0;
static ULONG g_VadRootOffset = 0;

ULONG ResolveDirectoryTableBaseOffset(void)
{
	if (g_DirectoryTableBaseOffset != 0)
		return g_DirectoryTableBaseOffset;

	PEPROCESS currentProc = IoGetCurrentProcess();
	UINT64 currentCr3 = __readcr3() & 0x000FFFFFFFFFF000ULL;

	if (currentProc && currentCr3 != 0)
	{
		PUCHAR p = (PUCHAR)currentProc;
		for (ULONG off = 0x18; off <= 0x80; off += sizeof(ULONG_PTR))
		{
			UINT64 val = *(PUINT64)(p + off) & 0x000FFFFFFFFFF000ULL;
			if (val == currentCr3)
			{
				g_DirectoryTableBaseOffset = off;
				return off;
			}
		}
	}

	g_DirectoryTableBaseOffset = 0x28;
	return 0x28;
}

ULONG ResolveUserDirectoryTableBaseOffset(PEPROCESS Process)
{
	if (g_UserDirectoryTableBaseOffset != 0)
		return g_UserDirectoryTableBaseOffset;

	if (!Process)
		return 0x388;

	PVOID base = PsGetProcessSectionBaseAddress(Process);
	if (!base)
		return 0x388;

	PUCHAR p = (PUCHAR)Process;
	ULONG dtbOffset = ResolveDirectoryTableBaseOffset();
	UINT64 kernelCr3 = *(PUINT64)(p + dtbOffset) & 0x000FFFFFFFFFF000ULL;

	for (ULONG off = 0x270; off <= 0x450; off += sizeof(ULONG_PTR))
	{
		if (off == dtbOffset)
			continue;

		UINT64 candidate = *(PUINT64)(p + off);
		if ((candidate & 0xFFF) == 0 && candidate > 0x1000 && candidate < 0x000FFFFFFFFFF000ULL && candidate != kernelCr3)
		{
			if (TranslateVirtualToPhysicalWithCr3(candidate, (ULONG64)base) != 0)
			{
				g_UserDirectoryTableBaseOffset = off;
				return off;
			}
		}
	}

	g_UserDirectoryTableBaseOffset = 0x388;
	return 0x388;
}

void InitDynamicKernelOffsets(void)
{
	InitializeSafePhysicalRanges();
	ResolveDirectoryTableBaseOffset();
}

UINT64 GetProcessCR3(PEPROCESS Process)
{
	if (!Process)
		return 0;

	PUCHAR p = (PUCHAR)Process;
	ULONG dtbOffset = ResolveDirectoryTableBaseOffset();
	UINT64 cr3 = *(PUINT64)(p + dtbOffset);

	ULONG userDtbOffset = ResolveUserDirectoryTableBaseOffset(Process);
	UINT64 user_cr3 = userDtbOffset ? *(PUINT64)(p + userDtbOffset) : 0;

	if (user_cr3 != 0)
		return user_cr3;

	return cr3;
}

typedef struct _RTL_BALANCED_NODE_INTERNAL {
	struct _RTL_BALANCED_NODE_INTERNAL* Left;
	struct _RTL_BALANCED_NODE_INTERNAL* Right;
	ULONG_PTR ParentValue;
} RTL_BALANCED_NODE_INTERNAL, *PRTL_BALANCED_NODE_INTERNAL;

static BOOLEAN CheckVadNodeMatchesBase(PRTL_BALANCED_NODE_INTERNAL Node, ULONG64 TargetVpn, int Depth)
{
	if (!Node || Depth > 32)
		return FALSE;

	if (!MmIsAddressValid(Node))
		return FALSE;

	__try
	{
		ULONG startingVpn = *(PULONG)((PUCHAR)Node + 0x18);
		UCHAR startingVpnHigh = *(PUCHAR)((PUCHAR)Node + 0x20);
		ULONG64 vpn = (ULONG64)startingVpn | ((ULONG64)startingVpnHigh << 32);

		if (vpn == TargetVpn)
			return TRUE;

		if (TargetVpn < vpn)
		{
			PRTL_BALANCED_NODE_INTERNAL left = Node->Left;
			if (left && (ULONG_PTR)left > 0xFFFF800000000000ULL)
				return CheckVadNodeMatchesBase(left, TargetVpn, Depth + 1);
		}
		else
		{
			PRTL_BALANCED_NODE_INTERNAL right = Node->Right;
			if (right && (ULONG_PTR)right > 0xFFFF800000000000ULL)
				return CheckVadNodeMatchesBase(right, TargetVpn, Depth + 1);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}

	return FALSE;
}

static ULONG ResolveVadRootOffset(PEPROCESS Process)
{
	if (g_VadRootOffset != 0)
		return g_VadRootOffset;

	ULONG defaultOffset = 0x7d8;
	PVOID base = PsGetProcessSectionBaseAddress(Process);
	if (!base)
	{
		g_VadRootOffset = defaultOffset;
		return defaultOffset;
	}

	ULONG64 targetVpn = (ULONG64)base >> 12;

	for (ULONG off = 0x440; off <= 0x9c0; off += sizeof(ULONG_PTR))
	{
		PVOID rootCandidate = *(PVOID*)((PUCHAR)Process + off);
		if (rootCandidate && (ULONG_PTR)rootCandidate > 0xFFFF800000000000ULL)
		{
			if (CheckVadNodeMatchesBase((PRTL_BALANCED_NODE_INTERNAL)rootCandidate, targetVpn, 0))
			{
				g_VadRootOffset = off;
				return off;
			}
		}
	}

	g_VadRootOffset = defaultOffset;
	return defaultOffset;
}

NTSTATUS EnumerateProcessVadModules(PEPROCESS Process, PVAD_MODULE_ENTRY ModuleBuffer, ULONG MaxModules, PULONG OutCount)
{
	if (!Process || !ModuleBuffer || MaxModules == 0 || !OutCount)
		return STATUS_INVALID_PARAMETER;

	*OutCount = 0;
	ULONG vadOffset = ResolveVadRootOffset(Process);
	PRTL_BALANCED_NODE_INTERNAL root = *(PRTL_BALANCED_NODE_INTERNAL*)((PUCHAR)Process + vadOffset);

	if (!root || (ULONG_PTR)root <= 0xFFFF800000000000ULL || !MmIsAddressValid(root))
		return STATUS_NOT_FOUND;

	PRTL_BALANCED_NODE_INTERNAL stack[256];
	int top = 0;
	PRTL_BALANCED_NODE_INTERNAL curr = root;
	ULONG count = 0;

	__try
	{
		while ((curr != NULL || top > 0) && count < MaxModules)
		{
			while (curr != NULL)
			{
				if (!MmIsAddressValid(curr) || (ULONG_PTR)curr <= 0xFFFF800000000000ULL)
					break;

				if (top < 255)
					stack[top++] = curr;
				else
					break;

				curr = curr->Left;
			}

			if (top == 0)
				break;

			curr = stack[--top];

			if (!MmIsAddressValid(curr))
			{
				curr = NULL;
				continue;
			}

			ULONG startingVpn = *(PULONG)((PUCHAR)curr + 0x18);
			ULONG endingVpn = *(PULONG)((PUCHAR)curr + 0x1C);
			UCHAR startingVpnHigh = *(PUCHAR)((PUCHAR)curr + 0x20);
			UCHAR endingVpnHigh = *(PUCHAR)((PUCHAR)curr + 0x21);

			ULONG64 baseAddr = ((ULONG64)startingVpn | ((ULONG64)startingVpnHigh << 32)) << 12;
			ULONG64 endAddr = (((ULONG64)endingVpn | ((ULONG64)endingVpnHigh << 32)) << 12) | 0xFFF;
			ULONG64 modSize = (endAddr - baseAddr) + 1;

			PVOID subsection = *(PVOID*)((PUCHAR)curr + 0x48);
			if (subsection && (ULONG_PTR)subsection > 0xFFFF800000000000ULL && MmIsAddressValid(subsection))
			{
				PVOID controlArea = *(PVOID*)((PUCHAR)subsection + 0x00);
				if (controlArea && (ULONG_PTR)controlArea > 0xFFFF800000000000ULL && MmIsAddressValid(controlArea))
				{
					PFILE_OBJECT fobj = (PFILE_OBJECT)(*(ULONG_PTR*)((PUCHAR)controlArea + 0x40) & ~0xFULL);
					if (!fobj || (ULONG_PTR)fobj <= 0xFFFF800000000000ULL || !MmIsAddressValid(fobj) || *(CSHORT*)fobj != 5)
					{
						fobj = (PFILE_OBJECT)(*(ULONG_PTR*)((PUCHAR)controlArea + 0x48) & ~0xFULL);
					}

					if (fobj && (ULONG_PTR)fobj > 0xFFFF800000000000ULL && MmIsAddressValid(fobj) && *(CSHORT*)fobj == 5)
					{
						PUNICODE_STRING pFileName = (PUNICODE_STRING)((PUCHAR)fobj + 0x58);
						if (pFileName && pFileName->Length > 0 && pFileName->Buffer && MmIsAddressValid(pFileName->Buffer))
						{
							PVAD_MODULE_ENTRY entry = &ModuleBuffer[count];
							RtlZeroMemory(entry, sizeof(VAD_MODULE_ENTRY));
							entry->BaseAddress = baseAddr;
							entry->ModuleSize = modSize;

							USHORT copyLen = pFileName->Length / sizeof(WCHAR);
							if (copyLen > 259)
								copyLen = 259;

							RtlCopyMemory(entry->FullPath, pFileName->Buffer, copyLen * sizeof(WCHAR));
							entry->FullPath[copyLen] = 0;

							LONG lastSlash = -1;
							for (LONG i = 0; i < copyLen; i++)
							{
								if (entry->FullPath[i] == L'\\' || entry->FullPath[i] == L'/')
									lastSlash = i;
							}

							PWCHAR nameSrc = (lastSlash >= 0) ? &entry->FullPath[lastSlash + 1] : entry->FullPath;
							USHORT nameLen = 0;
							while (nameSrc[nameLen] != 0 && nameLen < 63)
							{
								entry->ModuleName[nameLen] = nameSrc[nameLen];
								nameLen++;
							}
							entry->ModuleName[nameLen] = 0;

							if (entry->ModuleName[0] != 0)
							{
								count++;
							}
						}
					}
				}
			}

			curr = curr->Right;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	*OutCount = count;
	return STATUS_SUCCESS;
}

ULONG64 TranslateVirtualToPhysicalCR3(PEPROCESS Process, ULONG64 VirtualAddress)
{
	if (!Process)
		return 0;

	UINT64 cr3 = GetProcessCR3(Process);
	ULONG64 phys = 0;
	if (cr3)
		phys = TranslateVirtualToPhysicalWithCr3(cr3, VirtualAddress);

	if (!phys)
	{
		ULONG dtbOffset = ResolveDirectoryTableBaseOffset();
		UINT64 kcr3 = *(PUINT64)((PUCHAR)Process + dtbOffset);
		if (kcr3 && kcr3 != cr3)
			phys = TranslateVirtualToPhysicalWithCr3(kcr3, VirtualAddress);
	}

	return phys;
}

BOOLEAN ReadProcessMemoryPhysicalCR3(PEPROCESS Process, ULONG64 VirtualAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead)
{
	if (!Process || !Buffer || Size == 0)
		return FALSE;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return FALSE;

	if (!IsCanonicalVirtualAddress(VirtualAddress))
		return FALSE;

	SIZE_T totalRead = 0;
	PUCHAR dest = (PUCHAR)Buffer;

	__try
	{
		while (totalRead < Size)
		{
			ULONG64 currentVa = VirtualAddress + totalRead;
			ULONG64 physAddr = TranslateVirtualToPhysicalCR3(Process, currentVa);
			if (!physAddr)
				break;

			SIZE_T bytesRemaining = Size - totalRead;
			SIZE_T bytesInPage = 0x1000 - (physAddr & 0xFFF);
			SIZE_T chunkSize = (bytesRemaining < bytesInPage) ? bytesRemaining : bytesInPage;

			if (!ReadPhysicalChunk(physAddr, dest + totalRead, chunkSize))
				break;

			totalRead += chunkSize;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	if (BytesRead)
		*BytesRead = totalRead;

	return (totalRead == Size);
}

BOOLEAN BulkDumpProcessMemoryPhysicalCR3(PEPROCESS Process, ULONG64 VirtualAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesDumped)
{
	if (!Process || !Buffer || Size == 0)
		return FALSE;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return FALSE;

	if (!IsCanonicalVirtualAddress(VirtualAddress))
		return FALSE;

	SIZE_T totalProcessed = 0;
	PUCHAR dest = (PUCHAR)Buffer;

	__try
	{
		while (totalProcessed < Size)
		{
			ULONG64 currentVa = VirtualAddress + totalProcessed;
			SIZE_T bytesRemaining = Size - totalProcessed;
			SIZE_T bytesInPage = 0x1000 - (currentVa & 0xFFF);
			SIZE_T chunkSize = (bytesRemaining < bytesInPage) ? bytesRemaining : bytesInPage;

			ULONG64 physAddr = TranslateVirtualToPhysicalCR3(Process, currentVa);
			if (physAddr && IsPhysicalAddressSafe(physAddr, chunkSize))
			{
				if (!ReadPhysicalChunk(physAddr, dest + totalProcessed, chunkSize))
				{
					RtlZeroMemory(dest + totalProcessed, chunkSize);
				}
			}
			else
			{
				RtlZeroMemory(dest + totalProcessed, chunkSize);
			}

			totalProcessed += chunkSize;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	if (BytesDumped)
		*BytesDumped = totalProcessed;

	return (totalProcessed > 0);
}

BOOLEAN StealthReadProcessMemoryPTE(PEPROCESS Process, ULONG64 VirtualAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead)
{
	if (!Process || !Buffer || Size == 0)
		return FALSE;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return FALSE;

	if (!IsCanonicalVirtualAddress(VirtualAddress))
		return FALSE;

	UINT64 cr3 = GetProcessCR3(Process);
	if (!cr3)
		return FALSE;

	SIZE_T totalRead = 0;
	PUCHAR dest = (PUCHAR)Buffer;

	__try
	{
		while (totalRead < Size)
		{
			ULONG64 currentVa = VirtualAddress + totalRead;
			SIZE_T bytesRemaining = Size - totalRead;
			SIZE_T bytesInPage = 0x1000 - (currentVa & 0xFFF);
			SIZE_T chunkSize = (bytesRemaining < bytesInPage) ? bytesRemaining : bytesInPage;
			ULONG64 offset = currentVa & 0xFFF;

			ULONG64 phys = TranslateVirtualToPhysicalCR3(Process, currentVa);
			if (phys && IsPhysicalAddressSafe(phys, chunkSize))
			{
				if (ReadPhysicalChunk(phys, dest + totalRead, chunkSize))
				{
					totalRead += chunkSize;
					continue;
				}
			}

			ULONG64 pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;
			ULONG64 pml4_idx  = (currentVa >> 39) & 0x1FF;
			ULONG64 pdpt_idx  = (currentVa >> 30) & 0x1FF;
			ULONG64 pd_idx    = (currentVa >> 21) & 0x1FF;
			ULONG64 pt_idx    = (currentVa >> 12) & 0x1FF;

			ULONG64 pml4e = 0;
			if (!ReadPhysicalChunk(pml4_base + (pml4_idx * 8), &pml4e, sizeof(pml4e)) || !(pml4e & 1))
			{
				RtlZeroMemory(dest + totalRead, chunkSize);
				totalRead += chunkSize;
				continue;
			}

			ULONG64 pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
			ULONG64 pdpte = 0;
			if (!ReadPhysicalChunk(pdpt_base + (pdpt_idx * 8), &pdpte, sizeof(pdpte)) || !(pdpte & 1))
			{
				RtlZeroMemory(dest + totalRead, chunkSize);
				totalRead += chunkSize;
				continue;
			}

			if (pdpte & 0x80)
			{
				ULONG64 p1gb = (pdpte & 0x000FFFFFC0000000ULL) | (currentVa & 0x3FFFFFFFULL);
				if (IsPhysicalAddressSafe(p1gb, chunkSize) && ReadPhysicalChunk(p1gb, dest + totalRead, chunkSize))
				{
					totalRead += chunkSize;
					continue;
				}
				RtlZeroMemory(dest + totalRead, chunkSize);
				totalRead += chunkSize;
				continue;
			}

			ULONG64 pd_base = pdpte & 0x000FFFFFFFFFF000ULL;
			ULONG64 pde = 0;
			if (!ReadPhysicalChunk(pd_base + (pd_idx * 8), &pde, sizeof(pde)) || !(pde & 1))
			{
				RtlZeroMemory(dest + totalRead, chunkSize);
				totalRead += chunkSize;
				continue;
			}

			if (pde & 0x80)
			{
				ULONG64 p2mb = (pde & 0x000FFFFFFFE00000ULL) | (currentVa & 0x1FFFFFULL);
				if (IsPhysicalAddressSafe(p2mb, chunkSize) && ReadPhysicalChunk(p2mb, dest + totalRead, chunkSize))
				{
					totalRead += chunkSize;
					continue;
				}
				RtlZeroMemory(dest + totalRead, chunkSize);
				totalRead += chunkSize;
				continue;
			}

			ULONG64 pt_base = pde & 0x000FFFFFFFFFF000ULL;
			ULONG64 pte_entry_phys = pt_base + (pt_idx * 8);
			ULONG64 original_pte = 0;

			if (ReadPhysicalChunk(pte_entry_phys, &original_pte, sizeof(original_pte)))
			{
				ULONG64 pfn = (original_pte >> 12) & 0x000000FFFFFFFFFFULL;
				ULONG64 candidatePhys = (pfn << 12) | offset;

				if (pfn != 0 && IsPhysicalAddressSafe(candidatePhys, chunkSize))
				{
					if (!(original_pte & 1))
					{

						ULONG64 patched_pte = original_pte | 1ULL;
						WritePhysicalChunk(pte_entry_phys, &patched_pte, sizeof(patched_pte));

						BOOLEAN readOk = ReadPhysicalChunk(candidatePhys, dest + totalRead, chunkSize);

						WritePhysicalChunk(pte_entry_phys, &original_pte, sizeof(original_pte));

						if (readOk)
						{
							totalRead += chunkSize;
							continue;
						}
					}
					else
					{
						if (ReadPhysicalChunk(candidatePhys, dest + totalRead, chunkSize))
						{
							totalRead += chunkSize;
							continue;
						}
					}
				}
			}

			RtlZeroMemory(dest + totalRead, chunkSize);
			totalRead += chunkSize;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	if (BytesRead)
		*BytesRead = totalRead;

	return (totalRead > 0);
}

#pragma pack(push, 1)
typedef struct _OB_CALLBACK_ENTRY {
	LIST_ENTRY CallbackList;
	ULONG Operations;
	ULONG Enabled;
	PVOID Entry;
	POBJECT_TYPE ObjectType;
	PVOID PreOperation;
	PVOID PostOperation;
	KSPIN_LOCK Lock;
} OB_CALLBACK_ENTRY, *POB_CALLBACK_ENTRY;
#pragma pack(pop)

typedef struct _STRIPPED_CALLBACK_BACKUP {
	POB_CALLBACK_ENTRY EntryAddress;
	ULONG OriginalOperations;
	ULONG OriginalEnabled;
	PVOID OriginalPreOperation;
	PVOID OriginalPostOperation;
} STRIPPED_CALLBACK_BACKUP;

static STRIPPED_CALLBACK_BACKUP g_CallbackBackups[64];
static ULONG g_CallbackBackupCount = 0;

ULONG StripProcessCallbacks(BOOLEAN Restore)
{
	if (KeGetCurrentIrql() > APC_LEVEL)
		return 0;

	if (!PsProcessType || !*PsProcessType)
		return 0;

	POBJECT_TYPE pProcessType = *PsProcessType;
	ULONG affected = 0;

	__try
	{
		if (Restore)
		{
			for (ULONG i = 0; i < g_CallbackBackupCount; i++)
			{
				POB_CALLBACK_ENTRY entry = g_CallbackBackups[i].EntryAddress;
				if (entry && MmIsAddressValid(entry))
				{
					entry->Operations = g_CallbackBackups[i].OriginalOperations;
					entry->Enabled = g_CallbackBackups[i].OriginalEnabled;
					entry->PreOperation = g_CallbackBackups[i].OriginalPreOperation;
					entry->PostOperation = g_CallbackBackups[i].OriginalPostOperation;
					affected++;
				}
			}
			g_CallbackBackupCount = 0;
			return affected;
		}

		PUCHAR p = (PUCHAR)pProcessType;
		PLIST_ENTRY pCallbackList = NULL;

		for (ULONG off = 0x80; off <= 0x140; off += sizeof(ULONG_PTR))
		{
			PLIST_ENTRY candidate = (PLIST_ENTRY)(p + off);
			if (candidate->Flink != candidate && MmIsAddressValid(candidate->Flink))
			{
				POB_CALLBACK_ENTRY testEntry = (POB_CALLBACK_ENTRY)candidate->Flink;
				if (MmIsAddressValid(&testEntry->ObjectType) && testEntry->ObjectType == pProcessType)
				{
					pCallbackList = candidate;
					break;
				}
			}
		}

		if (!pCallbackList)
		{
			pCallbackList = (PLIST_ENTRY)(p + 0xC8);
		}

		if (!MmIsAddressValid(pCallbackList))
			return 0;

		PLIST_ENTRY curr = pCallbackList->Flink;
		while (curr != pCallbackList && curr != NULL)
		{
			if (!MmIsAddressValid(curr))
				break;

			POB_CALLBACK_ENTRY entry = (POB_CALLBACK_ENTRY)curr;
			if (MmIsAddressValid(&entry->ObjectType) && entry->ObjectType == pProcessType)
			{
				if (g_CallbackBackupCount < 64)
				{
					g_CallbackBackups[g_CallbackBackupCount].EntryAddress = entry;
					g_CallbackBackups[g_CallbackBackupCount].OriginalOperations = entry->Operations;
					g_CallbackBackups[g_CallbackBackupCount].OriginalEnabled = entry->Enabled;
					g_CallbackBackups[g_CallbackBackupCount].OriginalPreOperation = entry->PreOperation;
					g_CallbackBackups[g_CallbackBackupCount].OriginalPostOperation = entry->PostOperation;
					g_CallbackBackupCount++;
				}

				entry->PreOperation = NULL;
				entry->Operations = 0;
				entry->Enabled = 0;
				affected++;
			}

			curr = curr->Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	return affected;
}

ULONG PatternScanProcessCR3(
	PEPROCESS Process,
	ULONG64 StartAddress,
	ULONG64 ScanSize,
	const UCHAR* Pattern,
	const UCHAR* Mask,
	ULONG PatternLength,
	PULONG64 Matches,
	ULONG MaxMatches
)
{
	if (!Process || !Pattern || !Mask || PatternLength == 0 || PatternLength > 64 || ScanSize == 0 || !Matches || MaxMatches == 0)
		return 0;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return 0;

	if (!IsCanonicalVirtualAddress(StartAddress))
		return 0;

	const SIZE_T CHUNK_SIZE = 64 * 1024;
	PUCHAR chunk = (PUCHAR)ExAllocatePoolWithTag(DBK_POOL_NX, CHUNK_SIZE, 'kbaS');
	if (!chunk)
		return 0;

	ULONG matchCount = 0;
	SIZE_T scanned = 0;

	ULONG firstFixedIdx = 0;
	while (firstFixedIdx < PatternLength && Mask[firstFixedIdx] == 0)
	{
		firstFixedIdx++;
	}

	UCHAR firstByte = (firstFixedIdx < PatternLength) ? Pattern[firstFixedIdx] : 0;
	BOOLEAN hasFixedFirst = (firstFixedIdx < PatternLength && Mask[firstFixedIdx] == 0xFF);

	__try
	{
		while (scanned < ScanSize && matchCount < MaxMatches)
		{
			ULONG64 currentVa = StartAddress + scanned;
			SIZE_T remaining = ScanSize - scanned;
			SIZE_T toRead = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;

			SIZE_T bytesRead = 0;
			if (!BulkDumpProcessMemoryPhysicalCR3(Process, currentVa, chunk, toRead, &bytesRead) || bytesRead < PatternLength)
			{
				scanned += 0x1000;
				continue;
			}

			SIZE_T limit = bytesRead - PatternLength;
			for (SIZE_T i = 0; i <= limit; i++)
			{
				if (hasFixedFirst && chunk[i + firstFixedIdx] != firstByte)
				{
					continue;
				}

				BOOLEAN found = TRUE;
				for (ULONG p = 0; p < PatternLength; p++)
				{
					if ((chunk[i + p] & Mask[p]) != (Pattern[p] & Mask[p]))
					{
						found = FALSE;
						break;
					}
				}

				if (found)
				{
					Matches[matchCount++] = currentVa + i;
					if (matchCount >= MaxMatches)
						break;
				}
			}

			if (toRead > PatternLength)
			{
				scanned += (toRead - PatternLength + 1);
			}
			else
			{
				scanned += toRead;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	ExFreePoolWithTag(chunk, 'kbaS');
	return matchCount;
}

typedef NTSTATUS (NTAPI *PFN_PsSuspendProcess)(PEPROCESS Process);
typedef NTSTATUS (NTAPI *PFN_PsResumeProcess)(PEPROCESS Process);

static PFN_PsSuspendProcess g_PsSuspendProcess = NULL;
static PFN_PsResumeProcess g_PsResumeProcess = NULL;

NTSTATUS FreezeProcess(PEPROCESS Process, BOOLEAN Freeze)
{
	if (!Process)
		return STATUS_INVALID_PARAMETER;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return STATUS_UNSUCCESSFUL;

	if (!g_PsSuspendProcess || !g_PsResumeProcess)
		{
		UNICODE_STRING uSuspend, uResume;
		RtlInitUnicodeString(&uSuspend, L"PsSuspendProcess");
		RtlInitUnicodeString(&uResume, L"PsResumeProcess");
		g_PsSuspendProcess = (PFN_PsSuspendProcess)MmGetSystemRoutineAddress(&uSuspend);
		g_PsResumeProcess = (PFN_PsResumeProcess)MmGetSystemRoutineAddress(&uResume);
	}

	if (!g_PsSuspendProcess || !g_PsResumeProcess)
		return STATUS_NOT_SUPPORTED;

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	__try
	{
		if (Freeze)
		{
			status = g_PsSuspendProcess(Process);
		}
		else
		{
			status = g_PsResumeProcess(Process);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = STATUS_UNSUCCESSFUL;
	}

	return status;
}

static BOOLEAN WritePhysicalChunk(ULONG64 PhysAddr, PVOID Buffer, SIZE_T Size)
{
	if (!Buffer || Size == 0)
		return FALSE;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return FALSE;

	if (!IsPhysicalAddressSafe(PhysAddr, Size))
		return FALSE;

	BOOLEAN success = FALSE;
	PVOID mapped = NULL;

	__try
	{
		PHYSICAL_ADDRESS pa;
		pa.QuadPart = (LONGLONG)PhysAddr;

		mapped = SafeMapPhysicalMemory(pa, Size, PAGE_READWRITE);
		if (mapped != NULL)
		{
			__try
			{
				RtlCopyMemory(mapped, Buffer, Size);
				success = TRUE;
			}
			__finally
			{
				MmUnmapIoSpace(mapped, Size);
				mapped = NULL;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		if (mapped != NULL)
		{
			MmUnmapIoSpace(mapped, Size);
			mapped = NULL;
		}
		success = FALSE;
	}

	return success;
}

BOOLEAN WriteProcessMemoryPhysicalCR3(PEPROCESS Process, ULONG64 VirtualAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesWritten)
{
	if (!Process || !Buffer || Size == 0)
		return FALSE;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return FALSE;

	if (!IsCanonicalVirtualAddress(VirtualAddress))
		return FALSE;

	SIZE_T totalWritten = 0;
	PUCHAR src = (PUCHAR)Buffer;

	__try
	{
		while (totalWritten < Size)
		{
			ULONG64 currentVa = VirtualAddress + totalWritten;
			ULONG64 physAddr = TranslateVirtualToPhysicalCR3(Process, currentVa);
			if (!physAddr)
				break;

			SIZE_T bytesRemaining = Size - totalWritten;
			SIZE_T bytesInPage = 0x1000 - (physAddr & 0xFFF);
			SIZE_T chunkSize = (bytesRemaining < bytesInPage) ? bytesRemaining : bytesInPage;

			if (!WritePhysicalChunk(physAddr, src + totalWritten, chunkSize))
				break;

			totalWritten += chunkSize;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	if (BytesWritten)
		*BytesWritten = totalWritten;

	return (totalWritten == Size);
}

static DWORD ConvertVadProtection(ULONG VadProtection)
{
	static const DWORD ProtectionMap[32] = {
		PAGE_NOACCESS,
		PAGE_READONLY,
		PAGE_EXECUTE,
		PAGE_EXECUTE_READ,
		PAGE_READWRITE,
		PAGE_WRITECOPY,
		PAGE_EXECUTE_READWRITE,
		PAGE_EXECUTE_WRITECOPY,
		PAGE_NOACCESS,
		PAGE_NOCACHE | PAGE_READONLY,
		PAGE_NOCACHE | PAGE_EXECUTE,
		PAGE_NOCACHE | PAGE_EXECUTE_READ,
		PAGE_NOCACHE | PAGE_READWRITE,
		PAGE_NOCACHE | PAGE_WRITECOPY,
		PAGE_NOCACHE | PAGE_EXECUTE_READWRITE,
		PAGE_NOCACHE | PAGE_EXECUTE_WRITECOPY,
		PAGE_NOACCESS,
		PAGE_GUARD | PAGE_READONLY,
		PAGE_GUARD | PAGE_EXECUTE,
		PAGE_GUARD | PAGE_EXECUTE_READ,
		PAGE_GUARD | PAGE_READWRITE,
		PAGE_GUARD | PAGE_WRITECOPY,
		PAGE_GUARD | PAGE_EXECUTE_READWRITE,
		PAGE_GUARD | PAGE_EXECUTE_WRITECOPY,
		PAGE_NOACCESS,
		PAGE_WRITECOMBINE | PAGE_READONLY,
		PAGE_WRITECOMBINE | PAGE_EXECUTE,
		PAGE_WRITECOMBINE | PAGE_EXECUTE_READ,
		PAGE_WRITECOMBINE | PAGE_READWRITE,
		PAGE_WRITECOMBINE | PAGE_WRITECOPY,
		PAGE_WRITECOMBINE | PAGE_EXECUTE_READWRITE,
		PAGE_WRITECOMBINE | PAGE_EXECUTE_WRITECOPY
	};

	ULONG index = VadProtection & 0x1F;
	return ProtectionMap[index];
}

NTSTATUS CloakProcessPage(PEPROCESS Process, ULONG64 VirtualAddress)
{
	if (!vmxusable)
		return STATUS_NOT_SUPPORTED;

	if (!Process)
		return STATUS_INVALID_PARAMETER;

	ULONG64 phys = TranslateVirtualToPhysicalCR3(Process, VirtualAddress);
	if (!phys)
		return STATUS_NOT_FOUND;

	ULONG64 pagePhys = phys & ~0xFFFULL;
	unsigned int r = vmx_cloak_activate(pagePhys);
	return (r == 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS UncloakProcessPage(PEPROCESS Process, ULONG64 VirtualAddress)
{
	if (!vmxusable)
		return STATUS_NOT_SUPPORTED;

	if (!Process)
		return STATUS_INVALID_PARAMETER;

	ULONG64 phys = TranslateVirtualToPhysicalCR3(Process, VirtualAddress);
	if (!phys)
		return STATUS_NOT_FOUND;

	ULONG64 pagePhys = phys & ~0xFFFULL;
	unsigned int r = vmx_cloak_deactivate(pagePhys);
	return (r == 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS WriteCloakedPageMemory(PEPROCESS Process, ULONG64 VirtualAddress, PVOID Buffer, ULONG Size)
{
	if (!vmxusable)
		return STATUS_NOT_SUPPORTED;

	if (!Process || !Buffer || Size == 0)
		return STATUS_INVALID_PARAMETER;

	ULONG64 phys = TranslateVirtualToPhysicalCR3(Process, VirtualAddress);
	if (!phys)
		return STATUS_NOT_FOUND;

	ULONG64 pagePhys = phys & ~0xFFFULL;
	ULONG pageOffset = VirtualAddress & 0xFFF;

	if ((pageOffset + Size) > 0x1000)
		return STATUS_BUFFER_TOO_SMALL;

	PUCHAR pageBuf = (PUCHAR)ExAllocatePoolWithTag(DBK_POOL_NX, 0x1000, 'KOLC');
	if (!pageBuf)
		return STATUS_INSUFFICIENT_RESOURCES;

	unsigned int r = vmx_cloak_readOriginal(pagePhys, pageBuf);
	if (r != 0)
	{
		ExFreePoolWithTag(pageBuf, 'KOLC');
		return STATUS_UNSUCCESSFUL;
	}

	RtlCopyMemory(pageBuf + pageOffset, Buffer, Size);

	r = vmx_cloak_writeOriginal(pagePhys, pageBuf);

	ExFreePoolWithTag(pageBuf, 'KOLC');
	return (r == 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS QueryProcessMemoryVad(PEPROCESS Process, ULONG64 VirtualAddress, PMEMORY_BASIC_INFORMATION64 MemoryInfo)
{
	if (!Process || !MemoryInfo)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(MemoryInfo, sizeof(MEMORY_BASIC_INFORMATION64));

	ULONG vadOffset = ResolveVadRootOffset(Process);
	PRTL_BALANCED_NODE_INTERNAL root = *(PRTL_BALANCED_NODE_INTERNAL*)((PUCHAR)Process + vadOffset);

	if (!root || (ULONG_PTR)root <= 0xFFFF800000000000ULL || !MmIsAddressValid(root))
		return STATUS_NOT_FOUND;

	ULONG64 targetVpn = VirtualAddress >> 12;
	PRTL_BALANCED_NODE_INTERNAL curr = root;
	PRTL_BALANCED_NODE_INTERNAL found = NULL;
	ULONG64 nextStartingVpn = (ULONG64)-1;

	__try
	{
		while (curr != NULL)
		{
			if (!MmIsAddressValid(curr) || (ULONG_PTR)curr <= 0xFFFF800000000000ULL)
				break;

			ULONG startingVpn = *(PULONG)((PUCHAR)curr + 0x18);
			ULONG endingVpn   = *(PULONG)((PUCHAR)curr + 0x1C);
			UCHAR startingVpnHigh = *(PUCHAR)((PUCHAR)curr + 0x20);
			UCHAR endingVpnHigh   = *(PUCHAR)((PUCHAR)curr + 0x21);

			ULONG64 startVpn = (ULONG64)startingVpn | ((ULONG64)startingVpnHigh << 32);
			ULONG64 endVpn   = (ULONG64)endingVpn   | ((ULONG64)endingVpnHigh << 32);

			if (targetVpn >= startVpn && targetVpn <= endVpn)
			{
				found = curr;
				break;
			}

			if (targetVpn < startVpn)
			{
				if (startVpn < nextStartingVpn)
					nextStartingVpn = startVpn;

				curr = curr->Left;
			}
			else
			{
				curr = curr->Right;
			}
		}

		if (found != NULL)
		{
			ULONG startingVpn = *(PULONG)((PUCHAR)found + 0x18);
			ULONG endingVpn   = *(PULONG)((PUCHAR)found + 0x1C);
			UCHAR startingVpnHigh = *(PUCHAR)((PUCHAR)found + 0x20);
			UCHAR endingVpnHigh   = *(PUCHAR)((PUCHAR)found + 0x21);

			ULONG64 startVpn = (ULONG64)startingVpn | ((ULONG64)startingVpnHigh << 32);
			ULONG64 endVpn   = (ULONG64)endingVpn   | ((ULONG64)endingVpnHigh << 32);

			MemoryInfo->BaseAddress = startVpn << 12;
			MemoryInfo->AllocationBase = MemoryInfo->BaseAddress;
			MemoryInfo->RegionSize = ((endVpn - startVpn) + 1) << 12;
			MemoryInfo->State = 0x1000;

			ULONG flags = *(PULONG)((PUCHAR)found + 0x30);
			ULONG vadProt = flags & 0x1F;
			MemoryInfo->Protect = ConvertVadProtection(vadProt);
			MemoryInfo->AllocationProtect = MemoryInfo->Protect;

			PVOID subsection = *(PVOID*)((PUCHAR)found + 0x48);
			if (subsection && (ULONG_PTR)subsection > 0xFFFF800000000000ULL && MmIsAddressValid(subsection))
			{
				MemoryInfo->Type = 0x1000000;
			}
			else if (flags & (1 << 7))
			{
				MemoryInfo->Type = 0x20000;
			}
			else
			{
				MemoryInfo->Type = 0x40000;
			}
		}
		else
		{
			MemoryInfo->BaseAddress = VirtualAddress & ~0xFFFULL;
			MemoryInfo->AllocationBase = 0;
			MemoryInfo->AllocationProtect = 0;
			MemoryInfo->State = 0x10000;
			MemoryInfo->Protect = PAGE_NOACCESS;
			MemoryInfo->Type = 0;

			if (nextStartingVpn != (ULONG64)-1 && (nextStartingVpn << 12) > MemoryInfo->BaseAddress)
			{
				MemoryInfo->RegionSize = (nextStartingVpn << 12) - MemoryInfo->BaseAddress;
			}
			else
			{
				MemoryInfo->RegionSize = 0x1000;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

static ULONG g_ProtectionOffset = 0;

ULONG ResolveProcessProtectionOffset(VOID)
{
	if (g_ProtectionOffset != 0)
		return g_ProtectionOffset;

	UNICODE_STRING uRoutine;
	RtlInitUnicodeString(&uRoutine, L"PsIsProtectedProcess");
	PUCHAR pfn = (PUCHAR)MmGetSystemRoutineAddress(&uRoutine);

	if (!pfn)
		return 0;

	__try
	{
		for (ULONG i = 0; i < 48; i++)
		{

			if (pfn[i] == 0xF6 && pfn[i + 1] == 0x81 && pfn[i + 6] == 0x07)
			{
				ULONG offset = *(PULONG)(pfn + i + 2);
				if (offset >= 0x400 && offset <= 0x1000)
				{
					g_ProtectionOffset = offset;
					return offset;
				}
			}

			else if (pfn[i] == 0x8A && pfn[i + 1] == 0x81)
			{
				ULONG offset = *(PULONG)(pfn + i + 2);
				if (offset >= 0x400 && offset <= 0x1000)
				{
					g_ProtectionOffset = offset;
					return offset;
				}
			}

			else if (pfn[i] == 0x0F && pfn[i + 1] == 0xB6 && pfn[i + 2] == 0x81)
			{
				ULONG offset = *(PULONG)(pfn + i + 3);
				if (offset >= 0x400 && offset <= 0x1000)
				{
					g_ProtectionOffset = offset;
					return offset;
				}
			}
			else if (pfn[i] == 0xC3 || pfn[i] == 0xCC)
			{
				break;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		g_ProtectionOffset = 0;
	}

	return g_ProtectionOffset;
}

NTSTATUS SetProcessProtection(PEPROCESS Process, BOOLEAN Enable)
{
	if (!Process)
		return STATUS_INVALID_PARAMETER;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return STATUS_UNSUCCESSFUL;

	ULONG offset = ResolveProcessProtectionOffset();
	if (offset == 0)
		return STATUS_NOT_SUPPORTED;

	__try
	{
		PUCHAR targetByte = (PUCHAR)Process + offset;
		if (Enable)
		{

			*targetByte = 0x72;
		}
		else
		{
			*targetByte = 0x00;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

typedef struct _PIDDB_CACHE_ENTRY
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	CHAR			_pad[16];
} PIDDB_CACHE_ENTRY, *PPIDDB_CACHE_ENTRY;

typedef struct _UNLOADED_DRIVER_ENTRY
{
	UNICODE_STRING	Name;
	PVOID			StartAddress;
	PVOID			EndAddress;
	LARGE_INTEGER	CurrentTime;
} UNLOADED_DRIVER_ENTRY, *PUNLOADED_DRIVER_ENTRY;

typedef BOOLEAN (NTAPI *PFN_RtlDeleteElementGenericTableAvl)(PVOID Table, PVOID Buffer);
typedef PVOID (NTAPI *PFN_RtlLookupElementGenericTableAvl)(PVOID Table, PVOID Buffer);

static PVOID GetNtoskrnlBase(VOID)
{
	typedef struct _SYSTEM_MODULE_ENTRY {
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

	typedef struct _SYSTEM_MODULE_INFORMATION {
		ULONG Count;
		SYSTEM_MODULE_ENTRY Modules[1];
	} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

	typedef NTSTATUS (NTAPI *PFN_ZwQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	UNICODE_STRING uRoutine;
	RtlInitUnicodeString(&uRoutine, L"ZwQuerySystemInformation");
	PFN_ZwQuerySystemInformation pfnZwQuery = (PFN_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&uRoutine);

	if (!pfnZwQuery)
		return NULL;

	ULONG size = 0;
	pfnZwQuery(11, NULL, 0, &size);
	if (size == 0)
		return NULL;

	PSYSTEM_MODULE_INFORMATION pMods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(DBK_POOL_NX, size, 'sDoM');
	if (!pMods)
		return NULL;

	PVOID ntoskrnlBase = NULL;
	if (NT_SUCCESS(pfnZwQuery(11, pMods, size, &size)) && pMods->Count > 0)
	{
		ntoskrnlBase = pMods->Modules[0].ImageBase;
	}

	ExFreePoolWithTag(pMods, 'sDoM');
	return ntoskrnlBase;
}

static NTSTATUS CleanPiDDBCache(PVOID NtosBase)
{
	if (!NtosBase)
		return STATUS_NOT_FOUND;

	PUCHAR base = (PUCHAR)NtosBase;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
	PUCHAR piddbSite = NULL;

	for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{

		if (RtlEqualMemory(sec[i].Name, "PAGE", 4))
		{
			PUCHAR start = base + sec[i].VirtualAddress;
			ULONG size = sec[i].Misc.VirtualSize;

			for (ULONG j = 0; j < size - 60; j++)
			{

				if (start[j] == 0xBA && start[j + 1] == 0x49 && start[j + 2] == 0x6F && start[j + 3] == 0x43 && start[j + 4] == 0x70)
				{

					if (start[j + 20] == 0x48 && start[j + 21] == 0x8D && start[j + 22] == 0x0D &&
					    start[j + 37] == 0x48 && start[j + 38] == 0x8D && start[j + 39] == 0x0D)
					{
						piddbSite = start + j;
						break;
					}
				}
			}
			break;
		}
	}

	if (!piddbSite)
		return STATUS_NOT_FOUND;

	LONG dispLock = *(PLONG)(piddbSite + 20 + 3);
	PERESOURCE pLock = (PERESOURCE)(piddbSite + 20 + 7 + dispLock);

	LONG dispTable = *(PLONG)(piddbSite + 37 + 3);
	PVOID pTable = (PVOID)(piddbSite + 37 + 7 + dispTable);

	if (!MmIsAddressValid(pLock) || !MmIsAddressValid(pTable))
		return STATUS_INVALID_ADDRESS;

	UNICODE_STRING uLookup, uDelete;
	RtlInitUnicodeString(&uLookup, L"RtlLookupElementGenericTableAvl");
	RtlInitUnicodeString(&uDelete, L"RtlDeleteElementGenericTableAvl");
	PFN_RtlLookupElementGenericTableAvl pfnLookup = (PFN_RtlLookupElementGenericTableAvl)MmGetSystemRoutineAddress(&uLookup);
	PFN_RtlDeleteElementGenericTableAvl pfnDelete = (PFN_RtlDeleteElementGenericTableAvl)MmGetSystemRoutineAddress(&uDelete);

	if (!pfnLookup || !pfnDelete)
		return STATUS_NOT_SUPPORTED;

	UNICODE_STRING targets[4];
	RtlInitUnicodeString(&targets[0], L"lydumen.sys");
	RtlInitUnicodeString(&targets[1], L"dbk64.sys");
	RtlInitUnicodeString(&targets[2], L"OwMemDriver.sys");
	RtlInitUnicodeString(&targets[3], L"owmemdriver.sys");

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(pLock, TRUE);

	__try
	{
		for (int t = 0; t < 4; t++)
		{
			PIDDB_CACHE_ENTRY lookupEntry;
			RtlZeroMemory(&lookupEntry, sizeof(PIDDB_CACHE_ENTRY));
			lookupEntry.DriverName = targets[t];
			lookupEntry.TimeDateStamp = 0;

			PPIDDB_CACHE_ENTRY found = (PPIDDB_CACHE_ENTRY)pfnLookup(pTable, &lookupEntry);
			if (found)
			{

				if (found->List.Flink && found->List.Blink)
				{
					RemoveEntryList(&found->List);
				}
				pfnDelete(pTable, found);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	ExReleaseResourceLite(pLock);
	KeLeaveCriticalRegion();

	return STATUS_SUCCESS;
}

static NTSTATUS CleanMmUnloadedDrivers(PVOID NtosBase)
{
	if (!NtosBase)
		return STATUS_NOT_FOUND;

	PUCHAR base = (PUCHAR)NtosBase;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
	PUCHAR unloadedSite = NULL;

	for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		if (RtlEqualMemory(sec[i].Name, "PAGE", 4))
		{
			PUCHAR start = base + sec[i].VirtualAddress;
			ULONG size = sec[i].Misc.VirtualSize;

			for (ULONG j = 0; j < size - 40; j++)
			{

				if (start[j] == 0x48 && start[j + 1] == 0x8B && start[j + 2] == 0x0D &&
				    start[j + 7] == 0x48 && start[j + 8] == 0x85 && start[j + 9] == 0xC9 &&
				    start[j + 10] == 0x0F && start[j + 11] == 0x84 &&
				    start[j + 16] == 0x8B && start[j + 17] == 0x05 &&
				    start[j + 22] == 0x83 && start[j + 23] == 0xF8 && start[j + 24] == 0x32)
				{
					unloadedSite = start + j;
					break;
				}
			}
			break;
		}
	}

	if (!unloadedSite)
		return STATUS_NOT_FOUND;

	LONG dispUnloaded = *(PLONG)(unloadedSite + 3);
	PUNLOADED_DRIVER_ENTRY* pMmUnloadedDrivers = (PUNLOADED_DRIVER_ENTRY*)(unloadedSite + 7 + dispUnloaded);

	if (!MmIsAddressValid(pMmUnloadedDrivers) || !*pMmUnloadedDrivers)
		return STATUS_SUCCESS;

	PUNLOADED_DRIVER_ENTRY driverArray = *pMmUnloadedDrivers;
	if (!MmIsAddressValid(driverArray))
		return STATUS_INVALID_ADDRESS;

	UNICODE_STRING targets[4];
	RtlInitUnicodeString(&targets[0], L"lydumen.sys");
	RtlInitUnicodeString(&targets[1], L"dbk64.sys");
	RtlInitUnicodeString(&targets[2], L"OwMemDriver.sys");
	RtlInitUnicodeString(&targets[3], L"owmemdriver.sys");

	__try
	{
		for (ULONG i = 0; i < 50; i++)
		{
			PUNLOADED_DRIVER_ENTRY entry = &driverArray[i];
			if (!MmIsAddressValid(entry) || !entry->Name.Buffer || entry->Name.Length == 0)
				continue;

			for (int t = 0; t < 4; t++)
			{
				if (RtlCompareUnicodeString(&entry->Name, &targets[t], TRUE) == 0)
				{

					RtlZeroMemory(entry->Name.Buffer, entry->Name.MaximumLength);
					RtlZeroMemory(entry, sizeof(UNLOADED_DRIVER_ENTRY));
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS CleanKernelTraces(VOID)
{
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
		return STATUS_UNSUCCESSFUL;

	PVOID ntosBase = GetNtoskrnlBase();
	if (!ntosBase)
		return STATUS_NOT_FOUND;

	NTSTATUS statusPiDDB = CleanPiDDBCache(ntosBase);
	NTSTATUS statusMmUnloaded = CleanMmUnloadedDrivers(ntosBase);

	if (NT_SUCCESS(statusPiDDB) || NT_SUCCESS(statusMmUnloaded))
		return STATUS_SUCCESS;

	return STATUS_UNSUCCESSFUL;
}

extern UNICODE_STRING uszDriverString;
extern UNICODE_STRING uszDeviceString;
static WCHAR g_CloakedSymlinkBuffer[128] = { 0 };

NTSTATUS CloakDeviceSymlink(PCWSTR NewSymlinkName)
{
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
		return STATUS_UNSUCCESSFUL;

	if (!NewSymlinkName)
		return STATUS_INVALID_PARAMETER;

	__try
	{

		UNICODE_STRING uNewLink;
		WCHAR fullDosDevicesPath[128];
		RtlZeroMemory(fullDosDevicesPath, sizeof(fullDosDevicesPath));

		if (wcsncmp(NewSymlinkName, L"\\DosDevices\\", 12) == 0 ||
		    wcsncmp(NewSymlinkName, L"\\??\\", 4) == 0)
		{
			RtlStringCchCopyW(fullDosDevicesPath, 128, NewSymlinkName);
		}
		else
		{
			RtlStringCchPrintfW(fullDosDevicesPath, 128, L"\\DosDevices\\%s", NewSymlinkName);
		}

		RtlInitUnicodeString(&uNewLink, fullDosDevicesPath);

		UNICODE_STRING uTargetDevice;
		if (uszDriverString.Buffer && uszDriverString.Length > 0)
		{
			uTargetDevice = uszDriverString;
		}
		else
		{
			RtlInitUnicodeString(&uTargetDevice, L"\\Device\\OwMemDriver");
		}

		NTSTATUS status = IoCreateSymbolicLink(&uNewLink, &uTargetDevice);
		if (!NT_SUCCESS(status))
		{
			return status;
		}

		if (uszDeviceString.Buffer && uszDeviceString.Length > 0)
		{
			if (RtlCompareUnicodeString(&uszDeviceString, &uNewLink, TRUE) != 0)
			{
				IoDeleteSymbolicLink(&uszDeviceString);
			}
		}

		RtlStringCchCopyW(g_CloakedSymlinkBuffer, 128, fullDosDevicesPath);
		RtlInitUnicodeString(&uszDeviceString, g_CloakedSymlinkBuffer);

		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNSUCCESSFUL;
	}
}

ULONG PhysicalRamScavenge(
	ULONG64 StartPhysAddr,
	ULONG64 MaxBytesToScan,
	const UCHAR* Pattern,
	const UCHAR* Mask,
	ULONG PatternLength,
	PULONG64 Matches,
	ULONG MaxMatches,
	PULONG64 NextPhysAddr)
{
	if (!Pattern || !Mask || PatternLength == 0 || !Matches || MaxMatches == 0)
		return 0;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return 0;

	if (g_SafePhysicalRangeCount == 0)
	{
		InitializeSafePhysicalRanges();
	}

	if (g_SafePhysicalRangeCount == 0)
		return 0;

	const SIZE_T CHUNK_SIZE = 64 * 1024;
	PUCHAR chunk = (PUCHAR)ExAllocatePoolWithTag(DBK_POOL_NX, CHUNK_SIZE, 'vaCS');
	if (!chunk)
		return 0;

	ULONG matchCount = 0;
	ULONG64 totalScanned = 0;
	ULONG64 currentPhys = StartPhysAddr;
	UCHAR firstByte = Pattern[0];
	UCHAR firstMask = Mask[0];

	__try
	{
		for (ULONG r = 0; r < g_SafePhysicalRangeCount && matchCount < MaxMatches; r++)
		{
			ULONG64 rangeBase = g_SafePhysicalRanges[r].BaseAddress;
			ULONG64 rangeEnd  = g_SafePhysicalRanges[r].EndAddress;

			if (rangeEnd <= currentPhys)
				continue;

			ULONG64 scanBase = (currentPhys > rangeBase) ? currentPhys : rangeBase;

			while (scanBase < rangeEnd && matchCount < MaxMatches)
			{
				if (MaxBytesToScan > 0 && totalScanned >= MaxBytesToScan)
					break;

				SIZE_T bytesRemainingInRange = (SIZE_T)(rangeEnd - scanBase);
				SIZE_T toRead = (bytesRemainingInRange < CHUNK_SIZE) ? bytesRemainingInRange : CHUNK_SIZE;

				if (MaxBytesToScan > 0)
				{
					SIZE_T bytesRemainingInScan = (SIZE_T)(MaxBytesToScan - totalScanned);
					if (toRead > bytesRemainingInScan)
						toRead = bytesRemainingInScan;
				}

				if (toRead < PatternLength)
					break;

				if (!IsPhysicalAddressSafe(scanBase, toRead))
				{
					scanBase += 0x1000;
					continue;
				}

				SIZE_T readOk = 0;
				if (!ReadPhysicalChunk(scanBase, chunk, toRead))
				{
					scanBase += 0x1000;
					continue;
				}

				SIZE_T limit = toRead - PatternLength + 1;
				for (SIZE_T i = 0; i < limit; i++)
				{

					if ((chunk[i] & firstMask) != (firstByte & firstMask))
						continue;

					BOOLEAN found = TRUE;
					for (ULONG p = 1; p < PatternLength; p++)
					{
						if ((chunk[i + p] & Mask[p]) != (Pattern[p] & Mask[p]))
						{
							found = FALSE;
							break;
						}
					}

					if (found)
					{
						Matches[matchCount++] = scanBase + i;
						if (matchCount >= MaxMatches)
							break;
					}
				}

				if (toRead > PatternLength)
				{
					SIZE_T step = toRead - PatternLength + 1;
					scanBase += step;
					totalScanned += step;
				}
				else
				{
					scanBase += toRead;
					totalScanned += toRead;
				}
			}

			currentPhys = scanBase;
			if (MaxBytesToScan > 0 && totalScanned >= MaxBytesToScan)
				break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	ExFreePoolWithTag(chunk, 'vaCS');

	if (NextPhysAddr)
		*NextPhysAddr = currentPhys;

	return matchCount;
}

NTSTATUS CloakRegionMemory(PEPROCESS Process, ULONG64 VirtualAddress, PVOID Buffer, ULONG Size)
{
	if (!vmxusable)
		return STATUS_NOT_SUPPORTED;

	if (!Process || !Buffer || Size == 0)
		return STATUS_INVALID_PARAMETER;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return STATUS_UNSUCCESSFUL;

	ULONG written = 0;
	PUCHAR src = (PUCHAR)Buffer;

	__try
	{
		while (written < Size)
		{
			ULONG64 currentVa = VirtualAddress + written;
			ULONG pageOffset = currentVa & 0xFFF;
			ULONG bytesInPage = 0x1000 - pageOffset;
			ULONG bytesRemaining = Size - written;
			ULONG chunkSize = (bytesRemaining < bytesInPage) ? bytesRemaining : bytesInPage;

			NTSTATUS status = CloakProcessPage(Process, currentVa);
			if (!NT_SUCCESS(status) && status != STATUS_IMAGE_ALREADY_LOADED)
			{

				break;
			}

			status = WriteCloakedPageMemory(Process, currentVa, src + written, chunkSize);
			if (!NT_SUCCESS(status))
			{
				break;
			}

			written += chunkSize;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNSUCCESSFUL;
	}

	return (written == Size) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

ULONG ResolveActiveProcessLinksOffset(void)
{
	static ULONG g_ActiveProcessLinksOffset = 0;
	if (g_ActiveProcessLinksOffset != 0)
		return g_ActiveProcessLinksOffset;

	PEPROCESS currentProc = IoGetCurrentProcess();
	HANDLE currentPid = PsGetCurrentProcessId();

	if (currentProc && currentPid)
	{
		PUCHAR p = (PUCHAR)currentProc;
		for (ULONG off = 0x200; off <= 0x600; off += sizeof(ULONG_PTR))
		{
			if (*(PHANDLE)(p + off) == currentPid)
			{
				ULONG linksOff = off + sizeof(HANDLE);
				PLIST_ENTRY list = (PLIST_ENTRY)(p + linksOff);
				if (MmIsAddressValid(list->Flink) && MmIsAddressValid(list->Blink))
				{
					g_ActiveProcessLinksOffset = linksOff;
					return linksOff;
				}
			}
		}
	}

	g_ActiveProcessLinksOffset = 0x448;
	return 0x448;
}

NTSTATUS HideProcessByPid(ULONG ProcessId)
{
	if (KeGetCurrentIrql() > APC_LEVEL)
		return STATUS_UNSUCCESSFUL;

	PEPROCESS proc = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)ProcessId, &proc)) || !proc)
		return STATUS_NOT_FOUND;

	ULONG linksOffset = ResolveActiveProcessLinksOffset();
	PLIST_ENTRY links = (PLIST_ENTRY)((PUCHAR)proc + linksOffset);

	__try
	{
		if (links->Flink && links->Blink && links->Flink != links)
		{
			links->Blink->Flink = links->Flink;
			links->Flink->Blink = links->Blink;
			links->Flink = links;
			links->Blink = links;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ObDereferenceObject(proc);
		return STATUS_UNHANDLED_EXCEPTION;
	}

	ObDereferenceObject(proc);
	return STATUS_SUCCESS;
}
