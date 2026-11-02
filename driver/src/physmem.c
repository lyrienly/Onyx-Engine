#include <ntifs.h>
#include <ntddk.h>
#include "OnyxFunc.h"
#include "vmxhelper.h"
#include "xorstr.h"

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

static PVOID MapPhysicalWithMdl(ULONG64 PhysAddr, SIZE_T Size, MEMORY_CACHING_TYPE CacheType, PMDL* OutMdl)
{
	if (!OutMdl || Size == 0)
		return NULL;

	*OutMdl = NULL;
	ULONG pfnCount = (ULONG)(((PhysAddr & 0xFFF) + Size + 0xFFF) >> 12);
	PMDL mdl = IoAllocateMdl(NULL, (ULONG)Size, FALSE, FALSE, NULL);
	if (!mdl)
		return NULL;

	PPFN_NUMBER pfnArray = MmGetMdlPfnArray(mdl);
	ULONG64 startPfn = PhysAddr >> 12;
	for (ULONG i = 0; i < pfnCount; i++) {
		pfnArray[i] = (PFN_NUMBER)(startPfn + i);
	}
	mdl->MdlFlags |= MDL_PAGES_LOCKED;

	PVOID mapped = NULL;
	__try {
		mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, CacheType, NULL, FALSE, NormalPagePriority);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		mapped = NULL;
	}

	if (!mapped) {
		IoFreeMdl(mdl);
		return NULL;
	}

	*OutMdl = mdl;
	return (PVOID)((PUCHAR)mapped + (PhysAddr & 0xFFF));
}

static VOID UnmapPhysicalWithMdl(PMDL Mdl, PVOID MappedAddress)
{
	if (Mdl && MappedAddress) {
		PVOID pageAligned = (PVOID)((ULONG_PTR)MappedAddress & ~(ULONG_PTR)0xFFF);
		MmUnmapLockedPages(pageAligned, Mdl);
		IoFreeMdl(Mdl);
	}
}

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

		if (!success)
		{
			PMDL mdl = NULL;
			PVOID mdlMapped = MapPhysicalWithMdl(PhysAddr, Size, MmCached, &mdl);
			if (!mdlMapped)
				mdlMapped = MapPhysicalWithMdl(PhysAddr, Size, MmNonCached, &mdl);

			if (mdlMapped)
			{
				__try {
					RtlCopyMemory(Buffer, mdlMapped, Size);
					success = TRUE;
				} __finally {
					UnmapPhysicalWithMdl(mdl, mdlMapped);
				}
			}
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
	PUCHAR chunk = (PUCHAR)ExAllocatePoolWithTag(ONYX_POOL_NX, CHUNK_SIZE, 'kbaS');
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

	if (!success)
	{
		PMDL mdl = NULL;
		PVOID mdlMapped = MapPhysicalWithMdl(PhysAddr, Size, MmCached, &mdl);
		if (!mdlMapped)
			mdlMapped = MapPhysicalWithMdl(PhysAddr, Size, MmNonCached, &mdl);

		if (mdlMapped)
		{
			__try {
				RtlCopyMemory(mdlMapped, Buffer, Size);
				success = TRUE;
			} __finally {
				UnmapPhysicalWithMdl(mdl, mdlMapped);
			}
		}
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
	PUCHAR chunk = (PUCHAR)ExAllocatePoolWithTag(ONYX_POOL_NX, CHUNK_SIZE, 'vaCS');
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

