#include <ntifs.h>
#include <ntddk.h>
#include "OnyxFunc.h"
#include "vmxhelper.h"
#include "xorstr.h"

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

	PUCHAR pageBuf = (PUCHAR)ExAllocatePoolWithTag(ONYX_POOL_NX, 0x1000, 'KOLC');
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

	PSYSTEM_MODULE_INFORMATION pMods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(ONYX_POOL_NX, size, 'sDoM');
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

	UNICODE_STRING targets[6];
	RtlInitUnicodeString(&targets[0], L"lydumen.sys");
	RtlInitUnicodeString(&targets[1], L"dbk64.sys");
	RtlInitUnicodeString(&targets[2], L"OwMemDriver.sys");
	RtlInitUnicodeString(&targets[3], L"owmemdriver.sys");
	RtlInitUnicodeString(&targets[4], L"OnyxDriver.sys");
	RtlInitUnicodeString(&targets[5], L"onyxdriver.sys");

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(pLock, TRUE);

	__try
	{
		for (int t = 0; t < 6; t++)
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

	UNICODE_STRING targets[6];
	RtlInitUnicodeString(&targets[0], L"lydumen.sys");
	RtlInitUnicodeString(&targets[1], L"dbk64.sys");
	RtlInitUnicodeString(&targets[2], L"OwMemDriver.sys");
	RtlInitUnicodeString(&targets[3], L"owmemdriver.sys");
	RtlInitUnicodeString(&targets[4], L"OnyxDriver.sys");
	RtlInitUnicodeString(&targets[5], L"onyxdriver.sys");

	__try
	{
		for (ULONG i = 0; i < 50; i++)
		{
			PUNLOADED_DRIVER_ENTRY entry = &driverArray[i];
			if (!MmIsAddressValid(entry) || !entry->Name.Buffer || entry->Name.Length == 0)
				continue;

			for (int t = 0; t < 6; t++)
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

NTSTATUS CleanKernelHashBucketList(VOID)
{
	// Non-destructive safe stub
	return STATUS_SUCCESS;
}

