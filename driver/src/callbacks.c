#include <ntifs.h>
#include <ntddk.h>
#include "OnyxFunc.h"
#include "vmxhelper.h"
#include "xorstr.h"

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
	PLIST_ENTRY OriginalFlink;
	PLIST_ENTRY OriginalBlink;
	BOOLEAN Unlinked;
} STRIPPED_CALLBACK_BACKUP;

static STRIPPED_CALLBACK_BACKUP g_CallbackBackups[128];
static ULONG g_CallbackBackupCount = 0;
static KSPIN_LOCK g_CallbackBackupLock = 0;
static BOOLEAN g_CallbackBackupLockInit = FALSE;

static VOID InitCallbackBackupLock(VOID)
{
	if (!g_CallbackBackupLockInit)
	{
		KeInitializeSpinLock(&g_CallbackBackupLock);
		g_CallbackBackupLockInit = TRUE;
	}
}

static PLIST_ENTRY GetObjectTypeCallbackList(POBJECT_TYPE ObjType)
{
	if (!ObjType || !MmIsAddressValid(ObjType))
		return NULL;

	PUCHAR p = (PUCHAR)ObjType;
	for (ULONG off = 0x80; off <= 0x140; off += sizeof(ULONG_PTR))
	{
		PLIST_ENTRY candidate = (PLIST_ENTRY)(p + off);
		if (MmIsAddressValid(candidate) && candidate->Flink != candidate && MmIsAddressValid(candidate->Flink))
		{
			POB_CALLBACK_ENTRY testEntry = (POB_CALLBACK_ENTRY)candidate->Flink;
			if (MmIsAddressValid(&testEntry->ObjectType) && testEntry->ObjectType == ObjType)
			{
				return candidate;
			}
		}
	}

	PLIST_ENTRY fallback = (PLIST_ENTRY)(p + 0xC8);
	if (MmIsAddressValid(fallback))
		return fallback;

	return NULL;
}

static VOID ResolveDriverNameByAddress(PDRIVER_OBJECT DriverObject, PVOID Address, PCHAR OutName, ULONG OutNameSize)
{
	if (!OutName || OutNameSize == 0)
		return;

	RtlZeroMemory(OutName, OutNameSize);

	if (!Address)
	{
		strncpy(OutName, "NULL", OutNameSize - 1);
		return;
	}

	__try
	{
		if (DriverObject && DriverObject->DriverSection)
		{
			PKLDR_DATA_TABLE_ENTRY head = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
			PLIST_ENTRY listHead = &head->InLoadOrderLinks;
			PLIST_ENTRY curr = listHead->Flink;

			while (curr != NULL && curr != listHead && MmIsAddressValid(curr))
			{
				PKLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (MmIsAddressValid(entry) && entry->DllBase != NULL && entry->SizeOfImage > 0)
				{
					ULONG_PTR base = (ULONG_PTR)entry->DllBase;
					ULONG_PTR target = (ULONG_PTR)Address;
					if (target >= base && target < (base + entry->SizeOfImage))
					{
						if (entry->BaseDllName.Buffer && MmIsAddressValid(entry->BaseDllName.Buffer))
						{
							ANSI_STRING ansi;
							if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, &entry->BaseDllName, TRUE)))
							{
								strncpy(OutName, ansi.Buffer, OutNameSize - 1);
								RtlFreeAnsiString(&ansi);
								return;
							}
						}
					}
				}
				curr = curr->Flink;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	strncpy(OutName, "Unknown", OutNameSize - 1);
}

ULONG StripProcessAndThreadCallbacks(ULONG Mode)
{
	if (KeGetCurrentIrql() > APC_LEVEL)
		return 0;

	InitCallbackBackupLock();

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_CallbackBackupLock, &oldIrql);

	ULONG affected = 0;

	__try
	{
		// Mode 1: Restore all backed up callbacks
		if (Mode == 1)
		{
			for (ULONG i = 0; i < g_CallbackBackupCount; i++)
			{
				POB_CALLBACK_ENTRY entry = g_CallbackBackups[i].EntryAddress;
				if (entry && MmIsAddressValid(entry))
				{
					if (g_CallbackBackups[i].Unlinked)
					{
						PLIST_ENTRY blink = g_CallbackBackups[i].OriginalBlink;
						PLIST_ENTRY flink = g_CallbackBackups[i].OriginalFlink;
						if (MmIsAddressValid(blink) && MmIsAddressValid(flink))
						{
							entry->CallbackList.Blink = blink;
							entry->CallbackList.Flink = flink;
							blink->Flink = &entry->CallbackList;
							flink->Blink = &entry->CallbackList;
						}
					}

					entry->Operations = g_CallbackBackups[i].OriginalOperations;
					entry->Enabled = g_CallbackBackups[i].OriginalEnabled;
					entry->PreOperation = g_CallbackBackups[i].OriginalPreOperation;
					entry->PostOperation = g_CallbackBackups[i].OriginalPostOperation;
					affected++;
				}
			}
			g_CallbackBackupCount = 0;
			KeReleaseSpinLock(&g_CallbackBackupLock, oldIrql);
			return affected;
		}

		// Mode 0 (Temporary Zero) or Mode 2 (DKOM Unlink)
		// Process both *PsProcessType and *PsThreadType
		POBJECT_TYPE types[2] = { 0 };
		if (PsProcessType) types[0] = *PsProcessType;
		if (PsThreadType)  types[1] = *PsThreadType;

		for (int t = 0; t < 2; t++)
		{
			POBJECT_TYPE pType = types[t];
			if (!pType) continue;

			PLIST_ENTRY pCallbackList = GetObjectTypeCallbackList(pType);
			if (!pCallbackList || !MmIsAddressValid(pCallbackList))
				continue;

			PLIST_ENTRY curr = pCallbackList->Flink;
			while (curr != pCallbackList && curr != NULL)
			{
				if (!MmIsAddressValid(curr))
					break;

				POB_CALLBACK_ENTRY entry = (POB_CALLBACK_ENTRY)curr;
				PLIST_ENTRY next = curr->Flink;

				if (MmIsAddressValid(&entry->ObjectType) && entry->ObjectType == pType)
				{
					// Check if already backed up
					BOOLEAN alreadyBackedUp = FALSE;
					for (ULONG b = 0; b < g_CallbackBackupCount; b++)
					{
						if (g_CallbackBackups[b].EntryAddress == entry)
						{
							alreadyBackedUp = TRUE;
							break;
						}
					}

					if (!alreadyBackedUp && g_CallbackBackupCount < 128)
					{
						g_CallbackBackups[g_CallbackBackupCount].EntryAddress = entry;
						g_CallbackBackups[g_CallbackBackupCount].OriginalOperations = entry->Operations;
						g_CallbackBackups[g_CallbackBackupCount].OriginalEnabled = entry->Enabled;
						g_CallbackBackups[g_CallbackBackupCount].OriginalPreOperation = entry->PreOperation;
						g_CallbackBackups[g_CallbackBackupCount].OriginalPostOperation = entry->PostOperation;
						g_CallbackBackups[g_CallbackBackupCount].OriginalFlink = entry->CallbackList.Flink;
						g_CallbackBackups[g_CallbackBackupCount].OriginalBlink = entry->CallbackList.Blink;
						g_CallbackBackups[g_CallbackBackupCount].Unlinked = (Mode == 2);
						g_CallbackBackupCount++;
					}

					if (Mode == 2)
					{
						// DKOM Unlink: splice out of CallbackList
						if (entry->CallbackList.Blink && entry->CallbackList.Flink &&
						    entry->CallbackList.Flink != &entry->CallbackList)
						{
							entry->CallbackList.Blink->Flink = entry->CallbackList.Flink;
							entry->CallbackList.Flink->Blink = entry->CallbackList.Blink;
							entry->CallbackList.Flink = &entry->CallbackList;
							entry->CallbackList.Blink = &entry->CallbackList;
						}
					}
					else
					{
						// Temporary Zero (Safe against PatchGuard / KPP)
						entry->PreOperation = NULL;
						entry->Operations = 0;
						entry->Enabled = 0;
					}

					affected++;
				}

				curr = next;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	KeReleaseSpinLock(&g_CallbackBackupLock, oldIrql);
	return affected;
}

ULONG EnumerateKernelObCallbacks(PDRIVER_OBJECT DriverObject, PKERNEL_OB_CALLBACK_INFO OutCallbacks, ULONG MaxCount)
{
	if (!OutCallbacks || MaxCount == 0)
		return 0;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return 0;

	RtlZeroMemory(OutCallbacks, sizeof(KERNEL_OB_CALLBACK_INFO) * MaxCount);

	ULONG count = 0;

	POBJECT_TYPE types[2] = { 0 };
	if (PsProcessType) types[0] = *PsProcessType;
	if (PsThreadType)  types[1] = *PsThreadType;

	__try
	{
		for (int t = 0; t < 2; t++)
		{
			POBJECT_TYPE pType = types[t];
			if (!pType) continue;

			PLIST_ENTRY pCallbackList = GetObjectTypeCallbackList(pType);
			if (!pCallbackList || !MmIsAddressValid(pCallbackList))
				continue;

			PLIST_ENTRY curr = pCallbackList->Flink;
			while (curr != pCallbackList && curr != NULL && count < MaxCount)
			{
				if (!MmIsAddressValid(curr))
					break;

				POB_CALLBACK_ENTRY entry = (POB_CALLBACK_ENTRY)curr;
				if (MmIsAddressValid(&entry->ObjectType) && entry->ObjectType == pType)
				{
					OutCallbacks[count].EntryAddress = (UINT64)entry;
					OutCallbacks[count].ObjectType = (t == 0) ? 1 : 2; // 1 = Process, 2 = Thread
					OutCallbacks[count].PreOperation = (UINT64)entry->PreOperation;
					OutCallbacks[count].PostOperation = (UINT64)entry->PostOperation;
					OutCallbacks[count].Operations = entry->Operations;
					OutCallbacks[count].Enabled = entry->Enabled;

					PVOID inspectTarget = entry->PreOperation ? entry->PreOperation : entry->PostOperation;
					ResolveDriverNameByAddress(DriverObject, inspectTarget, OutCallbacks[count].OwnerModule, sizeof(OutCallbacks[count].OwnerModule));

					count++;
				}

				curr = curr->Flink;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return count;
}
