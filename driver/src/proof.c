#include <ntifs.h>
#include <ntddk.h>
#include "OnyxFunc.h"
#include "vmxhelper.h"
#include "xorstr.h"

NTSTATUS InspectProcessByPid(ULONG ProcessId, PPROCESS_MEMORY_PROOF Proof)
{
	if (!Proof)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(Proof, sizeof(PROCESS_MEMORY_PROOF));
	Proof->ProcessId = ProcessId;

	PEPROCESS proc = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)ProcessId, &proc)) || !proc)
		return STATUS_NOT_FOUND;

	ULONG linksOffset = ResolveActiveProcessLinksOffset();
	PLIST_ENTRY links = (PLIST_ENTRY)((PUCHAR)proc + linksOffset);

	Proof->EprocessAddress = (UINT64)proc;
	Proof->ActiveProcessLinksAddress = (UINT64)links;

	__try
	{
		if (MmIsAddressValid(links))
		{
			Proof->Flink = (UINT64)links->Flink;
			Proof->Blink = (UINT64)links->Blink;

			if ((UINT64)links->Flink == (UINT64)links && (UINT64)links->Blink == (UINT64)links)
			{
				Proof->IsSelfLinked = TRUE;
				Proof->CircularIntegrity = FALSE;
			}
			else
			{
				Proof->IsSelfLinked = FALSE;
				if (MmIsAddressValid(links->Flink))
				{
					Proof->FlinkBlink = (UINT64)links->Flink->Blink;
					if (links->Flink->Blink == links)
					{
						Proof->CircularIntegrity = TRUE;
					}
				}
			}
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

NTSTATUS InspectDriverMemory(PDRIVER_OBJECT DriverObject, PDRIVER_MEMORY_PROOF Proof)
{
	if (!Proof || !DriverObject)
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(Proof, sizeof(DRIVER_MEMORY_PROOF));
	Proof->DriverObjectAddress = (UINT64)DriverObject;

	PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	Proof->DriverSectionAddress = (UINT64)entry;

	if (entry && MmIsAddressValid(entry))
	{
		Proof->InLoadOrderFlink = (UINT64)entry->InLoadOrderLinks.Flink;
		Proof->InLoadOrderBlink = (UINT64)entry->InLoadOrderLinks.Blink;

		if ((UINT64)entry->InLoadOrderLinks.Flink == (UINT64)&entry->InLoadOrderLinks)
		{
			Proof->IsDriverModuleUnlinked = TRUE;
		}
		else
		{
			Proof->IsDriverModuleUnlinked = FALSE;
		}
	}

	Proof->UnloadedDriversEstimatedCount = 0;
	return STATUS_SUCCESS;
}

