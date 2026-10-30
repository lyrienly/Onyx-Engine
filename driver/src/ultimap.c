#pragma warning( disable: 4100 4101 4213)

#include <ntifs.h>
#include "ultimap.h"
#include "vmxhelper.h"
#include "DBKFunc.h"
#include <windef.h>

#include "ultimap2\apic.h"

JUMPBACK perfmonJumpBackLocation;

BOOL SaveToFile;
HANDLE FileHandle;

int MaxDataBlocks=1;

KSEMAPHORE DataBlockSemaphore;
FAST_MUTEX DataBlockMutex;

typedef struct
{
	BOOL Available;
	PBTS Data;
	int DataSize;
	int CpuID;
	KEVENT DataReady;
} _DataBlock;

_DataBlock *DataBlock;
PVOID *DataReadyPointerList;

int perfmon_interrupt_centry(void);

void ultimap_flushBuffers_all(UINT_PTR param)
{
	DbgPrint("Calling perfmon_interrupt_centry() manually\n");
	if (DS_AREA[cpunr()])
	{
		perfmon_interrupt_centry();
		enableInterrupts();
	}
}

void ultimap_flushBuffers(void)
{

	int i;
	int count;

	DbgPrint("ultimap_flushBuffers\n");

	forEachCpuPassive(ultimap_flushBuffers_all,0);

	DbgPrint("ultimap_flushBuffers_all has returned\n");

}

NTSTATUS ultimap_continue(PULTIMAPDATAEVENT data)

{
	DbgPrint("ultimap_continue\n");
	MmUnmapLockedPages((PVOID)(UINT_PTR)data->Address, (PMDL)(UINT_PTR)data->Mdl);
	IoFreeMdl((PMDL)(UINT_PTR)data->Mdl);

	ExFreePool((PVOID)(UINT_PTR)data->KernelAddress);

	if (DataBlock)
		DataBlock[data->Block].Available=TRUE;

	KeReleaseSemaphore(&DataBlockSemaphore, 1, 1, FALSE);
	DbgPrint("Released semaphore\n");
	return STATUS_SUCCESS;
}

NTSTATUS ultimap_waitForData(ULONG timeout, PULTIMAPDATAEVENT data)

{
	NTSTATUS r;
	LARGE_INTEGER wait;

	PKWAIT_BLOCK waitblock;

	if (DataBlock)
	{
		waitblock = (PKWAIT_BLOCK)ExAllocatePoolWithTag(DBK_POOL_NX, MaxDataBlocks * sizeof(KWAIT_BLOCK), 'mtlU');
		if (!waitblock)
			return STATUS_INSUFFICIENT_RESOURCES;

		wait.QuadPart=-10000LL * timeout;

		if (timeout==0xffffffff)
			r=KeWaitForMultipleObjects(MaxDataBlocks, DataReadyPointerList, WaitAny, UserRequest, UserMode, TRUE, NULL, waitblock);
		else
			r=KeWaitForMultipleObjects(MaxDataBlocks, DataReadyPointerList, WaitAny, UserRequest, UserMode, TRUE, &wait, waitblock);

		ExFreePool(waitblock);

		data->Block=r-STATUS_WAIT_0;

		if (data->Block <= MaxDataBlocks)
		{

			ExAcquireFastMutex(&DataBlockMutex);
			if (DataBlock)
			{
				data->KernelAddress=(UINT64)DataBlock[data->Block].Data;
				data->Mdl=(UINT64)IoAllocateMdl(DataBlock[data->Block].Data, DataBlock[data->Block].DataSize, FALSE, FALSE, NULL);
				if (data->Mdl)
				{
					MmBuildMdlForNonPagedPool((PMDL)(UINT_PTR)data->Mdl);

					data->Address=(UINT_PTR)MmMapLockedPagesSpecifyCache((PMDL)(UINT_PTR)data->Mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
					if (data->Address)
					{
						data->Size=DataBlock[data->Block].DataSize;
						data->CpuID=DataBlock[data->Block].CpuID;
						r=STATUS_SUCCESS;
					}
					else
						r=STATUS_UNSUCCESSFUL;
				}
				else
					r=STATUS_UNSUCCESSFUL;
			}
			else
				r=STATUS_UNSUCCESSFUL;

			ExReleaseFastMutex(&DataBlockMutex);

			return r;
		}
		else
			return STATUS_UNSUCCESSFUL;

	}
	else
		return STATUS_UNSUCCESSFUL;

}

void ultimap_cleanstate()
{
	apic_clearPerfmon();
}

int perfmon_interrupt_centry(void)
{

	KIRQL old = PASSIVE_LEVEL;
	int changedIRQL = 0;

	void *temp;
	int causedbyme=(DS_AREA[cpunr()]->BTS_IndexBaseAddress>=DS_AREA[cpunr()]->BTS_InterruptThresholdAddress);
	UINT_PTR blocksize;

	DbgPrint("perfmon_interrupt_centry\n", cpunr());

	if (causedbyme)
		ultimap_cleanstate();

	blocksize=(UINT_PTR)(DS_AREA[cpunr()]->BTS_IndexBaseAddress-DS_AREA[cpunr()]->BTS_BufferBaseAddress);

	{
		if (KeGetCurrentIrql() < DISPATCH_LEVEL)
		{

			changedIRQL = 1;
			old = KeRaiseIrqlToDpcLevel();
		}

		DbgPrint("Entry cpunr=%d\n", cpunr());
		DbgPrint("Entry threadid=%d\n", PsGetCurrentThreadId());

		temp = ExAllocatePoolWithTag(DBK_POOL_NX, blocksize, 'mtlU');
		if (temp)
		{
			RtlCopyMemory(temp, (PVOID *)(UINT_PTR)DS_AREA[cpunr()]->BTS_BufferBaseAddress, blocksize);

			DbgPrint("temp=%p\n", temp);

			DS_AREA[cpunr()]->BTS_IndexBaseAddress=DS_AREA[cpunr()]->BTS_BufferBaseAddress;
		}
		else
		{
			DbgPrint("ExAllocatePool has failed\n");
			KeLowerIrql(old);
			disableInterrupts();
			return causedbyme;
		}

		if (changedIRQL)
			KeLowerIrql(old);

		if (SaveToFile)
		{
			IO_STATUS_BLOCK iosb;
			NTSTATUS r;

			DbgPrint("Writing buffer to disk\n");
			r=ZwWriteFile(FileHandle, NULL, NULL, NULL, &iosb,  temp, (ULONG)blocksize, NULL, NULL);
			DbgPrint("Done Writing. Result=%x\n", r);
		}
		else
		{
			DbgPrint("Waiting till there is a block free\n");

			if ((DataBlock) && (KeWaitForSingleObject(&DataBlockSemaphore, Executive, KernelMode, FALSE, NULL) == STATUS_SUCCESS))
			{
				int currentblock;
				int i;

				DbgPrint("Acquired semaphore. Now picking a usable datablock\n");

				ExAcquireFastMutex(&DataBlockMutex);
				DbgPrint("Acquired mutex. Looking for a Datablock that can be used\n");

				if (DataBlock)
				{
					currentblock=-1;
					for (i=0; i< MaxDataBlocks; i++)
					{
						if (DataBlock[i].Available)
						{
							currentblock=i;
							DataBlock[currentblock].Available=FALSE;
							break;
						}
					}
				}
				else currentblock=-1;

				if (currentblock>=0)
				{
					DbgPrint("Using datablock %d\n", currentblock);
					DataBlock[currentblock].Data=temp;
					DataBlock[currentblock].DataSize=(int)blocksize;
					DataBlock[currentblock].CpuID=cpunr();

					DbgPrint("Calling KeSetEvent/KeWaitForSingleObject\n");
					KeSetEvent(&DataBlock[currentblock].DataReady, 1, FALSE);
				}
				ExReleaseFastMutex(&DataBlockMutex);

			}
			else
			{
				DbgPrint("if ((DataBlock) && (KeWaitForSingleObject(&DataBlockSemaphore, Executive, KernelMode, FALSE, NULL) == STATUS_SUCCESS)) failed\n");
			}

		}

		disableInterrupts();
		return causedbyme;

	}
}

#ifdef AMD64
extern void perfmon_interrupt();
#else
_declspec( naked ) void perfmon_interrupt( void )
{
	__asm{
		cld

		push ebp
		mov ebp,esp

		pushad
		xor eax,eax
		mov ax,ds
		push eax

		mov ax,es
		push eax

		mov ax,fs
		push eax

		mov ax,gs
		push eax

		mov ax,0x23
		mov ds,ax
		mov es,ax
		mov gs,ax
		mov ax,0x30
		mov fs,ax

		call perfmon_interrupt_centry
		cmp eax,1

		pop gs
		pop fs
		pop es
		pop ds
		popad

		pop ebp

		je skip_original_perfmon

		jmp far [perfmonJumpBackLocation]

skip_original_perfmon:

		iretd
	}
}
#endif

VOID ultimap_pause_dpc(IN struct _KDPC *Dpc, IN PVOID DeferredContext, IN PVOID SystemArgumen1, IN PVOID SystemArgument2)
{
	vmx_ultimap_pause();
}

void ultimap_pause(void)
{
	forEachCpu(ultimap_pause_dpc, NULL, NULL, NULL, NULL);
}

VOID ultimap_resume_dpc(IN struct _KDPC *Dpc, IN PVOID DeferredContext, IN PVOID SystemArgumen1, IN PVOID SystemArgument2)
{
	vmx_ultimap_resume();
}

void ultimap_resume(void)
{
	forEachCpu(ultimap_resume_dpc, NULL, NULL, NULL, NULL);
}

VOID ultimap_disable_dpc(IN struct _KDPC *Dpc, IN PVOID DeferredContext, IN PVOID SystemArgumen1, IN PVOID SystemArgument2)
{
	int i;

	if (vmxusable)
	{
		i=vmx_ultimap_disable();

		if (DS_AREA[cpunr()])
		{
			ExFreePool(DS_AREA[cpunr()]);
			DS_AREA[cpunr()]=NULL;
		}
	}
}

void ultimap_disable(void)
{
	void *clear = NULL;

	if (DataBlock)
	{
		int i;

		forEachCpu(ultimap_disable_dpc, NULL, NULL, NULL, NULL);

		if (SaveToFile && FileHandle)
		{
			ZwClose(FileHandle);
			FileHandle=NULL;
		}

		ExAcquireFastMutex(&DataBlockMutex);

		for (i=0; i<MaxDataBlocks; i++)
			KeSetEvent(&DataBlock[i].DataReady,0, FALSE);

		ExFreePool(DataBlock);
		DataBlock=NULL;

		if (DataReadyPointerList)
		{
			ExFreePool(DataReadyPointerList);
			DataReadyPointerList=NULL;
		}
		ExReleaseFastMutex(&DataBlockMutex);

	    HalSetSystemInformation(HalProfileSourceInterruptHandler, sizeof(PVOID*), &clear);

	}
}

VOID ultimap_setup_dpc(IN struct _KDPC *Dpc, IN PVOID  DeferredContext, IN PVOID  SystemArgument1, IN PVOID  SystemArgument2)

{
	struct
	{
		UINT64 cr3;
		UINT64 dbgctl_msr;
		int DS_AREA_SIZE;
	} *params;

	params=DeferredContext;

	DS_AREA_SIZE=params->DS_AREA_SIZE;
	if (DS_AREA_SIZE == 0)
	{
		DbgPrint("DS_AREA_SIZE==0\n");
		return;
	}

	DbgPrint("ultimap(%I64x, %I64x, %d)", (UINT64)params->cr3, (UINT64)params->dbgctl_msr, params->DS_AREA_SIZE);
	DS_AREA[cpunr()]=NULL;

	if (params->DS_AREA_SIZE)
	{
		DS_AREA[cpunr()] = ExAllocatePoolWithTag(DBK_POOL_NX, params->DS_AREA_SIZE, 'mtlU');

		if (DS_AREA[cpunr()] == NULL)
		{
			DbgPrint("ExAllocatePool failed\n");
			return;
		}

		RtlZeroMemory(DS_AREA[cpunr()],  params->DS_AREA_SIZE);

		DbgPrint("DS_AREA[%d]=%p", cpunr(), DS_AREA[cpunr()]);

		DS_AREA[cpunr()]->BTS_BufferBaseAddress=(QWORD)(UINT_PTR)DS_AREA[cpunr()]+sizeof(DS_AREA_MANAGEMENT);
        DS_AREA[cpunr()]->BTS_BufferBaseAddress+=sizeof(BTS);

        DS_AREA[cpunr()]->BTS_BufferBaseAddress-=DS_AREA[cpunr()]->BTS_BufferBaseAddress % sizeof(BTS);

        DS_AREA[cpunr()]->BTS_IndexBaseAddress=DS_AREA[cpunr()]->BTS_BufferBaseAddress;
        DS_AREA[cpunr()]->BTS_AbsoluteMaxAddress=(QWORD)(UINT_PTR)DS_AREA[cpunr()]+params->DS_AREA_SIZE-sizeof(BTS);
        DS_AREA[cpunr()]->BTS_AbsoluteMaxAddress-=DS_AREA[cpunr()]->BTS_AbsoluteMaxAddress % sizeof(BTS);
        DS_AREA[cpunr()]->BTS_AbsoluteMaxAddress++;

        DS_AREA[cpunr()]->BTS_InterruptThresholdAddress=(DS_AREA[cpunr()]->BTS_AbsoluteMaxAddress-1) - 4*sizeof(BTS);
	}

	if (params->dbgctl_msr & (1 << 8))
	{

		int perfmonIVT=(APIC_BASE->LVT_Performance_Monitor.a) & 0xff;

		DbgPrint("APIC_BASE->LVT_Performance_Monitor.a=%x\n", APIC_BASE->LVT_Performance_Monitor.a);
		if (perfmonIVT==0)
			perfmonIVT=0xfe;

		APIC_BASE->LVT_Performance_Monitor.a=perfmonIVT;

		DbgPrint("APIC_BASE->LVT_Performance_Monitor.a=%x\n", APIC_BASE->LVT_Performance_Monitor.a);

	}

	if (vmxusable)
	{
		vmx_ultimap((UINT_PTR)params->cr3, params->dbgctl_msr, DS_AREA[cpunr()]);
	}
	else
	{
		DbgPrint("vmxusable is false. So no ultimap for you!!!\n");
	}
}

void ultimapapc(PKAPC Apc, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	EFLAGS e = getEflags();
	DbgPrint("ultimapapc call for cpu %d ( IF=%d IRQL=%d)\n", KeGetCurrentProcessorNumber(), e.IF, KeGetCurrentIrql());
	DbgPrint("SystemArgument1=%x\n", *(PULONG)SystemArgument1);
	DbgPrint("tid=%x\n", PsGetCurrentThreadId());
	DbgPrint("Apc=%p\n", Apc);
}

void ultimapapcnormal(PVOID arg1, PVOID arg2, PVOID arg3)
{
	EFLAGS e = getEflags();
	DbgPrint("ultimapapcnormal call for cpu %d ( IF=%d IRQL=%d)\n", KeGetCurrentProcessorNumber(), e.IF, KeGetCurrentIrql());
	DbgPrint("tid=%x\n", PsGetCurrentThreadId());

	ultimap_flushBuffers();

	return;
}

KAPC      kApc[128];
volatile LONG apcnr = 0;

void perfmon_hook(__in struct _KINTERRUPT *Interrupt, __in PVOID ServiceContext)
{

	int i = InterlockedIncrement(&apcnr) % 128;

	EFLAGS e = getEflags();
	DbgPrint("permon_hook call for cpu %d ( IF=%d IRQL=%d)\n", KeGetCurrentProcessorNumber(), e.IF, KeGetCurrentIrql());

	DbgPrint("kApc=%p\n", &kApc);

	KeInitializeApc(&kApc[i],
		(PKTHREAD)PsGetCurrentThread(),
		0,
		(PKKERNEL_ROUTINE)ultimapapc,
		NULL,
		(PKNORMAL_ROUTINE)ultimapapcnormal,
		KernelMode,
		0
		);

	KeInsertQueueApc(&kApc[i], NULL, NULL, 0);

	DbgPrint("after KeInsertQueueApc");

	ultimap_cleanstate();

	DbgPrint("permon_return");
}

void *pperfmon_hook = (void*)perfmon_hook;

NTSTATUS ultimap(UINT64 cr3, UINT64 dbgctl_msr, int _DS_AREA_SIZE, BOOL savetofile, WCHAR *filename, int handlerCount)
{
	struct
	{
		UINT64 cr3;
		UINT64 dbgctl_msr;
		int DS_AREA_SIZE;
	} params;
	int i;

	if (handlerCount>64)
		return STATUS_UNSUCCESSFUL;

	SaveToFile=savetofile;

	if (SaveToFile)
	{
		UNICODE_STRING usFile;
		OBJECT_ATTRIBUTES oaFile;
		IO_STATUS_BLOCK iosb;
		NTSTATUS r;

		RtlInitUnicodeString(&usFile, filename);
		InitializeObjectAttributes(&oaFile,&usFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,NULL);

		DbgPrint("Creating file %S", usFile.Buffer);

		FileHandle=0;
		r=ZwCreateFile(&FileHandle,SYNCHRONIZE|FILE_READ_DATA|FILE_APPEND_DATA | GENERIC_ALL,&oaFile,&iosb,0,FILE_ATTRIBUTE_NORMAL,0,FILE_SUPERSEDE, FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT,NULL,0);
		DbgPrint("ZwCreateFile=%x\n", r);

	}

	MaxDataBlocks=handlerCount;
	KeInitializeSemaphore(&DataBlockSemaphore, MaxDataBlocks, MaxDataBlocks);
	ExInitializeFastMutex(&DataBlockMutex);

	DataBlock = (_DataBlock*)ExAllocatePoolWithTag(DBK_POOL_NX, sizeof(_DataBlock) * MaxDataBlocks, 'mtlU');
	DataReadyPointerList = (PVOID*)ExAllocatePoolWithTag(DBK_POOL_NX, sizeof(PVOID) * MaxDataBlocks, 'mtlU');

	RtlZeroMemory(DataBlock, sizeof(_DataBlock) * MaxDataBlocks);
	RtlZeroMemory(DataReadyPointerList, sizeof(PVOID) * MaxDataBlocks);

	if ((DataBlock) && (DataReadyPointerList))
	{
		NTSTATUS r;

		for (i=0; i< MaxDataBlocks; i++)
		{

			DataBlock[i].Data=NULL;

			KeInitializeEvent(&DataBlock[i].DataReady, SynchronizationEvent , FALSE);

			DataBlock[i].Available=TRUE;

			DataReadyPointerList[i]=&DataBlock[i].DataReady;
		}

		params.cr3=cr3;
		params.dbgctl_msr=dbgctl_msr;
		params.DS_AREA_SIZE=_DS_AREA_SIZE;

		r=HalSetSystemInformation(HalProfileSourceInterruptHandler, sizeof(PVOID*), &pperfmon_hook);

		DbgPrint("HalSetSystemInformation returned %x\n", r);

		forEachCpu(ultimap_setup_dpc, &params, NULL, NULL, NULL);
		return STATUS_SUCCESS;
	}
	else
	{
		DbgPrint("Failure allocating DataBlock and DataReadyPointerList\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

}
