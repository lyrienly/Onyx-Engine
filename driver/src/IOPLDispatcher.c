#pragma warning( disable: 4100 4101 4103 4189)

#include "IOPLDispatcher.h"
#include "DBKFunc.h"
#include "DBKDrvr.h"

#include "memscan.h"

#include "deepkernel.h"

#include "vmxhelper.h"
#include "vmxoffload.h"
UINT64 PhysicalMemoryRanges=0;
UINT64 PhysicalMemoryRangesListSize=0;

#if (NTDDI_VERSION >= NTDDI_VISTA)
PVOID DRMHandle = NULL;
PEPROCESS DRMProcess = NULL;
PEPROCESS DRMProcess2 = NULL;
#endif

typedef PCHAR (*GET_PROCESS_IMAGE_NAME) (PEPROCESS Process);
GET_PROCESS_IMAGE_NAME PsGetProcessImageFileName;

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);

void mykapc2(PKAPC Apc, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	ULONG_PTR iswow64;
	ExFreePool(Apc);
	DbgPrint("My second kernelmode apc!!!!\n");
	DbgPrint("SystemArgument1=%x\n",*(PULONG)SystemArgument1);
	DbgPrint("SystemArgument2=%x\n", *(PULONG)SystemArgument2);

	if (ZwQueryInformationProcess(ZwCurrentProcess(), ProcessWow64Information, &iswow64, sizeof(iswow64), NULL) == STATUS_SUCCESS)
	{
#if (NTDDI_VERSION >= NTDDI_VISTA)
		if (iswow64)
		{
			DbgPrint("WOW64 apc");
			PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);
		}
#endif
	}

}

void nothing2(PVOID arg1, PVOID arg2, PVOID arg3)
{

	return;
}

void mykapc(PKAPC Apc, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{

	PKAPC      kApc;
	LARGE_INTEGER Timeout;

	kApc = (PKAPC)ExAllocatePoolWithTag(DBK_POOL_NX, sizeof(KAPC), 'cpAk');
	if (!kApc)
	{
		ExFreePool(Apc);
		return;
	}

	ExFreePool(Apc);

	DbgPrint("My kernelmode apc!!!!(irql=%d)\n", KeGetCurrentIrql());

	DbgPrint("NormalRoutine=%p\n",*(PUINT_PTR)NormalRoutine);
	DbgPrint("NormalContext=%p\n",*(PUINT_PTR)NormalContext);
	DbgPrint("SystemArgument1=%p\n",*(PUINT_PTR)SystemArgument1);
	DbgPrint("SystemArgument2=%p\n",*(PUINT_PTR)SystemArgument2);

	KeInitializeApc(kApc,
		            (PKTHREAD)PsGetCurrentThread(),
                    0,
                    (PKKERNEL_ROUTINE)mykapc2,
                    NULL,
                    (PKNORMAL_ROUTINE)*(PUINT_PTR)SystemArgument1,
                    UserMode,
                    (PVOID)*(PUINT_PTR)NormalContext
                    );

	KeInsertQueueApc (kApc, (PVOID)*(PUINT_PTR)SystemArgument1, (PVOID)*(PUINT_PTR)SystemArgument2, 0);

	Timeout.QuadPart = 0;
	KeDelayExecutionThread(UserMode, TRUE, &Timeout);

	return;
}

void nothing(PVOID arg1, PVOID arg2, PVOID arg3)
{
	return;
}

void CreateRemoteAPC(ULONG threadid,PVOID addresstoexecute)
{

	PKTHREAD   kThread;
	PKAPC      kApc;

	kApc = (PKAPC)ExAllocatePoolWithTag(DBK_POOL_NX, sizeof(KAPC), 'cpAk');
	if (!kApc)
		return;

	kThread=(PKTHREAD)getPEThread(threadid);
	DbgPrint("(PVOID)KThread=%p\n",kThread);
	DbgPrint("addresstoexecute=%p\n", addresstoexecute);

	KeInitializeApc(kApc,
		            kThread,
                    0,
                    (PKKERNEL_ROUTINE)mykapc,
                    NULL,
                    (PKNORMAL_ROUTINE)nothing,
                    KernelMode,
                    0
                    );

	KeInsertQueueApc (kApc, addresstoexecute, addresstoexecute, 0);
}

#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)

#if (NTDDI_VERSION >= NTDDI_VISTA)
OB_PREOP_CALLBACK_STATUS ThreadPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	if (DRMProcess == NULL)
		return OB_PREOP_SUCCESS;

	if (PsGetCurrentProcess() == DRMProcess)
		return OB_PREOP_SUCCESS;

	if (OperationInformation->ObjectType == *PsThreadType)
	{
		if ((PsGetProcessId(DRMProcess) == PsGetThreadProcessId(OperationInformation->Object)) || ((DRMProcess2) && (PsGetProcessId(DRMProcess2) == PsGetThreadProcessId(OperationInformation->Object))))
		{

			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			{

				ACCESS_MASK da = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

				DbgPrint("PID %d opened a handle to the a CE thread with access mask %x", PsGetCurrentProcessId(), da);

				da = da & (THREAD_SET_LIMITED_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION);

				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
			}
			else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{

				ACCESS_MASK da = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;

				DbgPrint("PID %d duplicated a handle to a CE thread with access mask %x", PsGetCurrentProcessId(), da);

				da = da & (THREAD_SET_LIMITED_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION);
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}

VOID ThreadPostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{

}

OB_PREOP_CALLBACK_STATUS ProcessPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	if (DRMProcess == NULL)
		return OB_PREOP_SUCCESS;

	if (OperationInformation->ObjectType == *PsProcessType)
	{
		if ((OperationInformation->Object == DRMProcess) || (OperationInformation->Object == DRMProcess2))
		{

			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			{

				ACCESS_MASK da = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

				DbgPrint("PID %d(%p) opened a handle to the CE process(%p) with access mask %x", PsGetCurrentProcessId(), PsGetCurrentProcess(), DRMProcess, da);

				da = da & (PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME);

				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
			}
			else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{

				ACCESS_MASK da = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;

				DbgPrint("PID %d(%p) opened a handle to the CE process(%p) with access mask %x", PsGetCurrentProcessId(), PsGetCurrentProcess(), DRMProcess, da);

				da = da & (PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME);

				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}

VOID ProcessPostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{

}
#endif

BOOL DispatchIoctlDBVM(IN PDEVICE_OBJECT DeviceObject, ULONG IoControlCode, PVOID lpInBuffer, DWORD nInBufferSize, PVOID lpOutBuffer, DWORD nOutBufferSize, PDWORD lpBytesReturned)

{

	IRP FakeIRP;
	BOOL r;
	PVOID buffer;
	buffer=ExAllocatePool(PagedPool, max(nInBufferSize, nOutBufferSize));
	RtlCopyMemory(buffer, lpInBuffer, nInBufferSize);

	DbgPrint("DispatchIoctlDBVM\n");

	FakeIRP.AssociatedIrp.SystemBuffer=buffer;
	FakeIRP.Flags=IoControlCode;

	r=DispatchIoctl(DeviceObject, &FakeIRP)==STATUS_SUCCESS;

	RtlCopyMemory(lpOutBuffer, buffer, nOutBufferSize);

	ExFreePool(buffer);

	return r;
}

NTSTATUS DispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS ntStatus=STATUS_UNSUCCESSFUL;

    PIO_STACK_LOCATION     irpStack=NULL;
	LUID sedebugprivUID;
	ULONG IoControlCode;

	if (!loadedbydbvm)
	{
		irpStack=IoGetCurrentIrpStackLocation(Irp);
		IoControlCode=irpStack->Parameters.DeviceIoControl.IoControlCode;
	}
	else
		IoControlCode=Irp->Flags;

#ifdef TOBESIGNED
    sedebugprivUID.LowPart=SE_DEBUG_PRIVILEGE;
	sedebugprivUID.HighPart=0;

	if (SeSinglePrivilegeCheck(sedebugprivUID, UserMode)==FALSE)
	{
		DbgPrint("DispatchIoctl called by a process without SeDebugPrivilege");
		return STATUS_UNSUCCESSFUL;
	}
#endif

    __try
    {
        switch(IoControlCode)
        {

        case IOCTL_CE_READMEMORY:
			__try
			{
				struct input
				{
					UINT64 processid;
					UINT64 startaddress;
					WORD bytestoread;
				} *pinp;

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
				ULONG outLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
				if (inLen < sizeof(struct input) || outLen < sizeof(struct input))
				{
					ntStatus = STATUS_INFO_LENGTH_MISMATCH;
					break;
				}

				pinp=Irp->AssociatedIrp.SystemBuffer;

				ntStatus=ReadProcessMemory((DWORD)pinp->processid,NULL,(PVOID)(UINT_PTR)pinp->startaddress,pinp->bytestoread,pinp) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				ntStatus = STATUS_UNSUCCESSFUL;
			};

            break;

        case IOCTL_CE_WRITEMEMORY:
			__try
			{
				struct input
				{
					UINT64 processid;
					UINT64 startaddress;
					WORD bytestowrite;
				} *pinp,inp;

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
				if (inLen < sizeof(inp))
				{
					ntStatus = STATUS_INFO_LENGTH_MISMATCH;
					break;
				}

				pinp=Irp->AssociatedIrp.SystemBuffer;
				if (inLen < (sizeof(inp) + pinp->bytestowrite))
				{
					ntStatus = STATUS_BUFFER_TOO_SMALL;
					break;
				}

				ntStatus=WriteProcessMemory((DWORD)pinp->processid,NULL,(PVOID)(UINT_PTR)pinp->startaddress,pinp->bytestowrite,(PVOID)((UINT_PTR)pinp+sizeof(inp))) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				ntStatus = STATUS_UNSUCCESSFUL;
			};

            break;

		case IOCTL_CE_OPENPROCESS:
			{
				PEPROCESS selectedprocess = NULL;
				struct out
				{
					UINT64 h;
					BYTE   Special;
				} *POutput = Irp->AssociatedIrp.SystemBuffer;

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
				ULONG outLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
				if (inLen < sizeof(ULONG) || outLen < sizeof(struct out))
				{
					ntStatus = STATUS_INFO_LENGTH_MISMATCH;
					break;
				}

				ULONG processid=*(PULONG)Irp->AssociatedIrp.SystemBuffer;
				HANDLE ProcessHandle = 0;

				ntStatus = STATUS_SUCCESS;
				if (ProcessHandle == 0)
				{
					POutput->Special = 0;
					__try
					{
						ProcessHandle = 0;

						if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(processid), &selectedprocess) == STATUS_SUCCESS)
						{

							ULONG strippedCount = StripProcessCallbacks(FALSE);

							ntStatus = ObOpenObjectByPointer(
								selectedprocess,
								0,
								NULL,
								PROCESS_ALL_ACCESS,
								*PsProcessType,
								KernelMode,
								&ProcessHandle);

							if (strippedCount > 0)
							{
								StripProcessCallbacks(TRUE);
							}
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						ntStatus = STATUS_UNSUCCESSFUL;
					}
				}
				else
				{
					POutput->Special = 1;
				}

				if (selectedprocess)
				{
					ObDereferenceObject(selectedprocess);
				}

				POutput->h=(UINT64)ProcessHandle;
				break;
			}

		case IOCTL_CE_OPENTHREAD:
			{
				HANDLE ThreadHandle;
				CLIENT_ID ClientID;
				OBJECT_ATTRIBUTES ObjectAttributes;

				RtlZeroMemory(&ObjectAttributes,sizeof(OBJECT_ATTRIBUTES));

				ntStatus=STATUS_SUCCESS;

				ClientID.UniqueProcess=0;
				ClientID.UniqueThread=(HANDLE)(UINT_PTR)*(PULONG)Irp->AssociatedIrp.SystemBuffer;
				ThreadHandle=0;

				__try
				{
					ThreadHandle=0;
					ntStatus=ZwOpenThread(&ThreadHandle,PROCESS_ALL_ACCESS,&ObjectAttributes,&ClientID);
				}
				__except(1)
				{
					ntStatus=STATUS_UNSUCCESSFUL;
				}

				*(PUINT64)Irp->AssociatedIrp.SystemBuffer=(UINT64)ThreadHandle;

				break;
			}

		case IOCTL_CE_MAKEWRITABLE:
			{
#ifdef AMD64

#else
				struct InputBuf
				{
				    UINT64 StartAddress;
					ULONG Size;
					BYTE CopyOnWrite;
				} *PInputBuf;

				PInputBuf=Irp->AssociatedIrp.SystemBuffer;

				ntStatus=MakeWritable((PVOID)(UINT_PTR)PInputBuf->StartAddress,PInputBuf->Size,(PInputBuf->CopyOnWrite==1)) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
#endif
				break;
			}

		case IOCTL_CE_QUERY_VIRTUAL_MEMORY:
			{
				struct InputBuf
				{
				    UINT64 ProcessID;
					UINT64 StartAddress;
				} *PInputBuf = (struct InputBuf*)Irp->AssociatedIrp.SystemBuffer;

				PEPROCESS selectedprocess = NULL;
				ULONG outLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
				MEMORY_BASIC_INFORMATION64 mbi;
				RtlZeroMemory(&mbi, sizeof(mbi));

				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)PInputBuf->ProcessID, &selectedprocess)))
				{
					ntStatus = QueryProcessMemoryVad(selectedprocess, PInputBuf->StartAddress, &mbi);
					ObDereferenceObject(selectedprocess);

					if (NT_SUCCESS(ntStatus))
					{
						if (outLen >= sizeof(MEMORY_BASIC_INFORMATION64))
						{
							RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &mbi, sizeof(MEMORY_BASIC_INFORMATION64));
						}
						else if (outLen >= 16)
						{
							struct OutputBuf
							{
								UINT64 length;
								DWORD protection;
							} *POutputBuf = (struct OutputBuf*)Irp->AssociatedIrp.SystemBuffer;

							POutputBuf->length = mbi.RegionSize;
							POutputBuf->protection = mbi.Protect;
						}
					}
				}
				else
				{
					ntStatus = STATUS_NOT_FOUND;
				}
				break;
			}

		case IOCTL_CE_TEST:
			{
				UNICODE_STRING test;
				PVOID x;
				QWORD a, b;

				_disable();
				a = __rdtsc();
				b = __rdtsc();

				_enable();

				DbgPrint("%d\n", (int)(b - a));
				break;
			}

		case IOCTL_CE_GETPETHREAD:
			{

				*(PUINT64)Irp->AssociatedIrp.SystemBuffer=(UINT64)getPEThread((UINT_PTR)*(PULONG)Irp->AssociatedIrp.SystemBuffer);
				ntStatus= STATUS_SUCCESS;
				break;
			}

		case IOCTL_CE_GETPEPROCESS:
			{
				DWORD processid=*(PDWORD)Irp->AssociatedIrp.SystemBuffer;
				PEPROCESS selectedprocess;

				if (processid==0)
				{
					ntStatus=STATUS_UNSUCCESSFUL;
				}
				else
				{
					if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(processid),&selectedprocess)==STATUS_SUCCESS)
					{
#ifdef AMD64
						*(PUINT64)Irp->AssociatedIrp.SystemBuffer=(UINT64)selectedprocess;
#else
						*(PUINT64)Irp->AssociatedIrp.SystemBuffer=(DWORD)selectedprocess;
#endif

						ObDereferenceObject(selectedprocess);

					}
					else
						*(PUINT64)Irp->AssociatedIrp.SystemBuffer=0;
				}

				ntStatus= STATUS_SUCCESS;
				break;
			}

		case IOCTL_CE_READPHYSICALMEMORY:
			{
				struct input
				{
					UINT64 startaddress;
					UINT64 bytestoread;
				} *pinp;
				pinp=Irp->AssociatedIrp.SystemBuffer;

				DbgPrint("IOCTL_CE_READPHYSICALMEMORY:pinp->startaddress=%x, pinp->bytestoread=%d", pinp->startaddress, pinp->bytestoread);

				ntStatus = ReadPhysicalMemory((PVOID)(UINT_PTR)pinp->startaddress, (UINT_PTR)pinp->bytestoread, pinp);
				break;

			}

		case IOCTL_CE_WRITEPHYSICALMEMORY:
			{
				HANDLE			physmem;
				UNICODE_STRING	physmemString;
				OBJECT_ATTRIBUTES attributes;
				WCHAR			physmemName[] = L"\\device\\physicalmemory";
				UCHAR*			memoryview;

				RtlInitUnicodeString( &physmemString, physmemName );

            	InitializeObjectAttributes( &attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL );
			    ntStatus=ZwOpenSection( &physmem, SECTION_ALL_ACCESS, &attributes );
				if (ntStatus==STATUS_SUCCESS)
				{

					struct input
					{
						UINT64 startaddress;
						UINT64 bytestoread;
					} *pinp;

					UCHAR* pinp2;

					SIZE_T length;
					PHYSICAL_ADDRESS	viewBase;
					UINT_PTR offset;
					UINT_PTR toread;

					pinp=Irp->AssociatedIrp.SystemBuffer;
					pinp2=(UCHAR *)pinp;
					viewBase.QuadPart = (ULONGLONG)(pinp->startaddress);

					length=0x2000;
					toread=(UINT_PTR)pinp->bytestoread;

					memoryview=NULL;
					ntStatus=ZwMapViewOfSection(
						physmem,
						NtCurrentProcess(),
						&memoryview,
						0L,
						length,
						&viewBase,
						&length,
						ViewShare,
						0,
						PAGE_READWRITE);

					if (ntStatus==STATUS_SUCCESS)
					{
                        offset=(UINT_PTR)(pinp->startaddress)-(UINT_PTR)viewBase.QuadPart;
						RtlCopyMemory(&memoryview[offset],&pinp2[16],toread);

						ZwUnmapViewOfSection(
							NtCurrentProcess(),
							memoryview);
					}

					ZwClose(physmem);
				}

				break;
			}

		case IOCTL_CE_GETPHYSICALADDRESS:
			{
				struct input
				{
					UINT64  ProcessID;
					UINT64 BaseAddress;
				} *pinp;

				PEPROCESS selectedprocess;
				PHYSICAL_ADDRESS physical;
				physical.QuadPart = 0;

				ntStatus=STATUS_SUCCESS;
				pinp=Irp->AssociatedIrp.SystemBuffer;

				__try
				{

					if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(pinp->ProcessID),&selectedprocess)==STATUS_SUCCESS)
					{
						KAPC_STATE apc_state;
						RtlZeroMemory(&apc_state,sizeof(apc_state));
    					KeStackAttachProcess((PVOID)selectedprocess,&apc_state);

						__try
						{
							physical=MmGetPhysicalAddress((PVOID)(UINT_PTR)pinp->BaseAddress);
						}
						__finally
						{
							KeUnstackDetachProcess(&apc_state);
						}

						ObDereferenceObject(selectedprocess);

					}
				}
				__except(1)
				{
						ntStatus=STATUS_UNSUCCESSFUL;
				}

				if (ntStatus==STATUS_SUCCESS)
				{

                    RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,&physical.QuadPart,8);

				}

				break;
			}

		case IOCTL_CE_GETMEMORYRANGES:
			{

				struct output
				{
					UINT64 address;
					UINT64 size;
				} *poutp=Irp->AssociatedIrp.SystemBuffer;

				DbgPrint("IOCTL_CE_GETMEMORYRANGES\n");

				if (PhysicalMemoryRanges==0)
				{
					__try
					{
						PPHYSICAL_MEMORY_RANGE mr=MmGetPhysicalMemoryRanges();

						if (mr)
						{

							int i;
							PhysicalMemoryRanges=(UINT64)mr;
							for (i=0; mr[i].NumberOfBytes.QuadPart || mr[i].BaseAddress.QuadPart; i++);

							PhysicalMemoryRangesListSize=(UINT64)(&mr[i])-(UINT64)(&mr[0]);
						}

					}
					__except(1)
					{

					}
				}

				poutp->address=PhysicalMemoryRanges;
				poutp->size=PhysicalMemoryRangesListSize;

				ntStatus=STATUS_SUCCESS;

				break;
			}

		case IOCTL_CE_GETSDTADDRESS:
			{
				DbgPrint("Obsolete\n");
				ntStatus=STATUS_UNSUCCESSFUL;
				break;
			}

		case IOCTL_CE_GETCR0:
			{
				*(UINT64*)Irp->AssociatedIrp.SystemBuffer=getCR0();
				ntStatus=STATUS_SUCCESS;

				break;
			}

		case IOCTL_CE_GETCR4:
			{

				*(UINT64*)Irp->AssociatedIrp.SystemBuffer=(UINT64)getCR4();
				ntStatus=STATUS_SUCCESS;

				break;
			}

		case IOCTL_CE_SETCR4:
			{

				ULONG cr4reg=*(ULONG*)Irp->AssociatedIrp.SystemBuffer;
				setCR4((UINT64)cr4reg);
				ntStatus=STATUS_SUCCESS;
				break;
			}

				case IOCTL_CE_GETCR3:
			{
				UINT_PTR cr3reg = 0;
				PEPROCESS selectedprocess = NULL;
				ULONG pid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;

				ntStatus = STATUS_SUCCESS;

				if (pid != 0 && NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &selectedprocess)))
				{
					cr3reg = (UINT_PTR)GetProcessCR3(selectedprocess);
					ObDereferenceObject(selectedprocess);
				}
				else
				{
					cr3reg = (UINT_PTR)getCR3();
				}

				*(PUINT64)Irp->AssociatedIrp.SystemBuffer = (UINT64)cr3reg;
				break;
			}

		case IOCTL_CE_GET_BASE:
			{
				ULONG pid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
				PEPROCESS selectedprocess = NULL;
				UINT_PTR baseAddr = 0;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &selectedprocess)))
				{
					baseAddr = (UINT_PTR)PsGetProcessSectionBaseAddress(selectedprocess);
					ObDereferenceObject(selectedprocess);
					ntStatus = STATUS_SUCCESS;
				}
				else
				{
					ntStatus = STATUS_NOT_FOUND;
				}
				*(PUINT64)Irp->AssociatedIrp.SystemBuffer = (UINT64)baseAddr;
				break;
			}

		case IOCTL_CE_HIDEDRIVER:
			{
				HideDriverFromLoadedModuleList(DeviceObject->DriverObject);
				ntStatus = STATUS_SUCCESS;
				break;
			}

		case IOCTL_CE_HIDE_PROCESS:
			{
				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
				if (inLen < sizeof(ULONG))
				{
					ntStatus = STATUS_INFO_LENGTH_MISMATCH;
					break;
				}
				ULONG targetPid = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
				ntStatus = HideProcessByPid(targetPid);
				break;
			}

		case IOCTL_CE_ENUM_VAD_MODULES:
			{
				ULONG pid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
				PEPROCESS selectedprocess = NULL;
				ULONG outBufferSize = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

				if (outBufferSize >= sizeof(VAD_ENUM_OUTPUT))
				{
					PVAD_ENUM_OUTPUT out = (PVAD_ENUM_OUTPUT)Irp->AssociatedIrp.SystemBuffer;
					ULONG maxModules = (outBufferSize - FIELD_OFFSET(VAD_ENUM_OUTPUT, Modules)) / sizeof(VAD_MODULE_ENTRY);
					ULONG count = 0;

					if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &selectedprocess)))
					{
						ntStatus = EnumerateProcessVadModules(selectedprocess, out->Modules, maxModules, &count);
						out->Count = count;
						ObDereferenceObject(selectedprocess);
					}
					else
					{
						ntStatus = STATUS_NOT_FOUND;
					}
				}
				else
				{
					ntStatus = STATUS_BUFFER_TOO_SMALL;
				}
				break;
			}

		case IOCTL_CE_TRANSLATE_CR3:
			{
#pragma pack(1)
				struct in_trans
				{
					ULONG ProcessId;
					ULONG64 VirtualAddress;
				} *pinp = (struct in_trans*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack()

				PEPROCESS selectedprocess = NULL;
				ULONG64 physAddr = 0;

				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pinp->ProcessId, &selectedprocess)))
				{
					physAddr = TranslateVirtualToPhysicalCR3(selectedprocess, pinp->VirtualAddress);
					ObDereferenceObject(selectedprocess);
					ntStatus = (physAddr != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
				}
				else
				{
					ntStatus = STATUS_NOT_FOUND;
				}

				*(PUINT64)Irp->AssociatedIrp.SystemBuffer = (UINT64)physAddr;
				break;
			}

		case IOCTL_CE_CLOAK_PAGE:
			{
#pragma pack(1)
				struct in_cloak
				{
					ULONG ProcessId;
					ULONG64 VirtualAddress;
				} *pinp = (struct in_cloak*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack()

				PEPROCESS selectedprocess = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pinp->ProcessId, &selectedprocess)))
				{
					ntStatus = CloakProcessPage(selectedprocess, pinp->VirtualAddress);
					ObDereferenceObject(selectedprocess);
				}
				else
				{
					ntStatus = STATUS_NOT_FOUND;
				}
				break;
			}

		case IOCTL_CE_STEALTH_READ_PTE:
			{
#pragma pack(push, 1)
				struct in_stealth_read
				{
					ULONG64 ProcessId;
					ULONG64 VirtualAddress;
					ULONG Size;
				} *pinp = (struct in_stealth_read*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack(pop)

				ULONG outBufferSize = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
				ULONG inBufferSize = irpStack->Parameters.DeviceIoControl.InputBufferLength;

				if (!pinp || inBufferSize < sizeof(struct in_stealth_read) || outBufferSize == 0)
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				ULONG64 pid = pinp->ProcessId;
				ULONG64 va = pinp->VirtualAddress;
				ULONG readSize = pinp->Size;
				if (readSize > outBufferSize)
					readSize = outBufferSize;

				PEPROCESS selectedprocess = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &selectedprocess)))
				{
					SIZE_T bytesRead = 0;
					if (StealthReadProcessMemoryPTE(selectedprocess, va, Irp->AssociatedIrp.SystemBuffer, (SIZE_T)readSize, &bytesRead))
					{
						ntStatus = STATUS_SUCCESS;
					}
					else
					{
						ntStatus = STATUS_UNSUCCESSFUL;
					}
					ObDereferenceObject(selectedprocess);
				}
				else
				{
					ntStatus = STATUS_NOT_FOUND;
				}
				break;
			}

		case IOCTL_CE_UNCLOAK_PAGE:
			{
#pragma pack(1)
				struct in_cloak
				{
					ULONG ProcessId;
					ULONG64 VirtualAddress;
				} *pinp = (struct in_cloak*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack()

				PEPROCESS selectedprocess = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pinp->ProcessId, &selectedprocess)))
				{
					ntStatus = UncloakProcessPage(selectedprocess, pinp->VirtualAddress);
					ObDereferenceObject(selectedprocess);
				}
				else
				{
					ntStatus = STATUS_NOT_FOUND;
				}
				break;
			}

		case IOCTL_CE_WRITE_CLOAKED:
			{
#pragma pack(1)
				struct in_write_cloaked
				{
					ULONG ProcessId;
					ULONG64 VirtualAddress;
					ULONG Size;
					UCHAR Data[1];
				} *pinp = (struct in_write_cloaked*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack()

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
				if (inLen >= sizeof(struct in_write_cloaked) && inLen >= (sizeof(struct in_write_cloaked) - 1 + pinp->Size))
				{
					PEPROCESS selectedprocess = NULL;
					if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pinp->ProcessId, &selectedprocess)))
					{
						ntStatus = WriteCloakedPageMemory(selectedprocess, pinp->VirtualAddress, pinp->Data, pinp->Size);
						ObDereferenceObject(selectedprocess);
					}
					else
					{
						ntStatus = STATUS_NOT_FOUND;
					}
				}
				else
				{
					ntStatus = STATUS_INVALID_BUFFER_SIZE;
				}
				break;
			}

		case IOCTL_CE_BULK_DUMP_CR3:
			{
#pragma pack(push, 1)
				struct in_bulk_dump
				{
					ULONG64 ProcessId;
					ULONG64 BaseAddress;
					ULONG Size;
				} *pinp = (struct in_bulk_dump*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack(pop)

				ULONG outBufferSize = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
				ULONG inBufferSize = irpStack->Parameters.DeviceIoControl.InputBufferLength;

				if (!pinp || inBufferSize < sizeof(struct in_bulk_dump) || outBufferSize == 0)
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				ULONG64 pid = pinp->ProcessId;
				ULONG64 baseAddr = pinp->BaseAddress;
				ULONG dumpSize = pinp->Size;
				if (dumpSize > outBufferSize)
					dumpSize = outBufferSize;

				PEPROCESS selectedprocess = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &selectedprocess)))
				{
					SIZE_T bytesDumped = 0;
					if (BulkDumpProcessMemoryPhysicalCR3(selectedprocess, baseAddr, Irp->AssociatedIrp.SystemBuffer, (SIZE_T)dumpSize, &bytesDumped))
					{
						ntStatus = STATUS_SUCCESS;
					}
					else
					{
						ntStatus = STATUS_UNSUCCESSFUL;
					}
					ObDereferenceObject(selectedprocess);
				}
				else
				{
					ntStatus = STATUS_NOT_FOUND;
				}
				break;
			}

		case IOCTL_CE_STRIP_CALLBACKS:
			{
#pragma pack(push, 1)
				struct in_strip
				{
					ULONG Restore;
				} *pinp = (struct in_strip*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack(pop)

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
				ULONG outLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

				if (!pinp || inLen < sizeof(struct in_strip) || outLen < sizeof(ULONG))
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				BOOLEAN bRestore = (pinp->Restore != 0);
				ULONG affected = StripProcessCallbacks(bRestore);

				*(PULONG)Irp->AssociatedIrp.SystemBuffer = affected;
				ntStatus = STATUS_SUCCESS;
				break;
			}

		case IOCTL_CE_PATTERN_SCAN:
			{
#pragma pack(push, 1)
				struct in_scan
				{
					ULONG64 ProcessId;
					ULONG64 StartAddress;
					ULONG64 ScanSize;
					ULONG PatternLength;
					UCHAR Pattern[64];
					UCHAR Mask[64];
				} *pinp = (struct in_scan*)Irp->AssociatedIrp.SystemBuffer;

				struct out_scan
				{
					ULONG MatchCount;
					ULONG64 Matches[32];
				} *pout = (struct out_scan*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack(pop)

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
				ULONG outLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

				if (!pinp || inLen < sizeof(struct in_scan) || outLen < sizeof(struct out_scan))
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				ULONG64 pid = pinp->ProcessId;
				ULONG64 startVa = pinp->StartAddress;
				ULONG64 scanSize = pinp->ScanSize;
				ULONG patternLen = pinp->PatternLength;
				UCHAR localPattern[64];
				UCHAR localMask[64];

				if (patternLen > 64)
					patternLen = 64;

				RtlCopyMemory(localPattern, pinp->Pattern, patternLen);
				RtlCopyMemory(localMask, pinp->Mask, patternLen);

				PEPROCESS selectedprocess = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &selectedprocess)))
				{
					ULONG64 matches[32];
					RtlZeroMemory(matches, sizeof(matches));

					ULONG foundCount = PatternScanProcessCR3(
						selectedprocess,
						startVa,
						scanSize,
						localPattern,
						localMask,
						patternLen,
						matches,
						32
					);

					pout->MatchCount = foundCount;
					RtlCopyMemory(pout->Matches, matches, sizeof(matches));

					ObDereferenceObject(selectedprocess);
					ntStatus = STATUS_SUCCESS;
				}
				else
				{
					ntStatus = STATUS_NOT_FOUND;
				}
				break;
			}

		case IOCTL_CE_FREEZE_PROCESS:
			{
#pragma pack(push, 1)
				struct in_freeze
				{
					ULONG64 ProcessId;
					ULONG Freeze;
				} *pinp = (struct in_freeze*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack(pop)

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;

				if (!pinp || inLen < sizeof(struct in_freeze))
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				ULONG64 pid = pinp->ProcessId;
				BOOLEAN bFreeze = (pinp->Freeze != 0);

				PEPROCESS selectedprocess = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &selectedprocess)))
				{
					ntStatus = FreezeProcess(selectedprocess, bFreeze);
					ObDereferenceObject(selectedprocess);
				}
				else
				{
					ntStatus = STATUS_NOT_FOUND;
				}
				break;
			}

		case IOCTL_CE_SET_PROCESS_PROTECTION:
			{
#pragma pack(push, 1)
				struct in_protect
				{
					ULONG64 ProcessId;
					ULONG Enable;
				} *pinp = (struct in_protect*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack(pop)

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;

				if (!pinp || inLen < sizeof(struct in_protect))
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				ULONG64 pid = pinp->ProcessId;
				BOOLEAN bEnable = (pinp->Enable != 0);

				PEPROCESS selectedprocess = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pid, &selectedprocess)))
				{
					ntStatus = SetProcessProtection(selectedprocess, bEnable);
					ObDereferenceObject(selectedprocess);
				}
				else
				{
					ntStatus = STATUS_NOT_FOUND;
				}
				break;
			}

		case IOCTL_CE_CLEAN_KERNEL_TRACES:
			{
				ntStatus = CleanKernelTraces();
				break;
			}

		case IOCTL_CE_CLOAK_DEVICE_SYMLINK:
			{
				PCWSTR newName = (PCWSTR)Irp->AssociatedIrp.SystemBuffer;
				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;

				if (!newName || inLen < sizeof(WCHAR) * 2 || inLen > 256)
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				PWCHAR safeBuf = (PWCHAR)ExAllocatePoolWithTag(DBK_POOL_NX, inLen + sizeof(WCHAR), 'kOLS');
				if (!safeBuf)
				{
					ntStatus = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				RtlCopyMemory(safeBuf, newName, inLen);
				safeBuf[inLen / sizeof(WCHAR)] = L'\0';

				ntStatus = CloakDeviceSymlink(safeBuf);
				ExFreePoolWithTag(safeBuf, 'kOLS');
				break;
			}

		case IOCTL_CE_PHYSICAL_RAM_SCAVENGE:
			{
#pragma pack(push, 1)
				struct in_scavenge
				{
					ULONG64 StartPhysAddr;
					ULONG64 MaxBytesToScan;
					ULONG PatternLength;
					UCHAR Pattern[64];
					UCHAR Mask[64];
				} *pinp = (struct in_scavenge*)Irp->AssociatedIrp.SystemBuffer;

				struct out_scavenge
				{
					ULONG MatchCount;
					ULONG64 NextPhysAddr;
					ULONG64 Matches[32];
				} *pout = (struct out_scavenge*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack(pop)

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
				ULONG outLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

				if (!pinp || inLen < sizeof(struct in_scavenge) || outLen < sizeof(struct out_scavenge))
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				if (pinp->PatternLength == 0 || pinp->PatternLength > 64)
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				ULONG64 startPhys = pinp->StartPhysAddr;
				ULONG64 maxBytes = pinp->MaxBytesToScan;
				ULONG patLen = pinp->PatternLength;
				UCHAR pat[64], mask[64];
				RtlCopyMemory(pat, pinp->Pattern, patLen);
				RtlCopyMemory(mask, pinp->Mask, patLen);

				ULONG64 matches[32];
				ULONG64 nextPhys = 0;
				RtlZeroMemory(matches, sizeof(matches));

				ULONG count = PhysicalRamScavenge(startPhys, maxBytes, pat, mask, patLen, matches, 32, &nextPhys);

				RtlZeroMemory(pout, sizeof(struct out_scavenge));
				pout->MatchCount = count;
				pout->NextPhysAddr = nextPhys;
				RtlCopyMemory(pout->Matches, matches, sizeof(ULONG64) * count);

				ntStatus = STATUS_SUCCESS;
				break;
			}

		case IOCTL_CE_GET_DBVM_STATUS:
			{
#pragma pack(push, 1)
				struct out_dbvm_status
				{
					ULONG IsActive;
					ULONG Version;
				} *pout = (struct out_dbvm_status*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack(pop)

				ULONG outLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
				if (!pout || outLen < sizeof(struct out_dbvm_status))
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				pout->IsActive = vmxusable ? 1 : 0;
				pout->Version = vmx_version;
				ntStatus = STATUS_SUCCESS;
				break;
			}

		case IOCTL_CE_CLOAK_REGION:
			{
#pragma pack(push, 1)
				struct in_cloak_region
				{
					ULONG64 ProcessId;
					ULONG64 VirtualAddress;
					ULONG Size;
					UCHAR Data[1];
				} *pinp = (struct in_cloak_region*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack(pop)

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
				ULONG headerSize = FIELD_OFFSET(struct in_cloak_region, Data);

				if (!pinp || inLen < headerSize || inLen < (headerSize + pinp->Size))
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				if (!vmxusable)
				{
					ntStatus = STATUS_NOT_SUPPORTED;
					break;
				}

				PEPROCESS selectedprocess = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pinp->ProcessId, &selectedprocess)))
				{
					ntStatus = CloakRegionMemory(selectedprocess, pinp->VirtualAddress, pinp->Data, pinp->Size);
					ObDereferenceObject(selectedprocess);
				}
				else
				{
					ntStatus = STATUS_NOT_FOUND;
				}
				break;
			}

		case IOCTL_CE_START_DBVM_WATCH:
			{
#pragma pack(push, 1)
				struct in_start_watch
				{
					ULONG64 ProcessId;
					ULONG64 VirtualAddress;
					ULONG Size;
					ULONG WatchType;
				} *pinp = (struct in_start_watch*)Irp->AssociatedIrp.SystemBuffer;

				struct out_start_watch
				{
					ULONG WatcherId;
					ULONG64 PhysicalAddress;
				} *pout = (struct out_start_watch*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack(pop)

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
				ULONG outLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

				if (!pinp || inLen < sizeof(struct in_start_watch) || outLen < sizeof(struct out_start_watch))
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				if (!vmxusable)
				{
					ntStatus = STATUS_NOT_SUPPORTED;
					break;
				}

				PEPROCESS selectedprocess = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pinp->ProcessId, &selectedprocess)))
				{
					ULONG64 phys = TranslateVirtualToPhysicalCR3(selectedprocess, pinp->VirtualAddress);
					ObDereferenceObject(selectedprocess);

					if (!phys || !IsPhysicalAddressSafe(phys, pinp->Size))
					{
						ntStatus = STATUS_NOT_FOUND;
						break;
					}

					unsigned int watchId = 0xFFFFFFFF;
					if (pinp->WatchType == 0)
					{
						watchId = vmx_watch_pagewrites(phys, pinp->Size, 0, 1024);
					}
					else
					{
						watchId = vmx_watch_pageaccess(phys, pinp->Size, 0, 1024);
					}

					if (watchId != 0xFFFFFFFF)
					{
						pout->WatcherId = watchId;
						pout->PhysicalAddress = phys;
						ntStatus = STATUS_SUCCESS;
					}
					else
					{
						ntStatus = STATUS_UNSUCCESSFUL;
					}
				}
				else
				{
					ntStatus = STATUS_NOT_FOUND;
				}
				break;
			}

		case IOCTL_CE_STOP_DBVM_WATCH:
			{
				if (!vmxusable)
				{
					ntStatus = STATUS_NOT_SUPPORTED;
					break;
				}

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
				if (inLen < sizeof(ULONG))
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				ULONG watchId = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
				vmx_watch_delete(watchId);
				ntStatus = STATUS_SUCCESS;
				break;
			}

		case IOCTL_CE_POLL_DBVM_WATCH:
			{
				if (!vmxusable)
				{
					ntStatus = STATUS_NOT_SUPPORTED;
					break;
				}

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
				ULONG outLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

				if (inLen < sizeof(ULONG) || outLen < sizeof(PageEventListDescriptor))
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				ULONG watchId = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
				PPageEventListDescriptor pList = (PPageEventListDescriptor)Irp->AssociatedIrp.SystemBuffer;
				int bufSize = (int)outLen;

				unsigned int r = vmx_watch_retreivelog(watchId, pList, &bufSize);
				if (r == 0)
				{
					ntStatus = STATUS_SUCCESS;
				}
				else
				{
					ntStatus = STATUS_BUFFER_TOO_SMALL;
				}
				break;
			}

static PVOID g_TraceStoreBuffer = NULL;

		case IOCTL_CE_START_HARDWARE_TRACE:
			{
#pragma pack(push, 1)
				struct in_trace
				{
					ULONG64 ProcessId;
				} *pinp = (struct in_trace*)Irp->AssociatedIrp.SystemBuffer;
#pragma pack(pop)

				ULONG inLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
				if (!pinp || inLen < sizeof(struct in_trace))
				{
					ntStatus = STATUS_INVALID_PARAMETER;
					break;
				}

				if (!vmxusable)
				{
					ntStatus = STATUS_NOT_SUPPORTED;
					break;
				}

				PEPROCESS selectedprocess = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT_PTR)pinp->ProcessId, &selectedprocess)))
				{
					ULONG cr3Offset = ResolveDirectoryTableBaseOffset();
					ULONG64 cr3 = *(PULONG64)((PUCHAR)selectedprocess + cr3Offset);
					ObDereferenceObject(selectedprocess);

					if (!cr3)
					{
						ntStatus = STATUS_NOT_FOUND;
						break;
					}

					if (!g_TraceStoreBuffer)
					{

						g_TraceStoreBuffer = ExAllocatePoolWithTag(DBK_POOL_NX, 64 * 1024, 'rtSU');
					}

					if (!g_TraceStoreBuffer)
					{
						ntStatus = STATUS_INSUFFICIENT_RESOURCES;
						break;
					}

					RtlZeroMemory(g_TraceStoreBuffer, 64 * 1024);

					UINT64 debugctl = 0x1 | 0x40;
					unsigned int r = vmx_ultimap(cr3, debugctl, g_TraceStoreBuffer);

					ntStatus = (r == 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
				}
				else
				{
					ntStatus = STATUS_NOT_FOUND;
				}
				break;
			}

		case IOCTL_CE_STOP_HARDWARE_TRACE:
			{
				if (!vmxusable)
				{
					ntStatus = STATUS_NOT_SUPPORTED;
					break;
				}

				vmx_ultimap_disable();

				if (g_TraceStoreBuffer)
				{
					ExFreePoolWithTag(g_TraceStoreBuffer, 'rtSU');
					g_TraceStoreBuffer = NULL;
				}

				ntStatus = STATUS_SUCCESS;
				break;
			}

		case IOCTL_CE_GETSDT:
			{

				ntStatus = STATUS_UNSUCCESSFUL;
				break;
			}

		case IOCTL_CE_GETIDT:
			{

				IDT idt;
				RtlZeroMemory(&idt,sizeof(IDT));
				GetIDT(&idt);
				RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer,2+8);
				RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,&idt,sizeof(IDT));
				ntStatus=STATUS_SUCCESS;

				break;
			}

		case IOCTL_CE_GETGDT:
			{

				GDT gdt;
				RtlZeroMemory(&gdt,sizeof(GDT));
				GetGDT(&gdt);
				RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer,2+8);
				RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,&gdt,sizeof(GDT));
				ntStatus=STATUS_SUCCESS;

				break;
			}

		case IOCTL_CE_LAUNCHDBVM:
			{
				struct intput
				{
					UINT64 dbvmimgpath;
					DWORD32 cpuid;
				} *pinp;
				pinp=Irp->AssociatedIrp.SystemBuffer;
				DbgPrint("IOCTL_CE_LAUNCHDBVM\n");

				initializeDBVM((PCWSTR)(UINT_PTR)pinp->dbvmimgpath);

				if (pinp->cpuid == 0xffffffff) {
					forEachCpu(vmxoffload_dpc, NULL, NULL, NULL, vmxoffload_override);
					cleanupDBVM();
				}
				else
					forOneCpu((CCHAR)pinp->cpuid, vmxoffload_dpc, NULL, NULL, NULL, vmxoffload_override);

				DbgPrint("Returned from vmxoffload()\n");
				break;
			}

		case IOCTL_CE_HOOKINTS:
		case IOCTL_CE_USERDEFINEDINTERRUPTHOOK:
		case IOCTL_CE_UNHOOKALLINTERRUPTS:
		case IOCTL_CE_SETGLOBALDEBUGSTATE:
		case IOCTL_CE_DEBUGPROCESS:
		case IOCTL_CE_STOPDEBUGGING:
			ntStatus = STATUS_NOT_SUPPORTED;
			break;

		case IOCTL_CE_SETKERNELSTEPABILITY:
			{
				struct input
				{
					int state;

				} *inp=Irp->AssociatedIrp.SystemBuffer;
				KernelCodeStepping=inp->state;
				ntStatus=STATUS_SUCCESS;
				break;
			}

		case IOCTL_CE_WRITESIGNOREWP:
		{
			KernelWritesIgnoreWP = *(BYTE*)Irp->AssociatedIrp.SystemBuffer;
			ntStatus = STATUS_SUCCESS;
			break;
		}

		case IOCTL_CE_GD_SETBREAKPOINT:
		case IOCTL_CE_TOUCHDEBUGREGISTER:
		case IOCTL_CE_SETSTORELBR:
			ntStatus = STATUS_NOT_SUPPORTED;
			break;

		case IOCTL_CE_EXECUTE_CODE:
			{
				typedef NTSTATUS (*PARAMETERLESSFUNCTION)(UINT64 parameters);
				PARAMETERLESSFUNCTION functiontocall;

				struct input
				{
					UINT64	functionaddress;
					UINT64	parameters;
				} *inp=Irp->AssociatedIrp.SystemBuffer;
				DbgPrint("IOCTL_CE_EXECUTE_CODE\n");

				functiontocall=(PARAMETERLESSFUNCTION)(UINT_PTR)(inp->functionaddress);

				__try
				{
					ntStatus=functiontocall(inp->parameters);
					DbgPrint("Still alive\n");
					ntStatus=STATUS_SUCCESS;
				}
				__except(1)
				{
					DbgPrint("Exception occured\n");
					ntStatus=STATUS_UNSUCCESSFUL;
				}

				break;
			}

		case IOCTL_CE_GETVERSION:
			{
				DbgPrint("IOCTL_CE_GETVERSION. Version=%d\n",dbkversion);
				*(PULONG)Irp->AssociatedIrp.SystemBuffer=dbkversion;
				ntStatus=STATUS_SUCCESS;
				break;
			}

		case IOCTL_CE_READMSR:
			{
				DWORD msr=*(PDWORD)Irp->AssociatedIrp.SystemBuffer;

				__try
				{
					*(PUINT64)Irp->AssociatedIrp.SystemBuffer=__readmsr(msr);

					ntStatus=STATUS_SUCCESS;
				}
				__except(1)
				{
					ntStatus=STATUS_UNSUCCESSFUL;
				}

				break;
			}

		case IOCTL_CE_WRITEMSR:
			{
				struct input
				{
					UINT64 msr;
					UINT64 value;
				} *inp=Irp->AssociatedIrp.SystemBuffer;

				DbgPrint("IOCTL_CE_WRITEMSR:\n");
				DbgPrint("msr=%llx\n", inp->msr);
				DbgPrint("value=%llx\n", inp->value);

				__try
				{
					__writemsr(inp->msr, inp->value );
					ntStatus=STATUS_SUCCESS;
				}
				__except(1)
				{
					DbgPrint("Error while writing value\n");
					ntStatus=STATUS_UNSUCCESSFUL;
				}
				break;
			}

		case IOCTL_CE_ULTIMAP2:
		case IOCTL_CE_ULTIMAP2_WAITFORDATA:
		case IOCTL_CE_ULTIMAP2_LOCKFILE:
		case IOCTL_CE_ULTIMAP2_RELEASEFILE:
		case IOCTL_CE_ULTIMAP2_GETTRACESIZE:
		case IOCTL_CE_ULTIMAP2_RESETTRACESIZE:
		case IOCTL_CE_ULTIMAP2_CONTINUE:
		case IOCTL_CE_ULTIMAP2_FLUSH:
		case IOCTL_CE_ULTIMAP2_PAUSE:
		case IOCTL_CE_ULTIMAP2_RESUME:
		case IOCTL_CE_DISABLEULTIMAP2:
		case IOCTL_CE_ULTIMAP:
		case IOCTL_CE_ULTIMAP_DISABLE:
		case IOCTL_CE_ULTIMAP_WAITFORDATA:
		case IOCTL_CE_ULTIMAP_CONTINUE:
		case IOCTL_CE_ULTIMAP_FLUSH:
		case IOCTL_CE_ULTIMAP_PAUSE:
		case IOCTL_CE_ULTIMAP_RESUME:
			ntStatus = STATUS_NOT_SUPPORTED;
			break;

		case IOCTL_CE_STARTACCESMONITOR:
			{

				struct input
				{
					UINT64 ProcessID;
				} *inp;
				PEPROCESS selectedprocess;

				PVOID BaseAddress;
				SIZE_T RegionSize;

				inp=Irp->AssociatedIrp.SystemBuffer;
				DbgPrint("IOCTL_CE_STARTACCESMONITOR(%d)\n", inp->ProcessID);

				ntStatus = STATUS_UNSUCCESSFUL;

				if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(inp->ProcessID), &selectedprocess) == STATUS_SUCCESS)
				{
					ntStatus = markAllPagesAsNeverAccessed(selectedprocess);
					ObDereferenceObject(selectedprocess);
				}

				break;
			}

		case IOCTL_CE_ENUMACCESSEDMEMORY:
			{
				struct input
				{
					UINT64 ProcessID;
				} *inp;
				PEPROCESS selectedprocess;

				PVOID BaseAddress;
				SIZE_T RegionSize;

				inp = Irp->AssociatedIrp.SystemBuffer;
				DbgPrint("IOCTL_CE_ENUMACCESSEDMEMORY(%d)\n", inp->ProcessID);

				ntStatus = STATUS_UNSUCCESSFUL;

				if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(inp->ProcessID), &selectedprocess) == STATUS_SUCCESS)
				{
					*(int *)Irp->AssociatedIrp.SystemBuffer = enumAllAccessedPages(selectedprocess);
					ObDereferenceObject(selectedprocess);
				}

				ntStatus = STATUS_SUCCESS;
				break;
			}

		case IOCTL_CE_GETACCESSEDMEMORYLIST:
			{
				int ListSizeInBytes = *(int *)Irp->AssociatedIrp.SystemBuffer;
				PPRANGE List = (PPRANGE)Irp->AssociatedIrp.SystemBuffer;

				DbgPrint("IOCTL_CE_GETACCESSEDMEMORYLIST\n");

				getAccessedPageList(List, ListSizeInBytes);

				DbgPrint("return from IOCTL_CE_GETACCESSEDMEMORYLIST\n");
				ntStatus = STATUS_SUCCESS;
				break;
			}

		case IOCTL_CE_INITIALIZE:
			{

				struct input
				{
					UINT64 AddressOfWin32K;
					UINT64 SizeOfWin32K;
					UINT64 NtUserBuildHwndList_callnumber;
					UINT64 NtUserQueryWindow_callnumber;
					UINT64 NtUserFindWindowEx_callnumber;
					UINT64 NtUserGetForegroundWindow_callnumber;
					UINT64 ActiveLinkOffset;
					UINT64 ProcessNameOffset;
					UINT64 DebugportOffset;
					UINT64 ProcessEvent;
					UINT64 ThreadEvent;
  				} *pinp;

				DbgPrint("IOCTL_CE_INITIALIZE\n");
				pinp=Irp->AssociatedIrp.SystemBuffer;
				ntStatus=STATUS_SUCCESS;

				*(UINT_PTR*)Irp->AssociatedIrp.SystemBuffer=(UINT_PTR)0;
				break;
			}

		case IOCTL_CE_VMXCONFIG:
			{
#pragma pack(1)
				struct input
				{
					ULONG Virtualization_Enabled;
					QWORD Password1;
					ULONG Password2;
					QWORD Password3;
  				} *pinp;
#pragma pack()

				DbgPrint("IOCTL_CE_VMXCONFIG called\n");
				ntStatus=STATUS_SUCCESS;

				pinp=Irp->AssociatedIrp.SystemBuffer;

				if (pinp->Virtualization_Enabled)
				{
					vmx_password1=pinp->Password1;
					vmx_password2=pinp->Password2;
					vmx_password3=pinp->Password3;

					DbgPrint("new passwords are: %p-%x-%p\n", (void*)vmx_password1, vmx_password2, (void*)vmx_password3);

					__try
					{
						vmx_version=vmx_getversion();
						DbgPrint("Still here, so vmx is loaded. vmx_version=%x\n",vmx_version);
						vmxusable = 1;
					}
					__except(1)
					{
						DbgPrint("Exception happened. This means no vmx installed, or one of the passwords is wrong\n");
						ntStatus = STATUS_UNSUCCESSFUL;

						vmxusable = 0;
					};
				}
				else
				{
					DbgPrint("Virtualization_Enabled=0\n");
					vmxusable=0;
				}

				break;
			}

		case IOCTL_CE_ENABLE_DRM:
			{
#if (NTDDI_VERSION >= NTDDI_VISTA)
				struct
				{
					QWORD PreferedAltitude;
					QWORD ProtectedProcess;
				} *inp = Irp->AssociatedIrp.SystemBuffer;

				DbgPrint("inp->PreferedAltitude=%p", inp->PreferedAltitude);
				DbgPrint("inp->PreferedAltitude=%p", inp->ProtectedProcess);

				if (DRMProcess)
				{

					LARGE_INTEGER timeout;

					timeout.QuadPart = -500000;
					ntStatus=KeWaitForSingleObject(DRMProcess, UserRequest, UserMode, FALSE, &timeout);

					if (ntStatus != STATUS_SUCCESS)
						break;
				}

				DRMProcess = PsGetCurrentProcess();

				if (inp->ProtectedProcess)
				{
					if (DRMProcess != (PEPROCESS)((UINT_PTR)inp->ProtectedProcess))
						DRMProcess2 = (PEPROCESS)((UINT_PTR)inp->ProtectedProcess);
				}

				DbgPrint("DRMProcess=%p", DRMProcess);
				DbgPrint("DRMProcess2=%p", DRMProcess2);

				if (DRMHandle == NULL)
				{
					WCHAR wcAltitude[10];
					UNICODE_STRING usAltitude;
					OB_CALLBACK_REGISTRATION r;
					LARGE_INTEGER tc;
					OB_OPERATION_REGISTRATION obr[2];
					int RandomVal = (int)(inp->PreferedAltitude);
					int trycount = 0;

					if (RandomVal == 0)
					{
						tc.QuadPart = 0;
						KeQueryTickCount(&tc);
						RandomVal = 1000 + (tc.QuadPart % 50000);
					}

					DbgPrint("Activating CE's super advanced DRM");

					DbgPrint("RandomVal=%d", RandomVal);
					RtlStringCbPrintfW(wcAltitude, sizeof(wcAltitude) - 2, L"%d", RandomVal);

					DbgPrint("wcAltitude=%S", wcAltitude);
					RtlInitUnicodeString(&usAltitude, wcAltitude);

					r.Version = OB_FLT_REGISTRATION_VERSION;
					r.Altitude = usAltitude;
					r.RegistrationContext = NULL;

					obr[0].ObjectType = PsProcessType;
					obr[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
					obr[0].PreOperation = ProcessPreCallback;
					obr[0].PostOperation = ProcessPostCallback;

					obr[1].ObjectType = PsThreadType;
					obr[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
					obr[1].PreOperation = ThreadPreCallback;
					obr[1].PostOperation = ThreadPostCallback;

					r.OperationRegistration = obr;
					r.OperationRegistrationCount = 2;

					ntStatus = ObRegisterCallbacks(&r, &DRMHandle);

					while ((ntStatus == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION) && (trycount<10))
					{
						RandomVal++;
						RtlStringCbPrintfW(wcAltitude, sizeof(wcAltitude) - 2, L"%d", RandomVal);
						RtlInitUnicodeString(&usAltitude, wcAltitude);
						r.Altitude = usAltitude;

						trycount++;

						ntStatus = ObRegisterCallbacks(&r, &DRMHandle);
					}

					DbgPrint("ntStatus=%X", ntStatus);
				}
				else
					ntStatus = STATUS_SUCCESS;
#else
				ntStatus = STATUS_NOT_IMPLEMENTED;
#endif
				break;
			}

		case IOCTL_CE_GET_PEB:
		{
			KAPC_STATE oldstate;
			PEPROCESS ep = *(PEPROCESS *)Irp->AssociatedIrp.SystemBuffer;

			KeStackAttachProcess((PKPROCESS)ep, &oldstate);
			__try
			{
				ULONG r;
				PROCESS_BASIC_INFORMATION pbi;

				ntStatus = ZwQueryInformationProcess(ZwCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &r);
				if (ntStatus==STATUS_SUCCESS)
				{

					*(QWORD *)Irp->AssociatedIrp.SystemBuffer = (QWORD)(pbi.PebBaseAddress);
				}
				else
					DbgPrint("ZwQueryInformationProcess failed");
			}
			__finally
			{
				KeUnstackDetachProcess(&oldstate);
			}

			break;
		}

		case IOCTL_CE_QUERYINFORMATIONPROCESS:
		{
			struct
			{
				QWORD processid;
				QWORD ProcessInformationAddress;
				QWORD ProcessInformationClass;
				QWORD ProcessInformationLength;
			}  *inp = Irp->AssociatedIrp.SystemBuffer;

			struct
			{
				QWORD result;
				QWORD returnLength;
				char data;
			} *outp = Irp->AssociatedIrp.SystemBuffer;

			PEPROCESS selectedprocess;
			DbgPrint("IOCTL_CE_QUERYINFORMATIONPROCESS");

			if (inp->processid == 0)
			{
				DbgPrint("Still works\n");
				ntStatus = STATUS_SUCCESS;
				break;
			}
			__try
			{

				if (PsLookupProcessByProcessId((HANDLE)(UINT_PTR)inp->processid, &selectedprocess) == STATUS_SUCCESS)
				{
					KAPC_STATE oldstate;
					KeStackAttachProcess((PKPROCESS)selectedprocess, &oldstate);
					__try
					{
						ULONG returnLength;

						if (inp->ProcessInformationAddress == 0)
						{
							DbgPrint("NULL ProcessInformationAddress");
							outp->result = ZwQueryInformationProcess(NtCurrentProcess(), inp->ProcessInformationClass, NULL, (ULONG)inp->ProcessInformationLength, &returnLength);
						}
						else
							outp->result = ZwQueryInformationProcess(NtCurrentProcess(), inp->ProcessInformationClass, &(outp->data), (ULONG)inp->ProcessInformationLength, &returnLength);

						DbgPrint("outp->result=%x", outp->result);

						outp->returnLength = returnLength;
						DbgPrint("outp->returnLength=%x", outp->returnLength);

						ntStatus = STATUS_SUCCESS;
					}
					__finally
					{
						KeUnstackDetachProcess(&oldstate);
					}

					ObDereferenceObject(selectedprocess);
				}
				else
				{
					DbgPrint("Failed to find pid %x", inp->processid);
					ntStatus = STATUS_EXPIRED_HANDLE;
				}
			}
			__except (1)
			{
				DbgPrint("Exception");
				ntStatus = STATUS_EXPIRED_HANDLE;
			}
			break;
		}

		case IOCTL_CE_NTPROTECTVIRTUALMEMORY:
		{

			break;
		}

		case IOCTL_CE_ALLOCATE_MEMORY_FOR_DBVM:
		{
			PHYSICAL_ADDRESS LowAddress, HighAddress, SkipBytes;
			PMDL mdl;
			QWORD pagecount = *(QWORD*)Irp->AssociatedIrp.SystemBuffer;
			PFN_NUMBER *pfnlist;
			DbgPrint("IOCTL_CE_ALLOCATE_MEMORY_FOR_DBVM(%d)\n", pagecount);

			if (!vmxusable)
			{
				DbgPrint("This only works when DBVM is present\n");
				ntStatus = STATUS_INVALID_DEVICE_STATE;
				break;
			}

			LowAddress.QuadPart = 0;
			HighAddress.QuadPart = 0xffffffffffffffffI64;
			SkipBytes.QuadPart = 0;
			mdl = MmAllocatePagesForMdlEx(LowAddress, HighAddress, SkipBytes, (SIZE_T)pagecount * 4096, MmCached, MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS | MM_ALLOCATE_FULLY_REQUIRED);
			if (mdl)
			{
				int i;
				PDBVMOffloadMemInfo mi;

				pagecount = MmGetMdlByteCount(mdl) / 4096;
				DbgPrint("Allocated %d pages\n", pagecount);

				pfnlist = MmGetMdlPfnArray(mdl);

				if (pfnlist)
				{

					mi = ExAllocatePool(PagedPool, sizeof(DBVMOffloadMemInfo));
					if (mi)
					{
						mi->List = ExAllocatePool(PagedPool, sizeof(UINT64) * 32);
						if (mi->List)
						{
							mi->Count = 0;
							for (i = 0; i < pagecount; i++)
							{
								mi->List[mi->Count] = pfnlist[i] << 12;
								mi->Count++;

								if (mi->Count == 32)
								{
									int j;
									int r = vmx_add_memory(mi->List, mi->Count);

									DbgPrint("vmx_add_memory for %d pages returned %d\n", mi->Count, r);

									for (j = 0; j < mi->Count; j++)
									{
										DbgPrint("%d : %p\n", j, (void*)((UINT_PTR)mi->List[j]));
									}

									mi->Count = 0;
								}
							}

							if (mi->Count)
							{
								int r = vmx_add_memory(mi->List, mi->Count);
								DbgPrint("vmx_add_memory for %d pages returned %d\n", mi->Count, r);
							}
							ExFreePool(mi->List);
						}
						else
							DbgPrint("Failure allocating mi->List");
						ExFreePool(mi);
					}
					else
						DbgPrint("Failure allocting mi");

				}
				else
					DbgPrint("Failure getting pfn list");
				ExFreePool(mdl);

				ntStatus = STATUS_SUCCESS;
			}
			else
			{
				DbgPrint("Failure allocating MDL");
				ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
			}

			break;
		}

        default:
			DbgPrint("Unhandled IO request: %x\n", IoControlCode);
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[OwMemDriver] DispatchIoctl: Unhandled kernel exception on IoControlCode 0x%X\n", IoControlCode);
        ntStatus = STATUS_UNSUCCESSFUL;
    }

    Irp->IoStatus.Status = ntStatus;

	if (irpStack)
	{
		if (ntStatus == STATUS_SUCCESS)
			Irp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
		else
			Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}

    return ntStatus;
}
