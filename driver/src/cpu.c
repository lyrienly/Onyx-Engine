#include <ntifs.h>
#include <ntddk.h>
#include "OnyxFunc.h"
#include "vmxhelper.h"


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

	dpc = ExAllocatePoolWithTag(ONYX_POOL_NX, sizeof(KDPC), 'kcpD');
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

	dpc = (PKDPC)ExAllocatePoolWithTag(ONYX_POOL_NX, sizeof(KDPC) * cpucount, 'kcpD');
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

	dpc = (PKDPC)ExAllocatePoolWithTag(ONYX_POOL_NX, sizeof(KDPC) * cpucount, 'kcpD');
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
