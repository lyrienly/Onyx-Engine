#pragma warning( disable: 4100 4103 4189)
#include <ntifs.h>
#include <windef.h>

#include "OnyxFunc.h"
#include "interruptHook.h"

#include "debugger.h"
#include "vmxhelper.h"

#ifdef AMD64
extern void interrupt1_asmentry( void );
#else
void interrupt1_asmentry( void );
#endif

volatile struct
{
	BOOL		isDebugging;
	BOOL		stoppingTheDebugger;
	DWORD		debuggedProcessID;
	struct {
		BOOL		active;
		UINT_PTR	address;
		BreakType	breakType;
		BreakLength breakLength;
	} breakpoint[4];

	BOOL globalDebug;

	UINT_PTR *LastStackPointer;
	UINT_PTR *LastRealDebugRegisters;
	HANDLE LastThreadID;
	BOOL CausedByDBVM;
	BOOL handledlastevent;

	volatile struct {
		UINT_PTR DR0;
		UINT_PTR DR1;
		UINT_PTR DR2;
		UINT_PTR DR3;
		UINT_PTR DR6;
		UINT_PTR DR7;
		UINT_PTR reserved;
		volatile int inEpilogue;
	} FakedDebugRegisterState[256];

	char b[1];

	BOOL isSteppingTillClear;

} DebuggerState;

KEVENT debugger_event_WaitForContinue;
KEVENT debugger_event_CanBreak;
KEVENT debugger_event_WaitForDebugEvent;

DebugReg7 debugger_dr7_getValue(void);
void debugger_dr7_setValue(DebugReg7 value);
DebugReg6 debugger_dr6_getValue(void);

JUMPBACK Int1JumpBackLocation;

typedef struct _SavedStack
{
	BOOL inuse;
	QWORD stacksnapshot[600];
} SavedStack, *PSavedStack;

criticalSection StacksCS;
int StackCount;
PSavedStack *Stacks;

void debugger_dr7_setGD(int state)
{

	DebugReg7 _dr7=debugger_dr7_getValue();
	_dr7.GD=state;
	debugger_dr7_setValue(_dr7);

}

void debugger_dr0_setValue(UINT_PTR value)
{
	__writedr(0,value);
}

UINT_PTR debugger_dr0_getValue(void)
{
	return __readdr(0);
}

void debugger_dr1_setValue(UINT_PTR value)
{
	__writedr(1,value);
}

UINT_PTR debugger_dr1_getValue(void)
{
	return __readdr(1);
}

void debugger_dr2_setValue(UINT_PTR value)
{
	__writedr(2,value);
}

UINT_PTR debugger_dr2_getValue(void)
{
	return __readdr(2);
}

void debugger_dr3_setValue(UINT_PTR value)
{
	__writedr(3,value);
}

UINT_PTR debugger_dr3_getValue(void)
{
	return __readdr(3);
}

void debugger_dr6_setValue(UINT_PTR value)
{
	__writedr(6,value);
}

void debugger_dr7_setValue(DebugReg7 value)
{
	UINT_PTR temp=*(UINT_PTR *)&value;
	__writedr(7,temp);
}

void debugger_dr7_setValueDword(UINT_PTR value)
{
	__writedr(7,value);
}

UINT_PTR debugger_dr7_getValueDword(void)
{
	return __readdr(7);
}

DebugReg7 debugger_dr7_getValue(void)
{
	UINT_PTR temp=debugger_dr7_getValueDword();
	return *(DebugReg7 *)&temp;
}

UINT_PTR debugger_dr6_getValueDword(void)
{
	return __readdr(6);
}

DebugReg6 debugger_dr6_getValue(void)
{
	UINT_PTR temp=debugger_dr6_getValueDword();
	return *(DebugReg6 *)&temp;
}

void debugger_touchDebugRegister(UINT_PTR param)
{

	debugger_dr0_setValue(debugger_dr0_getValue());

}

void debugger_initialize(void)
{

	KeInitializeEvent(&debugger_event_WaitForContinue, SynchronizationEvent, FALSE);
	KeInitializeEvent(&debugger_event_CanBreak, SynchronizationEvent, TRUE);
	KeInitializeEvent(&debugger_event_WaitForDebugEvent, SynchronizationEvent, FALSE);

	StackCount = getCpuCount() * 4;
	Stacks = (PSavedStack*)ExAllocatePoolWithTag(ONYX_POOL_NX, StackCount * sizeof(PSavedStack), 'kbtS');
	if (!Stacks)
		return;

	int i;
	for (i = 0; i < StackCount; i++)
	{
		Stacks[i] = (PSavedStack)ExAllocatePoolWithTag(ONYX_POOL_NX, sizeof(SavedStack), 'kbtS');
		if (Stacks[i])
			RtlZeroMemory(Stacks[i], sizeof(SavedStack));
	}
}

void debugger_shutdown(void)
{
	if (Stacks)
	{
		int i;
		for (i = 0; i < StackCount; i++)
		{
			if (Stacks[i])
			{
				ExFreePool(Stacks[i]);
				Stacks[i] = NULL;
			}
		}

		ExFreePool(Stacks);
		Stacks = NULL;
	}
}

void debugger_growstack()

{
	if (Stacks)
	{
		KIRQL oldIRQL=KeRaiseIrqlToDpcLevel();

		csEnter(&StacksCS);
		enableInterrupts();

		int newStackCount = StackCount * 2;
		int i;
		PSavedStack *newStacks;
		newStacks = (PSavedStack*)ExAllocatePoolWithTag(ONYX_POOL_NX, newStackCount * sizeof(PSavedStack), 'kbtS');

		if (newStacks)
		{
			for (i = 0; i < StackCount; i++)
				newStacks[i] = Stacks[i];

			for (i = StackCount; i < newStackCount; i++)
			{
				newStacks[i] = (PSavedStack)ExAllocatePoolWithTag(ONYX_POOL_NX, sizeof(SavedStack), 'kbtS');
				if (newStacks[i])
					RtlZeroMemory(newStacks[i], sizeof(SavedStack));
				else
				{
					ExFreePool(newStacks);
					csLeave(&StacksCS);
					KeLowerIrql(oldIRQL);
					return;
				}
			}

			ExFreePool(Stacks);
			Stacks = newStacks;
		}

		csLeave(&StacksCS);
		KeLowerIrql(oldIRQL);

	}
}

void debugger_setInitialFakeState(void)
{

	DebuggerState.FakedDebugRegisterState[cpunr()].DR0=debugger_dr0_getValue();
	DebuggerState.FakedDebugRegisterState[cpunr()].DR1=debugger_dr1_getValue();
	DebuggerState.FakedDebugRegisterState[cpunr()].DR2=debugger_dr2_getValue();
	DebuggerState.FakedDebugRegisterState[cpunr()].DR3=debugger_dr3_getValue();
	DebuggerState.FakedDebugRegisterState[cpunr()].DR6=debugger_dr6_getValueDword();
	DebuggerState.FakedDebugRegisterState[cpunr()].DR7=debugger_dr7_getValueDword();
}

VOID debugger_initHookForCurrentCPU_DPC(IN struct _KDPC *Dpc, IN PVOID  DeferredContext, IN PVOID  SystemArgument1, IN PVOID  SystemArgument2)
{
	debugger_initHookForCurrentCPU();
}

int debugger_removeHookForCurrentCPU(UINT_PTR params)
{

    return inthook_UnhookInterrupt(1);
}

int debugger_initHookForCurrentCPU(void)

{
	int result=TRUE;

	result=inthook_HookInterrupt(1,getCS() & 0xfff8, (ULONG_PTR)interrupt1_asmentry, &Int1JumpBackLocation);

#ifdef AMD64
	if (result)
	{
		;
	}
	else
	{

		return result;
	}
#endif

	if (DebuggerState.globalDebug)
	{

		debugger_dr7_setGD(1);
	}

	return result;
}

void debugger_setStoreLBR(BOOL state)
{
	return;

}

int debugger_setGlobalDebugState(BOOL state)

{

	if (state)
	  DebuggerState.globalDebug=state;

	if (inthook_isHooked(1))
	{
		int oldEpilogueState=DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue;

		DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue=TRUE;
		DebuggerState.globalDebug=state;
		debugger_dr7_setGD(state);

		DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue=oldEpilogueState;

		DebuggerState.FakedDebugRegisterState[cpunr()].DR7=0x400;
		debugger_dr7_setValueDword(0x400);

	}

	return TRUE;
}

int debugger_startDebugging(DWORD debuggedProcessID)

{

	Int1JumpBackLocation.eip=inthook_getOriginalEIP(1);
	Int1JumpBackLocation.cs=inthook_getOriginalCS(1);

#ifdef AMD64

#endif

	DebuggerState.isDebugging=TRUE;
	DebuggerState.debuggedProcessID=debuggedProcessID;

	return TRUE;
}

int debugger_stopDebugging(void)
{
	int i;

	DebuggerState.stoppingTheDebugger=TRUE;

	if (DebuggerState.globalDebug)
	{

        forEachCpuPassive(debugger_touchDebugRegister, 0);
	}

    DebuggerState.globalDebug=FALSE;
	DebuggerState.isDebugging=FALSE;

	for (i=0; i<4; i++)
		DebuggerState.breakpoint[i].active=FALSE;

	forEachCpuPassive(debugger_removeHookForCurrentCPU, 0);

	return TRUE;
}

int debugger_unsetGDBreakpoint(int breakpointnr)
{
	int result=DebuggerState.breakpoint[breakpointnr].active;
	DebuggerState.breakpoint[breakpointnr].active=FALSE;
	return result;
}

int debugger_setGDBreakpoint(int breakpointnr, ULONG_PTR Address, BreakType bt, BreakLength bl)

{

	DebuggerState.breakpoint[breakpointnr].active=TRUE;
	DebuggerState.breakpoint[breakpointnr].address=Address;
	DebuggerState.breakpoint[breakpointnr].breakType=bt;
	DebuggerState.breakpoint[breakpointnr].breakLength=bl;
	return TRUE;
}

NTSTATUS debugger_waitForDebugEvent(ULONG timeout)
{
	NTSTATUS r;
	LARGE_INTEGER wait;

	wait.QuadPart=-10000LL * timeout;

	if (timeout==0xffffffff)
	  r=KeWaitForSingleObject(&debugger_event_WaitForDebugEvent, UserRequest, KernelMode, TRUE, NULL);
	else
	  r=KeWaitForSingleObject(&debugger_event_WaitForDebugEvent, UserRequest, KernelMode, TRUE, &wait);

	if (r==STATUS_SUCCESS)
		return r;
	else
		return STATUS_UNSUCCESSFUL;
}

NTSTATUS debugger_continueDebugEvent(BOOL handled)

{

	DebuggerState.handledlastevent=handled;
	KeSetEvent(&debugger_event_WaitForContinue, 0,FALSE);

	return STATUS_SUCCESS;
}

UINT_PTR *debugger_getLastStackPointer(void)
{

	return DebuggerState.LastStackPointer;
}

NTSTATUS debugger_getDebuggerState(PDebugStackState state)
{

	state->threadid=(UINT64)DebuggerState.LastThreadID;
	state->causedbydbvm = (UINT64)DebuggerState.CausedByDBVM;
	if (DebuggerState.LastStackPointer)
	{
		state->rflags=(UINT_PTR)DebuggerState.LastStackPointer[si_eflags];
		state->rax=DebuggerState.LastStackPointer[si_eax];
		state->rbx=DebuggerState.LastStackPointer[si_ebx];
		state->rcx=DebuggerState.LastStackPointer[si_ecx];
		state->rdx=DebuggerState.LastStackPointer[si_edx];
		state->rsi=DebuggerState.LastStackPointer[si_esi];
		state->rdi=DebuggerState.LastStackPointer[si_edi];
		state->rbp=DebuggerState.LastStackPointer[si_ebp];

	#ifdef AMD64

		state->r8=DebuggerState.LastStackPointer[si_r8];
		state->r9=DebuggerState.LastStackPointer[si_r9];
		state->r10=DebuggerState.LastStackPointer[si_r10];
		state->r11=DebuggerState.LastStackPointer[si_r11];
		state->r12=DebuggerState.LastStackPointer[si_r12];
		state->r13=DebuggerState.LastStackPointer[si_r13];
		state->r14=DebuggerState.LastStackPointer[si_r14];
		state->r15=DebuggerState.LastStackPointer[si_r15];
		memcpy(state->fxstate, (void *)&DebuggerState.LastStackPointer[si_xmm], 512);
	#endif

		if ((DebuggerState.LastStackPointer[si_cs] & 3) == 3)
		{

			state->rsp=DebuggerState.LastStackPointer[si_esp];
			state->ss=DebuggerState.LastStackPointer[si_ss];
		}
		else
		{

			state->rsp=(UINT_PTR)(DebuggerState.LastStackPointer)-4;
			state->ss=getSS();;
		}

		state->rip=DebuggerState.LastStackPointer[si_eip];
		state->cs=DebuggerState.LastStackPointer[si_cs];
		state->ds=DebuggerState.LastStackPointer[si_ds];
		state->es=DebuggerState.LastStackPointer[si_es];
	#ifdef AMD64
		state->fs=0;
		state->gs=0;
	#else
		state->fs=DebuggerState.LastStackPointer[si_fs];
		state->gs=DebuggerState.LastStackPointer[si_gs];
	#endif

		state->dr0=DebuggerState.LastRealDebugRegisters[0];
		state->dr1=DebuggerState.LastRealDebugRegisters[1];
		state->dr2=DebuggerState.LastRealDebugRegisters[2];
		state->dr3=DebuggerState.LastRealDebugRegisters[3];
		state->dr6=DebuggerState.LastRealDebugRegisters[4];
		state->dr7=DebuggerState.LastRealDebugRegisters[5];

			state->LBR_Count=0;

		return STATUS_SUCCESS;
	}
	else
	{

		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS debugger_setDebuggerState(PDebugStackState state)
{
	if (DebuggerState.LastStackPointer)
	{
		DebuggerState.LastStackPointer[si_eflags]=(UINT_PTR)state->rflags;

		DebuggerState.LastStackPointer[si_eax]=(UINT_PTR)state->rax;
		DebuggerState.LastStackPointer[si_ebx]=(UINT_PTR)state->rbx;
		DebuggerState.LastStackPointer[si_ecx]=(UINT_PTR)state->rcx;
		DebuggerState.LastStackPointer[si_edx]=(UINT_PTR)state->rdx;

		DebuggerState.LastStackPointer[si_esi]=(UINT_PTR)state->rsi;
		DebuggerState.LastStackPointer[si_edi]=(UINT_PTR)state->rdi;

		DebuggerState.LastStackPointer[si_ebp]=(UINT_PTR)state->rbp;

		if ((DebuggerState.LastStackPointer[si_cs] & 3) == 3)
		{

			DebuggerState.LastStackPointer[si_esp]=(UINT_PTR)state->rsp;

		}
		else
		{

		}

		DebuggerState.LastStackPointer[si_eip]=(UINT_PTR)state->rip;
		DebuggerState.LastStackPointer[si_cs]=(UINT_PTR)state->cs;
		DebuggerState.LastStackPointer[si_ds]=(UINT_PTR)state->ds;
		DebuggerState.LastStackPointer[si_es]=(UINT_PTR)state->es;
	#ifndef AMD64
		DebuggerState.LastStackPointer[si_fs]=(UINT_PTR)state->fs;
		DebuggerState.LastStackPointer[si_gs]=(UINT_PTR)state->gs;
	#else
		DebuggerState.LastStackPointer[si_r8]=(UINT_PTR)state->r8;
		DebuggerState.LastStackPointer[si_r9]=(UINT_PTR)state->r9;
		DebuggerState.LastStackPointer[si_r10]=(UINT_PTR)state->r10;
		DebuggerState.LastStackPointer[si_r11]=(UINT_PTR)state->r11;
		DebuggerState.LastStackPointer[si_r12]=(UINT_PTR)state->r12;
		DebuggerState.LastStackPointer[si_r13]=(UINT_PTR)state->r13;
		DebuggerState.LastStackPointer[si_r14]=(UINT_PTR)state->r14;
		DebuggerState.LastStackPointer[si_r15]=(UINT_PTR)state->r15;
		memcpy((void *)&DebuggerState.LastStackPointer[si_xmm], state->fxstate, 512);
	#endif

		if (!DebuggerState.globalDebug)
		{

			DebuggerState.LastRealDebugRegisters[0]=(UINT_PTR)state->dr0;
			DebuggerState.LastRealDebugRegisters[1]=(UINT_PTR)state->dr1;
			DebuggerState.LastRealDebugRegisters[2]=(UINT_PTR)state->dr2;
			DebuggerState.LastRealDebugRegisters[3]=(UINT_PTR)state->dr3;
			DebuggerState.LastRealDebugRegisters[4]=(UINT_PTR)state->dr6;
			DebuggerState.LastRealDebugRegisters[5]=(UINT_PTR)state->dr7;

		}
	}
	else
	{

		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

int breakpointHandler_kernel(UINT_PTR *stackpointer, UINT_PTR *currentdebugregs, UINT_PTR *LBR_Stack, int causedbyDBVM)

{
	NTSTATUS r=STATUS_UNSUCCESSFUL;
	int handled=0;
	LARGE_INTEGER timeout;
	timeout.QuadPart=-100000;

#ifdef AMD64

#endif

	if (KeGetCurrentIrql()==0)
	{

		if ((stackpointer[si_cs] & 3)==0)
		{

		}

		while (r != STATUS_SUCCESS)
		{
			r=KeWaitForSingleObject(&debugger_event_CanBreak,Executive, KernelMode, FALSE, NULL);

		}

		if ((stackpointer[si_cs] & 3)==0)
		{

		}

		DebuggerState.LastStackPointer=stackpointer;
		DebuggerState.LastRealDebugRegisters=currentdebugregs;

		DebuggerState.LastThreadID=PsGetCurrentThreadId();
		DebuggerState.CausedByDBVM = causedbyDBVM;

		KeSetEvent(&debugger_event_WaitForDebugEvent,0,FALSE);

		while (1)
		{

			NTSTATUS s=STATUS_UNSUCCESSFUL;

			while (s != STATUS_SUCCESS)
			{
				s=KeWaitForSingleObject(&debugger_event_WaitForContinue, Executive, KernelMode, FALSE, NULL);

			}

			if (s==STATUS_SUCCESS)
			{
				if (DebuggerState.handledlastevent)
				{

					handled=1;
				}
				else
					handled=0;

				break;
			}

		}

		DebuggerState.LastStackPointer=NULL;

		KeSetEvent(&debugger_event_CanBreak, 0, FALSE);

		if ((stackpointer[si_cs] & 3)==0)
		{

		}

		return handled;
	}
	else
	{

		return 1;
	}

}

int interrupt1_handler(UINT_PTR *stackpointer, UINT_PTR *currentdebugregs)
{
	HANDLE CurrentProcessID=PsGetCurrentProcessId();
	UINT_PTR originaldr6=currentdebugregs[4];
	DebugReg6 _dr6=*(DebugReg6 *)&currentdebugregs[4];

	UINT_PTR LBR_Stack[16];

	int causedbyDBVM = vmxusable && vmx_causedCurrentDebugBreak();

	if (DebuggerState.globalDebug)
	{

		if (_dr6.BD)
		{
			_dr6.BD = 0;
			debugger_dr6_setValue(*(UINT_PTR *)&_dr6);

			if ((stackpointer[si_cs] & 3)==0)
			{
				int instructionPointer;
	#ifdef AMD64
				int prefixpointer;
	#endif
				int currentcpunr = cpunr();
				int debugregister;
				int generalpurposeregister;
				unsigned char *instruction = (unsigned char *)stackpointer[si_eip];

				_dr6.BD = 0;
				debugger_dr6_setValue(*(UINT_PTR *)&_dr6);

				if (DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue)
				{
					((EFLAGS *)&stackpointer[si_eflags])->RF = 1;
					return 2;
				}

				DebuggerState.FakedDebugRegisterState[cpunr()].DR6 = *(UINT_PTR *)&_dr6;

				for (instructionPointer = 0; instruction[instructionPointer] != 0x0f; instructionPointer++);

				debugregister = (instruction[instructionPointer + 2] >> 3) & 7;
				generalpurposeregister = instruction[instructionPointer + 2] & 7;

	#ifdef AMD64
				for (prefixpointer = 0; prefixpointer < instructionPointer; prefixpointer++)
				{

					if ((instruction[prefixpointer] & 0x41) == 0x41)
					{

						generalpurposeregister += 8;
					}
				}

	#endif

				if (instruction[instructionPointer + 1] == 0x21)
				{
					UINT_PTR drvalue = 0;

					switch (debugregister)
					{
					case 0:

						drvalue = DebuggerState.FakedDebugRegisterState[cpunr()].DR0;

						break;

					case 1:
						drvalue = DebuggerState.FakedDebugRegisterState[cpunr()].DR1;
						break;

					case 2:
						drvalue = DebuggerState.FakedDebugRegisterState[cpunr()].DR2;
						break;

					case 3:
						drvalue = DebuggerState.FakedDebugRegisterState[cpunr()].DR3;
						break;

					case 4:
					case 6:
						drvalue = DebuggerState.FakedDebugRegisterState[cpunr()].DR6;

						break;

					case 5:
					case 7:
						drvalue = DebuggerState.FakedDebugRegisterState[cpunr()].DR7;
						break;

					default:

						drvalue = 0;
						break;
					}

					switch (generalpurposeregister)
					{
					case 0:
						stackpointer[si_eax] = drvalue;
						break;

					case 1:
						stackpointer[si_ecx] = drvalue;
						break;

					case 2:
						stackpointer[si_edx] = drvalue;
						break;

					case 3:
						stackpointer[si_ebx] = drvalue;
						break;

					case 4:
						if ((stackpointer[si_cs] & 3) == 3)
							stackpointer[si_esp] = drvalue;
						else
							stackpointer[si_stack_esp] = drvalue;

						break;

					case 5:
						stackpointer[si_ebp] = drvalue;
						break;

					case 6:
						stackpointer[si_esi] = drvalue;
						break;

					case 7:
						stackpointer[si_edi] = drvalue;
						break;

	#ifdef AMD64
					case 8:
						stackpointer[si_r8] = drvalue;
						break;

					case 9:
						stackpointer[si_r9] = drvalue;
						break;

					case 10:
						stackpointer[si_r10] = drvalue;
						break;

					case 11:
						stackpointer[si_r11] = drvalue;
						break;

					case 12:
						stackpointer[si_r12] = drvalue;
						break;

					case 13:
						stackpointer[si_r13] = drvalue;
						break;

					case 14:
						stackpointer[si_r14] = drvalue;
						break;

					case 15:
						stackpointer[si_r15] = drvalue;
						break;

	#endif
					}

				}
				else
					if (instruction[instructionPointer + 1] == 0x23)
					{

						UINT_PTR gpvalue = 0;

						switch (generalpurposeregister)
						{
						case 0:
							gpvalue = stackpointer[si_eax];
							break;

						case 1:
							gpvalue = stackpointer[si_ecx];
							break;

						case 2:
							gpvalue = stackpointer[si_edx];
							break;

						case 3:
							gpvalue = stackpointer[si_ebx];
							break;

						case 4:
							if ((stackpointer[si_cs] & 3) == 3)
								gpvalue = stackpointer[si_esp];

							break;

						case 5:
							gpvalue = stackpointer[si_ebp];
							break;

						case 6:
							gpvalue = stackpointer[si_esi];
							break;

						case 7:
							gpvalue = stackpointer[si_edi];
							break;
	#ifdef AMD64
						case 8:
							gpvalue = stackpointer[si_r8];
							break;

						case 9:
							gpvalue = stackpointer[si_r9];
							break;

						case 10:
							gpvalue = stackpointer[si_r10];
							break;

						case 11:
							gpvalue = stackpointer[si_r11];
							break;

						case 12:
							gpvalue = stackpointer[si_r12];
							break;

						case 13:
							gpvalue = stackpointer[si_r13];
							break;

						case 14:
							gpvalue = stackpointer[si_r14];
							break;

						case 15:
							gpvalue = stackpointer[si_r15];
							break;

						default:

							break;
	#endif
						}

						switch (debugregister)
						{
						case 0:

							debugger_dr0_setValue(gpvalue);
							DebuggerState.FakedDebugRegisterState[cpunr()].DR0 = debugger_dr0_getValue();
							break;

						case 1:
							debugger_dr1_setValue(gpvalue);
							DebuggerState.FakedDebugRegisterState[cpunr()].DR1 = debugger_dr1_getValue();
							break;

						case 2:
							debugger_dr2_setValue(gpvalue);
							DebuggerState.FakedDebugRegisterState[cpunr()].DR2 = debugger_dr2_getValue();
							break;

						case 3:
							debugger_dr3_setValue(gpvalue);
							DebuggerState.FakedDebugRegisterState[cpunr()].DR3 = debugger_dr3_getValue();
							break;

						case 4:
						case 6:

							_dr6 = *(DebugReg6 *)&gpvalue;

							debugger_dr6_setValue(gpvalue);
							DebuggerState.FakedDebugRegisterState[cpunr()].DR6 = debugger_dr6_getValueDword();

							if (_dr6.BD)
							{
								_dr6.BD = 0;
								debugger_dr6_setValue(gpvalue);
							}

							break;

						case 5:
						case 7:

							gpvalue = (gpvalue | 0x400) & (~(1 << 13));

							debugger_dr7_setValueDword(gpvalue);

							DebuggerState.FakedDebugRegisterState[cpunr()].DR7 = debugger_dr7_getValueDword();

							break;
						}

					}
					else
					{

					}

				stackpointer[si_eip] += instructionPointer + 3;

				return 1;
			}
			else
			{

				_dr6.BD = 0;
				debugger_dr6_setValue(*(UINT_PTR *)&_dr6);
				DebuggerState.FakedDebugRegisterState[cpunr()].DR6 = debugger_dr6_getValueDword();
			}
		}
	}

	if (DebuggerState.isSteppingTillClear)
	{

		if ((((PEFLAGS)&stackpointer[si_eflags])->IF == 0) || (KeGetCurrentIrql() != PASSIVE_LEVEL))
		{
			((PEFLAGS)&stackpointer[si_eflags])->TF = 1;
			((PEFLAGS)&stackpointer[si_eflags])->RF = 1;
			debugger_dr6_setValue(0xffff0ff0);
			return 1;
		}

		DebuggerState.isSteppingTillClear = FALSE;
	}

	if (DebuggerState.isDebugging)
	{

		if (CurrentProcessID == (HANDLE)(UINT_PTR)DebuggerState.debuggedProcessID)
		{
			UINT_PTR originaldebugregs[6];
			UINT64 oldDR7 = getDR7();

			if ((((PEFLAGS)&stackpointer[si_eflags])->IF == 0) || (KeGetCurrentIrql() != PASSIVE_LEVEL))
			{

				if (!KernelCodeStepping)
				{
					((PEFLAGS)&stackpointer[si_eflags])->TF = 0;

				}
				else
				{

					((PEFLAGS)&stackpointer[si_eflags])->TF = 1;
					DebuggerState.isSteppingTillClear = TRUE;
				}

				((PEFLAGS)&stackpointer[si_eflags])->RF = 1;
				debugger_dr6_setValue(0xffff0ff0);
				return 1;
			}

			DebuggerState.isSteppingTillClear = FALSE;

			if (DebuggerState.globalDebug)
			{
				originaldebugregs[0] = DebuggerState.FakedDebugRegisterState[cpunr()].DR0;
				originaldebugregs[1] = DebuggerState.FakedDebugRegisterState[cpunr()].DR1;
				originaldebugregs[2] = DebuggerState.FakedDebugRegisterState[cpunr()].DR2;
				originaldebugregs[3] = DebuggerState.FakedDebugRegisterState[cpunr()].DR3;
				originaldebugregs[4] = DebuggerState.FakedDebugRegisterState[cpunr()].DR6;
				originaldebugregs[5] = DebuggerState.FakedDebugRegisterState[cpunr()].DR7;
			}

			if (DebuggerState.globalDebug)
			{

				if (!DebuggerState.stoppingTheDebugger)
					debugger_dr7_setGD(DebuggerState.globalDebug);
			}
			else
			{

				debugger_dr7_setValueDword(0x400);
				debugger_dr0_setValue(0);
				debugger_dr1_setValue(0);
				debugger_dr2_setValue(0);
				debugger_dr3_setValue(0);
				debugger_dr6_setValue(0xffff0ff0);
			}

			BOOL NeedsToGrowStackList = FALSE;
			PSavedStack SelectedStackEntry = NULL;

			{
				int rs=1;

				if (SelectedStackEntry == NULL)
					rs = breakpointHandler_kernel(stackpointer, currentdebugregs, LBR_Stack, causedbyDBVM);
				else
					rs = breakpointHandler_kernel((UINT_PTR *)(SelectedStackEntry->stacksnapshot), currentdebugregs, LBR_Stack, causedbyDBVM);

				disableInterrupts();

				if (DebuggerState.globalDebug)
				{
					DebuggerState.FakedDebugRegisterState[cpunr()].DR0=originaldebugregs[0];
					DebuggerState.FakedDebugRegisterState[cpunr()].DR1=originaldebugregs[1];
					DebuggerState.FakedDebugRegisterState[cpunr()].DR2=originaldebugregs[2];
					DebuggerState.FakedDebugRegisterState[cpunr()].DR3=originaldebugregs[3];
					DebuggerState.FakedDebugRegisterState[cpunr()].DR6=originaldebugregs[4];
					DebuggerState.FakedDebugRegisterState[cpunr()].DR7=originaldebugregs[5];
				}
				else
				{

					debugger_dr0_setValue(currentdebugregs[0]);
					debugger_dr1_setValue(currentdebugregs[1]);
					debugger_dr2_setValue(currentdebugregs[2]);
					debugger_dr3_setValue(currentdebugregs[3]);
					debugger_dr6_setValue(currentdebugregs[4]);

					if ((currentdebugregs[5] >> 13) & 1)
					{

					}
					else
						debugger_dr7_setValue(*(DebugReg7 *)&currentdebugregs[5]);

				}

				return rs;
			}
		}
		else
		{

			if (DebuggerState.globalDebug)
			{
				DebugReg6 dr6=debugger_dr6_getValue();
				DebugReg7 dr7=*(DebugReg7 *)&DebuggerState.FakedDebugRegisterState[cpunr()].DR7;

				if ((dr6.B0) && (!(dr7.L0 || dr7.G0))) {  ((PEFLAGS)&stackpointer[si_eflags])->RF=1; return 1; }
				if ((dr6.B1) && (!(dr7.L1 || dr7.G1))) {  ((PEFLAGS)&stackpointer[si_eflags])->RF=1; return 1; }
				if ((dr6.B2) && (!(dr7.L2 || dr7.G2))) {  ((PEFLAGS)&stackpointer[si_eflags])->RF=1; return 1; }
				if ((dr6.B3) && (!(dr7.L3 || dr7.G3))) {  ((PEFLAGS)&stackpointer[si_eflags])->RF=1; return 1; }
			}

			if (causedbyDBVM)
				return 1;

			if (DebuggerState.isSteppingTillClear)
			{

				((PEFLAGS)&stackpointer[si_eflags])->TF = 0;

				DebuggerState.isSteppingTillClear = 0;
				return 1;
			}

			return 0;

		}
	}
	else
		return 0;

}

int interrupt1_centry(UINT_PTR *stackpointer)
{
	UINT_PTR before;
	UINT_PTR currentdebugregs[6];
	int handled=0;
	QWORD naddress;

	IDT idt;
	GetIDT(&idt);

	naddress = idt.vector[1].wLowOffset + (idt.vector[1].wHighOffset << 16);
#ifdef AMD64
	naddress += ((UINT64)idt.vector[1].TopOffset << 32);
#endif
	stackpointer[si_errorcode] = (UINT_PTR)naddress;

	before=getRSP();

	currentdebugregs[0]=debugger_dr0_getValue();
	currentdebugregs[1]=debugger_dr1_getValue();
	currentdebugregs[2]=debugger_dr2_getValue();
	currentdebugregs[3]=debugger_dr3_getValue();
	currentdebugregs[4]=debugger_dr6_getValueDword();
	currentdebugregs[5]=debugger_dr7_getValueDword();

	handled=interrupt1_handler(stackpointer, currentdebugregs);

	disableInterrupts();

	DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue=1;
	debugger_dr7_setGD(0);
	DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue=1;

#ifdef AMD64

#endif

	if (DebuggerState.globalDebug)
	{

        DebugReg6 dr6=debugger_dr6_getValue();

		DebugReg6 _dr6=*(DebugReg6 *)&DebuggerState.FakedDebugRegisterState[cpunr()].DR6;
        DebugReg7 _dr7=*(DebugReg7 *)&DebuggerState.FakedDebugRegisterState[cpunr()].DR7;
		int debugregister=0, breakpoint=0;

		if (!handled)
		{

			if (dr6.BD && _dr7.GD) _dr6.BD=1;
			if (dr6.B0 && (_dr7.L0 || _dr7.G0)) _dr6.B0=1;
			if (dr6.B1 && (_dr7.L1 || _dr7.G1)) _dr6.B1=1;
			if (dr6.B2 && (_dr7.L2 || _dr7.G2)) _dr6.B2=1;
			if (dr6.B3 && (_dr7.L3 || _dr7.G3)) _dr6.B3=1;

			_dr6.BS=dr6.BS;
			_dr6.BT=dr6.BT;

		}

		debugger_dr6_setValue(0xffff0ff0);

		debugger_dr0_setValue(DebuggerState.FakedDebugRegisterState[cpunr()].DR0);
		debugger_dr1_setValue(DebuggerState.FakedDebugRegisterState[cpunr()].DR1);
		debugger_dr2_setValue(DebuggerState.FakedDebugRegisterState[cpunr()].DR2);
		debugger_dr3_setValue(DebuggerState.FakedDebugRegisterState[cpunr()].DR3);
		debugger_dr6_setValue(DebuggerState.FakedDebugRegisterState[cpunr()].DR6);

		for (breakpoint=0; breakpoint<4; breakpoint++)
		{

			if (DebuggerState.breakpoint[breakpoint].active)
			{

				int foundone=0;

				while ((debugregister<4) && (foundone==0))
				{

					if (DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue==0)
					{
						DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue=1;
					}

					if (((DebuggerState.FakedDebugRegisterState[cpunr()].DR7 >> (debugregister*2)) & 3)==0)
					{

						foundone=1;

						switch (debugregister)
						{
							case 0:
								debugger_dr0_setValue(DebuggerState.breakpoint[breakpoint].address);
								_dr7.L0=1;
								_dr7.LEN0=DebuggerState.breakpoint[breakpoint].breakLength;
								_dr7.RW0=DebuggerState.breakpoint[breakpoint].breakType;
								break;

							case 1:
								debugger_dr1_setValue(DebuggerState.breakpoint[breakpoint].address);
								_dr7.L1=1;
								_dr7.LEN1=DebuggerState.breakpoint[breakpoint].breakLength;
								_dr7.RW1=DebuggerState.breakpoint[breakpoint].breakType;
								break;

							case 2:
								debugger_dr2_setValue(DebuggerState.breakpoint[breakpoint].address);
								_dr7.L2=1;
								_dr7.LEN2=DebuggerState.breakpoint[breakpoint].breakLength;
								_dr7.RW2=DebuggerState.breakpoint[breakpoint].breakType;
								break;

							case 3:
								debugger_dr3_setValue(DebuggerState.breakpoint[breakpoint].address);
								_dr7.L3=1;
								_dr7.LEN3=DebuggerState.breakpoint[breakpoint].breakLength;
								_dr7.RW3=DebuggerState.breakpoint[breakpoint].breakType;
								break;
						}

					}

					debugregister++;

				}

			}

		}

		debugger_dr7_setValue(_dr7);

	}
	else
	{

		if (handled)
			debugger_dr6_setValue(0xffff0ff0);

	}

	disableInterrupts();

	if (handled == 2)
	{

		handled = 1;
	}
	else
	{

		if (DebuggerState.globalDebug)
		{
			DebuggerState.FakedDebugRegisterState[cpunr()].inEpilogue=0;

			if (!DebuggerState.stoppingTheDebugger)
				debugger_dr7_setGD(DebuggerState.globalDebug);
		}
	}

	return handled;
}

#ifndef AMD64
_declspec( naked ) void interrupt1_asmentry( void )

{
	__asm{

		cld

		push 0
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

		push ebp
		call interrupt1_centry

		cmp eax,1

		pop gs
		pop fs
		pop es
		pop ds
		popad

		pop ebp

		je skip_original_int1

		add esp,4

		jmp far [Int1JumpBackLocation]

skip_original_int1:
		add esp,4
		iretd
	}
}
#endif
