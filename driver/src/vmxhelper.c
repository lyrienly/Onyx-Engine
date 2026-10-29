#pragma warning( disable: 4100 4103 4213)
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include "vmxhelper.h"
#include "DBKFunc.h"

#ifdef AMD64
extern UINT_PTR dovmcall_intel(void *vmcallinfo, unsigned int level1pass);
extern UINT_PTR dovmcall_amd(void *vmcallinfo, unsigned int level1pass);

#else
_declspec( naked ) UINT_PTR dovmcall_intel(void *vmcallinfo)
{
	__asm
	{
		push edx
		mov eax,[esp+8]
		mov edx, dword ptr vmx_password1
		mov ecx, dword ptr vmx_password3
		__emit 0x0f
		__emit 0x01
	    __emit 0xc1
		pop edx
		ret 8
	}
}

_declspec( naked ) UINT_PTR dovmcall_amd(void *vmcallinfo)
{
	__asm
	{
		push edx
		mov eax,[esp+8]
		mov edx, dword ptr  vmx_password1
		mov ecx, dword ptr  vmx_password3
		__emit 0x0f
		__emit 0x01
	    __emit 0xd9
		pop edx
		ret 8
	}
}
#endif

typedef UINT_PTR (DOVMCALL) (void *vmcallinfo);
DOVMCALL *dovmcall;

int vmx_hasredirectedint1()
{
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
	} vmcallinfo;

	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_INT1REDIRECTED;
	return (int)dovmcall(&vmcallinfo);
}

unsigned int vmx_getversion()

{
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
	} vmcallinfo;

	DbgPrint("vmx_getversion()\n");

	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_GETVERSION;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_getRealCR0()
{
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
	} vmcallinfo;

	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_GETCR0;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

UINT_PTR vmx_getRealCR3()
{
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
	} vmcallinfo;

	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_GETCR3;

	return dovmcall(&vmcallinfo);;
}

unsigned int vmx_getRealCR4()
{
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
	} vmcallinfo;

	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_GETCR4;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_redirect_interrupt1(VMXInterruptRedirectType redirecttype, unsigned int newintvector, unsigned int int1cs, UINT_PTR int1eip)
{
	#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		unsigned int redirecttype;
		unsigned int newintvector;
		UINT64 int1eip;
		unsigned int int1cs;
	} vmcallinfo;
	#pragma pack()

	DbgPrint("vmx_redirect_interrupt1: redirecttype=%d int1cs=%x int1eip=%llx sizeof(vmcallinfo)=%x\n", redirecttype, int1cs, int1eip, sizeof(vmcallinfo));
	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_REDIRECTINT1;
	vmcallinfo.redirecttype=redirecttype;
	vmcallinfo.newintvector=newintvector;
	vmcallinfo.int1eip=int1eip;
	vmcallinfo.int1cs=int1cs;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_redirect_interrupt3(VMXInterruptRedirectType redirecttype, unsigned int newintvector, unsigned int int3cs, UINT_PTR int3eip)
{
	#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		unsigned int redirecttype;
		unsigned int newintvector;
		unsigned long long int3eip;
		unsigned int int3cs;
	} vmcallinfo;
	#pragma pack()

	DbgPrint("vmx_redirect_interrupt3: int3cs=%x int3eip=%x sizeof(vmcallinfo)=%x\n", int3cs, int3eip, sizeof(vmcallinfo));
	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_REDIRECTINT3;
	vmcallinfo.redirecttype=redirecttype;
	vmcallinfo.newintvector=newintvector;
	vmcallinfo.int3eip=int3eip;
	vmcallinfo.int3cs=int3cs;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_redirect_interrupt14(VMXInterruptRedirectType redirecttype, unsigned int newintvector, unsigned int int14cs, UINT_PTR int14eip)
{
	#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		unsigned int redirecttype;
		unsigned int newintvector;
		unsigned long long int14eip;
		unsigned int int14cs;
	} vmcallinfo;
	#pragma pack()

	DbgPrint("vmx_redirect_interrupt14: int14cs=%x int14eip=%x sizeof(vmcallinfo)=%x\n", int14cs, int14eip, sizeof(vmcallinfo));
	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_REDIRECTINT14;
	vmcallinfo.redirecttype=redirecttype;
	vmcallinfo.newintvector=newintvector;
	vmcallinfo.int14eip=int14eip;
	vmcallinfo.int14cs=int14cs;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_register_cr3_callback(unsigned int cs, unsigned int eip, unsigned int ss, unsigned int esp)
{
	#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		unsigned int callbacktype;
		unsigned long long callback_eip;
		unsigned int callback_cs;
		unsigned long long callback_esp;
		unsigned int callback_ss;
	} vmcallinfo;
	#pragma pack()

	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_REGISTER_CR3_EDIT_CALLBACK;
	vmcallinfo.callbacktype=0;
	vmcallinfo.callback_eip=eip;
	vmcallinfo.callback_cs=cs;
	vmcallinfo.callback_esp=esp;
	vmcallinfo.callback_ss=ss;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_exit_cr3_callback(unsigned int newcr3)
{
	#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		unsigned long long newcr3;
	} vmcallinfo;
	#pragma pack()

	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_RETURN_FROM_CR3_EDIT_CALLBACK;
	vmcallinfo.newcr3=newcr3;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_watch_pagewrites(UINT64 PhysicalAddress, int Size, int Options, int MaxEntryCount)
{
#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		UINT64 PhysicalAddress;
		int Size;
		int Options;

		int MaxEntryCount;
		int UsePMI;
		int ID;
	} vmcallinfo;
#pragma pack()

	vmcallinfo.structsize = sizeof(vmcallinfo);
	vmcallinfo.level2pass = vmx_password2;
	vmcallinfo.command = VMCALL_WATCH_WRITES;
	vmcallinfo.PhysicalAddress = PhysicalAddress;

	if (((PhysicalAddress + Size) & 0xfffffffffffff000ULL) > PhysicalAddress)
		Size = 0x1000 - (PhysicalAddress & 0xfff);

	vmcallinfo.Size = Size;
	vmcallinfo.Options = Options;
	vmcallinfo.MaxEntryCount = MaxEntryCount;
	vmcallinfo.ID = 0xffffffff;

	dovmcall(&vmcallinfo);;
	return vmcallinfo.ID;
}

unsigned int vmx_watch_pageaccess(UINT64 PhysicalAddress, int Size, int Options, int MaxEntryCount)
{
#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		UINT64 PhysicalAddress;
		int Size;
		int Options;

		int MaxEntryCount;

		int ID;
	} vmcallinfo;
#pragma pack()

	vmcallinfo.structsize = sizeof(vmcallinfo);
	vmcallinfo.level2pass = vmx_password2;
	vmcallinfo.command = VMCALL_WATCH_READS;
	vmcallinfo.PhysicalAddress = PhysicalAddress;

	if (((PhysicalAddress + Size) & 0xfffffffffffff000ULL) > PhysicalAddress)
		Size = 0x1000 - (PhysicalAddress & 0xfff);

	vmcallinfo.Size = Size;
	vmcallinfo.Options = Options;
	vmcallinfo.MaxEntryCount = MaxEntryCount;
	vmcallinfo.ID = 0xffffffff;

	dovmcall(&vmcallinfo);;
	return vmcallinfo.ID;
}

unsigned int vmx_watch_retreivelog(int ID, PPageEventListDescriptor result, int *resultsize)

{
	unsigned int r;
#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		DWORD ID;
		UINT64 results;
		int resultsize;
		int copied;
	} vmcallinfo;
#pragma pack()

	vmcallinfo.structsize = sizeof(vmcallinfo);
	vmcallinfo.level2pass = vmx_password2;
	vmcallinfo.command = VMCALL_WATCH_RETRIEVELOG;

	vmcallinfo.ID = ID;
	vmcallinfo.results = (UINT64)result;
	vmcallinfo.resultsize = *resultsize;
	r=(unsigned int)dovmcall(&vmcallinfo);;
	*resultsize = vmcallinfo.resultsize;
	return r;
}

unsigned int vmx_watch_delete(int ID)
{

#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		DWORD ID;
	} vmcallinfo;
#pragma pack()

	vmcallinfo.structsize = sizeof(vmcallinfo);
	vmcallinfo.level2pass = vmx_password2;
	vmcallinfo.command = VMCALL_WATCH_DELETE;

	vmcallinfo.ID = ID;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_cloak_activate(QWORD physicalPage)

{

#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		QWORD physicalAddress;
	} vmcallinfo;
#pragma pack()

	vmcallinfo.structsize = sizeof(vmcallinfo);
	vmcallinfo.level2pass = vmx_password2;
	vmcallinfo.command = VMCALL_CLOAK_ACTIVATE;
	vmcallinfo.physicalAddress = physicalPage;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_cloak_deactivate(QWORD physicalPage)
{
#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		QWORD physicalAddress;
	} vmcallinfo;
#pragma pack()

	vmcallinfo.structsize = sizeof(vmcallinfo);
	vmcallinfo.level2pass = vmx_password2;
	vmcallinfo.command = VMCALL_CLOAK_DEACTIVATE;
	vmcallinfo.physicalAddress = physicalPage;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_cloak_readOriginal(QWORD physicalPage, void *destination)

{
#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		QWORD physicalAddress;
		QWORD destination;
	} vmcallinfo;
#pragma pack()

	vmcallinfo.structsize = sizeof(vmcallinfo);
	vmcallinfo.level2pass = vmx_password2;
	vmcallinfo.command = VMCALL_CLOAK_READORIGINAL;
	vmcallinfo.physicalAddress = physicalPage;
	vmcallinfo.destination = (QWORD)destination;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_cloak_writeOriginal(QWORD physicalPage, void *source)

{
#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		QWORD physicalAddress;
		QWORD source;
	} vmcallinfo;
#pragma pack()

	vmcallinfo.structsize = sizeof(vmcallinfo);
	vmcallinfo.level2pass = vmx_password2;
	vmcallinfo.command = VMCALL_CLOAK_WRITEORIGINAL;
	vmcallinfo.physicalAddress = physicalPage;
	vmcallinfo.source = (QWORD)source;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_changeregonbp(QWORD physicalAddress, CHANGEREGONBPINFO *changereginfo)

{
#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		QWORD physicalAddress;
		CHANGEREGONBPINFO changereginfo;
	} vmcallinfo;
#pragma pack()

	vmcallinfo.structsize = sizeof(vmcallinfo);
	vmcallinfo.level2pass = vmx_password2;
	vmcallinfo.command = VMCALL_CLOAK_CHANGEREGONBP;
	vmcallinfo.physicalAddress = physicalAddress;
	vmcallinfo.changereginfo = *changereginfo;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_ultimap_getDebugInfo(PULTIMAPDEBUGINFO debuginfo)
{
	#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		ULTIMAPDEBUGINFO debuginfo;
	} vmcallinfo;
	#pragma pack()

	unsigned int i;

	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_ULTIMAP_DEBUGINFO;

	i=(unsigned int)dovmcall(&vmcallinfo);;
	*debuginfo=vmcallinfo.debuginfo;

	return i;
}

unsigned int vmx_ultimap(UINT_PTR cr3towatch, UINT64 debugctl_value, void *storeaddress)
{
	#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		UINT64 cr3;
		UINT64 debugctl;
		UINT64 storeaddress;
	} vmcallinfo;
	#pragma pack()

	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_ULTIMAP;
	vmcallinfo.cr3=(UINT64)cr3towatch;
	vmcallinfo.debugctl=(UINT64)debugctl_value;
	vmcallinfo.storeaddress=(UINT64)(UINT_PTR)storeaddress;

	DbgPrint("vmx_ultimap(%I64x, %I64x, %I64x)\n", (UINT64)vmcallinfo.cr3, (UINT64)vmcallinfo.debugctl, vmcallinfo.storeaddress);

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_ultimap_disable()
{
	#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
	} vmcallinfo;
	#pragma pack()

	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_ULTIMAP_DISABLE;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_ultimap_pause()
{
#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
	} vmcallinfo;
#pragma pack()

	vmcallinfo.structsize = sizeof(vmcallinfo);
	vmcallinfo.level2pass = vmx_password2;
	vmcallinfo.command = VMCALL_ULTIMAP_PAUSE;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_ultimap_resume()
{
#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
	} vmcallinfo;
#pragma pack()

	vmcallinfo.structsize = sizeof(vmcallinfo);
	vmcallinfo.level2pass = vmx_password2;
	vmcallinfo.command = VMCALL_ULTIMAP_RESUME;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_disable_dataPageFaults()
{
	#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
	} vmcallinfo;
	#pragma pack()

	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_DISABLE_DATAPAGEFAULTS;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

unsigned int vmx_enable_dataPageFaults()
{
	#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
	} vmcallinfo;
	#pragma pack()

	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_ENABLE_DATAPAGEFAULTS;

	return (unsigned int)dovmcall(&vmcallinfo);;
}

UINT_PTR vmx_getLastSkippedPageFault()
{
	#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
	} vmcallinfo;
	#pragma pack()

	vmcallinfo.structsize=sizeof(vmcallinfo);
	vmcallinfo.level2pass=vmx_password2;
	vmcallinfo.command=VMCALL_GETLASTSKIPPEDPAGEFAULT;

	return (UINT_PTR)dovmcall(&vmcallinfo);;
}

unsigned int vmx_add_memory(UINT64 *list, int count)
{
	int r=0;
	int j=0;
#pragma pack(1)
	typedef struct _vmcall_add_memory
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
		UINT64 PhysicalPages[0];
	} AddMemoryInfoCall, *PAddMemoryInfoCall;
#pragma pack()
	PAddMemoryInfoCall vmcallinfo=ExAllocatePool(NonPagedPool, sizeof(AddMemoryInfoCall) + count * sizeof(UINT64));

	DbgPrint("vmx_add_memory(%p,%d)\n", list, count);
	DbgPrint("vmx_add_memory(vmx_password1=%x,vmx_password2=%x)\n", vmx_password1, vmx_password2);

	DbgPrint("structsize at offset %d\n", (UINT64)(&vmcallinfo->structsize) - (UINT64)vmcallinfo);
	DbgPrint("level2pass at offset %d\n", (UINT64)(&vmcallinfo->level2pass) - (UINT64)vmcallinfo);
	DbgPrint("command at offset %d\n", (UINT64)(&vmcallinfo->command) - (UINT64)vmcallinfo);
	DbgPrint("PhysicalPages[0] at offset %d\n", (UINT64)(&vmcallinfo->PhysicalPages[0]) - (UINT64)vmcallinfo);
	DbgPrint("PhysicalPages[1] at offset %d\n", (UINT64)(&vmcallinfo->PhysicalPages[1]) - (UINT64)vmcallinfo);

	__try
	{
		int i;
		vmcallinfo->structsize = sizeof(AddMemoryInfoCall) + count * sizeof(UINT64);
		DbgPrint("vmcallinfo->structsize=%d\n", vmcallinfo->structsize);
		vmcallinfo->level2pass = vmx_password2;
		vmcallinfo->command = VMCALL_ADD_MEMORY;
		j = 1;
		for (i = 0; i < count; i++)
		{
			vmcallinfo->PhysicalPages[i] = list[i];
		}
		j = 2;

		r = (unsigned int)dovmcall(vmcallinfo);
		j = 3;
	}
	__except (1)
	{
		DbgPrint("vmx_add_memory(%p,%d) gave an exception at part %d with exception code %x\n", list, count, j, GetExceptionCode());

		r = 0x100;
	}

	ExFreePool(vmcallinfo);
	return r;

}

int vmx_causedCurrentDebugBreak()
{
#pragma pack(1)
	struct
	{
		unsigned int structsize;
		unsigned int level2pass;
		unsigned int command;
	} vmcallinfo;
#pragma pack()

	vmcallinfo.structsize = sizeof(vmcallinfo);
	vmcallinfo.level2pass = vmx_password2;
	vmcallinfo.command = VMCALL_CAUSEDDEBUGBREAK;

	return (int)dovmcall(&vmcallinfo);;
}

void vmx_init_dovmcall(int isIntel)
{
	if (isIntel)
		(void *)dovmcall=(void *)dovmcall_intel;
	else
		(void *)dovmcall=(void *)dovmcall_amd;

}
