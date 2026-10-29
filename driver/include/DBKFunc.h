#ifndef DBKFUNC_H
#define DBKFUNC_H

#pragma warning( disable: 4214 )

#include <ntifs.h>
#include <ntstrsafe.h>

#include <windef.h>
#include <ntimage.h>

#ifndef NonPagedPoolNx
#define NonPagedPoolNx 512
#endif

#ifndef DBK_POOL_NX
#define DBK_POOL_NX NonPagedPoolNx
#endif

#pragma pack(1)
typedef struct tagINT_VECTOR
{
	WORD	wLowOffset;
	WORD	wSelector;
	BYTE	bUnused;
	BYTE    bAccessFlags;
	WORD	wHighOffset;
#ifdef AMD64
	DWORD	TopOffset;
	DWORD	Reserved;
#endif
} INT_VECTOR, *PINT_VECTOR;
#pragma pack()

#pragma pack(2)
typedef struct tagIDT
{
    WORD wLimit;
	PINT_VECTOR vector;
} IDT, *PIDT;
#pragma pack()

void GetIDT(PIDT pIdt);

#ifdef RELEASE
#define DbgPrint(...)
#endif

int _fltused;

typedef VOID F(UINT_PTR param);
typedef F *PF;

typedef VOID PREDPC_CALLBACK(CCHAR cpunr, PKDEFERRED_ROUTINE Dpc, PVOID DeferredContext, PVOID *SystemArgument1, PVOID *SystemArgument2);

typedef PREDPC_CALLBACK *PPREDPC_CALLBACK;

typedef struct _criticalSection
{
  LONG locked;
  int cpunr;
  int lockcount;
  int oldIFstate;
} criticalSection, *PcriticalSection;

typedef
_Function_class_(KNORMAL_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KNORMAL_ROUTINE(
	_In_opt_ PVOID NormalContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
);
typedef KNORMAL_ROUTINE *PKNORMAL_ROUTINE;

typedef
_Function_class_(KKERNEL_ROUTINE)
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(APC_LEVEL)
_IRQL_requires_(APC_LEVEL)
_IRQL_requires_same_
VOID
KKERNEL_ROUTINE(
	_In_ struct _KAPC *Apc,
	_Inout_ PKNORMAL_ROUTINE *NormalRoutine,
	_Inout_ PVOID *NormalContext,
	_Inout_ PVOID *SystemArgument1,
	_Inout_ PVOID *SystemArgument2
);
typedef KKERNEL_ROUTINE *PKKERNEL_ROUTINE;

typedef
_Function_class_(KRUNDOWN_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KRUNDOWN_ROUTINE(
	_In_ struct _KAPC *Apc
);
typedef KRUNDOWN_ROUTINE *PKRUNDOWN_ROUTINE;

typedef
_IRQL_requires_same_
_Function_class_(KENUM_ROUTINE)
VOID
KENUM_ROUTINE(
	_In_reads_(_Inexpressible_(Length)) PVOID Data,
	_In_ ULONG Length,
	_In_ PVOID Context
);

typedef KENUM_ROUTINE *PKENUM_ROUTINE;

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

NTKERNELAPI
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeEnumerateQueueApc(
	_Inout_ PKTHREAD Thread,
	_In_ PKENUM_ROUTINE CallbackRoutine,
	_In_ PVOID Context,
	_In_opt_ KPROCESSOR_MODE *ApcMode
);

NTKERNELAPI
_IRQL_requires_same_
_When_(Environment != OriginalApcEnvironment, __drv_reportError("Caution: "
	"Using an APC environment other than the original environment can lead to "
	"a system bugcheck if the target thread is attached to a process with APCs "
	"disabled. APC environments should be used with care."))
	VOID
	KeInitializeApc(
		_Out_ PRKAPC Apc,
		_In_ PRKTHREAD Thread,
		_In_ KAPC_ENVIRONMENT Environment,
		_In_ PKKERNEL_ROUTINE KernelRoutine,
		_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
		_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
		_In_opt_ KPROCESSOR_MODE ProcessorMode,
		_In_opt_ PVOID NormalContext
	);

NTKERNELAPI
_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
BOOLEAN
KeInsertQueueApc(
	_Inout_ PRKAPC Apc,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	_In_ KPRIORITY Increment
);

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenThread(
	OUT PHANDLE             ThreadHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PCLIENT_ID           ClientId
);

struct PTEStruct
{
	unsigned P         :  1;
	unsigned RW        :  1;
	unsigned US        :  1;
	unsigned PWT       :  1;
	unsigned PCD       :  1;
	unsigned A         :  1;
	unsigned Reserved  :  1;
	unsigned PS        :  1;
	unsigned G         :  1;
	unsigned A1		   :  1;
	unsigned A2		   :  1;
	unsigned A3		   :  1;
	unsigned PFN       : 20;
};

struct PTEStruct64
{
	unsigned long long P : 1;
	unsigned long long RW : 1;
	unsigned long long US : 1;
	unsigned long long PWT : 1;
	unsigned long long PCD : 1;
	unsigned long long A : 1;
	unsigned long long Reserved : 1;
	unsigned long long PS : 1;
	unsigned long long G : 1;
	unsigned long long A1 : 1;
	unsigned long long A2 : 1;
	unsigned long long A3 : 1;
	unsigned long long PFN : 52;
};

typedef struct tagDebugregs
{
	ULONG DR0;
	ULONG DR1;
	ULONG DR2;
	ULONG DR3;
	ULONG DR5;
	ULONG DR6;
	ULONG DR7;
} Debugregs;

typedef struct
{
	unsigned CF			:1;
	unsigned reserved1	:1;
	unsigned PF			:1;
	unsigned reserved2	:1;
	unsigned AF			:1;
	unsigned reserved3	:1;
	unsigned ZF			:1;
	unsigned SF			:1;
	unsigned TF			:1;
	unsigned IF			:1;
	unsigned DF			:1;
	unsigned OF			:1;
	unsigned IOPL		:2;
	unsigned NT			:1;
	unsigned reserved4	:1;
	unsigned RF			:1;
	unsigned VM			:1;
	unsigned AC			:1;
	unsigned VIF		:1;
	unsigned VIP		:1;
	unsigned ID			:1;
	unsigned reserved5	:10;
#ifdef AMD64
	unsigned reserved6	:8;
	unsigned reserved7	:8;
	unsigned reserved8	:8;
	unsigned reserved9	:8;
#endif
} EFLAGS,*PEFLAGS;

typedef struct tagDebugReg7
{
	unsigned L0			:1;
	unsigned G0			:1;
	unsigned L1			:1;
	unsigned G1			:1;
	unsigned L2			:1;
	unsigned G2			:1;
	unsigned L3			:1;
	unsigned G3			:1;
	unsigned GL			:1;
	unsigned GE			:1;
	unsigned undefined_1: 1;
	unsigned RTM		: 1;
	unsigned undefined_0: 1;
	unsigned GD			:1;
	unsigned undefined2	:2;
	unsigned RW0		:2;
	unsigned LEN0		:2;
	unsigned RW1		:2;
	unsigned LEN1		:2;
	unsigned RW2		:2;
	unsigned LEN2		:2;
	unsigned RW3		:2;
	unsigned LEN3		:2;
#ifdef AMD64
	unsigned undefined3	:8;
	unsigned undefined4	:8;
	unsigned undefined5	:8;
	unsigned undefined6	:8;
#endif
} DebugReg7;

typedef struct DebugReg6
{
	unsigned B0			:1;
	unsigned B1			:1;
	unsigned B2			:1;
	unsigned B3			:1;
	unsigned undefined1	:9;
	unsigned BD			:1;
	unsigned BS			:1;
	unsigned BT			:1;
	unsigned RTM       : 1;
	unsigned undefined2	:15;
#ifdef AMD64
	unsigned undefined3	:8;
	unsigned undefined4	:8;
	unsigned undefined5	:8;
	unsigned undefined6	:8;
#endif
} DebugReg6;

#pragma pack(2)
typedef struct tagGDT
{
    WORD wLimit;
	PVOID vector;
} GDT, *PGDT;
#pragma pack()

void GetIDT(PIDT pIdt);

#ifdef AMD64
extern void _fxsave(volatile void *);
extern void GetGDT(PGDT pGdt);
extern WORD GetLDT();
extern WORD GetTR(void);
#else
void GetGDT(PGDT pGdt);
WORD GetLDT();
WORD GetTR(void);
#endif

UINT64 readMSR(DWORD msr);
UINT64 getDR7(void);
void setCR0(UINT64 newCR0);
UINT64 getCR0(void);
UINT64 getCR2(void);
void setCR3(UINT64 newCR3);
UINT64 getCR3(void);
UINT64 getCR4(void);
void setCR4(UINT64 newcr4);
UINT64 getTSC(void);

#ifdef AMD64

extern WORD getCS(void);
extern WORD getSS(void);
extern WORD getDS(void);
extern WORD getES(void);
extern WORD getFS(void);
extern WORD getGS(void);
extern UINT64 getRSP(void);
extern UINT64 getRBP(void);
extern UINT64 getRAX(void);
extern UINT64 getRBX(void);
extern UINT64 getRCX(void);
extern UINT64 getRDX(void);
extern UINT64 getRSI(void);
extern UINT64 getRDI(void);
#else
WORD getCS(void);
WORD getSS(void);
WORD getDS(void);
WORD getES(void);
WORD getFS(void);
WORD getGS(void);
ULONG getRSP(void);
ULONG getRBP(void);
ULONG getRAX(void);
ULONG getRBX(void);
ULONG getRCX(void);
ULONG getRDX(void);
ULONG getRSI(void);
ULONG getRDI(void);
#endif

extern UINT64 getR8(void);
extern UINT64 getR9(void);
extern UINT64 getR10(void);
extern UINT64 getR11(void);
extern UINT64 getR12(void);
extern UINT64 getR13(void);
extern UINT64 getR14(void);
extern UINT64 getR15(void);

extern UINT64 getAccessRights(UINT64 segment);
extern UINT64 getSegmentLimit(UINT64 segment);

int getCpuCount(void);

BOOL loadedbydbvm;
int PTESize;
UINT_PTR PAGE_SIZE_LARGE;
UINT_PTR MAX_PDE_POS;
UINT_PTR MAX_PTE_POS;

int cpu_stepping;
int cpu_model;
int cpu_familyID;
int cpu_type;
int cpu_ext_modelID;
int cpu_ext_familyID;

int KernelCodeStepping;
int KernelWritesIgnoreWP;

int isPrefix(unsigned char b);
EFLAGS getEflags(void);
int cpunr(void);
void disableInterrupts(void);
void enableInterrupts(void);

void csEnter(PcriticalSection CS);
void csLeave(PcriticalSection CS);

void forOneCpu(CCHAR cpunr, PKDEFERRED_ROUTINE dpcfunction, PVOID DeferredContext, PVOID  SystemArgument1, PVOID  SystemArgument2, OPTIONAL PPREDPC_CALLBACK preDPCCallback);
void forEachCpu(PKDEFERRED_ROUTINE dpcfunction, PVOID DeferredContext, PVOID  SystemArgument1, PVOID  SystemArgument2, OPTIONAL PPREDPC_CALLBACK preDPCCallback);
void forEachCpuAsync(PKDEFERRED_ROUTINE dpcfunction, PVOID DeferredContext, PVOID  SystemArgument1, PVOID  SystemArgument2, OPTIONAL PPREDPC_CALLBACK preDPCCallback);
void forEachCpuPassive(PF f, UINT_PTR param);

NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
VOID HideDriverFromLoadedModuleList(PDRIVER_OBJECT DriverObject);
UINT64 GetProcessCR3(PEPROCESS Process);

typedef struct _VAD_MODULE_ENTRY {
    UINT64 BaseAddress;
    UINT64 ModuleSize;
    WCHAR  ModuleName[64];
    WCHAR  FullPath[260];
} VAD_MODULE_ENTRY, *PVAD_MODULE_ENTRY;

typedef struct _VAD_ENUM_OUTPUT {
    ULONG Count;
    VAD_MODULE_ENTRY Modules[1];
} VAD_ENUM_OUTPUT, *PVAD_ENUM_OUTPUT;

NTSTATUS EnumerateProcessVadModules(PEPROCESS Process, PVAD_MODULE_ENTRY ModuleBuffer, ULONG MaxModules, PULONG OutCount);

#ifndef MM_COPY_MEMORY_PHYSICAL
#define MM_COPY_MEMORY_PHYSICAL 0x1
#define MM_COPY_MEMORY_VIRTUAL  0x2

typedef struct _MM_COPY_ADDRESS {
    union {
        PVOID VirtualAddress;
        PHYSICAL_ADDRESS PhysicalAddress;
    };
} MM_COPY_ADDRESS, *PMM_COPY_ADDRESS;

NTKERNELAPI
NTSTATUS
NTAPI
MmCopyMemory(
    _Out_ PVOID TargetAddress,
    _In_ MM_COPY_ADDRESS SourceAddress,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Flags,
    _Out_ PSIZE_T NumberOfBytesTransferred
);
#endif

void InitDynamicKernelOffsets(void);
VOID InitializeSafePhysicalRanges(VOID);
BOOLEAN IsPhysicalAddressSafe(ULONG64 PhysAddr, SIZE_T Size);
ULONG ResolveDirectoryTableBaseOffset(void);
ULONG ResolveUserDirectoryTableBaseOffset(PEPROCESS Process);
ULONG64 TranslateVirtualToPhysicalWithCr3(ULONG64 cr3, ULONG64 VirtualAddress);

ULONG64 TranslateVirtualToPhysicalCR3(PEPROCESS Process, ULONG64 VirtualAddress);
BOOLEAN ReadProcessMemoryPhysicalCR3(PEPROCESS Process, ULONG64 VirtualAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead);
BOOLEAN BulkDumpProcessMemoryPhysicalCR3(PEPROCESS Process, ULONG64 VirtualAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesDumped);
BOOLEAN StealthReadProcessMemoryPTE(PEPROCESS Process, ULONG64 VirtualAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead);
ULONG StripProcessCallbacks(BOOLEAN Restore);
ULONG PatternScanProcessCR3(PEPROCESS Process, ULONG64 StartAddress, ULONG64 ScanSize, const UCHAR* Pattern, const UCHAR* Mask, ULONG PatternLength, PULONG64 Matches, ULONG MaxMatches);
NTSTATUS FreezeProcess(PEPROCESS Process, BOOLEAN Freeze);
ULONG ResolveProcessProtectionOffset(VOID);
NTSTATUS SetProcessProtection(PEPROCESS Process, BOOLEAN Enable);
NTSTATUS CleanKernelTraces(VOID);
NTSTATUS CloakDeviceSymlink(PCWSTR NewSymlinkName);
ULONG PhysicalRamScavenge(ULONG64 StartPhysAddr, ULONG64 MaxBytesToScan, const UCHAR* Pattern, const UCHAR* Mask, ULONG PatternLength, PULONG64 Matches, ULONG MaxMatches, PULONG64 NextPhysAddr);
BOOLEAN WriteProcessMemoryPhysicalCR3(PEPROCESS Process, ULONG64 VirtualAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesWritten);

typedef struct _MEMORY_BASIC_INFORMATION64 {
    ULONGLONG BaseAddress;
    ULONGLONG AllocationBase;
    DWORD     AllocationProtect;
    DWORD     __alignment1;
    ULONGLONG RegionSize;
    DWORD     State;
    DWORD     Protect;
    DWORD     Type;
    DWORD     __alignment2;
} MEMORY_BASIC_INFORMATION64, *PMEMORY_BASIC_INFORMATION64;

NTSTATUS CloakProcessPage(PEPROCESS Process, ULONG64 VirtualAddress);
NTSTATUS UncloakProcessPage(PEPROCESS Process, ULONG64 VirtualAddress);
NTSTATUS WriteCloakedPageMemory(PEPROCESS Process, ULONG64 VirtualAddress, PVOID Buffer, ULONG Size);
NTSTATUS CloakRegionMemory(PEPROCESS Process, ULONG64 VirtualAddress, PVOID Buffer, ULONG Size);

NTSTATUS QueryProcessMemoryVad(PEPROCESS Process, ULONG64 VirtualAddress, PMEMORY_BASIC_INFORMATION64 MemoryInfo);
NTSTATUS HideProcessByPid(ULONG ProcessId);

#endif
