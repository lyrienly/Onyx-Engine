#include <windef.h>

#ifdef AMD64
#define PAGETABLEBASE 0xfffff68000000000ULL

#else
#define PAGETABLEBASE 0xc0000000
#endif

typedef struct _ADDRESSENTRY {
DWORD Address;
BYTE  size;
BOOLEAN frozen;
PVOID frozendata;
} ADDRESSENTRY;

typedef struct _MEMREGION
{
	DWORD BaseAddress;
	DWORD Size;
} MEMREGION;

typedef struct _MEMSCANOPTIONS
{
BYTE ShowAsSigned;
BYTE BinariesAsDecimal;
WORD max;
DWORD buffersize;
BYTE skip_page_no_cache;
BYTE UseDebugRegs;
BYTE UseDBKQueryMemoryRegion;
BYTE UseDBKReadWriteMemory;
BYTE UseDBKOpenProcess;
} MEMSCANOPTIONS;
MEMSCANOPTIONS MemscanOptions;

typedef struct _SCANDATA {
PEPROCESS process;
DWORD Start;
DWORD Stop;
BYTE Vartype;
BYTE Scantype;
BYTE ScanOptions;
BYTE scanvaluelength;
char *scanvalue;
BOOLEAN scanning;
BOOLEAN ThreadActive;
} SCANDATA;

SCANDATA CurrentScan;

typedef struct
{
	UINT64 StartAddress;
	UINT64 EndAddress;
} PRANGE, *PPRANGE;

typedef struct
{
	PRANGE Range;
	void *Next;
} PENTRY, *PPENTRY;

#ifdef CETC
BOOLEAN FirstScan(PEPROCESS ActivePEPROCESS, DWORD start,DWORD stop,BYTE vartype,BYTE scantype,BYTE scanvaluesize,char *scanvalue,BYTE ScanOptions);
#endif

NTSTATUS ReadPhysicalMemory(char *startaddress, UINT_PTR bytestoread, void *output);
BOOLEAN ReadProcessMemory(DWORD PID,PEPROCESS PEProcess,PVOID Address,DWORD Size, PVOID Buffer);
BOOLEAN WriteProcessMemory(DWORD PID,PEPROCESS PEProcess,PVOID Address,DWORD Size, PVOID Buffer);
BOOLEAN IsAddressSafe(UINT_PTR StartAddress);
BOOLEAN GetMemoryRegionData(DWORD PID,PEPROCESS PEProcess, PVOID mempointer,ULONG *regiontype, UINT_PTR *memorysize,UINT_PTR *baseaddress);
NTSTATUS markAllPagesAsNeverAccessed(PEPROCESS PEProcess);
int enumAllAccessedPages(PEPROCESS PEProcess);
int getAccessedPageList(PPRANGE List, int ListSizeInBytes);

UINT_PTR getPageTableBase();

UINT_PTR getPEThread(UINT_PTR threadid);

ADDRESSENTRY *AddressList;
unsigned int AddressListSize;
unsigned int AddressListEntries;
KSPIN_LOCK AddressListSpinlock;

PVOID FrozenData;
int FrozenDataSize;
LARGE_INTEGER FreezeInterval;
HANDLE addressfile;
HANDLE valuefile;

BOOLEAN HiddenDriver;

#define SO_FASTSCAN		(0x1)
#define SO_HEXADECIMAL	(0x2)
#define SO_READONLY		(0x4)
#define SO_FINDONLYONE	(0x8)
#define SO_ISBINARY		(0x10)
#define SO_UNICODE		(0x20)

#define  ST_Exact_value			0
#define  ST_Increased_value		1
#define  ST_Increased_value_by	2
#define  ST_Decreased_value		3
#define  ST_Decreased_value_by	4
#define  ST_Changed_value		5
#define  ST_Unchanged_value		6
#define  ST_Advanced_Scan		7
#define  ST_String_Scan			8
#define  ST_SmallerThan			9
#define  ST_BiggerThan			10
#define  ST_Userdefined			11

#define SE_IncorrectType -1
#define SE_NotSupported -2
#define SE_NoMemoryFound -3
