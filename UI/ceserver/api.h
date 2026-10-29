#ifndef API_H_
#define API_H_

#include <stdint.h>
#include <pthread.h>
#include <sys/queue.h>

#include "porthelp.h"
#include "context.h"

#include <sys/ptrace.h>

#ifdef __ANDROID__
  #include<android/log.h>
#endif

#ifdef HAS_LINUX_USER_H
  #include <linux/user.h>
#else
  #include <sys/user.h>
#endif

#include <sys/uio.h>

#define VQE_PAGEDONLY 1
#define VQE_DIRTYONLY 2
#define VQE_NOSHARED 4

typedef struct
{
  unsigned long long baseAddress;
  uint32_t fileOffset;
  int part;
  int is64bit;
  int moduleSize;
  char *moduleName;
} ModuleListEntry, *PModuleListEntry;

typedef struct
{
  int PID;
  char *ProcessName;

} ProcessListEntry, *PProcessListEntry;

typedef struct
{
  int ReferenceCount;
  int processListIterator;
  int processCount;
  PProcessListEntry processList;
} ProcessList, *PProcessList;

typedef struct
{
  int ReferenceCount;
  int moduleListIterator;
  int moduleCount;
  PModuleListEntry moduleList;
} ModuleList, *PModuleList;

typedef struct
{
  int ReferenceCount;
  int threadListIterator;
  int threadCount;
  int *threadList;
} ThreadList, *PThreadList;

typedef struct
{
  int socket;
  char* pipename;
} PipeData, *PPipeData;

#pragma pack(1)

typedef struct
{
  uint8_t num_brps;
  uint8_t num_wrps;
  uint8_t wp_len;
  uint8_t debug_arch;

} HBP_RESOURCE_INFO, *PHBP_RESOURCE_INFO;

#ifdef __arm__

#endif

typedef struct {
  int debugevent;
  int64_t threadid;
  union
  {
    uint64_t address;
    struct {
      uint8_t maxBreakpointCount;
      uint8_t maxWatchpointCount;
      uint8_t maxSharedBreakpoints;
    };
  };

} DebugEvent, *PDebugEvent;

struct DebugEventQueueElement {
  TAILQ_ENTRY(DebugEventQueueElement) entries;
  DebugEvent de;
};

#pragma pack()

TAILQ_HEAD(debugEventQueueHead, DebugEventQueueElement);

typedef struct {
  int tid;
  int isPaused;
  int suspendCount;
  DebugEvent suspendedDevent;
} ThreadData, *PThreadData;

typedef struct {
  int ReferenceCount;
  int pid;
  int is64bit;
  int mapfd;
  char *path;
  char *maps;
  int mem;
  int memrw;
  int hasLoadedExtension;
  int neverForceLoadExtension;
  pthread_mutex_t extensionMutex;
  int extensionFD;

  int isDebugged;
  pthread_t debuggerThreadID;

  PThreadData threadlist;
  int threadlistmax;
  int threadlistpos;

  DebugEvent debuggedThreadEvent;

  int debuggerServer;
  int debuggerClient;

  pthread_mutex_t debugEventQueueMutex;

  struct debugEventQueueHead debugEventQueue;

  uintptr_t dlopen;
  uintptr_t dlerror;
  int dlopenalt;
  uintptr_t dlopencaller;
  uintptr_t mmap;
} ProcessData, *PProcessData;

#pragma pack(1)
typedef struct {
  uint64_t baseaddress;
  uint64_t size;
  uint32_t protection;
  uint32_t type;
} RegionInfo, *PRegionInfo;
#pragma pack()

#if defined __i386__ || defined __x86_64__
typedef struct _regDR6
{
  union{
    uintptr_t value;
    struct {
      unsigned B0        :1;
      unsigned B1        :1;
      unsigned B2        :1;
      unsigned B3        :1;
      unsigned Reserved  :9;
      unsigned BD        :1;
      unsigned BS        :1;
      unsigned BT        :1;
    };
  };
} __attribute__((__packed__)) regDR6,*PregDR6;
#endif

typedef ssize_t (*PROCESS_VM_READV)(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
typedef ssize_t (*PROCESS_VM_WRITEV)(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);

extern PROCESS_VM_READV process_vm_readv;
extern PROCESS_VM_WRITEV process_vm_writev;

void CloseHandle(HANDLE h);
BOOL Process32Next(HANDLE hSnapshot, PProcessListEntry processentry);
BOOL Process32First(HANDLE hSnapshot, PProcessListEntry processentry);
BOOL Module32First(HANDLE hSnapshot, PModuleListEntry moduleentry);
BOOL Module32Next(HANDLE hSnapshot, PModuleListEntry moduleentry);
HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
HANDLE OpenProcess(DWORD pid);
int VirtualQueryEx(HANDLE hProcess, void *lpAddress, PRegionInfo rinfo, char *mapsline);
int VirtualQueryExFull(HANDLE hProcess, uint32_t flags, RegionInfo **rinfo, uint32_t *count);
int ReadProcessMemory(HANDLE hProcess, void *lpAddress, void *buffer, int size);
int WriteProcessMemory(HANDLE hProcess, void *lpAddress, void *buffer, int size);

int StartDebug(HANDLE hProcess);
int StopDebug(HANDLE hProcess);

int WaitForDebugEventNative(PProcessData p, PDebugEvent devent, int tid, int timeout);
int WaitForDebugEvent(HANDLE hProcess, PDebugEvent devent, int timeout);
int ContinueFromDebugEvent(HANDLE hProcess, int tid, int ignoresignal);
int GetDebugPort(HANDLE hProcess);

int getArchitecture(HANDLE hProcess);

int SetBreakpoint(HANDLE hProcess, int tid, int debugreg, void *address, int bptype, int bpsize);
int RemoveBreakpoint(HANDLE hProcess, int tid, int debugreg, int wasWatchpoint);

int SuspendThread(HANDLE hProcess, int tid);
int ResumeThread(HANDLE hProcess, int tid);

BOOL GetThreadContext(HANDLE hProcess, int tid, PCONTEXT Context);
BOOL SetThreadContext(HANDLE hProcess, int tid, PCONTEXT Context);

PDebugEvent FindThreadDebugEventInQueue(PProcessData p, int tid);
void AddDebugEventToQueue(PProcessData p, PDebugEvent devent);
int RemoveThreadDebugEventFromQueue(PProcessData p, int tid);

int ptrace_attach_andwait(int pid);

int WakeDebuggerThread();
int windowsProtectionToLinux(uint32_t windowsprotection);
uint32_t linuxProtectionToWindows(int prot);

HANDLE OpenPipe(char *pipename, int timeout);
int ReadPipe(HANDLE ph, void* destination, int size, int timeout);
int WritePipe(HANDLE ph, void* source, int size, int timeout);
void CloseAllPipes();

uint64_t getTickCount();

void initAPI();

extern pthread_mutex_t debugsocketmutex;

#ifdef __ANDROID__
  #define LOG_TAG "CESERVER"
  #define LOGD(fmt, args...) __android_log_vprint(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
#endif

int debug_log(const char * format , ...);
uintptr_t safe_ptrace(int request, pid_t pid, void * addr, void * data);
extern int ATTACH_TO_ACCESS_MEMORY;
extern int ATTACH_TO_WRITE_MEMORY;
extern int MEMORY_SEARCH_OPTION;
extern int ATTACH_PID;
extern unsigned char SPECIFIED_ARCH;
#endif
