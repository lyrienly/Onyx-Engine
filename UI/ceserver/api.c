#define TRACEPTRACE

#define _FILE_OFFSET_BITS 64
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#include <stdio.h>
#include <pthread.h>

#include <sys/mman.h>

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <stdint.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>

#include <strings.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <signal.h>

#ifdef __ANDROID__

#ifndef SUN_LEN
# include <string.h>

# define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path)        \
          + strlen ((ptr)->sun_path))
#endif
#if defined (__arm__) || defined(__aarch64__)
#include <arm-linux-androideabi/asm/ptrace.h>
#endif
#endif

#ifndef __x86_64__

#endif

#include <sys/eventfd.h>

#include <errno.h>

#include <semaphore.h>
#include <sys/queue.h>
#include <limits.h>

#include <sys/ptrace.h>

#include <linux/elf.h>

#ifdef __arm__
  #ifndef __ANDROID__
    #include <linux/user.h>
  #endif
#endif

#include <dlfcn.h>

#define PTRACE_GETHBPREGS 29
#define PTRACE_SETHBPREGS 30

#define ARM_BREAKPOINT_EXECUTE  0

#define ARM_BREAKPOINT_LOAD     1
#define ARM_BREAKPOINT_STORE    2

#define ARM_BREAKPOINT_PRIV     1
#define ARM_BREAKPOINT_USER     2

#define ARM_BREAKPOINT_LEN_1    0x1
#define ARM_BREAKPOINT_LEN_2    0x3
#define ARM_BREAKPOINT_LEN_4    0xf
#define ARM_BREAKPOINT_LEN_8    0xff

#if defined (__arm__) || defined(__aarch64__)
static inline unsigned int encode_ctrl_reg(int mismatch, int len, int type, int privilege, int enabled)
{
        return (mismatch << 22) | (len << 5) | (type << 3) | (privilege << 1) | enabled;
}
#endif

#ifndef __ANDROID__
  #if defined(__i386__) || defined(__x86_64__)
    #include <sys/user.h>
  #endif
#endif

#include "api.h"
#include "porthelp.h"
#include "ceserver.h"
#include "threads.h"
#include "symbols.h"
#include "context.h"

PROCESS_VM_WRITEV process_vm_writev=NULL;
PROCESS_VM_READV process_vm_readv=NULL;

sem_t sem_DebugThreadEvent;

pthread_mutex_t memorymutex;
pthread_mutex_t debugsocketmutex;

int VerboseLevel=0;

int MEMORY_SEARCH_OPTION = 2;
int ATTACH_PID = 0;
int ATTACH_TO_ACCESS_MEMORY = 0;
int ATTACH_TO_WRITE_MEMORY = 1;
unsigned char SPECIFIED_ARCH = 9;

#ifndef SYS_process_vm_readv
  #if defined(__aarch64__)
    #define SYS_process_vm_readv 270
    #define SYS_process_vm_writev 271
  #elif defined(__arm__)
    #define SYS_process_vm_readv 376
    #define SYS_process_vm_writev 377
  #elif defined(__x86_64__)
    #define SYS_process_vm_readv 310
    #define SYS_process_vm_writev 311
  #elif defined(__i386__)
    #define SYS_process_vm_readv 347
    #define SYS_process_vm_writev 348
  #endif
#endif

#ifdef SYS_process_vm_readv

ssize_t process_vm_readv2(pid_t process_id, const struct iovec *io_local, unsigned long liovcnt, const struct iovec *io_remote, unsigned long riovcnt, unsigned long flags) {
    if (process_id < 0) return FALSE;
    return syscall(SYS_process_vm_readv, process_id, io_local, liovcnt, io_remote, riovcnt, flags);
}

ssize_t process_vm_writev2(pid_t process_id, const struct iovec *io_local, unsigned long liovcnt, const struct iovec *io_remote, unsigned long riovcnt, unsigned long flags) {
    if (process_id < 0) return FALSE;
    return syscall(SYS_process_vm_writev, process_id, io_local, liovcnt, io_remote, riovcnt, flags);
}
#endif

int debug_log(const char * format , ...)
{
  va_list list;
  va_start(list,format);
  int ret = vprintf(format,list);
  va_end(list);

  #ifdef __ANDROID__
  va_start(list,format);
  LOGD(format,list);
  va_end(list);
  #endif

  return ret;
}

#ifdef TRACEPTRACE
char *PTraceToString(int request)
{
  switch (request)
  {
    case PTRACE_ATTACH: return "PTRACE_ATTACH";
    case PTRACE_DETACH: return "PTRACE_DETACH";
    case PTRACE_PEEKDATA: return "PTRACE_PEEKDATA";
    case PTRACE_POKEDATA: return "PTRACE_POKEDATA";
    case PTRACE_CONT: return "PTRACE_CONT";
    case PTRACE_GETSIGINFO: return "PTRACE_GETSIGINFO";
    case PTRACE_GETREGSET: return "PTRACE_GETREGSET";
    case PTRACE_SINGLESTEP: return "PTRACE_SINGLESTEP";
    case PTRACE_SETREGS: return "PTRACE_SETREGS";
    case PTRACE_GETREGS: return "PTRACE_GETREGS";
    case PTRACE_GETFPREGS: return "PTRACE_GETFPREGS";
#ifdef PT_GETFPXREGS
    case PTRACE_GETFPXREGS: return "PTRACE_GETFPXREGS";
#endif
    default:
      return "";

  }
}
#endif

uintptr_t safe_ptrace(int request, pid_t pid, void * addr, void * data)
{
#ifdef TRACEPTRACE

  if (threadname)
    debug_log("%s: ptrace called (%s(%x), %d, %p, %p)\n",threadname, PTraceToString(request),request, pid, addr, data);
  else
    debug_log("ptrace called (%s(%x), %d, %p, %p)\n",PTraceToString(request),request, pid, addr, data);

#endif
  uintptr_t result;
  errno = 0;
  result = ptrace(request, pid, addr, data);
  if(errno != 0)
  {
    debug_log("ptrace error(%s (%d))!\n",strerror(errno), errno);
  }
  return result;
}

int ptrace_attach_andwait(int pid)

{
  if (safe_ptrace(PTRACE_ATTACH, pid,0,0)==0)
  {
    int status;
    while (1)
    {
      pid=waitpid(-1, &status,0);
      if (WIFSTOPPED(status))
      {
        if (WSTOPSIG(status)==SIGSTOP)
          return pid;

        debug_log("ptrace_attach_andwait:Received stop with signal %d instead of %d\n", WSTOPSIG(status), SIGSTOP);
        safe_ptrace(PTRACE_CONT, pid, (void*)0, (void*)(uint64_t)WSTOPSIG(status));
        continue;
      }

      if (WIFCONTINUED(status))
      {
        debug_log("ptrace_attach_andwait:It already continued?\n");
        continue;
      }

      if (WIFEXITED(status))
      {
        debug_log("ptrace_attach_andwait:Target terminated with code %d\n", WEXITSTATUS(status));
        return -2;
      }

      if (WIFSIGNALED(status))
      {
        debug_log("trace_attach_andwait:Target received a ");

        if (WTERMSIG(status))
          debug_log("terminate signal");

        if (WCOREDUMP(status))
          debug_log("core Dump");

        debug_log("\n");
        return -3;
      }

      debug_log("ptrace_attach_andwait: Unexpected status: %x\n", status);
      return -4;
    }

  }
  else
  {
    debug_log("ptrace_attach_andwait: ptrace attach failed\n");
    return -1;
  }

}

int WakeDebuggerThread()
{
  return sem_post(&sem_DebugThreadEvent);
}

void mychildhandler(int signal, struct siginfo *info, void *context)
{

  int orig_errno = errno;
  WakeDebuggerThread();
  errno = orig_errno;
}

int windowsProtectionToLinux(uint32_t windowsprotection)
{
  int newprotection=0;
  switch (windowsprotection)
  {
    case PAGE_EXECUTE_READWRITE: newprotection=PROT_WRITE | PROT_READ | PROT_EXEC; break;
    case PAGE_EXECUTE_READ: newprotection=PROT_READ | PROT_EXEC; break;
    case PAGE_EXECUTE: newprotection=PROT_EXEC; break;
    case PAGE_READWRITE: newprotection=PROT_READ | PROT_WRITE; break;
    case PAGE_READONLY: newprotection=PROT_READ; break;
    default:
      newprotection=0;
  }

  return newprotection;
}

uint32_t linuxProtectionToWindows(int prot)
{
  int r=0, w=0, x=0;

  r=prot & PROT_READ;
  w=prot & PROT_WRITE;
  x=prot & PROT_EXEC;

  if (r && w && x)
    return PAGE_EXECUTE_READWRITE;

  if (r && x)
    return PAGE_EXECUTE_READ;

  if (x)
     return PAGE_EXECUTE;

  if (r && w)
    return PAGE_READWRITE;

  if (r)
    return PAGE_READONLY;

  return PAGE_NOACCESS;

}

int getArchitecture(HANDLE hProcess)
{
  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);
    if (p->is64bit)
#if defined (__arm__) || defined(__aarch64__)
      return 3;
    else
      return 2;
#else
      return 1;
    else
      return 0;
#endif
  }

  return -1;
}

int GetDebugPort(HANDLE hProcess)

{
  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);
    if (p->isDebugged)
    {
      return p->debuggerServer;
    }
  }

  return -1;

}

int FindPausedThread(PProcessData p)

{
  int i;
  for (i=0; i<p->threadlistpos; i++)
    if (p->threadlist[i].isPaused)
      return p->threadlist[i].tid;

  return 0;
}

int getBreakpointCapabilities(int tid, uint8_t *maxBreakpointCount, uint8_t *maxWatchpointCount, uint8_t *maxSharedBreakpoints)

{

  *maxBreakpointCount=0;
  *maxWatchpointCount=0;
  *maxSharedBreakpoints=0;

#ifdef __arm__
  HBP_RESOURCE_INFO hwbpcap;

  memset(&hwbpcap, 0, sizeof(HBP_RESOURCE_INFO));
  if (safe_ptrace(PTRACE_GETHBPREGS, tid, 0, &hwbpcap)==0)
  {

    *maxBreakpointCount=hwbpcap.num_brps;
    *maxWatchpointCount=hwbpcap.num_wrps;
    *maxSharedBreakpoints=0;

    return 1;
  }
  else
    return 0;
#endif

#ifdef __aarch64__
  struct iovec iov;
  struct user_hwdebug_state hwd;
  memset(&hwd, 0, sizeof(hwd));

  iov.iov_base=&hwd;
  iov.iov_len=sizeof(hwd);

  if (safe_ptrace(PTRACE_GETREGSET, tid, (void*)NT_ARM_HW_WATCH, &iov)==0)
  {
    debug_log("NT_ARM_HW_WATCH: dbg_info=%x:\n", hwd.dbg_info);
    *maxWatchpointCount=hwd.dbg_info & 0xf;
  }
  else
  {
    debug_log("NT_ARM_HW_WATCH: Failure getting watch breakpoint information\n");
    *maxWatchpointCount=0;
  }

  iov.iov_base=&hwd;
  iov.iov_len=sizeof(hwd);
  if (safe_ptrace(PTRACE_GETREGSET, tid, (void*)NT_ARM_HW_BREAK, &iov)==0)
  {
    debug_log("NT_ARM_HW_BREAK: dbg_info=%x:\n", hwd.dbg_info);
    *maxBreakpointCount=hwd.dbg_info & 0xf;
  }
  else
  {
    debug_log("NT_ARM_HW_BREAK: Failure getting breakpoint information\n");
    *maxBreakpointCount=0;
  }

  return 1;
#endif

#if defined(__i386__) || defined(__x86_64__)
  *maxBreakpointCount=0;
  *maxWatchpointCount=0;
  *maxSharedBreakpoints=4;
  return 1;
#endif
}

int StartDebug(HANDLE hProcess)
{
  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);

    struct sigaction childactionhandler;
    if (p->isDebugged)
    {
      debug_log("Trying to start debugging a process that is already debugged. (Close ceserver and try again if you had to force close CE earlier)\n");
    }

    InitializeProcessThreadlist(p);

    memset(&childactionhandler, 0, sizeof(childactionhandler));
    childactionhandler.sa_handler=(void *)mychildhandler;
    childactionhandler.sa_flags=SA_SIGINFO;

    sigaction(SIGCHLD, &childactionhandler, NULL);

    char _taskdir[255];
    DIR *taskdir;

    sprintf(_taskdir, "/proc/%d/task", p->pid);

    taskdir=opendir(_taskdir);

    if (taskdir)
    {
      struct dirent *d;

      d=readdir(taskdir);
      while (d)
      {
        int tid=atoi(d->d_name);

        if (tid)
        {
          ThreadData td;
          memset(&td, 0, sizeof(td));
          td.tid=tid;
          td.isPaused=0;
          AddThreadToProcess(p, &td);

          pthread_mutex_lock(&memorymutex);

          if (safe_ptrace(PTRACE_ATTACH, tid,0,0)<0)
            debug_log("Failed to attach to thread %d\n", tid);
          else
          {
            DebugEvent createThreadEvent;

            if (p->isDebugged==0)
            {
              p->isDebugged=1;
              p->debuggedThreadEvent.threadid=0;
              p->debuggerThreadID=pthread_self();

              threadname="CEServer Debugger Thread";

              socketpair(PF_LOCAL, SOCK_STREAM, 0, &p->debuggerServer);

              DebugEvent createProcessEvent;

#if defined(__arm__) || defined (__aarch64__)

              if (WaitForDebugEventNative(p, &createProcessEvent, tid, -1))
              {

                getBreakpointCapabilities(tid, &createProcessEvent.maxBreakpointCount, &createProcessEvent.maxWatchpointCount, &createProcessEvent.maxSharedBreakpoints);

                debug_log("hwbpcap:\n");
                debug_log("number of instruction breakpoints: %d\n", createProcessEvent.maxBreakpointCount);
                debug_log("number of data breakpoints:        %d\n", createProcessEvent.maxWatchpointCount);

                safe_ptrace(PTRACE_CONT, createProcessEvent.threadid, 0,0);

                PThreadData _td=GetThreadData(p, createProcessEvent.threadid);

                if (_td)
                  _td->isPaused=0;
                else
                  debug_log("Invalid first debug thread\n");
              }
              else
              {
                debug_log("Failure waiting for create event");
                createProcessEvent.maxBreakpointCount=0;
                createProcessEvent.maxWatchpointCount=0;
                createProcessEvent.maxSharedBreakpoints=4;
              }

#endif

#if defined(__i386__) || defined(__x86_64__)

              createProcessEvent.maxBreakpointCount=0;
              createProcessEvent.maxWatchpointCount=0;
              createProcessEvent.maxSharedBreakpoints=4;
#endif

              createProcessEvent.debugevent=-2;
              createProcessEvent.threadid=p->pid;

              AddDebugEventToQueue(p, &createProcessEvent);

            }

            createThreadEvent.debugevent=-1;
            createThreadEvent.threadid=tid;
            AddDebugEventToQueue(p, &createThreadEvent);

          }

          pthread_mutex_unlock(&memorymutex);

        }

        d=readdir(taskdir);
      }

      closedir(taskdir);

    }
    else
    {
      debug_log("Failure opening %s",_taskdir);
    }

    return p->isDebugged;

  }
  else
  {

    return FALSE;
  }

}

int SetBreakpoint(HANDLE hProcess, int tid, int debugreg, void *address, int bptype, int bpsize)

{
  int result=FALSE;

  debug_log("SetBreakpoint(%d, %d, %d, %p, %d, %d)\n", hProcess, tid, debugreg, address, bptype, bpsize);
  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);

    if (p->debuggerThreadID==pthread_self())
    {

      int isdebugged=FindPausedThread(p);
      int wtid;
      DebugEvent de;

      debug_log("SetBreakpoint from debuggerthread\n");

      if (tid==-1)
      {
        int i,r;
        debug_log("Calling SetBreakpoint for all threads\n");

        for (i=0; i<p->threadlistpos; i++)
        {
          r=SetBreakpoint(hProcess, p->threadlist[i].tid, debugreg, address, bptype, bpsize);
          if (r)
            result=TRUE;
        }

      }
      else
      {
        PThreadData td=GetThreadData(p, tid);
        int wasPaused;

        if (td==NULL)
          return FALSE;

        wasPaused=td->isPaused;

        debug_log("Calling setbreakpoint for thread :%d\n", tid);

        debug_log("isdebugged=%d\n", isdebugged);

        if (wasPaused==0)
        {

          debug_log("Target thread wasn't stopped yet\n");

          int k=0;

          debug_log("td=%p\n", td);
          debug_log("td->isPaused=%d\n", td->isPaused);

          wtid=tid;
          while ((td) && (td->isPaused==0) && (k<10))
          {
            debug_log("Not yet paused\n");
            syscall(__NR_tkill, tid, SIGSTOP);

            if (WaitForDebugEventNative(p, &de, tid, 100))
            {
              wtid=de.threadid;
              break;
            }
            k++;
          }

          if (wtid!=tid)
          {
            debug_log("<<<================UNEXPECTED TID (wtid=%d tid=%d)================>>>\n", wtid, tid);
          }

          debug_log("k=%d (number of tries)\n", k);

          if (k==10)
          {
            debug_log("Timeout when waiting for thread\n");
          }
        }
        else
        {
          debug_log("The thread I wanted to break was already broken. Yeeeh\n");
          wtid=isdebugged;
        }

        debug_log("Setting breakpoint in thread %d\n", wtid);
#ifdef __aarch64__
        struct user_pt_regs regset;

        int armbpsize=ARM_BREAKPOINT_LEN_4;

        struct iovec iov;
        int maxWatchCount=0;
        int maxBreakCount=0;

        debug_log("ceserver compiled for aarch64\n");

        memset(&regset, 0, sizeof(regset));
        memset(&iov, 0, sizeof(iov));
        iov.iov_base=&regset;
        iov.iov_len=sizeof(regset);
        int i=safe_ptrace(PTRACE_GETREGSET, wtid, (void*)NT_PRSTATUS, &iov);

        debug_log("PTRACE_GETREGSET returned %d\n", i);
        debug_log("iov.iov_len=%d\n", (int)iov.iov_len);

        if (iov.iov_len==72)
        {
          struct pt_regs32 {
            uint32_t uregs[18];
          };

          struct pt_regs32 *regset32;

          regset32=iov.iov_base;
          debug_log("This is a 32 bit target\n");

          debug_log("pc=%x\n", regset32->ARM_pc);
          debug_log("r0 orig=%x\n", regset32->ARM_ORIG_r0);
          debug_log("r0=%x\n", regset32->ARM_r0);
          debug_log("r1=%x\n", regset32->ARM_r1);
          debug_log("r2=%x\n", regset32->ARM_r2);

          int i;
          for (i=0; i<18; i++)
            debug_log("uregs[%d]=%x\n", i, regset32->uregs[i]);

          if (((uintptr_t)address) & 1)
          {
            armbpsize=ARM_BREAKPOINT_LEN_2;
            address=(void *)((uintptr_t)address & 0xfffffffe);
          }

        }
        else
        {
          debug_log("pc=%lx\n", regset.pc);
          debug_log("x0=%llx\n", regset.regs[0]);
          debug_log("x1=%llx\n", regset.regs[1]);
          debug_log("x2=%llx\n", regset.regs[2]);
          debug_log("x3=%llx\n", regset.regs[3]);
        }

        struct user_hwdebug_state hwd;
        memset(&hwd, 0, sizeof(hwd));

        iov.iov_base=&hwd;
        iov.iov_len=sizeof(hwd);
        i=safe_ptrace(PTRACE_GETREGSET, wtid, (void*)NT_ARM_HW_WATCH, &iov);

        if (i==0)
          maxWatchCount=hwd.dbg_info & 0xf;

        debug_log("iov.iov_len=%d\n", (int)iov.iov_len);
        debug_log("PTRACE_GETREGSET for NT_ARM_HW_WATCH returned %d %d\n", i,errno);

        iov.iov_base=&hwd;
        iov.iov_len=sizeof(hwd);
        i=safe_ptrace(PTRACE_GETREGSET, wtid, (void*)NT_ARM_HW_BREAK, &iov);
        if (i==0)
          maxBreakCount=hwd.dbg_info & 0xf;

        debug_log("PTRACE_GETREGSET for NT_ARM_HW_BREAK returned %d %d\n", i,errno);

        debug_log("iov.iov_len=%d\n", (int)iov.iov_len);

        int btype=0;
        int bplist=NT_ARM_HW_BREAK;

        int listsize;

        if (bptype==0)
        {

          debug_log("Execute BP\n");
          bplist=NT_ARM_HW_BREAK;

          btype=ARM_BREAKPOINT_EXECUTE;
          listsize=maxBreakCount;

        }
        else
        {

          debug_log("Watchpoint\n");
          bplist=NT_ARM_HW_WATCH;
          if (bptype==1)
            btype=ARM_BREAKPOINT_STORE;
          else
          if (bptype==2)
            btype=ARM_BREAKPOINT_LOAD;
          else
          if (bptype==3)
            btype=ARM_BREAKPOINT_STORE | ARM_BREAKPOINT_LOAD;

          listsize=maxWatchCount;

          if (bpsize<=1)
            armbpsize=ARM_BREAKPOINT_LEN_1;
          else if (bpsize<=2)
            armbpsize=ARM_BREAKPOINT_LEN_2;
          else if (bpsize<=4)
            armbpsize=ARM_BREAKPOINT_LEN_4;
          else
            armbpsize=ARM_BREAKPOINT_LEN_8;
        }

        debug_log("Caling PTRACE_GETREGSET for bplist %d\n", bplist);
        debug_log("iov.iov_len=%d\n", iov.iov_len);
        i=safe_ptrace(PTRACE_GETREGSET, wtid, (void*)(size_t)bplist, &iov);

        debug_log("PTRACE_GETREGSET returned %d\n", i);

        debug_log("debugreg=%d\n", debugreg);
        debug_log("Before:\n");

        iov.iov_len=8+16*listsize;

        for (i=0; i<listsize; i++)
        {
          if (hwd.dbg_regs[i].addr)
          {
            if (bplist==NT_ARM_HW_BREAK)
              hwd.dbg_regs[i].ctrl=encode_ctrl_reg(0, ARM_BREAKPOINT_LEN_2, ARM_BREAKPOINT_EXECUTE, 0, 1);
            else
              hwd.dbg_regs[i].ctrl=hwd.dbg_regs[i].ctrl | 1;
          }

          if (i==debugreg) debug_log("*");
          debug_log("%p - %x\n", (void*)hwd.dbg_regs[i].addr, hwd.dbg_regs[i].ctrl);
        }

        hwd.dbg_regs[debugreg].addr=(uintptr_t)address;
        hwd.dbg_regs[debugreg].ctrl=encode_ctrl_reg(0, armbpsize, btype, 0, 1);

        debug_log("setting hwd.dbg_regs[%d].addr to %p\n",debugreg, hwd.dbg_regs[debugreg].addr);
        debug_log("setting hwd.dbg_regs[%d].ctrl to %x\n",debugreg, hwd.dbg_regs[debugreg].ctrl);

        debug_log("iov.iov_len=%d\n", iov.iov_len);

        debug_log("Caling PTRACE_SETREGSET\n", bplist);

        i=safe_ptrace(PTRACE_SETREGSET, wtid, (void*)(size_t)bplist, &iov);

        debug_log("set=%d",i);
        if (i==-1)
        {
          debug_log(" Error=%s",strerror(errno));

        }
        else
          result=TRUE;

        debug_log("\n");

        memset(&hwd, 0, sizeof(hwd));

        i=safe_ptrace(PTRACE_GETREGSET, wtid, (void*)(size_t)bplist, &iov);

        debug_log("after:\n");
        if (bplist==NT_ARM_HW_BREAK)
        {
          int i;
          for (i=0; i<maxBreakCount; i++)
          {
            if (i==debugreg) debug_log("*");
            debug_log("%p - %x\n", (void*)hwd.dbg_regs[i].addr, hwd.dbg_regs[i].ctrl);
          }
        }
        else
        {
          int i;
          for (i=0; i<maxWatchCount; i++)
          {
            if (i==debugreg) debug_log("*");
            debug_log("%p - %x\n", (void*)hwd.dbg_regs[i].addr, hwd.dbg_regs[i].ctrl);
          }
        }

#endif

#ifdef __arm__

        unsigned long long val;
        int bpindex=1+(2*debugreg);

        debug_log("PTRACE_GETHBPREGS=%d\n",PTRACE_GETHBPREGS);

        val=0;

        if (safe_ptrace(PTRACE_GETHBPREGS, wtid, 0, &val)==0)
        {
          int i;
          unsigned int hwbpreg;
          debug_log("BPREG0 (Info)=%x\n", val);

          debug_log("Setting bp address\n");

          if (bptype==0)
          {

            void *rv=NULL;

            i=safe_ptrace(PTRACE_GETHBPREGS, wtid, bpindex, &rv);
            debug_log("%d: Before: %d=%p\n", i, bpindex, rv);

            i=safe_ptrace(PTRACE_SETHBPREGS, wtid, bpindex, &address);
            debug_log("i1=%d\n", i, hwbpreg);

            i=safe_ptrace(PTRACE_GETHBPREGS, wtid, bpindex, &rv);
            debug_log("%d: After: %d=%p\n", i, bpindex, rv);

            result=i==0;

            hwbpreg=encode_ctrl_reg(0, ARM_BREAKPOINT_LEN_4, ARM_BREAKPOINT_EXECUTE, 2, 1);
            if (safe_ptrace(PTRACE_SETHBPREGS, wtid, bpindex+1, &hwbpreg)<0)
            {
              debug_log("f1\n");
              hwbpreg=encode_ctrl_reg(0, ARM_BREAKPOINT_LEN_2, ARM_BREAKPOINT_EXECUTE, 2, 1);
              if (safe_ptrace(PTRACE_SETHBPREGS, wtid, bpindex+1, &hwbpreg)<0)
              {
                debug_log("f2\n");
                hwbpreg=encode_ctrl_reg(0, ARM_BREAKPOINT_LEN_1, ARM_BREAKPOINT_EXECUTE, 2, 1);
                if (safe_ptrace(PTRACE_SETHBPREGS, wtid, bpindex+1, &hwbpreg)<0)
                {
                  debug_log("f3\n");

                  hwbpreg=encode_ctrl_reg(0, ARM_BREAKPOINT_LEN_8, ARM_BREAKPOINT_EXECUTE, 2, 1);
                  if (safe_ptrace(PTRACE_SETHBPREGS, wtid, bpindex+1, &hwbpreg)<0)
                  {
                    debug_log("Failure to set breakpoint\n");
                    result=FALSE;
                  }
                }

              }
            }

            debug_log("bpindex=%d bpindex+1=%d\n", bpindex, bpindex+1);

            debug_log("hwbpreg=%x\n", hwbpreg);

            i=safe_ptrace(PTRACE_GETHBPREGS, wtid, bpindex+1, &hwbpreg);
            debug_log("after=%x\n", hwbpreg);

          }
          else
          {

            int btype;

            debug_log("watchpoint\n");

            i=safe_ptrace(PTRACE_SETHBPREGS, wtid, -bpindex, &address);
            debug_log("i1=%d\n", i, hwbpreg);

            btype=0;
            if (bptype==1)
              btype=ARM_BREAKPOINT_STORE;
            else
            if (bptype==2)
              btype=ARM_BREAKPOINT_LOAD;
            else
            if (bptype==3)
              btype=ARM_BREAKPOINT_STORE | ARM_BREAKPOINT_LOAD;

            hwbpreg=encode_ctrl_reg(0, ARM_BREAKPOINT_LEN_4, btype, 0, 1);
            i=safe_ptrace(PTRACE_SETHBPREGS, wtid, -(bpindex+1), &hwbpreg);

            debug_log("-bpindex=%d -(bpindex+1)=%d\n", -bpindex, -(bpindex+1));

            result=i==0;

          }

        }
        else
          debug_log("Failure getting the debug capability register for thread %d (%d)\n", wtid, errno);

#endif

#if defined(__i386__) || defined(__x86_64__)

        int r,r2;

        uintptr_t newdr7=safe_ptrace(PTRACE_PEEKUSER, wtid, (void *)(offsetof(struct user, u_debugreg[7])), 0);

        newdr7=newdr7 | (1<<debugreg*2);

        if (bptype==2)
          bptype=3;

        newdr7=newdr7 | (bptype << (16+(debugreg*4)));

        debug_log("Setting DR7 to %x\n", newdr7);

        if (bpsize<=1)
          newdr7=newdr7 | (0 << (18+(debugreg*4)));
        else
        if (bpsize<=2)
          newdr7=newdr7 | (1 << (18+(debugreg*4)));
        else
          newdr7=newdr7 | (3 << (18+(debugreg*4)));

        r=safe_ptrace(PTRACE_POKEUSER, wtid, (void*)(offsetof(struct user, u_debugreg[debugreg])), address);
        r2=safe_ptrace(PTRACE_POKEUSER, wtid, (void*)(offsetof(struct user, u_debugreg[7])), (void*)newdr7);

        result=(r==0) && (r2==0);
        if (!result)
        {
          debug_log("Failure setting breakpoint\n");
        }

        debug_log("result=%d  (r=%d r2=%d)\n", result, r, r2);

#endif

        if (wasPaused==0)
        {
          int r;

          debug_log("Continue self broken thread\n");

          if (de.debugevent!=SIGSTOP)
          {
            debug_log("Not a SIGSTOP. Adding to queue and leave suspended\n");
            td->isPaused=1;
            AddDebugEventToQueue(p, &de);
          }
          else
          {
            td->isPaused=0;
            r=safe_ptrace(PTRACE_CONT, wtid, 0,0);
            debug_log("PTRACE_CONT=%d\n", r);
          }
        }
      }

      debug_log("end of SetBreakpoint reached. result=%d\n", result);

    }
    else
    {

      debug_log("SetBreakpoint from outside the debuggerthread. Waking debuggerthread\n");

  #pragma pack(1)
      struct
      {
        char command;
        HANDLE hProcess;
        int tid;
        int debugreg;
        uint64_t address;
        int bptype;
        int bpsize;
      } sb;
  #pragma pack()

      sb.command=CMD_SETBREAKPOINT;
      sb.hProcess=hProcess;
      sb.tid=tid;
      sb.debugreg=debugreg;
      sb.address=(uintptr_t)address;
      sb.bptype=bptype;
      sb.bpsize=bpsize;

      if (pthread_mutex_lock(&debugsocketmutex) == 0)
      {
        debug_log("Sending message to the debuggerthread\n");

        sendall(p->debuggerClient, &sb, sizeof(sb), 0);
        WakeDebuggerThread();
        recvall(p->debuggerClient, &result, sizeof(result), MSG_WAITALL);

        debug_log("Received reply from debugger thread: %d\n", result);

        pthread_mutex_unlock(&debugsocketmutex);
      }

    }

  }
  else
  {

  }

  return result;

}

int RemoveBreakpoint(HANDLE hProcess, int tid, int debugreg,int wasWatchpoint)

{
  int result=FALSE;

  debug_log("RemoveBreakpoint(%d, %d, %d, %d)\n", hProcess, tid, debugreg, wasWatchpoint);
  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);
    if (p->isDebugged==0)
    {
      debug_log("The current process is not being debugged\n");
      return FALSE;
    }

    if (p->debuggerThreadID==pthread_self())
    {
      int isdebugged=p->debuggedThreadEvent.threadid;
      int wtid;
      DebugEvent de;

      debug_log("Called from the debuggerthread itself\n");

      if (tid==-1)
      {
        int i;
        debug_log("Calling RemoveBreakpoint for all threads\n");
        for (i=0; i<p->threadlistpos; i++)
        {
          if (RemoveBreakpoint(hProcess, p->threadlist[i].tid, debugreg, wasWatchpoint)==TRUE)
            result=TRUE;
        }
      }
      else
      {
        debug_log("specific thread\n");

        PThreadData td=GetThreadData(p, tid);
        int wasPaused=td->isPaused;

        if (wasPaused==0)
        {

          debug_log("Not currently paused\n");
          debug_log("Going to kill and wait for this thread\n");

          int k;

          k=0;
          while ((td) && (td->isPaused==0) && (k<10))
          {
            syscall(__NR_tkill, tid, SIGSTOP);
            if (WaitForDebugEventNative(p, &de, tid, 100))
              break;
            k++;
          }

          wtid=de.threadid;

          debug_log("----AFTER WAIT----\n");

          debug_log("after wtid=%d\n", wtid);
          debug_log("^^^^AFTER WAIT^^^^\n");
        }
        else
        {
          debug_log("The thread I wanted to break was already broken. Yeeeh\n");
          wtid=isdebugged;
        }

        debug_log("Removing breakpoint from thread %d\n", wtid);

#ifdef __arm__
        int bpreg=0;
        int i,i2,i3;
        void *a=NULL;

        int bpIndex=1+(2*debugreg);

        debug_log("arm\n");

        if (wasWatchpoint)
        {
          i=safe_ptrace(PTRACE_SETHBPREGS, wtid, -bpIndex, &bpreg);
          i2=safe_ptrace(PTRACE_SETHBPREGS, wtid, -(bpIndex+1), &bpreg);
        }
        else
        {
          i=safe_ptrace(PTRACE_SETHBPREGS, wtid, bpIndex, &bpreg);
          i2=safe_ptrace(PTRACE_SETHBPREGS, wtid, bpIndex+1, &bpreg);
        }

        debug_log("i1=%d\n", i);

        debug_log("i2=%d\n", i2);

        i3=safe_ptrace(PTRACE_SETHBPREGS, wtid, 1, &a);

        result=(i==0) && (i2==0) && (i3==0);
#endif

#ifdef __aarch64__
        int i;
        struct user_hwdebug_state hwd;
        struct iovec iov;

        memset(&hwd, 0, sizeof(hwd));
        memset(&iov, 0, sizeof(iov));
        iov.iov_base=&hwd;
        iov.iov_len=sizeof(hwd);

        int bplist;

        if (wasWatchpoint)
          bplist=NT_ARM_HW_WATCH;
        else
          bplist=NT_ARM_HW_BREAK;

        i=safe_ptrace(PTRACE_GETREGSET, wtid, (void*)(size_t)bplist, &iov);
        if (i!=0)
          debug_log("PTRACE_GETREGSET failed\n");

        int listsize=hwd.dbg_info & 0xf;

        for (i=0; i<listsize; i++)
        {
          if (hwd.dbg_regs[i].addr)
          {
            if (bplist==NT_ARM_HW_BREAK)
              hwd.dbg_regs[i].ctrl=encode_ctrl_reg(0, ARM_BREAKPOINT_LEN_2, ARM_BREAKPOINT_EXECUTE, 0, 1);
            else
              hwd.dbg_regs[i].ctrl= hwd.dbg_regs[i].ctrl | 1;
          }

          if (i==debugreg) debug_log("*");
          debug_log("%p - %x\n", (void*)hwd.dbg_regs[i].addr, hwd.dbg_regs[i].ctrl);
        }

        if (debugreg<listsize)
        {
          hwd.dbg_regs[debugreg].addr=0;
          hwd.dbg_regs[debugreg].ctrl=0;

          iov.iov_len=8+16*(hwd.dbg_info & 0xf);

          i=safe_ptrace(PTRACE_SETREGSET, wtid, (void*)(size_t)bplist, (void*)&iov);
          if (i!=0)
            debug_log("PTRACE_SETREGSET failed :%s\n", strerror(errno));
        }
        else
        {
          debug_log("Error: Tried to remove a breakpoint index out of range\n");
          i=1000;
        }

        result=i;
#endif

#if defined(__i386__) || defined(__x86_64__)
        int r;
        uintptr_t dr7=0;
        debug_log("x86\n");

        dr7=safe_ptrace(PTRACE_PEEKUSER, wtid, (void*)(offsetof(struct user, u_debugreg[7])), 0);

        dr7&=~(3 << (debugreg*2));
        dr7&=~(15 << (16+debugreg*4));

        r=safe_ptrace(PTRACE_POKEUSER, wtid, (void*)(offsetof(struct user, u_debugreg[debugreg])), 0);

        r=safe_ptrace(PTRACE_POKEUSER, wtid, (void*)(offsetof(struct user, u_debugreg[7])), (void*)dr7);
        if (r==0)
          result=TRUE;
        else
          debug_log("Failure removing breakpoint from thread %d\n", wtid);

#endif

        if (wasPaused==0)
        {
          int r;
          PThreadData td=GetThreadData(p, tid);

          debug_log("Continue self broken thread\n");

          if (de.debugevent!=SIGSTOP)
          {
            debug_log("Not a SIGSTOP. Adding to queue and leave suspended\n");
            td->isPaused=1;
            AddDebugEventToQueue(p, &de);
          }
          else
          {
            r=safe_ptrace(PTRACE_CONT, wtid, 0,0);
            debug_log("PTRACE_CONT=%d\n", r);

            td->isPaused=0;
          }
        }

      }

    }
    else
    {
      debug_log("Called from a secondary thread\n");
#pragma pack(1)
      struct
      {
        char command;
        HANDLE hProcess;
        int tid;
        int debugreg;
        int wasWatchpoint;
      } rb;
#pragma pack()

      rb.command=CMD_REMOVEBREAKPOINT;
      rb.hProcess=hProcess;
      rb.tid=tid;
      rb.debugreg=debugreg;
      rb.wasWatchpoint=wasWatchpoint;

      if (pthread_mutex_lock(&debugsocketmutex) == 0)
      {

        debug_log("Sending message to the debuggerthread\n");

        sendall(p->debuggerClient, &rb, sizeof(rb), 0);
        WakeDebuggerThread();
        recvall(p->debuggerClient, &result, sizeof(result), MSG_WAITALL);

        pthread_mutex_unlock(&debugsocketmutex);
      }

    }

  }
  else
    debug_log("Invalid handle\n");

  fflush(stdout);

  return result;
}

BOOL GetThreadContext(HANDLE hProcess, int tid, PCONTEXT Context)

{
  BOOL r=FALSE;
  debug_log("GetThreadContext(%d)\n", tid);

  if (tid<=0)
  {
    debug_log("Invalid tid\n");
    return FALSE;
  }

  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);

    if (!p->isDebugged)
    {
      debug_log("GetThreadContext with no debugger attached\n");
      int pid=ptrace_attach_andwait(tid);
      int k=getContext(pid, Context);

      safe_ptrace(PTRACE_DETACH, pid,0,0);
      if (k==0)
        return TRUE;
      else
        return FALSE;
    }

    if (p->debuggerThreadID==pthread_self())
    {
      PThreadData td=GetThreadData(p, tid);

      debug_log("Inside debuggerthread\n");

      if (td)
      {
        DebugEvent de;
        int wasPaused=td->isPaused;
        int k=0;

        while ((td->isPaused==0) && (k<10))
        {
          debug_log("This thread was not paused. Pausing it\n");
          syscall(__NR_tkill, tid, SIGSTOP);
          if (WaitForDebugEventNative(p, &de, tid, 100))
            break;

          k++;
        }

        debug_log("Getting context of thread %d\n", tid);

        k=getContext(tid, Context);

        debug_log("getRegisters() returned %d\n", k);

        if (k==0)
          r=TRUE;
        else
          r=FALSE;

        if (!wasPaused)
        {

          PThreadData td=GetThreadData(p, tid);

          debug_log("The thread was not paused, so resuming it now\n");

          if (de.debugevent!=SIGSTOP)
          {
            debug_log("Not a SIGSTOP. Adding to queue and leave suspended\n");
            td->isPaused=1;
            AddDebugEventToQueue(p, &de);

          }
          else
          {
            r=(r && (safe_ptrace(PTRACE_CONT, de.threadid, 0,0)==0));

            td->isPaused=0;
            debug_log("r=%d\n", r);
          }
        }

      }
      else
        debug_log("Invalid tid\n");

    }
    else
    {
      debug_log("Not the debugger thread. Pass to serverthread");
#pragma pack(1)
      struct
      {
        char command;
        HANDLE hProcess;
        int tid;
      } gtc;
#pragma pack()

      gtc.command=CMD_GETTHREADCONTEXT;
      gtc.hProcess=hProcess;
      gtc.tid=tid;

      if (pthread_mutex_lock(&debugsocketmutex) == 0)
      {
        debug_log("Sending message to the debuggerthread\n");

        sendall(p->debuggerClient, &gtc, sizeof(gtc), 0);
        WakeDebuggerThread();
        recvall(p->debuggerClient, &r, sizeof(r), MSG_WAITALL);

        debug_log("Returned from the debuggerthread.  result=%d\n",r);

        if (r)
        {

          uint32_t structsize;
          recvall(p->debuggerClient, &structsize, sizeof(structsize), MSG_WAITALL);
          debug_log("structsize received from p->debuggerClient=%d\n", structsize);

          recvall(p->debuggerClient, Context, structsize, MSG_WAITALL);

          debug_log("context->structsize received from p->debuggerClient=%d\n",Context->structsize);
        }

        pthread_mutex_unlock(&debugsocketmutex);
      }

    }
  }
  else
    debug_log("invalid handle\n");

  return r;
}

BOOL SetThreadContext(HANDLE hProcess, int tid, PCONTEXT Context)
{
  BOOL r=FALSE;
  debug_log("SetThreadContext(%d)\n", tid);

  if (tid<=0)
  {
    debug_log("Invalid tid\n");
    return FALSE;
  }

  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);

    if (p->debuggerThreadID==pthread_self())
    {
        PThreadData td=GetThreadData(p, tid);

        debug_log("Inside debuggerthread\n");

        if (td)
        {
          DebugEvent de;
          int wasPaused=td->isPaused;
          int k=0;

          while ((td->isPaused==0) && (k<10))
          {
            debug_log("This thread was not paused. Pausing it\n");
            syscall(__NR_tkill, tid, SIGSTOP);
            if (WaitForDebugEventNative(p, &de, tid, 100))
              break;

            k++;
          }

          k=setContext(tid, Context);

          debug_log("setRegisters() returned %d\n", k);

          if (k==0)
            r=TRUE;
          else
            r=FALSE;

          if (!wasPaused)
          {

            PThreadData td=GetThreadData(p, tid);

            debug_log("The thread was not paused, so resuming it now\n");

            if (de.debugevent!=SIGSTOP)
            {
              debug_log("Not a SIGSTOP. Adding to queue and leave suspended\n");
              td->isPaused=1;
              AddDebugEventToQueue(p, &de);
            }
            else
            {
              r=(r && (safe_ptrace(PTRACE_CONT, de.threadid, 0,0)==0));

              td->isPaused=0;
              debug_log("r=%d\n", r);
            }
          }

        }
        else
          debug_log("Invalid tid\n");

      }
    }
    else
      debug_log("invalid handle\n");

    return r;
}

int SuspendThread(HANDLE hProcess, int tid)

{
  int result=-1;

  debug_log("SuspendThread(%d)\n", tid);
  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);
    PThreadData t=GetThreadData(p, tid);

    if (t==NULL)
    {
      debug_log("Invalid thread\n");
      return -1;
    }

    if (p->debuggerThreadID==pthread_self())
    {

      debug_log("Inside the debugger thread.\n");

      if (t->isPaused)
      {
        debug_log("Already paused\n");

        if (t->suspendCount==0)
        {

          if (p->debuggedThreadEvent.threadid==tid)
            t->suspendedDevent=p->debuggedThreadEvent;
          else
          {

            t->suspendedDevent=*FindThreadDebugEventInQueue(p,tid);
            RemoveThreadDebugEventFromQueue(p, tid);
          }
        }

        t->suspendCount++;

      }
      else
      {
        debug_log("Not yet paused\n");

        while (t->isPaused==0)
        {
          syscall(__NR_tkill, tid, SIGSTOP);
          if (WaitForDebugEventNative(p, &t->suspendedDevent, tid, 100))
            break;

        }

        t->suspendCount++;

      }

      return t->suspendCount;

    }
    else
    {
      debug_log("Not from the debugger thread. Switching...\n");
#pragma pack(1)
      struct
      {
        char command;
        HANDLE hProcess;
        int tid;
      } st;
#pragma pack()

      st.command=CMD_SUSPENDTHREAD;
      st.hProcess=hProcess;
      st.tid=tid;

      if (pthread_mutex_lock(&debugsocketmutex) == 0)
      {
        sendall(p->debuggerClient, &st, sizeof(st), 0);
        WakeDebuggerThread();
        recvall(p->debuggerClient, &result, sizeof(result), MSG_WAITALL);

        pthread_mutex_unlock(&debugsocketmutex);

      }
    }
  }
  else
  {
    debug_log("invalid handle\n");
    result=-1;
  }

  return result;

}

int ResumeThread(HANDLE hProcess, int tid)

{
  int result=-1;

  debug_log("ResumeThread(%d)\n", tid);
  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);
    PThreadData t=GetThreadData(p, tid);

    if (t==NULL)
    {
      debug_log("Invalid thread\n");
      return -1;
    }

    if (p->debuggerThreadID==pthread_self())
    {

      debug_log("Inside the debugger thread.\n");

      if ((t->isPaused) && (t->suspendCount>0))
      {

        t->suspendCount--;

        result=t->suspendCount;

        if (t->suspendCount==0)
        {

          PThreadData td=GetThreadData(p, tid);
          debug_log("suspeneCount==0\n");

          if (t->suspendedDevent.debugevent==SIGSTOP)
          {
            debug_log("SIGSTOP: Continue thread without queing\n");
            safe_ptrace(PTRACE_CONT, t->suspendedDevent.threadid, 0,0);
            td->isPaused=0;
          }
          else
          {
            debug_log("Not a SIGSTOP Add to the event queue\n");
            td->isPaused=1;
            AddDebugEventToQueue(p, &t->suspendedDevent);
            WakeDebuggerThread();
          }
        }
      }
      else
      {
        debug_log("Failure resuming this thread\n");

      }

    }
    else
    {
      debug_log("Not from the debugger thread. Switching...\n");
#pragma pack(1)
      struct
      {
        char command;
        HANDLE hProcess;
        int tid;
      } rt;
#pragma pack()

      rt.command=CMD_RESUMETHREAD;
      rt.hProcess=hProcess;
      rt.tid=tid;

      if (pthread_mutex_lock(&debugsocketmutex) == 0)
      {
        sendall(p->debuggerClient, &rt, sizeof(rt), 0);
        WakeDebuggerThread();
        recvall(p->debuggerClient, &result, sizeof(result), MSG_WAITALL);

        pthread_mutex_unlock(&debugsocketmutex);
      }
    }
  }
  else
    debug_log("invalid handle\n");

  return result;
}

int RemoveThreadDebugEventFromQueue(PProcessData p, int tid)

{
  int result=FALSE;
  struct DebugEventQueueElement *deqe;

  pthread_mutex_lock(&p->debugEventQueueMutex);

  deqe=p->debugEventQueue.tqh_first;
  while (deqe)
  {

    if (deqe->de.threadid==tid)
    {

      TAILQ_REMOVE(&p->debugEventQueue, deqe, entries);

      free(deqe);
      result=TRUE;
      break;
    }

    deqe=deqe->entries.tqe_next;
  }

  pthread_mutex_unlock(&p->debugEventQueueMutex);
  return result;
}

PDebugEvent FindThreadDebugEventInQueue(PProcessData p, int tid)

{
  PDebugEvent result=NULL;
  struct DebugEventQueueElement *deqe;
  pthread_mutex_lock(&p->debugEventQueueMutex);

  deqe=p->debugEventQueue.tqh_first;
  while (deqe)
  {
    if ((tid==-1) || (deqe->de.threadid==tid))
    {
      result=&deqe->de;
      break;
    }

    deqe=deqe->entries.tqe_next;
  }

  pthread_mutex_unlock(&p->debugEventQueueMutex);
  return result;
}

void AddDebugEventToQueue(PProcessData p, PDebugEvent devent)
{
  struct DebugEventQueueElement *deqe;

  if (devent->debugevent==SIGSTOP)
  {
    debug_log("<<<<<--------------------SIGSTOP ADDED TO THE QUEUE!\n");
  }

  pthread_mutex_lock(&p->debugEventQueueMutex);

  deqe=malloc(sizeof(struct DebugEventQueueElement));
  deqe->de=*devent;

  TAILQ_INSERT_TAIL(&p->debugEventQueue, deqe, entries);

  pthread_mutex_unlock(&p->debugEventQueueMutex);
}

int GetStopSignalFromThread(int tid)
{
  siginfo_t si;

  if (safe_ptrace(PTRACE_GETSIGINFO, tid, NULL, &si)==0)
    return si.si_signo;
  else
    return -1;
}

int WaitForDebugEventNative(PProcessData p, PDebugEvent devent, int tid, int timeout)

{
  int currentTID;
  int status;
  int r;

  currentTID=1;
  while (currentTID>0)
  {
    currentTID=waitpid(tid, &status, __WALL | WNOHANG);

    if (currentTID>0)
    {
      devent->threadid=currentTID;
      devent->debugevent=GetStopSignalFromThread(devent->threadid);

      PThreadData td=GetThreadData(p, currentTID);
      if (td)
        td->isPaused=1;

      if ((tid==-1) || (currentTID==tid))
        return TRUE;

      AddDebugEventToQueue(p, devent);
    }

  }

  if (timeout>=0)
  {

    if (timeout>0)
    {
      struct timespec abstime;
      struct timeval current,wanted, diff;
      int timedwait;

      memset(&abstime, 0, sizeof(abstime));
      gettimeofday(&current,NULL);

      diff.tv_sec=(timeout / 1000);
      diff.tv_usec=(timeout % 1000)*1000;

      timeradd(&current, &diff, &wanted);

      abstime.tv_sec=wanted.tv_sec;
      abstime.tv_nsec=wanted.tv_usec*1000;

      currentTID=-1;
      while (currentTID<=0)
      {
        timedwait=sem_timedwait(&sem_DebugThreadEvent, &abstime);

        if (timedwait==0)
        {

          CheckForAndDispatchCommand(p->debuggerServer);
          if (VerboseLevel>10)
            debug_log("CheckForAndDispatchCommand returned\n");

          PDebugEvent e=FindThreadDebugEventInQueue(p, tid);
          if (e)
          {
            debug_log("There was a queued event after CheckForAndDispatchCommand. TID=%ld (wanted %d)\n", e->threadid, tid);
            currentTID=e->threadid;

            r=RemoveThreadDebugEventFromQueue(p, currentTID);
            debug_log("RemoveThreadDebugEventFromQueue returned %d\n", r);
          }
          else
            currentTID=waitpid(tid, &status, __WALL | WNOHANG);

          if (VerboseLevel>10)
            debug_log("currentTID = %d\n", currentTID);

          if (currentTID>0)
          {
            devent->threadid=currentTID;
            devent->debugevent=GetStopSignalFromThread(devent->threadid);

            PThreadData td=GetThreadData(p, currentTID);
            if (td)
              td->isPaused=1;

            if ((tid==-1) || (currentTID==tid))
              return TRUE;

            debug_log("Still here so currentTID(%d) is not the same as tid (%d)\n", currentTID, tid);
            AddDebugEventToQueue(p, devent);
          }
          currentTID=-1;

        }
        else
        {
          if (errno==ETIMEDOUT)
          {

            return FALSE;
          }

        }
      }
    }
    else
    {

    }

  }
  else
  {

    currentTID=-1;
    while (currentTID<0)
    {
      currentTID=waitpid(tid, &status, __WALL);
      if (currentTID>0)
      {
        devent->threadid=currentTID;
        devent->debugevent=GetStopSignalFromThread(devent->threadid);

        PThreadData td=GetThreadData(p, currentTID);
        if (td)
          td->isPaused=1;

        if ((tid==-1) || (currentTID==tid))
          return TRUE;

        AddDebugEventToQueue(p, devent);
      }

      if ((currentTID==-1) && (errno!=EINTR))
      {
        debug_log("WaitForDebugEventNative: Infinite wait: Could not wait for tid %d (errno=%d)\n", tid, errno);
        return FALSE;
      }

      currentTID=-1;
    }

  }

  return FALSE;

}

int WaitForDebugEvent(HANDLE hProcess, PDebugEvent devent, int timeout)

{

  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);

    if (p->debuggedThreadEvent.threadid==0)
    {

      int isdebugged=FindPausedThread(p);
      if (isdebugged)
      {
        debug_log("Error: WaitForDebugEvent and FindPausedThread returned true and p->debuggedThreadEvent.threadid==0");

        int i;
        for (i=0; i<p->threadlistpos; i++)
        {
          if (p->threadlist[i].isPaused)
          {
            p->threadlist[i].isPaused=0;
            debug_log("suspendcount=%d\n", p->threadlist[i].suspendCount);
            debug_log("suspendedDevent.debugevent=%d\n", p->threadlist[i].suspendedDevent.debugevent);
          }
        }

      }

      int r=0;
      struct DebugEventQueueElement *de=NULL;

      pthread_mutex_lock(&p->debugEventQueueMutex);
      de=TAILQ_FIRST(&p->debugEventQueue);

      if (de)
        TAILQ_REMOVE(&p->debugEventQueue, de, entries);

      pthread_mutex_unlock(&p->debugEventQueueMutex);

      if (de)
      {
        debug_log("Returning queued event (sig=%d,  thread=%ld)\n", de->de.debugevent, de->de.threadid);
        if (de->de.debugevent==SIGSTOP)
        {
          debug_log("<---Something queued a SIGSTOP--->\n");
        }

        *devent=de->de;
        p->debuggedThreadEvent=*devent;
        free(de);

        r=1;
      }

      if (!r)
        r=WaitForDebugEventNative(p, devent, -1, timeout);

      if (r)
      {
        p->debuggedThreadEvent=*devent;

        if (p->debuggedThreadEvent.debugevent==SIGTRAP)
        {
          siginfo_t si;
          memset(&si, 0, sizeof(si));
          debug_log("SIGTRAP\n");

#if (defined(__arm__) || defined(__aarch64__))

          if (safe_ptrace(PTRACE_GETSIGINFO, p->debuggedThreadEvent.threadid, NULL, &si)==0)
          {

            p->debuggedThreadEvent.address=(uintptr_t)si.si_addr;
            debug_log("si.si_addr=%p\n", si.si_addr);
          }
          else
            debug_log("Failure getting siginfo for this trap\n");
#endif

#if defined __i386__ || defined __x86_64__

          uintptr_t DR0,DR1,DR2,DR3,DR7, IP, SP;
          regDR6 DR6;
#if defined __i386__
          IP=safe_ptrace(PTRACE_PEEKUSER, p->debuggedThreadEvent.threadid, offsetof(struct user, regs.eip), 0);
          SP=safe_ptrace(PTRACE_PEEKUSER, p->debuggedThreadEvent.threadid, offsetof(struct user, regs.esp), 0);
#else
          IP=safe_ptrace(PTRACE_PEEKUSER, p->debuggedThreadEvent.threadid, (void*)offsetof(struct user, regs.rip), 0);
          SP=safe_ptrace(PTRACE_PEEKUSER, p->debuggedThreadEvent.threadid, (void*)offsetof(struct user, regs.rsp), 0);
#endif
          DR0=safe_ptrace(PTRACE_PEEKUSER, p->debuggedThreadEvent.threadid, (void*)offsetof(struct user, u_debugreg[0]), 0);
          DR1=safe_ptrace(PTRACE_PEEKUSER, p->debuggedThreadEvent.threadid, (void*)offsetof(struct user, u_debugreg[1]), 0);
          DR2=safe_ptrace(PTRACE_PEEKUSER, p->debuggedThreadEvent.threadid, (void*)offsetof(struct user, u_debugreg[2]), 0);
          DR3=safe_ptrace(PTRACE_PEEKUSER, p->debuggedThreadEvent.threadid, (void*)offsetof(struct user, u_debugreg[3]), 0);

          DR6.value=safe_ptrace(PTRACE_PEEKUSER, p->debuggedThreadEvent.threadid, (void*)offsetof(struct user, u_debugreg[6]), 0);
          DR7=safe_ptrace(PTRACE_PEEKUSER, p->debuggedThreadEvent.threadid, (void*)offsetof(struct user, u_debugreg[7]), 0);

          debug_log("sizeof(dr0)=%d\n", sizeof(DR0));
          debug_log("sizeof(long)=%d\n", sizeof(long));
          debug_log("DR0=%p\n",(void*)DR0);
          debug_log("DR1=%p\n",(void*)DR1);
          debug_log("DR2=%p\n",(void*)DR2);
          debug_log("DR3=%p\n",(void*)DR3);
          debug_log("DR6=%p\n",(void*)(DR6.value));
          debug_log("DR7=%p\n",(void*)DR7);
          debug_log("IP=%p\n",(void*)IP);
          debug_log("SP=%p\n",(void*)SP);

          p->debuggedThreadEvent.address=0;
          if (DR6.B0)
            p->debuggedThreadEvent.address=DR0;
          else
          if (DR6.B1)
            p->debuggedThreadEvent.address=DR1;
          else
          if (DR6.B2)
            p->debuggedThreadEvent.address=DR2;
          else
          if (DR6.B3)
            p->debuggedThreadEvent.address=DR3;
          else
          if (DR6.BS)
            p->debuggedThreadEvent.address=1;

#endif
          debug_log("p->debuggedThreadEvent.address=%lx\n", p->debuggedThreadEvent.address);

          devent->address=p->debuggedThreadEvent.address;
        }
      }

      return r;
    }
    else
    {
      *devent=p->debuggedThreadEvent;
      debug_log("Can not wait for a debug event when a thread is still paused\n");
      debug_log("tid=%d  debugevent=%d\n", (int)devent->threadid, devent->debugevent);
      return 1;
    }

  }
  return 0;
}

int ContinueFromDebugEvent(HANDLE hProcess, int tid, int ignoresignal)
{

  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);
    PThreadData td=GetThreadData(p, tid);
    siginfo_t si;

    if (p->debuggedThreadEvent.debugevent<0)
    {
      debug_log("Virtual event. Ignore\n");
      p->debuggedThreadEvent.threadid=0;
      p->debuggedThreadEvent.debugevent=0;

      if (td)
      {
        debug_log("td->isPaused was %d\n", td->isPaused);
      }

      return 1;
    }

    if (td==NULL)
    {
      debug_log("Invalid thread\n");
      p->debuggedThreadEvent.threadid=0;

      return 0;
    }

    if (td->suspendCount>0)
    {
      debug_log("Tried to continue a suspended thread (suspendcount=%d)\n", td->suspendCount);
      return 1;
    }

    if (safe_ptrace(PTRACE_GETSIGINFO, tid, NULL, &si)==0)
    {
      int signal=ignoresignal?0:si.si_signo;

      if ((signal==19) || (signal==21))
      {
        signal=0;
      }

#if defined __i386__ || defined __x86_64__
      safe_ptrace(PTRACE_POKEUSER, tid, (void*)offsetof(struct user, u_debugreg[6]), 0);
#endif

      int result;
      if (ignoresignal==2)
      {
        debug_log("ContinueFromDebugEvent(): Single step\n");

#ifdef __aarch64__

#endif

        result=safe_ptrace(PTRACE_SINGLESTEP, tid, 0,0);

#ifdef __aarch64__

        if (result==0)
          debug_log("PTRACE_SINGLESTEP returned success\n");

#endif
        if (result!=0)
        {
          debug_log("PTRACE_SINGLESTEP failed (%d). Shit happens\n", errno);
          result=safe_ptrace(PTRACE_CONT, tid, 0,(void*)(size_t)signal);
        }

      }
      else
      {
        result=safe_ptrace(PTRACE_CONT, tid, 0,(void*)(size_t)signal);
      }

      if (td)
        td->isPaused=0;

      if (result<0)
      {
        debug_log("Failure to continue thread %d with signal %d\n", tid, signal);
        RemoveThreadFromProcess(p, tid);
        p->debuggedThreadEvent.threadid=0;
        return 0;
      }
      else
      {
        p->debuggedThreadEvent.threadid=0;
        return 1;
      }
    }
    else
      debug_log("Failure getting sig info\n");

  }
  else
    debug_log("Invalid handle\n");

  return 0;
}

int StopDebug(HANDLE hProcess)
{
  debug_log("StopDebug\n");
  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);
    int i;

    if (p)
    {
      for (i=0; i<p->threadlistpos;i++)
      {
        int tid;
        int status;

        while (1)
        {
          syscall(__NR_tkill, p->threadlist[i].tid, SIGSTOP);
          debug_log("Waiting for thread %d\n", p->threadlist[i].tid);

          tid=waitpid(p->threadlist[i].tid, &status,0);
          if (WIFSTOPPED(status))
          {
            if (WSTOPSIG(status)==SIGSTOP)
            {
              if (tid==p->threadlist[i].tid)
                break;
              else
              {
                debug_log("Got %d instead (status=%x)\n",tid, status);
                safe_ptrace(PTRACE_CONT, tid, 0, 0);
                continue;
              }
            }
            else
            {
              debug_log("It stopped but with a wrong signal (%d)\n", WSTOPSIG(status));

              safe_ptrace(PTRACE_CONT, tid, 0, (void*)(size_t)WSTOPSIG(status));
            }
          }
          else
          {
            tid=0;
            break;
          }
        }

        if (tid)
        {
          debug_log("Detaching %d\n", tid);
          safe_ptrace(PTRACE_DETACH, tid,0,0);
        }
        else
        {
          debug_log("Thread %d was already gone (%x)\n", p->threadlist[i].tid, status);

        }
      }

      p->isDebugged=0;
      if (p->debuggerClient)
      {
        close(p->debuggerClient);
        p->debuggerClient=0;
      }
      if (p->debuggerServer)
      {
        close(p->debuggerServer);
        p->debuggerServer=0;
      }
    }
    else
      debug_log("GetPointerFromHandle failed\n");
  }

  debug_log("after StopDebug\n");
  return 1;

}

int WriteProcessMemoryDebug(HANDLE hProcess, PProcessData p, void *lpAddress, void *buffer, int size)
{
  int byteswritten=0;
  int i;

  if (threadname)
    debug_log("%s: WriteProcessMemoryDebug:",threadname);
  else
    debug_log("WriteProcessMemoryDebug:");

  for (i=0; i<size; i++)
  {
    debug_log("%.2x ", ((unsigned char *)buffer)[i]);
  }

  debug_log("\n");

  if (p->debuggerThreadID==pthread_self())
  {
    int isdebugged=FindPausedThread(p);
    DebugEvent event;

    event.threadid=isdebugged;

    if (!isdebugged)
    {
      debug_log("Not currently debugging a thread. Suspending a random thread\n");
      kill(p->pid, SIGSTOP);

      WaitForDebugEventNative(p, &event, -1, -1);

      debug_log("After WaitForDebugEventNative (tid=%d)\n", event.threadid);
    }
    else
    {
      debug_log("isdebugged=%d\n", isdebugged);

    }

    {
      int offset=0;
      int max=size-sizeof(long int);

      long int *address=(long int *)buffer;

      while (offset<max)
      {
        debug_log("offset=%d max=%d\n", offset, max);
        safe_ptrace(PTRACE_POKEDATA, event.threadid, (void*)((uintptr_t)lpAddress+offset), (void *)*address);

        address++;
        offset+=sizeof(long int);
        byteswritten+=sizeof(long int);
      }

      if (offset<size)
      {
        debug_log("WPMD: Still some bytes left: %d\n", size-offset);

        uintptr_t oldvalue=0;
        oldvalue=safe_ptrace(PTRACE_PEEKDATA, event.threadid,  (void *)(uintptr_t)lpAddress+offset, (void*)0);
        #ifdef __x86_64__

          debug_log("64-bit: oldvalue=%lx\n", oldvalue);

        #endif
        unsigned char *oldbuf=(unsigned char *)&oldvalue;
        unsigned char *newmem=(unsigned char *)address;
        int i;

        debug_log("oldvalue=%lx\n", oldvalue);

        for (i=0; i< (size-offset); i++)
          oldbuf[i]=newmem[i];

        debug_log("newvalue=%lx\n", oldvalue);

        i=safe_ptrace(PTRACE_POKEDATA, event.threadid, (void*)((uintptr_t)lpAddress+offset), (void *)oldvalue);

        debug_log("ptrace poke returned %d\n", i);
        if (i>=0)
          byteswritten+=size-offset;

      }

    }

    if (!isdebugged)
    {
      PThreadData td=GetThreadData(p, event.threadid);

      if (event.debugevent==SIGSTOP)
      {

        if (td)
          td->isPaused=0;

        safe_ptrace(PTRACE_CONT, event.threadid, 0,0);
      }
      else
      {
        debug_log("WriteProcessMemoryDebug: Adding unexpected signal to eventqueue (event.debugevent=%d event.threadid)\n", event.debugevent, event.threadid);

        if (td)
          td->isPaused=1;

        AddDebugEventToQueue(p, &event);
      }
    }

  }
  else
  {
    debug_log("WriteProcessMemoryDebug from outside the debuggerthread. Waking debuggerthread\n");

#pragma pack(1)
    struct
    {
      uint8_t command;
      uint32_t pHandle;
      uint64_t address;
      uint32_t size;
    } wpm;
#pragma pack()

    unsigned char data [size];
    debug_log("sizeof wpm=%d\n", sizeof(wpm));
    wpm.command=CMD_WRITEPROCESSMEMORY;
    wpm.pHandle=hProcess;
    wpm.address=(uintptr_t)lpAddress;
    wpm.size=size;
    memcpy(data, buffer, size);

    if (pthread_mutex_lock(&debugsocketmutex) == 0)
    {
      sendall(p->debuggerClient, &wpm, sizeof(wpm), 0);
      sendall (p-> debuggerClient, &data, size, 0);
      WakeDebuggerThread();

      recvall(p->debuggerClient, &byteswritten, sizeof(byteswritten), MSG_WAITALL);

      pthread_mutex_unlock(&debugsocketmutex);

      debug_log("after recvall byteswritten=%d\n", byteswritten);
    }
  }

  return byteswritten;
}

int WriteProcessMemory(HANDLE hProcess, void *lpAddress, void *buffer, int size)
{
  int written=0;

  debug_log("WriteProcessMemory(%d, %p, %p, %d)\n", hProcess, lpAddress, buffer, size);

  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);

    if (p->isDebugged)
    {
      debug_log("This process is being debugged\n");

      return WriteProcessMemoryDebug(hProcess, p, lpAddress, buffer, size);
    }

    if (((MEMORY_SEARCH_OPTION == 2) && (process_vm_writev)) || (MEMORY_SEARCH_OPTION == 3))
    {
      struct iovec local;
      struct iovec remote;
      int attachedpid=-1;

      debug_log("WPM: MEMORY_SEARCH_OPTION == 2\n");

      if (ATTACH_TO_WRITE_MEMORY)
      {
        debug_log("WPM: ATTACH_TO_WRITE_MEMORY=%d\n",ATTACH_TO_WRITE_MEMORY);
        attachedpid=ptrace_attach_andwait(p->pid);
      }

      local.iov_base=buffer;
      local.iov_len=size;

      remote.iov_base=lpAddress;
      remote.iov_len=size;

      PROCESS_VM_WRITEV write_v;
      if (MEMORY_SEARCH_OPTION==2)
        write_v=process_vm_writev;
      else
        write_v=process_vm_writev2;

      written=write_v(p->pid,&local,1,&remote,1,0);
      if (written==-1)
      {
       debug_log("process_vm_writev(%p, %d) failed: %s\n", lpAddress, size, strerror(errno));
       written=0;
      }
      else
       debug_log("Write successful\n");

      if (attachedpid>=0)
      {
        debug_log("WPM: Detaching\n");
        safe_ptrace(PTRACE_DETACH, attachedpid,0,0);
      }

      pthread_mutex_unlock(&memorymutex);

      if ((written) || (size==0))
        return written;

    }

    debug_log("aquiring memorymutex\n");
    if (pthread_mutex_lock(&memorymutex) == 0)
    {
      debug_log("aquired memorymutex\n");

      if (MEMORY_SEARCH_OPTION==2)
        debug_log("process_vm_writev==NULL or failure.  Using other method\n");

      debug_log("WPM: ATTACH_TO_WRITE_MEMORY == %d\n",ATTACH_TO_WRITE_MEMORY);
      debug_log("p->memrw=%d\n", p->memrw);
      debug_log("p->mem=%d\n", p->mem);

      if ((p->memrw==0) && (ATTACH_TO_WRITE_MEMORY==0))
      {
        debug_log("p->memrw is 0. Overriding ATTACH_TO_WRITE_MEMORY from 0 to 1\n");
        ATTACH_TO_WRITE_MEMORY=1;
      }

      pid_t pid;
      int canwrite=0;

      if (ATTACH_TO_WRITE_MEMORY==0)
      {
        pid=p->pid;
        canwrite=1;

      }
      else
      {
        pid=ptrace_attach_andwait(p->pid);
        if (pid>0)
          canwrite=1;
      }

      if (canwrite)
      {

        if ((MEMORY_SEARCH_OPTION == 0) && (p->memrw))
        {
          debug_log("WPM: MEMORY_SEARCH_OPTION == 0\n");

          lseek64(p->mem, (uintptr_t)lpAddress, SEEK_SET);
          written=write(p->mem, buffer, size);
          if (written==-1)
          {
            debug_log("write() to address %p failed with error: %s\n", lpAddress, strerror(errno));
            written=0;
          }

        }
        else
        {
          debug_log("WPM: MEMORY_SEARCH_OPTION == %d p->memrw=%d\n", MEMORY_SEARCH_OPTION, p->memrw);

          int offset=0;
          int max=size-sizeof(long int);

          long int *address=(long int *)buffer;

          debug_log("start: offset=%d  max=%d\n", offset, max);

          while (offset<max)
          {
            debug_log("offset=%d max=%d\n", offset, max);
            safe_ptrace(PTRACE_POKEDATA, pid, (void*)((uintptr_t)lpAddress+offset), (void *)*address);

            address++;
            offset+=sizeof(long int);

            written+=sizeof(long int);
          }

          debug_log("after loop: offset=%d  max=%d\n", offset, max);

          if (offset<size)
          {
            debug_log("WPM: Still some bytes left: %d\n", size-offset);

            uintptr_t oldvalue=0;
            oldvalue=safe_ptrace(PTRACE_PEEKDATA, pid,  (void *)(uintptr_t)lpAddress+offset, (void*)0);

            unsigned char *oldbuf=(unsigned char *)&oldvalue;
            unsigned char *newmem=(unsigned char *)address;
            int i;

            debug_log("oldvalue=%lx\n", oldvalue);

            for (i=0; i< (size-offset); i++)
              oldbuf[i]=newmem[i];

            debug_log("newvalue=%lx\n", oldvalue);

            i=safe_ptrace(PTRACE_POKEDATA, pid, (void*)((uintptr_t)lpAddress+offset), (void *)oldvalue);

            debug_log("ptrace poke returned %d\n", i);
            if (i>=0)
              written+=size-offset;
          }
        }

        if (ATTACH_TO_WRITE_MEMORY)
          safe_ptrace(PTRACE_DETACH, pid,0,0);
      }
      else
        debug_log("PTRACE ATTACH FAILED\n");

      pthread_mutex_unlock(&memorymutex);
    }

  }

  return written;
}

int ReadProcessMemoryDebug(HANDLE hProcess, PProcessData p, void *lpAddress, void *buffer, int size)
{

  int bytesread=0;

  if (p->debuggerThreadID==pthread_self())
  {
    int isdebugged=FindPausedThread(p);
    DebugEvent event;

    event.threadid=isdebugged;

    if (!isdebugged)
    {

      kill(p->pid, SIGSTOP);

      if (WaitForDebugEventNative(p, &event, -1, -1)==FALSE)
      {
        debug_log("WaitForDebugEventNative returned FALSE for a wait without timeout\n");
        return 0;
      }

    }

    if(MEMORY_SEARCH_OPTION== 0)
    {

      int inflooptest=0;

      bytesread=-1;
      while (bytesread==-1)
      {
        inflooptest++;

        if (inflooptest>10)
          debug_log("FUUU");

        lseek64(p->mem, (uintptr_t)lpAddress, SEEK_SET);
        bytesread=read(p->mem, buffer, size);

        if ((bytesread<0) && (errno!=EINTR))
        {

          bytesread=0;

          if (isdebugged)
          {

            int f;
            char mempath[255];

            sprintf(mempath,"/proc/%d/task/%d/mem", p->pid, (int)event.threadid);

            f=open(mempath, O_RDONLY);
            debug_log("f=%d\n", f);
            if (f>=0)
            {

              lseek64(p->mem, (uintptr_t)lpAddress, SEEK_SET);
              bytesread=read(p->mem, buffer, size);

              if ((bytesread<0) && (errno!=EINTR))
              {

                bytesread=0;
              }
              close(f);
            }
          }

          break;
        }
      }
    }
    else
    {

      int offset=0;
      int max=size-sizeof(long int);

      long int *address = (long int *)buffer;

      long int value = 0;

      int is_readable = 1;

      while(offset<max)
      {
        errno = 0;
        value =  safe_ptrace(PTRACE_PEEKDATA, p->pid, (void*)((uintptr_t)lpAddress+offset), (void *)0);

        if(errno == 0)
        {
          *address = value;

          address++;
          offset+=sizeof(long int);

          bytesread+=sizeof(long int);
        }
        else
        {
          is_readable = 0;
          break;
        }

      }

      if(offset < size && is_readable)
      {
        errno = 0;
        value =  safe_ptrace(PTRACE_PEEKDATA, p->pid, (void*)((uintptr_t)lpAddress+offset), (void *)0);

        if(errno == 0)
        {
          memcpy(address,&value,size-offset);

          int i = size-offset;
          if(i>=0)
            bytesread+=size-offset;
        }

      }
    }

    if (!isdebugged)
    {
      PThreadData td=GetThreadData(p, event.threadid);

      if (event.debugevent==SIGSTOP)
      {

        safe_ptrace(PTRACE_CONT, event.threadid, 0,0);

        if (td)
          td->isPaused=0;

      }
      else
      {
        debug_log("ReadProcessMemoryDebug: Adding unexpected signal to eventqueue (event.debugevent=%d event.threadid=%d)\n", event.debugevent, event.threadid);

        if (td)
          td->isPaused=1;

        AddDebugEventToQueue(p, &event);

        debug_log("After add\n");

        VerboseLevel=1000000000;

      }
    }

  }
  else
  {

#pragma pack(1)
    struct
    {
      uint8_t command;
      uint32_t pHandle;
      uint64_t address;
      uint32_t size;
      uint8_t compressed;
    } rpm;
#pragma pack()

    rpm.command=CMD_READPROCESSMEMORY;
    rpm.pHandle=hProcess;
    rpm.address=(uintptr_t)lpAddress;
    rpm.size=size;
    rpm.compressed=0;

    if (pthread_mutex_lock(&debugsocketmutex) == 0)
    {

      sendall(p->debuggerClient, &rpm, sizeof(rpm), 0);

      WakeDebuggerThread();

      recvall(p->debuggerClient, &bytesread, sizeof(bytesread), MSG_WAITALL);

      if (VerboseLevel>10)
        debug_log("After waiting for debugger thread: bytesread=%d\n", bytesread);

      if (bytesread>0)
        recvall(p->debuggerClient, buffer, bytesread, MSG_WAITALL);

      pthread_mutex_unlock(&debugsocketmutex);
    }

  }

  if (VerboseLevel>10)
    debug_log("ReadProcessMemoryDebug returns %d\n", bytesread);

  return bytesread;
}

int ReadProcessMemory(HANDLE hProcess, void *lpAddress, void *buffer, int size)
{

  if (lpAddress==NULL)
    return 0;

  int bread=0;

  if (GetHandleType(hProcess) == htProcesHandle )
  {

    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);

    if ((MEMORY_SEARCH_OPTION == 2) || (MEMORY_SEARCH_OPTION == 3))
    {

      PROCESS_VM_READV readv=NULL;
      if (MEMORY_SEARCH_OPTION == 2)
        readv=process_vm_readv;
      else
        readv=process_vm_readv2;

      if (readv)
      {
        struct iovec local;
        struct iovec remote;

        local.iov_base=buffer;
        local.iov_len=size;

        remote.iov_base=lpAddress;
        remote.iov_len=size;

        int canreadnow=1;
        pid_t pid;

        if (ATTACH_TO_ACCESS_MEMORY)
        {
          canreadnow=0;
          pid=ptrace_attach_andwait(p->pid);
          if (pid>0)
            canreadnow=1;

        }

        if (canreadnow)
        {
          bread=readv(p->pid,&local,1,&remote,1,0);
          if (bread==-1)
          {

            bread=0;
          }
        }

        if (ATTACH_TO_ACCESS_MEMORY)
          safe_ptrace(PTRACE_DETACH, pid,0,0);

        return bread;
      }
      else
        MEMORY_SEARCH_OPTION=0;
    }

    if (p->isDebugged)
    {

      return ReadProcessMemoryDebug(hProcess, p, lpAddress, buffer, size);
    }

    if (pthread_mutex_lock(&memorymutex) == 0)
    {

      {

        int canreadnow=0;
        pid_t pid;

        if (ATTACH_TO_ACCESS_MEMORY==0)
        {
          canreadnow=1;
          pid=p->pid;
        }
        else
        {
          pid=ptrace_attach_andwait(p->pid);
          if (pid>0)
            canreadnow=1;
        }

        if (canreadnow)
        {
          if (MEMORY_SEARCH_OPTION == 0)
          {
            if (p->mem)
            {
              lseek64(p->mem, (uintptr_t)lpAddress, SEEK_SET);
              bread=read(p->mem, buffer, size);
              if (bread==-1)
              {
                bread=0;

              }
            }
            else
              bread=0;
          }
          else
          {
            int offset=0;
            int max=size-sizeof(long int);

            long int *address = (long int *)buffer;

            long int value = 0;

            int is_readable = 1;

            while(offset<max)
            {
              errno = 0;
              value =  safe_ptrace(PTRACE_PEEKDATA, pid, (void*)((uintptr_t)lpAddress+offset), (void *)0);

              if(errno == 0)
              {
                *address = value;

                address++;
                offset+=sizeof(long int);

                bread+=sizeof(long int);
              }
              else
              {
                is_readable = 0;
                break;
              }

            }

            if(offset < size && is_readable)
            {
              errno = 0;
              value =  safe_ptrace(PTRACE_PEEKDATA, pid, (void*)((uintptr_t)lpAddress+offset), (void *)0);

              if(errno == 0)
              {
                memcpy(address,&value,size-offset);

                int i = size-offset;
                if(i>=0)
                  bread+=size-offset;
              }

            }

          }

          if (ATTACH_TO_ACCESS_MEMORY)
          {
            int r=safe_ptrace(PTRACE_DETACH, pid,0,0);

          }

        }
        else
          debug_log("ptrace attach failed (pid=%d). You may not have proper rights, or there's something interfering\n", p->pid);

      }

      pthread_mutex_unlock(&memorymutex);
    }
    else
      debug_log("For some reason I failed to obtain a lock\n");
  }

  fflush(stdout);

  return bread;
}

DWORD ProtectionStringToType(char *protectionstring)
{
  if (strchr(protectionstring, 's'))
    return MEM_MAPPED;
  else
    return MEM_PRIVATE;
}

uint32_t ProtectionStringToProtection(char *protectionstring)
{
  int w,x;

  if (strchr(protectionstring, 'x'))
    x=1;
  else
    x=0;

  if (strchr(protectionstring, 'w'))
    w=1;
  else
    w=0;

  if (x)
  {

    if (w)
      return PAGE_EXECUTE_READWRITE;
    else
      return PAGE_EXECUTE_READ;
  }
  else
  {

    if (w)
      return PAGE_READWRITE;
    else
      return PAGE_READONLY;
  }
}

void AddToRegionList(uint64_t base, uint64_t size, uint32_t type, uint32_t protection, RegionInfo **list, int *pos, int *max)

{

  debug_log("++>%llx->%llx : (%llx)  - %d\n", (unsigned long long)base, (unsigned long long)base+size, (unsigned long long)size, type);

  (*list)[*pos].baseaddress=base;
  (*list)[*pos].size=size;
  (*list)[*pos].type=type;
  (*list)[*pos].protection=protection;

  (*pos)++;

  if (*pos>=*max)
  {
    debug_log("resize list\n");
    *max=(*max)*2;
    *list=(RegionInfo *)realloc(*list, sizeof(RegionInfo)*(*max));
  }

}

int VirtualQueryExFull(HANDLE hProcess, uint32_t flags, RegionInfo **rinfo, uint32_t *count)

{
  int pagedonly=flags & VQE_PAGEDONLY;
  int dirtyonly=flags & VQE_DIRTYONLY;
  int noshared=flags & VQE_NOSHARED;

  debug_log("VirtualQueryExFull:\n");

  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);

    char smaps_name[64];
    char pagemap_name[64];

    sprintf(smaps_name,"/proc/%d/smaps", p->pid);
    sprintf(pagemap_name,"/proc/%d/pagemap", p->pid);

    FILE *maps=fopen(smaps_name, "r");
    int pagemap=-1;

    uint64_t *pagemap_entries=NULL;

    if (pagedonly)
    {
      debug_log("pagedonly\n");
      pagemap=open(pagemap_name, O_RDONLY);

      pagemap_entries=(uint64_t *)malloc(512*8);

      debug_log("allocated pagemap_entries at %p\n", pagemap_entries);
    }

    if (maps && (!pagedonly || (pagemap>=0)))
    {

      unsigned long long start=0, stop=0;
      char protectionstring[25];
      char x[200];
      int pos=0, max=pagedonly?64:128;
      RegionInfo *r;

      debug_log("going to allocate r\n");
      r=(RegionInfo *)malloc(sizeof(RegionInfo)*max);

      debug_log("Allocated r at %p\n", r);

      int isdirty=0;
      int end=0;

      while (!end)
      {
        unsigned long long _start, _stop;
        char temp[25];

        end=fgets(x, 200, maps)==0;

        if (x[strlen(x)-1]!='\n')
        {

          char discard[100];

          do
          {
            discard[99]=0;
            fgets(discard, 99, maps);
          } while (discard[99]!=0);
        }

        temp[0]=0;
        sscanf(x, "%llx-%llx %24s", &_start, &_stop, temp);

        if ((end) || (temp[0]!=0))
        {

          if (start)
          {
            int passed=1;
            DWORD type=ProtectionStringToType(protectionstring);
            DWORD protection=ProtectionStringToProtection(protectionstring);

            if (noshared && (type==MEM_MAPPED))
              passed=0;

            if (dirtyonly && !isdirty)
              passed=0;

            if (passed)
            {

              if (pagedonly)
              {

                uint64_t current=start;
                int pagesize;
#ifndef PAGESIZE
                pagesize=getpagesize();
#else
                pagesize=PAGESIZE;
#endif
                while (current<stop)
                {
                  int i;
                  int currentstart=-1;
                  off_t offset=(current / pagesize)*8;
                  size_t pagecount=(stop-current) / pagesize;
                  if (pagecount>512)
                    pagecount=512;

                  debug_log("-->%llx->%llx : %s (%llx)\n", start, stop, protectionstring, stop-start);

                  i=pread(pagemap, pagemap_entries, pagecount*8, offset);
                  if (i==-1)
                  {
                    debug_log("offset=%llx, pagecount=%d read=%d (%d) \n", (unsigned long long)offset, (int)pagecount, i/8, i);

                  }
                  else
                  {
                    for (i=0; i<pagecount; i++)
                    {
                      if (pagemap_entries[i] >> 63)
                      {
                        if (currentstart==-1)
                          currentstart=i;

                      }
                      else
                      {
                        if (currentstart!=-1)
                        {

                          AddToRegionList((uint64_t)(current+currentstart*pagesize), (i-currentstart)*pagesize, type, protection, &r, &pos, &max);
                        }

                        currentstart=-1;
                      }
                    }

                    if (currentstart!=-1)
                    {

                      int count=pagecount-currentstart;
                      AddToRegionList((uint64_t)(current+currentstart*pagesize), count*pagesize, type, protection, &r, &pos, &max);
                    }

                    current+=pagecount*pagesize;
                  }

                }

              }
              else
                AddToRegionList(start, stop-start, type, protection, &r, &pos, &max);
            }

          }

          isdirty=0;
          strcpy(protectionstring, temp);
          start=_start;
          stop=_stop;
        }
        else
        {

          if (dirtyonly && (start!=0))
          {

            int i;
            int number;
            char name[32];
            i=sscanf(x, "%31[^:]: %d", name, &number);
            if (i==2)
            {
              if ((number>0) && ((strcmp(name,"Shared_Dirty")==0) || (strcmp(name,"Private_Dirty")==0)))
                isdirty=1;
            }

          }

        }

      }

      if (maps)
        fclose(maps);

      if (pagemap>=0)
        close(pagemap);

      *count=pos;
      *rinfo=r;

      if (pagemap_entries)
        free(pagemap_entries);

      fflush(stdout);

      return 1;
    }
    else
    {
      debug_log("Failure maps=%p pagemap=%d\n", maps, pagemap);

      if (maps)
        fclose(maps);
      else
        debug_log("Failure opening /proc/%d/smaps", p->pid);

      if (pagemap>=0)
        close(pagemap);
      else
        debug_log("Failure opening /proc/%d/pagemap", p->pid);

      fflush(stdout);

      return 0;
    }

  }
  else
    return 0;

}

int VirtualQueryEx(HANDLE hProcess, void *lpAddress, PRegionInfo rinfo, char *mapsline)
{

  int found=0;

  if (GetHandleType(hProcess) == htProcesHandle )
  {
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);
    FILE *maps=fopen(p->maps, "r");
    if (maps)
    {
      char x[200];

      rinfo->protection=0;
      rinfo->baseaddress=(uintptr_t)lpAddress & ~0xfff;
      lpAddress=(void *)(uintptr_t)(rinfo->baseaddress);

      while (fgets(x, 200, maps) )
      {
        unsigned long long start=0, stop=0;
        char protectionstring[25];

        x[199]=0;

        if (x[strlen(x)-1]!='\n')
        {
          char discard[100];

          do
          {
            discard[99]=0;
            fgets(discard, 99, maps);
          } while (discard[99]!=0);
        }

        sscanf(x, "%llx-%llx %s", &start, &stop, protectionstring);

        if (stop > ((uintptr_t)lpAddress) )
        {
          found=1;

          if (((uintptr_t)lpAddress) >= start )
          {

            rinfo->protection=ProtectionStringToProtection(protectionstring);
            rinfo->type=ProtectionStringToType(protectionstring);
            rinfo->size=stop-rinfo->baseaddress;
          }
          else
          {
            rinfo->size=start-rinfo->baseaddress;
            rinfo->protection=PAGE_NOACCESS;
            rinfo->type=0;
          }

          if (mapsline!=NULL)
            strcpy(mapsline, x);

          break;
        }
      }

      fclose(maps);

      return found;
    }
    else
    {
      debug_log("failed opening %s\n", p->maps);
    }
  }

  return 0;
}

int SearchHandleListProcessCallback(PProcessData data, int *pid)

{
  return (data->pid==*pid);
}

int CloseAllPipesCallback(void *data, void *searchdata)
{
  return 1;
}

void CloseAllPipes()
{
  HANDLE h;
  do
  {
    h=SearchHandleList(htPipeHandle, CloseAllPipesCallback,0);
    if (h)
      CloseHandle(h);

  } while (h);
}

HANDLE OpenPipe(char *pipename, int timeout)
{
  int i;
  int s;
  int al;
  char name[256];
  debug_log("OpenPipe(\"%s\")", pipename);
  s=socket(AF_UNIX, SOCK_STREAM, 0);

  sprintf(name, " %s",pipename);

  struct sockaddr_un address;
  address.sun_family=AF_UNIX;
  strcpy(address.sun_path, name);

  al=SUN_LEN(&address);

  address.sun_path[0]=0;

  debug_log("trying to connect to %s\n", pipename);
  i=connect(s, (struct sockaddr *)&address, al);

  if ((i!=0) && (timeout))
  {
    uint64_t starttime=getTickCount();
    while ((i!=0) && (getTickCount()<starttime+timeout))
    {
      usleep(50*1000);
      i=connect(s, (struct sockaddr *)&address, al);
    }
  }

  debug_log("connect returned %d\n", i);

  if (i==0)
  {
    PPipeData pd=(PPipeData)malloc(sizeof(PipeData));

    pd->socket=s;
    pd->pipename=strdup(pipename);

    debug_log("Successful connection to %s\n", pd->pipename);

    return CreateHandleFromPointer(pd, htPipeHandle);
  }
  else
  {
    debug_log("Failed connecting to %s\n", pipename);
    close(s);
    return 0;
  }
}

int ReadPipe(HANDLE ph, void* destination, int size, int timeout)
{
  PPipeData pd=(PPipeData)GetPointerFromHandle(ph);
  if (pd)
  {

    return recvall(pd->socket, destination, size,MSG_NOSIGNAL);
  }
  else
    return -1;
}

int WritePipe(HANDLE ph, void* source, int size, int timeout)
{

  PPipeData pd=(PPipeData)GetPointerFromHandle(ph);
  if (pd)
  {

    return sendall(pd->socket, source, size,MSG_NOSIGNAL);
  }
  else
  {
    debug_log("WritePipe: invalid handle\n");
    return -1;
  }
}

HANDLE OpenProcess(DWORD pid)
{

  char processpath[100];
  int handle;
  sprintf(processpath, "/proc/%d/", pid);

  handle=SearchHandleList(htProcesHandle, (HANDLESEARCHCALLBACK)SearchHandleListProcessCallback, &pid);
  if (handle)
  {

    PProcessData p=(PProcessData)GetPointerFromHandle(handle);
    p->ReferenceCount++;
    return handle;
  }

  if (chdir(processpath)==0)
  {

    PProcessData p=(PProcessData)malloc(sizeof(ProcessData));

    memset(p, 0, sizeof(ProcessData));

    p->ReferenceCount=1;
    p->pid=pid;
    p->path=strdup(processpath);

    sprintf(processpath,"/proc/%d/maps", pid);
    p->maps=strdup(processpath);

    if(MEMORY_SEARCH_OPTION == 0)
    {
      debug_log("Opening memory access\n");
      sprintf(processpath,"/proc/%d/mem", pid);

      p->memrw=1;
      p->mem=open(processpath, O_RDWR);
      if (p->mem==-1)
      {
        debug_log("Failure opening %s for RW access because of :%s\nTrying RO: ",processpath, strerror(errno));
        p->mem=open(processpath, O_RDONLY);
        p->memrw=0;

        if (p->mem==-1)
        {
          debug_log("Also failed\n");
          if (process_vm_readv && process_vm_writev)
          {
            debug_log("Falling back to MEMORY_SEARCH_OPTION=2 (process_vm_readv and process_vm_writev)\n");
            MEMORY_SEARCH_OPTION=2;
          }
#ifdef SYS_process_vm_readv
          else
          {
            debug_log("Falling back to MEMORY_SEARCH_OPTION=3 (process_vm_readv2 syscall)\n");
            MEMORY_SEARCH_OPTION=3;
          }
#else
          else
          {
            MEMORY_SEARCH_OPTION=1;
            ATTACH_TO_ACCESS_MEMORY=1;
            debug_log("Falling back to MEMORY_SEARCH_OPTION=1 (ptrace)\n");
          }
#endif
        }
        else
        {
          debug_log("Success. ReadOnly access.  Use an alternate write access routine\n");
          ATTACH_TO_WRITE_MEMORY=1;
        }
      }
    }

    pthread_mutex_init(&p->extensionMutex, NULL);
    p->hasLoadedExtension=0;
    p->extensionFD=0;

    p->isDebugged=0;

    p->threadlistmax=0;
    p->threadlistpos=0;
    p->threadlist=NULL;

    p->debuggedThreadEvent.threadid=0;

    pthread_mutex_init(&p->debugEventQueueMutex, NULL);

    TAILQ_INIT(&p->debugEventQueue);

    HANDLE result=CreateHandleFromPointer(p, htProcesHandle);

    debug_log("Getting processdata for TH32CS_SNAPFIRSTMODULE\n");

    HANDLE ths=CreateToolhelp32Snapshot(TH32CS_SNAPFIRSTMODULE, p->pid);
    if (ths)
    {
      ModuleListEntry mle;
      if (Module32First(ths, &mle))
      {
        p->is64bit=mle.is64bit;

        if (p->is64bit)
          debug_log("The opened process is 64-bit\n");
        else
          debug_log("The opened process is 32-bit\n");
      }
      else
      {
        debug_log("Module32First returned false\n");
#if defined(__aarch64__) || defined(__x86_64__)
        p->is64bit=1;
#else
        p->is64bit=0;
#endif
      }

      CloseHandle(ths);
    }
    else
    {
      debug_log("Failed creating toolhelp snapshot for firstmodule\n");

    }

    return result;
  }
  else
  {
    debug_log("Failure opening the process");
    return 0;
  }

}

BOOL Process32Next(HANDLE hSnapshot, PProcessListEntry processentry)
{

  if (GetHandleType(hSnapshot) == htTHSProcess)
  {
    PProcessList pl=(PProcessList)GetPointerFromHandle(hSnapshot);

    if (pl->processListIterator<pl->processCount)
    {
      processentry->PID=pl->processList[pl->processListIterator].PID;
      processentry->ProcessName=pl->processList[pl->processListIterator].ProcessName;
      pl->processListIterator++;

      return TRUE;
    }
    else
      return FALSE;
  }
  else
    return FALSE;
}

BOOL Process32First(HANDLE hSnapshot, PProcessListEntry processentry)
{

  if (GetHandleType(hSnapshot) == htTHSProcess)
  {
    PProcessList pl=(PProcessList)GetPointerFromHandle(hSnapshot);
    pl->processListIterator=0;
    return Process32Next(hSnapshot, processentry);
  }
  else
    return FALSE;
}

BOOL Module32Next(HANDLE hSnapshot, PModuleListEntry moduleentry)
{

  if (GetHandleType(hSnapshot) == htTHSModule)
  {
    PModuleList ml=(PModuleList)GetPointerFromHandle(hSnapshot);

    if (ml->moduleListIterator<ml->moduleCount)
    {
      moduleentry->baseAddress=ml->moduleList[ml->moduleListIterator].baseAddress;
      moduleentry->moduleName=ml->moduleList[ml->moduleListIterator].moduleName;
      moduleentry->moduleSize=ml->moduleList[ml->moduleListIterator].moduleSize;
      moduleentry->part=ml->moduleList[ml->moduleListIterator].part;
      moduleentry->fileOffset=ml->moduleList[ml->moduleListIterator].fileOffset;
      moduleentry->is64bit=ml->moduleList[ml->moduleListIterator].is64bit;

      ml->moduleListIterator++;

      return TRUE;
    }
    else
    {

      return FALSE;
    }
  }
  else
  {
    debug_log("Module32First/Next failed: Handle is not a htHTSModule handle: %d\n",GetHandleType(hSnapshot));
    return FALSE;
  }
}

BOOL Module32First(HANDLE hSnapshot, PModuleListEntry moduleentry)
{

  if (GetHandleType(hSnapshot) == htTHSModule)
  {
    PModuleList ml=(PModuleList)GetPointerFromHandle(hSnapshot);
    ml->moduleListIterator=0;
    return Module32Next(hSnapshot, moduleentry);
  }
  else
  {
    debug_log("Module32First error. Handle is not a THSModule handle\n");
    return FALSE;
  }
}

BOOL Thread32Next(HANDLE hSnapshot, int* threadid)
{
  if (GetHandleType(hSnapshot) == htTHSThread)
  {
    PThreadList tl=(PThreadList)GetPointerFromHandle(hSnapshot);
    if (tl->threadListIterator>=tl->threadCount)
      return FALSE;

    *threadid=tl->threadList[tl->threadListIterator];
    tl->threadListIterator++;
    return TRUE;
  }
  else
    return FALSE;
}

BOOL Thread32First(HANDLE hSnapshot, int* threadid)
{
  if (GetHandleType(hSnapshot) == htTHSThread)
  {
    PThreadList tl=(PThreadList)GetPointerFromHandle(hSnapshot);
    tl->threadListIterator=0;
    return Thread32Next(hSnapshot, threadid);
  }
  else
  {
    debug_log("Module32First error. Handle is not a THSModule handle\n");
    return FALSE;
  }

}

HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{

  if (dwFlags & TH32CS_SNAPPROCESS)
  {

    int max=2048;
    PProcessList pl=(PProcessList)malloc(sizeof(ProcessList));

    pl->ReferenceCount=1;
    pl->processCount=0;
    pl->processList=(PProcessListEntry)malloc(sizeof(ProcessListEntry)* max);

    DIR *procfolder=opendir("/proc/");

    struct dirent *currentfile;

    while ((currentfile=readdir(procfolder)) != NULL)
    {

      if (strspn(currentfile->d_name, "1234567890")==strlen(currentfile->d_name))
      {
        int pid;
        char exepath[512];
        char processpath[512];
        snprintf(exepath, 512, "/proc/%s/exe", currentfile->d_name);
        exepath[511]=0;

        int i=readlink(exepath, processpath, 254);
        if (i != -1)
        {
          char extrafile[512];
          int f;

          if (i>254)
            i=254;

          processpath[i]=0;

          snprintf(extrafile, 512, "/proc/%s/cmdline", currentfile->d_name);
          extrafile[511]=0;

          f=open(extrafile, O_RDONLY);
          if (f!=-1)
          {
            i=read(f, extrafile, 255);
            if (i>=0)
              extrafile[i]=0;
            else
              extrafile[0]=0;

            strcat(processpath," ");
            strcat(processpath,extrafile);

            close(f);
          }

          sscanf(currentfile->d_name, "%d", &pid);

          pl->processList[pl->processCount].PID=pid;
          pl->processList[pl->processCount].ProcessName=strdup(processpath);

          pl->processCount++;

          if (pl->processCount>=max)
          {
            max=max*2;
            pl->processList=(PProcessListEntry)realloc(pl->processList, max*sizeof(ProcessListEntry));
          }
        }

      }

    }

    closedir(procfolder);

    return CreateHandleFromPointer(pl, htTHSProcess);
  }
  else
  if (((dwFlags & TH32CS_SNAPMODULE) || (dwFlags & TH32CS_SNAPFIRSTMODULE) ) && (ATTACH_PID == 0 ||(ATTACH_PID != 0 && (th32ProcessID == ATTACH_PID))))
  {

    int max=64;
    char mapfile[255];
    FILE *f=NULL;
    snprintf(mapfile, 255, "/proc/%d/maps", th32ProcessID);

    PModuleList ml=(PModuleList)malloc(sizeof(ModuleList));

    if (dwFlags & TH32CS_SNAPFIRSTMODULE)
      debug_log("Creating 1-entry module list for process %d\n", th32ProcessID);

    ml->ReferenceCount=1;
    ml->moduleCount=0;
    ml->moduleList=(PModuleListEntry)malloc(sizeof(ModuleListEntry)*max);

    f=fopen(mapfile, "r");

    if (f)
    {
      char s[512];
      memset(s, 0, 512);

      PModuleListEntry mle=NULL;
      int phandle=OpenProcess(th32ProcessID);

      while (fgets(s, 511, f))
      {
        unsigned long long start, stop;
        uint32_t fileoffset;
        char protectionstring[32],modulepath[511];
        unsigned char elfident[8];

        modulepath[0]='\0';
        memset(modulepath, 0, 255);

        sscanf(s, "%llx-%llx %s %x %*s %*s %[^\t\n]\n", &start, &stop, protectionstring, &fileoffset, modulepath);

        if (modulepath[0])
        {
          int i;
          if (strcmp(modulepath, "[heap]")==0)
            continue;

          if ((modulepath[0]=='/') && (modulepath[1]=='d') && (modulepath[2]=='e') && (modulepath[3]=='v') && (modulepath[4]=='/'))
            continue;

          if (strcmp(modulepath, "[vdso]")!=0)
          {
            for (i=0; modulepath[i]; i++)
            {
              if ((modulepath[i]=='[') || (modulepath[i]==']'))
                modulepath[i]='_';
            }
          }

          mle=NULL;

          if (start==0x7f9f9144e000)
          {
            debug_log("break");
          }

          i=ReadProcessMemory(phandle, (void *)start, elfident, 8);
          if (i==0)
          {

            continue;
          }

          int part=0;

          for (i=ml->moduleCount-1; i>=0; i--)
          {
            if (strcmp(ml->moduleList[i].moduleName, modulepath)==0)
            {
              part=ml->moduleList[i].part+1;
              break;
            }
          }

          if (((elfident[0]!=ELFMAG0) || (elfident[1]!=ELFMAG1) || (elfident[2]!=ELFMAG2) || (elfident[3]!=ELFMAG3) ) )
          {

            continue;
          }

          mle=&ml->moduleList[ml->moduleCount];
          mle->moduleName=strdup(modulepath);
          mle->baseAddress=start;
          mle->fileOffset=fileoffset;
          mle->moduleSize=GetModuleSize(modulepath, fileoffset,0);
          if (mle->moduleSize==-1)
            mle->moduleSize=stop-start;
          mle->part=part;

          if (part==0)
            mle->is64bit=elfident[EI_CLASS]==ELFCLASS64;

          ml->moduleCount++;

          if (ml->moduleCount>=max)
          {

            max=max*2;
            ml->moduleList=(PModuleListEntry)realloc(ml->moduleList, max* sizeof(ModuleListEntry));
          }

          if (dwFlags & TH32CS_SNAPFIRSTMODULE)
            break;

        }
        else
          mle=NULL;

      }

      CloseHandle(phandle);

      fclose(f);

      return CreateHandleFromPointer(ml, htTHSModule);
    }
    else
    {
      if (dwFlags & TH32CS_SNAPFIRSTMODULE)
        debug_log("Failed opening %s\n", mapfile);

      return 0;
    }

  }
  else
  if (dwFlags & TH32CS_SNAPTHREAD)
  {
    int max=64;
    char _taskdir[255];
    DIR *taskdir;

    debug_log("TH32CS_SNAPTHREAD\n");
    if (th32ProcessID==0)
      return 0;

    sprintf(_taskdir, "/proc/%d/task", th32ProcessID);

    debug_log("reading %s\n",_taskdir);

    taskdir=opendir(_taskdir);
    if (taskdir)
    {
      struct dirent *d;
      PThreadList tl=(PThreadList)malloc(sizeof(ThreadList));

      tl->ReferenceCount=1;
      tl->threadCount=0;
      tl->threadList=(int*)malloc(max*sizeof(int));

      d=readdir(taskdir);
      while (d)
      {
        int tid=atoi(d->d_name);

        if (tid)
        {
          debug_log("found threadid %d\n", tid);
          tl->threadList[tl->threadCount]=tid;
          tl->threadCount++;
          if (tl->threadCount>=max)
          {
            max=max*2;
            tl->threadList=(int*)realloc(tl->threadList, max*sizeof(int));
          }
        }
        d=readdir(taskdir);
      }
      closedir(taskdir);

      return CreateHandleFromPointer(tl, htTHSThread);
    }
  }

  debug_log("Unhandled toolhelp32snapshot flags: %x\n", dwFlags);
  return 0;
}

void CloseHandle(HANDLE h)
{
  int i;
  handleType ht=GetHandleType(h);

  if (ht==htTHSModule)
  {
    ModuleList *ml=(PModuleList)GetPointerFromHandle(h);
    ml->ReferenceCount--;
    if (ml->ReferenceCount<=0)
    {

      for (i=0; i<ml->moduleCount; i++)
        free(ml->moduleList[i].moduleName);

      free(ml->moduleList);
      free(ml);

      RemoveHandle(h);
    }

  }
  else
  if (ht==htTHSProcess)
  {
    ProcessList *pl=(PProcessList)GetPointerFromHandle(h);

    pl->ReferenceCount--;

    if (pl->ReferenceCount<=0)
    {

      for (i=0; i<pl->processCount; i++)
        free(pl->processList[i].ProcessName);

      free(pl->processList);
      free(pl);

      RemoveHandle(h);
    }
  }
  else
  if (ht==htTHSThread)
  {
    ThreadList *tl=(PThreadList)GetPointerFromHandle(h);

    tl->ReferenceCount--;
    if (tl->ReferenceCount<=0)
    {
      free(tl->threadList);
      RemoveHandle(h);
    }
  }
  else
  if (ht==htProcesHandle)
  {
    PProcessData pd=(PProcessData)GetPointerFromHandle(h);

    pd->ReferenceCount--;
    if (pd->ReferenceCount<=0)
    {
      free(pd->maps);
      free(pd->path);
      close(pd->mem);
      free(pd);

      RemoveHandle(h);
    }
  }
  else
  if (ht==htNativeThreadHandle)
  {
    uint64_t *th=GetPointerFromHandle(h);
    debug_log("Closing thread handle\n");

    free(th);
    RemoveHandle(h);
  }
  else
  if (ht==htPipeHandle)
  {
    debug_log("Closing pipe handle\n");

    PPipeData pd=GetPointerFromHandle(h);
    close(pd->socket);
    free(pd->pipename);
    free(pd);
    RemoveHandle(h);
  }
  else
    RemoveHandle(h);

}

uint64_t getTickCount()
{
  struct timespec ts;
  uint64_t r=0;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  r  = ts.tv_nsec / 1000000;
  r += ts.tv_sec * 1000;
  return r;
}

void initAPI()
{
  pthread_mutex_init(&memorymutex, NULL);
  pthread_mutex_init(&debugsocketmutex, NULL);

  sem_init(&sem_DebugThreadEvent, 0, 0);

  void *libc=dlopen("libc.so",RTLD_NOW);

  if (libc)
  {
    process_vm_readv=dlsym(libc,"process_vm_readv");
    process_vm_writev=dlsym(libc,"process_vm_writev");
  }

  if (!process_vm_readv)
  {
    process_vm_readv=dlsym(0, "process_vm_readv");
    process_vm_writev=dlsym(0, "process_vm_writev");
  }

  debug_log("process_vm_readv=%p\n",process_vm_readv);
  debug_log("process_vm_writev=%p\n",process_vm_writev);

}
