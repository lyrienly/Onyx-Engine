#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <dlfcn.h>
#include <stdarg.h>
#ifdef __ANDROID__
#include <android/log.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>

#include "server.h"
#include "speedhack.h"

int done=0;

#ifndef SUN_LEN
# include <string.h>

# define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path)        \
          + strlen ((ptr)->sun_path))
#endif

void dvmJitStats();

typedef struct
{
  uint64_t address;
  uint32_t size;
} AllocEntry, *PAllocEntry;

PAllocEntry allocList;
int allocList_Max;
int allocList_Pos;

#ifdef __ANDROID__
  #define LOG_TAG "CESERVER_EXTENSION"
  #define LOGD(fmt, args...) __android_log_vprint(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
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

void allocListAdd(uint64_t address, uint32_t size)
{
  if (allocList==NULL)
  {
    allocList=calloc(16, sizeof(AllocEntry));
    allocList_Max=16;
  }

  allocList[allocList_Pos].address=address;
  allocList[allocList_Pos].size=size;

  allocList_Pos++;
  if (allocList_Pos==allocList_Max)
  {
    allocList_Max*=2;
    allocList=realloc(allocList, allocList_Max*sizeof(AllocEntry));
  }
}

void allocListRemove(uint64_t address)
{
  int i;
  for (i=0; i<allocList_Pos; i++)
  {
    if (allocList[i].address==address)
    {
      int j;
      for (j=i; j<allocList_Pos-1; j++)
        allocList[j]=allocList[j+1];

      allocList_Pos--;
      break;
    }
  }

}

int allocListFind(uint64_t address)

{
  int i;
  for (i=0; i<allocList_Pos; i++)
  {
    if (allocList[i].address==address)
    {
      return allocList[i].size;
    }
  }

  return 0;

}

ssize_t recvall (int s, void *buf, size_t size, int flags)
{
  ssize_t totalreceived=0;
  ssize_t sizeleft=size;
  unsigned char *buffer=(unsigned char*)buf;

  flags=flags | MSG_WAITALL;

  while (sizeleft>0)
  {
    ssize_t i=recv(s, &buffer[totalreceived], sizeleft, flags);

    if (i==0)
    {
      debug_log("recv returned 0\n");
      return i;
    }

    if (i==-1)
    {
      debug_log("recv returned -1\n");
      if (errno==EINTR)
      {
        debug_log("errno = EINTR\n");
        i=0;
      }
      else
      {
        debug_log("Error during recvall: %d. errno=%d (%s)\n",(int)i, errno, strerror(errno));
        return i;
      }

    }

    totalreceived+=i;
    sizeleft-=i;
  }

  return totalreceived;
}

ssize_t sendall (int s, void *buf, size_t size, int flags)
{
  ssize_t totalsent=0;
  ssize_t sizeleft=size;
  unsigned char *buffer=(unsigned char*)buf;

  while (sizeleft>0)
  {
    ssize_t i=send(s, &buffer[totalsent], sizeleft, flags);

    if (i==0)
    {
      return i;
    }

    if (i==-1)
    {
      if (errno==EINTR)
        i=0;
      else
      {
        debug_log("Error during sendall: %d. errno=%d\n",(int)i, errno);
        return i;
      }
    }

    totalsent+=i;
    sizeleft-=i;
  }

  return totalsent;
}

int DispatchCommand(int currentsocket, unsigned char command)
{

  switch (command)
  {
    case EXTCMD_ALLOC:
    {
#pragma pack(1)
      struct {
        uint64_t preferedAddress;
        uint32_t size;
        uint32_t prot;
      } params;
#pragma pack()

      if (recvall(currentsocket, &params, sizeof(params), 0)>0)
      {

        if (params.prot==0)
          params.prot=PROT_READ | PROT_WRITE | PROT_EXEC;

        uint64_t address=(uint64_t)mmap((void *)params.preferedAddress, params.size, params.prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (address)
          allocListAdd(address, params.size);

        sendall(currentsocket, &address, sizeof(address), 0);

      }

      break;
    }

    case EXTCMD_FREE:
    {
#pragma pack(1)
      struct {
        uint64_t address;
        uint32_t size;
      } params;
#pragma pack()

      uint32_t result;

      if (recvall(currentsocket, &params, sizeof(params), 0)>0)
      {

        if (params.size==0)
          params.size=allocListFind(params.address);

        if (params.size)
        {

          result=munmap((void *)params.address, params.size);
          if (result==-1)
            result=0;
          else
            result=1;
        }
        else
          result=0;

        allocListRemove(params.address);

        sendall(currentsocket, &result, sizeof(result), 0);

      }
      break;
    }

    case EXTCMD_CREATETHREAD:
    {
#pragma pack(1)
      struct {
        uint64_t startaddress;
        uint64_t parameter;
      } params;
#pragma pack()

      if (recvall(currentsocket, &params, sizeof(params), 0)>0)
      {

        uint64_t threadhandle=0;

        pthread_create((pthread_t *)&threadhandle, NULL, (void *)params.startaddress, (void *)params.parameter);

        sendall(currentsocket, &threadhandle, sizeof(threadhandle), 0);
      }

      break;
    }

    case EXTCMD_LOADMODULEEX:
    {
      debug_log("EXTCMD_LOADMODULEEX\n");
#pragma pack(1)
      struct {
        uint64_t dlopenaddress;
        uint32_t modulepathlength;
      } params;
#pragma pack()

      if (recvall(currentsocket, &params, sizeof(params),0)>0)
      {
        char *modulepath[params.modulepathlength+1];
        if (recvall(currentsocket, modulepath, params.modulepathlength, 0)>0)
        {
          typedef void* (*_dlopen)(const char *filename, int flags);
          _dlopen __dlopen=(_dlopen)params.dlopenaddress;
          uint64_t result;
          result=(uint64_t)__dlopen(modulepath,RTLD_NOW);
          sendall(currentsocket, &result, sizeof(result), 0);
        }
      }

      break;
    }

    case EXTCMD_LOADMODULE:
    {
      uint32_t modulepathlength;
      debug_log("EXTCMD_LOADMODULE\n");
      debug_log("receiving modulepath:\n");

      if (recvall(currentsocket, &modulepathlength, sizeof(modulepathlength), 0)>0)
      {
        debug_log("pathlength is %d bytes long\n", modulepathlength);

        char *modulepath[modulepathlength+4];
        if (recvall(currentsocket, modulepath, modulepathlength, 0)>0)
        {
          modulepath[modulepathlength]=0;
          modulepath[modulepathlength+1]=0;
          modulepath[modulepathlength+2]=0;
          modulepath[modulepathlength+3]=0;

          debug_log("EXTCMD_LOADMODULE: modulepath=%s\n",modulepath);
          uint64_t result;
          result=(uint64_t)(dlopen((const char *)modulepath, RTLD_NOW));

          debug_log("EXTCMD_LOADMODULE: dlopen returned %p\n",(void*)result);

          if (result==0)
          {
            debug_log("EXTCMD_LOADMODULE: %s\n",dlerror());
          }

          sendall(currentsocket, &result, sizeof(result), 0);
        }
      }
      break;
    }

    case EXTCMD_SPEEDHACK_SETSPEED:
    {
#pragma pack(1)
      struct {
        float speed;
      } params;

      uint32_t result;

      if (recvall(currentsocket, &params, sizeof(params), 0)>0)
      {

        result=speedhack_initializeSpeed(params.speed);
        sendall(currentsocket, &result, sizeof(result), 0);
      }
      break;
    }

    case EXTCMD_CHANGEMEMORYPROTECTION:
    {
#pragma pack(1)
      struct {
        uint64_t address;
        int size;
        int newprotection;
      } params;
#pragma pack()

      printf("EXTCMD_CHANGEMEMORYPROTECTION\n");

      if (recvall(currentsocket, &params, sizeof(params), 0)>0)
      {
        uint32_t result;
        result=mprotect((void*)params.address, params.size, params.newprotection);
        sendall(currentsocket, &result, sizeof(result), 0);
      }

      break;
    }

  }
  return 1;

}

void *newconnection(void *arg)
{
  int sockethandle=(uintptr_t)arg;
  unsigned char command;
  int r;

  r=1;
  while (r>=0)
  {
    r=recvall(sockethandle, &command, 1, MSG_WAITALL);
    if (r==1)
      DispatchCommand(sockethandle, command);
    else
    {

      close(sockethandle);
    }
  }

  debug_log("Bye\n");
  return NULL;
}

void *ServerThread(void *arg)
{
  int s=(uintptr_t)arg;

  while (!done)
  {
    struct sockaddr_un addr_client;
    socklen_t clisize=sizeof(addr_client);
    int a;
    debug_log("extension:calling accept\n");
    a=accept(s, (struct sockaddr *)&addr_client, &clisize);
    debug_log("accept returned\n");

    if (a==-1)
    {
      debug_log("accept failed: %d\n", a);
      break;
    }
    else
    {
      pthread_t pth;
      pthread_create(&pth, NULL, (void *)newconnection, (void *)(uintptr_t)a);
    }

  }

  return NULL;
}

__attribute__((destructor)) void term(void)
{

  done=1;

}

__attribute__((constructor)) void moduleinit(void)
{
  char name[256];
  int s;

  int i;

  speedhack_initializeSpeed(1.0f);

  void *X;
  void *module=NULL;

  s=socket(AF_UNIX, SOCK_STREAM, 0);

  sprintf(name, " ceserver_extension%d", getpid());

  struct sockaddr_un address;
  address.sun_family=AF_UNIX;
  strcpy(address.sun_path,name);

  int al=SUN_LEN(&address);

  address.sun_path[0]=0;

  int optval = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, optval);

  i=bind(s, (struct sockaddr *)&address, al);

  if (i==0)
  {

    int l;
    l=listen(s, 32);
    debug_log("listen=%d\n",l);

    if (l==0)
    {

      pthread_t pth;
      pthread_create(&pth, NULL, (void *)ServerThread, (void *)(uintptr_t)s);
    }
    else debug_log("listen failed: %d\n", errno);
  }
  else
    debug_log("bind failed: %d\n", errno);
}
