#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include "api.h"
#include "options.h"
#include "ceserver.h"

int optioncount;

CEServerOption optMRO={.optname="optMSO", .parent=NULL, .description="Memory search option",  .acceptablevalues="0=/proc/pid/mem reads;1=ptrace read;2=process_vm_readv;3=process_vm_readv syscall", .type=2, .data=&MEMORY_SEARCH_OPTION};
CEServerOption optATAM={.optname="optATAM", .parent=NULL, .description="Attach to access memory",  .acceptablevalues=NULL, .type=1, .data=&ATTACH_TO_ACCESS_MEMORY};
CEServerOption optATWM={.optname="optATWM", .parent=NULL, .description="Attach to write memory",  .acceptablevalues=NULL, .type=1, .data=&ATTACH_TO_WRITE_MEMORY};
CEServerOption optAWSO={.optname="optAWSO", .parent=NULL, .description="Allocate memory without extension injection",  .acceptablevalues=NULL, .type=1, .data=&ALLOC_WITHOUT_EXTENSION};

PCEServerOption options[] = {&optMRO, &optATAM, &optATWM, &optAWSO, NULL};

void handleGetOptions(int currentsocket)
{
  int i;
  uint16_t count;
  if (optioncount==0)
    while (options[optioncount])
      optioncount++;

  count=optioncount;

  debug_log("handleGetOptions\n");

  sendall(currentsocket, &count, sizeof(count),MSG_MORE);
  for (i=0; i<count; i++)
  {
    char *currentValue=getOptionValue(options[i]);
    sendstring16(currentsocket, options[i]->optname, MSG_MORE);
    sendstring16(currentsocket, options[i]->parent, MSG_MORE);
    sendstring16(currentsocket, options[i]->description, MSG_MORE);
    sendstring16(currentsocket, options[i]->acceptablevalues, MSG_MORE);
    sendstring16(currentsocket, currentValue, MSG_MORE);
    sendinteger(currentsocket, options[i]->type, (i==count-1)?0:MSG_MORE);

    free(currentValue);
  }
}

PCEServerOption getOption(char *name)
{
  int i;
  for (i=0; i<optioncount; i++)
    if (strcmp(name, options[i]->optname)==0)
      return options[i];

  return NULL;
}

void handleSetOption(int currentsocket)
{
  char *optname=receivestring16(currentsocket);
  char *newvalue=receivestring16(currentsocket);
  char r=0;
  int i;

  if (optname && newvalue)
  {
    PCEServerOption o=getOption(optname);
    if (o)
    {
      switch (o->type)
      {
        case 1:
          i=atoi(newvalue);
          if (i)
            *(BOOL *)(o->data)=1;
          else
            *(BOOL *)(o->data)=0;

          break;

        case 2:
          *(int *)(o->data)=atoi(newvalue);
          break;

        case 3:
          *(float *)(o->data)=atof(newvalue);
          break;

        case 4:
          *(double *)(o->data)=atof(newvalue);
          break;

        case 5:
        {
          char *olds=*(char **)(o->data);
          *(char **)(o->data)=strdup(newvalue);

          free(olds);
          break;
        }

      }

    }

    free(optname);
    free(newvalue);
  }
}

char *getOptionValue(PCEServerOption o)

{
  int i;
  float f;
  double d;
  char *str;

  switch (o->type)
  {
    case 1:
      i=*(BOOL *)(o->data);
      if (i)
        return strdup("1");
      else
        return strdup("0");

    case 2:
      i=*(int *)(o->data);
      str=malloc(32);
      snprintf(str,31,"%d", i);
      return str;

    case 3:
      f=*(float *)(o->data);
      str=malloc(64);
      snprintf(str,63,"%f", f);
      return str;

    case 4:
      d=*(double *)(o->data);
      str=malloc(64);
      snprintf(str,63,"%f", d);
      return str;

    case 5:
      return strdup(*(char **)(o->data));

    case 0:
    default:
      return NULL;
  }
}

void handleGetOption(int currentsocket)
{
  char *optname=receivestring16(currentsocket);
  char *tempstring;

  if (optname)
  {
    PCEServerOption o=getOption(optname);
    if (o)
    {
      tempstring=getOptionValue(o);
      sendstring16(currentsocket, tempstring, 0);
      free(tempstring);
    }
    else
      sendstring16(currentsocket, NULL,0);

    free(optname);
  }
}
