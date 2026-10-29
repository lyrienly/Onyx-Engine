#ifndef TREADS_H_
#define TREADS_H_

#include <sys/queue.h>
#include "api.h"

void InitializeProcessThreadlist(PProcessData p);
void AddThreadToProcess(PProcessData p, PThreadData threaddata);
int RemoveThreadFromProcess(PProcessData p, int tid);
PThreadData GetThreadData(PProcessData p, int tid);

#endif
