#ifndef VMM_INTERRUPTHANDLER_H_
#define VMM_INTERRUPTHANDLER_H_

#include "common.h"

extern PINT_VECTOR intvector;
extern int IntHandlerDebug;
extern int ClearDR6OnInterrupt;

void setints(void);

#endif
