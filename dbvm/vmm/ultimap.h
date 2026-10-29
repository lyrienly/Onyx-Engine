#ifndef ULTIMAP_H_
#define ULTIMAP_H_

#include "vmmhelper.h"
#include "common.h"

void ultimap_disable(pcpuinfo currentcpuinfo);
void ultimap_setup(pcpuinfo currentcpuinfo, QWORD CR3, QWORD DEBUGCTL, QWORD DS_AREA);
void ultimap_handleCR3Change(pcpuinfo currentcpuinfo, QWORD oldcr3, QWORD newcr3);
void ultimap_handleDB(pcpuinfo currentcpuinfo);
void ultimap_handleMSRWrite(pcpuinfo currentcpuinfo, DWORD msr, QWORD value);
QWORD ultimap_handleMSRRead(pcpuinfo currentcpuinfo, DWORD msr);

void ultimap_pause(pcpuinfo currentcpuinfo);
void ultimap_resume(pcpuinfo currentcpuinfo);
#ifdef ULTIMAPDEBUG

typedef struct
{
  QWORD Active;
  QWORD CR3;
  QWORD DEBUGCTL;
  QWORD DS_AREA;
  QWORD OriginalDebugCTL;
  QWORD OriginalDS_AREA;
  QWORD CR3_switchcount;
  QWORD CR3_switchcount2;
  QWORD LastOldCR3;
  QWORD LastNewCR3;
  QWORD CpuNr;
} *PULTIMAPDEBUGINFO;

void ultimap_debugoutput(pcpuinfo currentcpuinfo, PULTIMAPDEBUGINFO UltimapDebugInfo);
#endif

#endif
