#ifndef VMM_VBE3_H_
#define VMM_VBE3_H_

#include "common.h"

int initializeVBE3();

typedef struct _VBE3_PM_InfoBlock
{
  DWORD ID;
  WORD entrypoint;
  WORD PMInitialize;
  WORD BIOSDataSel;
  WORD A0000Sel;
  WORD B0000Sel;
  WORD B8000Sel;
  WORD CodeSegSel;
  unsigned char InProtectMode;
  unsigned char Checksum;
} __attribute__((__packed__)) VBE3_PM_InfoBlock, *PVBE3_PM_InfoBlock;

typedef struct _VBE_ControllerInfo
{
  DWORD VbeSignature;
  WORD VbeVersion;
  DWORD OemStringPtr;
  DWORD Capabilities;
  DWORD VideoModePtr;
  WORD TotalMemory;
  WORD OemSoftwareRev;
  DWORD OemVendorNamePtr;
  DWORD OemProductNamePtr;
  DWORD OemProductRevPtr;
  BYTE  Reserved[222];
  BYTE  OemData[256];
} __attribute__((__packed__)) VBE_ControllerInfo, *PVBE_ControllerInfo;

typedef struct _VBE_ModeInfo
{
  WORD ModeAttributes;
  BYTE WinAAttributes;
  BYTE WinBAttributes;
  WORD WinGranularity;
  WORD WinSize;
  WORD WinASegment;
  WORD WinBSegment;
  DWORD WinFuncPtr;
  WORD BytesPerScanLine;

  WORD XResolution;
  WORD YResolution;
  BYTE XCharSize;
  BYTE YCharSize;
  BYTE NumberOfPlanes;
  BYTE BitsPerPixel;
  BYTE NumberOfBanks;
  BYTE MemoryModel;
  BYTE BankSize;
  BYTE NumberOfImagePages;
  BYTE Reserved;

  BYTE RedMaskSize;
  BYTE RedFieldPosition;
  BYTE GreenMaskSize;
  BYTE GreenFieldPosition;
  BYTE BlueMaskSize;
  BYTE BlueFieldPosition;
  BYTE RsvdMaskSize;
  BYTE RsvdFieldPosition;
  BYTE DirectColorModeInfo;

  DWORD PhysBasePtr;
  DWORD Reserved2;
  WORD Reserved3;

  WORD LinBytesPerScanLine;
  BYTE BnkNumberOfImagePages;
  BYTE LinNumberOfImagePages;
  BYTE LinRedMaskSize;
  BYTE LinRedFieldPosition;
  BYTE LinGreenMaskSize;
  BYTE LinGreenFieldPosition;
  BYTE LinBlueMaskSize;
  BYTE LinBlueFieldPosition;
  BYTE LinRsvdMaskSize;
  BYTE LinRsvdFieldPosition;
  DWORD MaxPixelClock;
  BYTE filler[189];
} __attribute__((__packed__)) VBE_ModeInfo, *PVBE_ModeInfo;

typedef struct _VBE_CRTCInfo
{
  WORD HorizontalTotal;
  WORD HorizontalSyncStart;
  WORD orizontalSyncEnd;
  WORD VerticalTotal;
  WORD VerticalSyncStart;
  WORD VerticalSyncEnd;
  BYTE Flags;
  DWORD PixelClock;
  WORD RefreshRate;
} __attribute__((__packed__)) VBE_CRTCInfo, *PVBE_CRTCInfo;

void *VBEPtrToAddress(DWORD vbeptr);

int VBE_GetControllerInfo(PVBE_ControllerInfo info);
int VBE_GetModeInfo(WORD mode, PVBE_ModeInfo info);
int VBE_SetMode(WORD mode, PVBE_CRTCInfo crtcinfo);
int VBE_SaveState(void *statestore, int size);
int VBE_RestoreState(void *statestore, int size);
int VBE_GetStateStoreSize();
int VBE_SetDrawPage(int i);
int VBE_ResetStart();

void VBE_SetPenColor(DWORD ARGB);
void VBE_SetPixel(int x,int y);
void VBE_DrawLine(int x1, int y1, int x2,int y2);
void VBE_DrawBox(int x1, int y1, int x2, int y2);

#endif
