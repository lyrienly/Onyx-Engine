#ifndef D3DHOOKSHARED_H
#define D3DHOOKSHARED_H

#include <windows.h>

#pragma pack(1)

typedef struct
{

	float offset;
	float charwidth;
} CHARINFO, *PCHARINFO;

typedef struct
{
	float charheight;
	float fullwidth;
	CHARINFO charinfo[96];
} FONTMAP, *PFONTMAP;

typedef volatile struct
{
	UINT64 AddressOfTexture;
	UINT64 AddressOfFontmap;
	int size;
	int hasBeenUpdated;
} *PTextureEntry;

enum RenderCommandEnum { rcEndOfCommandlist=0,
						 rcIgnored=1,
						 rcDrawSprite=2,
						 rcDrawFont=3
   					};

typedef volatile struct
{
	int Command;
	float x;
	float y;
	float alphablend;

	float centerX;
	float centerY;
	float rotation;

	union
	{
		struct
		{
			int width;
			int height;
			int textureid;
		} sprite;

		struct
		{
			UINT64 addressoftext;
			int fontid;
		} font;
	};

} D3DRenderCommand, *PD3DRenderCommand;

typedef volatile struct
{
	char CheatEngineDir[256];
	char SnapShotDir[256];
	UINT64 dxgi_present;
	UINT64 dxgi_resizebuffers;
	UINT64 d3d9_present;
	UINT64 d3d9_reset;

	UINT64 d3d9_drawprimitive;
	UINT64 d3d9_drawindexedprimitive;
	UINT64 d3d9_drawprimitiveup;
	UINT64 d3d9_drawindexedprimitiveup;
	UINT64 d3d9_drawrectpatch;
	UINT64 d3d9_drawtripatch;

	UINT64 d3d10_drawindexed;
	UINT64 d3d10_draw;
	UINT64 d3d10_drawindexedinstanced;
	UINT64 d3d10_drawinstanced;
	UINT64 d3d10_drawauto;

	UINT64 d3d11_drawindexed;
	UINT64 d3d11_draw;
	UINT64 d3d11_drawindexedinstanced;
	UINT64 d3d11_drawinstanced;
	UINT64 d3d11_drawauto;

	UINT64 dxgi_newpresent;
	UINT64 dxgi_newresizebuffers;
	UINT64 d3d9_newpresent;
	UINT64 d3d9_newreset;

	UINT64 d3d9_newdrawprimitive;
	UINT64 d3d9_newdrawindexedprimitive;
	UINT64 d3d9_newdrawprimitiveup;
	UINT64 d3d9_newdrawindexedprimitiveup;
	UINT64 d3d9_newdrawrectpatch;
	UINT64 d3d9_newdrawtripatch;

	UINT64 d3d10_newdrawindexed;
	UINT64 d3d10_newdraw;
	UINT64 d3d10_newdrawindexedinstanced;
	UINT64 d3d10_newdrawinstanced;
	UINT64 d3d10_newdrawauto;

	UINT64 d3d11_newdrawindexed;
	UINT64 d3d11_newdraw;
	UINT64 d3d11_newdrawindexedinstanced;
	UINT64 d3d11_newdrawinstanced;
	UINT64 d3d11_newdrawauto;

	UINT64 dxgi_originalpresent;
	UINT64 dxgi_originalresizebuffers;
	UINT64 d3d9_originalpresent;
	UINT64 d3d9_originalreset;

	UINT64 d3d9_originaldrawprimitive;
	UINT64 d3d9_originaldrawindexedprimitive;
	UINT64 d3d9_originaldrawprimitiveup;
	UINT64 d3d9_originaldrawindexedprimitiveup;
	UINT64 d3d9_originaldrawrectpatch;
	UINT64 d3d9_originaldrawtripatch;

	UINT64 d3d10_originaldrawindexed;
	UINT64 d3d10_originaldraw;
	UINT64 d3d10_originaldrawindexedinstanced;
	UINT64 d3d10_originaldrawinstanced;
	UINT64 d3d10_originaldrawauto;

	UINT64 d3d11_originaldrawindexed;
	UINT64 d3d11_originaldraw;
	UINT64 d3d11_originaldrawindexedinstanced;
	UINT64 d3d11_originaldrawinstanced;
	UINT64 d3d11_originaldrawauto;

	int wireframe;
	int disabledzbuffer;

	int hookwnd;
	int clipmouseinwindow;
	int clickedoverlay;
	int clickedx;
	int clickedy;

	struct
	{
		int hasconsole;
		int consolevisible;
		DWORD consolekey;

		int overlayid;
		int cursorid;

		struct
		{
			UINT uMsg;
			UINT64 wParam;
			UINT64 lParam;
			DWORD character;
		} lastmessage;

	} console;

	DWORD lastHwnd;

	int texturelistHasUpdate;
	int textureCount;
	UINT64 texturelist;
	UINT64 TextureLock;

	UINT64 CommandlistLock;
	int UseCommandlistLock;
	int hasOnKey;

    DWORD snapshotKey;
	DWORD smallSnapshotKey;

	UINT64 snapshotDone;
	int snapshotImageFormat;
	int snapshotcount;
	int progressiveSnapshot;
	int alsoClearDepthBuffer;
	int savePNGSeperateAsWell;
	int canDoSnapshot;
	DWORD initialized;

	D3DRenderCommand RenderCommands[100000];

} *PD3DHookShared;
#pragma pack()

#endif
