#include "common.h"

#ifndef VMMSIZE
  #error VMMSIZE must be provided
#endif

extern int reservedmem_listcount;
extern PPDPTE_PAE PageMapLevel4;
extern void gotoVMM(void) __attribute__((stdcall));
extern int readsectorasm(void) __attribute__((stdcall));
extern void halt(void) __attribute__((stdcall));

unsigned int isAP=0;

unsigned short int VMMlocation;
unsigned short int LOGOlocation;

extern int a20state;

extern int readerror;
extern int sectorsread;

extern int bootdisk;
extern int SectorsPerTrack;
extern int NumberOfHeads;
extern int NumberOfCylinders;

extern unsigned int vmmPA;

extern DWORD GDTVA;

int readsector(int sectornr, void *destination)
{
	struct
	{
		BYTE sector;
		BYTE head;
		BYTE cylinder;
		BYTE drive;
	} __attribute__((__packed__)) *readstruct=(void *)0x00070000;

	readstruct->sector=(sectornr % (SectorsPerTrack-1));
	readstruct->head=(sectornr/(SectorsPerTrack-1)) % NumberOfHeads;
	readstruct->cylinder=(sectornr/(SectorsPerTrack-1))/NumberOfHeads;
	readstruct->drive=bootdisk;
	readstruct->sector++;

	zeromemory((void *)0x00060000,512);

	if (readsectorasm()==1)
	{

		copymem(destination,(void *)0x00060000,512);
		return 1;
	}
	else
	{

		return 0;
	}
}

int _vmloader_main(void)
{
	PARD p;

	unsigned char bootsectorm[1024];
	unsigned char *bootsector=(unsigned char *)(((DWORD)bootsectorm+512) & 0xfffffe00);

	int i;
	unsigned long long maxAvailableAddress=0;
	unsigned long long tempbase=0,templength=0;
	unsigned int extramemory;
	int chosenregion=-1;
	nosendchar[getAPICID()]=0;

	zeromemory(bootsectorm, 1024);

	sendstringf("\n\n--------------------------------\n\r");
	sendstringf("Welcome to Dark Byte\'s vmloader\n\r");
	sendstringf("--------------------------------\n\r");

	sendstringf("a=%8\n\r",readerror);
	sendstringf("b=%8\n\r",sectorsread);

	sendstringf("_vmloader_main got loaded at address %8\n\r",(unsigned int)_vmloader_main);
	sendstringf("reservedmem_listcount=%d (address of it = %8 ) \n\r",reservedmem_listcount,&reservedmem_listcount);

	sendstringf("Going to read the VMM into memory...\n\r");

	sendstringf("isAP value=%2  (address=%8)\n\r",isAP,(ULONG)&isAP);

	if (!isAP)
	{
		printstring("\311\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\273", 0,0,15, 1);
		printstring("\272                                                                             \272", 0,1,15, 1);
		printstring("\272                                                                             \272", 0,2,15, 1);
		printstring("\272                                                                             \272", 0,3,15, 1);
		printstring("\272                                                                             \272", 0,4,15, 1);
		printstring("\310\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\315\274", 0,5,15, 1);

		printstring("This tool originated at",40-11,2,10,1);
		printstring("www.cheatengine.org",40-8,3,12,1);

		currentdisplayline=7;

		displayline("a20state=%d (should be 1)\n",a20state);
		displayline("bootdrive=%2 (stored at %p)\n",bootdisk, &bootdisk);
		displayline("SectorsPerTrack=%d\n",SectorsPerTrack);
		displayline("NumberOfHeads=%d\n",NumberOfHeads);
		displayline("NumberOfCylinders=%d\n",NumberOfCylinders);

		displayline("&bootsector=%p\n", &bootsector);

		displayline("Testing diskread ability....");

		if (!readsector(0, bootsector))
		{
		  sendstringf("Error loading the bootsector.\n");
			displayline("Error loading the bootsector.\n");
			while (1) ;

			readsector(-1, bootsector);
			readsector(0, bootsector);
			readsector(1, bootsector);
			readsector(2, bootsector);

			halt();
		}
		else
		{
		  displayline("Successfully loaded the bootsector\n");

		}

		VMMlocation=*(unsigned short int *)&bootsector[0x8];
		LOGOlocation=*(unsigned short int *)&bootsector[0x10];

		zeromemory(bootsectorm, 1024);
		sendstringf("VMM starts at sector %d\n\r",VMMlocation);
		sendstringf("LOGO starts at sector %d\n\r",LOGOlocation);

		displayline("VMM starts at sector %d\n",VMMlocation);

		isAP=1;
		p=(PARD)0x80000;
		for (i=0; i<reservedmem_listcount;i++)
		{
			tempbase=((unsigned long long)p[i].BaseAddrHigh << 32)+p[i].BaseAddrLow;
			templength=((unsigned long long)p[i].LengthHigh << 32)+p[i].LengthLow;

			sendstringf("i=%d : BaseAddress=%6, Length=%6, Type=%d ",i, tempbase, templength, p[i].Type);
			displayline("i=%d : BaseAddress=%6, Length=%6, Type=%d \n\r",i, tempbase, templength, p[i].Type);

			if (((tempbase+templength) < 0x100000000ULL ) && (templength>=0xc00000) && (p[i].Type==1) && (tempbase+templength>maxAvailableAddress) )
			{
				maxAvailableAddress=tempbase+templength;
				chosenregion=i;

				sendstringf(" < 'new' potential region");

			}

			sendstring("\n\r");
		}

		if (chosenregion==-1)
		{
			displayline("Failure in picking a fitting region\n");
			halt();
		}

		p[reservedmem_listcount].BaseAddrHigh=0;
		p[reservedmem_listcount].BaseAddrLow=0;
		p[reservedmem_listcount].LengthHigh=0;
		p[reservedmem_listcount].LengthLow=0;
		p[reservedmem_listcount].Type=255;

		if (maxAvailableAddress==0)
		{
			sendstringf("Not enough usable memory (at end)\n\r");
			displayline("Not enough usable memory (at end)\n\r");
		}
		else
		{
			unsigned int start;
			unsigned int gdt;
			unsigned int oldend;
			PPDE2MB_PAE PageDir;
			PPDPTE_PAE PageDirPtr;

			sendstringf("Max address=%6  (region %d)\n\r",maxAvailableAddress, chosenregion);

			start=(maxAvailableAddress-8*1024*1024);

			sendstringf("1:start=%8\n\r",start);
			displayline("1:start=%8\n\r",start);

			extramemory=0x00400000+(start & 0x003FFFFF);
			start=start & 0xFFC00000;

			sendstringf("2:start after align=%8\n\r",start);
			displayline("2:start after align=%8\n\r",start);

			sendstringf("extramemory=%8\n\r", extramemory);

			sendstringf("chosenregion=%d\n\r",chosenregion);
			displayline("chosenregion=%d\n\r",chosenregion);

			sendstringf("Adjusting memory map (done for physical memory access devices)\n\r");
			displayline("Adjusting memory map (done for physical memory access devices)\n\r");
			oldend=p[chosenregion].BaseAddrLow+p[chosenregion].LengthLow;
			p[chosenregion].LengthLow=start-p[chosenregion].BaseAddrLow;
			if (p[chosenregion+1].Type==2)
			{
				oldend=p[chosenregion+1].BaseAddrLow+p[chosenregion+1].LengthLow;

				p[chosenregion+1].BaseAddrLow=start;
				p[chosenregion+1].LengthLow=oldend-start;

				sendstringf("Adjusted reserved memory size as well\n\r");
				displayline("Adjusted reserved memory size as well\n\r");
			}
			else
			{

				for (i=reservedmem_listcount;i>chosenregion;i--)
					p[i]=p[i-1];

				p[chosenregion+1].BaseAddrHigh=0;
				p[chosenregion+1].BaseAddrLow=start;
				p[chosenregion+1].LengthHigh=0;
				p[chosenregion+1].LengthLow=oldend-start;
				p[chosenregion+1].Type=2;

				reservedmem_listcount++;
				sendstringf("inserted new region\n\r");
				displayline("inserted new region\n\r");
			}

			sendstringf("newmap=\n\r");
			displayline("newmap=\n\r");
			for (i=0; i<reservedmem_listcount;i++)
			{
				tempbase=((unsigned long long)p[i].BaseAddrHigh << 32)+p[i].BaseAddrLow;
				templength=((unsigned long long)p[i].LengthHigh << 32)+p[i].LengthLow;
				sendstringf("i=%d : BaseAddress=%6, Length=%6, Type=%d \n\r",i, tempbase, templength, p[i].Type);
				displayline("i=%d : BaseAddress=%6, Length=%6, Type=%d \n\r",i, tempbase, templength, p[i].Type);
			}

			sendstringf("reservedmem_listcount=%d\n", reservedmem_listcount);
			displayline("reservedmem_listcount=%d\n", reservedmem_listcount);

			p[reservedmem_listcount].BaseAddrHigh=0;
			p[reservedmem_listcount].BaseAddrLow=0;
			p[reservedmem_listcount].LengthHigh=0;
			p[reservedmem_listcount].LengthLow=0;
			p[reservedmem_listcount].Type=255;

			sendstringf("Going to zero 0x00400000 bytes at %p\n", start);
			displayline("Going to zero 0x00400000 bytes at %p\n", start);

			zeromemory((void *)start, 0x00400000 );

      sendstringf("After zeroing 0x00400000 bytes at %p\n", start);

			displayline("Reading %d bytes from disk into %8 ...",VMMSIZE, (unsigned int)start);

			displayline("VMMlocation=%8\n",VMMlocation);
			displayline("start=%8\n",start);
			displayline("VMMSIZE=%8\n",VMMSIZE);

			int bytesread=0;
			while (bytesread<VMMSIZE)
			{
				if (readsector(VMMlocation+(bytesread / 512),(void*)((ULONG)start+bytesread)))
				{
					displayline("+");

					bytesread+=512;
				}
				else
				{
					displayline("Read error after %d bytes\n",bytesread);
					while (1)
					{
					  displayline("ERROR!\n");
					}

				}
			}
			displayline("\n");

      displayline("Read successful\n");

      DWORD FreePA=((start+VMMSIZE) & 0xfffff000)+4096;
      PPTE_PAE pagetable2=(PPTE_PAE)FreePA;
      FreePA+=4096;
      PPTE_PAE pagetable3=(PPTE_PAE)FreePA;
      FreePA+=4096;
      DWORD mainstack=FreePA;
      FreePA+=16*4096;

      gdt=FreePA;
      FreePA+=4096;

      sendstringf("gdtbase=%8\n\r",gdt);
      copymem((void *)gdt,(void *)0x50000,0x6f);

      GDTVA=0x00400000+(gdt-start);

      PageDirPtr=(PPDPTE_PAE)FreePA;
      FreePA+=4096;
      zeromemory((void *)PageDirPtr,4096);

      PageDir=(PPDE2MB_PAE)FreePA;
      FreePA+=4096;
      zeromemory((void *)PageDir,4096);

      PageMapLevel4=(PPDPTE_PAE)FreePA;
      zeromemory((void *)PageMapLevel4,4096);
      FreePA+=4096;

      sendstringf("PageMapLevel4=%8\n\r",PageMapLevel4);
      displayline("PageMapLevel4=%8\n\r",PageMapLevel4);

      *(QWORD*)(&PageMapLevel4[0])=(QWORD)(DWORD)PageDirPtr;
      PageMapLevel4[0].P=1;
      PageMapLevel4[0].RW=1;

      *(QWORD*)(&PageDirPtr[0])=(QWORD)(DWORD)PageDir;
			PageDirPtr[0].P=1;
      PageDirPtr[0].RW=1;

      *(QWORD*)(&PageDir[0])=0;
      PageDir[0].P=1;
      PageDir[0].RW=1;
      PageDir[0].PS=1;

      *(QWORD*)(&PageDir[1])=0x00200000;
      PageDir[1].P=1;
      PageDir[1].RW=1;
      PageDir[1].PS=1;

      *(QWORD*)(&PageDir[2])=(QWORD)(DWORD)pagetable2;
      PageDir[2].P=1;
      PageDir[2].RW=1;

      *(QWORD*)(&PageDir[3])=(QWORD)(DWORD)pagetable3;
      PageDir[3].P=1;
      PageDir[3].RW=1;

      for (i=0; i<1024; i++)
      {
        *(QWORD*)(&pagetable2[i])=start+i*4096;
        pagetable2[i].P=1;
        pagetable2[i].RW=1;
      }

      int stackindex=(mainstack-start) >> 12;
      pagetable2[stackindex].P=0;

      vmmPA=start;

      sendstringf("PageDirPtr[0].PFN=%8\n\r",PageDirPtr[0].PFN);

      int t,v;
      unsigned char *u;

      sendstringf("\n\r\n\r%8:\n\r",(ULONG)start);
      u=(unsigned char*)start;

      for (v=0; v<8; v++)
      {
        sendstringf("%8 : ",start+(16*v));

        for (t=0; t<16; t++,u++)
          sendstringf("%2 ",*u);

        sendstring("\n\r");
      }

      UINT64 *s=(UINT64 *)start;

      s[2]=0;
      s[3]=start;
      s[4]=0x00400000+((DWORD)PageMapLevel4-start);
      s[5]=0x00400000+(mainstack-start)+(16*4096)-0x40;
      if (extramemory)
      {
        s[6]=start+0x00400000;
        s[7]=extramemory >> 12;
      }

      sendstringf("vmloader finished. Switching from 32-bit to 64-bit and entering VMM\n");
      displayline("vmloader finished. Switching from 32-bit to 64-bit and entering VMM\n");

      for (i=1; i<25; i++)
        displayline("\n");

      gotoVMM();
    }
  }
  else
  {
    sendstringf("This is a Application Processor\n\r");
    gotoVMM();
  }

	sendstringf("I managed to get to the end of the function. YEEEH!!!\n\r");

	return 0;
};
