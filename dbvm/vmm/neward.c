#include "neward.h"
#include "common.h"
#include "main.h"

PARD fakeARD;

void setARDAddress(PARD entry, QWORD address)
{
  entry->BaseAddrLow=(DWORD)address;
  entry->BaseAddrHigh=address << 32;
}

QWORD getARDAddress(PARD entry)
{
  return entry->BaseAddrLow+(((QWORD)(entry->BaseAddrHigh))<<32);
}

void setARDSize(PARD entry, QWORD size)
{
  entry->LengthLow=(DWORD)size;
  entry->LengthHigh=size << 32;
}

QWORD getARDSize(PARD entry)
{
  return entry->LengthLow+(((QWORD)entry->LengthHigh)<<32);
}

void fakeARD_insertAtPos(int index, PARD ard)
{

  int length;
  int i;
  if (loadedOS)
    return;
  for (length=index; fakeARD[length].Type != 255; length++);

  for (i=length+1; i>index; i--)
    fakeARD[i]=fakeARD[i-1];

  fakeARD[index]=*ard;
}

void fakeARD_InsertRange(QWORD address, QWORD size, DWORD type)

{
  int i;

  if (loadedOS)
    return;

  for (i=0; fakeARD[i].Type != 255 ;i++)
  {
    PARD e=&fakeARD[i];
    QWORD a_address=getARDAddress(e);
    QWORD a_size=getARDSize(e);

    if ((address>=a_address) && (address<a_address+a_size))
    {

      if (e->Type==type)
        return;

      if (address==a_address)
      {

        if ((i>0) && (fakeARD[i-1].Type==type) && (getARDAddress(&fakeARD[i-1])==address))
        {
          PARD e2=&fakeARD[i-1];

          setARDSize(e2, getARDSize(e2)+size);
          setARDAddress(e, getARDAddress(e)+size);
          setARDSize(e, getARDAddress(e)-size);
          return;
        }
      }

      if ((address+size)==a_address+a_size)
      {

        PARD e2=&fakeARD[i+1];
        if ((e2->Type==type) && (getARDAddress(e2)==address+size))
        {

          setARDSize(e, getARDSize(e)-size);
          setARDAddress(e2, getARDAddress(e2)-size);
          setARDSize(e2, getARDSize(e2)+size);
          return;
        }
      }

      int j;
      ARD newentry;
      setARDAddress(&newentry, address);
      setARDSize(&newentry, size);

      ARD before=*e;
      ARD after=*e;

      setARDSize(&before, address-a_address);

      setARDAddress(&after, address+size);
      setARDSize(&after, (a_address+a_size)-getARDAddress(&after));

      if ((getARDSize(&before)==0) && (getARDSize(&after)==0))
      {

        e->Type=type;
        return;
      }

      j=i;
      if (getARDSize(&before))
      {
        *e=before;
        j++;
      }

      fakeARD_insertAtPos(j, &newentry);
      j++;

      if (getARDSize(&after))
        fakeARD_insertAtPos(j, &after);
    }

  }
}

int fakeARD_getConventionalMemory()
{

  int i;
  int size=0;
  if (!loadedOS)
  {
    for (i=0; fakeARD[i].Type != 255 ;i++)
    {
      if (getARDAddress(&fakeARD[i])==0)
        size=max(size, getARDSize(&fakeARD[i]));

    }
  }

  return size;
}

void sendARD(void)
{
	int i;
	unsigned long long tempbase;
	unsigned long long templength;

	if (!loadedOS)
	{
    for (i=0; fakeARD[i].Type != 255 ;i++)
    {
      tempbase=((unsigned long long)fakeARD[i].BaseAddrHigh << 32)+fakeARD[i].BaseAddrLow;
      templength=((unsigned long long)fakeARD[i].LengthHigh << 32)+fakeARD[i].LengthLow;

      displayline("i=%d : BaseAddress=%6, Length=%6, Type=%d \n",i, tempbase, templength, fakeARD[i].Type);
    }
	}
}

void initARDcount(void)
{
  int i;
  ARDcount=0;

  if (!loadedOS)
  {
    for (i=0; fakeARD[i].Type != 255 ;i++)
    {
      ARDcount++;
    }
  }
}
