#include <stdio.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <zlib.h>
#include <errno.h>

#include "api.h"
#include "symbols.h"

#pragma pack(1)
typedef struct
{
  uint64_t address;
  int size;
  int type;
  unsigned char namelength;
  char name[0];
} symbolinfo, *psymbolinfo;
#pragma pack()

#define TEMPBUFSIZE 64*1024

void loadStringTable64(int f, unsigned int fileoffset, Elf64_Shdr *sectionHeaders, unsigned char **stringTable, int index)
{
  if ((stringTable[index]==NULL) && (sectionHeaders[index].sh_type==SHT_STRTAB))
  {
    stringTable[index]=malloc(sectionHeaders[index].sh_size);
    if (pread(f, stringTable[index], sectionHeaders[index].sh_size, sectionHeaders[index].sh_offset+fileoffset)==-1)
    {
      debug_log("loadStringTable64: Failure loading the stringtable\n");
      free(stringTable[index]);
      stringTable[index]=NULL;
    }

  }
  else
  {
    if (stringTable[index]==NULL)
      debug_log("loadStringTable64: Was already loaded");
    else
      debug_log("loadStringTable64: Not a string table\n");
  }
}

void loadStringTable32(int f, unsigned int fileoffset, Elf32_Shdr *sectionHeaders, unsigned char **stringTable, int index)
{
  if ((stringTable[index]==NULL) && (sectionHeaders[index].sh_type==SHT_STRTAB))
  {
    stringTable[index]=malloc(sectionHeaders[index].sh_size);
    if (pread(f, stringTable[index], sectionHeaders[index].sh_size, sectionHeaders[index].sh_offset+fileoffset)==-1)
    {
      debug_log("Failure loading the stringtable\n");
      free(stringTable[index]);
      stringTable[index]=NULL;
    }

  }
  else
    debug_log("Not a string table\n");
}

BOOL ELF32_scan(int f, unsigned int fileoffset, Elf32_Ehdr *b, char *searchedsymbolname, symcallback cb, void* context)

{
  int i,j;

  Elf32_Shdr *sectionHeaders=malloc(b->e_shentsize*b->e_shnum);

  if (pread(f, sectionHeaders, b->e_shentsize*b->e_shnum, b->e_shoff+fileoffset)==-1)
  {
    if (sectionHeaders)
      free(sectionHeaders);

    return FALSE;
  }

  unsigned char **stringTable=calloc(b->e_shnum, sizeof(unsigned char*) );

  loadStringTable32(f, fileoffset, sectionHeaders, stringTable, b->e_shstrndx);

  for (i=0; i<b->e_shnum; i++)
  {
    if ((sectionHeaders[i].sh_type==SHT_SYMTAB) || (sectionHeaders[i].sh_type==SHT_DYNSYM))
    {
      Elf32_Sym *symbolTable=malloc(sectionHeaders[i].sh_size);
      if (pread(f, symbolTable, sectionHeaders[i].sh_size, sectionHeaders[i].sh_offset+fileoffset)==-1)
      {
        free(symbolTable);
        symbolTable=NULL;
      }

      if (symbolTable)
      {
        int maxindex=sectionHeaders[i].sh_size / sizeof(Elf32_Sym);

        loadStringTable32(f, fileoffset, sectionHeaders, stringTable, sectionHeaders[i].sh_link);

        for (j=0; j<maxindex; j++)
        {
          if (symbolTable[j].st_value)
          {

            char *symbolname=(char *)&stringTable[sectionHeaders[i].sh_link][symbolTable[j].st_name];

            if (strcmp(symbolname,searchedsymbolname)==0)
            {
              cb(symbolTable[j].st_value, symbolname, context);
              break;
            }
          }
        }

        free(symbolTable);
      }
    }
  }

  for (i=0; i<b->e_shnum; i++)
  {
    if (stringTable[i])
      free(stringTable[i]);
  }
  free(stringTable);
  free(sectionHeaders);

  return TRUE;
}

int ELF64_scan(int f, unsigned int fileoffset, Elf64_Ehdr *b, char *searchedsymbolname, symcallback cb, void* context)

{
  int i,j;

  Elf64_Shdr *sectionHeaders=malloc(b->e_shentsize*b->e_shnum);

  if (pread(f, sectionHeaders, b->e_shentsize*b->e_shnum, b->e_shoff+fileoffset)==-1)
  {
    if (sectionHeaders)
      free(sectionHeaders);

    return FALSE;
  }

  unsigned char **stringTable=calloc(b->e_shnum, sizeof(unsigned char*) );

  loadStringTable64(f, fileoffset, sectionHeaders, stringTable, b->e_shstrndx);

  for (i=0; i<b->e_shnum; i++)
  {
    if ((sectionHeaders[i].sh_type==SHT_SYMTAB) || (sectionHeaders[i].sh_type==SHT_DYNSYM))
    {
      Elf64_Sym *symbolTable=malloc(sectionHeaders[i].sh_size);
      if (pread(f, symbolTable, sectionHeaders[i].sh_size, sectionHeaders[i].sh_offset+fileoffset)==-1)
      {
        free(symbolTable);
        symbolTable=NULL;
      }

      if (symbolTable)
      {
        int maxindex=sectionHeaders[i].sh_size / sizeof(Elf64_Sym);

        loadStringTable64(f, fileoffset, sectionHeaders, stringTable, sectionHeaders[i].sh_link);

        for (j=0; j<maxindex; j++)
        {
          if (symbolTable[j].st_value)
          {

            char *symbolname=(char *)&stringTable[sectionHeaders[i].sh_link][symbolTable[j].st_name];

            if (strcmp(symbolname,searchedsymbolname)==0)
            {
              cb(symbolTable[j].st_value, symbolname, context);
              break;
            }
          }
        }
      }
      free(symbolTable);

    }

  }

  for (i=0; i<b->e_shnum; i++)
  {
    if (stringTable[i])
      free(stringTable[i]);
  }
  free(stringTable);
  free(sectionHeaders);

  return TRUE;

}

int ELF32(int f, unsigned int fileoffset, Elf32_Ehdr *b, unsigned char **output)

{
  int i,j;

  if (b->e_phentsize==0)
  {
    debug_log("invalid: e_phentsize is 0");
    return 0;
  }

  unsigned char *tempbuffer=NULL;
  int tempbufferpos=0;
  int maxoutputsize=TEMPBUFSIZE;
  tempbuffer=malloc(TEMPBUFSIZE);
  int offset=0;

  Elf64_Phdr *programHeaders=malloc(b->e_phentsize*b->e_phnum);
  if (pread(f, programHeaders, b->e_phentsize*b->e_phnum, b->e_phoff+fileoffset)==-1)
  {
    if (programHeaders)
      free(programHeaders);

    return 0;
  }

  for (i=0; i<b->e_phnum; i++)
  {
    if (programHeaders[i].p_type==PT_LOAD)
    {
      offset=programHeaders[i].p_vaddr;
      break;
    }
  }

  z_stream strm;
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  deflateInit(&strm, 9);

  *output=malloc(maxoutputsize);

  strm.avail_out=maxoutputsize-3*sizeof(uint32_t);
  strm.next_out=(unsigned char *)&(*output)[sizeof(uint32_t)*3];

  *(uint32_t *)(&(*output)[0])=(b->e_type==ET_EXEC);

  Elf32_Shdr *sectionHeaders=malloc(b->e_shentsize*b->e_shnum);

  if (pread(f, sectionHeaders, b->e_shentsize*b->e_shnum, b->e_shoff+fileoffset)==-1)
  {

    deflateEnd(&strm);
    if (sectionHeaders)
      free(sectionHeaders);

    if (*output)
    {
      free(*output);
      *output=NULL;
    }

    if (tempbuffer)
      free(tempbuffer);

    if (programHeaders)
      free(programHeaders);

    return -1;
  }

  unsigned char **stringTable=calloc(b->e_shnum, sizeof(unsigned char*) );

  loadStringTable32(f, fileoffset, sectionHeaders, stringTable, b->e_shstrndx);

  for (i=0; i<b->e_shnum; i++)
  {
    if ((sectionHeaders[i].sh_type==SHT_SYMTAB) || (sectionHeaders[i].sh_type==SHT_DYNSYM))
    {
      Elf32_Sym *symbolTable=malloc(sectionHeaders[i].sh_size);
      if (pread(f, symbolTable, sectionHeaders[i].sh_size, sectionHeaders[i].sh_offset+fileoffset)==-1)
      {
        free(symbolTable);
        symbolTable=NULL;
      }

      if (symbolTable)
      {
        int maxindex=sectionHeaders[i].sh_size / sizeof(Elf32_Sym);

        loadStringTable32(f, fileoffset, sectionHeaders, stringTable, sectionHeaders[i].sh_link);

        for (j=0; j<maxindex; j++)
        {
          if (symbolTable[j].st_value)
          {

            char *symbolname=(char *)&stringTable[sectionHeaders[i].sh_link][symbolTable[j].st_name];
            size_t namelength=strlen(symbolname);
            int entrysize=sizeof(symbolinfo)+namelength;
            if (tempbufferpos+entrysize>=TEMPBUFSIZE)
            {

               strm.avail_in=tempbufferpos;
               strm.next_in=tempbuffer;

               while (strm.avail_in)
               {
                 if (deflate(&strm, Z_NO_FLUSH)!=Z_OK)
                 {

                   if (sectionHeaders)
                     free(sectionHeaders);

                   if (*output)
                   {
                     free(*output);
                     *output=NULL;
                   }

                   if (tempbuffer)
                     free(tempbuffer);

                   if (programHeaders)
                     free(programHeaders);
                   return -1;
                 }

                 if (strm.avail_out==0)
                 {
                   *output=realloc(*output, maxoutputsize*2);

                   strm.next_out=(unsigned char *)&(*output)[maxoutputsize];
                   strm.avail_out=maxoutputsize;
                   maxoutputsize=maxoutputsize*2;
                 }

               }
               tempbufferpos=0;
            }

            psymbolinfo si=(psymbolinfo)&tempbuffer[tempbufferpos];
            si->address=symbolTable[j].st_value;
            si->size=symbolTable[j].st_size;
            si->type=symbolTable[j].st_info;
            si->namelength=namelength;
            memcpy(&si->name, symbolname, namelength);

            tempbufferpos+=entrysize;
          }
        }
      }
      free(symbolTable);

    }

  }

  for (i=0; i<b->e_shnum; i++)
  {
    if (stringTable[i])
      free(stringTable[i]);
  }
  free(stringTable);

  free(sectionHeaders);

  if (programHeaders)
    free(programHeaders);

  strm.avail_in=tempbufferpos;
  strm.next_in=tempbuffer;

  while (1)
  {

    i=deflate(&strm, Z_FINISH);

    if (i==Z_STREAM_END)
      break;

    if (i!=Z_OK)
    {
      debug_log("Failure to compress: %i\n", i);
      return -1;
    }

    if (strm.avail_out==0)
    {
      debug_log("Out buffer full. Reallocating :%d\n", maxoutputsize*2);
      *output=realloc(*output, maxoutputsize*2);

      strm.next_out=(unsigned char *)&(*output)[maxoutputsize];
      strm.avail_out=maxoutputsize;
      maxoutputsize=maxoutputsize*2;

    }
    else
      break;

  };

  deflateEnd(&strm);

  *(uint32_t *)(&(*output)[4])=strm.total_out+3*sizeof(uint32_t);
  *(uint32_t *)(&(*output)[8])=strm.total_in;

  free(tempbuffer);

  return 0;
}

int ELF64(int f, unsigned int fileoffset, Elf64_Ehdr *b, unsigned char **output)

{
  int i,j;

  if (b->e_phentsize==0)
  {
    debug_log("invalid: e_phentsize is 0");
    return 0;
  }

  unsigned char *tempbuffer=NULL;
  int tempbufferpos=0;
  int maxoutputsize=TEMPBUFSIZE;
  tempbuffer=malloc(TEMPBUFSIZE);
  int offset=0;

  Elf64_Phdr *programHeaders=malloc(b->e_phentsize*b->e_phnum);
  if (pread(f, programHeaders, b->e_phentsize*b->e_phnum, b->e_phoff+fileoffset)==-1)
  {
    if (programHeaders)
      free(programHeaders);

    return 0;
  }

  for (i=0; i<b->e_phnum; i++)
  {
    if (programHeaders[i].p_type==PT_LOAD)
    {
      offset=programHeaders[i].p_vaddr;
      break;
    }
  }

  z_stream strm;
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  deflateInit(&strm, 9);

  *output=malloc(maxoutputsize);

  strm.avail_out=maxoutputsize-3*sizeof(uint32_t);
  strm.next_out=(unsigned char *)&(*output)[sizeof(uint32_t)*3];

  *(uint32_t *)(&(*output)[0])=(b->e_type==ET_EXEC);

  Elf64_Shdr *sectionHeaders=malloc(b->e_shentsize*b->e_shnum);

  if (pread(f, sectionHeaders, b->e_shentsize*b->e_shnum, b->e_shoff+fileoffset)==-1)
  {

    deflateEnd(&strm);
    if (sectionHeaders)
      free(sectionHeaders);

    if (*output)
    {
      free(*output);
      *output=NULL;
    }

    if (tempbuffer)
      free(tempbuffer);

    if (programHeaders)
      free(programHeaders);

    return -1;
  }

  unsigned char **stringTable=calloc(b->e_shnum, sizeof(unsigned char*) );

  if (b->e_shstrndx<b->e_shnum)
  {
    loadStringTable64(f, fileoffset, sectionHeaders, stringTable, b->e_shstrndx);

    for (i=0; i<b->e_shnum; i++)
    {

      if ((sectionHeaders[i].sh_type==SHT_SYMTAB) || (sectionHeaders[i].sh_type==SHT_DYNSYM))
      {
        Elf64_Sym *symbolTable=malloc(sectionHeaders[i].sh_size);
        if (pread(f, symbolTable, sectionHeaders[i].sh_size, sectionHeaders[i].sh_offset+fileoffset)==-1)
        {

          free(symbolTable);
          symbolTable=NULL;
        }

        if (symbolTable)
        {
          int maxindex=sectionHeaders[i].sh_size / sizeof(Elf64_Sym);

          if (sectionHeaders[i].sh_link<b->e_shnum)
          {

            loadStringTable64(f, fileoffset, sectionHeaders, stringTable, sectionHeaders[i].sh_link);

            for (j=0; j<maxindex; j++)
            {

              if (symbolTable[j].st_value)
              {

                char *symbolname=(char *)&stringTable[sectionHeaders[i].sh_link][symbolTable[j].st_name];

                size_t namelength=strlen(symbolname);
                int entrysize=sizeof(symbolinfo)+namelength;
                if (tempbufferpos+entrysize>=TEMPBUFSIZE)
                {

                   strm.avail_in=tempbufferpos;
                   strm.next_in=tempbuffer;

                   while (strm.avail_in)
                   {
                     if (deflate(&strm, Z_NO_FLUSH)!=Z_OK)
                     {
                       debug_log("FAILURE TO COMPRESS!\n");
                       return -1;
                     }

                     if (strm.avail_out==0)
                     {

                       *output=realloc(*output, maxoutputsize*2);

                       strm.next_out=(unsigned char *)&(*output)[maxoutputsize];
                       strm.avail_out=maxoutputsize;
                       maxoutputsize=maxoutputsize*2;
                     }

                   }
                   tempbufferpos=0;
                }

                psymbolinfo si=(psymbolinfo)&tempbuffer[tempbufferpos];
                si->address=symbolTable[j].st_value-offset;
                si->size=symbolTable[j].st_size;
                si->type=symbolTable[j].st_info;
                si->namelength=namelength;
                memcpy(&si->name, symbolname, namelength);

                tempbufferpos+=entrysize;
              }
            }
          }
          else
          {
            debug_log("Error: sectionHeaders[%d].sh_link>=b->e_shnum", i);
          }
        }
        free(symbolTable);

      }

    }
  }
  else
  {
    debug_log("Error: e_shstrndx>=e_shnum");
  }

  for (i=0; i<b->e_shnum; i++)
  {
    if (stringTable[i])
      free(stringTable[i]);
  }
  free(stringTable);

  free(sectionHeaders);

  free(programHeaders);

  strm.avail_in=tempbufferpos;
  strm.next_in=tempbuffer;

  while (1)
  {

    i=deflate(&strm, Z_FINISH);

    if (i==Z_STREAM_END)
      break;

    if (i!=Z_OK)
    {
      debug_log("Failure to compress: %i\n", i);
      return -1;
    }

    if (strm.avail_out==0)
    {

      *output=realloc(*output, maxoutputsize*2);

      strm.next_out=(unsigned char *)&(*output)[maxoutputsize];
      strm.avail_out=maxoutputsize;
      maxoutputsize=maxoutputsize*2;
    }
    else
      break;

  };

  deflateEnd(&strm);

  *(uint32_t *)(&(*output)[4])=strm.total_out+3*sizeof(uint32_t);
  *(uint32_t *)(&(*output)[8])=strm.total_in;

  free(tempbuffer);

  return 0;

}

typedef struct _fsc {
  uintptr_t modulebase;
  symcallback originalCallback;
  void* originalContext;
} FindSymbolContext, *PFindSymbolContext;

void FindSymbol_internal(uintptr_t address, char* symbolname, PFindSymbolContext context)
{
  context->originalCallback(context->modulebase+address, symbolname, context->originalContext);
}

int FindSymbol(HANDLE hProcess, char *symbolname, symcallback cb, void* context)
{
  HANDLE ths;
  ModuleListEntry mle;

  if (GetHandleType(hProcess) == htProcesHandle )
  {

    FindSymbolContext c;
    c.originalCallback=cb;
    c.originalContext=context;
    PProcessData p=(PProcessData)GetPointerFromHandle(hProcess);
    if (p==NULL)
      return FALSE;

    ths=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,p->pid);

    if (Module32First(ths,&mle)) do
    {
      if (mle.part==0)
      {
        int i,f;
        unsigned char *b=NULL;
        unsigned int fileoffset=mle.fileOffset;

        c.modulebase=mle.baseAddress;

        f=open(mle.moduleName, O_RDONLY);
        if (f==-1)
          continue;

        b=malloc(sizeof(Elf64_Ehdr));
        if (b)
        {
          i=pread(f, b, sizeof(Elf64_Ehdr), fileoffset);
          if (*(uint32_t *)b==0x464c457f)
          {
            if (b[EI_CLASS]==ELFCLASS32)
              i=ELF32_scan(f, fileoffset, (Elf32_Ehdr *)b, symbolname, (symcallback)FindSymbol_internal, (void*)&c);
            else
              i=ELF64_scan(f, fileoffset, (Elf64_Ehdr *)b, symbolname, (symcallback)FindSymbol_internal, (void*)&c);
          }

          free(b);
        }

        close(f);
      }
    } while (Module32Next(ths, &mle));

    CloseHandle(ths);

  }

  return 0;
}

int GetSymbolListFromFile(char *filename, uint32_t fileoffset, unsigned char **output)

{
  int i, f;
  unsigned char *b=NULL;

  if (fileoffset)
    debug_log("GetSymbolListFromFile(%s, %x)\n", filename, fileoffset);

  *output=NULL;
  f=open(filename, O_RDONLY);
  if (f==-1)
  {
    if (fileoffset)
      debug_log("open(%s) failed: %s\n", strerror(errno));
    return -1;
  }

  b=malloc(sizeof(Elf64_Ehdr));
  if (b)
  {
    i=pread(f, b, sizeof(Elf64_Ehdr), fileoffset);
    if (i==-1)
    {
      debug_log("Failure reading %d bytes from %s at 0x%x\n (%s)", sizeof(Elf64_Ehdr), filename, fileoffset, strerror(errno));
      return -1;
    }

    if (fileoffset)
      debug_log("b[0..3]=%.2x %.2x %.2x %.2x\n", b[0],b[1],b[2],b[3]);

    if (*(uint32_t *)b!=0x464c457f)
    {
      if (fileoffset)
        debug_log("Not an ELF file\n");

      return -1;
    }

    if (b[EI_CLASS]==ELFCLASS32)
      i=ELF32(f, fileoffset, (Elf32_Ehdr *)b, output);
    else
      i=ELF64(f, fileoffset, (Elf64_Ehdr *)b, output);

    free(b);
  }
  else
    i=-1;

  close(f);

  return i;
}

int GetModuleSize32(int f, uint32_t fileoffset, Elf32_Ehdr *b)
{

  if (b->e_phentsize==0)
  {
    debug_log("invalid program header entry size (0)\n");
    return -1;
  }

  Elf32_Phdr *programHeaders=malloc(b->e_phentsize*b->e_phnum);

  if (pread(f, programHeaders, b->e_phentsize*b->e_phnum, b->e_phoff+fileoffset)==-1)
  {
    if (programHeaders)
      free(programHeaders);

    return 0;
  }

  int i;
  unsigned long long lowest=0x1000;
  unsigned long long highest=0x1000;

  for (i=0; i<b->e_phnum; i++)
  {

    if ((programHeaders[i].p_type==PT_LOAD) && (programHeaders[i].p_memsz>0))
    {
      if ((i==0) || (programHeaders[i].p_vaddr<lowest))
         lowest=programHeaders[i].p_vaddr;

      if ((i==0) || (programHeaders[i].p_vaddr+programHeaders[i].p_memsz>highest))
         highest=programHeaders[i].p_vaddr+programHeaders[i].p_memsz;

    }
  }

  if (programHeaders)
    free(programHeaders);

  if (lowest)
    return -1;
  else
    return highest;
}

int GetModuleSize64(int f, uint32_t fileoffset, Elf64_Ehdr *b)
{

  debug_log("b->e_phentsize=%d\n", b->e_phentsize);

  if (b->e_phentsize==0)
  {
    debug_log("invalid program header entry size (0)\n");
    return -1;
  }

  Elf64_Phdr *programHeaders=malloc(b->e_phentsize*b->e_phnum);

  memset(programHeaders,0, sizeof(Elf64_Phdr));

  if (pread(f, programHeaders, b->e_phentsize*b->e_phnum, b->e_phoff+fileoffset)==-1)
  {
    if (programHeaders)
      free(programHeaders);

    return 0;
  }

  int i;
  unsigned long long lowest=0x1000;
  unsigned long long highest=0x1000;

  for (i=0; i<b->e_phnum; i++)
  {
     if ((programHeaders[i].p_type==PT_LOAD) && (programHeaders[i].p_memsz>0))
     {
       if ((i==0) || (programHeaders[i].p_vaddr<lowest))
          lowest=programHeaders[i].p_vaddr;

       if ((i==0) || (programHeaders[i].p_vaddr+programHeaders[i].p_memsz>highest))
          highest=programHeaders[i].p_vaddr+programHeaders[i].p_memsz;

     }
  }

    if (programHeaders)
      free(programHeaders);

   if (lowest)
     return -1;
   else
     return highest;
}

unsigned long long GetModuleSize(char *filename, uint32_t fileoffset, unsigned long long defaultsize)

{
  int i,f;
  unsigned char *b=NULL;

  f=open(filename, O_RDONLY);
  if (f==-1)
  {
    printf("Failed to open %s\n", filename);
    return defaultsize;
  }
  else
  {
    b=malloc(sizeof(Elf64_Ehdr));
    if (b)
    {
      i=pread(f, b, sizeof(Elf64_Ehdr), fileoffset);

      if (*(uint32_t *)b!=0x464c457f)
      {
        printf("%s is not an elf\n", filename);
        free(b);
        close(f);
        return defaultsize;
      }

      if (b[EI_CLASS]==ELFCLASS32)
        i=GetModuleSize32(f, fileoffset, (Elf32_Ehdr *)b);
      else
        i=GetModuleSize64(f, fileoffset, (Elf64_Ehdr *)b);

      free(b);
      close(f);

      if (i==-1)
        i=defaultsize;

      return i;
    }
    else
    {
      close(f);
      return defaultsize;
    }

  }

}
