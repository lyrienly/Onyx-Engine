#include "tcc.h"

#define DEBUG_MACHO 0
#define dprintf if (DEBUG_MACHO) printf

struct fat_header {
    uint32_t        magic;
    uint32_t        nfat_arch;
};

struct fat_arch {
    int             cputype;
    int             cpusubtype;
    uint32_t        offset;
    uint32_t        size;
    uint32_t        align;
};

#define FAT_MAGIC       0xcafebabe
#define FAT_CIGAM       0xbebafeca
#define FAT_MAGIC_64    0xcafebabf
#define FAT_CIGAM_64    0xbfbafeca

struct mach_header {
    uint32_t        magic;
    int             cputype;
    int             cpusubtype;
    uint32_t        filetype;
    uint32_t        ncmds;
    uint32_t        sizeofcmds;
    uint32_t        flags;
};

struct mach_header_64 {
    struct mach_header  mh;
    uint32_t            reserved;
};

#define MH_MAGIC        0xfeedface
#define MH_CIGAM        0xcefaedfe
#define MH_MAGIC_64     0xfeedfacf
#define MH_CIGAM_64     0xcffaedfe

struct load_command {
    uint32_t        cmd;
    uint32_t        cmdsize;
};

#define LC_REQ_DYLD 0x80000000
#define LC_SYMTAB        0x2
#define LC_DYSYMTAB      0xb
#define LC_LOAD_DYLIB    0xc
#define LC_ID_DYLIB      0xd
#define LC_LOAD_DYLINKER 0xe
#define LC_SEGMENT_64    0x19
#define LC_REEXPORT_DYLIB (0x1f | LC_REQ_DYLD)
#define LC_MAIN (0x28|LC_REQ_DYLD)

typedef int vm_prot_t;

struct segment_command_64 {
    uint32_t        cmd;
    uint32_t        cmdsize;
    char            segname[16];
    uint64_t        vmaddr;
    uint64_t        vmsize;
    uint64_t        fileoff;
    uint64_t        filesize;
    vm_prot_t       maxprot;
    vm_prot_t       initprot;
    uint32_t        nsects;
    uint32_t        flags;
};

struct section_64 {
    char            sectname[16];
    char            segname[16];
    uint64_t        addr;
    uint64_t        size;
    uint32_t        offset;
    uint32_t        align;
    uint32_t        reloff;
    uint32_t        nreloc;
    uint32_t        flags;
    uint32_t        reserved1;
    uint32_t        reserved2;
    uint32_t        reserved3;
};

#define S_REGULAR                       0x0
#define S_ZEROFILL                      0x1
#define S_NON_LAZY_SYMBOL_POINTERS      0x6
#define S_MOD_INIT_FUNC_POINTERS        0x9
#define S_MOD_TERM_FUNC_POINTERS        0xa

#define S_ATTR_PURE_INSTRUCTIONS        0x80000000
#define S_ATTR_SOME_INSTRUCTIONS        0x00000400

typedef uint32_t lc_str;

struct dylib_command {
    uint32_t cmd;
    uint32_t cmdsize;
    lc_str   name;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
};

struct dylinker_command {
    uint32_t        cmd;
    uint32_t        cmdsize;
    lc_str          name;
};

struct symtab_command {
    uint32_t        cmd;
    uint32_t        cmdsize;
    uint32_t        symoff;
    uint32_t        nsyms;
    uint32_t        stroff;
    uint32_t        strsize;
};

struct dysymtab_command {
    uint32_t cmd;
    uint32_t cmdsize;

    uint32_t ilocalsym;
    uint32_t nlocalsym;

    uint32_t iextdefsym;
    uint32_t nextdefsym;

    uint32_t iundefsym;
    uint32_t nundefsym;

    uint32_t tocoff;
    uint32_t ntoc;

    uint32_t modtaboff;
    uint32_t nmodtab;

    uint32_t extrefsymoff;
    uint32_t nextrefsyms;

    uint32_t indirectsymoff;
    uint32_t nindirectsyms;

    uint32_t extreloff;
    uint32_t nextrel;
    uint32_t locreloff;
    uint32_t nlocrel;
};

#define INDIRECT_SYMBOL_LOCAL   0x80000000

struct entry_point_command {
    uint32_t  cmd;
    uint32_t  cmdsize;
    uint64_t  entryoff;
    uint64_t  stacksize;
};

enum skind {
    sk_unknown = 0,
    sk_discard,
    sk_text,
    sk_stubs,
    sk_ro_data,
    sk_uw_info,
    sk_nl_ptr,
    sk_la_ptr,
    sk_init,
    sk_fini,
    sk_rw_data,
    sk_bss,
    sk_linkedit,
    sk_last
};

struct nlist_64 {
    uint32_t  n_strx;
    uint8_t n_type;
    uint8_t n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

#define N_UNDF  0x0
#define N_ABS   0x2
#define N_EXT   0x1
#define N_SECT  0xe

#define N_WEAK_REF      0x0040
#define N_WEAK_DEF      0x0080

struct macho {
    struct mach_header_64 mh;
    int seg2lc[4], nseg;
    struct load_command **lc;
    struct entry_point_command *ep;
    int nlc;
    struct {
        Section *s;
        int machosect;
    } sk_to_sect[sk_last];
    int *elfsectomacho;
    int *e2msym;
    Section *symtab, *strtab, *wdata, *indirsyms, *stubs;
    int stubsym;
    uint32_t ilocal, iextdef, iundef;
};

#define SHT_LINKEDIT (SHT_LOOS + 42)
#define SHN_FROMDLL  (SHN_LOOS + 2)

static void * add_lc(struct macho *mo, uint32_t cmd, uint32_t cmdsize)
{
    struct load_command *lc = tcc_mallocz(cmdsize);
    lc->cmd = cmd;
    lc->cmdsize = cmdsize;
    mo->lc = tcc_realloc(mo->lc, sizeof(mo->lc[0]) * (mo->nlc + 1));
    mo->lc[mo->nlc++] = lc;
    return lc;
}

static struct segment_command_64 * add_segment(struct macho *mo, char *name)
{
    struct segment_command_64 *sc = add_lc(mo, LC_SEGMENT_64, sizeof(*sc));
    strncpy(sc->segname, name, 16);
    mo->seg2lc[mo->nseg++] = mo->nlc - 1;
    return sc;
}

static struct segment_command_64 * get_segment(struct macho *mo, int i)
{
    return (struct segment_command_64 *) (mo->lc[mo->seg2lc[i]]);
}

static int add_section(struct macho *mo, struct segment_command_64 **_seg, char *name)
{
    struct segment_command_64 *seg = *_seg;
    int ret = seg->nsects;
    struct section_64 *sec;
    seg->nsects++;
    seg->cmdsize += sizeof(*sec);
    seg = tcc_realloc(seg, sizeof(*seg) + seg->nsects * sizeof(*sec));
    sec = (struct section_64*)((char*)seg + sizeof(*seg)) + ret;
    memset(sec, 0, sizeof(*sec));
    strncpy(sec->sectname, name, 16);
    strncpy(sec->segname, seg->segname, 16);
    *_seg = seg;
    return ret;
}

static struct section_64 *get_section(struct segment_command_64 *seg, int i)
{
    return (struct section_64*)((char*)seg + sizeof(*seg)) + i;
}

static void * add_dylib(struct macho *mo, char *name)
{
    struct dylib_command *lc;
    int sz = (sizeof(*lc) + strlen(name) + 1 + 7) & -8;
    lc = add_lc(mo, LC_LOAD_DYLIB, sz);
    lc->name = sizeof(*lc);
    strcpy((char*)lc + lc->name, name);
    lc->timestamp = 2;
    lc->current_version = 1 << 16;
    lc->compatibility_version = 1 << 16;
    return lc;
}

static void check_relocs(TCCState *s1, struct macho *mo)
{
    Section *s;
    ElfW_Rel *rel;
    ElfW(Sym) *sym;
    int i, type, gotplt_entry, sym_index, for_code;
    struct sym_attr *attr;

    s1->got = new_section(s1, ".got", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);
    mo->indirsyms = new_section(s1, "LEINDIR", SHT_LINKEDIT, SHF_ALLOC | SHF_WRITE);
    for (i = 1; i < s1->nb_sections; i++) {
        s = s1->sections[i];
        if (s->sh_type != SHT_RELX)
            continue;
        for_each_elem(s, 0, rel, ElfW_Rel) {
            type = ELFW(R_TYPE)(rel->r_info);
            gotplt_entry = gotplt_entry_type(type);
            for_code = code_reloc(type);

            sym_index = ELFW(R_SYM)(rel->r_info);
            sym = &((ElfW(Sym) *)symtab_section->data)[sym_index];
            if (sym->st_shndx == SHN_UNDEF
                || gotplt_entry == ALWAYS_GOTPLT_ENTRY) {
                attr = get_sym_attr(s1, sym_index, 1);
                if (!attr->dyn_index) {
                    uint32_t *pi = section_ptr_add(mo->indirsyms, sizeof(*pi));
                    attr->got_offset = s1->got->data_offset;
                    attr->plt_offset = -1;
                    attr->dyn_index = 1;
                    section_ptr_add(s1->got, PTR_SIZE);
                    if (ELFW(ST_BIND)(sym->st_info) == STB_LOCAL) {
                        if (sym->st_shndx == SHN_UNDEF)
                          tcc_error("undefined local symbol???");
                        *pi = INDIRECT_SYMBOL_LOCAL;

                        put_elf_reloc(s1->symtab, s1->got, attr->got_offset,
                                      R_DATA_PTR, sym_index);
                    } else
                      *pi = mo->e2msym[sym_index];
                }
                if (for_code) {
                    if (attr->plt_offset == -1) {
                        uint8_t *jmp;
                        attr->plt_offset = mo->stubs->data_offset;
                        jmp = section_ptr_add(mo->stubs, 6);
                        jmp[0] = 0xff;
                        jmp[1] = 0x25;
                        put_elf_reloc(s1->symtab, mo->stubs,
                                      attr->plt_offset + 2,
                                      R_X86_64_GOTPCREL, sym_index);
                    }
                    rel->r_info = ELFW(R_INFO)(mo->stubsym, type);
                    rel->r_addend += attr->plt_offset;
                }
            }
        }
    }
}

static int check_symbols(TCCState *s1, struct macho *mo)
{
    int sym_index, sym_end;
    int ret = 0;

    mo->ilocal = mo->iextdef = mo->iundef = -1;
    sym_end = symtab_section->data_offset / sizeof(ElfW(Sym));
    for (sym_index = 1; sym_index < sym_end; ++sym_index) {
        int elf_index = ((struct nlist_64 *)mo->symtab->data + sym_index - 1)->n_value;
        ElfW(Sym) *sym = (ElfW(Sym) *)symtab_section->data + elf_index;
        const char *name = (char*)symtab_section->link->data + sym->st_name;
        unsigned type = ELFW(ST_TYPE)(sym->st_info);
        unsigned bind = ELFW(ST_BIND)(sym->st_info);
        unsigned vis  = ELFW(ST_VISIBILITY)(sym->st_other);

        dprintf("%4d (%4d): %09lx %4d %4d %4d %3d %s\n",
                sym_index, elf_index, (long)sym->st_value,
                type, bind, vis, sym->st_shndx, name);
        if (bind == STB_LOCAL) {
            if (mo->ilocal == -1)
              mo->ilocal = sym_index - 1;
            if (mo->iextdef != -1 || mo->iundef != -1)
              tcc_error("local syms after global ones");
        } else if (sym->st_shndx != SHN_UNDEF) {
            if (mo->iextdef == -1)
              mo->iextdef = sym_index - 1;
            if (mo->iundef != -1)
              tcc_error("external defined symbol after undefined");
        } else if (sym->st_shndx == SHN_UNDEF) {
            if (mo->iundef == -1)
              mo->iundef = sym_index - 1;
            if (ELFW(ST_BIND)(sym->st_info) == STB_WEAK
                || find_elf_sym(s1->dynsymtab_section, name)) {

                sym->st_shndx = SHN_FROMDLL;
                continue;
            }
            tcc_error_noabort("undefined symbol '%s'", name);
            ret = -1;
        }
    }
    return ret;
}

static void convert_symbol(TCCState *s1, struct macho *mo, struct nlist_64 *pn)
{
    struct nlist_64 n = *pn;
    ElfSym *sym = (ElfW(Sym) *)symtab_section->data + pn->n_value;
    const char *name = (char*)symtab_section->link->data + sym->st_name;
    switch(ELFW(ST_TYPE)(sym->st_info)) {
    case STT_NOTYPE:
    case STT_OBJECT:
    case STT_FUNC:
    case STT_SECTION:
        n.n_type = N_SECT;
        break;
    case STT_FILE:
        n.n_type = N_ABS;
        break;
    default:
        tcc_error("unhandled ELF symbol type %d %s",
                  ELFW(ST_TYPE)(sym->st_info), name);
    }
    if (sym->st_shndx == SHN_UNDEF)
      tcc_error("should have been rewritten to SHN_FROMDLL: %s", name);
    else if (sym->st_shndx == SHN_FROMDLL)
      n.n_type = N_UNDF, n.n_sect = 0;
    else if (sym->st_shndx == SHN_ABS)
      n.n_type = N_ABS, n.n_sect = 0;
    else if (sym->st_shndx >= SHN_LORESERVE)
      tcc_error("unhandled ELF symbol section %d %s", sym->st_shndx, name);
    else if (!mo->elfsectomacho[sym->st_shndx])
      tcc_error("ELF section %d not mapped into Mach-O for symbol %s",
                sym->st_shndx, name);
    else
      n.n_sect = mo->elfsectomacho[sym->st_shndx];
    if (ELFW(ST_BIND)(sym->st_info) == STB_GLOBAL)
      n.n_type |=  N_EXT;
    else if (ELFW(ST_BIND)(sym->st_info) == STB_WEAK)
      n.n_desc |= N_WEAK_REF | (n.n_type != N_UNDF ? N_WEAK_DEF : 0);
    n.n_strx = pn->n_strx;
    n.n_value = sym->st_value;
    *pn = n;
}

static void convert_symbols(TCCState *s1, struct macho *mo)
{
    struct nlist_64 *pn;
    for_each_elem(mo->symtab, 0, pn, struct nlist_64)
        convert_symbol(s1, mo, pn);
}

static int machosymcmp(const void *_a, const void *_b)
{
    TCCState *s1 = tcc_state;
    int ea = ((struct nlist_64 *)_a)->n_value;
    int eb = ((struct nlist_64 *)_b)->n_value;
    ElfSym *sa = (ElfSym *)symtab_section->data + ea;
    ElfSym *sb = (ElfSym *)symtab_section->data + eb;
    int r;

    r = (ELFW(ST_BIND)(sb->st_info) == STB_LOCAL)
        - (ELFW(ST_BIND)(sa->st_info) == STB_LOCAL);
    if (r)
      return r;
    r = (sa->st_shndx == SHN_UNDEF) - (sb->st_shndx == SHN_UNDEF);
    if (r)
      return r;
    if (ELFW(ST_BIND)(sa->st_info) != STB_LOCAL) {
        const char * na = (char*)symtab_section->link->data + sa->st_name;
        const char * nb = (char*)symtab_section->link->data + sb->st_name;
        r = strcmp(na, nb);
        if (r)
          return r;
    }
    return ea - eb;
}

static void create_symtab(TCCState *s1, struct macho *mo)
{
    int sym_index, sym_end;
    struct nlist_64 *pn;

    mo->stubs = new_section(s1, "__stubs", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR);
    mo->stubsym = put_elf_sym(s1->symtab, 0, 0,
                              ELFW(ST_INFO)(STB_LOCAL, STT_SECTION), 0,
                              mo->stubs->sh_num, ".__stubs");

    mo->symtab = new_section(s1, "LESYMTAB", SHT_LINKEDIT, SHF_ALLOC | SHF_WRITE);
    mo->strtab = new_section(s1, "LESTRTAB", SHT_LINKEDIT, SHF_ALLOC | SHF_WRITE);
    put_elf_str(mo->strtab, " ");
    sym_end = symtab_section->data_offset / sizeof(ElfW(Sym));
    pn = section_ptr_add(mo->symtab, sizeof(*pn) * (sym_end - 1));
    for (sym_index = 1; sym_index < sym_end; ++sym_index) {
        ElfW(Sym) *sym = (ElfW(Sym) *)symtab_section->data + sym_index;
        const char *name = (char*)symtab_section->link->data + sym->st_name;
        pn[sym_index - 1].n_strx = put_elf_str(mo->strtab, name);
        pn[sym_index - 1].n_value = sym_index;
    }
    tcc_enter_state(s1);
    qsort(pn, sym_end - 1, sizeof(*pn), machosymcmp);
    tcc_exit_state();
    mo->e2msym = tcc_malloc(sym_end * sizeof(*mo->e2msym));
    mo->e2msym[0] = -1;
    for (sym_index = 1; sym_index < sym_end; ++sym_index) {
        mo->e2msym[pn[sym_index - 1].n_value] = sym_index - 1;
    }
}

struct {
    int seg;
    uint32_t flags;
    char *name;
} skinfo[sk_last] = {
      { 0 },
      { 0 },
         { 1, S_REGULAR | S_ATTR_PURE_INSTRUCTIONS
                             | S_ATTR_SOME_INSTRUCTIONS, "__text" },
        { 0 },
      { 1, S_REGULAR, "__rodata" },
      { 0 },
       { 2, S_NON_LAZY_SYMBOL_POINTERS, "__got" },
       { 0 },
         { 2, S_MOD_INIT_FUNC_POINTERS, "__mod_init_func" },
         { 2, S_MOD_TERM_FUNC_POINTERS, "__mod_term_func" },
      { 2, S_REGULAR, "__data" },
          { 2, S_ZEROFILL, "__bss" },
     { 3, S_REGULAR, NULL },
};

static void collect_sections(TCCState *s1, struct macho *mo)
{
    int i, sk, numsec;
    uint64_t curaddr, fileofs;
    Section *s;
    struct segment_command_64 *seg = NULL;
    struct dylinker_command *dyldlc;
    struct symtab_command *symlc;
    struct dysymtab_command *dysymlc;
    char *str;

    seg = add_segment(mo, "__PAGEZERO");
    seg->vmsize = (uint64_t)1 << 32;

    seg = add_segment(mo, "__TEXT");
    seg->vmaddr = (uint64_t)1 << 32;
    seg->maxprot = 7;
    seg->initprot = 5;

    seg = add_segment(mo, "__DATA");
    seg->vmaddr = -1;
    seg->maxprot = 7;
    seg->initprot = 3;

    seg = add_segment(mo, "__LINKEDIT");
    seg->vmaddr = -1;
    seg->maxprot = 7;
    seg->initprot = 1;

    mo->ep = add_lc(mo, LC_MAIN, sizeof(*mo->ep));
    mo->ep->entryoff = 4096;

    i = (sizeof(*dyldlc) + strlen("/usr/lib/dyld") + 1 + 7) &-8;
    dyldlc = add_lc(mo, LC_LOAD_DYLINKER, i);
    dyldlc->name = sizeof(*dyldlc);
    str = (char*)dyldlc + dyldlc->name;
    strcpy(str, "/usr/lib/dyld");

    symlc = add_lc(mo, LC_SYMTAB, sizeof(*symlc));
    dysymlc = add_lc(mo, LC_DYSYMTAB, sizeof(*dysymlc));

    for(i = 0; i < s1->nb_loaded_dlls; i++) {
        DLLReference *dllref = s1->loaded_dlls[i];
        if (dllref->level == 0)
          add_dylib(mo, dllref->name);
    }

    section_ptr_add(data_section, 1);
    memset (mo->sk_to_sect, 0, sizeof(mo->sk_to_sect));
    for (i = s1->nb_sections; i-- > 1;) {
        int type, flags;
        s = s1->sections[i];
        type = s->sh_type;
        flags = s->sh_flags;
        sk = sk_unknown;
        if (flags & SHF_ALLOC) {
            switch (type) {
            default:           sk = sk_unknown; break;
            case SHT_INIT_ARRAY: sk = sk_init; break;
            case SHT_FINI_ARRAY: sk = sk_fini; break;
            case SHT_NOBITS:   sk = sk_bss; break;
            case SHT_SYMTAB:   sk = sk_discard; break;
            case SHT_STRTAB:   sk = s == stabstr_section ? sk_ro_data : sk_discard; break;
            case SHT_RELX:     sk = sk_discard; break;
            case SHT_LINKEDIT: sk = sk_linkedit; break;
            case SHT_PROGBITS:
                if (s == s1->got)
                  sk = sk_nl_ptr;
                else if (flags & SHF_EXECINSTR)
                  sk = sk_text;
                else if (flags & SHF_WRITE)
                  sk = sk_rw_data;
                else
                  sk = sk_ro_data;
                break;
            }
        } else
          sk = sk_discard;
        s->prev = mo->sk_to_sect[sk].s;
        mo->sk_to_sect[sk].s = s;
    }
    fileofs = 4096;
    curaddr = get_segment(mo, 1)->vmaddr;
    curaddr += 4096;
    seg = NULL;
    numsec = 0;
    mo->elfsectomacho = tcc_mallocz(sizeof(*mo->elfsectomacho) * s1->nb_sections);
    for (sk = sk_unknown; sk < sk_last; sk++) {
        struct section_64 *sec = NULL;
        if (seg) {
            seg->vmsize = curaddr - seg->vmaddr;
            seg->filesize = fileofs - seg->fileoff;
        }
        if (skinfo[sk].seg && mo->sk_to_sect[sk].s) {
            uint64_t al = 0;
            int si;
            seg = get_segment(mo, skinfo[sk].seg);
            if (skinfo[sk].name) {
                si = add_section(mo, &seg, skinfo[sk].name);
                numsec++;
                mo->lc[mo->seg2lc[skinfo[sk].seg]] = (struct load_command*)seg;
                mo->sk_to_sect[sk].machosect = si;
                sec = get_section(seg, si);
                sec->flags = skinfo[sk].flags;
            }
            if (seg->vmaddr == -1) {
                curaddr = (curaddr + 4095) & -4096;
                seg->vmaddr = curaddr;
                fileofs = (fileofs + 4095) & -4096;
                seg->fileoff = fileofs;
            }

            for (s = mo->sk_to_sect[sk].s; s; s = s->prev) {
                int a = exact_log2p1(s->sh_addralign);
                if (a && al < (a - 1))
                  al = a - 1;
                s->sh_size = s->data_offset;
            }
            if (sec)
              sec->align = al;
            al = 1ULL << al;
            if (al > 4096)
              tcc_warning("alignment > 4096"), sec->align = 12, al = 4096;
            curaddr = (curaddr + al - 1) & -al;
            fileofs = (fileofs + al - 1) & -al;
            if (sec) {
                sec->addr = curaddr;
                sec->offset = fileofs;
            }
            for (s = mo->sk_to_sect[sk].s; s; s = s->prev) {
                al = s->sh_addralign;
                curaddr = (curaddr + al - 1) & -al;
                dprintf("curaddr now 0x%lx\n", (long)curaddr);
                s->sh_addr = curaddr;
                curaddr += s->sh_size;
                if (s->sh_type != SHT_NOBITS) {
                    fileofs = (fileofs + al - 1) & -al;
                    s->sh_offset = fileofs;
                    fileofs += s->sh_size;
                    dprintf("fileofs now %ld\n", (long)fileofs);
                }
                if (sec)
                  mo->elfsectomacho[s->sh_num] = numsec;
            }
            if (sec)
              sec->size = curaddr - sec->addr;
        }
        if (DEBUG_MACHO)
          for (s = mo->sk_to_sect[sk].s; s; s = s->prev) {
              int type = s->sh_type;
              int flags = s->sh_flags;
              printf("%d section %-16s %-10s %09lx %04x %02d %s,%s,%s\n",
                     sk,
                     s->name,
                     type == SHT_PROGBITS ? "progbits" :
                     type == SHT_NOBITS ? "nobits" :
                     type == SHT_SYMTAB ? "symtab" :
                     type == SHT_STRTAB ? "strtab" :
                     type == SHT_INIT_ARRAY ? "init" :
                     type == SHT_FINI_ARRAY ? "fini" :
                     type == SHT_RELX ? "rel" : "???",
                     (long)s->sh_addr,
                     (unsigned)s->data_offset,
                     s->sh_addralign,
                     flags & SHF_ALLOC ? "alloc" : "",
                     flags & SHF_WRITE ? "write" : "",
                     flags & SHF_EXECINSTR ? "exec" : ""
                    );
          }
    }
    if (seg) {
        seg->vmsize = curaddr - seg->vmaddr;
        seg->filesize = fileofs - seg->fileoff;
    }

    symlc->symoff = mo->symtab->sh_offset;
    symlc->nsyms = mo->symtab->data_offset / sizeof(struct nlist_64);
    symlc->stroff = mo->strtab->sh_offset;
    symlc->strsize = mo->strtab->data_offset;

    dysymlc->iundefsym = mo->iundef == -1 ? symlc->nsyms : mo->iundef;
    dysymlc->iextdefsym = mo->iextdef == -1 ? dysymlc->iundefsym : mo->iextdef;
    dysymlc->ilocalsym = mo->ilocal == -1 ? dysymlc->iextdefsym : mo->ilocal;
    dysymlc->nlocalsym = dysymlc->iextdefsym - dysymlc->ilocalsym;
    dysymlc->nextdefsym = dysymlc->iundefsym - dysymlc->iextdefsym;
    dysymlc->nundefsym = symlc->nsyms - dysymlc->iundefsym;
    dysymlc->indirectsymoff = mo->indirsyms->sh_offset;
    dysymlc->nindirectsyms = mo->indirsyms->data_offset / sizeof(uint32_t);
}

static void macho_write(TCCState *s1, struct macho *mo, FILE *fp)
{
    int i, sk;
    uint64_t fileofs = 0;
    Section *s;
    mo->mh.mh.magic = MH_MAGIC_64;
    mo->mh.mh.cputype = 0x1000007;
    mo->mh.mh.cpusubtype = 0x80000003;
    mo->mh.mh.filetype = 2;
    mo->mh.mh.flags = 4;
    mo->mh.mh.ncmds = mo->nlc;
    mo->mh.mh.sizeofcmds = 0;
    for (i = 0; i < mo->nlc; i++)
      mo->mh.mh.sizeofcmds += mo->lc[i]->cmdsize;

    fwrite(&mo->mh, 1, sizeof(mo->mh), fp);
    fileofs += sizeof(mo->mh);
    for (i = 0; i < mo->nlc; i++) {
        fwrite(mo->lc[i], 1, mo->lc[i]->cmdsize, fp);
        fileofs += mo->lc[i]->cmdsize;
    }

    for (sk = sk_unknown; sk < sk_last; sk++) {

        if (!skinfo[sk].seg || !mo->sk_to_sect[sk].s)
          continue;
         get_segment(mo, skinfo[sk].seg);
        for (s = mo->sk_to_sect[sk].s; s; s = s->prev) {
            if (s->sh_type != SHT_NOBITS) {
                while (fileofs < s->sh_offset)
                  fputc(0, fp), fileofs++;
                if (s->sh_size) {
                    fwrite(s->data, 1, s->sh_size, fp);
                    fileofs += s->sh_size;
                }
            }
        }
    }
}

ST_FUNC int macho_output_file(TCCState *s1, const char *filename)
{
    int fd, mode, file_type;
    FILE *fp;
    int i, ret = -1;
    struct macho mo;

    (void)memset(&mo, 0, sizeof(mo));

    file_type = s1->output_type;
    if (file_type == TCC_OUTPUT_OBJ)
        mode = 0666;
    else
        mode = 0777;
    unlink(filename);
    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, mode);
    if (fd < 0) {
        tcc_error_noabort("could not write '%s: %s'", filename, strerror(errno));
        return -1;
    }
    fp = fdopen(fd, "wb");
    if (s1->verbose)
        printf("<- %s\n", filename);

    tcc_add_runtime(s1);
    resolve_common_syms(s1);
    create_symtab(s1, &mo);
    check_relocs(s1, &mo);
    ret = check_symbols(s1, &mo);
    if (!ret) {
        int i;
        Section *s;
        collect_sections(s1, &mo);
        relocate_syms(s1, s1->symtab, 0);
        mo.ep->entryoff = get_sym_addr(s1, "main", 1, 1)
                            - get_segment(&mo, 1)->vmaddr;
        if (s1->nb_errors)
          goto do_ret;

        for(i = 1; i < s1->nb_sections; i++) {
            s = s1->sections[i];
            if (s->reloc)
              relocate_section(s1, s);
        }
        convert_symbols(s1, &mo);

        macho_write(s1, &mo, fp);
    }

 do_ret:
    for (i = 0; i < mo.nlc; i++)
      tcc_free(mo.lc[i]);
    tcc_free(mo.lc);
    tcc_free(mo.elfsectomacho);
    tcc_free(mo.e2msym);

    fclose(fp);
    return ret;
}

static uint32_t macho_swap32(uint32_t x)
{
  return (x >> 24) | (x << 24) | ((x >> 8) & 0xff00) | ((x & 0xff00) << 8);
}
#define SWAP(x) (swap ? macho_swap32(x) : (x))

ST_FUNC int macho_load_dll(TCCState *s1, int fd, const char *filename, int lev)
{
    unsigned char buf[sizeof(struct mach_header_64)];
    void *buf2;
    uint32_t machofs = 0;
    struct fat_header fh;
    struct mach_header mh;
    struct load_command *lc;
    int i, swap = 0;
    const char *soname = filename;
    struct nlist_64 *symtab = 0;
    uint32_t nsyms = 0;
    char *strtab = 0;
    uint32_t strsize = 0;
    uint32_t iextdef = 0;
    uint32_t nextdef = 0;
    DLLReference *dllref;

  again:
    if (full_read(fd, buf, sizeof(buf)) != sizeof(buf))
      return -1;
    memcpy(&fh, buf, sizeof(fh));
    if (fh.magic == FAT_MAGIC || fh.magic == FAT_CIGAM) {
        struct fat_arch *fa = load_data(fd, sizeof(fh),
                                        fh.nfat_arch * sizeof(*fa));
        swap = fh.magic == FAT_CIGAM;
        for (i = 0; i < SWAP(fh.nfat_arch); i++)
          if (SWAP(fa[i].cputype) == 0x01000007
              && SWAP(fa[i].cpusubtype) == 3)
            break;
        if (i == SWAP(fh.nfat_arch)) {
            tcc_free(fa);
            return -1;
        }
        machofs = SWAP(fa[i].offset);
        tcc_free(fa);
        lseek(fd, machofs, SEEK_SET);
        goto again;
    } else if (fh.magic == FAT_MAGIC_64 || fh.magic == FAT_CIGAM_64) {
        tcc_warning("%s: Mach-O fat 64bit files of type 0x%x not handled",
                    filename, fh.magic);
        return -1;
    }

    memcpy(&mh, buf, sizeof(mh));
    if (mh.magic != MH_MAGIC_64)
      return -1;
    dprintf("found Mach-O at %d\n", machofs);
    buf2 = load_data(fd, machofs + sizeof(struct mach_header_64), mh.sizeofcmds);
    for (i = 0, lc = buf2; i < mh.ncmds; i++) {
        dprintf("lc %2d: 0x%08x\n", i, lc->cmd);
        switch (lc->cmd) {
        case LC_SYMTAB:
        {
            struct symtab_command *sc = (struct symtab_command*)lc;
            nsyms = sc->nsyms;
            symtab = load_data(fd, machofs + sc->symoff, nsyms * sizeof(*symtab));
            strsize = sc->strsize;
            strtab = load_data(fd, machofs + sc->stroff, strsize);
            break;
        }
        case LC_ID_DYLIB:
        {
            struct dylib_command *dc = (struct dylib_command*)lc;
            soname = (char*)lc + dc->name;
            dprintf(" ID_DYLIB %d 0x%x 0x%x %s\n",
                    dc->timestamp, dc->current_version,
                    dc->compatibility_version, soname);
            break;
        }
        case LC_REEXPORT_DYLIB:
        {
            struct dylib_command *dc = (struct dylib_command*)lc;
            char *name = (char*)lc + dc->name;
            int subfd = open(name, O_RDONLY | O_BINARY);
            dprintf(" REEXPORT %s\n", name);
            if (subfd < 0)
              tcc_warning("can't open %s (reexported from %s)", name, filename);
            else {

                macho_load_dll(s1, subfd, name, lev + 1);
                close(subfd);
            }
            break;
        }
        case LC_DYSYMTAB:
        {
            struct dysymtab_command *dc = (struct dysymtab_command*)lc;
            iextdef = dc->iextdefsym;
            nextdef = dc->nextdefsym;
            break;
        }
        }
        lc = (struct load_command*) ((char*)lc + lc->cmdsize);
    }

    for(i = 0; i < s1->nb_loaded_dlls; i++) {
        dllref = s1->loaded_dlls[i];
        if (!strcmp(soname, dllref->name)) {

            if (lev < dllref->level)
                dllref->level = lev;
            goto the_end;
        }
    }
    dllref = tcc_mallocz(sizeof(DLLReference) + strlen(soname));
    dllref->level = lev;
    strcpy(dllref->name, soname);
    dynarray_add(&s1->loaded_dlls, &s1->nb_loaded_dlls, dllref);

    if (!nsyms || !nextdef)
      tcc_warning("%s doesn't export any symbols?", filename);

    dprintf("symbols (exported):\n");
    dprintf("    n: typ sec   desc              value name\n");

    for (i = iextdef; i < iextdef + nextdef; i++) {
        struct nlist_64 *sym = symtab + i;
        dprintf("%5d: %3d %3d 0x%04x 0x%016lx %s\n",
                i, sym->n_type, sym->n_sect, sym->n_desc, (long)sym->n_value,
                strtab + sym->n_strx);
        set_elf_sym(s1->dynsymtab_section, 0, 0,
                    ELFW(ST_INFO)(STB_GLOBAL, STT_NOTYPE),
                    0, SHN_UNDEF, strtab + sym->n_strx);
    }

  the_end:
    tcc_free(strtab);
    tcc_free(symtab);
    tcc_free(buf2);
    return 0;
}
