struct filehdr {
        unsigned short  f_magic;
        unsigned short  f_nscns;
        long            f_timdat;
        long            f_symptr;
        long            f_nsyms;
        unsigned short  f_opthdr;
        unsigned short  f_flags;
        unsigned short  f_TargetID;
        };

#define  F_RELFLG   0x01
#define  F_EXEC     0x02
#define  F_LNNO     0x04
#define  F_LSYMS    0x08
#define  F_GSP10    0x10
#define  F_GSP20    0x20
#define  F_SWABD    0x40
#define  F_AR16WR   0x80
#define  F_LITTLE   0x100
#define  F_BIG      0x200
#define  F_PATCH    0x400
#define  F_NODF     0x400

#define F_VERSION    (F_GSP10  | F_GSP20)
#define F_BYTE_ORDER (F_LITTLE | F_BIG)
#define FILHDR  struct filehdr

#define FILHSZ  22

#define COFF_C67_MAGIC 0x00c2

#define ISMAGIC(x)      (((unsigned short)(x))==(unsigned short)magic)
#define ISARCHIVE(x)    ((((unsigned short)(x))==(unsigned short)ARTYPE))
#define BADMAGIC(x)     (((unsigned short)(x) & 0x8080) && !ISMAGIC(x))

typedef struct aouthdr {
        short   magic;
        short   vstamp;
        long    tsize;
        long    dsize;
        long    bsize;
        long    entrypt;
        long    text_start;
        long    data_start;
} AOUTHDR;

#define AOUTSZ  sizeof(AOUTHDR)

#define AOUT1MAGIC 0410
#define AOUT2MAGIC 0407
#define PAGEMAGIC  0413

#define COFF_ARMAG   "!<arch>\n"
#define SARMAG  8
#define ARFMAG  "`\n"

struct ar_hdr
{
        char    ar_name[16];
        char    ar_date[12];
        char    ar_uid[6];
        char    ar_gid[6];
        char    ar_mode[8];
        char    ar_size[10];
        char    ar_fmag[2];
};

struct scnhdr {
        char            s_name[8];
        long            s_paddr;
        long            s_vaddr;
        long            s_size;
        long            s_scnptr;
        long            s_relptr;
        long            s_lnnoptr;
        unsigned int	s_nreloc;
        unsigned int	s_nlnno;
        unsigned int	s_flags;
		unsigned short	s_reserved;
		unsigned short  s_page;
        };

#define SCNHDR  struct scnhdr
#define SCNHSZ  sizeof(SCNHDR)

#define _DATA    ".data"
#define _BSS     ".bss"
#define _CINIT   ".cinit"
#define _TV      ".tv"

#define STYP_REG    0x00
#define STYP_DSECT  0x01
#define STYP_NOLOAD 0x02
#define STYP_GROUP  0x04
#define STYP_PAD    0x08
#define STYP_COPY   0x10
#define STYP_TEXT   0x20
#define STYP_DATA   0x40
#define STYP_BSS    0x80

#define STYP_ALIGN  0x100
#define ALIGN_MASK  0x0F00
#define ALIGNSIZE(x) (1 << ((x & ALIGN_MASK) >> 8))

struct reloc
{
   long            r_vaddr;
   short           r_symndx;
   unsigned short  r_disp;
   unsigned short  r_type;
};

#define RELOC   struct reloc
#define RELSZ   10

#define R_ABS           0
#define R_DIR16         01
#define R_REL16         02
#define R_DIR24         04
#define R_REL24         05
#define R_DIR32         06
#define R_RELBYTE      017
#define R_RELWORD      020
#define R_RELLONG      021
#define R_PCRBYTE      022
#define R_PCRWORD      023
#define R_PCRLONG      024
#define R_OCRLONG      030
#define R_GSPPCR16     031
#define R_GSPOPR32     032
#define R_PARTLS16     040
#define R_PARTMS8      041
#define R_PARTLS7      050
#define R_PARTMS9      051
#define R_REL13        052

struct lineno
{
        union
        {
                long    l_symndx ;
                long    l_paddr ;
        }               l_addr ;
        unsigned short  l_lnno ;
};

#define LINENO  struct lineno
#define LINESZ  6

#define  C_EFCN          -1
#define  C_NULL          0
#define  C_AUTO          1
#define  C_EXT           2
#define  C_STAT          3
#define  C_REG           4
#define  C_EXTDEF        5
#define  C_LABEL         6
#define  C_ULABEL        7
#define  C_MOS           8
#define  C_ARG           9
#define  C_STRTAG        10
#define  C_MOU           11
#define  C_UNTAG         12
#define  C_TPDEF         13
#define C_USTATIC        14
#define  C_ENTAG         15
#define  C_MOE           16
#define  C_REGPARM       17
#define  C_FIELD         18

#define  C_BLOCK         100
#define  C_FCN           101
#define  C_EOS           102
#define  C_FILE          103
#define  C_LINE          104
#define  C_ALIAS         105
#define  C_HIDDEN        106

#define  SYMNMLEN   8
#define  FILNMLEN   14
#define  DIMNUM     4

struct syment
{
        union
        {
                char            _n_name[SYMNMLEN];
                struct
                {
                        long    _n_zeroes;
                        long    _n_offset;
                } _n_n;
                char            *_n_nptr[2];
        } _n;
        long                    n_value;
        short                   n_scnum;
        unsigned short          n_type;
        char                    n_sclass;
        char                    n_numaux;
};

#define n_name          _n._n_name
#define n_nptr          _n._n_nptr[1]
#define n_zeroes        _n._n_n._n_zeroes
#define n_offset        _n._n_n._n_offset

#define  N_UNDEF  0
#define  N_ABS    -1
#define  N_DEBUG  -2
#define  N_TV     (unsigned short)-3
#define  P_TV     (unsigned short)-4

#define  _EF    ".ef"

#define  T_NULL     0
#define  T_ARG      1
#define  T_CHAR     2
#define  T_SHORT    3
#define  T_INT      4
#define  T_LONG     5
#define  T_FLOAT    6
#define  T_DOUBLE   7
#define  T_STRUCT   8
#define  T_UNION    9
#define  T_ENUM     10
#define  T_MOE      11
#define  T_UCHAR    12
#define  T_USHORT   13
#define  T_UINT     14
#define  T_ULONG    15

#define  DT_NON      0
#define  DT_PTR      1
#define  DT_FCN      2
#define  DT_ARY      3

#define MKTYPE(basic, d1,d2,d3,d4,d5,d6) \
       ((basic) | ((d1) <<  4) | ((d2) <<  6) | ((d3) <<  8) |\
                  ((d4) << 10) | ((d5) << 12) | ((d6) << 14))

#define  N_BTMASK_COFF     017
#define  N_TMASK_COFF      060
#define  N_TMASK1_COFF     0300
#define  N_TMASK2_COFF     0360
#define  N_BTSHFT_COFF     4
#define  N_TSHIFT_COFF     2

#define  BTYPE_COFF(x)  ((x) & N_BTMASK_COFF)
#define  ISINT(x)  (((x) >= T_CHAR && (x) <= T_LONG) ||   \
		    ((x) >= T_UCHAR && (x) <= T_ULONG) || (x) == T_ENUM)
#define  ISFLT_COFF(x)  ((x) == T_DOUBLE || (x) == T_FLOAT)
#define  ISPTR_COFF(x)  (((x) & N_TMASK_COFF) == (DT_PTR << N_BTSHFT_COFF))
#define  ISFCN_COFF(x)  (((x) & N_TMASK_COFF) == (DT_FCN << N_BTSHFT_COFF))
#define  ISARY_COFF(x)  (((x) & N_TMASK_COFF) == (DT_ARY << N_BTSHFT_COFF))
#define  ISTAG_COFF(x)  ((x)==C_STRTAG || (x)==C_UNTAG || (x)==C_ENTAG)

#define  INCREF_COFF(x) ((((x)&~N_BTMASK_COFF)<<N_TSHIFT_COFF)|(DT_PTR<<N_BTSHFT_COFF)|(x&N_BTMASK_COFF))
#define  DECREF_COFF(x) ((((x)>>N_TSHIFT_COFF)&~N_BTMASK_COFF)|((x)&N_BTMASK_COFF))

union auxent
{
	struct
	{
		long            x_tagndx;
		union
		{
			struct
			{
				unsigned short  x_lnno;
				unsigned short  x_size;
			} x_lnsz;
			long    x_fsize;
		} x_misc;
		union
		{
			struct
			{
				long    x_lnnoptr;
				long    x_endndx;
			}       x_fcn;
			struct
			{
				unsigned short  x_dimen[DIMNUM];
			}       x_ary;
		}               x_fcnary;
		unsigned short  x_regcount;
	}       x_sym;
	struct
	{
		char    x_fname[FILNMLEN];
	}       x_file;
	struct
	{
		long    x_scnlen;
		unsigned short  x_nreloc;
		unsigned short  x_nlinno;
	}       x_scn;
};

#define SYMENT  struct syment
#define SYMESZ  18

#define AUXENT  union auxent
#define AUXESZ  18

#define _STEXT          ".text"
#define _ETEXT          "etext"
#define _SDATA          ".data"
#define _EDATA          "edata"
#define _SBSS           ".bss"
#define _END            "end"
#define _CINITPTR       "cinit"

#define _START          "_start"
#define _MAIN           "_main"

#define _TVORIG         "_tvorig"
#define _TORIGIN        "_torigin"
#define _DORIGIN        "_dorigin"

#define _SORIGIN        "_sorigin"
