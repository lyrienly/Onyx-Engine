#ifdef TARGET_DEFS_ONLY

#define NB_REGS         5
#define NB_ASM_REGS     8
#define CONFIG_TCC_ASM

#define RC_INT     0x0001
#define RC_FLOAT   0x0002
#define RC_EAX     0x0004
#define RC_ST0     0x0008
#define RC_ECX     0x0010
#define RC_EDX     0x0020
#define RC_EBX     0x0040

#define RC_IRET    RC_EAX
#define RC_IRE2    RC_EDX
#define RC_FRET    RC_ST0

enum {
    TREG_EAX = 0,
    TREG_ECX,
    TREG_EDX,
    TREG_EBX,
    TREG_ST0,
    TREG_ESP = 4
};

#define REG_IRET TREG_EAX
#define REG_IRE2 TREG_EDX
#define REG_FRET TREG_ST0

#define INVERT_FUNC_PARAMS

#define PTR_SIZE 4

#define LDOUBLE_SIZE  12
#define LDOUBLE_ALIGN 4

#define MAX_ALIGN     8

#define PROMOTE_RET

#else

#define USING_GLOBALS
#include "tcc.h"

ST_DATA const char *target_machine_defs =
    "__i386__\0"
    "__i386\0"
    ;

#define USE_EBX 0

ST_DATA const int reg_classes[NB_REGS] = {
     RC_INT | RC_EAX,
     RC_INT | RC_ECX,
     RC_INT | RC_EDX,
     (RC_INT | RC_EBX) * USE_EBX,
     RC_FLOAT | RC_ST0,
};

static unsigned long func_sub_sp_offset;
static int func_ret_sub;
#ifdef CONFIG_TCC_BCHECK
static addr_t func_bound_offset;
static unsigned long func_bound_ind;
ST_DATA int func_bound_add_epilog;
static void gen_bounds_prolog(void);
static void gen_bounds_epilog(void);
#endif

ST_FUNC void g(int c)
{
    int ind1;
    if (nocode_wanted)
        return;
    ind1 = ind + 1;
    if (ind1 > cur_text_section->data_allocated)
        section_realloc(cur_text_section, ind1);
    cur_text_section->data[ind] = c;
    ind = ind1;
}

ST_FUNC void o(unsigned int c)
{
    while (c) {
        g(c);
        c = c >> 8;
    }
}

ST_FUNC void gen_le16(int v)
{
    g(v);
    g(v >> 8);
}

ST_FUNC void gen_le32(int c)
{
    g(c);
    g(c >> 8);
    g(c >> 16);
    g(c >> 24);
}

ST_FUNC void gsym_addr(int t, int a)
{
    while (t) {
        unsigned char *ptr = cur_text_section->data + t;
        uint32_t n = read32le(ptr);
        write32le(ptr, a - t - 4);
        t = n;
    }
}

static int oad(int c, int s)
{
    int t;
    if (nocode_wanted)
        return s;
    o(c);
    t = ind;
    gen_le32(s);
    return t;
}

ST_FUNC void gen_fill_nops(int bytes)
{
    while (bytes--)
      g(0x90);
}

#define gjmp2(instr,lbl) oad(instr,lbl)

ST_FUNC void gen_addr32(int r, Sym *sym, int c)
{
    if (r & VT_SYM)
        greloc(cur_text_section, sym, ind, R_386_32);
    gen_le32(c);
}

ST_FUNC void gen_addrpc32(int r, Sym *sym, int c)
{
    if (r & VT_SYM)
        greloc(cur_text_section, sym, ind, R_386_PC32);
    gen_le32(c - 4);
}

static void gen_modrm(int op_reg, int r, Sym *sym, int c)
{
    op_reg = op_reg << 3;
    if ((r & VT_VALMASK) == VT_CONST) {

        o(0x05 | op_reg);
        gen_addr32(r, sym, c);
    } else if ((r & VT_VALMASK) == VT_LOCAL) {

        if (c == (char)c) {

            o(0x45 | op_reg);
            g(c);
        } else {
            oad(0x85 | op_reg, c);
        }
    } else {
        g(0x00 | op_reg | (r & VT_VALMASK));
    }
}

ST_FUNC void load(int r, SValue *sv)
{
    int v, t, ft, fc, fr;
    SValue v1;

#ifdef TCC_TARGET_PE
    SValue v2;
    sv = pe_getimport(sv, &v2);
#endif

    fr = sv->r;
    ft = sv->type.t & ~VT_DEFSIGN;
    fc = sv->c.i;

    ft &= ~(VT_VOLATILE | VT_CONSTANT);

    v = fr & VT_VALMASK;
    if (fr & VT_LVAL) {
        if (v == VT_LLOCAL) {
            v1.type.t = VT_INT;
            v1.r = VT_LOCAL | VT_LVAL;
            v1.c.i = fc;
            v1.sym = NULL;
            fr = r;
            if (!(reg_classes[fr] & RC_INT))
                fr = get_reg(RC_INT);
            load(fr, &v1);
        }
        if ((ft & VT_BTYPE) == VT_FLOAT) {
            o(0xd9);
            r = 0;
        } else if ((ft & VT_BTYPE) == VT_DOUBLE) {
            o(0xdd);
            r = 0;
        } else if ((ft & VT_BTYPE) == VT_LDOUBLE) {
            o(0xdb);
            r = 5;
        } else if ((ft & VT_TYPE) == VT_BYTE || (ft & VT_TYPE) == VT_BOOL) {
            o(0xbe0f);
        } else if ((ft & VT_TYPE) == (VT_BYTE | VT_UNSIGNED)) {
            o(0xb60f);
        } else if ((ft & VT_TYPE) == VT_SHORT) {
            o(0xbf0f);
        } else if ((ft & VT_TYPE) == (VT_SHORT | VT_UNSIGNED)) {
            o(0xb70f);
        } else {
            o(0x8b);
        }
        gen_modrm(r, fr, sv->sym, fc);
    } else {
        if (v == VT_CONST) {
            o(0xb8 + r);
            gen_addr32(fr, sv->sym, fc);
        } else if (v == VT_LOCAL) {
            if (fc) {
                o(0x8d);
                gen_modrm(r, VT_LOCAL, sv->sym, fc);
            } else {
                o(0x89);
                o(0xe8 + r);
            }
        } else if (v == VT_CMP) {
            o(0x0f);
            o(fc);
            o(0xc0 + r);
            o(0xc0b60f + r * 0x90000);
        } else if (v == VT_JMP || v == VT_JMPI) {
            t = v & 1;
            oad(0xb8 + r, t);
            o(0x05eb);
            gsym(fc);
            oad(0xb8 + r, t ^ 1);
        } else if (v != r) {
            o(0x89);
            o(0xc0 + r + v * 8);
        }
    }
}

ST_FUNC void store(int r, SValue *v)
{
    int fr, bt, ft, fc;

#ifdef TCC_TARGET_PE
    SValue v2;
    v = pe_getimport(v, &v2);
#endif

    ft = v->type.t;
    fc = v->c.i;
    fr = v->r & VT_VALMASK;
    ft &= ~(VT_VOLATILE | VT_CONSTANT);
    bt = ft & VT_BTYPE;

    if (bt == VT_FLOAT) {
        o(0xd9);
        r = 2;
    } else if (bt == VT_DOUBLE) {
        o(0xdd);
        r = 2;
    } else if (bt == VT_LDOUBLE) {
        o(0xc0d9);
        o(0xdb);
        r = 7;
    } else {
        if (bt == VT_SHORT)
            o(0x66);
        if (bt == VT_BYTE || bt == VT_BOOL)
            o(0x88);
        else
            o(0x89);
    }
    if (fr == VT_CONST ||
        fr == VT_LOCAL ||
        (v->r & VT_LVAL)) {
        gen_modrm(r, v->r, v->sym, fc);
    } else if (fr != r) {
        o(0xc0 + fr + r * 8);
    }
}

static void gadd_sp(int val)
{
    if (val == (char)val) {
        o(0xc483);
        g(val);
    } else {
        oad(0xc481, val);
    }
}

#if defined CONFIG_TCC_BCHECK || defined TCC_TARGET_PE
static void gen_static_call(int v)
{
    Sym *sym;

    sym = external_helper_sym(v);
    oad(0xe8, -4);
    greloc(cur_text_section, sym, ind-4, R_386_PC32);
}
#endif

static void gcall_or_jmp(int is_jmp)
{
    int r;
    if ((vtop->r & (VT_VALMASK | VT_LVAL)) == VT_CONST && (vtop->r & VT_SYM)) {

        greloc(cur_text_section, vtop->sym, ind + 1, R_386_PC32);
        oad(0xe8 + is_jmp, vtop->c.i - 4);
    } else {

        r = gv(RC_INT);
        o(0xff);
        o(0xd0 + r + (is_jmp << 4));
    }
}

static uint8_t fastcall_regs[3] = { TREG_EAX, TREG_EDX, TREG_ECX };
static uint8_t fastcallw_regs[2] = { TREG_ECX, TREG_EDX };

ST_FUNC int gfunc_sret(CType *vt, int variadic, CType *ret, int *ret_align, int *regsize)
{
#if defined(TCC_TARGET_PE) || TARGETOS_FreeBSD || TARGETOS_OpenBSD
    int size, align;
    *ret_align = 1;
    *regsize = 4;
    size = type_size(vt, &align);
    if (size > 8 || (size & (size - 1)))
        return 0;
    if (size == 8)
        ret->t = VT_LLONG;
    else if (size == 4)
        ret->t = VT_INT;
    else if (size == 2)
        ret->t = VT_SHORT;
    else
        ret->t = VT_BYTE;
    ret->ref = NULL;
    return 1;
#else
    *ret_align = 1;
    return 0;
#endif
}

ST_FUNC void gfunc_call(int nb_args)
{
    int size, align, r, args_size, i, func_call;
    Sym *func_sym;

#ifdef CONFIG_TCC_BCHECK
    if (tcc_state->do_bounds_check)
        gbound_args(nb_args);
#endif

    args_size = 0;
    for(i = 0;i < nb_args; i++) {
        if ((vtop->type.t & VT_BTYPE) == VT_STRUCT) {
            size = type_size(&vtop->type, &align);

            size = (size + 3) & ~3;

#ifdef TCC_TARGET_PE
            if (size >= 4096) {
                r = get_reg(RC_EAX);
                oad(0x68, size);

                gen_static_call(tok_alloc_const("__alloca"));
                gadd_sp(4);
            } else
#endif
            {
                oad(0xec81, size);

                r = get_reg(RC_INT);
                o(0xe089 + (r << 8));
            }
            vset(&vtop->type, r | VT_LVAL, 0);
            vswap();
            vstore();
            args_size += size;
        } else if (is_float(vtop->type.t)) {
            gv(RC_FLOAT);
            if ((vtop->type.t & VT_BTYPE) == VT_FLOAT)
                size = 4;
            else if ((vtop->type.t & VT_BTYPE) == VT_DOUBLE)
                size = 8;
            else
                size = 12;
            oad(0xec81, size);
            if (size == 12)
                o(0x7cdb);
            else
                o(0x5cd9 + size - 4);
            g(0x24);
            g(0x00);
            args_size += size;
        } else {

            r = gv(RC_INT);
            if ((vtop->type.t & VT_BTYPE) == VT_LLONG) {
                size = 8;
                o(0x50 + vtop->r2);
            } else {
                size = 4;
            }
            o(0x50 + r);
            args_size += size;
        }
        vtop--;
    }
    save_regs(0);
    func_sym = vtop->type.ref;
    func_call = func_sym->f.func_call;

    if ((func_call >= FUNC_FASTCALL1 && func_call <= FUNC_FASTCALL3) ||
        func_call == FUNC_FASTCALLW) {
        int fastcall_nb_regs;
        uint8_t *fastcall_regs_ptr;
        if (func_call == FUNC_FASTCALLW) {
            fastcall_regs_ptr = fastcallw_regs;
            fastcall_nb_regs = 2;
        } else {
            fastcall_regs_ptr = fastcall_regs;
            fastcall_nb_regs = func_call - FUNC_FASTCALL1 + 1;
        }
        for(i = 0;i < fastcall_nb_regs; i++) {
            if (args_size <= 0)
                break;
            o(0x58 + fastcall_regs_ptr[i]);

            args_size -= 4;
        }
    }
#if !defined(TCC_TARGET_PE) && !TARGETOS_FreeBSD || TARGETOS_OpenBSD
    else if ((vtop->type.ref->type.t & VT_BTYPE) == VT_STRUCT)
        args_size -= 4;
#endif

    gcall_or_jmp(0);

    if (args_size && func_call != FUNC_STDCALL && func_call != FUNC_FASTCALLW)
        gadd_sp(args_size);
    vtop--;
}

#ifdef TCC_TARGET_PE
#define FUNC_PROLOG_SIZE (10 + USE_EBX)
#else
#define FUNC_PROLOG_SIZE (9 + USE_EBX)
#endif

ST_FUNC void gfunc_prolog(Sym *func_sym)
{
    CType *func_type = &func_sym->type;
    int addr, align, size, func_call, fastcall_nb_regs;
    int param_index, param_addr;
    uint8_t *fastcall_regs_ptr;
    Sym *sym;
    CType *type;

    sym = func_type->ref;
    func_call = sym->f.func_call;
    addr = 8;
    loc = 0;
    func_vc = 0;

    if (func_call >= FUNC_FASTCALL1 && func_call <= FUNC_FASTCALL3) {
        fastcall_nb_regs = func_call - FUNC_FASTCALL1 + 1;
        fastcall_regs_ptr = fastcall_regs;
    } else if (func_call == FUNC_FASTCALLW) {
        fastcall_nb_regs = 2;
        fastcall_regs_ptr = fastcallw_regs;
    } else {
        fastcall_nb_regs = 0;
        fastcall_regs_ptr = NULL;
    }
    param_index = 0;

    ind += FUNC_PROLOG_SIZE;
    func_sub_sp_offset = ind;

#if defined(TCC_TARGET_PE) || TARGETOS_FreeBSD || TARGETOS_OpenBSD
    size = type_size(&func_vt,&align);
    if (((func_vt.t & VT_BTYPE) == VT_STRUCT)
        && (size > 8 || (size & (size - 1)))) {
#else
    if ((func_vt.t & VT_BTYPE) == VT_STRUCT) {
#endif

        func_vc = addr;
        addr += 4;
        param_index++;
    }

    while ((sym = sym->next) != NULL) {
        type = &sym->type;
        size = type_size(type, &align);
        size = (size + 3) & ~3;
#ifdef FUNC_STRUCT_PARAM_AS_PTR

        if ((type->t & VT_BTYPE) == VT_STRUCT) {
            size = 4;
        }
#endif
        if (param_index < fastcall_nb_regs) {

            loc -= 4;
            o(0x89);
            gen_modrm(fastcall_regs_ptr[param_index], VT_LOCAL, NULL, loc);
            param_addr = loc;
        } else {
            param_addr = addr;
            addr += size;
        }
        sym_push(sym->v & ~SYM_FIELD, type,
                 VT_LOCAL | VT_LVAL, param_addr);
        param_index++;
    }
    func_ret_sub = 0;

    if (func_call == FUNC_STDCALL || func_call == FUNC_FASTCALLW)
        func_ret_sub = addr - 8;
#if !defined(TCC_TARGET_PE) && !TARGETOS_FreeBSD || TARGETOS_OpenBSD
    else if (func_vc)
        func_ret_sub = 4;
#endif

#ifdef CONFIG_TCC_BCHECK
    if (tcc_state->do_bounds_check)
        gen_bounds_prolog();
#endif
}

ST_FUNC void gfunc_epilog(void)
{
    addr_t v, saved_ind;

#ifdef CONFIG_TCC_BCHECK
    if (tcc_state->do_bounds_check)
        gen_bounds_epilog();
#endif

    v = (-loc + 3) & -4;

#if USE_EBX
    o(0x8b);
    gen_modrm(TREG_EBX, VT_LOCAL, NULL, -(v+4));
#endif

    o(0xc9);
    if (func_ret_sub == 0) {
        o(0xc3);
    } else {
        o(0xc2);
        g(func_ret_sub);
        g(func_ret_sub >> 8);
    }
    saved_ind = ind;
    ind = func_sub_sp_offset - FUNC_PROLOG_SIZE;
#ifdef TCC_TARGET_PE
    if (v >= 4096) {
        oad(0xb8, v);
        gen_static_call(TOK___chkstk);
    } else
#endif
    {
        o(0xe58955);
        o(0xec81);
        gen_le32(v);
#ifdef TCC_TARGET_PE
        o(0x90);
#endif
    }
    o(0x53 * USE_EBX);
    ind = saved_ind;
}

ST_FUNC int gjmp(int t)
{
    return gjmp2(0xe9, t);
}

ST_FUNC void gjmp_addr(int a)
{
    int r;
    r = a - ind - 2;
    if (r == (char)r) {
        g(0xeb);
        g(r);
    } else {
        oad(0xe9, a - ind - 5);
    }
}

#if 0

ST_FUNC void gjmp_cond_addr(int a, int op)
{
    int r = a - ind - 2;
    if (r == (char)r)
        g(op - 32), g(r);
    else
        g(0x0f), gjmp2(op - 16, r - 4);
}
#endif

ST_FUNC int gjmp_append(int n, int t)
{
    void *p;

    if (n) {
        uint32_t n1 = n, n2;
        while ((n2 = read32le(p = cur_text_section->data + n1)))
            n1 = n2;
        write32le(p, t);
        t = n;
    }
    return t;
}

ST_FUNC int gjmp_cond(int op, int t)
{
    g(0x0f);
    t = gjmp2(op - 16, t);
    return t;
}

ST_FUNC void gen_opi(int op)
{
    int r, fr, opc, c;

    switch(op) {
    case '+':
    case TOK_ADDC1:
        opc = 0;
    gen_op8:
        if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {

            vswap();
            r = gv(RC_INT);
            vswap();
            c = vtop->c.i;
            if (c == (char)c) {

                if ((c == 1 || c == -1) && (op == '+' || op == '-')) {
                    opc = (c == 1) ^ (op == '+');
                    o (0x40 | (opc << 3) | r);
                } else {
                    o(0x83);
                    o(0xc0 | (opc << 3) | r);
                    g(c);
                }
            } else {
                o(0x81);
                oad(0xc0 | (opc << 3) | r, c);
            }
        } else {
            gv2(RC_INT, RC_INT);
            r = vtop[-1].r;
            fr = vtop[0].r;
            o((opc << 3) | 0x01);
            o(0xc0 + r + fr * 8);
        }
        vtop--;
        if (op >= TOK_ULT && op <= TOK_GT)
            vset_VT_CMP(op);
        break;
    case '-':
    case TOK_SUBC1:
        opc = 5;
        goto gen_op8;
    case TOK_ADDC2:
        opc = 2;
        goto gen_op8;
    case TOK_SUBC2:
        opc = 3;
        goto gen_op8;
    case '&':
        opc = 4;
        goto gen_op8;
    case '^':
        opc = 6;
        goto gen_op8;
    case '|':
        opc = 1;
        goto gen_op8;
    case '*':
        gv2(RC_INT, RC_INT);
        r = vtop[-1].r;
        fr = vtop[0].r;
        vtop--;
        o(0xaf0f);
        o(0xc0 + fr + r * 8);
        break;
    case TOK_SHL:
        opc = 4;
        goto gen_shift;
    case TOK_SHR:
        opc = 5;
        goto gen_shift;
    case TOK_SAR:
        opc = 7;
    gen_shift:
        opc = 0xc0 | (opc << 3);
        if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {

            vswap();
            r = gv(RC_INT);
            vswap();
            c = vtop->c.i & 0x1f;
            o(0xc1);
            o(opc | r);
            g(c);
        } else {

            gv2(RC_INT, RC_ECX);
            r = vtop[-1].r;
            o(0xd3);
            o(opc | r);
        }
        vtop--;
        break;
    case '/':
    case TOK_UDIV:
    case TOK_PDIV:
    case '%':
    case TOK_UMOD:
    case TOK_UMULL:

        gv2(RC_EAX, RC_ECX);
        r = vtop[-1].r;
        fr = vtop[0].r;
        vtop--;
        save_reg(TREG_EDX);

        save_reg_upstack(TREG_EAX, 1);
        if (op == TOK_UMULL) {
            o(0xf7);
            o(0xe0 + fr);
            vtop->r2 = TREG_EDX;
            r = TREG_EAX;
        } else {
            if (op == TOK_UDIV || op == TOK_UMOD) {
                o(0xf7d231);
                o(0xf0 + fr);
            } else {
                o(0xf799);
                o(0xf8 + fr);
            }
            if (op == '%' || op == TOK_UMOD)
                r = TREG_EDX;
            else
                r = TREG_EAX;
        }
        vtop->r = r;
        break;
    default:
        opc = 7;
        goto gen_op8;
    }
}

ST_FUNC void gen_opf(int op)
{
    int a, ft, fc, swapped, r;

    if (op == TOK_NEG) {
        gv(RC_FLOAT);
        o(0xe0d9);
        return;
    }

    if ((vtop[-1].r & (VT_VALMASK | VT_LVAL)) == VT_CONST) {
        vswap();
        gv(RC_FLOAT);
        vswap();
    }
    if ((vtop[0].r & (VT_VALMASK | VT_LVAL)) == VT_CONST)
        gv(RC_FLOAT);

    if ((vtop[-1].r & VT_LVAL) &&
        (vtop[0].r & VT_LVAL)) {
        vswap();
        gv(RC_FLOAT);
        vswap();
    }
    swapped = 0;

    if (vtop[-1].r & VT_LVAL) {
        vswap();
        swapped = 1;
    }
    if (op >= TOK_ULT && op <= TOK_GT) {

        load(TREG_ST0, vtop);
        save_reg(TREG_EAX);
        if (op == TOK_GE || op == TOK_GT)
            swapped = !swapped;
        else if (op == TOK_EQ || op == TOK_NE)
            swapped = 0;
        if (swapped)
            o(0xc9d9);
        if (op == TOK_EQ || op == TOK_NE)
            o(0xe9da);
        else
            o(0xd9de);
        o(0xe0df);
        if (op == TOK_EQ) {
            o(0x45e480);
            o(0x40fC80);
        } else if (op == TOK_NE) {
            o(0x45e480);
            o(0x40f480);
            op = TOK_NE;
        } else if (op == TOK_GE || op == TOK_LE) {
            o(0x05c4f6);
            op = TOK_EQ;
        } else {
            o(0x45c4f6);
            op = TOK_EQ;
        }
        vtop--;
        vset_VT_CMP(op);
    } else {

        if ((vtop->type.t & VT_BTYPE) == VT_LDOUBLE) {
            load(TREG_ST0, vtop);
            swapped = !swapped;
        }

        switch(op) {
        default:
        case '+':
            a = 0;
            break;
        case '-':
            a = 4;
            if (swapped)
                a++;
            break;
        case '*':
            a = 1;
            break;
        case '/':
            a = 6;
            if (swapped)
                a++;
            break;
        }
        ft = vtop->type.t;
        fc = vtop->c.i;
        if ((ft & VT_BTYPE) == VT_LDOUBLE) {
            o(0xde);
            o(0xc1 + (a << 3));
        } else {

            r = vtop->r;
            if ((r & VT_VALMASK) == VT_LLOCAL) {
                SValue v1;
                r = get_reg(RC_INT);
                v1.type.t = VT_INT;
                v1.r = VT_LOCAL | VT_LVAL;
                v1.c.i = fc;
                v1.sym = NULL;
                load(r, &v1);
                fc = 0;
            }

            if ((ft & VT_BTYPE) == VT_DOUBLE)
                o(0xdc);
            else
                o(0xd8);
            gen_modrm(a, r, vtop->sym, fc);
        }
        vtop--;
    }
}

ST_FUNC void gen_cvt_itof(int t)
{
    save_reg(TREG_ST0);
    gv(RC_INT);
    if ((vtop->type.t & VT_BTYPE) == VT_LLONG) {

        o(0x50 + vtop->r2);
        o(0x50 + (vtop->r & VT_VALMASK));
        o(0x242cdf);
        o(0x08c483);
        vtop->r2 = VT_CONST;
    } else if ((vtop->type.t & (VT_BTYPE | VT_UNSIGNED)) ==
               (VT_INT | VT_UNSIGNED)) {

        o(0x6a);
        g(0x00);
        o(0x50 + (vtop->r & VT_VALMASK));
        o(0x242cdf);
        o(0x08c483);
    } else {

        o(0x50 + (vtop->r & VT_VALMASK));
        o(0x2404db);
        o(0x04c483);
    }
    vtop->r2 = VT_CONST;
    vtop->r = TREG_ST0;
}

ST_FUNC void gen_cvt_ftoi(int t)
{
    int bt = vtop->type.t & VT_BTYPE;
    if (bt == VT_FLOAT)
        vpush_helper_func(TOK___fixsfdi);
    else if (bt == VT_LDOUBLE)
        vpush_helper_func(TOK___fixxfdi);
    else
        vpush_helper_func(TOK___fixdfdi);
    vswap();
    gfunc_call(1);
    vpushi(0);
    vtop->r = REG_IRET;
    if ((t & VT_BTYPE) == VT_LLONG)
        vtop->r2 = REG_IRE2;
}

ST_FUNC void gen_cvt_ftof(int t)
{

    gv(RC_FLOAT);
}

ST_FUNC void gen_cvt_csti(int t)
{
    int r, sz, xl;
    r = gv(RC_INT);
    sz = !(t & VT_UNSIGNED);
    xl = (t & VT_BTYPE) == VT_SHORT;
    o(0xc0b60f
        | (sz << 3 | xl) << 8
        | (r << 3 | r) << 16
        );
}

ST_FUNC void ggoto(void)
{
    gcall_or_jmp(1);
    vtop--;
}

#ifdef CONFIG_TCC_BCHECK

static void gen_bounds_prolog(void)
{

    func_bound_offset = lbounds_section->data_offset;
    func_bound_ind = ind;
    func_bound_add_epilog = 0;
    oad(0xb8, 0);
    oad(0xb8, 0);
}

static void gen_bounds_epilog(void)
{
    addr_t saved_ind;
    addr_t *bounds_ptr;
    Sym *sym_data;
    int offset_modified = func_bound_offset != lbounds_section->data_offset;

    if (!offset_modified && !func_bound_add_epilog)
        return;

    bounds_ptr = section_ptr_add(lbounds_section, sizeof(addr_t));
    *bounds_ptr = 0;

    sym_data = get_sym_ref(&char_pointer_type, lbounds_section,
                           func_bound_offset, lbounds_section->data_offset);

    if (offset_modified) {
        saved_ind = ind;
        ind = func_bound_ind;
        greloc(cur_text_section, sym_data, ind + 1, R_386_32);
        ind = ind + 5;
        gen_static_call(TOK___bound_local_new);
        ind = saved_ind;
    }

    o(0x5250);
    greloc(cur_text_section, sym_data, ind + 1, R_386_32);
    oad(0xb8, 0);
    gen_static_call(TOK___bound_local_delete);
    o(0x585a);
}
#endif

ST_FUNC void gen_vla_sp_save(int addr) {

    o(0x89);
    gen_modrm(TREG_ESP, VT_LOCAL, NULL, addr);
}

ST_FUNC void gen_vla_sp_restore(int addr) {
    o(0x8b);
    gen_modrm(TREG_ESP, VT_LOCAL, NULL, addr);
}

ST_FUNC void gen_vla_alloc(CType *type, int align) {
    int use_call = 0;

#if defined(CONFIG_TCC_BCHECK)
    use_call = tcc_state->do_bounds_check;
#endif
#ifdef TCC_TARGET_PE
    use_call = 1;
#endif
    if (use_call)
    {
        vpush_helper_func(TOK_alloca);
        vswap();
        gfunc_call(1);
    }
    else {
        int r;
        r = gv(RC_INT);

        o(0x2b);
        o(0xe0 | r);

        o(0xf0e483);
        vpop();
    }
}

#endif
