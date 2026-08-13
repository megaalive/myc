/*
 * units.c -- Units, Shape, dan Provenance Contracts (Fase 5, SOL-11).
 *
 * Annotation ringan di atas type system C:
 *
 *     //@ unit        len bytes          -- satuan kuantitas
 *     //@ shape       buf capacity=cap length=len
 *     //@ provenance  p owned
 *     //@ endian      value little
 *
 * myc melacak subset sederhana secara DETERMINISTIK (analisis teks,
 * bukan AST):
 *   - UNBOUND       : identifier annotation tidak muncul di source.
 *   - UNIT_MISMATCH : `a = b` (assignment) dengan unit berbeda.
 *   - SHAPE_DIM     : capacity vs length shape beda dimensi/unit.
 *   - DUP_CONFLICT  : dua annotation bertentangan pada id yang sama.
 *
 * Temuan = observasi NON-blocking; verdict TIDAK pernah turun.
 * Hasil di res->units_* (arena). Deterministik.
 */
#include "units.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- */
/* Buffer dinamis kecil                                             */
/* ---------------------------------------------------------------- */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} u_buf;

static int ubuf_put(u_buf *b, char c)
{
    if (b->len + 2 > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 4096;
        char  *nd = (char *)myc_realloc(b->data, ncap);
        if (!nd)
            return 0;
        b->data = nd;
        b->cap = ncap;
    }
    b->data[b->len++] = c;
    b->data[b->len] = '\0';
    return 1;
}

static int ubuf_puts(u_buf *b, const char *s)
{
    size_t i;
    for (i = 0; s[i]; i++)
        if (!ubuf_put(b, s[i]))
            return 0;
    return 1;
}

/* ---------------------------------------------------------------- */
/* Lexical helper                                                   */
/* ---------------------------------------------------------------- */

static int u_is_ident_start(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int u_is_ident_char(int c)
{
    return u_is_ident_start(c) || (c >= '0' && c <= '9');
}

static int u_line_at(const char *s, size_t len, size_t pos)
{
    int    l = 1;
    size_t i;
    if (pos > len)
        pos = len;
    for (i = 0; i < pos; i++)
        if (s[i] == '\n')
            l++;
    return l;
}

/* Lewati whitespace dan komentar (line `//` maupun blok C-style);
 * string literal ditangani pemanggil lewat u_skip_literal. */
static size_t u_skip_trivia(const char *s, size_t len, size_t p)
{
    for (;;) {
        while (p < len &&
               (s[p] == ' ' || s[p] == '\t' || s[p] == '\r' ||
                s[p] == '\n'))
            p++;
        if (p + 1 < len && s[p] == '/' && s[p + 1] == '*') {
            p += 2;
            while (p + 1 < len && !(s[p] == '*' && s[p + 1] == '/'))
                p++;
            p += 2;
            continue;
        }
        if (p + 1 < len && s[p] == '/' && s[p + 1] == '/') {
            while (p < len && s[p] != '\n')
                p++;
            continue;
        }
        break;
    }
    return p;
}

/* Baca kata identifier (menerima digit lanjutan); bila tak ada ident di
 * posisi p, kembalikan p. */
static size_t u_read_word(const char *s, size_t p, size_t end,
                          char *t, size_t cap)
{
    size_t i = p;
    size_t w = 0;
    if (i < end && u_is_ident_start((unsigned char)s[i])) {
        while (i < end && u_is_ident_char((unsigned char)s[i]) &&
               w + 1 < cap)
            t[w++] = s[i++];
    }
    t[w] = '\0';
    return (w) ? i : p;
}

static int u_is_keyword(const char *w)
{
    static const char *const KW[] = {
        "auto", "break", "case", "char", "const", "continue",
        "default", "do", "double", "else", "enum", "extern",
        "float", "for", "goto", "if", "inline", "int", "long",
        "register", "restrict", "return", "short", "signed",
        "sizeof", "static", "struct", "switch", "typedef",
        "union", "unsigned", "void", "volatile", "while",
        "_Atomic", "_Bool", "_Complex", "_Imaginary",
        "_Alignas", "_Alignof", "_Generic", "_Noreturn",
        "_Static_assert", "_Thread_local", NULL
    };
    int i;
    for (i = 0; KW[i]; i++)
        if (strcmp(w, KW[i]) == 0)
            return 1;
    return 0;
}

/* Skip string/char literal, dimulai s[p] == '"' atau '\''. */
static size_t u_skip_literal(const char *s, size_t len, size_t p)
{
    char q = s[p++];
    while (p < len && s[p] != q) {
        if (s[p] == '\\' && p + 1 < len)
            p += 2;
        else
            p++;
    }
    return (p < len) ? (p + 1) : len;
}

/* ---------------------------------------------------------------- */
/* State: vars + shapes + findings                                  */
/* ---------------------------------------------------------------- */

#define MYC_UNITS_MAX_VARS   64
#define MYC_UNITS_MAX_SHAPE  32

typedef struct {
    char  name[MYC_UNITS_NAME_LEN];
    char  unit[MYC_UNITS_NAME_LEN];
    char  prov[MYC_UNITS_NAME_LEN];
    char  endian[MYC_UNITS_NAME_LEN];
    int   has_unit;
    int   has_prov;
    int   has_endian;
    int   ann_line;   /* baris annotation pertama utk id ini */
} uvar;

typedef struct {
    char  name[MYC_UNITS_NAME_LEN];
    char  cap[MYC_UNITS_NAME_LEN];   /* id pada `capacity=` */
    char  len[MYC_UNITS_NAME_LEN];   /* id pada `length=`   */
    int   line;
} ushape;

typedef struct {
    myc_units_finding_kind kind;
    char  text[256];
    char  witness[192];
    int   line;
} ufind;

/* Mutable state analisis non-const => _Thread_local (aturan AGENTS.md). */
static _Thread_local uvar   s_vars[MYC_UNITS_MAX_VARS];
static _Thread_local int    s_nvars;
static _Thread_local ushape s_shapes[MYC_UNITS_MAX_SHAPE];
static _Thread_local int    s_nshapes;

static uvar *u_find_var(const char *name)
{
    int i;
    for (i = 0; i < s_nvars; i++)
        if (strcmp(s_vars[i].name, name) == 0)
            return &s_vars[i];
    return NULL;
}

static uvar *u_get_var(const char *name)
{
    uvar *v = u_find_var(name);
    if (v)
        return v;
    if (s_nvars >= MYC_UNITS_MAX_VARS)
        return NULL;
    v = &s_vars[s_nvars];
    memset(v, 0, sizeof(*v));
    snprintf(v->name, MYC_UNITS_NAME_LEN, "%s", name);
    s_nvars++;
    return v;
}

/* ---------------------------------------------------------------- */
/* Temuan                                                            */
/* ---------------------------------------------------------------- */

static void u_add(ufind *fnd, int *nf, myc_units_finding_kind kind,
                  const char *text, int line)
{
    if (*nf >= MYC_UNITS_MAX_FINDINGS)
        return;
    memset(&fnd[*nf], 0, sizeof(ufind));
    fnd[*nf].kind = kind;
    snprintf(fnd[*nf].text, sizeof(fnd[*nf].text), "%.240s", text);
    fnd[*nf].line = line;
    (*nf)++;
}

/* ---------------------------------------------------------------- */
/* Scan `//@` annotations                                            */
/* ---------------------------------------------------------------- */

static void scan_annotations(const char *src, size_t len,
                             ufind *fnd, int *nf)
{
    size_t i = 0;
    while (i < len) {
        if (src[i] == '/' && i + 1 < len && src[i + 1] == '*') {
            i = u_skip_trivia(src, len, i);
            continue;
        }
        if (src[i] == '/' && i + 1 < len && src[i + 1] == '/') {
            size_t le = i;
            while (le < len && src[le] != '\n')
                le++;
            if (i + 2 < le && src[i + 2] == '@') {
                size_t p = i + 3;
                char   kw[32];
                int    line = u_line_at(src, len, i);
                p = u_skip_trivia(src, len, p);
                p = u_read_word(src, p, le, kw, sizeof(kw));
                p = u_skip_trivia(src, len, p);
                if (strcmp(kw, "unit") == 0) {
                    char var[MYC_UNITS_NAME_LEN], un[MYC_UNITS_NAME_LEN];
                    size_t q = u_read_word(src, p, le, var,
                                           sizeof(var));
                    if (var[0] != '\0') {
                        q = u_skip_trivia(src, len, q);
                        u_read_word(src, q, le, un, sizeof(un));
                        if (un[0] != '\0') {
                            uvar *v = u_get_var(var);
                            if (v) {
                                if (v->has_unit &&
                                    strcmp(v->unit, un) != 0) {
                                    char tb[256];
                                    snprintf(tb, sizeof(tb),
                                             "unit `%.40s` dari "
                                             "`%.40s` (baris %d) "
                                             "bertentangan dgn unit "
                                             "`%.40s`",
                                             un, var, line, v->unit);
                                    u_add(fnd, nf, MYC_UNITS_DUP_CONFLICT,
                                          tb, line);
                                } else if (!v->has_unit) {
                                    snprintf(v->unit, MYC_UNITS_NAME_LEN,
                                             "%s", un);
                                    v->has_unit = 1;
                                    v->ann_line = line;
                                }
                            }
                        }
                    }
                } else if (strcmp(kw, "shape") == 0) {
                    char   var[MYC_UNITS_NAME_LEN];
                    size_t q = u_read_word(src, p, le, var,
                                           sizeof(var));
                    if (var[0] != '\0' &&
                        s_nshapes < MYC_UNITS_MAX_SHAPE) {
                        ushape *sh = &s_shapes[s_nshapes];
                        memset(sh, 0, sizeof(*sh));
                        snprintf(sh->name, MYC_UNITS_NAME_LEN, "%s",
                                 var);
                        sh->line = line;
                        q = u_skip_trivia(src, len, q);
                        while (q < le) {
                            char key[32];
                            size_t e2 = u_read_word(src, q, le, key,
                                                    sizeof(key));
                            if (key[0] == '\0')
                                break;
                            q = u_skip_trivia(src, len, e2);
                            if (q < le && src[q] == '=') {
                                q = u_skip_trivia(src, len, q + 1);
                                if (strcmp(key, "capacity") == 0 ||
                                    strcmp(key, "length") == 0) {
                                    char val[MYC_UNITS_NAME_LEN];
                                    char *dst =
                                        (strcmp(key, "capacity") == 0)
                                            ? sh->cap : sh->len;
                                    q = u_read_word
                                        (src, q, le, val, sizeof(val));
                                    if (val[0] != '\0')
                                        snprintf(dst, MYC_UNITS_NAME_LEN,
                                                 "%s", val);
                                } else {
                                    char drop[MYC_UNITS_NAME_LEN];
                                    q = u_read_word
                                        (src, q, le, drop, sizeof(drop));
                                }
                                q = u_skip_trivia(src, len, q);
                            } else
                                break;
                        }
                        s_nshapes++;
                    }
                } else if (strcmp(kw, "provenance") == 0 ||
                           strcmp(kw, "prov") == 0) {
                    char var[MYC_UNITS_NAME_LEN], pv[64];
                    size_t q = u_read_word(src, p, le, var,
                                           sizeof(var));
                    if (var[0] != '\0') {
                        q = u_skip_trivia(src, len, q);
                        u_read_word(src, q, le, pv, sizeof(pv));
                        if (pv[0] != '\0') {
                            uvar *v = u_get_var(var);
                            if (v) {
                                if (v->has_prov &&
                                    strcmp(v->prov, pv) != 0) {
                                    char tb[256];
                                    snprintf(tb, sizeof(tb),
"provenance `%.40s` dari "
                                     "`%.40s` (baris %d) vs "
                                     "`%.40s`",
                                             pv, var, line, v->prov);
                                    u_add(fnd, nf,
                                          MYC_UNITS_DUP_CONFLICT, tb,
                                          line);
                                } else if (!v->has_prov) {
                                    snprintf(v->prov, MYC_UNITS_NAME_LEN,
                                             "%s", pv);
                                    v->has_prov = 1;
                                    if (v->ann_line == 0)
                                        v->ann_line = line;
                                }
                            }
                        }
                    }
                } else if (strcmp(kw, "endian") == 0) {
                    char var[MYC_UNITS_NAME_LEN], en[32];
                    size_t q = u_read_word(src, p, le, var,
                                           sizeof(var));
                    if (var[0] != '\0') {
                        q = u_skip_trivia(src, len, q);
                        u_read_word(src, q, le, en, sizeof(en));
                        if (en[0] != '\0') {
                            uvar *v = u_get_var(var);
                            if (v) {
                                if (v->has_endian &&
                                    strcmp(v->endian, en) != 0) {
                                    char tb[256];
                                    snprintf(tb, sizeof(tb),
                                             "endian `%.20s` dari "
                                             "`%.40s` (baris %d) vs "
                                             "`%.20s`",
                                             en, var, line, v->endian);
                                    u_add(fnd, nf,
                                          MYC_UNITS_DUP_CONFLICT, tb,
                                          line);
                                } else if (!v->has_endian) {
                                    snprintf(v->endian, MYC_UNITS_NAME_LEN,
                                             "%s", en);
                                    v->has_endian = 1;
                                    if (v->ann_line == 0)
                                        v->ann_line = line;
                                }
                            }
                        }
                    }
                }
            }
            i = le;
            continue;
        }
        i++;
    }
}

/* ---------------------------------------------------------------- */
/* Unbound: identifier annotation (th nama) yang tak muncul di teks   */
/* ---------------------------------------------------------------- */

static int count_ident(const char *src, size_t len, const char *name)
{
    size_t i = 0;
    int    n = 0;
    while (i < len) {
        if (src[i] == '/' && i + 1 < len &&
            (src[i + 1] == '*' || src[i + 1] == '/')) {
            i = u_skip_trivia(src, len, i);
            continue;
        }
        if (src[i] == '"' || src[i] == '\'') {
            i = u_skip_literal(src, len, i);
            continue;
        }
        if (u_is_ident_start((unsigned char)src[i])) {
            char w[MYC_UNITS_NAME_LEN];
            size_t e2 = u_read_word(src, i, len, w, sizeof(w));
            if (strcmp(w, name) == 0)
                n++;
            i = e2;
            continue;
        }
        i++;
    }
    return n;
}

/* ---------------------------------------------------------------- */
/* Assignment scan: `a = b` -- unit mismatch / propagation           */
/* ---------------------------------------------------------------- */

static void check_assignments(const char *src, size_t len,
                              ufind *fnd, int *nf, int *nmis)
{
    size_t i = 0;
    while (i < len) {
        if (src[i] == '/' && i + 1 < len &&
            (src[i + 1] == '*' || src[i + 1] == '/')) {
            i = u_skip_trivia(src, len, i);
            continue;
        }
        if (src[i] == '"' || src[i] == '\'') {
            i = u_skip_literal(src, len, i);
            continue;
        }
        if (u_is_ident_start((unsigned char)src[i])) {
            char   a[MYC_UNITS_NAME_LEN], b[MYC_UNITS_NAME_LEN];
            size_t ae, m, bs, be;
            int    line;
            ae = u_read_word(src, i, len, a, sizeof(a));
            m = u_skip_trivia(src, len, ae);
            if (m < len && src[m] == '=' && m + 1 < len &&
                src[m + 1] != '=') {
                bs = u_skip_trivia(src, len, m + 1);
                if (bs < len &&
                    u_is_ident_start((unsigned char)src[bs])) {
                    be = u_read_word(src, bs, len, b, sizeof(b));
                    uvar *va = u_find_var(a);
                    uvar *vb = u_find_var(b);
                    line = u_line_at(src, len, i);
                    if (va && vb && va->has_unit && vb->has_unit &&
                        strcmp(va->unit, vb->unit) != 0) {
                        char tb[256];
                        snprintf(tb, sizeof(tb),
                                 "assignment `%.40s = %.40s` "
                                 "mencampur unit `%.40s` dan "
                                 "`%.40s`",
                                 a, b, va->unit, vb->unit);
                        u_add(fnd, nf, MYC_UNITS_UNIT_MISMATCH, tb,
                              line);
                        (*nmis)++;
                    }
                    /* propagasi unit: sisi bertanda -> sisi belum */
                    if (va && va->has_unit &&
                        (!vb || !vb->has_unit)) {
                        if (!u_is_keyword(b)) {
                            uvar *vp = u_get_var(b);
                            if (vp && !vp->has_unit) {
                                snprintf(vp->unit, MYC_UNITS_NAME_LEN,
                                         "%s", va->unit);
                                vp->has_unit = 1;
                            }
                        }
                    } else if (vb && vb->has_unit &&
                               (!va || !va->has_unit)) {
                        if (!u_is_keyword(a)) {
                            uvar *vp = u_get_var(a);
                            if (vp && !vp->has_unit) {
                                snprintf(vp->unit, MYC_UNITS_NAME_LEN,
                                         "%s", vb->unit);
                                vp->has_unit = 1;
                            }
                        }
                    }
                    i = be;
                    continue;
                }
            }
            i = ae;
            continue;
        }
        i++;
    }
}

/* ---------------------------------------------------------------- */
/* Entri point (eksternal)                                          */
/* ---------------------------------------------------------------- */

const char *myc_units_finding_name(myc_units_finding_kind kind)
{
    switch (kind) {
    case MYC_UNITS_UNBOUND:       return "unbound";
    case MYC_UNITS_UNIT_MISMATCH: return "unit_mismatch";
    case MYC_UNITS_SHAPE_DIM:     return "shape_dim";
    case MYC_UNITS_DUP_CONFLICT:  return "dup_conflict";
    default:                      return "unknown";
    }
}

void myc_units_scan(const char *source, size_t len, myc_result *res)
{
    u_buf rep;
    char  line[640];
    int   i;
    ufind fndList[MYC_UNITS_MAX_FINDINGS];
    int   nf = 0;
    int   unbound = 0;
    int   nmismatch = 0;
    int   nshape = 0;
    int   ndup = 0;

    res->units_ran = 1;
    res->units_annotations = 0;
    res->units_unbound = 0;
    res->units_mismatches = 0;
    res->units_shape_dims = 0;
    res->units_duplicates = 0;
    res->units_report = NULL;
    for (i = 0; i < MYC_UNITS_MAX_FINDINGS; i++)
        memset(&res->units_finding_list[i], 0,
               sizeof(res->units_finding_list[i]));

    memset(fndList, 0, sizeof(fndList));
    s_nvars = 0;
    s_nshapes = 0;

    scan_annotations(source, len, fndList, &nf);

    /* UNBOUND */
    for (i = 0; i < s_nvars; i++) {
        if (count_ident(source, len, s_vars[i].name) == 0) {
            char tb[256];
            snprintf(tb, sizeof(tb),
                     "identifier `%.60s` (annotation baris %d) tidak "
                     "muncul di source",
                     s_vars[i].name, s_vars[i].ann_line);
            u_add(fndList, &nf, MYC_UNITS_UNBOUND, tb,
                  s_vars[i].ann_line);
            unbound++;
        }
    }

    /* SHAPE_DIM */
    for (i = 0; i < s_nshapes; i++) {
        uvar *vc = u_find_var(s_shapes[i].cap);
        uvar *vl = u_find_var(s_shapes[i].len);
        if (vc && vl && vc->has_unit && vl->has_unit &&
            strcmp(vc->unit, vl->unit) != 0) {
            char tb[256];
            snprintf(tb, sizeof(tb),
                     "shape `%.40s`: capacity `%.40s` unit `%.40s` vs "
                     "length `%.40s` unit `%.40s`",
                     s_shapes[i].name, vc->name, vc->unit,
                     vl->name, vl->unit);
            u_add(fndList, &nf, MYC_UNITS_SHAPE_DIM, tb,
                  s_shapes[i].line);
            nshape++;
        }
    }

    /* assignment scan (juga tulis propagasi unit antar var) */
    check_assignments(source, len, fndList, &nf, &nmismatch);

    /* classify dup findings */
    for (i = 0; i < nf; i++)
        if (fndList[i].kind == MYC_UNITS_DUP_CONFLICT)
            ndup++;

    memset(&rep, 0, sizeof(rep));
    ubuf_puts(&rep,
              "units / shape / provenance contracts (SOL-11): "
              "annotation (observasi, NON-blocking)\n");
    ubuf_puts(&rep, "  vars:\n");
    for (i = 0; i < s_nvars; i++) {
        snprintf(line, sizeof(line),
                 "    [%.40s]%s%s%s%s%s%s\n",
                 s_vars[i].name,
                 s_vars[i].has_unit ? " unit=" : "",
                 s_vars[i].has_unit ? s_vars[i].unit : "",
                 s_vars[i].has_prov ? " prov=" : "",
                 s_vars[i].has_prov ? s_vars[i].prov : "",
                 s_vars[i].has_endian ? " endian=" : "",
                 s_vars[i].has_endian ? s_vars[i].endian : "");
        ubuf_puts(&rep, line);
    }
    for (i = 0; i < s_nshapes; i++) {
        snprintf(line, sizeof(line),
                 "    shape[%.40s] capacity=%.40s length=%.40s (baris %d)\n",
                 s_shapes[i].name, s_shapes[i].cap, s_shapes[i].len,
                 s_shapes[i].line);
        ubuf_puts(&rep, line);
    }
    if (nf > 0)
        ubuf_puts(&rep, "  findings:\n");
    for (i = 0; i < nf; i++) {
        const char *kn = myc_units_finding_name(fndList[i].kind);
        snprintf(line, sizeof(line), "    [%s] %.220s (line %d)\n",
                 kn, fndList[i].text, fndList[i].line);
        ubuf_puts(&rep, line);
    }
    snprintf(line, sizeof(line),
             "  ringkasan: %d var, %d shape, %d unbound, %d unit-mismatch, "
             "%d shape-dim, %d dup-conflict\n",
             s_nvars, s_nshapes, unbound, nmismatch, nshape, ndup);
    ubuf_puts(&rep, line);
    ubuf_puts(&rep,
              "  (units = observasi teks; gunakan //@ unit|shape|provenance|endian "
              "untuk deklarasi)\n");

    if (rep.data) {
        res->units_report = myc_result_arena_dup(res, rep.data, 0);
        myc_free(rep.data);
    }

    res->units_annotations = s_nvars + s_nshapes;
    res->units_unbound = unbound;
    res->units_mismatches = nmismatch;
    res->units_shape_dims = nshape;
    res->units_duplicates = ndup;

    for (i = 0; i < nf; i++) {
        myc_units_finding *out = &res->units_finding_list[i];
        out->kind = fndList[i].kind;
        out->text = myc_result_arena_dup(res, fndList[i].text, 0);
        out->witness = myc_result_arena_dup(res, fndList[i].witness, 0);
        out->line = fndList[i].line;
    }
}