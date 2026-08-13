/*
 * resource.c -- Resource Linearity Ledger (Fase 5, SOL-12).
 *
 * Menelusuri acquire/release pair (profil default + deklarasi
 * `//@ resource ACQ -> REL;`) per fungsi, dan melaporkan nasib tiap
 * resource local:
 *
 *     acquired -> release | leaked | double-released | transferred | unknown
 *
 * Temuan (NON-blocking observasi; verdict TIDAK pernah turun):
 *   LEAKED          acq@L tidak pernah release/transfer sampai akhir body.
 *   DOUBLE_RELEASE  release kedua pada resource yang sudah release.
 *   RELEASE_UNKNOWN release pada variabel yang tak terlihat acquire-nya
 *                   (kecuali parameter: kepemilikan berasal dari caller,
 *                   TIDAK dilaporkan).
 *
 * Scanner TEKS deterministik (bukan AST), bounded dan parsial -- jujur:
 * tidak interprocedural. Resource yang dilewatkan ke fungsi lain sebagai
 * argumen biasa BUKAN klaim leak (dicari 'return var' = transferred).
 */
#include "resource.h"

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
} buffer_t;

static int buffer_put(buffer_t *b, char c)
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

static int buffer_puts(buffer_t *b, const char *s)
{
    size_t i;
    for (i = 0; s[i]; i++)
        if (!buffer_put(b, s[i]))
            return 0;
    return 1;
}

/* ---------------------------------------------------------------- */
/* Lexical helper                                                   */
/* ---------------------------------------------------------------- */

static int is_ident_start(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int is_ident_char(int c)
{
    return is_ident_start(c) || (c >= '0' && c <= '9');
}

static int is_keyword(const char *w)
{
    static const char *const KW[] = {
        "auto", "break", "case", "char", "const", "continue", "default",
        "do", "double", "else", "enum", "extern", "float", "for",
        "goto", "if", "inline", "int", "long", "register", "restrict",
        "return", "short", "signed", "sizeof", "static", "struct",
        "switch", "typedef", "union", "unsigned", "void", "volatile",
        "while", "_Atomic", "_Bool", "_Complex", "_Imaginary",
        "_Alignas", "_Alignof", "_Generic", "_Noreturn",
        "_Static_assert", "_Thread_local", NULL
    };
    int i;
    for (i = 0; KW[i]; i++)
        if (strcmp(w, KW[i]) == 0)
            return 1;
    return 0;
}

/* Nomor baris (1-based) untuk posisi dalam source. */
static int line_at(const char *s, size_t len, size_t pos)
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

/* Lewati whitespace, komentar, dan baris preprocessor (mulai baris baru). */
static size_t skip_trivia(const char *s, size_t len, size_t p)
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
        if (p < len && s[p] == '#' && (p == 0 || s[p - 1] == '\n')) {
            while (p < len && s[p] != '\n')
                p++;
            continue;
        }
        break;
    }
    return p;
}

/* Lewati sebuah string/char literal; s[p] == '"' atau '\''. */
static size_t skip_literal(const char *s, size_t len, size_t p)
{
    char q = s[p];
    p++;
    while (p < len && s[p] != q) {
        if (s[p] == '\\' && p + 1 < len)
            p += 2;
        else
            p++;
    }
    return (p < len) ? (p + 1) : len;
}

/* ( s[p]=='(' ) => kembalikan posisi ')' penutup. */
static size_t skip_parens(const char *s, size_t len, size_t p)
{
    size_t i = p + 1;
    int    depth = 1;
    while (i < len && depth > 0) {
        if (s[i] == '/' && i + 1 < len &&
            (s[i + 1] == '*' || s[i + 1] == '/')) {
            i = skip_trivia(s, len, i);
            continue;
        }
        if (s[i] == '"' || s[i] == '\'') {
            i = skip_literal(s, len, i);
            continue;
        }
        if (s[i] == '(')
            depth++;
        else if (s[i] == ')')
            depth--;
        if (depth == 0)
            break;
        i++;
    }
    return i;
}

/* s[p]=='{' => kembalikan posisi '}' penutup. */
static size_t matched_brace(const char *s, size_t len, size_t p)
{
    size_t i = p + 1;
    int    depth = 1;
    while (i < len && depth > 0) {
        if (s[i] == '/' && i + 1 < len &&
            (s[i + 1] == '*' || s[i + 1] == '/')) {
            i = skip_trivia(s, len, i);
            continue;
        }
        if (s[i] == '"' || s[i] == '\'') {
            i = skip_literal(s, len, i);
            continue;
        }
        if (s[i] == '{')
            depth++;
        else if (s[i] == '}')
            depth--;
        if (depth == 0)
            break;
        i++;
    }
    return i;
}

/* ---------------------------------------------------------------- */
/* Profil acquire/release (default + deklarasi //@ resource)        */
/* ---------------------------------------------------------------- */

static const char *const DEFAULT_ACQ[] = {
    "fopen", "open", "popen", "fdopen",
    "mmap", "CreateFile", "CreateFileA", "CreateFileW",
};
static const char *const DEFAULT_REL[] = {
    "fclose", "close", "pclose", "fclose",
    "munmap", "CloseHandle", "CloseHandle", "CloseHandle",
};
#define N_DEFAULT_PAIRS (sizeof(DEFAULT_ACQ) / sizeof(DEFAULT_ACQ[0]))

typedef struct {
    char acquire[MYC_RSRC_NAME_LEN];
    char release[MYC_RSRC_NAME_LEN];
    int  declared;
} profile;

/* Mutable state analisis non-const => wajib _Thread_local (aturan
 * AGENTS.md: static non-const yang ditulis harus _Thread_local atau
 * pindah ke arena). */
static _Thread_local profile s_prof[MYC_RSRC_MAX_PAIRS];
static _Thread_local int     s_nprof;

static void prof_reset(void)
{
    size_t i;
    if (s_nprof > 0)
        return;
    for (i = 0; i < N_DEFAULT_PAIRS && s_nprof < MYC_RSRC_MAX_PAIRS; i++) {
        strncpy(s_prof[s_nprof].acquire, DEFAULT_ACQ[i],
                MYC_RSRC_NAME_LEN - 1);
        strncpy(s_prof[s_nprof].release, DEFAULT_REL[i],
                MYC_RSRC_NAME_LEN - 1);
        s_prof[s_nprof].acquire[MYC_RSRC_NAME_LEN - 1] = '\0';
        s_prof[s_nprof].release[MYC_RSRC_NAME_LEN - 1] = '\0';
        s_prof[s_nprof].declared = 0;
        s_nprof++;
    }
}

static void prof_set(const char *acq, const char *rel)
{
    int i;
    for (i = 0; i < s_nprof; i++)
        if (strcmp(s_prof[i].acquire, acq) == 0) {
            strncpy(s_prof[i].release, rel, MYC_RSRC_NAME_LEN - 1);
            s_prof[i].release[MYC_RSRC_NAME_LEN - 1] = '\0';
            s_prof[i].declared = 1;
            return;
        }
    if (s_nprof < MYC_RSRC_MAX_PAIRS) {
        strncpy(s_prof[s_nprof].acquire, acq, MYC_RSRC_NAME_LEN - 1);
        strncpy(s_prof[s_nprof].release, rel, MYC_RSRC_NAME_LEN - 1);
        s_prof[s_nprof].acquire[MYC_RSRC_NAME_LEN - 1] = '\0';
        s_prof[s_nprof].release[MYC_RSRC_NAME_LEN - 1] = '\0';
        s_prof[s_nprof].declared = 1;
        s_nprof++;
    }
}

/* Ekstrak kata identifier dari [p,end). */
static size_t read_word(const char *s, size_t p, size_t end,
                        char *t, size_t cap)
{
    size_t i = p;
    size_t w = 0;
    while (i < end && is_ident_start((unsigned char)s[i]) &&
           w + 1 < cap)
        t[w++] = s[i++];
    t[w] = '\0';
    return (w) ? i : p;
}

/* Scan `//@ resource ACQ -> REL;` untuk profil kustom. */
static void prof_scan(const char *src, size_t len)
{
    size_t i = 0;
    while (i < len) {
        if (src[i] == '/' && i + 1 < len &&
            (src[i + 1] == '*' || src[i + 1] == '/')) {
            i = skip_trivia(src, len, i);
            continue;
        }
        if (src[i] == '/' && i + 1 < len && src[i + 1] == '/') {
            size_t le = i;
            while (le < len && src[le] != '\n')
                le++;
            if (i + 2 < le && src[i + 2] == '@') {
                char kw[64];
                size_t pe = read_word(src, i + 3, le, kw, sizeof(kw));
                if (strcmp(kw, "resource") == 0) {
                    char acq[MYC_RSRC_NAME_LEN];
                    char rel[MYC_RSRC_NAME_LEN];
                    size_t ae = read_word(src, pe, le, acq,
                                          sizeof(acq));
                    if (acq[0] != '\0') {
                        while (ae < le &&
                               (src[ae] == ' ' || src[ae] == '\t'))
                            ae++;
                        if (ae + 1 < le && src[ae] == '-' &&
                            src[ae + 1] == '>') {
                            ae += 2;
                            read_word(src, ae, le, rel, sizeof(rel));
                            if (rel[0] != '\0')
                                prof_set(acq, rel);
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
/* Tokenizer                                                         */
/* ---------------------------------------------------------------- */

enum {
    TK_IDENT = 1,
    TK_LPAREN,
    TK_RPAREN,
    TK_EQ,
    TK_COMMA,
    TK_PTR,     /* '&' '*' '.' '-' */
    TK_OTHER
};

typedef struct {
    char  text[MYC_RSRC_NAME_LEN];
    int   kind;
    int   line;
} rtok;

/* Tokenkan irisan source [s,e). ncap = kapasitas token array. */
static int tokenize(const char *src, size_t s, size_t e,
                    rtok *toks, int ncap)
{
    int    n = 0;
    size_t i = s;
    int    line = line_at(src, e, s);
    while (i < e && n < ncap) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\n') {
            line++;
            i++;
            continue;
        }
        if (c == ' ' || c == '\t' || c == '\r') {
            i++;
            continue;
        }
        if (src[i] == '/' && i + 1 < e &&
            (src[i + 1] == '*' || src[i + 1] == '/')) {
            i = skip_trivia(src, e, i);
            continue;
        }
        if (c == '"' || c == '\'') {
            i = skip_literal(src, e, i);
            continue;
        }
        if (is_ident_start(c)) {
            size_t w = 0;
            toks[n].kind = TK_IDENT;
            toks[n].line = line;
            while (i < e && is_ident_char((unsigned char)src[i]) &&
                   w + 1 < MYC_RSRC_NAME_LEN)
                toks[n].text[w++] = src[i++];
            toks[n].text[w] = '\0';
            n++;
            continue;
        }
        toks[n].kind = TK_OTHER;
        toks[n].line = line;
        toks[n].text[0] = (char)c;
        toks[n].text[1] = '\0';
        if (c == '(')
            toks[n].kind = TK_LPAREN;
        else if (c == ')')
            toks[n].kind = TK_RPAREN;
        else if (c == '=')
            toks[n].kind = TK_EQ;
        else if (c == ',')
            toks[n].kind = TK_COMMA;
        else if (c == '&' || c == '*' || c == '.' || c == '-')
            toks[n].kind = TK_PTR;
        n++;
        i++;
    }
    return n;
}

/* ---------------------------------------------------------------- */
/* Penemuan fungsi                                                  */
/* ---------------------------------------------------------------- */

#define MYC_RSRC_MAX_PARAMS 32

typedef struct {
    char   name[MYC_RSRC_NAME_LEN];
    int    line;          /* baris nama fungsi */
    size_t body_s;        /* setelah '{' pembuka */
    size_t body_e;        /* posisi '}' penutup  */
    int    nparams;
    char   params[MYC_RSRC_MAX_PARAMS][MYC_RSRC_NAME_LEN];
} fndef;

/* Ekstrak nama parameter memindai [paren+1, close). */
static void fn_params(const char *src, size_t a, size_t b,
                      fndef *def)
{
    size_t i = a;
    while (i < b) {
        if (is_ident_start((unsigned char)src[i])) {
            char tk[MYC_RSRC_NAME_LEN];
            size_t e2 = i;
            size_t w = 0;
            while (e2 < b && is_ident_char((unsigned char)src[e2]) &&
                   w + 1 < MYC_RSRC_NAME_LEN)
                tk[w++] = src[e2++];
            tk[w] = '\0';
            if (!is_keyword(tk) &&
                def->nparams < MYC_RSRC_MAX_PARAMS) {
                snprintf(def->params[def->nparams],
                         MYC_RSRC_NAME_LEN, "%s", tk);
                def->nparams++;
            }
            i = e2;
        } else
            i++;
    }
}

static int fn_is_param(const fndef *def, const char *name)
{
    int i;
    for (i = 0; i < def->nparams; i++)
        if (strcmp(def->params[i], name) == 0)
            return 1;
    return 0;
}

/* Kumpulkan definisi fungsi (heuristik deterministik). */
static int find_functions(const char *src, size_t len,
                          fndef *out, int max)
{
    int    n = 0;
    size_t i = 0;
    while (i < len) {
        if (src[i] == '/' && i + 1 < len &&
            (src[i + 1] == '*' || src[i + 1] == '/')) {
            i = skip_trivia(src, len, i);
            continue;
        }
        if (is_ident_start((unsigned char)src[i])) {
            char   nm[MYC_RSRC_NAME_LEN];
            size_t s = i;
            size_t w = 0;
            while (i < len && is_ident_char((unsigned char)src[i]) &&
                   w + 1 < MYC_RSRC_NAME_LEN)
                nm[w++] = src[i++];
            nm[w] = '\0';
            if (is_keyword(nm))
                continue;
            {
                size_t iline = (size_t)line_at(src, len, s);
                size_t q = skip_trivia(src, len, i);
                if (q < len && src[q] == '(') {
                    size_t close = skip_parens(src, len, q);
                    size_t brace = skip_trivia(
                        src, len, (close < len) ? (close + 1) : close);
                    if (brace < len && src[brace] == '{') {
                        size_t bend = matched_brace(src, len, brace);
                        if (n < max && bend < len) {
                            fndef *def = &out[n];
                            memset(def, 0, sizeof(*def));
                            memcpy(def->name, nm, w + 1);
                            def->line = (int)iline;
                            def->body_s = brace + 1;
                            def->body_e = bend;
                            fn_params(src, q + 1, close, def);
                            n++;
                        }
                    }
                }
            }
            continue;
        }
        i++;
    }
    return n;
}

/* ---------------------------------------------------------------- */
/* Ledger per fungsi                                                */
/* ---------------------------------------------------------------- */

typedef struct {
    char var[MYC_RSRC_NAME_LEN];
    char acq[MYC_RSRC_NAME_LEN];
    int  acq_line;
    int  rel_line;
    int  state;   /* 0 none, 1 acquired, 2 released, 3 transferred */
} rres;

typedef struct {
    const char *name;
    int         line;
    size_t      body_end;
} close_fn;

typedef struct {
    myc_rsrc_finding_kind kind;
    char text[256];
    char witness[192];
    int  line;
} rfind;

static int r_find(const rres *r, int n, const char *var)
{
    int i;
    for (i = 0; i < n; i++)
        if (strcmp(r[i].var, var) == 0)
            return i;
    return -1;
}

static void add_finding(rfind *fnd, int *nf,
                        myc_rsrc_finding_kind kind,
                        const char *text, int line)
{
    if (*nf >= MYC_RSRC_MAX_FINDINGS)
        return;
    memset(&fnd[*nf], 0, sizeof(rfind));
    fnd[*nf].kind = kind;
    snprintf(fnd[*nf].text, sizeof(fnd[*nf].text), "%s", text);
    fnd[*nf].line = line;
    (*nf)++;
}

/* Target assignment untuk sebuah acquire-call: `X = acq(...)`. */
static const char *acq_target(const rtok *toks, int st, int i)
{
    int j;
    for (j = i - 1; j >= st; j--) {
        if (toks[j].kind == TK_EQ)
            return (j - 1 >= st && toks[j - 1].kind == TK_IDENT)
                       ? toks[j - 1].text : NULL;
        if (toks[j].kind == TK_LPAREN || toks[j].kind == TK_COMMA)
            return NULL;
        if (toks[j].kind == TK_OTHER &&
            (toks[j].text[0] == ';' || toks[j].text[0] == '{' ||
             toks[j].text[0] == '}'))
            return NULL;
        if (toks[j].kind == TK_PTR && toks[j].text[0] == '&')
            return NULL;
    }
    return NULL;
}

typedef struct {
    int acquires;
    int releases;
    int transfers;
    int anon_acquired;
} fperf;

static void scan_body(const char *src, size_t bs, size_t be,
                      const fndef *def, rres *r, int *nr,
                      rfind *fnd, int *nf, fperf *perf)
{
    size_t nbytes = (be > bs) ? (be - bs) : 0;
    int    ntok;
    rtok  *toks;
    int    i;
    int    stmt = 0;
    const int TK_TOKENS_MAX = 65536;

    if (nbytes == 0)
        return;
    {
        size_t cap = nbytes;
        if (cap > (size_t)TK_TOKENS_MAX)
            cap = (size_t)TK_TOKENS_MAX;
        toks = (rtok *)myc_malloc(cap * sizeof(rtok));
        if (!toks)
            return;
        ntok = tokenize(src, bs, be, toks, (int)cap);
    }

    for (i = 0; i < ntok; i++) {
        int p;
        if (toks[i].kind == TK_OTHER &&
            (toks[i].text[0] == ';' || toks[i].text[0] == '{' ||
             toks[i].text[0] == '}')) {
            stmt = i + 1;
            continue;
        }
        /* return var; => transfer kepemilikan */
        if (toks[i].kind == TK_IDENT &&
            strcmp(toks[i].text, "return") == 0) {
            int    k = i + 1;
            const char *rv = NULL;
            int    junk = 0;
            while (k < ntok && toks[k].kind != TK_OTHER) {
                if (toks[k].kind == TK_IDENT) {
                    if (rv == NULL)
                        rv = toks[k].text;
                    else
                        junk = 1;
                }
                k++;
            }
            if (!junk && rv) {
                int fi = r_find(r, *nr, rv);
                if (fi >= 0 && r[fi].state == 1) {
                    r[fi].state = 3;
                    perf->transfers++;
                }
            }
            continue;
        }
        if (i + 1 >= ntok || toks[i + 1].kind != TK_LPAREN)
            continue;
        for (p = 0; p < s_nprof; p++) {
            if (strcmp(toks[i].text, s_prof[p].acquire) == 0) {
                const char *var = acq_target(toks, stmt, i);
                if (var) {
                    if (r_find(r, *nr, var) < 0 &&
                        *nr < MYC_RSRC_MAX_VARS) {
                        rres *r0 = &r[*nr];
                        snprintf(r0->var, MYC_RSRC_NAME_LEN, "%s", var);
                        snprintf(r0->acq, MYC_RSRC_NAME_LEN, "%.63s",
                                 s_prof[p].acquire);
                        r0->acq_line = toks[i].line;
                        r0->rel_line = 0;
                        r0->state = 1;
                        (*nr)++;
                    }
                    perf->acquires++;
                } else
                    perf->anon_acquired++;
                break;
            }
            if (strcmp(toks[i].text, s_prof[p].release) == 0) {
                const char *arg = NULL;
                if (i + 2 < ntok && toks[i + 2].kind == TK_IDENT)
                    arg = toks[i + 2].text;
                if (arg && i + 3 < ntok &&
                    toks[i + 3].kind == TK_LPAREN)
                    arg = NULL;   /* fclose(fopen(..)) nested */
                if (arg) {
                    int fi = r_find(r, *nr, arg);
                    if (fi >= 0) {
                        if (r[fi].state == 2) {
                            char tb[256];
snprintf(tb, sizeof(tb),
                                 "release ganda pada `%.63s` (line "
                                 "%d; sudah di-release di %d)",
                                 arg, toks[i].line,
                                 r[fi].rel_line);
                            add_finding(fnd, nf,
                                        MYC_RSRC_DOUBLE_RELEASE,
                                        tb, toks[i].line);
                        } else if (r[fi].state == 1) {
                            r[fi].state = 2;
                            r[fi].rel_line = toks[i].line;
                        }
                        perf->releases++;
                    } else if (!fn_is_param(def, arg)) {
                        char tb[256];
                        snprintf(tb, sizeof(tb),
                                 "release `%.63s` pada var `%.63s`: tak "
                                 "ada acquire di fungsi `%.63s`",
                                 s_prof[p].release, arg, def->name);
                        add_finding(fnd, nf,
                                    MYC_RSRC_RELEASE_UNKNOWN,
                                    tb, toks[i].line);
                        perf->releases++;
                    } else
                        perf->releases++;
                } else if (perf->anon_acquired > 0) {
                    perf->anon_acquired--;
                    perf->releases++;
                }
                break;
            }
        }
    }
    myc_free(toks);
}

/* resource yang masih acquired pada akhir fungsi => LEAKED. */
static void close_func(int endline, const fndef *def,
                       rres *r, int *nr, rfind *fnd, int *nf)
{
    int i;
    for (i = 0; i < *nr; i++) {
        if (r[i].state == 1) {
            char tb[512];
            char wit[192];
            snprintf(tb, sizeof(tb),
                     "`%.63s` di-acquire oleh `%.63s` (line %d) di "
                     "`%.63s`: tidak di-release atau ditransfer "
                     "sampai akhir fungsi (line %d)",
                     r[i].var, r[i].acq, r[i].acq_line, def->name,
                     endline);
            snprintf(wit, sizeof(wit),
                     "acq@%d..end@%d (fungsi `%.63s`)",
                     r[i].acq_line, endline, def->name);
            add_finding(fnd, nf, MYC_RSRC_LEAKED, tb,
                        r[i].acq_line);
            if (*nf > 0)
                snprintf(fnd[*nf - 1].witness,
                         sizeof(fnd[*nf - 1].witness), "%s", wit);
        }
    }
    *nr = 0;
}

/* ---------------------------------------------------------------- */
/* Entri point (eksternal)                                          */
/* ---------------------------------------------------------------- */

const char *myc_rsrc_finding_name(myc_rsrc_finding_kind kind)
{
    switch (kind) {
    case MYC_RSRC_LEAKED:        return "leaked";
    case MYC_RSRC_DOUBLE_RELEASE: return "double_release";
    case MYC_RSRC_RELEASE_UNKNOWN: return "release_unknown";
    default:                     return "unknown";
    }
}

void myc_resource_scan(const char *source, size_t len, myc_result *res)
{
    buffer_t rep;
    char     line[640];
    int      i;
    fndef    fn[MYC_RSRC_MAX_FUNCS];
    int      nfn;
    rres     rs[MYC_RSRC_MAX_VARS];
    int      nrs = 0;
    rfind    fndList[MYC_RSRC_MAX_FINDINGS];
    int      nf = 0;
    fperf    tot;

    /* reset / init */
    res->rsrc_ran = 1;
    res->rsrc_pairs = 0;
    res->rsrc_acquires = 0;
    res->rsrc_releases = 0;
    res->rsrc_transferred = 0;
    res->rsrc_leaks = 0;
    res->rsrc_double_releases = 0;
    res->rsrc_release_unknown = 0;
    res->rsrc_report = NULL;
    for (i = 0; i < MYC_RSRC_MAX_FINDINGS; i++)
        memset(&res->rsrc_finding_list[i], 0,
               sizeof(res->rsrc_finding_list[i]));
    memset(&tot, 0, sizeof(tot));

    prof_reset();
    prof_scan(source, len);
    res->rsrc_pairs = s_nprof;

    memset(&rep, 0, sizeof(rep));
    buffer_puts(&rep,
                "resource ledger (SOL-12): profil acquire->release "
                "(observasi, NON-blocking)\n");
    buffer_puts(&rep, "  pairs:");
    for (i = 0; i < s_nprof; i++) {
        snprintf(line, sizeof(line),
                 " %.63s -> %.63s%s", s_prof[i].acquire, s_prof[i].release,
                 s_prof[i].declared ? "(deklarasi)" : "");
        buffer_puts(&rep, line);
    }
    buffer_puts(&rep, "\n");

    nfn = find_functions(source, len, fn, MYC_RSRC_MAX_FUNCS);

    for (i = 0; i < nfn; i++) {
        int    endline = line_at(source, len, fn[i].body_e);
        fperf  one;
        memset(&one, 0, sizeof(one));
        scan_body(source, fn[i].body_s, fn[i].body_e,
                  &fn[i], rs, &nrs, fndList, &nf, &one);
        close_func(endline, &fn[i], rs, &nrs, fndList, &nf);
        tot.acquires += one.acquires;
        tot.releases += one.releases;
        tot.transfers += one.transfers;
        snprintf(line, sizeof(line),
                 "  [%.63s @%d] acquire=%d release=%d transfer=%d\n",
                 fn[i].name, fn[i].line, one.acquires,
                 one.releases, one.transfers);
        buffer_puts(&rep, line);
    }

    /* findings + per-kind counts */
    if (nf > 0)
        buffer_puts(&rep, "  findings:\n");
    for (i = 0; i < nf; i++) {
        const char *kn = myc_rsrc_finding_name(fndList[i].kind);
        if (fndList[i].kind == MYC_RSRC_LEAKED)
            res->rsrc_leaks++;
        else if (fndList[i].kind == MYC_RSRC_DOUBLE_RELEASE)
            res->rsrc_double_releases++;
        else if (fndList[i].kind == MYC_RSRC_RELEASE_UNKNOWN)
            res->rsrc_release_unknown++;
        snprintf(line, sizeof(line),
                 "    [%s] %.240s (line %d)\n",
                 kn, fndList[i].text, fndList[i].line);
        buffer_puts(&rep, line);
        if (fndList[i].witness[0]) {
            snprintf(line, sizeof(line), "      witness: %.180s\n",
                     fndList[i].witness);
            buffer_puts(&rep, line);
        }
    }
    snprintf(line, sizeof(line),
             "  ringkasan: %d fungsi, %d acquire, %d release, "
             "%d transfer, %d leak, %d double, %d unknown\n",
             nfn, tot.acquires, tot.releases, tot.transfers,
             res->rsrc_leaks, res->rsrc_double_releases,
             res->rsrc_release_unknown);
    buffer_puts(&rep, line);
    buffer_puts(&rep,
                "  (resource ledger = observasi teks; gunakan //@ "
                "resource ACQ -> REL; untuk profil kustom)\n");

    if (rep.data) {
        res->rsrc_report = myc_result_arena_dup(res, rep.data, 0);
        myc_free(rep.data);
    }

    res->rsrc_acquires = tot.acquires;
    res->rsrc_releases = tot.releases;
    res->rsrc_transferred = tot.transfers;

    for (i = 0; i < nf; i++) {
        myc_rsrc_finding *out = &res->rsrc_finding_list[i];
        out->kind = fndList[i].kind;
        out->text = myc_result_arena_dup(res, fndList[i].text, 0);
        out->witness = myc_result_arena_dup(res, fndList[i].witness,
                                            0);
        out->line = fndList[i].line;
    }
    /* jumlah finding (maks) tidak dicatat vendor; counts ada di scalar */
}