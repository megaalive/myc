/*
 * contract.c -- Contract-lite (D1.5): parse //@ requires/ensures.
 *
 * Kontrak satu-baris gaya ACSL minimum:
 *     //@ requires expr;
 *     //@ ensures  expr;
 *
 * Dua kegunaan (bertahap):
 *   1. myc_contract_scan -- hitung requires/ensures, tandai kontrak yang
 *      tidak terbaca (diagnostic). Data masukan untuk gate Frama-C Eva
 *      (D3.1, L2 EVA) nanti.
 *   2. myc_contract_inject -- salinan source dengan assert(requires)
 *      disisipkan setelah '{' pembuka fungsi yang didahului //@ requires.
 *      Dipakai verification build (--run, L3) sebagai defense-in-depth.
 *
 * Catatan jujur (lihat rencana D1.5): inject berbasis scanner baris/karakter,
 * HEURISTIK, bukan AST. Pola yang tidak dikenali dengan yakin TIDAK di-inject
 * (dibiarkan sebagai kontrak statis) agar tidak menimbulkan false violation.
 * ensures tidak di-inject di v1 (butuh menangkap nilai return -- diperiksa
 * oleh Frama-C nanti).
 */
#include "contract.h"

#include <ctype.h>
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
} buf;

static int buf_put(buf *b, char c)
{
    if (b->len + 2 > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 4096;
        char  *nd = (char *)realloc(b->data, ncap);
        if (!nd)
            return 0;
        b->data = nd;
        b->cap = ncap;
    }
    b->data[b->len++] = c;
    b->data[b->len] = '\0';
    return 1;
}

static int buf_putn(buf *b, const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (!buf_put(b, s[i]))
            return 0;
    return 1;
}

static int buf_puts(buf *b, const char *s)
{
    return buf_putn(b, s, strlen(s));
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

/* Baca kata identifier pada posisi i (dalam [0,len)); tulis ke out.
 * Return posisi akhir. */
static size_t read_word(const char *s, size_t i, size_t len,
                        char *out, size_t outcap)
{
    size_t w = 0;
    while (i < len && w + 1 < outcap && is_ident_char((unsigned char)s[i]))
        out[w++] = s[i++];
    out[w] = '\0';
    return i;
}

/* Baca ekspresi kontrak dari posisi i hingga ';' atau akhir baris.
 * Menulis ke out (TIDAK menruncate senyap), *endpos = posisi setelah
 * ';' (bila ada).
 * Return: 1 = ekspresi penuh terbaca;
 *         0 = ekspresi kosong;
 *         2 = ekspresi terlalu panjang untuk buffer (DITOLAK, caller
 *             menambah diagnostic -- prinsip "no silent truncate",
 *             Lampiran A roadmap: long contract expression rejected,
 *             not truncated). */
static int read_contract_expr(const char *s, size_t i, size_t len,
                              char *out, size_t outcap, size_t *endpos)
{
    size_t j = i;
    size_t a, b, t;
    while (j < len && s[j] != '\n' && s[j] != ';')
        j++;
    b = j;
    if (j < len && s[j] == ';')
        j++;
    *endpos = j;
    a = i;
    while (a < b && (s[a] == ' ' || s[a] == '\t'))
        a++;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t'))
        b--;
    t = b - a;
    if (t == 0)
        return 0;
    if (t >= outcap)
        return 2;   /* terlalu panjang: TOLAK, jangan truncate */
    memcpy(out, s + a, t);
    out[t] = '\0';
    return 1;
}

/* Tambah diagnostic kontrak ke res (tidak memiliki string). */
static void add_contract_diag(myc_result *res, int line, int col,
                              const char *msg)
{
    char *slot;
    if (res->diag_count >= MYC_MAX_DIAGNOSTICS)
        return;
    slot = myc_result_arena_dup(res, msg, 0);
    if (!slot)
        return;
    res->diags[res->diag_count].line = line;
    res->diags[res->diag_count].col = col;
    res->diags[res->diag_count].message = slot;
    res->diags[res->diag_count].confidence = MYC_CONF_OBSERVATION;
    res->diag_count++;
}

/* ---------------------------------------------------------------- */
/* Pure expression validation + stable function binding (MYC-AUDIT-025) */
/* ---------------------------------------------------------------- */

const char *myc_clause_status_name(myc_clause_status s)
{
    switch (s) {
    case MYC_CLAUSE_OK:       return "ok";
    case MYC_CLAUSE_EMPTY:    return "empty";
    case MYC_CLAUSE_TOO_LONG: return "too_long";
    case MYC_CLAUSE_IMPURE:   return "impure";
    case MYC_CLAUSE_CALL:     return "call";
    }
    return "unknown";
}

/* Lewati literal string/char (dengan escape) mulai posisi i (s[i] = kutip). */
static size_t skip_literal(const char *s, size_t len, size_t i)
{
    char q = s[i];
    size_t j = i + 1;
    while (j < len) {
        if (s[j] == '\\' && j + 1 < len)
            j += 2;
        else if (s[j] == q) {
            j++;
            break;
        } else
            j++;
    }
    return j;
}

/* Lewati spasi + komentar (baris // dan blok slash-star); return posisi
 * token berikutnya. */
static size_t skip_ws_comment(const char *s, size_t len, size_t i)
{
    for (;;) {
        while (i < len && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' ||
                           s[i] == '\r'))
            i++;
        if (i + 1 < len && s[i] == '/' && s[i + 1] == '/') {
            while (i < len && s[i] != '\n')
                i++;
            continue;
        }
        if (i + 1 < len && s[i] == '/' && s[i + 1] == '*') {
            i += 2;
            while (i + 1 < len && !(s[i] == '*' && s[i + 1] == '/'))
                i++;
            if (i + 1 < len)
                i += 2;
            continue;
        }
        break;
    }
    return i;
}

/* Validasi purity ekspresi kontrak (MYC-AUDIT-025, roadmap 7.4).
 * Purity = tanpa efek samping -- SYARAT agar aman di-inject sebagai assert:
 *   - IMPURE: assignment (=, +=, -=, *=, /=, %=, <<=, >>=, &=, |=, ^=),
 *     inkremen/dekremen (++/--), operator comma di level atas.
 *   - CALL: pemanggilan fungsi (identifier selain sizeof diikuti '(').
 *   - OK: ekspresi pure (perbandingan, aritmetika, bitwise, ternary, dst). */
static myc_clause_status contract_expr_purity(const char *e)
{
    size_t i = 0, len = strlen(e);
    int    paren = 0;
    myc_clause_status worst = MYC_CLAUSE_OK;

    while (i < len) {
        char c = e[i];
        if (c == '"' || c == '\'') {
            i = skip_literal(e, len, i);
            continue;
        }
        if (c == '/' && i + 1 < len && e[i + 1] == '/') {
            while (i < len && e[i] != '\n')
                i++;
            continue;
        }
        if (c == '/' && i + 1 < len && e[i + 1] == '*') {
            i += 2;
            while (i + 1 < len && !(e[i] == '*' && e[i + 1] == '/'))
                i++;
            i += 2;
            continue;
        }
        if (c == '(') {
            paren++;
            i++;
            continue;
        }
        if (c == ')') {
            if (paren > 0)
                paren--;
            i++;
            continue;
        }
        /* ++ / -- */
        if (c == '+' && i + 1 < len && e[i + 1] == '+') {
            worst = MYC_CLAUSE_IMPURE;
            i += 2;
            continue;
        }
        if (c == '-' && i + 1 < len && e[i + 1] == '-') {
            worst = MYC_CLAUSE_IMPURE;
            i += 2;
            continue;
        }
        /* assignment: periksa karakter depan DAN belakang.
         * (Bug MYC-AUDIT-025: `a == b` -- '=' pertama hanya melihat prev
         * spasi dan salah ter-flag impure.) */
        if (c == '=') {
            char p = i > 0 ? e[i - 1] : 0;
            char n = i + 1 < len ? e[i + 1] : 0;
            if (n == '=') {
                i += 2;              /* == : perbandingan pure */
                continue;
            }
            if (p == '=' || p == '!') {
                i++;                 /* '=' (sisa ==) / != : pure */
                continue;
            }
            if (p == '<' || p == '>') {
                if (i > 1 && (e[i - 2] == '<' || e[i - 2] == '>')) {
                    worst = MYC_CLAUSE_IMPURE;   /* <<= / >>= */
                    i++;
                    continue;
                }
                i++;                 /* <= / >= : pure */
                continue;
            }
            if (p == '+' || p == '-' || p == '*' || p == '/' || p == '%' ||
                p == '&' || p == '|' || p == '^') {
                worst = MYC_CLAUSE_IMPURE;   /* += -= *= /= %= &= |= ^= */
                i++;
                continue;
            }
            worst = MYC_CLAUSE_IMPURE;       /* '=' tunggal = assignment */
            i++;
            continue;
        }
        /* operator comma di level atas (sequence point = efek samping) */
        if (c == ',' && paren == 0) {
            worst = MYC_CLAUSE_IMPURE;
            i++;
            continue;
        }
        /* pemanggilan fungsi: identifier (bukan sizeof) diikuti '(' */
        if (is_ident_start((unsigned char)c)) {
            size_t j = i;
            char   w[64];
            size_t wl = 0;
            size_t k;
            while (j < len && wl + 1 < sizeof(w) &&
                   is_ident_char((unsigned char)e[j]))
                w[wl++] = e[j++];
            w[wl] = '\0';
            k = skip_ws_comment(e, len, j);
            if (k < len && e[k] == '(' && strcmp(w, "sizeof") != 0) {
                if (worst == MYC_CLAUSE_OK)
                    worst = MYC_CLAUSE_CALL;
            }
            i = j;
            continue;
        }
        i++;
    }
    return worst;
}

/* Keyword kontrol yang TIDAK bisa menjadi nama fungsi pada binding. */
static int is_control_keyword(const char *w)
{
    static const char *const kws[] = {
        "if", "for", "while", "switch", "return", "sizeof",
        "case", "do", "else", "goto", NULL
    };
    int i;
    for (i = 0; kws[i]; i++)
        if (strcmp(w, kws[i]) == 0)
            return 1;
    return 0;
}

/* Cari binding stabil kontrak ke definisi fungsi (MYC-AUDIT-025, roadmap
 * 7.4): dari posisi `from`, scan ke depan (lewat spasi/komentar/baris #)
 * untuk pola <ident>( ... ){ . Nama fungsi = identifier tepat sebelum '(';
 * keyword kontrol (if/for/while/...) ditolak. Bila ada ';' sebelum '{'
 * (prototype/pernyataan) atau '{' tanpa kandidat fungsi -> TIDAK terikat
 * (return 0). Isi func (NUL-terminated) + *brace_pos bila terikat. */
static int find_func_binding(const char *s, size_t len, size_t from,
                             char *func, size_t funccap, size_t *brace_pos)
{
    size_t i = from;
    char   last[64];
    size_t lastlen = 0;

    while (i < len) {
        char c;
        i = skip_ws_comment(s, len, i);
        if (i >= len)
            return 0;
        c = s[i];
        if (c == '#') {
            while (i < len && s[i] != '\n')
                i++;
            continue;
        }
        if (is_ident_start((unsigned char)c)) {
            lastlen = 0;
            while (i < len && lastlen + 1 < sizeof(last) &&
                   is_ident_char((unsigned char)s[i]))
                last[lastlen++] = s[i++];
            last[lastlen] = '\0';
            continue;
        }
        if (c == '(') {
            size_t j, depth;
            if (lastlen == 0 || is_control_keyword(last))
                return 0;      /* bukan fungsi (mis. if(...)) */
            depth = 1;
            j = i + 1;
            while (j < len && depth > 0) {
                char cc = s[j];
                if (cc == '"' || cc == '\'') {
                    j = skip_literal(s, len, j);
                    continue;
                }
                if (cc == '/' && j + 1 < len && s[j + 1] == '/') {
                    while (j < len && s[j] != '\n')
                        j++;
                    continue;
                }
                if (cc == '/' && j + 1 < len && s[j + 1] == '*') {
                    j += 2;
                    while (j + 1 < len &&
                           !(s[j] == '*' && s[j + 1] == '/'))
                        j++;
                    j += 2;
                    continue;
                }
                if (cc == '(')
                    depth++;
                else if (cc == ')') {
                    depth--;
                    if (depth == 0) {
                        j++;
                        break;
                    }
                }
                j++;
            }
            if (depth > 0)
                return 0;      /* paren tak seimbang */
            j = skip_ws_comment(s, len, j);
            if (j < len && s[j] == '{') {
                if (brace_pos)
                    *brace_pos = j;
                if (lastlen >= funccap)
                    lastlen = funccap - 1;
                memcpy(func, last, lastlen);
                func[lastlen] = '\0';
                return 1;
            }
            if (j < len && s[j] == ';')
                return 0;      /* prototype / pernyataan: tak terikat */
            /* sesuatu lain setelah ')' (mis. atribut): lanjut scan */
            i = j;
            lastlen = 0;
            continue;
        }
        if (c == '{' || c == ';')
            return 0;          /* blok/pernyataan sebelum fungsi: tak terikat */
        i++;
    }
    return 0;
}

/* ---------------------------------------------------------------- */
/* Scan & validasi kontrak                                          */
/* ---------------------------------------------------------------- */

int myc_contract_scan(const char *source, size_t len, myc_result *res)
{
    size_t i = 0;
    size_t line = 1;
    size_t col = 1;
    int    in_group = 0;        /* grup klausa kontrak berturut-turut */
    size_t group_from = 0;      /* posisi akhir baris klausa pertama grup */
    char   group_func[64];      /* binding stabil (dihitung sekali per grup) */
    size_t group_brace = 0;

    res->contract_requires = 0;
    res->contract_ensures = 0;
    res->contract_clause_count = 0;

    while (i < len) {
        char c = source[i];
        if (c == '\n') {
            line++;
            col = 1;
            i++;
            continue;
        }
        /* komentar blok: SKIP penuh -- teks \"//@\" di dalam komentar blok
         * bukan klausa nyata (bug review MYC-AUDIT-025: klausa hantu dari
         * contoh kontrak di komentar header; konsisten dengan inject yang
         * sudah skip komentar blok). */
        if (c == '/' && i + 1 < len && source[i + 1] == '*') {
            size_t end = i + 2;
            while (end + 1 < len &&
                   !(source[end] == '*' && source[end + 1] == '/'))
                end++;
            if (end + 1 < len)
                end += 2;
            while (i < end && i < len) {
                if (source[i] == '\n') {
                    line++;
                    col = 1;
                } else
                    col++;
                i++;
            }
            continue;
        }
        /* komentar // */
        if (c == '/' && i + 1 < len && source[i + 1] == '/') {
            size_t line_end = i;
            size_t start_col = col;
            while (line_end < len && source[line_end] != '\n')
                line_end++;
            if (i + 2 < len && source[i + 2] == '@') {
                size_t j = i + 3;
                char   kw[32];
                size_t kwend;
                while (j < line_end && (source[j] == ' ' || source[j] == '\t'))
                    j++;
                kwend = read_word(source, j, line_end, kw, sizeof(kw));
                if (strcmp(kw, "requires") == 0 ||
                    strcmp(kw, "ensures") == 0) {
                    char expr[512];
                    size_t endp;
                    int    st = read_contract_expr(source, kwend, line_end,
                                                   expr, sizeof(expr), &endp);
                    myc_clause_status status;
                    int kind = (strcmp(kw, "requires") == 0) ? 0 : 1;

                    if (st == 1)
                        status = contract_expr_purity(expr);
                    else if (st == 2)
                        status = MYC_CLAUSE_TOO_LONG;
                    else
                        status = MYC_CLAUSE_EMPTY;

                    /* stable function binding: seluruh grup klausa berturut
                     * berbagi satu hasil binding (dihitung sekali). */
                    if (!in_group) {
                        in_group = 1;
                        group_func[0] = '\0';
                        group_brace = 0;
                        group_from = line_end;
                    }
                    if (group_func[0] == '\0') {
                        if (!find_func_binding(source, len, group_from,
                                               group_func,
                                               sizeof(group_func),
                                               &group_brace)) {
                            group_func[0] = '\0';   /* tak terikat */
                        }
                    }

                    /* catat klausa (explicit clause status, MYC-AUDIT-025) */
                    if (res->contract_clause_count <
                        MYC_MAX_CONTRACT_CLAUSES) {
                        myc_contract_clause *cl =
                            &res->contract_clauses[res->contract_clause_count];
                        memset(cl, 0, sizeof(*cl));
                        cl->expr = (st == 1)
                                       ? myc_result_arena_dup(res, expr, 0)
                                       : NULL;
                        cl->func = group_func[0]
                                       ? myc_result_arena_dup(res,
                                                               group_func, 0)
                                       : NULL;
                        cl->status = status;
                        cl->line = (int)line;
                        cl->col = (int)(start_col + (j - i));
                        cl->kind = kind;
                        res->contract_clause_count++;
                    }

                    if (status == MYC_CLAUSE_TOO_LONG)
                        add_contract_diag(res, (int)line,
                                          (int)(start_col + (j - i)),
                                          kind == 0
                            ? "kontrak requires terlalu panjang (ditolak, bukan ditruncate)"
                            : "kontrak ensures terlalu panjang (ditolak, bukan ditruncate)");
                    else if (status == MYC_CLAUSE_EMPTY)
                        add_contract_diag(res, (int)line,
                                          (int)(start_col + (j - i)),
                                          kind == 0
                            ? "kontrak requires dengan ekspresi kosong"
                            : "kontrak ensures dengan ekspresi kosong");

                    if (kind == 0) {
                        if (status != MYC_CLAUSE_EMPTY &&
                            status != MYC_CLAUSE_TOO_LONG)
                            res->contract_requires++;
                    } else {
                        if (status != MYC_CLAUSE_EMPTY &&
                            status != MYC_CLAUSE_TOO_LONG)
                            res->contract_ensures++;
                    }
                }
            }
            /* lewati baris komentar */
            col += (line_end - i);
            i = line_end;
            continue;
        }
        /* kode non-komentar: grup kontrak berakhir */
        if (in_group)
            in_group = 0;
        i++;
        col++;
    }
    return 1;
}

/* ---------------------------------------------------------------- */
/* List kontrak sebagai string ekspresi (tool MCP `contracts`, P9)    */
/* ---------------------------------------------------------------- */

/* Tambah string malloc'd ke array dinamis; return 1 sukses. */
static int collect_expr(char ***out, int *n, const char *expr)
{
    char **na;
    char  *s = myc_strdup(expr);
    if (!s)
        return 0;
    na = (char **)realloc(*out, sizeof(char *) * (size_t)(*n + 1));
    if (!na) {
        free(s);
        return 0;
    }
    *out = na;
    (*out)[*n] = s;
    (*n)++;
    return 1;
}

int myc_contract_list(const char *source, size_t len,
                      char ***reqs, int *nreqs,
                      char ***ensures, int *nensures)
{
    size_t i = 0;
    size_t line = 1;
    size_t col = 1;

    *reqs = NULL;
    *nreqs = 0;
    *ensures = NULL;
    *nensures = 0;

    while (i < len) {
        char c = source[i];
        if (c == '\n') {
            line++;
            col = 1;
            i++;
            continue;
        }
        if (c == '/' && i + 1 < len && source[i + 1] == '/') {
            size_t line_end = i;
            while (line_end < len && source[line_end] != '\n')
                line_end++;
            if (i + 2 < len && source[i + 2] == '@') {
                size_t j = i + 3;
                char   kw[32];
                size_t kwend;
                while (j < line_end && (source[j] == ' ' || source[j] == '\t'))
                    j++;
                kwend = read_word(source, j, line_end, kw, sizeof(kw));
                if (strcmp(kw, "requires") == 0 ||
                    strcmp(kw, "ensures") == 0) {
                    char   expr[512];
                    size_t endp;
                    int    st = read_contract_expr(source, kwend, line_end,
                                                   expr, sizeof(expr), &endp);
                    /* st==2 = terlalu panjang: TOLAK (jangan kumpulkan
                     * ekspresi terpotong). "No silent truncate". */
                    if (st == 1) {
                        if (strcmp(kw, "requires") == 0)
                            collect_expr(reqs, nreqs, expr);
                        else
                            collect_expr(ensures, nensures, expr);
                    }
                }
            }
            col += (line_end - i);
            i = line_end;
            continue;
        }
        i++;
        col++;
    }
    return 1;
}

/* ---------------------------------------------------------------- */
/* Inject assert(requires) untuk verification build                 */
/* ---------------------------------------------------------------- */

#define MYC_INJECT_MAX_REQ 8   /* jumlah requires yang di-inject per fungsi */

char *myc_contract_inject(const char *source, size_t len, size_t *out_len)
{
    buf    out;
    size_t i = 0;
    size_t depth = 0;
    int    in_paren = 0;       /* di dalam '(' kandidat fungsi (binding) */
    int    expect_brace = 0;   /* ')' kandidat ditutup: tunggu '{' */
    char   func_ident[64];     /* identifier terakhir pada depth 0 */
    size_t func_ident_len = 0;
    char   pending[MYC_INJECT_MAX_REQ][512];
    int    pending_count = 0;
    int    injected_any = 0;
    char   assert_line[1024];

    memset(&out, 0, sizeof(out));
    buf_puts(&out, "#include <assert.h>\n");

    while (i < len) {
        char c = source[i];

        /* komentar // */
        if (c == '/' && i + 1 < len && source[i + 1] == '/') {
            size_t line_end = i;
            while (line_end < len && source[line_end] != '\n')
                line_end++;
            buf_putn(&out, source + i, line_end - i);
            if (line_end < len)
                buf_put(&out, '\n');
            /* parse kontrak: kumpulkan requires PURE saja (MYC-AUDIT-025:
             * ekspresi ber-efek samping / pemanggilan fungsi TIDAK pernah
             * di-inject sebagai assert -- safety). */
            if (i + 2 < len && source[i + 2] == '@') {
                size_t j = i + 3;
                char   kw[32];
                size_t kwend;
                while (j < line_end && (source[j] == ' ' || source[j] == '\t'))
                    j++;
                kwend = read_word(source, j, line_end, kw, sizeof(kw));
                if (strcmp(kw, "requires") == 0) {
                    char   expr[512];
                    size_t endp;
                    int    st = read_contract_expr(source, kwend, line_end,
                                                   expr, sizeof(expr), &endp);
                    if (st == 1 &&
                        contract_expr_purity(expr) == MYC_CLAUSE_OK &&
                        pending_count < MYC_INJECT_MAX_REQ) {
                        /* snprintf berbatas: hindari -Wstringop-truncation
                         * (gcc 13 menolak strncpy 511/511 di -Werror). */
                        snprintf(pending[pending_count],
                                 sizeof(pending[0]), "%s", expr);
                        pending_count++;
                    }
                }
            }
            i = line_end;
            if (i < len && source[i] == '\n')
                i++;
            continue;
        }

        /* komentar blok */
        if (c == '/' && i + 1 < len && source[i + 1] == '*') {
            size_t end = i + 2;
            while (end + 1 < len &&
                   !(source[end] == '*' && source[end + 1] == '/'))
                end++;
            if (end + 1 < len)
                end += 2;
            buf_putn(&out, source + i, end - i);
            i = end;
            continue;
        }

        /* string / char literal */
        if (c == '"' || c == '\'') {
            char   q = c;
            size_t j = i + 1;
            while (j < len) {
                if (source[j] == '\\' && j + 1 < len)
                    j += 2;
                else if (source[j] == q) {
                    j++;
                    break;
                } else
                    j++;
            }
            buf_putn(&out, source + i, j - i);
            i = j;
            continue;
        }

        /* preprocessor: salin apa adanya */
        if (c == '#') {
            size_t line_end = i;
            while (line_end < len && source[line_end] != '\n')
                line_end++;
            buf_putn(&out, source + i, line_end - i);
            if (line_end < len)
                buf_put(&out, '\n');
            i = line_end;
            if (i < len && source[i] == '\n')
                i++;
            continue;
        }

        /* pelacakan binding stabil fungsi (MYC-AUDIT-025):
         * <ident>( ... ){  -- ident bukan keyword kontrol; ';' sebelum '{'
         * = prototype/pernyataan (pending dibuang); '{' tanpa kandidat =
         * blok lain (pending dibuang). Spasi/komentar antar token TIDAK
         * memutus ikatan (bug: spasi antara ')' dan '{' membuang pending). */
        if (depth == 0 && !in_paren) {
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                buf_put(&out, c);
                i++;
                continue;
            }
            if (is_ident_start((unsigned char)c)) {
                func_ident_len = 0;
                while (i < len && func_ident_len + 1 < sizeof(func_ident) &&
                       is_ident_char((unsigned char)source[i]))
                    func_ident[func_ident_len++] = source[i++];
                func_ident[func_ident_len] = '\0';
                buf_putn(&out, source + i - func_ident_len, func_ident_len);
                continue;
            }
            if (c == '(') {
                if (func_ident_len > 0 &&
                    !is_control_keyword(func_ident) &&
                    pending_count > 0) {
                    in_paren = 1;
                    depth = 1;
                } else {
                    func_ident_len = 0;
                }
            } else if (c == '{') {
                if (expect_brace && pending_count > 0) {
                    /* definisi fungsi terkonfirmasi: inject semua requires */
                    int q;
                    buf_put(&out, '{');
                    buf_puts(&out, "\n");
                    for (q = 0; q < pending_count; q++) {
                        snprintf(assert_line, sizeof(assert_line),
                                 "    assert(%s);\n", pending[q]);
                        buf_puts(&out, assert_line);
                    }
                    injected_any = 1;
                    pending_count = 0;
                    expect_brace = 0;
                    i++;
                    continue;
                }
                if (pending_count > 0)
                    pending_count = 0;   /* blok tanpa signature: buang */
                expect_brace = 0;
            } else if (c == ';') {
                /* statement/prototype memutus ikatan kontrak: SELALU buang
                 * pending (bug review MYC-AUDIT-025: bila hanya dibuang saat
                 * expect_brace, pending basi menembus statement ber-parens
                 * dan ter-inject ke fungsi LAIN -- assert palsu). */
                pending_count = 0;
                expect_brace = 0;
                func_ident_len = 0;
            } else {
                expect_brace = 0;        /* token lain memutus ikatan */
            }
            buf_put(&out, c);
            i++;
            continue;
        }

        if (in_paren) {
            /* di dalam tanda tangan fungsi kandidat */
            if (c == '(')
                depth++;
            else if (c == ')') {
                depth--;
                if (depth == 0) {
                    in_paren = 0;
                    /* arm: karakter berikutnya (setelah spasi/komentar)
                     * menentukan definisi vs prototype -- ditangani di
                     * blok depth==0 (expect_brace). */
                    expect_brace = 1;
                }
            }
            buf_put(&out, c);
            i++;
            continue;
        }

        /* depth > 0 di luar kandidat (mis. ekspresi): salin, lacak kurung */
        if (c == '(')
            depth++;
        else if (c == ')') {
            if (depth > 0)
                depth--;
        }
        buf_put(&out, c);
        i++;
    }

    if (!injected_any) {
        free(out.data);
        /* Jangan sentuh *out_len: return NULL berarti caller memakai
         * source asli dengan panjang aslinya. */
        return NULL;
    }
    if (out_len)
        *out_len = out.len;
    return out.data ? out.data : NULL;
}
