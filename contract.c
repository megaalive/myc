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
    na = (char **)myc_realloc(*out, sizeof(char *) * (size_t)(*n + 1));
    if (!na) {
        myc_free(s);
        return 0;
    }
    *out = na;
    (*out)[*n] = s;
    (*n)++;
    return 1;
}

/* ---- Contract/domain delta (Fase 2) ---- */

const char *myc_contract_delta_name(myc_contract_delta_kind k)
{
    switch (k) {
    case MYC_DELTA_CLEAN:    return "CLEAN";
    case MYC_DELTA_NARROWED: return "NARROWED";
    case MYC_DELTA_WEAKENED: return "WEAKENED";
    case MYC_DELTA_CHANGED:  return "CHANGED";
    }
    return "UNKNOWN";
}

/* Cek apakah expr ada di list. Normalisasi SIMETRIS di kedua sisi:
 * strip spasi/tab/CR di ujung (menangani CRLF tanpa false delta). */
static size_t delta_trim(const char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r'))
        n--;
    return n;
}

static int delta_has(const char *const *list, int n, const char *expr)
{
    int i;
    size_t el = delta_trim(expr);
    for (i = 0; i < n; i++) {
        const char *a = list[i];
        size_t al = delta_trim(a);
        if (al == el && strncmp(a, expr, el) == 0)
            return 1;
    }
    return 0;
}

static int delta_diff(char **new_list, int n_new,
                      char **old_list, int n_old,
                      char ***added_out, int *n_added_out,
                      char ***removed_out, int *n_removed_out)
{
    int i;
    *added_out = NULL;
    *n_added_out = 0;
    *removed_out = NULL;
    *n_removed_out = 0;

    for (i = 0; i < n_new; i++) {
        if (!delta_has((const char *const *)old_list, n_old, new_list[i])) {
            if (!collect_expr(added_out, n_added_out, new_list[i]))
                return 0;
        }
    }
    for (i = 0; i < n_old; i++) {
        if (!delta_has((const char *const *)new_list, n_new, old_list[i])) {
            if (!collect_expr(removed_out, n_removed_out, old_list[i]))
                return 0;
        }
    }
    return 1;
}

/* Bebaskan list klausa sementara (reuse untuk semua path). */
static void delta_free_lists(char **r0, int nr0, char **e0, int ne0,
                             char **r1, int nr1, char **e1, int ne1)
{
    int i;
    for (i = 0; i < nr0; i++) myc_free(r0[i]);
    for (i = 0; i < ne0; i++) myc_free(e0[i]);
    for (i = 0; i < nr1; i++) myc_free(r1[i]);
    for (i = 0; i < ne1; i++) myc_free(e1[i]);
    myc_free(r0); myc_free(e0); myc_free(r1); myc_free(e1);
}

int myc_contract_delta_compare(const char *before, size_t before_len,
                               const char *after, size_t after_len,
                               myc_contract_delta *out)
{
    char **r0 = NULL, **e0 = NULL;
    char **r1 = NULL, **e1 = NULL;
    int nr0 = 0, ne0 = 0, nr1 = 0, ne1 = 0;
    int ok;

    memset(out, 0, sizeof(*out));

    /* Ekstrak kontrak kedua versi (reuse myc_contract_list). */
    myc_contract_list(before, before_len, &r0, &nr0, &e0, &ne0);
    myc_contract_list(after, after_len, &r1, &nr1, &e1, &ne1);

    ok = delta_diff(r1, nr1, r0, nr0,
                    &out->added_requires, &out->n_added_requires,
                    &out->removed_requires, &out->n_removed_requires);
    if (!ok)
        goto fail;
    ok = delta_diff(e1, ne1, e0, ne0,
                    &out->added_ensures, &out->n_added_ensures,
                    &out->removed_ensures, &out->n_removed_ensures);
    if (!ok)
        goto fail;

    /* Klasifikasi (DS-08 lifecycle: narrowing = laundering). */
    if (out->n_added_requires > 0)
        out->kind = MYC_DELTA_NARROWED;
    else if (out->n_removed_ensures > 0)
        out->kind = MYC_DELTA_WEAKENED;
    else if (out->n_added_ensures > 0 || out->n_removed_requires > 0)
        out->kind = MYC_DELTA_CHANGED;
    else
        out->kind = MYC_DELTA_CLEAN;

    delta_free_lists(r0, nr0, e0, ne0, r1, nr1, e1, ne1);
    return 1;

fail:
    /* OOM saat menghitung delta: JANGAN diam-diam jadi CLEAN (gate bypass).
     * Bebaskan semuanya dan kembalikan 0 = error nyata; caller harus
     * menampilkan kegagalan, bukan menganggap kontrak sama. */
    myc_contract_delta_free(out);
    delta_free_lists(r0, nr0, e0, ne0, r1, nr1, e1, ne1);
    return 0;
}

void myc_contract_delta_free(myc_contract_delta *out)
{
    int i;
    if (!out)
        return;
    for (i = 0; i < out->n_added_requires; i++) myc_free(out->added_requires[i]);
    for (i = 0; i < out->n_removed_requires; i++) myc_free(out->removed_requires[i]);
    for (i = 0; i < out->n_added_ensures; i++) myc_free(out->added_ensures[i]);
    for (i = 0; i < out->n_removed_ensures; i++) myc_free(out->removed_ensures[i]);
    myc_free(out->added_requires);
    myc_free(out->removed_requires);
    myc_free(out->added_ensures);
    myc_free(out->removed_ensures);
    memset(out, 0, sizeof(*out));
}

int myc_contract_list(const char *source, size_t len,
                      char ***reqs, int *nreqs,
                      char ***ensures, int *nensures)
{
    size_t i = 0;
    size_t line = 1;
    size_t col = 1;
    int    in_block = 0;   /* komentar blok: klausa //@ di dalamnya DIABAIKAN */

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
        if (in_block) {
            if (c == '*' && i + 1 < len && source[i + 1] == '/') {
                in_block = 0;
                i += 2;
                col += 2;
            } else {
                i++;
                col++;
            }
            continue;
        }
        /* Masuk komentar blok? */
        if (c == '/' && i + 1 < len && source[i + 1] == '*') {
            in_block = 1;
            i += 2;
            col += 2;
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
        myc_free(out.data);
        /* Jangan sentuh *out_len: return NULL berarti caller memakai
         * source asli dengan panjang aslinya. */
        return NULL;
    }
    if (out_len)
        *out_len = out.len;
    return out.data ? out.data : NULL;
}

/* ---------------------------------------------------------------- */
/* B4: Comments-as-Contracts (DS-08) -- panen kandidat kontrak       */
/* dari komentar biasa (bukan //@). NON-blocking, observasi murni.   */
/* ---------------------------------------------------------------- */

#define MYC_HARVEST_MAX_CAND 32    /* batas kandidat per source */
#define MYC_HARVEST_EXPR_LEN 192    /* ekspresi kandidat */
#define MYC_HARVEST_WORD_LEN 64     /* identifier/angka yang diekstrak */

/* Satu kandidat ter-harvest (internal). */
typedef struct {
    int    line;            /* baris komentar (1-based) */
    int    kind;            /* 0 = requires, 1 = ensures */
    char   expr[MYC_HARVEST_EXPR_LEN];   /* ekspresi C kandidat */
    char   func[64];        /* binding stabil ("" bila tak terikat) */
    int    valid;           /* 1 = ekspresi C murni (tervalidasi) */
    int    bound;           /* 1 = terikat fungsi berikutnya */
} myc_harvest_cand;

/* Salin s[0..len) ke buf sebagai huruf kecil (len diclamp ke cap-1). */
static size_t lower_copy(const char *s, size_t len, char *buf, size_t cap)
{
    size_t n = len < cap - 1 ? len : cap - 1;
    size_t i;
    for (i = 0; i < n; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
        buf[i] = c;
    }
    buf[n] = '\0';
    return n;
}

/* Cari substring pertama needle di hay (keduanya lowercase). */
static const char *find_sub_lc(const char *hay, const char *needle)
{
    const char *p = hay;
    size_t nlen = strlen(needle);
    while (*p) {
        if (strncmp(p, needle, nlen) == 0)
            return p;
        p++;
    }
    return NULL;
}

/* Ambil kata (identifier/angka) yang berakhir tepat sebelum posisi `end`
 * di s[0..end] (lewati spasi). Kosongkan bila bukan kata utuh. */
static void word_before(const char *s, size_t end, char *out, size_t cap)
{
    size_t a, b;
    if (cap == 0) {
        if (cap) out[0] = '\0';
        return;
    }
    b = end;
    while (b > 0 && (s[b - 1] == ' ' || s[b - 1] == '\t'))
        b--;
    a = b;
    while (a > 0 && is_ident_char((unsigned char)s[a - 1]))
        a--;
    if (a == b) {                       /* tidak ada kata */
        out[0] = '\0';
        return;
    }
    if (b - a >= cap)
        a = b - (cap - 1);
    memcpy(out, s + a, b - a);
    out[b - a] = '\0';
}

/* Ambil kata (identifier/angka) yang dimulai tepat setelah posisi `from`
 * (lewati spasi) di s. Kosongkan bila tidak ada. */
static void word_after(const char *s, size_t len, size_t from,
                       char *out, size_t cap)
{
    size_t i, a, b;
    i = from;
    while (i < len && (s[i] == ' ' || s[i] == '\t'))
        i++;
    a = i;
    while (i < len && is_ident_char((unsigned char)s[i]))
        i++;
    b = i;
    if (a == b || b - a >= cap) {
        out[0] = '\0';
        return;
    }
    memcpy(out, s + a, b - a);
    out[b - a] = '\0';
}

/* Apakah ekspresi mengandung operator C (syarat "terlihat seperti C",
 * bukan kata-kata bahasa alami seperti "number of X")? */
static int expr_has_operator(const char *e)
{
    size_t i;
    for (i = 0; e[i]; i++) {
        /* '->' (akses member) bukan operator kontrak */
        if (e[i] == '-' && e[i + 1] == '>') {
            i++;
            continue;
        }
        switch (e[i]) {
        case '<': case '>': case '=': case '!':
        case '&': case '|': case '+': case '-':
        case '*': case '/': case '%': case '?':
            return 1;
        default:
            break;
        }
    }
    return 0;
}

/* Ekstrak satu kandidat dari sebaris komentar (teks asli s, panjang len,
 * SEMUA LOWERCASE di lc). Pola deterministik B4. Mengisi out->expr /
 * out->kind. Return 1 bila pola cocok. */
static int harvest_extract(const char *s, size_t len, const char *lc,
                           myc_harvest_cand *out)
{
    const char *hit;
    char   x[MYC_HARVEST_WORD_LEN];
    char   y[MYC_HARVEST_WORD_LEN];

    /* --- komparasi langsung: SELURUH baris = "X op Y" ---
     * Rekonstruksi "X op Y" dan bandingkan dengan baris (case-insensitive)
     * agar pola "n must be <= 64" TIDAK salah tangkap jadi "be <= 64". */
    {
        char cmp[MYC_HARVEST_EXPR_LEN];
        char recon[MYC_HARVEST_EXPR_LEN];
        char rec_lc[MYC_HARVEST_EXPR_LEN];
        size_t clen = lower_copy(s, len, cmp, sizeof(cmp));
        const char *op = NULL;
        const char *opstr = NULL;
        static const char *const ops[] = {
            "<=", ">=", "==", "!=", "<", ">"
        };
        size_t k;
        size_t left, right, oplen;
        (void)clen;
        for (k = 0; k < 6; k++) {
            const char *f = find_sub_lc(cmp, ops[k]);
            if (f && (!op || f < op)) {
                op = f;
                opstr = ops[k];
            }
        }
        if (!op)
            goto not_direct;
        /* op harus di awal atau didahului spasi/tab */
        if (op != cmp && op[-1] != ' ' && op[-1] != '\t')
            goto not_direct;
        oplen = (op[1] == '=' || (op[0] == '!' && op[1] == '=')
                 || op[0] == '=') ? 2 : 1;
        left = (size_t)(op - cmp);
        right = left + oplen;
        {
            char x2[MYC_HARVEST_WORD_LEN], y2[MYC_HARVEST_WORD_LEN];
            word_before(s, left, x2, sizeof(x2));
            word_after(s, len, right, y2, sizeof(y2));
            if (!x2[0] || !y2[0])
                goto not_direct;
            snprintf(recon, sizeof(recon), "%s %s %s", x2, opstr, y2);
            lower_copy(recon, strlen(recon), rec_lc, sizeof(rec_lc));
            if (strcmp(rec_lc, cmp) == 0) {
                snprintf(out->expr, sizeof(out->expr), "%s", recon);
                out->kind = 0;
                return 1;
            }
        }
    }
not_direct:

    /* --- "X must not exceed Y" -> X <= Y --- */
    hit = find_sub_lc(lc, "must not exceed");
    if (hit) {
        size_t xoff = (size_t)(hit - lc);
        word_before(s, xoff, x, sizeof(x));
        word_after(s, len, xoff + strlen("must not exceed"), y, sizeof(y));
        if (x[0] && y[0]) {
            snprintf(out->expr, sizeof(out->expr), "%s <= %s", x, y);
            out->kind = 0;
            return 1;
        }
    }

    /* --- "X must be <op> Y" -> X <op> Y --- */
    hit = find_sub_lc(lc, "must be");
    if (hit) {
        static const char *const ops[] = {
            "<=", ">=", "<", ">", "==", "!="
        };
        size_t k;
        size_t after = (size_t)(hit - lc) + strlen("must be");
        /* lewati spasi setelah "must be" sebelum operator */
        while (after < len && (lc[after] == ' ' || lc[after] == '\t'))
            after++;
        for (k = 0; k < 6; k++) {
            size_t klen = strlen(ops[k]);
            if (strncmp(lc + after, ops[k], klen) == 0 &&
                (lc[after + klen] == ' ' || lc[after + klen] == '\t' ||
                 lc[after + klen] == '\0')) {
                size_t xoff = (size_t)(hit - lc);
                word_before(s, xoff, x, sizeof(x));
                word_after(s, len, after + klen, y, sizeof(y));
                if (x[0] && y[0]) {
                    snprintf(out->expr, sizeof(out->expr), "%s %s %s",
                             x, ops[k], y);
                    out->kind = 0;
                    return 1;
                }
            }
        }
    }

    /* --- keyword ensures dengan ekspresi sisa --- */
    {
        static const char *const ensures_kws[] = {
            "postcondition:", "post:", "returns", "return", NULL
        };
        size_t ki;
        for (ki = 0; ensures_kws[ki]; ki++) {
            size_t klen = strlen(ensures_kws[ki]);
            hit = find_sub_lc(lc, ensures_kws[ki]);
            if (hit && (hit == lc || hit[-1] == ' ' || hit[-1] == '\t')) {
                size_t j = (size_t)(hit - lc) + klen;
                size_t a = j, b = len;
                while (a < b && (s[a] == ' ' || s[a] == '\t'))
                    a++;
                while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t'))
                    b--;
                if (b - a > 0 && b - a < sizeof(out->expr)) {
                    memcpy(out->expr, s + a, b - a);
                    out->expr[b - a] = '\0';
                    out->kind = 1;
                    return 1;
                }
            }
        }
    }

    /* --- keyword requires dengan ekspresi sisa --- */
    {
        static const char *const requires_kws[] = {
            "precondition:", "pre:", "assumes", "requires", NULL
        };
        size_t ki;
        for (ki = 0; requires_kws[ki]; ki++) {
            size_t klen = strlen(requires_kws[ki]);
            hit = find_sub_lc(lc, requires_kws[ki]);
            if (hit && (hit == lc || hit[-1] == ' ' || hit[-1] == '\t')) {
                size_t j = (size_t)(hit - lc) + klen;
                size_t a = j, b = len;
                while (a < b && (s[a] == ' ' || s[a] == '\t'))
                    a++;
                while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t'))
                    b--;
                if (b - a > 0 && b - a < sizeof(out->expr)) {
                    memcpy(out->expr, s + a, b - a);
                    out->expr[b - a] = '\0';
                    out->kind = 0;
                    return 1;
                }
            }
        }
    }

    return 0;
}

/* Proses satu region komentar [start,end) (baris // atau blok slash-star).
 * Binding semua kandidat dicari dari `bind_from` (ujung region komentar). */
static void harvest_region(const char *source, size_t len,
                           size_t start, size_t end, size_t bind_from,
                           myc_harvest_cand *cands,
                           int *ncand, size_t *line_no)
{
    size_t i = start;
    size_t line = *line_no;
    while (i < end) {
        size_t le = i;
        while (le < end && source[le] != '\n')
            le++;
        {
            size_t a = i, b = le;
            while (a < b && (source[a] == ' ' || source[a] == '\t'))
                a++;
            if (b - a > 2 && source[a] == '/' && source[a + 1] == '*') {
                a += 2;                     /* buang pembuka komentar blok */
                while (b > a && source[a] == '*')
                    a++;                     /* gaya blok: leading '*', baru */
                while (b > a && (source[b - 1] == ' ' || source[b - 1] == '\t'
                                 || source[b - 1] == '*' ||
                                 source[b - 1] == '/'))
                    b--;                     /* buang penutup komentar blok */
            }
            if (b - a > 0) {
                char lc[MYC_HARVEST_EXPR_LEN];
                size_t tlen = b - a;
                if (tlen >= sizeof(lc))
                    tlen = sizeof(lc) - 1;
                lower_copy(source + a, tlen, lc, sizeof(lc));
                if (*ncand < MYC_HARVEST_MAX_CAND) {
                    myc_harvest_cand *c = &cands[*ncand];
                    memset(c, 0, sizeof(*c));
                    c->line = (int)line;
                    if (harvest_extract(source + a, tlen, lc, c)) {
                        /* validasi: purity + operator + binding */
                        if (contract_expr_purity(c->expr) == MYC_CLAUSE_OK &&
                            expr_has_operator(c->expr)) {
                            size_t brace;
                            c->valid = 1;
                            c->func[0] = '\0';
                            if (find_func_binding(source, len, bind_from,
                                                  c->func, sizeof(c->func),
                                                  &brace))
                                c->bound = 1;
                        }
                        (*ncand)++;
                    }
                }
            }
        }
        if (le < end && source[le] == '\n')
            line++;
        i = le + (source[le] == '\n' ? 1 : 0);
    }
    *line_no = line;
}

int myc_contract_harvest(const char *source, size_t len, myc_result *res)
{
    myc_harvest_cand cands[MYC_HARVEST_MAX_CAND];
    int  ncand = 0;
    int  i;
    size_t pos = 0;
    size_t line = 1;

    res->harvest_candidates = 0;
    res->harvest_validated = 0;
    res->harvest_unbound = 0;
    res->harvest_report = NULL;

    while (pos < len) {
        char c = source[pos];
        if (c == '\n') {
            line++;
            pos++;
            continue;
        }
        if (c == '/' && pos + 1 < len && source[pos + 1] == '/') {
            size_t le = pos;
            while (le < len && source[le] != '\n')
                le++;
            harvest_region(source, len, pos, le, le, cands, &ncand,
                           &line);
            pos = le;
            continue;
        }
        if (c == '/' && pos + 1 < len && source[pos + 1] == '*') {
            size_t end = pos + 2;
            size_t le;
            while (end + 1 < len &&
                   !(source[end] == '*' && source[end + 1] == '/'))
                end++;
            le = end + 2;
            if (le > len)
                le = len;
            harvest_region(source, len, pos, le, le, cands, &ncand,
                           &line);
            pos = le;
            continue;
        }
        pos++;
    }

    if (ncand == 0)
        return 1;

    /* agregasi + laporan */
    for (i = 0; i < ncand; i++) {
        const myc_harvest_cand *c = &cands[i];
        res->harvest_candidates++;
        if (c->valid && c->bound)
            res->harvest_validated++;
        else if (c->valid)
            res->harvest_unbound++;
    }
    {
        buf rep;
        char linebuf[MYC_HARVEST_EXPR_LEN + 96];
        memset(&rep, 0, sizeof(rep));
        buf_puts(&rep, "harvest (B4): kandidat kontrak dari komentar biasa\n");
        for (i = 0; i < ncand; i++) {
            const myc_harvest_cand *c = &cands[i];
            const char *status = "perlu //@ syntax (bukan C murni)";
            if (c->valid && c->bound)
                status = "validated (pure + terikat fungsi)";
            else if (c->valid)
                status = "validated (pure, TAK terikat fungsi)";
            snprintf(linebuf, sizeof(linebuf),
                     "  [line %d] %s %s: `%s` -- %s\n",
                     c->line, c->kind == 0 ? "requires" : "ensures",
                     c->func[0] ? c->func : "(unbound)", c->expr, status);
            buf_puts(&rep, linebuf);
        }
        buf_puts(&rep,
                 "  (harvest = observasi; tulis //@ requires/ensures agar "
                 "dipromosikan ke kontrak nyata)\n");
        if (rep.data) {
            res->harvest_report = myc_result_arena_dup(res, rep.data, 0);
            myc_free(rep.data);
        }
    }
    return 1;
}

/* ---------------------------------------------------------------- */
/* Fase 5: Relational contracts -- klasifikasi klausa kontrak       */
/* ---------------------------------------------------------------- */

/* Keyword/konstanta/tipe C yang BUKAN variabel kontrak. */
static int rel_is_constant(const char *w)
{
    static const char *const c[] = {
        "NULL", "true", "false", "sizeof",
        "if", "else", "while", "for", "return", "switch", "case",
        "do", "goto", "break", "continue",
        "int", "char", "void", "long", "short", "unsigned", "signed",
        "float", "double", "const", "volatile", "static", "extern",
        "struct", "union", "enum", "typedef", "register", "inline",
        "size_t", "ssize_t", "bool", "_Bool",
        "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t",
        "int64_t", "uint64_t", "intptr_t", "uintptr_t", "intmax_t",
        "uintmax_t", "ptrdiff_t", "wchar_t", "char16_t", "char32_t",
        "int_fast8_t", "uint_fast8_t", "int_least8_t", "uint_least8_t",
        NULL
    };
    int i;
    for (i = 0; c[i]; i++)
        if (strcmp(w, c[i]) == 0)
            return 1;
    return 0;
}

/* Alias return yang dianggap terikat (bukan unbound). */
static int rel_is_return_alias(const char *w)
{
    static const char *const a[] = { "r", "ret", "result", "res", NULL };
    int i;
    for (i = 0; a[i]; i++)
        if (strcmp(w, a[i]) == 0)
            return 1;
    return 0;
}

/* Tambah variabel (dedupe); jangan overflow. */
static void rel_add_var(char vars[][64], int *n, int max, const char *w)
{
    int i;
    for (i = 0; i < *n; i++)
        if (strcmp(vars[i], w) == 0)
            return;
    if (*n < max) {
        snprintf(vars[*n], 64, "%s", w);
        (*n)++;
    }
}

/* Tokenisasi ekspresi kontrak: kumpulkan identifier DISTINCT (bukan
 * konstanta/keyword/literal/pemanggilan fungsi/anggota struct),
 * deteksi operator order/equality/arith/logic. */
static int rel_extract_vars(const char *e,
                            char vars[][64], int maxvars,
                            int *has_order, int *has_equality,
                            int *has_arith, int *has_logic)
{
    size_t i = 0, len = strlen(e);
    int n = 0;
    *has_order = *has_equality = *has_arith = *has_logic = 0;
    while (i < len) {
        char c = e[i];
        if (c == '"' || c == '\'') {
            i = skip_literal(e, len, i);
            continue;
        }
        if (c == '/' && i + 1 < len && e[i + 1] == '/') {
            while (i < len && e[i] != '\n') i++;
            continue;
        }
        if (c == '/' && i + 1 < len && e[i + 1] == '*') {
            i += 2;
            while (i + 1 < len && !(e[i] == '*' && e[i + 1] == '/')) i++;
            i += 2;
            continue;
        }
        /* ACSL escape: \result -> alias return; \old/\at/\true/\false/
         * \nothing = konstanta/kata kunci (skip). */
        if (c == '\\') {
            char w[64];
            size_t wl = 0;
            i++;
            while (i < len && wl + 1 < sizeof(w) &&
                   is_ident_char((unsigned char)e[i]))
                w[wl++] = e[i++];
            w[wl] = '\0';
            if (strcmp(w, "result") == 0)
                rel_add_var(vars, &n, maxvars, "result");
            continue;
        }
        /* akses member p->size / p -> size / p.size: nama member BUKAN
         * variabel kontrak (pola `- >` terpisah juga ditangani; bila
         * tidak ada identifier setelahnya, `-` dianggap aritmetika). */
        if (c == '-') {
            size_t s2 = i + 1;
            while (s2 < len && (e[s2] == ' ' || e[s2] == '\t')) s2++;
            if (s2 < len && e[s2] == '>') {
                size_t m2 = s2 + 1;
                while (m2 < len && (e[m2] == ' ' || e[m2] == '\t')) m2++;
                if (m2 < len && is_ident_start((unsigned char)e[m2])) {
                    i = m2 + 1;
                    while (i < len && is_ident_char((unsigned char)e[i])) i++;
                    continue;
                }
            }
            /* fall through ke aritmetika di bawah */
        } else if (c == '.') {
            size_t m2 = i + 1;
            while (m2 < len && (e[m2] == ' ' || e[m2] == '\t')) m2++;
            if (m2 < len && is_ident_start((unsigned char)e[m2])) {
                i = m2 + 1;
                while (i < len && is_ident_char((unsigned char)e[i])) i++;
                continue;
            }
            i++;
            continue;
        }
        if (c == '<' || c == '>') {
            *has_order = 1;
            i++;
            if (i < len && e[i] == '=') i++;
            continue;
        }
        if (c == '=' || c == '!') {
            if (i + 1 < len && e[i + 1] == '=') {
                *has_equality = 1;
                i += 2;
                continue;
            }
            if (c == '!')
                *has_logic = 1;
            i++;
            continue;
        }
        if (c == '+' || c == '-' || c == '*' || c == '/' || c == '%') {
            if (c == '+' && i + 1 < len && e[i + 1] == '+') { i += 2; continue; }
            if (c == '-' && i + 1 < len && e[i + 1] == '-') { i += 2; continue; }
            *has_arith = 1;
            i++;
            continue;
        }
        if (c == '&' || c == '|') {
            if (i + 1 < len && e[i + 1] == c) {
                *has_logic = 1;
                i += 2;
                continue;
            }
            i++;
            continue;
        }
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
                i = j;      /* pemanggilan fungsi: nama = call, bukan var */
                continue;
            }
            if (!rel_is_constant(w))
                rel_add_var(vars, &n, maxvars, w);
            i = j;
            continue;
        }
        i++;
    }
    return n;
}

/* Cache parameter per fungsi (hindari scan ulang per klausa). */
typedef struct {
    char name[64];
    int  nparams;
    char params[24][64];
    int  resolved;   /* 1 = sudah dicoba di-resolve (nparams 0 = gagal) */
} rel_func_params;
/* Cap fungsi ber-kontrak yang parameter-nya di-resolve: fungsi ke-17+
 * melewati binding check (degradasi senyap ke "tak ada unbound" -- aman,
 * tidak pernah menimbulkan unbound palsu). */
#define MYC_REL_MAX_FUNCS 16

/* Ekstrak nama parameter dari DEFINISI fungsi `<func>(...){` (prototype
 * `;` diterima sebagai fallback). Return jumlah param. */
static int rel_extract_params(const char *s, size_t len, const char *func,
                              char out[][64], int max)
{
    size_t i = 0, flen = strlen(func);
    int    fallback = 0;   /* 1 = punya prototype (param sama) */
    char   fb[24][64];
    int    nfb = 0;
    while (i + flen <= len) {
        if ((i == 0 || !is_ident_char((unsigned char)s[i - 1])) &&
            strncmp(s + i, func, flen) == 0 &&
            (i + flen >= len ||
             !is_ident_char((unsigned char)s[i + flen]))) {
            size_t j = i + flen;
            j = skip_ws_comment(s, len, j);
            if (j < len && s[j] == '(') {
                size_t k = j + 1;
                int    depth = 1;
                int    n2 = 0;
                while (k < len && depth > 0) {
                    char cc = s[k];
                    if (cc == '"' || cc == '\'') {
                        k = skip_literal(s, len, k);
                        continue;
                    }
                    if (cc == '/' && k + 1 < len && s[k + 1] == '/') {
                        while (k < len && s[k] != '\n') k++;
                        continue;
                    }
                    if (cc == '/' && k + 1 < len && s[k + 1] == '*') {
                        k += 2;
                        while (k + 1 < len &&
                               !(s[k] == '*' && s[k + 1] == '/')) k++;
                        k += 2;
                        continue;
                    }
                    if (cc == '(') depth++;
                    else if (cc == ')') {
                        depth--;
                        if (depth == 0) { k++; break; }
                    } else if (cc == '{') {
                        depth = 0;   /* struct body: berhenti */
                        break;
                    } else if (cc == ',' || cc == ' ' || cc == '\t' ||
                               cc == '\n' || cc == '\r' || cc == '*' ||
                               cc == '[' || cc == ']') {
                        k++;
                        continue;
                    } else if (is_ident_start((unsigned char)cc)) {
                        /* identifier di depth 1 = calon nama param */
                        size_t wl = 0;
                        char   w[64];
                        while (k < len && wl + 1 < sizeof(w) &&
                               is_ident_char((unsigned char)s[k]))
                            w[wl++] = s[k++];
                        w[wl] = '\0';
                        if (depth == 1 && wl > 0 &&
                            !rel_is_constant(w) && n2 < max) {
                            snprintf(out[n2], 64, "%s", w);
                            n2++;
                        }
                        continue;
                    }
                    k++;
                }
                {
                    size_t m = skip_ws_comment(s, len, k);
                    if (m < len && s[m] == '{') {
                        return n2;   /* definisi ditemukan */
                    }
                    if (m < len && s[m] == ';' && !fallback) {
                        fallback = 1;
                        nfb = 0;
                        while (nfb < n2 && nfb < 24) {
                            /* 64-byte ke 64-byte: aman tanpa warning
                             * -Wformat-truncation (false positive gcc). */
                            memcpy(fb[nfb], out[nfb], 64);
                            nfb++;
                        }
                    }
                }
            }
        }
        i++;
    }
    if (fallback && nfb > 0) {
        int q;
        for (q = 0; q < nfb && q < max; q++)
            memcpy(out[q], fb[q], 64);   /* 64-byte ke 64-byte */
        return nfb;
    }
    return 0;
}

/* Klasifikasi relasional klausa yang sudah di-scan ke res->contract_clauses
 * (panggil SETELAH myc_contract_scan). NON-blocking observasi murni. */
int myc_contract_relational(const char *source, size_t len, myc_result *res)
{
    int i;
    rel_func_params funcs[MYC_REL_MAX_FUNCS];
    int nfuncs = 0;
    buf rep;
    char linebuf[768];   /* >= 511 (expr) + 63 (func) + format */

    res->rel_analyzed = 0;
    res->rel_relations = 0;
    res->rel_unary = 0;
    res->rel_unbound = 0;
    res->rel_report = NULL;
    res->rel_clause_count = 0;

    if (res->contract_clause_count == 0)
        return 1;

    memset(funcs, 0, sizeof(funcs));
    memset(&rep, 0, sizeof(rep));
    buf_puts(&rep, "relational (Fase 5): klasifikasi klausa kontrak "
                   "(observasi, NON-blocking)\n");

    for (i = 0; i < res->contract_clause_count; i++) {
        const myc_contract_clause *cl = &res->contract_clauses[i];
        myc_rel_clause *rc;
        /* Cap 8 variabel/klausa: klausa >8 var -> nvars undercount + unbound
         * hanya memeriksa 8 pertama (false negative ARAH AMAN: tidak pernah
         * menghasilkan unbound palsu). */
        char vars[8][64];
        int  nvars, has_order = 0, has_eq = 0, has_arith = 0, has_logic = 0;
        int  k, v, q, unbound = 0;
        const char *fname = cl->func ? cl->func : "";

        if (!cl->expr || cl->expr[0] == '\0')
            continue;
        if (res->rel_clause_count >= MYC_MAX_REL_CLAUSES)
            break;

        nvars = rel_extract_vars(cl->expr, vars, 8,
                                 &has_order, &has_eq, &has_arith,
                                 &has_logic);

        /* binding check: identifier harus ada di param fungsi atau alias
         * return; selain itu = unbound (typo / global tak terdeklarasi). */
        if (fname[0]) {
            int fi = -1;
            for (k = 0; k < nfuncs; k++)
                if (strcmp(funcs[k].name, fname) == 0) { fi = k; break; }
            if (fi < 0 && nfuncs < MYC_REL_MAX_FUNCS) {
                fi = nfuncs;
                snprintf(funcs[fi].name, 64, "%s", fname);
                funcs[fi].nparams = rel_extract_params(source, len, fname,
                                                       funcs[fi].params, 24);
                funcs[fi].resolved = 1;
                nfuncs++;
            }
            if (fi >= 0 && funcs[fi].resolved && funcs[fi].nparams > 0) {
                for (v = 0; v < nvars && !unbound; v++) {
                    int found = 0;
                    if (rel_is_return_alias(vars[v]))
                        continue;
                    for (q = 0; q < funcs[fi].nparams; q++)
                        if (strcmp(funcs[fi].params[q], vars[v]) == 0) {
                            found = 1;
                            break;
                        }
                    if (!found)
                        unbound = 1;
                }
            }
        }

        rc = &res->rel_clauses[res->rel_clause_count];
        memset(rc, 0, sizeof(*rc));
        rc->expr = cl->expr;
        rc->func = cl->func;
        rc->kind = cl->kind;
        rc->line = cl->line;
        rc->col = cl->col;
        rc->nvars = nvars;
        rc->relational = (nvars >= 2);
        rc->unbound = unbound;
        rc->has_order = has_order;
        rc->has_equality = has_eq;
        rc->has_arith = has_arith;
        rc->has_logic = has_logic;

        res->rel_analyzed++;
        if (rc->relational)
            res->rel_relations++;
        else if (nvars == 1)
            res->rel_unary++;
        if (unbound)
            res->rel_unbound++;

        snprintf(linebuf, sizeof(linebuf),
                 "  [%s:%d] %-8s `%s` -- %s%s (vars=%d)%s\n",
                 fname[0] ? fname : "(unbound)", rc->line,
                 rc->kind == 0 ? "requires" : "ensures",
                 cl->expr,
                 rc->relational ? "RELATIONAL" : (nvars == 0
                     ? "CONSTANT" : "UNARY"),
                 (has_order || has_eq || has_arith || has_logic) ? " " : "",
                 nvars,
                 unbound ? " [UNBOUND: identifier di luar param/return]" : "");
        buf_puts(&rep, linebuf);
        res->rel_clause_count++;
    }

    snprintf(linebuf, sizeof(linebuf),
             "  ringkasan: %d klausa dianalisis, %d unary, %d relational "
             "(>=2 variabel), %d unbound\n",
             res->rel_analyzed, res->rel_unary, res->rel_relations,
             res->rel_unbound);
    buf_puts(&rep, linebuf);
    buf_puts(&rep, "  (relational = observasi; periksa klausa unbound: "
                   "typo atau global tak terdeklarasi)\n");
    if (rep.data) {
        res->rel_report = myc_result_arena_dup(res, rep.data, 0);
        myc_free(rep.data);
    }
    return 1;
}

