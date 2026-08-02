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
 *      (D3.1, L2 PROVEN) nanti.
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
 * Menulis ke out (truncate bila terlalu panjang), *endpos = posisi setelah
 * ';' (bila ada). Mengembalikan 1 bila non-kosong. */
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
        t = outcap - 1;
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
    res->diag_count++;
}

/* ---------------------------------------------------------------- */
/* Scan & validasi kontrak                                          */
/* ---------------------------------------------------------------- */

int myc_contract_scan(const char *source, size_t len, myc_result *res)
{
    size_t i = 0;
    size_t line = 1;
    size_t col = 1;
    res->contract_requires = 0;
    res->contract_ensures = 0;

    while (i < len) {
        char c = source[i];
        if (c == '\n') {
            line++;
            col = 1;
            i++;
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
                if (strcmp(kw, "requires") == 0) {
                    char   expr[512];
                    size_t endp;
                    if (read_contract_expr(source, kwend, line_end, expr,
                                           sizeof(expr), &endp)) {
                        res->contract_requires++;
                    } else {
                        add_contract_diag(res, (int)line,
                                          (int)(start_col + (j - i)),
                                          "kontrak requires dengan ekspresi kosong");
                    }
                } else if (strcmp(kw, "ensures") == 0) {
                    char   expr[512];
                    size_t endp;
                    if (read_contract_expr(source, kwend, line_end, expr,
                                           sizeof(expr), &endp)) {
                        res->contract_ensures++;
                    } else {
                        add_contract_diag(res, (int)line,
                                          (int)(start_col + (j - i)),
                                          "kontrak ensures dengan ekspresi kosong");
                    }
                }
            }
            /* lewati baris komentar */
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
/* List kontrak sebagai string ekspresi (tool MCP `contracts`, P9)    */
/* ---------------------------------------------------------------- */

/* Tambah string malloc'd ke array dinamis; return 1 sukses. */
static int collect_expr(char ***out, int *n, const char *expr)
{
    char **na;
    char  *s = _strdup(expr);
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
                    if (read_contract_expr(source, kwend, line_end, expr,
                                           sizeof(expr), &endp)) {
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

char *myc_contract_inject(const char *source, size_t len, size_t *out_len)
{
    buf    out;
    size_t i = 0;
    size_t depth = 0;
    int    sig_closed = 0;   /* ')' penutup tanda tangan fungsi baru saja */
    int    has_pending = 0;
    char   pending[512];
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
            /* parse kontrak */
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
                    if (read_contract_expr(source, kwend, line_end, expr,
                                           sizeof(expr), &endp)) {
                        strncpy(pending, expr, sizeof(pending) - 1);
                        pending[sizeof(pending) - 1] = '\0';
                        has_pending = 1;
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

        /* token penanda struktur */
        if (c == '(') {
            depth++;
        } else if (c == ')') {
            if (depth > 0)
                depth--;
            if (depth == 0)
                sig_closed = 1;
        } else if (c == '{') {
            if (depth == 0 && has_pending && sig_closed) {
                /* sisipkan assert setelah pembuka fungsi */
                snprintf(assert_line, sizeof(assert_line),
                         "{\n    assert(%s);\n", pending);
                buf_puts(&out, assert_line);
                injected_any = 1;
                has_pending = 0;
                sig_closed = 0;
                i++;
                continue;
            }
        } else if (c == '}') {
            if (depth == 0) {
                sig_closed = 0;
                has_pending = 0;
            }
        } else if (c == ';') {
            if (depth == 0) {
                sig_closed = 0;
                /* kontrak yang tidak segera diikuti '{' fungsi: reset */
                has_pending = 0;
            }
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
