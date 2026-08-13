/*
 * abi.c -- ABI/FFI Surface Certificate (Fase 5, SOL-14).
 *
 * Scanner TEKS deterministik (bukan AST), NON-blocking observasi:
 * verdict TIDAK pernah turun karena analisis ini. Kegagalan (compiler
 * tak ditemukan, helper gagal compile) -> abi_ran = 0 + laporan.
 *
 * Snapshot per baris ("# myc abi v1"):
 *   TARGET <triple>                     (gcc -dumpmachine)
 *   HEADER <sha256-hex>                 (digest source; diabaikan delta)
 *   SYMBOL <ret> <name>(<params>)       (fungsi global non-static)
 *   STRUCT <name> size=<n> align=<n>    (sizeof/_Alignof)
 *   MEMBER <name> <member> off=<n>      (offsetof; bitfield dilewati)
 *   ENUM <enum> <enumerator>=<value>    (nilai dihitung compiler)
 *
 * Helper program di-generate dari deklarasi verbatim (bounded), di-compile
 * dengan compiler host, dijalankan; stdout di-parse. Semua buffer stack
 * bounded; tidak ada static mutable global.
 */
#include "abi.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proc.h"
#include "sha256.h"

/* --- helper platform portabel (pola driver.c) --- */
#ifdef _WIN32
#include <direct.h>
#include <process.h>
#define a_mkdir(path)  _mkdir(path)
#define a_rmdir(path)  _rmdir(path)
#define a_getpid()     _getpid()
#define a_getcwd(b, s) _getcwd(b, s)
#define ABI_EXE_SUFFIX ".exe"
#else
#include <sys/stat.h>
#include <unistd.h>
#define a_mkdir(path)  mkdir(path, 0700)
#define a_rmdir(path)  rmdir(path)
#define a_getpid()     getpid()
#define a_getcwd(b, s) getcwd(b, s)
#define ABI_EXE_SUFFIX ""
#endif

/* ---------------------------------------------------------------- */
/* Buffer dinamis kecil (pola state.c/contract.c)                   */
/* ---------------------------------------------------------------- */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} abuf;

static void abuf_putc(abuf *b, char c)
{
    if (b->len + 2 > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 8192;
        char  *nd = (char *)myc_realloc(b->data, ncap);
        if (!nd)
            return;
        b->data = nd;
        b->cap = ncap;
    }
    b->data[b->len++] = c;
    b->data[b->len] = '\0';
}

static void abuf_puts(abuf *b, const char *s)
{
    if (!s)
        return;
    while (*s)
        abuf_putc(b, *s++);
}

static void abuf_printf(abuf *b, const char *fmt, ...)
{
    char   tmp[512];
    va_list ap;
    int    n;
    size_t i;
    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    for (i = 0; i < (size_t)n && i < sizeof(tmp) - 1; i++)
        abuf_putc(b, tmp[i]);
}

static void abuf_free(abuf *b)
{
    myc_free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

/* ---------------------------------------------------------------- */
/* Lexical helpers                                                  */
/* ---------------------------------------------------------------- */

static int a_is_ident_start(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int a_is_ident(char c)
{
    return a_is_ident_start(c) || (c >= '0' && c <= '9');
}

static int a_is_ws(char c)
{
    /* \r\n: source Windows (CRLF) harus dianggap whitespace agar scan
     * teks konsisten lintas platform. */
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* Kata kunci yang bukan nama fungsi. */
static int a_is_keyword(const char *w)
{
    static const char *const KW[] = {
        "if", "for", "while", "switch", "return", "sizeof", "alignof",
        "else", "typedef", "struct", "union", "enum", "_Alignof", NULL
    };
    int i;
    for (i = 0; KW[i]; i++)
        if (strcmp(w, KW[i]) == 0)
            return 1;
    return 0;
}

/* Index '}' penyeimbang '{' di posisi open (harus '{'); -1 bila tak ada. */
static size_t a_match_brace(const char *s, size_t len, size_t open)
{
    int    depth = 0;
    size_t i;
    for (i = open; i < len; i++) {
        if (s[i] == '{')
            depth++;
        else if (s[i] == '}') {
            depth--;
            if (depth == 0)
                return i;
        }
    }
    return (size_t)-1;
}

/* Mask komentar: 1 = posisi berada di dalam komentar blok (bintang
 * miring) atau komentar baris (dua garis miring). Scanner teks melewati
 * komentar agar deklarasi ABI tidak salah terdeteksi dari komentar
 * (mis. teks "(dua run sama)" di dalam komentar). Hasil malloc'd
 * (caller free); NULL bila OOM (scan tetap aman). */
static unsigned char *a_comment_mask(const char *s, size_t len)
{
    unsigned char *m = (unsigned char *)myc_malloc(len ? len : 1);
    size_t         i = 0;
    if (!m)
        return NULL;
    memset(m, 0, len);
    while (i < len) {
        if (s[i] == '/' && i + 1 < len && s[i + 1] == '*') {
            m[i] = m[i + 1] = 1;
            i += 2;
            while (i < len && !(s[i] == '*' && i + 1 < len &&
                                s[i + 1] == '/')) {
                m[i] = 1;
                i++;
            }
            if (i + 1 < len) {
                m[i] = m[i + 1] = 1;
                i += 2;
            }
        } else if (s[i] == '/' && i + 1 < len && s[i + 1] == '/') {
            m[i] = m[i + 1] = 1;
            i += 2;
            while (i < len && s[i] != '\n') {
                m[i] = 1;
                i++;
            }
        } else {
            i++;
        }
    }
    return m;
}

/* Index ')' penyeimbang '(' di posisi open; -1 bila tak ada / > cap. */
static size_t a_match_paren(const char *s, size_t len, size_t open,
                            size_t cap)
{
    int    depth = 0;
    size_t i;
    size_t limit = open + cap;
    if (limit > len)
        limit = len;
    for (i = open; i < limit; i++) {
        if (s[i] == '(')
            depth++;
        else if (s[i] == ')') {
            depth--;
            if (depth == 0)
                return i;
        }
    }
    return (size_t)-1;
}

/* Nomor baris posisi (1-based) dalam source. */
static size_t a_line_at(const char *s, size_t len, size_t pos)
{
    size_t line = 1;
    size_t i;
    if (pos > len)
        pos = len;
    for (i = 0; i < pos; i++)
        if (s[i] == '\n')
            line++;
    return line;
}

/* ---------------------------------------------------------------- */
/* Scanner struct                                                   */
/* ---------------------------------------------------------------- */

typedef struct {
    char name[MYC_ABI_NAME_LEN];
    char body[MYC_ABI_BODY_LEN];            /* deklarasi verbatim + ';' */
    char members[MYC_ABI_MAX_MEMBERS][MYC_ABI_NAME_LEN];
    int  nmembers;
    int  line;
} a_struct;

/* Ekstrak nama-nama member dari satu pernyataan [start..semi). Nama ident
 * terakhir sebelum ';' (lewat ']' array / ')' function-pointer), lanjut
 * ke kiri melewati koma untuk `int x, y;`. Bitfield (':' di pernyataan)
 * dilewati seluruhnya (offsetof bitfield = UB). */
static int a_stmt_members(const char *p, size_t start, size_t semi,
                          char out[][MYC_ABI_NAME_LEN], int max)
{
    int    n = 0;
    size_t i = semi;

    while (n < max) {
        size_t e = i;
        int    d;
        size_t b;

        while (e > start && a_is_ws(p[e - 1]))
            e--;
        if (e <= start)
            break;
        if (memchr(p + start, ':', e - start))
            return n;               /* bitfield: skip pernyataan */
        if (p[e - 1] == ']') {      /* lewati [..] */
            d = 1;
            e--;
            while (e > start && d > 0) {
                if (p[e - 1] == ']')
                    d++;
                else if (p[e - 1] == '[')
                    d--;
                e--;
            }
        } else if (p[e - 1] == ')') {   /* lewati (..) function pointer */
            d = 1;
            e--;
            while (e > start && d > 0) {
                if (p[e - 1] == ')')
                    d++;
                else if (p[e - 1] == '(')
                    d--;
                e--;
            }
        }
        b = e;
        while (b > start && a_is_ident(p[b - 1]))
            b--;
        if (b == e)
            break;
        {
            size_t nl = e - b;
            if (nl >= MYC_ABI_NAME_LEN)
                nl = MYC_ABI_NAME_LEN - 1;
            memcpy(out[n], p + b, nl);
            out[n][nl] = '\0';
            n++;
        }
        /* cari koma top-level sebelum nama ini (untuk int x, y;) */
        {
            size_t c = b;
            while (c > start) {
                char ch = p[c - 1];
                if (ch == ',')
                    break;
                if (ch == ';' || ch == '{' || ch == '}')
                    break;
                c--;
            }
            if (c <= start || p[c - 1] != ',')
                break;
            i = c - 1;
        }
    }
    return n;
}

static int a_scan_structs(const char *src, size_t len,
                          const unsigned char *cm, a_struct *st, int max)
{
    int    n = 0;
    size_t i = 0;

    while (i + 6 <= len && n < max) {
        int is_typedef = 0;
        if (cm && cm[i]) {
            i++;
            continue;
        }
        if ((i == 0 || !a_is_ident(src[i - 1])) &&
            strncmp(src + i, "struct", 6) == 0 &&
            !a_is_ident(src[i + 6])) {
            size_t j = i + 6;
            size_t tag_start = (size_t)-1, tag_end = (size_t)-1;
            int    has_brace = 0;
            size_t open = 0, close = (size_t)-1;
            size_t k = i;

            while (k > 0 && a_is_ws(src[k - 1]))
                k--;
            if (k >= 7 && strncmp(src + k - 7, "typedef", 7) == 0 &&
                (k == 7 || !a_is_ident(src[k - 8])))
                is_typedef = 1;

            while (j < len && a_is_ws(src[j]))
                j++;
            if (j < len && a_is_ident_start(src[j])) {
                tag_start = j;
                while (j < len && a_is_ident(src[j]))
                    j++;
                tag_end = j;
                while (j < len && a_is_ws(src[j]))
                    j++;
            }
            if (j < len && src[j] == '{') {
                open = j;
                close = a_match_brace(src, len, open);
                has_brace = close != (size_t)-1;
            }
            if (has_brace) {
                size_t semi = close;
                size_t start = is_typedef ? (k - 7) : i;
                char   name[MYC_ABI_NAME_LEN];
                int    has_name = 0;
                size_t p = close + 1;

                while (semi < len && src[semi] != ';')
                    semi++;
                if (semi < len) {
                    if (is_typedef) {
                        while (p < len && a_is_ws(src[p]))
                            p++;
                        if (p < len && a_is_ident_start(src[p])) {
                            size_t q = p;
                            size_t nl;
                            while (q < len && a_is_ident(src[q]))
                                q++;
                            nl = q - p;
                            if (nl >= MYC_ABI_NAME_LEN)
                                nl = MYC_ABI_NAME_LEN - 1;
                            memcpy(name, src + p, nl);
                            name[nl] = '\0';
                            has_name = 1;
                        }
                    } else if (tag_start != (size_t)-1) {
                        size_t nl = tag_end - tag_start;
                        if (nl >= MYC_ABI_NAME_LEN)
                            nl = MYC_ABI_NAME_LEN - 1;
                        memcpy(name, src + tag_start, nl);
                        name[nl] = '\0';
                        has_name = 1;
                    } else {
                        /* struct tanpa tag: nama variabel setelah '}' */
                        while (p < len && a_is_ws(src[p]))
                            p++;
                        if (p < len && a_is_ident_start(src[p])) {
                            size_t q = p;
                            size_t nl;
                            while (q < len && a_is_ident(src[q]))
                                q++;
                            nl = q - p;
                            if (nl >= MYC_ABI_NAME_LEN)
                                nl = MYC_ABI_NAME_LEN - 1;
                            memcpy(name, src + p, nl);
                            name[nl] = '\0';
                            has_name = 1;
                        }
                    }
                    if (has_name) {
                        size_t bl = semi + 1 - start;
                        int    ok = 1;
                        size_t q;
                        if (bl >= MYC_ABI_BODY_LEN)
                            bl = MYC_ABI_BODY_LEN - 1;
                        memcpy(st[n].body, src + start, bl);
                        st[n].body[bl] = '\0';
                        if (strlen(st[n].body) == 0 ||
                            st[n].body[strlen(st[n].body) - 1] != ';')
                            ok = 0;             /* body terpotong: skip */
                        if (ok) {
                            /* member: scan ';' hanya di depth 0 brace
                             * struct sendiri (nesting struct/union dalam
                             * tidak ikut — offsetof member-nya invalid). */
                            st[n].nmembers = 0;
                            q = open + 1;
                            {
                                int depth = 0;
                                while (q < close && st[n].nmembers <
                                       MYC_ABI_MAX_MEMBERS) {
                                if (src[q] == '{')
                                    depth++;
                                else if (src[q] == '}')
                                    depth--;
                                else if (src[q] == ';' && depth == 0) {
                                    int got;
                                    size_t stmt_start = open + 1;
                                    size_t s = q;
                                    while (s > open + 1 &&
                                           a_is_ws(src[s - 1]))
                                        s--;
                                    /* mundur ke awal pernyataan: cari '{'
                                     * atau ';' atau '}' sebelum posisi */
                                    {
                                        size_t t = s;
                                        while (t > open + 1) {
                                            char ch = src[t - 1];
                                            if (ch == '{' || ch == ';' ||
                                                ch == '}')
                                                break;
                                            t--;
                                        }
                                        stmt_start = t;
                                    }
                                    got = a_stmt_members(
                                        src, stmt_start, q,
                                        st[n].members + st[n].nmembers,
                                        MYC_ABI_MAX_MEMBERS - st[n].nmembers);
                                    st[n].nmembers += got;
                                }
                                q++;
                                }
                            }
                            strncpy(st[n].name, name, MYC_ABI_NAME_LEN - 1);
                            st[n].name[MYC_ABI_NAME_LEN - 1] = '\0';
                            st[n].line = (int)a_line_at(src, len, i);
                            n++;
                        }
                    }
                }
            }
        }
        i++;
    }
    return n;
}

/* ---------------------------------------------------------------- */
/* Scanner enum                                                     */
/* ---------------------------------------------------------------- */

typedef struct {
    char name[MYC_ABI_NAME_LEN];
    char body[MYC_ABI_BODY_LEN];
    char values[MYC_ABI_MAX_ENUMVALS][MYC_ABI_NAME_LEN];
    int  nvalues;
    int  line;
} a_enum;

static int a_scan_enums(const char *src, size_t len,
                        const unsigned char *cm, a_enum *en, int max)
{
    int    n = 0;
    size_t i = 0;

    while (i + 4 <= len && n < max) {
        if (cm && cm[i]) {
            i++;
            continue;
        }
        if ((i == 0 || !a_is_ident(src[i - 1])) &&
            strncmp(src + i, "enum", 4) == 0 &&
            !a_is_ident(src[i + 4])) {
            size_t j = i + 4;
            size_t k = i;
            int    is_typedef = 0;
            size_t tag_start = (size_t)-1, tag_end = (size_t)-1;

            while (k > 0 && a_is_ws(src[k - 1]))
                k--;
            if (k >= 7 && strncmp(src + k - 7, "typedef", 7) == 0 &&
                (k == 7 || !a_is_ident(src[k - 8])))
                is_typedef = 1;

            while (j < len && a_is_ws(src[j]))
                j++;
            if (j < len && a_is_ident_start(src[j])) {
                tag_start = j;
                while (j < len && a_is_ident(src[j]))
                    j++;
                tag_end = j;
                while (j < len && a_is_ws(src[j]))
                    j++;
            }
            if (j < len && src[j] == '{') {
                size_t close = a_match_brace(src, len, j);
                if (close != (size_t)-1) {
                    size_t semi = close;
                    size_t start = is_typedef ? (k - 7) : i;
                    size_t p = close + 1;
                    char   name[MYC_ABI_NAME_LEN];
                    int    has_name = 0;
                    size_t q;

                    while (semi < len && src[semi] != ';')
                        semi++;
                    if (semi < len) {
                        if (is_typedef) {
                            while (p < len && a_is_ws(src[p]))
                                p++;
                            if (p < len && a_is_ident_start(src[p])) {
                                size_t nl;
                                q = p;
                                while (q < len && a_is_ident(src[q]))
                                    q++;
                                nl = q - p;
                                if (nl >= MYC_ABI_NAME_LEN)
                                    nl = MYC_ABI_NAME_LEN - 1;
                                memcpy(name, src + p, nl);
                                name[nl] = '\0';
                                has_name = 1;
                            }
                        } else if (tag_start != (size_t)-1) {
                            size_t nl = tag_end - tag_start;
                            if (nl >= MYC_ABI_NAME_LEN)
                                nl = MYC_ABI_NAME_LEN - 1;
                            memcpy(name, src + tag_start, nl);
                            name[nl] = '\0';
                            has_name = 1;
                        }
                        if (has_name) {
                            size_t bl = semi + 1 - start;
                            int    ok = 1;
                            if (bl >= MYC_ABI_BODY_LEN)
                                bl = MYC_ABI_BODY_LEN - 1;
                            memcpy(en[n].body, src + start, bl);
                            en[n].body[bl] = '\0';
                            if (strlen(en[n].body) == 0 ||
                                en[n].body[strlen(en[n].body) - 1] != ';')
                                ok = 0;
                            if (ok) {
                                /* enumerator: split koma top-level dalam
                                 * brace; tiap item = [q..koma/close), nama =
                                 * ident pertama (nilai ekspresi + komentar
                                 * trailing diabaikan). */
                                en[n].nvalues = 0;
                                q = j + 1;
                                while (q < close &&
                                       en[n].nvalues < MYC_ABI_MAX_ENUMVALS) {
                                    size_t e;
                                    size_t b;
                                    while (q < close &&
                                           (a_is_ws(src[q]) ||
                                            src[q] == ','))
                                        q++;
                                    if (q >= close || src[q] == '}')
                                        break;
                                    e = q;
                                    while (e < close && src[e] != ',')
                                        e++;
                                    while (e > q && a_is_ws(src[e - 1]))
                                        e--;
                                    b = q;
                                    while (b < e && a_is_ws(src[b]))
                                        b++;
                                    if (b < e && a_is_ident_start(src[b])) {
                                        size_t nl = 0;
                                        while (b + nl < e &&
                                               a_is_ident(src[b + nl]))
                                            nl++;
                                        if (nl >= MYC_ABI_NAME_LEN)
                                            nl = MYC_ABI_NAME_LEN - 1;
                                        memcpy(en[n].values[en[n].nvalues],
                                               src + b, nl);
                                        en[n].values[en[n].nvalues][nl] =
                                            '\0';
                                        en[n].nvalues++;
                                    }
                                    if (e >= close)
                                        break;
                                    q = e + 1;
                                }
                                if (en[n].nvalues > 0) {
                                    strncpy(en[n].name, name,
                                            MYC_ABI_NAME_LEN - 1);
                                    en[n].name[MYC_ABI_NAME_LEN - 1] = '\0';
                                    en[n].line = (int)a_line_at(src, len, i);
                                    n++;
                                }
                            }
                        }
                    }
                }
            }
        }
        i++;
    }
    return n;
}

/* ---------------------------------------------------------------- */
/* Scanner symbols (fungsi global non-static)                       */
/* ---------------------------------------------------------------- */

typedef struct {
    char sig[192];
    int  line;
} a_sym;

static void a_collapse(char *out, size_t cap, const char *s, size_t len)
{
    size_t w = 0;
    size_t i;
    int    sp = 0;
    for (i = 0; i < len && w + 1 < cap; i++) {
        char c = s[i];
        if (a_is_ws(c)) {
            sp = 1;
            continue;
        }
        if (sp && w > 0 && out[w - 1] != '(' && out[w - 1] != ',') {
            out[w++] = ' ';
            if (w + 1 >= cap)
                break;
        }
        sp = 0;
        out[w++] = c;
    }
    out[w] = '\0';
}

static int a_scan_symbols(const char *src, size_t len,
                          const unsigned char *cm, a_sym *sy, int max)
{
    int    n = 0;
    size_t i = 0;

    while (i + 1 < len && n < max) {
        if (cm && cm[i]) {
            i++;
            continue;
        }
        if (src[i] == '(') {
            /* mundur: nama fungsi */
            size_t k = i;
            size_t b;
            char   fname[MYC_ABI_NAME_LEN];
            size_t fnl;
            size_t p;               /* posisi setelah return-type scan */
            size_t rstart;
            char   ret[64];
            size_t close;
            size_t c;
            int    is_fptr = 0;
            int    is_static = 0;

            while (k > 0 && a_is_ws(src[k - 1]))
                k--;
            if (k == 0 || !a_is_ident(src[k - 1]))
                goto next;
            b = k;
            while (b > 0 && a_is_ident(src[b - 1]))
                b--;
            fnl = k - b;
            if (fnl >= MYC_ABI_NAME_LEN)
                fnl = MYC_ABI_NAME_LEN - 1;
            memcpy(fname, src + b, fnl);
            fname[fnl] = '\0';
            if (a_is_keyword(fname))
                goto next;
            /* garis preprocessor (#define FOO(x) { ... }) bukan simbol */
            {
                size_t ls = b;
                while (ls > 0 && src[ls - 1] != '\n')
                    ls--;
                if (memchr(src + ls, '#', b - ls))
                    goto next;
            }

            /* token sebelum nama: '*(' => function pointer; 'static' =>
             * internal; ident => lanjut scan return type. */
            p = b;
            while (p > 0 && a_is_ws(src[p - 1]))
                p--;
            if (p > 0 && src[p - 1] == '*') {
                size_t t = p - 1;
                while (t > 0 && a_is_ws(src[t - 1]))
                    t--;
                if (t > 0 && src[t - 1] == '(')
                    is_fptr = 1;    /* int (*fp)(..) */
            }
            if (!is_fptr && p > 0 && a_is_ident_start(src[p - 1])) {
                size_t t = p;
                while (t > 0 && a_is_ident(src[t - 1]))
                    t--;
                /* "static" tepat 6 huruf + 1 spasi sebelum tipe */
                if (t >= 7 && strncmp(src + t - 7, "static", 6) == 0 &&
                    !a_is_ident(src[t - 8]))
                    is_static = 1;
            }
            if (is_fptr || is_static)
                goto next;

            /* return type: mundur lewati ident/'*'/ws (bounded); JANGAN
             * lintasi newline agar return type tidak menyerap baris
             * sebelumnya (source CRLF/LF deterministik). */
            rstart = p;
            {
                size_t steps = 0;
                while (rstart > 0 && steps < 48) {
                    char ch = src[rstart - 1];
                    if (ch == '\n' || ch == '\r')
                        break;
                    if (a_is_ident(ch) || ch == '*' || a_is_ws(ch)) {
                        rstart--;
                        steps++;
                    } else {
                        break;
                    }
                }
                /* trim ws di kanan ret */
                while (p > rstart && a_is_ws(src[p - 1]))
                    p--;
            }
            if (p == rstart)
                goto next;          /* tak ada return type: pemanggilan */
            if (!a_is_ident(src[p - 1]))
                goto next;          /* ret harus berakhiran ident */
            {
                size_t rl = p - rstart;
                    if (rl >= sizeof(ret))
                        rl = sizeof(ret) - 1;
                    memcpy(ret, src + rstart, rl);
                    ret[rl] = '\0';
                    a_collapse(ret, sizeof(ret), ret, strlen(ret));
                }
            if (ret[0] == '\0')
                goto next;
            /* "static inline int f(...)" — static di dalam return type */
            if (strncmp(ret, "static", 6) == 0 &&
                (ret[6] == ' ' || ret[6] == '\0'))
                goto next;

            /* forward: parameter + sesudah ')' harus '{' atau ';' */
            close = a_match_paren(src, len, i, 512);
            if (close == (size_t)-1)
                goto next;
            c = close + 1;
            for (;;) {
                while (c < len && a_is_ws(src[c]))
                    c++;
                if (c + 1 < len && src[c] == '/' && src[c + 1] == '*') {
                    /* komentar blok setelah signature, mis.
                     * "void f(void) bintang-miring ... bintang-miring" */
                    c += 2;
                    while (c + 1 < len && !(src[c] == '*' &&
                                            src[c + 1] == '/'))
                        c++;
                    c += 2;
                    continue;
                }
                if (c + 1 < len && src[c] == '/' && src[c + 1] == '/') {
                    /* komentar baris setelah signature */
                    c += 2;
                    while (c < len && src[c] != '\n')
                        c++;
                    continue;
                }
                break;
            }
            if (c >= len || (src[c] != '{' && src[c] != ';'))
                goto next;

            /* signature normalisasi */
            {
                char   params[160];
                char   sig[288];
                size_t plen = close - (i + 1);
                int    j;
                int    dup = 0;
                a_collapse(params, sizeof(params), src + i + 1, plen);
                /* precision eksplisit: ret/fname/params semua dari buffer
                 * bounded, cap sig lebih besar dari total max agar
                 * -Wformat-truncation tidak terpicu palsu. */
                snprintf(sig, sizeof(sig), "%.63s %.63s(%.127s)", ret,
                         fname, params);
                for (j = 0; j < n; j++)
                    if (strcmp(sy[j].sig, sig) == 0) {
                        dup = 1;
                        break;
                    }
                if (!dup) {
                    strncpy(sy[n].sig, sig, sizeof(sy[n].sig) - 1);
                    sy[n].sig[sizeof(sy[n].sig) - 1] = '\0';
                    sy[n].line = (int)a_line_at(src, len, b);
                    n++;
                }
            }
        }
    next:
        i++;
    }
    return n;
}

/* ---------------------------------------------------------------- */
/* Helper program generator + proses eksternal                      */
/* ---------------------------------------------------------------- */

/* Tulis teks dengan CRLF dinormalkan ke LF (deterministik lintas
 * platform; body struct/enum verbatim bisa berasal dari source CRLF). */
static void a_puts_norm(abuf *out, const char *s)
{
    if (!s)
        return;
    while (*s) {
        if (*s != '\r')
            abuf_putc(out, *s);
        s++;
    }
}

static void a_build_helper(const a_struct *st, int nst, const a_enum *en,
                           int nen, abuf *out)
{
    int s, e, m, v;
    abuf_puts(out,
              "#include <stdio.h>\n"
              "#include <stddef.h>\n"
              "#include <stdint.h>\n"
              "#if __STDC_VERSION__ >= 201112L\n"
              "#include <stdalign.h>\n"
              "#endif\n");
    for (s = 0; s < nst; s++) {
        a_puts_norm(out, st[s].body);
        abuf_putc(out, '\n');
    }
    for (e = 0; e < nen; e++) {
        a_puts_norm(out, en[e].body);
        abuf_putc(out, '\n');
    }
    abuf_puts(out, "int main(void) {\n");
    for (s = 0; s < nst; s++) {
        abuf_printf(out,
                    "printf(\"STRUCT %s size=%%llu align=%%llu\\n\","
                    "(unsigned long long)sizeof(%s),"
                    "(unsigned long long)_Alignof(%s));\n",
                    st[s].name, st[s].name, st[s].name);
        for (m = 0; m < st[s].nmembers; m++) {
            abuf_printf(out,
                        "printf(\"MEMBER %s %s off=%%llu\\n\","
                        "(unsigned long long)offsetof(%s, %s));\n",
                        st[s].name, st[s].members[m], st[s].name,
                        st[s].members[m]);
        }
    }
    for (e = 0; e < nen; e++) {
        for (v = 0; v < en[e].nvalues; v++) {
            abuf_printf(out,
                        "printf(\"ENUM %s %s=%%d\\n\",(int)%s);\n",
                        en[e].name, en[e].values[v], en[e].values[v]);
        }
    }
    abuf_puts(out, "return 0;\n}\n");
}

static int a_run(const char *const *argv, char *out, size_t cap,
                 char *err, size_t errcap)
{
    static const char *const ENV_OVERRIDE[] = { "LC_ALL=C", NULL };
    myc_proc_request req;
    myc_proc_result pr;
    int              ok;

    memset(&req, 0, sizeof(req));
    req.argv = argv;
    req.timeout_ms = 15000;
    req.max_output_bytes = 262144;
    req.env = ENV_OVERRIDE;

    memset(&pr, 0, sizeof(pr));
    /* CATATAN: myc_proc_run mengembalikan 1 = sukses, 0 = gagal
     * (proc_run_win/posix: return res->ok ? 1 : ...). */
    ok = myc_proc_run(&req, &pr);
    if (ok != 1) {
        if (err && errcap)
            snprintf(err, errcap, "exec failed");
        myc_proc_result_free(&pr);
        return -1;
    }
    if (!pr.ok || pr.exit_code != 0) {
        if (err && errcap)
            snprintf(err, errcap, "%.*s",
                     (int)(errcap > 1 ? errcap - 1 : 1),
                     (pr.stderr_data && pr.stderr_data[0]) ? pr.stderr_data
                                                           : "exit != 0");
        myc_proc_result_free(&pr);
        return -1;
    }
    if (out && cap && pr.stdout_data)
        snprintf(out, cap, "%.*s", (int)(cap > 1 ? cap - 1 : 1),
                 pr.stdout_data);
    myc_proc_result_free(&pr);
    return 0;
}

static char *a_make_tmp_dir(void)
{
    const char *base = getenv("TEMP");
    char        cwdbuf[4096];
    char       *dir;
    int         n = 0;
    size_t      bl;

#ifdef _WIN32
    if (!base || !*base)
        base = getenv("TMP");
#else
    if (!base || !*base)
        base = getenv("TMPDIR");
#endif
    if (!base || !*base) {
#ifdef _WIN32
        base = "C:/Temp";
#else
        base = "/tmp";
#endif
    }
    if (base[0] != '/' && !(base[0] && base[1] == ':')) {
        if (a_getcwd(cwdbuf, sizeof(cwdbuf)))
            base = cwdbuf;
    }
    bl = strlen(base);
    while (n < 100) {
        char   buf[40];
        size_t need;
        dir = (char *)myc_malloc(bl + 1 + sizeof(buf) + 1);
        if (!dir)
            return NULL;
        snprintf(buf, sizeof(buf), "myc_abi_%lu_%d",
                 (unsigned long)a_getpid(), n);
        need = bl + 1 + strlen(buf) + 1;
        snprintf(dir, need, "%s/%s", base, buf);
        if (a_mkdir(dir) == 0)
            return dir;
        myc_free(dir);
        n++;
    }
    return NULL;
}

static char *a_join(const char *dir, const char *name)
{
    size_t dl = strlen(dir);
    size_t nl = strlen(name);
    char  *out = (char *)myc_malloc(dl + 1 + nl + 1);
    if (!out)
        return NULL;
    memcpy(out, dir, dl);
    out[dl] = '/';
    memcpy(out + dl + 1, name, nl);
    out[dl + 1 + nl] = '\0';
    return out;
}

/* Trim trailing whitespace in place. */
static void a_trim(char *s)
{
    size_t l = strlen(s);
    while (l > 0 && (s[l - 1] == ' ' || s[l - 1] == '\t' ||
                     s[l - 1] == '\r' || s[l - 1] == '\n'))
        s[--l] = '\0';
}

/* ---------------------------------------------------------------- */
/* Snapshot utama                                                   */
/* ---------------------------------------------------------------- */

void myc_abi_snapshot(const char *src, size_t len, const char *cc_arg,
                      myc_result *res)
{
    a_struct st[MYC_ABI_MAX_STRUCTS];
    a_enum   en[MYC_ABI_MAX_ENUMS];
    a_sym    sy[MYC_ABI_MAX_SYMBOLS];
    int      nst, nen, nsy;
    char    *cc = NULL;
    char     hex[65];
    abuf     snap;
    abuf     layout;
    char    *tmpdir = NULL;
    int      s;

    memset(st, 0, sizeof(st));
    memset(en, 0, sizeof(en));
    memset(sy, 0, sizeof(sy));
    memset(&snap, 0, sizeof(snap));
    memset(&layout, 0, sizeof(layout));

    res->abi_ran = 0;
    res->abi_n_structs = 0;
    res->abi_n_enums = 0;
    res->abi_n_symbols = 0;
    res->abi_changed = 0;
    res->abi_n_delta = 0;
    res->abi_snapshot = NULL;
    res->abi_delta = NULL;
    res->abi_target = NULL;
    res->abi_header_sha = NULL;

    {
        unsigned char *cm = a_comment_mask(src, len);
        nst = a_scan_structs(src, len, cm, st, MYC_ABI_MAX_STRUCTS);
        nen = a_scan_enums(src, len, cm, en, MYC_ABI_MAX_ENUMS);
        nsy = a_scan_symbols(src, len, cm, sy, MYC_ABI_MAX_SYMBOLS);
        myc_free(cm);
    }
    res->abi_n_structs = nst;
    res->abi_n_enums = nen;
    res->abi_n_symbols = nsy;

    sha256_hex(src, len, hex);
    res->abi_header_sha = myc_result_arena_dup(res, hex, 0);

    cc = myc_find_executable(cc_arg ? cc_arg : "gcc");
    if (!cc) {
        abuf_printf(&snap, "# myc abi v1\n"
                           "TARGET unknown\n"
                           "/* abi di-skip: compiler tidak ditemukan "
                           "(observasi non-blocking) */\n");
        res->abi_snapshot =
            myc_result_arena_dup(res, snap.data ? snap.data : "", 0);
        abuf_free(&snap);
        res->abi_ran = 0;
        return;
    }

    /* TARGET triple */
    {
        const char *targv[] = { cc, "-dumpmachine", NULL };
        char        tbuf[128] = "unknown";
        if (a_run(targv, tbuf, sizeof(tbuf), NULL, 0) == 0)
            a_trim(tbuf);
        res->abi_target = myc_result_arena_dup(res, tbuf, 0);
    }

    /* Layout struct/enum via helper program */
    if (nst || nen) {
        abuf helper;

        memset(&helper, 0, sizeof(helper));
        a_build_helper(st, nst, en, nen, &helper);
        if (helper.data) {
            tmpdir = a_make_tmp_dir();
            if (tmpdir) {
                char *hsrc = a_join(tmpdir, "abi_helper.c");
                char *hexe = a_join(tmpdir, "abi_helper" ABI_EXE_SUFFIX);
                if (hsrc && hexe) {
                    FILE *f = fopen(hsrc, "wb");
                    if (f) {
                        fwrite(helper.data, 1, helper.len, f);
                        fclose(f);
                        {
                            const char *cargv[] = {
                                cc, "-std=c11", "-O0", hsrc, "-o", hexe, NULL
                            };
                            char cerr[512];
                            if (a_run(cargv, NULL, 0, cerr, sizeof(cerr)) == 0) {
                                const char *rargv[] = { hexe, NULL };
                                char        out[262144];
                                if (a_run(rargv, out, sizeof(out), NULL, 0) == 0) {
                                    /* parse baris STRUCT/MEMBER/ENUM.
                                     * Baris diakhiri LF; \r trailing dari
                                     * printf Windows dibuang agar snapshot
                                     * identik lintas platform. */
                                    {
                                        size_t p = 0;
                                        while (out[p]) {
                                            size_t e = p;
                                            size_t l, k;
                                            while (out[e] && out[e] != '\n')
                                                e++;
                                            l = e - p;
                                            if (strncmp(out + p, "STRUCT ", 7) == 0 ||
                                                strncmp(out + p, "MEMBER ", 7) == 0 ||
                                                strncmp(out + p, "ENUM ", 5) == 0) {
                                                while (l > 0 &&
                                                       (out[p + l - 1] == '\r' ||
                                                        out[p + l - 1] == ' '))
                                                    l--;
                                                for (k = 0; k < l; k++)
                                                    abuf_putc(&layout,
                                                              out[p + k]);
                                                abuf_putc(&layout, '\n');
                                            }
                                            if (!out[e])
                                                break;
                                            p = e + 1;
                                        }
                                    }
                                } else {
                                    abuf_puts(&layout,
                                              "/* abi: helper gagal "
                                              "dijalankan (observasi "
                                              "non-blocking) */\n");
                                }
                            } else {
                                abuf_printf(&layout,
                                            "/* abi: helper compile gagal "
                                            "(%.384s) */\n", cerr);
                            }
                        }
                        remove(hsrc);
                        remove(hexe);
                    }
                }
                myc_free(hsrc);
                myc_free(hexe);
                a_rmdir(tmpdir);
                myc_free(tmpdir);
            }
        }
        abuf_free(&helper);
    }

    /* Susun snapshot: TARGET, HEADER, SYMBOL, lalu layout */
    abuf_puts(&snap, "# myc abi v1\n");
    abuf_printf(&snap, "TARGET %s\n",
                res->abi_target ? res->abi_target : "unknown");
    abuf_printf(&snap, "HEADER %s\n", hex);
    for (s = 0; s < nsy; s++)
        abuf_printf(&snap, "SYMBOL %s\n", sy[s].sig);
    if (layout.data)
        abuf_puts(&snap, layout.data);

    res->abi_snapshot = myc_result_arena_dup(res, snap.data ? snap.data : "", 0);
    abuf_free(&snap);
    abuf_free(&layout);
    myc_free(cc);
    res->abi_ran = 1;
}

/* ---------------------------------------------------------------- */
/* Delta                                                            */
/* ---------------------------------------------------------------- */

#define ABI_MAX_LINES 384
#define ABI_LINE_LEN  256

typedef struct {
    char line[ABI_LINE_LEN];
} a_line;

static int a_split_lines(const char *text, a_line *out, int max)
{
    int    n = 0;
    size_t i = 0;
    if (!text)
        return 0;
    while (text[i] && n < max) {
        size_t e = i;
        size_t l;
        int    skip;
        while (text[e] && text[e] != '\n')
            e++;
        l = e - i;
        if (l >= ABI_LINE_LEN)
            l = ABI_LINE_LEN - 1;
        skip = (l == 0) || text[i] == '#' ||
               (l >= 6 && strncmp(text + i, "HEADER", 6) == 0);
        if (!skip) {
            /* buang \r trailing (file snapshot dari Windows CRLF) agar
             * delta identik lintas platform */
            while (l > 0 && (text[i + l - 1] == '\r' ||
                             text[i + l - 1] == ' '))
                l--;
            memcpy(out[n].line, text + i, l);
            out[n].line[l] = '\0';
            n++;
        }
        if (!text[e])
            break;
        i = e + 1;
    }
    return n;
}

static int a_line_in(const a_line *arr, int n, const char *l)
{
    int j;
    for (j = 0; j < n; j++)
        if (strcmp(arr[j].line, l) == 0)
            return 1;
    return 0;
}

int myc_abi_texts_changed(const char *old_text, const char *new_text,
                          char *out, size_t cap)
{
    a_line ol[ABI_MAX_LINES];
    a_line nl[ABI_MAX_LINES];
    int    no, nn, i, nd = 0;
    size_t w = 0;

    no = a_split_lines(old_text, ol, ABI_MAX_LINES);
    nn = a_split_lines(new_text, nl, ABI_MAX_LINES);

    for (i = 0; i < no; i++) {
        if (!a_line_in(nl, nn, ol[i].line)) {
            if (out && w + 1 < cap) {
                int a = snprintf(out + w, cap - w, "- %s\n", ol[i].line);
                if (a > 0)
                    w += (size_t)((size_t)a < cap - w ? (size_t)a : cap - w);
            }
            nd++;
        }
    }
    for (i = 0; i < nn; i++) {
        if (!a_line_in(ol, no, nl[i].line)) {
            if (out && w + 1 < cap) {
                int a = snprintf(out + w, cap - w, "+ %s\n", nl[i].line);
                if (a > 0)
                    w += (size_t)((size_t)a < cap - w ? (size_t)a : cap - w);
            }
            nd++;
        }
    }
    return nd > 0 ? 1 : 0;
}

void myc_abi_delta(const char *old_text, const char *new_text, myc_result *res)
{
    a_line ol[ABI_MAX_LINES];
    a_line nl[ABI_MAX_LINES];
    int    no, nn, i, nd = 0;
    abuf   d;

    memset(&d, 0, sizeof(d));
    res->abi_changed = 0;
    res->abi_n_delta = 0;
    res->abi_delta = NULL;

    no = a_split_lines(old_text, ol, ABI_MAX_LINES);
    nn = a_split_lines(new_text, nl, ABI_MAX_LINES);

    for (i = 0; i < no; i++)
        if (!a_line_in(nl, nn, ol[i].line)) {
            abuf_printf(&d, "- %s\n", ol[i].line);
            nd++;
        }
    for (i = 0; i < nn; i++)
        if (!a_line_in(ol, no, nl[i].line)) {
            abuf_printf(&d, "+ %s\n", nl[i].line);
            nd++;
        }

    res->abi_changed = (nd > 0);
    res->abi_n_delta = nd;
    if (d.data) {
        res->abi_delta = myc_result_arena_dup(res, d.data, 0);
        abuf_free(&d);
    }
}
