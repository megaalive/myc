/*
 * lint.c -- Lint memory-safety myc (heuristik, tingkat token).
 *
 * Deteksi pola berisiko yang biasanya lolos gcc (lihat header):
 *   1. Pointer diubah via (intptr_t)/(uintptr_t)  -> VIOLATION (ok=0)
 *   2. realloc disimpan ke variabel lain          -> VIOLATION (ok=0)
 *   3. memcpy/memmove/memset tanpa sizeof          -> warning (ok=1)
 *   4. malloc/calloc ukuran berpotensi overflow    -> warning (ok=1)
 *
 * Scanner bekerja pada source mentah (bukan -E): melewati komentar, string,
 * char literal, dan baris preprocessor. Ini heuristik -- lihat rencana.
 */
#include "lint.h"

#include <ctype.h>
#include <string.h>

static void add_diag(myc_result *res, int line, int col, const char *msg)
{
    if (res->diag_count < MYC_MAX_DIAGNOSTICS) {
        res->diags[res->diag_count].line = line;
        res->diags[res->diag_count].col = col;
        res->diags[res->diag_count].message = msg;
        res->diag_count++;
    }
}

static int is_ident_start(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int is_ident_char(int c)
{
    return is_ident_start(c) || (c >= '0' && c <= '9');
}

/* Char signifikan sebelum posisi `i` (lewati spasi/tab). Return -1 bila EOF */
static int prev_sig(const char *s, size_t i)
{
    while (i > 0) {
        i--;
        if (s[i] != ' ' && s[i] != '\t')
            return (unsigned char)s[i];
    }
    return -1;
}

/* Ambil argumen pertama pemanggilan setelah '('. i = posisi sesudah '('.
 * Lewati prefix unary '&'/'*' lalu baca identifier. Isi *argend = posisi
 * akhir identifier. Mengembalikan posisi awal identifier (setelah prefix),
 * atau `i` bila tidak ada identifier. */
static size_t read_arg_ident(const char *s, size_t len, size_t i,
                             size_t *argend)
{
    size_t start = i;
    if (i < len && (s[i] == '&' || s[i] == '*'))
        i++;
    start = i;
    while (i < len && is_ident_start((unsigned char)s[i]))
        i++;
    *argend = i;
    return start;
}

/* Identifier yang berakhir tepat sebelum posisi `before` (lewati spasi).
 * Salin ke out/outcap; return 1 bila ketemu. */
static int ident_before(const char *s, size_t before,
                        char *out, size_t outcap)
{
    size_t end = before;
    size_t start;
    size_t n;
    while (end > 0 && (s[end - 1] == ' ' || s[end - 1] == '\t'))
        end--;
    start = end;
    while (start > 0 && is_ident_char((unsigned char)s[start - 1]))
        start--;
    if (start == end)
        return 0;
    n = end - start;
    if (n >= outcap)
        n = outcap - 1;
    memcpy(out, s + start, n);
    out[n] = '\0';
    return 1;
}

/* Cari target assignment `x = (...cast...) ident` mundur dari posisi `start`.
 * Lewati spasi, grup paren (mis. cast "(char *)"), dan '*'. Return ident
 * sebelum '=' terdekat. Heuristik: berhenti pada char tak dikenal. */
static int find_assign_target(const char *s, size_t start,
                              char *out, size_t outcap)
{
    size_t i = start;
    for (;;) {
        while (i > 0 && (s[i - 1] == ' ' || s[i - 1] == '\t'))
            i--;
        if (i == 0)
            return 0;
        if (s[i - 1] == ')') {
            /* lewati grup paren mundur, termasuk ')' itu sendiri */
            int depth = 0;
            for (;;) {
                if (i == 0)
                    return 0;
                i--;
                if (s[i] == ')')
                    depth++;
                else if (s[i] == '(') {
                    depth--;
                    if (depth == 0)
                        break;
                }
            }
            continue;
        }
        if (s[i - 1] == '*' || s[i - 1] == '(') {
            i--;
            continue;
        }
        if (s[i - 1] == '=') {
            size_t e = i - 1;
            return ident_before(s, e, out, outcap);
        }
        return 0;
    }
}

/* Cari pola assignment `<oldname> = <newname>` dalam jendela terbatas setelah
 * posisi `after` (lewati spasi). Dipakai untuk mengenali idiom aman realloc:
 *   tmp = realloc(buf, n); ...; buf = tmp;   (pointer lama disinkronkan).
 * Heuristik: jendela 1000 char; komentar/string dalam jendela dapat menimbulkan
 * false-positive, dianggap berterima utk lint (dokumentasikan di header). */
static int reassign_after(const char *s, size_t len, size_t after,
                          const char *oldname, const char *newname)
{
    size_t olen = strlen(oldname);
    size_t nlen = strlen(newname);
    size_t limit = after + 1000;
    size_t i;
    if (limit < after || limit > len)
        limit = len;
    for (i = after; i + olen <= limit; i++) {
        char before, afterc;
        size_t j;
        if (strncmp(s + i, oldname, olen) != 0)
            continue;
        before = i > 0 ? s[i - 1] : 0;
        afterc = i + olen < len ? s[i + olen] : 0;
        if (is_ident_char((unsigned char)before) ||
            is_ident_char((unsigned char)afterc))
            continue;
        j = i + olen;
        while (j < len && (s[j] == ' ' || s[j] == '\t'))
            j++;
        if (j < len && s[j] == '=') {
            j++;
            while (j < len && (s[j] == ' ' || s[j] == '\t'))
                j++;
            if (j + nlen <= len && strncmp(s + j, newname, nlen) == 0)
                return 1;
        }
    }
    return 0;
}

/* Lebar argumen pemanggilan: mulai dari '(', cari ')' penutup seimbang.
 * Isi *argstart,*argstop (di dalam tanda kurung). */
static void find_call_args(const char *s, size_t len, size_t openparen,
                           size_t *argstart, size_t *argstop)
{
    size_t i = openparen + 1;
    int    depth = 1;
    while (i < len && depth > 0) {
        if (s[i] == '(')
            depth++;
        else if (s[i] == ')')
            depth--;
        i++;
    }
    *argstart = openparen + 1;
    *argstop = depth == 0 ? i - 1 : len;
}

/* Apakah substring region memuat token "sizeof" (di luar string literal)? */
static int region_has_sizeof(const char *s, size_t a, size_t b)
{
    size_t i;
    for (i = a; i + 6 <= b && i < b; i++) {
        if (i + 6 <= b && strncmp(s + i, "sizeof", 6) == 0) {
            /* pastikan batas identifier benar */
            char before = i > a ? s[i - 1] : 0;
            char after = i + 6 < b ? s[i + 6] : 0;
            if (!is_ident_char((unsigned char)before) &&
                !is_ident_char((unsigned char)after))
                return 1;
        }
    }
    return 0;
}

/* Apakah region memuat '*' (perkalian) dan bukan hanya deklarasi/pointer? */
static int region_has_mul(const char *s, size_t a, size_t b)
{
    size_t i;
    for (i = a; i < b; i++)
        if (s[i] == '*')
            return 1;
    return 0;
}

int myc_lint_source(const char *source, size_t len, myc_result *res)
{
    size_t i = 0;
    size_t line = 1;
    size_t col = 1;
    int    ok = 1;

    while (i < len) {
        char c = source[i];

        if (c == '\n') {
            line++;
            col = 1;
            i++;
            continue;
        }

        if (c == ' ' || c == '\t') {
            col++;
            i++;
            continue;
        }

        /* komentar */
        if (c == '/' && i + 1 < len) {
            if (source[i + 1] == '/') {
                while (i < len && source[i] != '\n') {
                    i++;
                    col++;
                }
                continue;
            }
            if (source[i + 1] == '*') {
                i += 2;
                col += 2;
                while (i + 1 < len && !(source[i] == '*' && source[i + 1] == '/')) {
                    if (source[i] == '\n') {
                        line++;
                        col = 1;
                    } else {
                        col++;
                    }
                    i++;
                }
                if (i + 1 < len) {
                    i += 2;
                    col += 2;
                }
                continue;
            }
        }

        /* string literal */
        if (c == '"') {
            i++;
            col++;
            while (i < len) {
                if (source[i] == '\\') {
                    i += 2;
                    col += 2;
                    continue;
                }
                if (source[i] == '"') {
                    i++;
                    col++;
                    break;
                }
                if (source[i] == '\n') {
                    line++;
                    col = 1;
                } else {
                    col++;
                }
                i++;
            }
            continue;
        }

        /* char literal */
        if (c == '\'') {
            i++;
            col++;
            while (i < len) {
                if (source[i] == '\\') {
                    i += 2;
                    col += 2;
                    continue;
                }
                if (source[i] == '\'') {
                    i++;
                    col++;
                    break;
                }
                if (source[i] == '\n') {
                    line++;
                    col = 1;
                } else {
                    col++;
                }
                i++;
            }
            continue;
        }

        /* baris preprocessor: lewati */
        if (c == '#') {
            while (i < len && source[i] != '\n') {
                i++;
                col++;
            }
            continue;
        }

        /* identifier */
        if (is_ident_start((unsigned char)c)) {
            size_t start = i;
            size_t tokcol = col;
            char   tok[64];
            size_t tlen = 0;
            while (i < len && tlen < sizeof(tok) - 1 &&
                   is_ident_char((unsigned char)source[i])) {
                tok[tlen++] = source[i];
                i++;
                col++;
            }
            tok[tlen] = '\0';

            /* --- 1. cast pointer -> integer --- */
            if (strcmp(tok, "intptr_t") == 0 || strcmp(tok, "uintptr_t") == 0) {
                /* cast bila diawali '(' dan diakhiri ')' (setelah nama tipe) */
                if (prev_sig(source, start) == '(') {
                    size_t j = i;
                    while (j < len && (source[j] == ' ' || source[j] == '\t'))
                        j++;
                    if (j < len && source[j] == ')') {
                        add_diag(res, (int)line, (int)tokcol,
                                 "provenance pointer diubah via integer cast "
                                 "(tidak dapat diverifikasi)");
                        ok = 0;
                    }
                }
                continue;
            }

            /* --- 2. realloc ke variabel lain --- */
            if (strcmp(tok, "realloc") == 0) {
                size_t j = i;
                size_t a1start, a1end;
                char   arg1[64];
                size_t arg1n;
                char   target[64];
                while (j < len && (source[j] == ' ' || source[j] == '\t'))
                    j++;
                if (j < len && source[j] == '(') {
                    a1start = read_arg_ident(source, len, j + 1, &a1end);
                    arg1n = a1end - a1start;
                    if (arg1n > 0 && arg1n < sizeof(arg1)) {
                        memcpy(arg1, source + a1start, arg1n);
                        arg1[arg1n] = '\0';
                        /* cari target assignment: ident sebelum '=' sebelum tok */
                        if (find_assign_target(source, start, target,
                                               sizeof(target))) {
                            if (strcmp(target, arg1) != 0) {
                                /* idiom aman: target = realloc(arg1,...) lalu
                                 * arg1 disinkronkan (arg1 = target) di kemudian
                                 * hari -> bukan UAF. */
                                if (!reassign_after(source, len, i, arg1, target)) {
                                    add_diag(res, (int)line, (int)tokcol,
                                             "realloc ke variabel lain: pointer "
                                             "lama berpotensi use-after-free");
                                    ok = 0;
                                }
                            }
                        }
                    }
                }
                continue;
            }

            /* --- 3. memcpy/memmove/memset tanpa sizeof --- */
            if (strcmp(tok, "memcpy") == 0 || strcmp(tok, "memmove") == 0 ||
                strcmp(tok, "memset") == 0) {
                size_t j = i;
                size_t argstart, argstop;
                while (j < len && (source[j] == ' ' || source[j] == '\t'))
                    j++;
                if (j < len && source[j] == '(') {
                    find_call_args(source, len, j, &argstart, &argstop);
                    if (!region_has_sizeof(source, argstart, argstop)) {
                        add_diag(res, (int)line, (int)tokcol,
                                 "warning: memcpy/memmove/memset tanpa sizeof "
                                 "-- bounds tidak dibuktikan statis");
                    }
                }
                continue;
            }

            /* --- 4. malloc/calloc ukuran berpotensi overflow --- */
            if (strcmp(tok, "malloc") == 0 || strcmp(tok, "calloc") == 0) {
                size_t j = i;
                size_t argstart, argstop;
                while (j < len && (source[j] == ' ' || source[j] == '\t'))
                    j++;
                if (j < len && source[j] == '(') {
                    find_call_args(source, len, j, &argstart, &argstop);
                    if (region_has_mul(source, argstart, argstop) &&
                        !region_has_sizeof(source, argstart, argstop)) {
                        add_diag(res, (int)line, (int)tokcol,
                                 "warning: ukuran alokasi memuat perkalian "
                                 "tanpa sizeof -- potensi integer overflow");
                    }
                }
                continue;
            }

            continue;
        }

        i++;
        col++;
    }

    return ok;
}
