/*
 * scanner.c -- Scanner kebijakan myc.
 *
 * Lapis 1: #include mentah.
 * Lapis 2: penanda file hasil -E.
 * Lapis 3: panggilan fungsi denylist pada output -E.
 */
#include "scanner.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "policy.h"

/* ------------------------------------------------------------------ */
/* Util diagnostic                                                      */
/* ------------------------------------------------------------------ */

static void add_diag(myc_result *res, int line, int col, const char *msg)
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

static int is_ident_start(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int is_ident_char(int c)
{
    return is_ident_start(c) || (c >= '0' && c <= '9');
}

/* ------------------------------------------------------------------ */
/* Lapis 1: #include pada source mentah                                 */
/* ------------------------------------------------------------------ */

int myc_scan_include_raw(const char *source, size_t len, myc_result *res)
{
    size_t i = 0;
    size_t line = 1;

    while (i < len) {
        char c = source[i];

        if (c == '\n') {
            line++;
            i++;
            continue;
        }

        if (c == '/') {
            /* komentar */
            if (i + 1 < len && source[i + 1] == '/') {
                while (i < len && source[i] != '\n')
                    i++;
                continue;
            }
            if (i + 1 < len && source[i + 1] == '*') {
                i += 2;
                while (i + 1 < len && !(source[i] == '*' && source[i + 1] == '/')) {
                    if (source[i] == '\n')
                        line++;
                    i++;
                }
                i += 2;
                continue;
            }
        }

        if (c == '#') {
            size_t j = i + 1;
            /* awali token (boleh spasi sebelum include) */
            while (j < len && (source[j] == ' ' || source[j] == '\t'))
                j++;
            if (j + 6 < len &&
                strncmp(source + j, "include", 7) == 0 &&
                !is_ident_char(source[j + 7])) {
                size_t k = j + 7;
                while (k < len && (source[k] == ' ' || source[k] == '\t'))
                    k++;
                if (k < len && source[k] == '<') {
                    size_t start = k + 1;
                    size_t end = start;
                    while (end < len && source[end] != '>')
                        end++;
                    if (end < len) {
                        size_t hlen = end - start;
                        char   *hname = (char *)malloc(hlen + 1);
                        if (hname) {
                            memcpy(hname, source + start, hlen);
                            hname[hlen] = '\0';
                            if (!myc_policy_allow_include(hname)) {
                                add_diag(res, (int)line, (int)(start - i + 1),
                                         "warning: include di luar whitelist "
                                         "(non-blocking)");
                            }
                            free(hname);
                        }
                    }
                    i = end + 1;
                    continue;
                } else if (k < len && source[k] == '"') {
                    /* include "..." -- file lokal */
                    size_t start = k + 1;
                    size_t end = start;
                    while (end < len && source[end] != '"')
                        end++;
                    if (end < len) {
                        size_t hlen = end - start;
                        char   *hname = (char *)malloc(hlen + 1);
                        if (hname) {
                            memcpy(hname, source + start, hlen);
                            hname[hlen] = '\0';
                            if (!myc_policy_allow_include(hname)) {
                                add_diag(res, (int)line, (int)(start - i + 1),
                                         "warning: include lokal/kuotasi di "
                                         "luar whitelist (non-blocking)");
                            }
                            free(hname);
                        }
                    }
                    i = end + 1;
                    continue;
                }
            }
        }

        i++;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Lapis 2: penanda file hasil gcc -E                                   */
/* ------------------------------------------------------------------ */

/*
 * Lapis 2: penanda file hasil gcc -E.
 *
 * Format marker gcc:  "# <linenum> \"<path>\" <flags>..."
 *   flag "1" = memasuki file baru
 *   flag "2" = kembali ke file
 *   flag "3" = header sistem
 *
 * Ancaman: makro dapat menyelundupkan `#include H` (H = nama header tak
 * diizinkan). Setelah -E, marker menunjukkan file yang benar-benar
 * disertakan. Tapi header yang diizinkan (mis. stdio.h) menarik banyak
 * header sistem transitif. Maka: hanya header yang disertakan pada
 * "user depth" (dalam region source user, <built-in>/<command-line>/<stdin>)
 * yang wajib ada di whitelist. Header transitif dari header yang diizinkan
 * boleh (perilaku C normal).
 *
 * Implementasi: `user_depth` = kedalaman region source user. Marker ke
 * file pseudo (diawali '<') mengembalikan user_depth = 1. Header .h
 * dengan flag "1" menaikkan user_depth; flag "2" menurunkannya. Header
 * yang di-include langsung dari user (user_depth == 1 sebelum naik) dan
 * .h harus ada di whitelist.
 */
int myc_scan_markers(const char *pre, size_t len, myc_result *res)
{
    size_t i = 0;
    int    user_depth = 1;

    while (i < len) {
        if (pre[i] == '#') {
            size_t j = i + 1;
            int    saw_digit = 0;
            while (j < len && (pre[j] == ' ' || pre[j] == '\t'))
                j++;
            while (j < len && isdigit((unsigned char)pre[j])) {
                saw_digit = 1;
                j++;
            }
            if (saw_digit) {
                while (j < len && (pre[j] == ' ' || pre[j] == '\t'))
                    j++;
                if (j < len && pre[j] == '"') {
                    size_t start = j + 1;
                    size_t end = start;
                    int    is_new = 0;
                    int    is_return = 0;
                    int    is_pseudo = 0;
                    int    is_hdr = 0;
                    while (end < len && pre[end] != '"')
                        end++;
                    if (end < len && end > start) {
                        size_t plen = end - start;
                        size_t f = end + 1;
                        if (plen >= 2 && pre[start] == '<' &&
                            pre[end - 1] == '>')
                            is_pseudo = 1;
                        if (plen >= 2 && pre[end - 2] == '.' &&
                            pre[end - 1] == 'h')
                            is_hdr = 1;
                        /* parse flags setelah penutup kutip */
                        while (f < len) {
                            while (f < len && (pre[f] == ' ' || pre[f] == '\t'))
                                f++;
                            if (f >= len || pre[f] == '\n')
                                break;
                            if (pre[f] == '1')
                                is_new = 1;
                            else if (pre[f] == '2')
                                is_return = 1;
                            while (f < len && pre[f] != ' ' && pre[f] != '\t' &&
                                   pre[f] != '\n')
                                f++;
                        }
                    }
                    if (end < len && end > start) {
                        size_t plen = end - start;
                        char  *path = (char *)malloc(plen + 1);
                        if (path) {
                            memcpy(path, pre + start, plen);
                            path[plen] = '\0';
                            if (is_pseudo) {
                                user_depth = 1;
                            } else if (is_new) {
                                user_depth++;
                                if (is_hdr && user_depth == 2) {
                                    /* include langsung dari user */
                                    const char *base = strrchr(path, '/');
                                    const char *base2 = strrchr(path, '\\');
                                    const char *bn = base ? base + 1
                                                          : (base2 ? base2 + 1 : path);
                                    if (!myc_policy_allow_include(bn)) {
                                        add_diag(res, 0, 0,
                                                 "warning: include langsung "
                                                 "header non-whitelist "
                                                 "(non-blocking)");
                                    }
                                }
                            } else if (is_return) {
                                if (user_depth > 1)
                                    user_depth--;
                            }
                            free(path);
                        }
                    }
                    while (i < len && pre[i] != '\n')
                        i++;
                    continue;
                }
            }
        }

        if (pre[i] == '\n') {
            /* line dihitung di atas; tidak dipakai lapis ini */
        }
        i++;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Lapis 3: deteksi panggilan denylist pada output -E                   */
/* ------------------------------------------------------------------ */

/*
 * Lapis 3: deteksi panggilan denylist pada output -E.
 *
 * Output -E berisi isi header yang di-include; memindai semuanya akan
 * false positive (header standar memanggil fopen/printf dkk). Maka scan
 * hanya baris milik source user: saat `user_depth == 1`.
 * Makro smuggle tetap ketahuan karena `#define RUN system`
 * menghasilkan `system(...)` di baris source user setelah -E.
 *
 * Pelacakan lokasi memakai marker gcc "# <linenum> \"<file>\" ...":
 *   - file pseudo "<stdin>", "<built-in>", "<command-line>" = user (depth 1)
 *   - flag "1" = masuk file (depth naik); flag "2" = kembali (depth turun)
 *   - kedalaman berlaku untuk semua file (header, .inl, dll) agar sinkron
 * `src_line` memetakan ke baris source asli untuk diagnostic.
 */
int myc_scan_calls(const char *pre, size_t len, myc_result *res)
{
    size_t i = 0;
    size_t col = 1;
    int    user_depth = 1;
    int    src_line = 1;    /* baris source asli (dari marker <stdin>) */
    char   ident[256];

    while (i < len) {
        char c = pre[i];

        if (c == '\n') {
            if (user_depth == 1)
                src_line++;
            col = 1;
            i++;
            continue;
        }

        if (c == '#') {
            /* Marker/direktif. Update in_user + src_line bila marker file. */
            size_t j = i + 1;
            int    saw_digit = 0;
            int    linenum = 0;
            while (j < len && (pre[j] == ' ' || pre[j] == '\t'))
                j++;
            while (j < len && isdigit((unsigned char)pre[j])) {
                linenum = linenum * 10 + (pre[j] - '0');
                saw_digit = 1;
                j++;
            }
            if (saw_digit) {
                while (j < len && (pre[j] == ' ' || pre[j] == '\t'))
                    j++;
                if (j < len && pre[j] == '"') {
                    size_t start = j + 1;
                    size_t end = start;
                    int    is_new = 0, is_return = 0;
                    while (end < len && pre[end] != '"')
                        end++;
                    if (end < len) {
                        size_t f = end + 1;
                        int    is_pseudo = 0;
                        size_t plen = end - start;
                        /* pseudo file: nama diawali '<' (e.g. <stdin>) */
                        if (plen >= 2 && pre[start] == '<' &&
                            pre[end - 1] == '>')
                            is_pseudo = 1;
                        while (f < len) {
                            while (f < len && (pre[f] == ' ' || pre[f] == '\t'))
                                f++;
                            if (f >= len || pre[f] == '\n')
                                break;
                            if (pre[f] == '1')
                                is_new = 1;
                            else if (pre[f] == '2')
                                is_return = 1;
                            while (f < len && pre[f] != ' ' && pre[f] != '\t' &&
                                   pre[f] != '\n')
                                f++;
                        }
                        if (is_pseudo) {
                            user_depth = 1;
                            src_line = linenum;
                        } else if (is_new) {
                            user_depth++;
                        } else if (is_return) {
                            if (user_depth > 1)
                                user_depth--;
                        }
                    }
                }
            }
            /* lewati seluruh baris direktif + newline-nya (tanpa count) */
            while (i < len && pre[i] != '\n')
                i++;
            if (i < len)
                i++;
            continue;
        }

        /* Hanya scan baris source user. */
        if (user_depth == 1) {
            /* string literal */
            if (c == '"' || c == '\'') {
                char q = c;
                i++;
                col++;
                while (i < len) {
                    if (pre[i] == '\\') {
                        i += 2;
                        col += 2;
                        continue;
                    }
                    if (pre[i] == q) {
                        i++;
                        col++;
                        break;
                    }
                    i++;
                    col++;
                }
                continue;
            }

            /* identifier */
            if (is_ident_start((unsigned char)c)) {
                size_t n = 0;
                size_t save_col = col;
                while (i < len && n < sizeof(ident) - 1 &&
                       is_ident_char((unsigned char)pre[i])) {
                    ident[n++] = pre[i];
                    i++;
                    col++;
                }
                ident[n] = '\0';

                /* lewati spasi, cek '(' */
                {
                    size_t j = i;
                    while (j < len && (pre[j] == ' ' || pre[j] == '\t'))
                        j++;

                    if (j < len && pre[j] == '(') {
                        if (myc_policy_deny_function(ident)) {
                            add_diag(res, src_line, (int)save_col,
                                     "warning: fungsi dilarang (non-blocking)");
                        }
                    }
                }
                continue;
            }
        }

        i++;
        col++;
    }
    return 1;
}
