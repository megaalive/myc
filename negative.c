/*
 * negative.c -- Negative-Space Analysis (gagasan pembeda 9.8, --negative).
 *
 * Structural mining tanpa AI: analisis "pola yang hilang". Fokus pertama
 * (satu keluarga pola): konvensi pemeriksaan hasil fungsi alokasi.
 *
 *   - Untuk tiap callsite malloc/calloc/realloc/strdup/_strdup/wcsdup/fopen,
 *     tentukan apakah hasilnya DIPERIKSA (== NULL / != NULL / !var) baik
 *     langsung ((p = malloc()) == NULL) maupun kemudian (p == NULL di fungsi).
 *   - Bila mayoritas callsite fungsi tertentu memeriksa tetapi ada beberapa
 *     yang tidak -> "project convention deviation" dengan confidence.
 *
 * Sifat: HANYA observation (diagnostic + confidence), TIDAK pernah hard
 * verdict -- konsisten dengan prinsip MYC-AUDIT-014 (heuristik teks tidak
 * boleh jadi verdict kecuali dikonfirmasi bukti semantik). Non-blocking:
 * tanpa callsite yang cocok -> laporan 0, tidak ada klaim apa pun.
 *
 * Reentrancy (Fase 5, MYC-AUDIT-008): TIDAK memakai static/global state.
 * Statistik per-fungsi disimpan di array lokal yang diindeks oleh posisi
 * fungsi di ALLOC_FUNCS -- tanpa strdup, tanpa salinan nama (nama = pointer
 * ke ALLOC_FUNCS statis). Aman dipanggil bersamaan dari banyak thread
 * (MCP in-process siap concurrency).
 */
#include "negative.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int is_ident_start(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int is_ident_char(int c)
{
    return is_ident_start(c) || (c >= '0' && c <= '9');
}

/* Fungsi alokasi: hasilnya dianggap wajib diperiksa (konvensi aman). */
static const char *const ALLOC_FUNCS[] = {
    "malloc", "calloc", "realloc", "strdup", "_strdup", "wcsdup", "fopen",
    NULL
};

#define NEG_MAX_FUNC    16          /* ukuran array stats (>= jumlah ALLOC_FUNCS) */
#define NEG_MAX_VAR     96
#define NEG_SCAN_WINDOW 4096   /* jendela forward-check per callsite */

typedef struct {
    const char *name;           /* pointer ke ALLOC_FUNCS (statis) */
    int         total;
    int         checked;
} neg_stat;

/* Deteksi fungsi alokasi di posisi `i`: identifier utuh (bukan bagian
 * identifier lain). Mengisi *namelen dan *idx (indeks di ALLOC_FUNCS).
 * Return 1 bila cocok. */
static int is_alloc_func(const char *s, size_t len, size_t i, size_t *namelen,
                         int *idx);

/* Skip komentar/string/char-literal/preprocessor mulai posisi `i`.
 * Mengembalikan posisi setelah konstruksi, atau `i` bila bukan konstruksi. */
static size_t skip_construct(const char *s, size_t len, size_t i)
{
    if (s[i] == '/' && i + 1 < len) {
        if (s[i + 1] == '/') {
            while (i < len && s[i] != '\n')
                i++;
            return i;
        }
        if (s[i + 1] == '*') {
            i += 2;
            while (i + 1 < len && !(s[i] == '*' && s[i + 1] == '/'))
                i++;
            return i + 2 < len ? i + 2 : len;
        }
    }
    if (s[i] == '"' || s[i] == '\'') {
        char q = s[i];
        i++;
        while (i < len && s[i] != q) {
            if (s[i] == '\\')
                i++;
            i++;
        }
        return i < len ? i + 1 : len;
    }
    if (s[i] == '#') {
        while (i < len && s[i] != '\n')
            i++;
        return i;
    }
    return i;
}

/* Cari ')' penutup dari '(' di posisi `open` (parenthesis balance). */
static size_t find_close_paren(const char *s, size_t len, size_t open)
{
    int d = 0;
    size_t i = open;
    while (i < len) {
        if (s[i] == '(')
            d++;
        else if (s[i] == ')') {
            d--;
            if (d == 0)
                return i;
        }
        i++;
    }
    return len;   /* tidak tertutup: anggap sampai EOF */
}

/* Baca identifier (boleh rantai member -> / . / [ ]) tepat sebelum '='
 * pada posisi eqpos (eqpos menunjuk ke '='). Output normalized (tanpa
 * spasi). Mendukung: p = malloc(...); cfg->items = malloc(...);
 * arr[i] = malloc(...). Return 0 bila tidak ada identifier. */
static int read_lhs(const char *s, size_t eqpos, char *out, size_t cap)
{
    size_t i = eqpos;
    size_t e, n;

    /* lewati spasi mundur */
    while (i > 0 && (s[i - 1] == ' ' || s[i - 1] == '\t'))
        i--;
    /* lewati bracket penutup bila ada: arr[i] = ... */
    if (i > 0 && s[i - 1] == ']') {
        int d = 0;
        size_t j = i - 1;
        while (j > 0) {
            if (s[j] == ']')
                d++;
            else if (s[j] == '[') {
                d--;
                if (d == 0) {
                    j--;
                    break;
                }
            }
            j--;
        }
        i = j + 1;
        while (i > 0 && (s[i - 1] == ' ' || s[i - 1] == '\t'))
            i--;
    }
    /* identifier terakhir */
    e = i;
    while (i > 0 && is_ident_char((unsigned char)s[i - 1]))
        i--;
    n = e - i;
    if (n == 0 || n >= cap)
        return 0;
    memcpy(out, s + i, n);
    out[n] = '\0';
    return 1;
}

/* Apakah di posisi `i` ada pola test NULL untuk `var`?
 * Pola:  var == NULL | var != NULL | NULL == var | NULL != var | !var
 * Return 1 bila ya. */
static int test_at(const char *s, size_t len, size_t i, const char *var)
{
    size_t vl = strlen(var);

    if (i + vl <= len && memcmp(s + i, var, vl) == 0) {
        size_t j = i + vl;
        while (j < len && (s[j] == ' ' || s[j] == '\t'))
            j++;
        if (j + 2 <= len && s[j] == '=' && s[j + 1] == '=') {
            size_t k = j + 2;
            while (k < len && (s[k] == ' ' || s[k] == '\t'))
                k++;
            if (k + 4 <= len && memcmp(s + k, "NULL", 4) == 0)
                return 1;
        }
        if (j + 2 <= len && s[j] == '!' && s[j + 1] == '=') {
            size_t k = j + 2;
            while (k < len && (s[k] == ' ' || s[k] == '\t'))
                k++;
            if (k + 4 <= len && memcmp(s + k, "NULL", 4) == 0)
                return 1;
        }
        return 0;
    }
    /* NULL == var | NULL != var | !var */
    if (i + 4 <= len && memcmp(s + i, "NULL", 4) == 0) {
        size_t j = i + 4;
        while (j < len && (s[j] == ' ' || s[j] == '\t'))
            j++;
        if (j + 2 <= len && (s[j] == '=' || s[j] == '!') && s[j + 1] == '=') {
            size_t k = j + 2;
            while (k < len && (s[k] == ' ' || s[k] == '\t'))
                k++;
            if (k + vl <= len && memcmp(s + k, var, vl) == 0)
                return 1;
        }
        return 0;
    }
    if (s[i] == '!' && i + 1 < len && s[i + 1] != '=') {
        size_t j = i + 1;
        while (j < len && (s[j] == ' ' || s[j] == '\t'))
            j++;
        if (j + vl <= len && memcmp(s + j, var, vl) == 0)
            return 1;
    }
    return 0;
}

/* Scan maju dari posisi `from` (jendela terbatas; berhenti saat keluar blok
 * enclose) untuk test NULL terhadap `var`. Return 1 bila ketemu. */
static int forward_null_test(const char *s, size_t len, size_t from,
                             const char *var)
{
    size_t i = from;
    size_t end = from + NEG_SCAN_WINDOW < len ? from + NEG_SCAN_WINDOW : len;
    int    depth = 0;

    while (i < end) {
        size_t skip = skip_construct(s, end, i);
        if (skip != i) {
            i = skip;
            continue;
        }
        if (s[i] == '{') {
            depth++;
            i++;
            continue;
        }
        if (s[i] == '}') {
            depth--;
            if (depth < 0)
                return 0;   /* keluar blok enclose: hentikan */
            i++;
            continue;
        }
        if (s[i] == '\n' || s[i] == ' ' || s[i] == '\t') {
            i++;
            continue;
        }
        if (is_ident_start((unsigned char)s[i]) || s[i] == '!' ||
            (i + 4 <= end && memcmp(s + i, "NULL", 4) == 0)) {
            if (test_at(s, end, i, var))
                return 1;
            /* lewati identifier utuh */
            if (is_ident_char((unsigned char)s[i]))
                while (i < end && is_ident_char((unsigned char)s[i]))
                    i++;
            else
                i++;
            continue;
        }
        i++;
    }
    return 0;
}

/* Tambah diagnostic (disalin ke arena milik hasil). */
static void add_diag_neg(myc_result *res, int line, const char *msg)
{
    char *slot;
    if (res->diag_count >= MYC_MAX_DIAGNOSTICS)
        return;
    slot = myc_result_arena_dup(res, msg, 0);
    if (!slot)
        return;
    res->diags[res->diag_count].line = line;
    res->diags[res->diag_count].col = 0;
    res->diags[res->diag_count].message = slot;
    res->diag_count++;
}

/* ================================================================== */
/* API publik                                                          */
/* ================================================================== */
void myc_negative_space(const char *source, size_t len, myc_result *res)
{
    neg_stat stats[NEG_MAX_FUNC];
    size_t   i = 0;
    size_t   line = 1;
    int      f;

    /* Inisialisasi statistik lokal (nama = pointer statis ke ALLOC_FUNCS,
     * tidak perlu salinan; array tidak pernah diindeks di luar ALLOC_FUNCS). */
    for (f = 0; ALLOC_FUNCS[f]; f++) {
        stats[f].name = ALLOC_FUNCS[f];
        stats[f].total = 0;
        stats[f].checked = 0;
    }

    while (i < len) {
        size_t skip = skip_construct(source, len, i);
        if (skip != i) {
            size_t j;
            for (j = i; j < skip && j < len; j++)
                if (source[j] == '\n')
                    line++;
            i = skip;
            continue;
        }
        if (source[i] == '\n') {
            line++;
            i++;
            continue;
        }
        if (is_ident_start((unsigned char)source[i])) {
            size_t namelen = 0;
            int    fidx = -1;
            size_t start = i;
            size_t j;
            while (i < len && is_ident_char((unsigned char)source[i]))
                i++;
            if (!is_alloc_func(source, len, start, &namelen, &fidx))
                continue;
            j = start + namelen;
            while (j < len && (source[j] == ' ' || source[j] == '\t'))
                j++;
            if (j >= len || source[j] != '(')
                continue;

            {
                neg_stat *st = &stats[fidx];
                int       handled = 0;
                size_t    close;
                size_t    after;
                char      var[NEG_MAX_VAR];
                char      fn[32];

                st->total++;

                /* LHS: identifier sebelum '=' sebelum nama fungsi.
                 * Lewati cast eksplisit di antaranya: `p = (char *)malloc(...)`
                 * -- tanpa ini var kosong dan pemeriksaan NULL tidak
                 * terdeteksi (false positive pada kode sah). */
                var[0] = '\0';
                {
                    size_t k = start;
                    for (;;) {
                        while (k > 0 && (source[k - 1] == ' ' ||
                                         source[k - 1] == '\t'))
                            k--;
                        if (k > 0 && source[k - 1] == ')') {
                            /* cast `(type)` : lompat ke '(' pasangannya */
                            int    d = 0;
                            size_t j = k - 1;
                            while (j > 0) {
                                if (source[j] == ')')
                                    d++;
                                else if (source[j] == '(') {
                                    d--;
                                    if (d == 0)
                                        break;
                                }
                                j--;
                            }
                            k = j;
                            continue;
                        }
                        break;
                    }
                    if (k > 0 && source[k - 1] == '=') {
                        size_t b = k - 1;
                        if (read_lhs(source, k - 1, var, sizeof(var))) {
                            /* pola !(p = ...) tepat di belakang LHS */
                            while (b > 0 && (source[b - 1] == ' ' ||
                                             source[b - 1] == '\t'))
                                b--;
                            if (b > 0 && source[b - 1] == '!' &&
                                (b < 2 || source[b - 2] != '='))
                                handled = 1;
                        }
                    }
                }

                close = find_close_paren(source, len, j);
                after = close < len ? close + 1 : len;
                while (after < len && (source[after] == ' ' ||
                                       source[after] == '\t'))
                    after++;

                /* pemeriksaan langsung setelah panggilan */
                if (!handled && after + 1 < len) {
                    if (source[after] == '=' && source[after + 1] == '=')
                        handled = 1;
                    else if (source[after] == '!' && after + 1 < len &&
                             source[after + 1] == '=')
                        handled = 1;
                    else if (source[after] == '?')
                        handled = 1;
                    else if (source[after] == ',' || source[after] == ')')
                        handled = 1;   /* hasil langsung jadi argumen */
                }

                /* pemeriksaan kemudian (statement assignment) */
                if (!handled && var[0])
                    handled = forward_null_test(source, len, after, var);

                if (handled) {
                    st->checked++;
                } else {
                    if (namelen >= sizeof(fn))
                        namelen = sizeof(fn) - 1;
                    memcpy(fn, source + start, namelen);
                    fn[namelen] = '\0';
                    {
                        char note[256];
                        snprintf(note, sizeof(note),
                                 "negative-space: callsite %s baris %llu "
                                 "tidak memeriksa hasil",
                                 fn, (unsigned long long)line);
                        add_diag_neg(res, (int)line, note);
                    }
                }
            }
            continue;
        }
        i++;
    }

    /* Laporan konvensi per fungsi: hanya bila total >= 3 dan mayoritas
     * memeriksa tetapi ada yang tidak (konvensi baru terbentuk). */
    res->negative_callsites = 0;
    res->negative_deviations = 0;
    for (f = 0; ALLOC_FUNCS[f]; f++) {
        neg_stat *st = &stats[f];
        int       unchecked = st->total - st->checked;
        res->negative_callsites += st->total;
        res->negative_deviations += unchecked;
        if (st->total >= 3 && st->checked > unchecked && unchecked > 0) {
            double conf = 0.55 + 0.43 *
                ((double)(st->checked - unchecked) / (double)st->total);
            char note[256];
            if (conf > 0.98)
                conf = 0.98;
            snprintf(note, sizeof(note),
                     "negative-space: konvensi proyek %d/%d callsite %s "
                     "memeriksa hasil (confidence %.2f) - periksa callsite "
                     "yang tidak",
                     st->checked, st->total, st->name, conf);
            add_diag_neg(res, 0, note);
        }
    }
}

/* Deteksi fungsi alokasi di posisi `i`: identifier utuh (bukan bagian
 * identifier lain). Mengisi *namelen dan *idx (indeks di ALLOC_FUNCS).
 * Return 1 bila cocok. */
static int is_alloc_func(const char *s, size_t len, size_t i, size_t *namelen,
                         int *idx)
{
    int f;
    for (f = 0; ALLOC_FUNCS[f]; f++) {
        size_t n = strlen(ALLOC_FUNCS[f]);
        if (i + n <= len && memcmp(s + i, ALLOC_FUNCS[f], n) == 0) {
            /* pastikan bukan bagian identifier lain */
            if (i > 0 && is_ident_char((unsigned char)s[i - 1]))
                continue;
            if (i + n < len && is_ident_char((unsigned char)s[i + n]))
                continue;
            *namelen = n;
            *idx = f;
            return 1;
        }
    }
    return 0;
}
