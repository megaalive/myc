/*
 * driver.c -- Gate driver-generator (D2.2, --driver).
 *
 * Alur:
 *   1. Scan source untuk fungsi yang didahului kontrak //@ requires.
 *   2. Parse signature: nama fungsi, daftar parameter (tipe + nama),
 *      dan ekspresi requires (satu-baris, hingga DRV_MAX_REQS per fungsi).
 *   3. Parse batas integer dari teks requires (mis. "n <= 4" -> hi=4)
 *      untuk menghasilkan kasus uji TEPI di dalam domain kontrak.
 *   4. Bangkitkan harness: source asli (main-nya di-rename via #define)
 *      + main() baru yang memanggil setiap fungsi ber-kontrak dengan
 *      kasus tepi (batas, batas-1, 0, 1, 2, dst) pada buffer calloc.
 *      Kasus yang melanggar requires dilewati guard ekspresi kontrak.
 *   5. Build harness dengan clang ASan+UBSan (-O0, source via stdin,
 *      pola sama dengan gate run P6), lalu eksekusi terkendali.
 *   6. Marker sanitizer -> MC_DRIVER_VIOLATION; bersih + >= 1 kasus
 *      tereksekusi -> caller naikkan ke L3 RUNTIME.
 *
 * Jujur (heuristik, bukan sound): type parsing berbasis teks; fungsi yang
 * parameternya tidak bisa dipanggil dengan aman (struct by value, variadic,
 * tipe tak dikenal) di-SKIP, bukan error. Nilai negatif/SIZE_MAX tidak
 * diuji bila kontrak tidak membuka peluangnya (hindari false positive).
 */
#include "driver.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <direct.h>
#include <process.h>
#define myc_mkdir(path) _mkdir(path)
#define myc_rmdir(path) _rmdir(path)
#define myc_getpid() _getpid()
#define my_getcwd(buf,sz) _getcwd(buf,sz)
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define myc_mkdir(path) mkdir(path, 0700)
#define myc_rmdir(path) rmdir(path)
#define myc_getpid() getpid()
#define my_getcwd(buf,sz) getcwd(buf,sz)
#endif

#include "proc.h"

#include "gate.h"

#include "sha256.h"

#include "json.h"

#define DRV_MAX_FUNCS  8
#define DRV_MAX_PARAMS 6
#define DRV_MAX_REQS   4
#define DRV_MAX_CASES  MYC_MAX_DRIVER_CASES
#define DRV_MAX_CANDS  8
#define DRV_MAX_LEN    128
#define DRV_BUF_CAP    65536    /* ukuran buffer pointer maksimum (bytes) */

#define ASAN_DLL_NAME "clang_rt.asan_dynamic-x86_64.dll"

/* Env deterministik untuk harness (MYC-AUDIT-017): ASan/UBSan menulis
 * report ke FILE unik (log_path) di tmp_dir — saluran non-spoofable. */
static const char *const DRV_RUN_ENV[] = {
    "ASAN_OPTIONS=log_path=myc_drv_asan_rpt:abort_on_error=1:halt_on_error=1",
    "UBSAN_OPTIONS=log_path=myc_drv_ubsan_rpt:halt_on_error=1:print_stacktrace=1",
    "LC_ALL=C",
    NULL
};

/* Marker laporan sanitizer (sama dengan gate run). */
static const char *const DRV_MARKERS[] = {
    "ERROR: AddressSanitizer",
    "SUMMARY: AddressSanitizer",
    "AddressSanitizer:",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "LeakSanitizer",
    "heap-buffer-overflow",
    "heap-use-after-free",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "use-after-poison",
    "Assertion failed",
    "MYC_CHECKED:",
    NULL
};

/* ------------------------------------------------------------------ */
/* Buffer dinamis kecil                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} drv_buf;

static int drv_buf_put(drv_buf *b, char c)
{
    if (b->len + 2 > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 8192;
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

static int drv_buf_putn(drv_buf *b, const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (!drv_buf_put(b, s[i]))
            return 0;
    return 1;
}

static int drv_buf_puts(drv_buf *b, const char *s)
{
    return drv_buf_putn(b, s, strlen(s));
}

static int drv_buf_printf(drv_buf *b, const char *fmt, ...)
{
    char   tmp[512];
    va_list ap;
    int    n;
    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0)
        return 0;
    if ((size_t)n >= sizeof(tmp))
        n = (int)sizeof(tmp) - 1;
    return drv_buf_putn(b, tmp, (size_t)n);
}

/* ------------------------------------------------------------------ */
/* Lexical helper                                                     */
/* ------------------------------------------------------------------ */

static int drv_ident_start(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int drv_ident_char(int c)
{
    return drv_ident_start(c) || (c >= '0' && c <= '9');
}

/* Identifier yang berakhir tepat sebelum posisi `before` (lewati spasi).
 * Salin ke out/outcap; return 1 bila ketemu. */
static int drv_ident_before(const char *s, size_t before,
                            char *out, size_t outcap)
{
    size_t end = before;
    size_t start;
    size_t n;
    while (end > 0 && (s[end - 1] == ' ' || s[end - 1] == '\t'))
        end--;
    start = end;
    while (start > 0 && drv_ident_char((unsigned char)s[start - 1]))
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

/* A4 (DS-04): ekstrak return type dari teks signature — token (bisa
 * multi-kata + '*') tepat sebelum nama fungsi (open_paren = posisi '(').
 * Normalisasi: spasi ganda diratakan, spasi di sekitar '*' dihilangkan
 * ("const char *" -> "const char*"). */
static void drv_ret_type_before(const char *s, size_t open_paren,
                                char *out, size_t outcap)
{
    size_t pos = open_paren;
    size_t start, k;
    size_t n;
    while (pos > 0 && (s[pos - 1] == ' ' || s[pos - 1] == '\t'))
        pos--;                                /* lewati spasi sebelum '(' */
    while (pos > 0 && drv_ident_char((unsigned char)s[pos - 1]))
        pos--;                                /* lewati nama fungsi */
    while (pos > 0 && (s[pos - 1] == ' ' || s[pos - 1] == '\t'))
        pos--;                                /* spasi antara tipe & nama */
    start = pos;
    while (start > 0) {
        char c = s[start - 1];
        if (c == '*' || drv_ident_char((unsigned char)c)) {
            start--;
        } else if (c == ' ' || c == '\t') {
            size_t t = start;
            while (t > 0 && (s[t - 1] == ' ' || s[t - 1] == '\t'))
                t--;
            if (t > 0 && drv_ident_char((unsigned char)s[t - 1]))
                start = t;   /* kata lain: lanjut (mis. "unsigned long") */
            else
                break;
        } else
            break;
    }
    while (start < pos && (s[start] == ' ' || s[start] == '\t'))
        start++;
    n = pos - start;
    if (n >= outcap)
        n = outcap - 1;
    /* salin + normalisasi: buang spasi yang berdampingan dengan '*' */
    {
        size_t w = 0;
        int    prev_star = 0;
        for (k = 0; k < n && w + 1 < outcap; k++) {
            char c = s[start + k];
            if (c == ' ') {
                if (w > 0 && out[w - 1] != ' ' && !prev_star)
                    out[w++] = ' ';
                prev_star = 0;
            } else if (c == '*') {
                if (w > 0 && out[w - 1] == ' ')
                    w--;
                out[w++] = '*';
                prev_star = 1;
            } else {
                out[w++] = c;
                prev_star = 0;
            }
        }
        if (w > 0 && out[w - 1] == ' ')
            w--;
        out[w] = '\0';
    }
}

/* ------------------------------------------------------------------ */
/* Struktur fungsi ber-kontrak yang di-parse                           */
/* ------------------------------------------------------------------ */

typedef struct {
    char  name[DRV_MAX_LEN];
    char  type[DRV_MAX_PARAMS][DRV_MAX_LEN];   /* teks tipe (tanpa nama) */
    char  pname[DRV_MAX_PARAMS][DRV_MAX_LEN];
    int   is_ptr[DRV_MAX_PARAMS];
    int   elem[DRV_MAX_PARAMS];                /* ukuran elemen pointer */
    int   nparams;
    char  reqs[DRV_MAX_REQS][512];
    int   nreqs;
    int   unsupported;                         /* 1 = lewati fungsi ini */
    /* A4 (--compare, DS-04): return type hasil ekstraksi signature. */
    char  ret[DRV_MAX_LEN];                    /* teks return type */
    int   ret_void;                            /* return type = void */
    int   ret_ptr;                             /* return type pointer */
} drv_func;

/* Daftar batas integer hasil parse requires. */
typedef struct {
    long lo, hi;
    int  has_lo, has_hi;
} drv_bounds;

/* Tambah nilai ke daftar kandidat (dedup, batas DRV_MAX_CANDS).
 * v bertipe long long agar guard range (jaga ukuran literal) bermakna di
 * semua platform (long 32-bit di Windows -> perbandingan 0x7FFFFFFFLL
 * selalu false = warning -Wtype-limits bila v long). */
static void cand_add(long *cands, int *nc, long long v)
{
    int i;
    if (v < -0x7FFFFFFFLL || v > 0x7FFFFFFFLL)   /* jaga ukuran literal */
        return;
    for (i = 0; i < *nc; i++)
        if (cands[i] == (long)v)
            return;
    if (*nc < DRV_MAX_CANDS)
        cands[(*nc)++] = (long)v;
}

/* Terapkan `name OP N` ke bounds. */
static void apply_op(const char *op, long n, drv_bounds *bd)
{
    if (strcmp(op, "<") == 0) {
        bd->has_hi = 1;
        if (!bd->has_lo || n - 1 >= bd->lo)
            bd->hi = n - 1;
    } else if (strcmp(op, "<=") == 0) {
        bd->has_hi = 1;
        if (!bd->has_lo || n >= bd->lo)
            bd->hi = n;
    } else if (strcmp(op, ">") == 0) {
        bd->has_lo = 1;
        if (!bd->has_hi || n + 1 <= bd->hi)
            bd->lo = n + 1;
    } else if (strcmp(op, ">=") == 0) {
        bd->has_lo = 1;
        if (!bd->has_hi || n <= bd->hi)
            bd->lo = n;
    } else if (strcmp(op, "==") == 0) {
        bd->has_lo = 1;
        bd->has_hi = 1;
        bd->lo = n;
        bd->hi = n;
    } else if (strcmp(op, "!=") == 0 && n == 0) {
        bd->has_lo = 1;          /* name != 0 -> lo = 1 */
        if (!bd->has_hi || 1 <= bd->hi)
            bd->lo = 1;
    }
}

/* Terapkan `N OP name` (terbalik) ke bounds. */
static void apply_op_rev(const char *op, long n, drv_bounds *bd)
{
    if (strcmp(op, "<") == 0) {          /* N < name -> name > N */
        bd->has_lo = 1;
        if (!bd->has_hi || n + 1 <= bd->hi)
            bd->lo = n + 1;
    } else if (strcmp(op, "<=") == 0) {  /* N <= name -> name >= N */
        bd->has_lo = 1;
        if (!bd->has_hi || n <= bd->hi)
            bd->lo = n;
    } else if (strcmp(op, ">") == 0) {   /* N > name -> name < N */
        bd->has_hi = 1;
        if (!bd->has_lo || n - 1 >= bd->lo)
            bd->hi = n - 1;
    } else if (strcmp(op, ">=") == 0) {  /* N >= name -> name <= N */
        bd->has_hi = 1;
        if (!bd->has_lo || n >= bd->lo)
            bd->hi = n;
    } else if (strcmp(op, "==") == 0) {
        bd->has_lo = 1;
        bd->has_hi = 1;
        bd->lo = n;
        bd->hi = n;
    } else if (strcmp(op, "!=") == 0 && n == 0) {
        bd->has_lo = 1;
        if (!bd->has_hi || 1 <= bd->hi)
            bd->lo = 1;
    }
}

/* Parse batas integer untuk `name` dari satu ekspresi requires.
 * Mencari pola `name OP N` dan `N OP name` (OP: <, <=, >, >=, ==, !=). */
static void parse_bound(const char *expr, const char *name, drv_bounds *bd)
{
    size_t elen = strlen(expr);
    size_t nlen = strlen(name);
    size_t i;
    for (i = 0; i < elen; i++) {
        char  op[3] = { 0, 0, 0 };
        size_t k = 0;
        long  n;
        if (expr[i] == '<' || expr[i] == '>') {
            op[k++] = expr[i];
            if (i + 1 < elen && expr[i + 1] == '=')
                op[k++] = '=';
        } else if (expr[i] == '=' && i + 1 < elen && expr[i + 1] == '=') {
            op[0] = '=';
            op[1] = '=';
            k = 2;
        } else if (expr[i] == '!' && i + 1 < elen && expr[i + 1] == '=') {
            op[0] = '!';
            op[1] = '=';
            k = 2;
        } else {
            continue;
        }

        /* name di kiri operator: `name OP N` */
        {
            size_t l = i, r;
            while (l > 0 && (expr[l - 1] == ' ' || expr[l - 1] == '\t'))
                l--;
            r = l;
            while (r > 0 && drv_ident_char((unsigned char)expr[r - 1]))
                r--;
            if (r < l && l - r == nlen && memcmp(expr + r, name, nlen) == 0) {
                size_t j = i + k;
                while (j < elen && (expr[j] == ' ' || expr[j] == '\t'))
                    j++;
                if (j < elen && expr[j] == '-' && j + 1 < elen &&
                    isdigit((unsigned char)expr[j + 1])) {
                    n = strtol(expr + j + 1, NULL, 10);
                    apply_op(op, -n, bd);
                } else if (j < elen && isdigit((unsigned char)expr[j])) {
                    n = strtol(expr + j, NULL, 10);
                    apply_op(op, n, bd);
                }
            }
        }

        /* name di kanan operator: `N OP name` */
        {
            size_t j = i + k;
            size_t start = j;
            while (j < elen && (expr[j] == ' ' || expr[j] == '\t'))
                j++;
            start = j;
            while (j < elen && drv_ident_char((unsigned char)expr[j]))
                j++;
            if (j - start == nlen && memcmp(expr + start, name, nlen) == 0) {
                size_t e = i;
                size_t s = e;
                while (s > 0 && (expr[s - 1] == ' ' || expr[s - 1] == '\t'))
                    s--;
                e = s;
                while (s > 0 && isdigit((unsigned char)expr[s - 1]))
                    s--;
                if (s < e) {
                    char num[64];
                    size_t nl = e - s;
                    if (nl >= sizeof(num))
                        nl = sizeof(num) - 1;
                    memcpy(num, expr + s, nl);
                    num[nl] = '\0';
                    n = strtol(num, NULL, 10);
                    apply_op_rev(op, n, bd);
                }
            }
        }
        i += k - 1;
    }
}

/* ------------------------------------------------------------------ */
/* Combinatorial budget (roadmap 7.5)                                  */
/* ------------------------------------------------------------------ */

/* Satu kombinasi parameter (indeks ke daftar kandidat tiap param). */
typedef struct {
    unsigned char idx[DRV_MAX_PARAMS];
} drv_combo;

/* Metadata kasus per fungsi: kombinasi yang dibangkitkan + info untuk
 * membangun case record (nama fungsi, nama parameter, alokasi buffer). */
typedef struct {
    char  func[DRV_MAX_LEN];
    char  pname[DRV_MAX_PARAMS][DRV_MAX_LEN];
    int   is_ptr[DRV_MAX_PARAMS];
    long  psize[DRV_MAX_PARAMS];     /* bytes utk pointer (0 utk scalar) */
    long  cands[DRV_MAX_PARAMS][DRV_MAX_CANDS]; /* nilai kandidat scalar */
    int   nc[DRV_MAX_PARAMS];
    int   nparams;
    drv_combo combos[DRV_MAX_CASES];
    int   ncombos;
    long  product;                   /* produk kartesian penuh (sebelum budget) */
    int   bounded;                   /* 1 = budget memotong (coverage-first) */
} drv_case_meta;

/* Bangun daftar kombinasi dari daftar kandidat per parameter dengan
 * BUDGET deterministik (combinatorial budget, roadmap 7.5):
 *   - Bila produk kartesian <= maxcases: SEMUA kombinasi (full cartesian).
 *   - Bila produk > maxcases: coverage-first — pastikan setiap nilai
 *     kandidat dari setiap parameter muncul di minimal satu kasus
 *     (base + one-per-extra-value), lalu isi sisa budget dengan kombinasi
 *     leksikografis yang belum ada. Strategi di-laporkan (meta->bounded). */
static int build_combos(const int *nc, int nparams, drv_combo *out, int maxcases,
                        long *product_out, int *bounded_out)
{
    long product = 1;
    int  p, i;
    int  count = 0;
    for (p = 0; p < nparams; p++)
        product *= (long)nc[p];
    if (product_out)
        *product_out = product;
    if (bounded_out)
        *bounded_out = 0;

    if (product <= (long)maxcases) {
        long k;
        for (k = 0; k < product && count < maxcases; k++) {
            long rem = k;
            drv_combo c;
            memset(&c, 0, sizeof(c));
            for (p = 0; p < nparams; p++) {
                c.idx[p] = (unsigned char)(rem % nc[p]);
                rem /= nc[p];
            }
            out[count++] = c;
        }
        return count;
    }

    if (bounded_out)
        *bounded_out = 1;

    /* coverage-first: base (semua nilai kandidat pertama) */
    {
        drv_combo c;
        memset(&c, 0, sizeof(c));
        out[count++] = c;
    }
    /* setiap nilai kandidat tambahan dari tiap parameter */
    for (p = 0; p < nparams && count < maxcases; p++) {
        for (i = 1; i < nc[p] && count < maxcases; i++) {
            drv_combo c;
            memset(&c, 0, sizeof(c));
            c.idx[p] = (unsigned char)i;
            out[count++] = c;
        }
    }
    /* filler: kombinasi leksikografis yang belum ada, sampai budget */
    if (count < maxcases) {
        long k;
        for (k = 0; k < product && count < maxcases; k++) {
            long rem = k;
            drv_combo c;
            int  j;
            int  dup = 0;
            memset(&c, 0, sizeof(c));
            for (p = 0; p < nparams; p++) {
                c.idx[p] = (unsigned char)(rem % nc[p]);
                rem /= nc[p];
            }
            for (j = 0; j < count; j++) {
                int q;
                for (q = 0; q < nparams; q++)
                    if (out[j].idx[q] != c.idx[q])
                        break;
                if (q == nparams) {
                    dup = 1;
                    break;
                }
            }
            if (!dup)
                out[count++] = c;
        }
    }
    return count;
}

/* ------------------------------------------------------------------ */
/* Scan fungsi ber-kontrak                                            */
/* ------------------------------------------------------------------ */

static int is_scalar_type(const char *t)
{
    static const char *const scalars[] = {
        "int", "char", "short", "long", "float", "double", "unsigned",
        "signed", "size_t", "ssize_t", "int8_t", "int16_t", "int32_t",
        "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "bool", "_Bool", NULL
    };
    int i;
    for (i = 0; scalars[i]; i++)
        if (strstr(t, scalars[i]))
            return 1;
    return 0;
}

/* Tentukan nama parameter dan tipe dari teks parameter (mis. "const int *a").
 * Teks sudah dipotong spasi. Menulis type/pname/is_ptr/elem. */
static void parse_param_text(const char *ptext, char *type, size_t typecap,
                             char *pname, size_t namecap, int *is_ptr,
                             int *elem)
{
    size_t len = strlen(ptext);
    size_t i, name_end, name_start;
    char   tbuf[DRV_MAX_LEN];

    *is_ptr = (strchr(ptext, '*') != NULL) || (strchr(ptext, '[') != NULL);

    /* cari nama = identifier terakhir (atau sebelum '[' untuk array) */
    name_end = len;
    /* array: nama sebelum '[' */
    {
        const char *br = strchr(ptext, '[');
        if (br)
            name_end = (size_t)(br - ptext);
    }
    i = name_end;
    while (i > 0 && (ptext[i - 1] == ' ' || ptext[i - 1] == '\t'))
        i--;
    name_end = i;
    name_start = name_end;
    while (name_start > 0 && drv_ident_char((unsigned char)ptext[name_start - 1]))
        name_start--;
    if (name_start == name_end) {
        strcpy(pname, "");
        strcpy(type, ptext);
        *elem = 4;
        return;
    }
    {
        size_t n = name_end - name_start;
        if (n >= namecap)
            n = namecap - 1;
        memcpy(pname, ptext + name_start, n);
        pname[n] = '\0';
    }
    /* tipe = bagian sebelum nama (trim kanan), PERTAHANKAN '*' pada
     * pointer (mis. "const int *a" -> "const int *"). Untuk parameter
     * array tanpa '*' ("int buf[8]") tambahkan '*' karena array meluruh
     * ke pointer saat pemanggilan. Clamp tl ke typecap-2 pada cabang
     * "%s*" agar snprintf tidak ter-truncate (-Wformat-truncation). */
    {
        size_t tl = name_start;
        while (tl > 0 && (ptext[tl - 1] == ' ' || ptext[tl - 1] == '\t'))
            tl--;
        if (*is_ptr && strchr(ptext, '[') && strchr(ptext, '*') == NULL) {
            if (tl >= typecap)
                tl = typecap - 1;
            if (tl >= 1 && typecap >= 2)
                tl = tl > typecap - 2 ? typecap - 2 : tl;
        } else {
            if (tl >= typecap)
                tl = typecap - 1;
        }
        memcpy(tbuf, ptext, tl);
        tbuf[tl] = '\0';
        if (*is_ptr && strchr(ptext, '[') && strchr(ptext, '*') == NULL)
            snprintf(type, typecap, "%s*", tbuf);   /* "int buf[8]" -> "int *" */
        else
            snprintf(type, typecap, "%s", tbuf);    /* pertahankan "*" pointer */
    }
    /* ukuran elemen pointer: kenali tipe lebar eksplisit (_t) dan long long
     * sebelum default; long = sizeof(long) (4 di Windows, 8 di Linux).
     * Salah ukur di sini => buffer harness salah: int64_t dikecilkan (4)
     * => false DRIVER_VIOLATION pada kode sah; long dibesarkan (8 di
     * Windows) => bug OOB pada array long bisa lolos. */
    *elem = 4;
    if (strstr(type, "int64_t") || strstr(type, "uint64_t") ||
        strstr(type, "long long") || strstr(type, "double"))
        *elem = 8;
    else if (strstr(type, "int32_t") || strstr(type, "uint32_t"))
        *elem = 4;
    else if (strstr(type, "int16_t") || strstr(type, "uint16_t") ||
             strstr(type, "short"))
        *elem = 2;
    else if (strstr(type, "int8_t") || strstr(type, "uint8_t") ||
             strstr(type, "char"))
        *elem = 1;
    else if (strstr(type, "long"))
        *elem = (int)sizeof(long);
}

/* Parse daftar parameter (teks di antara kurung) ke f. Menandai
 * f->unsupported bila ada parameter yang tidak bisa dipanggil aman. */
static void parse_params(const char *ptext, size_t plen, drv_func *f)
{
    size_t i = 0;
    int    depth = 0;
    char   cur[DRV_MAX_LEN];
    size_t clen = 0;
    f->nparams = 0;

    while (i < plen) {
        char c = ptext[i];
        if (c == '(' || c == '[') {
            depth++;
        } else if (c == ')' || c == ']') {
            if (depth > 0)
                depth--;
        } else if (c == ',' && depth == 0) {
            if (clen > 0 && f->nparams < DRV_MAX_PARAMS) {
                /* trim */
                size_t a = 0, b = clen;
                while (a < b && (cur[a] == ' ' || cur[a] == '\t'))
                    a++;
                while (b > a && (cur[b - 1] == ' ' || cur[b - 1] == '\t'))
                    b--;
                if (b - a > 0 && !(b - a == 4 && memcmp(cur + a, "void", 4) == 0)) {
                    char tmp[DRV_MAX_LEN];
                    size_t n = b - a;
                    if (n >= sizeof(tmp))
                        n = sizeof(tmp) - 1;
                    memcpy(tmp, cur + a, n);
                    tmp[n] = '\0';
                    parse_param_text(tmp, f->type[f->nparams],
                                     sizeof(f->type[f->nparams]),
                                     f->pname[f->nparams],
                                     sizeof(f->pname[f->nparams]),
                                     &f->is_ptr[f->nparams],
                                     &f->elem[f->nparams]);
                    if (!f->is_ptr[f->nparams] &&
                        !is_scalar_type(f->type[f->nparams]))
                        f->unsupported = 1;    /* struct by value dll */
                    f->nparams++;
                }
            }
            clen = 0;
        } else {
            if (clen < sizeof(cur) - 1)
                cur[clen++] = c;
        }
        i++;
    }
    if (clen > 0 && f->nparams < DRV_MAX_PARAMS) {
        size_t a = 0, b = clen;
        while (a < b && (cur[a] == ' ' || cur[a] == '\t'))
            a++;
        while (b > a && (cur[b - 1] == ' ' || cur[b - 1] == '\t'))
            b--;
        if (b - a > 0 && !(b - a == 4 && memcmp(cur + a, "void", 4) == 0)) {
            char tmp[DRV_MAX_LEN];
            size_t n = b - a;
            if (n >= sizeof(tmp))
                n = sizeof(tmp) - 1;
            memcpy(tmp, cur + a, n);
            tmp[n] = '\0';
            parse_param_text(tmp, f->type[f->nparams],
                             sizeof(f->type[f->nparams]),
                             f->pname[f->nparams],
                             sizeof(f->pname[f->nparams]),
                             &f->is_ptr[f->nparams],
                             &f->elem[f->nparams]);
            if (!f->is_ptr[f->nparams] && !is_scalar_type(f->type[f->nparams]))
                f->unsupported = 1;
            f->nparams++;
        }
    }
}

/* Scan source; isi funcs[] dengan fungsi ber-kontrak. Return jumlah. */
static int scan_contract_funcs(const char *src, size_t len, drv_func *funcs,
                               int maxfuncs)
{
    drv_func cur;
    int      nf = 0;
    size_t   i = 0;
    int      depth = 0;
    int      sig_closed = 0;
    int      has_pending = 0;
    int      pending_n = 0;
    size_t   open_paren = 0;

    memset(&cur, 0, sizeof(cur));

    while (i < len) {
        char c = src[i];

        if (c == '/' && i + 1 < len && src[i + 1] == '/') {
            size_t line_end = i;
            while (line_end < len && src[line_end] != '\n')
                line_end++;
            if (i + 2 < len && src[i + 2] == '@') {
                size_t j = i + 3;
                char   kw[32];
                size_t kwend;
                while (j < line_end && (src[j] == ' ' || src[j] == '\t'))
                    j++;
                kwend = j;          /* baca keyword SETELAH spasi dilompati */
                while (kwend < line_end &&
                       drv_ident_char((unsigned char)src[kwend]))
                    kwend++;
                {
                    size_t n = kwend - j;
                    if (n >= sizeof(kw))
                        n = sizeof(kw) - 1;
                    memcpy(kw, src + j, n);
                    kw[n] = '\0';
                }
                if (strcmp(kw, "requires") == 0) {
                    /* ekspresi = sisa baris sampai ';' */
                    size_t a = kwend, b = line_end;
                    while (a < b && (src[a] == ' ' || src[a] == '\t'))
                        a++;
                    while (b > a && (src[b - 1] == ' ' || src[b - 1] == '\t'))
                        b--;
                    if (b > a && src[b - 1] == ';')
                        b--;
                    while (b > a && (src[b - 1] == ' ' || src[b - 1] == '\t'))
                        b--;
                    if (b > a && pending_n < DRV_MAX_REQS) {
                        size_t n = b - a;
                        if (n >= sizeof(cur.reqs[pending_n]))
                            n = sizeof(cur.reqs[pending_n]) - 1;
                        memcpy(cur.reqs[pending_n], src + a, n);
                        cur.reqs[pending_n][n] = '\0';
                        pending_n++;
                        has_pending = 1;
                    }
                }
            }
            i = line_end;
            if (i < len && src[i] == '\n')
                i++;
            continue;
        }

        if (c == '/' && i + 1 < len && src[i + 1] == '*') {
            size_t end = i + 2;
            while (end + 1 < len && !(src[end] == '*' && src[end + 1] == '/'))
                end++;
            if (end + 1 < len)
                end += 2;
            i = end;
            continue;
        }

        if (c == '"' || c == '\'') {
            char q = c;
            size_t j = i + 1;
            while (j < len) {
                if (src[j] == '\\' && j + 1 < len)
                    j += 2;
                else if (src[j] == q) {
                    j++;
                    break;
                } else
                    j++;
            }
            i = j;
            continue;
        }

        if (c == '(') {
            if (depth == 0 && has_pending && !sig_closed)
                open_paren = i;
            depth++;
        } else if (c == ')') {
            if (depth > 0)
                depth--;
            if (depth == 0)
                sig_closed = 1;
        } else if (c == '{') {
            if (depth == 0 && has_pending && sig_closed) {
                /* fungsi ber-kontrak ditemukan */
                if (nf < maxfuncs) {
                    char name[DRV_MAX_LEN];
                    size_t close_paren = open_paren + 1;
                    drv_func f;
                    /* cari ')' penutup daftar parameter */
                    {
                        int d = 1;
                        size_t k = open_paren + 1;
                        while (k < len && d > 0) {
                            if (src[k] == '(')
                                d++;
                            else if (src[k] == ')')
                                d--;
                            if (d > 0)
                                k++;
                        }
                        close_paren = k;
                    }
                    memset(&f, 0, sizeof(f));
                    drv_ident_before(src, open_paren, name, sizeof(name));
                    snprintf(f.name, sizeof(f.name), "%s", name);
                    /* A4 (DS-04): return type untuk ABI signature escrow. */
                    drv_ret_type_before(src, open_paren, f.ret,
                                        sizeof(f.ret));
                    if (strstr(f.ret, "*"))
                        f.ret_ptr = 1;
                    else if (strcmp(f.ret, "void") == 0)
                        f.ret_void = 1;
                    parse_params(src + open_paren + 1,
                                 close_paren > open_paren + 1
                                     ? close_paren - open_paren - 1 : 0,
                                 &f);
                    f.nreqs = pending_n;
                    if (f.nreqs > DRV_MAX_REQS)
                        f.nreqs = DRV_MAX_REQS;
                    /* Salin ekspresi requires dari `cur` ke `f` (f di-memset
                     * nol, jadi reqs[]-nya kosong walau nreqs sudah benar). */
                    {
                        int r;
                        for (r = 0; r < f.nreqs; r++) {
                            size_t rn = strlen(cur.reqs[r]);
                            if (rn >= sizeof(f.reqs[r]))
                                rn = sizeof(f.reqs[r]) - 1;
                            memcpy(f.reqs[r], cur.reqs[r], rn);
                            f.reqs[r][rn] = '\0';
                        }
                    }
                    funcs[nf] = f;
                    nf++;
                }
                has_pending = 0;
                pending_n = 0;
                sig_closed = 0;
            }
        } else if (c == '}') {
            if (depth == 0) {
                sig_closed = 0;
                has_pending = 0;
                pending_n = 0;
            }
        } else if (c == ';') {
            if (depth == 0) {
                sig_closed = 0;
                has_pending = 0;
                pending_n = 0;
            }
        }
        i++;
    }
    return nf;
}

/* ------------------------------------------------------------------ */
/* Generate harness                                                   */
/* ------------------------------------------------------------------ */

/* Bangun daftar kandidat nilai untuk satu parameter integer. */
static void build_candidates(const drv_func *f, int pi, long *cands, int *nc)
{
    drv_bounds bd;
    long mid;
    int  i;
    memset(&bd, 0, sizeof(bd));
    for (i = 0; i < f->nreqs; i++)
        parse_bound(f->reqs[i], f->pname[pi], &bd);
    if (!bd.has_lo)
        bd.lo = 0;             /* default non-negatif: hindari false pos */
    *nc = 0;
    cand_add(cands, nc, bd.lo);
    if (bd.has_lo)
        cand_add(cands, nc, bd.lo + 1);
    if (bd.has_hi && bd.hi >= bd.lo) {
        cand_add(cands, nc, bd.hi);
        if (bd.hi - 1 >= bd.lo)
            cand_add(cands, nc, bd.hi - 1);
        mid = (bd.lo + bd.hi) / 2;
        if (mid > bd.lo && mid < bd.hi)
            cand_add(cands, nc, mid);
    }
    cand_add(cands, nc, 1);
    cand_add(cands, nc, 2);
    cand_add(cands, nc, 3);
    if (*nc == 0)
        cand_add(cands, nc, 0);
}

/* Generate teks harness lengkap (source asli + main baru). */
static char *gen_harness(const char *src, size_t srclen,
                         const drv_func *funcs, int nfuncs,
                         size_t *out_len,
                         drv_case_meta *meta, int maxmeta, int *nmeta)
{
    drv_buf b;
    int     f;
    int     gid = 0;    /* case_id global lintas fungsi (roadmap 7.5) */
    memset(&b, 0, sizeof(b));
    if (nmeta)
        *nmeta = 0;

    drv_buf_puts(&b, "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n");
    drv_buf_puts(&b, "#define main myc_driver_orig_main\n");
    drv_buf_putn(&b, src, srclen);
    drv_buf_puts(&b, "\n#undef main\n\n");
    drv_buf_puts(&b, "static int drv_run = 0;\n");
    drv_buf_puts(&b, "static int drv_skip = 0;\n\n");
    drv_buf_puts(&b, "int main(void) {\n");
    /* Flush per baris: marker per-case harus sampai ke parent WALAUPUN
     * sanitizer meng-abort proses di tengah run (stdout bertipe pipe
     * fully-buffered secara default; tanpa ini semua marker hilang saat
     * abort dan record per-case salah tampil 'skip'). */
    drv_buf_puts(&b, "    setvbuf(stdout, NULL, _IONBF, 0);\n");

    for (f = 0; f < nfuncs; f++) {
        const drv_func *fn = &funcs[f];
        long cands[DRV_MAX_PARAMS][DRV_MAX_CANDS];
        int  nc[DRV_MAX_PARAMS];
        long psize[DRV_MAX_PARAMS];
        drv_combo combos[DRV_MAX_CASES];
        long product = 1;
        int  bounded = 0;
        int  ncombos = 0;
        int  p, ci;
        if (fn->unsupported || fn->nreqs == 0 || fn->name[0] == '\0')
            continue;
        /* Ukuran buffer pointer memakai batas MAKSIMUM di seluruh parameter
         * (mis. kontrak "n <= 4" mengikat buffer "a" walau ekspresi tidak
         * menyebut nama "a"), bukan hanya batas pada nama pointer itu.
         * Tanpa ini, bad_driver_oob (a[4] pada kontrak n<=4) tidak akan
         * terdeteksi: buffer dibuat terlalu besar (8*elem default). */
        {
            /* max_hi = batas ATAS terbesar yang ditemukan di seluruh
             * parameter. Default 8 HANYA dipakai bila tidak ada batas
             * sama sekali (mis. kontrak hanya "a != NULL"); bila ada
             * batas (mis. "n <= 4") pakai nilai itu, JANGAN di-unggulkan
             * ke 8 -- kalau tidak, buffer dibuat terlalu besar dan bug
             * OOB di dalam domain kontrak (a[4] pada n<=4) lolos. */
            long max_hi = 0;
            int  have_hi = 0;
            int  pp, ii;
            for (pp = 0; pp < fn->nparams; pp++) {
                drv_bounds bd;
                memset(&bd, 0, sizeof(bd));
                for (ii = 0; ii < fn->nreqs; ii++)
                    parse_bound(fn->reqs[ii], fn->pname[pp], &bd);
                if (bd.has_hi) {
                    if (!have_hi || bd.hi > max_hi)
                        max_hi = bd.hi;
                    have_hi = 1;
                }
            }
            if (!have_hi)
                max_hi = 8;
            if (max_hi < 1)
                max_hi = 1;
            for (p = 0; p < fn->nparams; p++) {
                psize[p] = fn->is_ptr[p] ? max_hi * fn->elem[p] : 0;
                if (psize[p] > DRV_BUF_CAP)
                    psize[p] = DRV_BUF_CAP;
                if (psize[p] < 1)
                    psize[p] = 1;
            }
        }
        for (p = 0; p < fn->nparams; p++) {
            if (fn->is_ptr[p]) {
                nc[p] = 1;
                cands[p][0] = 0;
            } else {
                build_candidates(fn, p, cands[p], &nc[p]);
            }
            if (nc[p] < 1)
                nc[p] = 1;
        }
        /* combinatorial budget (roadmap 7.5): produk kartesian dibatasi
         * budget deterministik dengan jaminan tiap nilai kandidat muncul. */
        ncombos = build_combos(nc, fn->nparams, combos, DRV_MAX_CASES,
                               &product, &bounded);
        if (ncombos < 1)
            ncombos = 1;

        /* simpan metadata untuk case record (hanya N pertama fungsi) */
        if (meta && nmeta && *nmeta < maxmeta) {
            drv_case_meta *m = &meta[*nmeta];
            int  mp;
            int  ci;
            int  i;
            memset(m, 0, sizeof(*m));
            {
                size_t nlen = strlen(fn->name);
                if (nlen >= sizeof(m->func))
                    nlen = sizeof(m->func) - 1;
                memcpy(m->func, fn->name, nlen);
                m->func[nlen] = '\0';
            }
            m->nparams = fn->nparams;
            m->ncombos = ncombos;
            m->product = product;
            m->bounded = bounded;
            for (mp = 0; mp < fn->nparams; mp++) {
                size_t plen = strlen(fn->pname[mp]);
                if (plen >= sizeof(m->pname[mp]))
                    plen = sizeof(m->pname[mp]) - 1;
                memcpy(m->pname[mp], fn->pname[mp], plen);
                m->pname[mp][plen] = '\0';
                m->is_ptr[mp] = fn->is_ptr[mp];
                m->psize[mp] = psize[mp];
                m->nc[mp] = nc[mp];
                for (i = 0; i < nc[mp]; i++)
                    m->cands[mp][i] = cands[mp][i];
                m->combos[0].idx[mp] = combos[0].idx[mp];
            }
            for (ci = 0; ci < ncombos; ci++)
                for (mp = 0; mp < fn->nparams; mp++)
                    m->combos[ci].idx[mp] = combos[ci].idx[mp];
            (*nmeta)++;
        }

        for (ci = 0; ci < ncombos; ci++) {
            long v[DRV_MAX_PARAMS];
            int  p;
            gid++;
            for (p = 0; p < fn->nparams; p++) {
                if (fn->is_ptr[p]) {
                    v[p] = psize[p];
                } else {
                    v[p] = cands[p][combos[ci].idx[p]];
                }
            }
            drv_buf_puts(&b, "    {\n");
            for (p = 0; p < fn->nparams; p++) {
                if (fn->is_ptr[p]) {
                    drv_buf_printf(&b, "        %s %s = (%s)calloc(%ld, 1);\n",
                                   fn->type[p], fn->pname[p],
                                   fn->type[p], v[p]);
                } else {
                    drv_buf_printf(&b, "        %s %s = %ld;\n",
                                   fn->type[p], fn->pname[p], v[p]);
                }
            }
            /* guard: pointer non-NULL && semua requires */
            drv_buf_puts(&b, "        if (");
            {
                int first = 1;
                int r;
                for (p = 0; p < fn->nparams; p++) {
                    if (fn->is_ptr[p]) {
                        if (!first)
                            drv_buf_puts(&b, " && ");
                        drv_buf_printf(&b, "%s != NULL", fn->pname[p]);
                        first = 0;
                    }
                }
                for (r = 0; r < fn->nreqs; r++) {
                    if (!first)
                        drv_buf_puts(&b, " && ");
                    drv_buf_printf(&b, "(%s)", fn->reqs[r]);
                    first = 0;
                }
                if (first)
                    drv_buf_puts(&b, "1");
            }
            drv_buf_printf(&b, ") {\n            drv_run++;\n");
            drv_buf_printf(&b, "            printf(\"DRIVER case=%d run\\n\", %d);\n",
                           gid, gid);
            drv_buf_puts(&b, "            (void)");
            drv_buf_puts(&b, fn->name);
            drv_buf_puts(&b, "(");
            for (p = 0; p < fn->nparams; p++) {
                if (p)
                    drv_buf_puts(&b, ", ");
                drv_buf_puts(&b, fn->pname[p]);
            }
            drv_buf_puts(&b, ");\n        } else {\n");
            drv_buf_printf(&b, "            drv_skip++;\n");
            drv_buf_printf(&b, "            printf(\"DRIVER case=%d skip\\n\", %d);\n",
                           gid, gid);
            drv_buf_puts(&b, "        }\n");
            for (p = 0; p < fn->nparams; p++) {
                if (fn->is_ptr[p])
                    drv_buf_printf(&b, "        free((void*)%s);\n", fn->pname[p]);
            }
            drv_buf_puts(&b, "    }\n");
        }
    }
    drv_buf_puts(&b, "    printf(\"DRIVER run=%d skip=%d\\n\", drv_run, drv_skip);\n");
    drv_buf_puts(&b, "    return drv_run == 0 ? 3 : 0;\n");
    drv_buf_puts(&b, "}\n");

    if (!b.data)
        return NULL;
    *out_len = b.len;
    return b.data;
}

/* ------------------------------------------------------------------ */
/* Build + run (pola sama dengan gate run P6)                          */
/* ------------------------------------------------------------------ */

static void add_diag_drv(myc_result *res, const char *msg)
{
    char *slot;
    if (res->diag_count >= MYC_MAX_DIAGNOSTICS)
        return;
    slot = myc_result_arena_dup(res, msg, 0);
    if (!slot)
        return;
    res->diags[res->diag_count].line = 0;
    res->diags[res->diag_count].col = 0;
    res->diags[res->diag_count].message = slot;
    /* fakta eksekusi/sanitizer harness = bukti semantik (MYC-AUDIT-014) */
    res->diags[res->diag_count].confidence = MYC_CONF_CONFIRMED;
    res->diag_count++;
}

static char *drv_join_path(const char *dir, const char *name)
{
    size_t dl = strlen(dir);
    size_t nl = strlen(name);
    char  *out = (char *)malloc(dl + 1 + nl + 1);
    if (!out)
        return NULL;
    memcpy(out, dir, dl);
    out[dl] = '/';
    memcpy(out + dl + 1, name, nl);
    out[dl + 1 + nl] = '\0';
    return out;
}

static char *drv_make_temp_dir(void)
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
    /* Base relatif -> canonicalize via getcwd agar path absolut. MYC-AUDIT-003:
     * tanpo ini exe_path relatif ("myc_drv/...") rusak setelah child
     * chdir(tmp_dir) -- run gate L3 jalan di POSIX, driver gagal "exec failed". */
    if (base[0] != '/' && !(base[0] && base[1] == ':')) {
        if (my_getcwd(cwdbuf, sizeof(cwdbuf))) {
            base = cwdbuf;
        }
    }
    bl = strlen(base);
    while (n < 100) {
        char   buf[32];
        size_t need;
        dir = (char *)malloc(bl + 1 + 32);
        if (!dir)
            return NULL;
        snprintf(buf, sizeof(buf), "myc_drv_%lu_%d",
                 (unsigned long)myc_getpid(), n);
        need = bl + 1 + strlen(buf) + 1;
        snprintf(dir, need, "%s/%s", base, buf);
        if (myc_mkdir(dir) == 0)
            return dir;
        free(dir);
        n++;
    }
    return NULL;
}

#ifdef _WIN32
static int drv_copy_file(const char *src, const char *dst)
{
    FILE *f = fopen(src, "rb");
    FILE *g;
    char  buf[65536];
    size_t rd;
    if (!f)
        return 0;
    g = fopen(dst, "wb");
    if (!g) {
        fclose(f);
        return 0;
    }
    while ((rd = fread(buf, 1, sizeof(buf), f)) > 0)
        fwrite(buf, 1, rd, g);
    fclose(f);
    fclose(g);
    return 1;
}

static char *drv_asan_dll_path(const char *clang_path)
{
    const char *argv_use[3];
    myc_proc_request preq;
    myc_proc_result  pres;
    char            *out = NULL;
    char            *nl;
    size_t           len;
    argv_use[0] = clang_path;
    argv_use[1] = "-print-file-name=" ASAN_DLL_NAME;
    argv_use[2] = NULL;
    memset(&preq, 0, sizeof(preq));
    preq.argv = argv_use;
    preq.timeout_ms = 15000;
    preq.max_output_bytes = 65536;
    if (!myc_proc_run(&preq, &pres))
        return NULL;
    if (!pres.stdout_data || !pres.stdout_shown) {
        myc_proc_result_free(&pres);
        return NULL;
    }
    nl = strpbrk(pres.stdout_data, "\r\n");
    if (nl)
        *nl = '\0';
    len = strlen(pres.stdout_data);
    if (len == 0 || strstr(pres.stdout_data, ASAN_DLL_NAME) == NULL) {
        myc_proc_result_free(&pres);
        return NULL;
    }
    out = myc_strdup(pres.stdout_data);
    myc_proc_result_free(&pres);
    return out;
}
#endif /* _WIN32 */

static int drv_marker_found(const char *out, const char *err)
{
    int i;
    for (i = 0; DRV_MARKERS[i]; i++) {
        if ((out && strstr(out, DRV_MARKERS[i])) ||
            (err && strstr(err, DRV_MARKERS[i])))
            return 1;
    }
    return 0;
}

int myc_driver_gate(const myc_request *req, const char *source, size_t source_len,
                    myc_result *res)
{
    drv_func funcs[DRV_MAX_FUNCS];
    drv_case_meta meta[DRV_MAX_FUNCS];
    int      nfuncs;
    int      nmeta = 0;
    char    *clang_path = NULL;
    char    *harness = NULL;
    char    *tmp_dir = NULL;
    char    *exe_path = NULL;
    char    *dll_src = NULL;
    char    *dll_dst = NULL;
    size_t   harness_len = 0;
    const char **build_argv = NULL;
    const char **run_argv = NULL;
    myc_proc_request preq;
    myc_proc_result  pres;
    int   ret = 0;
    int   n = 0, total = 0;
    size_t max_out = req->max_output_bytes > 0
                         ? (size_t)req->max_output_bytes
                         : MYC_MAX_OUTPUT_BYTES;
    static const char *const BASE_FLAGS[] = {
        "-x", "c", "-", "-std=c11", "-O0", "-g",
        "-fsanitize=address,undefined",
        "-fno-sanitize-recover=all",
        NULL
    };

    myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_NOT_APPLICABLE, NULL);

    /* 1. Scan fungsi ber-kontrak. */
    nfuncs = scan_contract_funcs(source, source_len, funcs, DRV_MAX_FUNCS);
    if (nfuncs == 0) {
        add_diag_drv(res, "driver di-skip: tidak ada fungsi ber-kontrak (//@ requires)");
        myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_NOT_APPLICABLE,
                            "tidak ada fungsi ber-kontrak");
        myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_SKIP,
                                "driver di-skip: tanpa //@ requires");
        return 0;
    }

    /* 2. Generate harness (roadmap 7.5: meta berisi combo + psize per
     * fungsi untuk membangun case record; harness sha untuk replay). */
    harness = gen_harness(source, source_len, funcs, nfuncs, &harness_len,
                          meta, DRV_MAX_FUNCS, &nmeta);
    if (!harness) {
        add_diag_drv(res, "driver di-skip: gagal generate harness");
        myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INFRA_FAILED,
                            "gagal generate harness");
        myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_ERROR,
                                "driver: harness generation failed");
        return 0;
    }
    /* Hash source harness (9.5 replay capsule: "generated harness hash").
     * Deterministik — mereplay berarti membangun ulang harness yang sama. */
    {
        char hex[65];
        sha256_hex(harness, harness_len, hex);
        res->driver_harness_sha256 = myc_strdup(hex);
        if (!res->driver_harness_sha256) {
            res->err = MYC_ERR_INTERNAL;
            free(harness);
            return 0;
        }
    }

    /* 3. Cari clang. */
    clang_path = myc_find_executable(req->clang_program ? req->clang_program : "clang");
    if (!clang_path) {
        res->err = MYC_ERR_CLANG_NOT_FOUND;
        add_diag_drv(res, "driver di-skip: clang tidak ditemukan");
        myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_UNAVAILABLE,
                            "clang tidak ditemukan");
        myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_SKIP,
                                "driver di-skip: clang hilang");
        free(harness);
        return 0;
    }
    /* MYC-AUDIT-022 (roadmap 7.1): exact tool identity — baris pertama
     * `clang --version`. Hanya diisi bila belum ada (bila --run juga
     * berjalan, jangan timpa/double-free). */
    if (!res->clang_version)
        res->clang_version = myc_tool_version(clang_path);

    /* 4. Direktori temp. */
    tmp_dir = drv_make_temp_dir();
    if (!tmp_dir) {
        res->err = MYC_ERR_INTERNAL;
        myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INFRA_FAILED,
                            "gagal membuat direktori temp");
        myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_ERROR,
                                "driver: temp dir gagal");
        free(harness);
        free(clang_path);
        return 0;
    }
    exe_path = drv_join_path(tmp_dir, "myc_drv.exe");
    if (!exe_path) {
        res->err = MYC_ERR_INTERNAL;
        myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INFRA_FAILED,
                            "gagal membuat path exe");
        myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_ERROR,
                                "driver: exe path gagal");
        free(harness);
        free(clang_path);
        free(tmp_dir);
        return 0;
    }

    /* 5. Build harness (source via stdin). */
    {
        int bfl = 0;
        total = 1;
        while (BASE_FLAGS[bfl++])
            total++;
        total += 2 + 1;              /* "-o", exe_path, NULL */
        build_argv = (const char **)malloc(sizeof(char *) * (size_t)total);
        if (!build_argv) {
            res->err = MYC_ERR_INTERNAL;
            goto out;
        }
        build_argv[n++] = clang_path;
        for (bfl = 0; BASE_FLAGS[bfl]; bfl++)
            build_argv[n++] = BASE_FLAGS[bfl];
        build_argv[n++] = "-o";
        build_argv[n++] = exe_path;
        build_argv[n] = NULL;

        memset(&preq, 0, sizeof(preq));
        preq.argv = build_argv;
        preq.cwd = req->cwd;
        preq.stdin_data = harness;
        preq.stdin_len = harness_len;
        preq.timeout_ms = req->timeout_ms;
        preq.max_output_bytes = max_out;
        if (!myc_proc_run(&preq, &pres)) {
            if (pres.timed_out) {
                res->verdict = MC_TIMEOUT;
                res->err = MYC_ERR_TIMEOUT;
                res->duration_ms += pres.duration_ms;
                myc_proc_result_free(&pres);
                free(build_argv);
                myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INCONCLUSIVE,
                                    "build harness timeout");
                myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_ERROR,
                                        "driver: build timeout");
                goto out;
            }
            res->err = MYC_ERR_EXECUTE_FAILED;
            myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INFRA_FAILED,
                                "build harness exec failed");
            myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_ERROR,
                                    "driver: build exec failed");
            free(build_argv);
            goto out;
        }
        res->duration_ms += pres.duration_ms;
        if (pres.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->err = MYC_ERR_TIMEOUT;
            myc_proc_result_free(&pres);
            free(build_argv);
            myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INCONCLUSIVE,
                                "build harness timeout");
            myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_ERROR,
                                    "driver: build timeout");
            goto out;
        }
        if (pres.exit_code != 0) {
            char note[512];
            const char *fe = pres.stderr_data && pres.stderr_data[0]
                                 ? pres.stderr_data : "build harness gagal";
            if (strlen(fe) > 420)
                snprintf(note, sizeof(note), "driver di-skip: build harness gagal: %.*s...", 420, fe);
            else
                snprintf(note, sizeof(note), "driver di-skip: build harness gagal: %s", fe);
            add_diag_drv(res, note);
            myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INFRA_FAILED, note);
            myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_SKIP, note);
            myc_proc_result_free(&pres);
            free(build_argv);
            goto out_skip;
        }
        myc_proc_result_free(&pres);
        free(build_argv);
    }

    /* 6. Windows: salin runtime DLL ASan. */
#ifdef _WIN32
    {
        dll_src = drv_asan_dll_path(clang_path);
        if (dll_src) {
            dll_dst = drv_join_path(tmp_dir, ASAN_DLL_NAME);
            if (dll_dst && !drv_copy_file(dll_src, dll_dst))
                add_diag_drv(res, "driver: gagal menyalin ASan DLL");
        } else {
            add_diag_drv(res, "driver: runtime ASan DLL tidak ditemukan");
        }
    }
#endif

    /* 7. Eksekusi terkendali. */
    run_argv = (const char **)malloc(sizeof(char *) * 2);
    if (!run_argv) {
        res->err = MYC_ERR_INTERNAL;
        goto out;
    }
    run_argv[0] = exe_path;
    run_argv[1] = NULL;
    memset(&preq, 0, sizeof(preq));
    preq.argv = run_argv;
    preq.cwd = tmp_dir;
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = max_out;
    preq.env = DRV_RUN_ENV;
    if (!myc_proc_run(&preq, &pres)) {
        if (pres.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->err = MYC_ERR_TIMEOUT;
            res->duration_ms += pres.duration_ms;
            myc_proc_result_free(&pres);
            free(run_argv);
            myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INCONCLUSIVE,
                                "driver run timeout");
            myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_ERROR,
                                    "driver: run timeout");
            goto out;
        }
        res->err = MYC_ERR_EXECUTE_FAILED;
        myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INFRA_FAILED,
                            "driver run exec failed");
        myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_ERROR,
                                "driver: run exec failed");
        free(run_argv);
        goto out;
    }
    res->duration_ms += pres.duration_ms;
    res->ran_driver = 1;
    res->run_timed_out = pres.timed_out;
    res->exit_code = pres.exit_code;

    free(res->driver_stdout_text);
    free(res->driver_stderr_text);
    res->driver_stdout_text = pres.stdout_data; pres.stdout_data = NULL;
    res->driver_stderr_text = pres.stderr_data; pres.stderr_data = NULL;
    myc_proc_result_free(&pres);
    free(run_argv);

    /* 8. Hitung jumlah fungsi yang benar-benar dipanggil & kasus,
     * lalu bangun CASE RECORD per kasus (roadmap 7.5): parameter
     * values + allocation sizes + status eksekusi. */
    res->driver_funcs = 0;
    res->driver_cases = 0;
    res->driver_case_count = 0;
    {
        int f;
        for (f = 0; f < nfuncs; f++) {
            if (funcs[f].unsupported || funcs[f].nreqs == 0)
                continue;
            res->driver_funcs++;
        }
    }
    /* parse "DRIVER run=N skip=M" dari stdout */
    if (res->driver_stdout_text) {
        const char *p = strstr(res->driver_stdout_text, "DRIVER run=");
        if (p) {
            int run = 0, skip = 0;
            sscanf(p, "DRIVER run=%d skip=%d", &run, &skip);
            res->driver_cases = run;
            res->driver_skipped = skip;
        }
    }
    /* parse per-case status: "DRIVER case=ID run|skip" */
    {
        int exec_map[MYC_MAX_DRIVER_RECORDS];
        const char *t = res->driver_stdout_text;
        int  mi;
        int  gid = 0;
        memset(exec_map, -1, sizeof(exec_map));
        while (t && *t) {
            const char *m = strstr(t, "DRIVER case=");
            int  id = 0;
            const char *q;
            if (!m)
                break;
            q = m + strlen("DRIVER case=");
            while (*q >= '0' && *q <= '9') {
                id = id * 10 + (*q - '0');
                q++;
            }
            if (id >= 1 && id <= MYC_MAX_DRIVER_RECORDS) {
                while (*q == ' ')
                    q++;
                exec_map[id - 1] = (strncmp(q, "run", 3) == 0) ? 1 : 0;
            }
            t = m + strlen("DRIVER case=");
        }
        /* Bila program abort sebelum mencetak summary "DRIVER run=N skip=M"
         * (mis. sanitizer menghentikan proses), turunkan jumlah kasus dari
         * marker per-case yang sudah ter-flush (setvbuf _IONBF di harness)
         * agar record tidak berbohong '0 kasus' padahal beberapa dieksekusi. */
        if (res->driver_cases == 0) {
            int n_run = 0, n_skip = 0, i;
            for (i = 0; i < MYC_MAX_DRIVER_RECORDS; i++) {
                if (exec_map[i] == 1)
                    n_run++;
                else if (exec_map[i] == 0)
                    n_skip++;
            }
            res->driver_cases = n_run;
            res->driver_skipped = n_skip;
        }
        /* bangun record dari meta (deterministik, sama dengan harness) */
        for (mi = 0; mi < nmeta; mi++) {
            const drv_case_meta *m = &meta[mi];
            int  ci;
            if (m->product > res->driver_max_product)
                res->driver_max_product = m->product;
            if (m->bounded)
                res->driver_bounded = 1;
            for (ci = 0; ci < m->ncombos; ci++) {
                drv_buf params;
                long   alloc = 0;
                int    p;
                gid++;
                memset(&params, 0, sizeof(params));
                for (p = 0; p < m->nparams; p++) {
                    if (p > 0)
                        drv_buf_puts(&params, ", ");
                    if (m->is_ptr[p]) {
                        drv_buf_printf(&params, "%s=%ldB",
                                       m->pname[p], m->psize[p]);
                        alloc += m->psize[p];
                    } else {
                        long v = m->cands[p][m->combos[ci].idx[p]];
                        drv_buf_printf(&params, "%s=%ld", m->pname[p], v);
                    }
                }
                if (res->driver_case_count < MYC_MAX_DRIVER_RECORDS &&
                    gid >= 1 && gid <= MYC_MAX_DRIVER_RECORDS) {
                    myc_driver_case *r = &res->driver_case_records[
                                             res->driver_case_count];
                    r->case_id = gid;
                    r->alloc_bytes = alloc;
                    r->executed = (gid - 1 < MYC_MAX_DRIVER_RECORDS &&
                                   exec_map[gid - 1] == 1) ? 1 : 0;
                    r->func = myc_result_arena_dup(res, m->func, 0);
                    r->params = params.data
                                    ? myc_result_arena_dup(res, params.data,
                                                           params.len)
                                    : NULL;
                    if (r->func && (params.len == 0 || r->params))
                        res->driver_case_count++;
                }
                free(params.data);
            }
        }
    }

    if (res->run_timed_out) {
        res->verdict = MC_TIMEOUT;
        res->err = MYC_ERR_TIMEOUT;
        myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INCONCLUSIVE,
                            "driver run timeout");
        myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_ERROR,
                                "driver: run timeout");
        goto out;
    }
    /* 8b. Finding = bukti FILE report sanitizer (log_path, non-spoofable)
     * ATAU marker teks yang terkonfirmasi exit != 0 (MYC-AUDIT-017).
     * Teks mirip marker dengan exit 0 diabaikan (bukan bukti). */
    {
        char *asan_rpt = myc_read_sanitizer_report(tmp_dir,
                                                   "myc_drv_asan_rpt");
        char *ubsan_rpt = myc_read_sanitizer_report(tmp_dir,
                                                    "myc_drv_ubsan_rpt");
        int   report_evidence = (asan_rpt != NULL) || (ubsan_rpt != NULL);
        int   omarker = drv_marker_found(res->driver_stdout_text,
                                         res->driver_stderr_text);
        free(asan_rpt);
        free(ubsan_rpt);
        myc_remove_sanitizer_reports(tmp_dir, "myc_drv_asan_rpt");
        myc_remove_sanitizer_reports(tmp_dir, "myc_drv_ubsan_rpt");
        if (report_evidence || (omarker && res->exit_code != 0)) {
            add_diag_drv(res, "driver: sanitizer menangkap bug pada kasus tepi");
            res->verdict = MC_DRIVER_VIOLATION;
            res->err = MYC_ERR_DRIVER_VIOLATION;
            myc_gate_set_status(res, MYC_GATE_DRIVER,
                                MYC_GATE_COMPLETED_FINDINGS,
                                "sanitizer menangkap bug pada kasus tepi");
            myc_result_add_evidence(res, MYC_GATE_DRIVER,
                                    MYC_EVIDENCE_FINDING,
                                    "driver: DRIVER_VIOLATION "
                                    "(report sanitizer / marker + exit != 0)");
            /* Isi witness dari driver (Fase 1). */
            if (!res->witness) {
                res->witness = (myc_witness *)malloc(sizeof(myc_witness));
                if (res->witness) {
                    myc_witness_init(res->witness);
                    res->witness->violation_kind =
                        myc_result_arena_dup(res, "driver-sanitizer", 0);
                    res->witness->violation_msg =
                        myc_result_arena_dup(res,
                            "driver: sanitizer menangkap bug pada kasus tepi", 0);
                    res->witness->backend =
                        myc_result_arena_dup(res, "driver", 0);
                    res->witness->operation =
                        myc_result_arena_dup(res,
                            "driver: sanitizer menangkap bug pada kasus tepi", 0);
                    res->witness->pre_state =
                        myc_result_arena_dup(res,
                            "driver: kasus tepi dari kontrak", 0);
                }
            }
            goto out;
        }
        if (omarker) {
            add_diag_drv(res, "driver: teks mirip marker sanitizer tetapi "
                              "exit 0 — diabaikan (bukan bukti finding)");
            myc_result_add_evidence(res, MYC_GATE_DRIVER,
                                    MYC_EVIDENCE_DIAGNOSTIC,
                                    "driver: marker teks diabaikan (exit 0)");
        }
    }
    if (res->exit_code != 0) {
        /* keluar non-zero tanpa marker: bukan bukti bug memori */
        add_diag_drv(res, "driver: run keluar non-zero tanpa laporan sanitizer");
        myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INCONCLUSIVE,
                            "exit non-zero tanpa sanitizer");
        myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_SKIP,
                                "driver: exit non-zero tanpa marker");
        goto out_skip;
    }
    if (res->driver_cases == 0) {
        add_diag_drv(res, "driver: semua kasus dilewati guard requires");
        myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_NOT_APPLICABLE,
                            "semua kasus dilewati guard requires");
        myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_SKIP,
                                "driver: 0 kasus tereksekusi");
        goto out_skip;
    }

    ret = 1;
    myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_COMPLETED_CLEAN,
                        "driver clean");
    myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_GATE_END,
                            "driver: clean");
    goto out;

out_skip:
    ret = 0;

out:
    if (harness) free(harness);
    if (dll_dst) free(dll_dst);
    if (dll_src) free(dll_src);
    if (exe_path) {
        remove(exe_path);
        free(exe_path);
    }
    if (tmp_dir) {
        /* clang -g menghasilkan <exe>.pdb di Windows: hapus semua artefak
         * agar direktori temp bisa di-rmdir (pola sama dengan run.c). */
        static const char *const artifacts[] = { ASAN_DLL_NAME, "myc_drv.pdb", NULL };
        int ai;
        for (ai = 0; artifacts[ai]; ai++) {
            char *p = drv_join_path(tmp_dir, artifacts[ai]);
            if (p) {
                remove(p);
                free(p);
            }
        }
        myc_rmdir(tmp_dir);
        free(tmp_dir);
    }
    free(clang_path);
    return ret;
}

/* ================================================================== */
/* A3: Small-Domain Exhaustive Proof (--exhaustive, DS-03)            */
/* Enumerasi PENUH domain fungsi ber-kontrak yang terbatas = bukti     */
/* riil untuk domain yang dideklarasikan (bukan sampel tepi).          */
/* ================================================================== */

#define EXH_MAX_PER_PARAM 1024      /* lebar maksimum tiap dimensi */
#define EXH_MAX_POINTS    1000000   /* budget produk kartesian (A3) */
#define EXH_PRINT_CASES   20000     /* marker per-case maksimum dicetak */
#define EXH_MAX_ENSURES   8         /* ensures per fungsi */
#define EXH_STATE_FILE    ".myc/exhaustive.json"
#define EXH_MAX_STATE     64

/* Satu domain ter-enumerasi: per-parameter int lo..hi. */
typedef struct {
    int    fi;                          /* index di funcs[] */
    long   lo[DRV_MAX_PARAMS], hi[DRV_MAX_PARAMS];
    int    intp[DRV_MAX_PARAMS];        /* index param integer */
    int    nint;
    long   points;                      /* produk kartesian */
    int    ok;
    char   spec[160];                   /* "lo..hi,lo..hi" */
    char   prev_spec[160];              /* spec run sebelumnya (""=none) */
    int    narrowed;                    /* 1 = domain dipersempit (DS-03) */
} ex_domain;

/* Entry state DS-03 (.myc/exhaustive.json). */
typedef struct {
    char   func[64];
    char   spec[160];
    long   points;
} ex_state_entry;

/* Pilih fungsi ber-kontrak yang domain-nya bisa di-enumerasi penuh.
 * Bila tidak ada yang lolos, skip_note (opsional) diisi alasan pertama
 * (pesan skip yang akurat: tak terbatas vs terlalu lebar). */
static void ex_build_domains(const drv_func *funcs, int nfuncs,
                             ex_domain *doms, int maxdoms, int *ndoms,
                             char *skip_note, size_t skip_cap)
{
    int f, d = 0;
    *ndoms = 0;
    if (skip_note && skip_cap > 0)
        skip_note[0] = '\0';
    for (f = 0; f < nfuncs; f++) {
        const drv_func *fn = &funcs[f];
        ex_domain dom;
        long product = 1;
        int  p;
        if (fn->unsupported || fn->nreqs == 0 || fn->name[0] == '\0')
            continue;
        memset(&dom, 0, sizeof(dom));
        dom.fi = f;
        for (p = 0; p < fn->nparams; p++) {
            drv_bounds bd;
            long width;
            int  ii;
            if (fn->is_ptr[p])
                continue;               /* pointer: bukan dimensi enumerasi */
            memset(&bd, 0, sizeof(bd));
            for (ii = 0; ii < fn->nreqs; ii++)
                parse_bound(fn->reqs[ii], fn->pname[p], &bd);
            if (!bd.has_lo || !bd.has_hi || bd.hi < bd.lo) {
                if (skip_note && skip_note[0] == '\0')
                    snprintf(skip_note, skip_cap,
                             "domain %.32s tak terbatas (perlu requires "
                             "\"%.32s >= LO && %.32s <= HI\")",
                             fn->pname[p], fn->pname[p], fn->pname[p]);
                goto skip_func;         /* tanpa rentang penuh: bukan kecil */
            }
            width = bd.hi - bd.lo + 1;
            if (width <= 0 || width > EXH_MAX_PER_PARAM) {
                if (skip_note && skip_note[0] == '\0')
                    snprintf(skip_note, skip_cap,
                             "domain %.32s terlalu lebar (%ld..%ld, max "
                             "%d titik/dimensi)",
                             fn->pname[p], bd.lo, bd.hi, EXH_MAX_PER_PARAM);
                goto skip_func;         /* dimensi terlalu lebar */
            }
            if (product > EXH_MAX_POINTS / width) {
                if (skip_note && skip_note[0] == '\0')
                    snprintf(skip_note, skip_cap,
                             "produk domain melebihi budget %d titik",
                             EXH_MAX_POINTS);
                goto skip_func;         /* produk melebihi budget 1e6 */
            }
            product *= width;
            dom.lo[dom.nint] = bd.lo;
            dom.hi[dom.nint] = bd.hi;
            dom.intp[dom.nint] = p;
            dom.nint++;
        }
        if (dom.nint == 0) {
            if (skip_note && skip_note[0] == '\0')
                snprintf(skip_note, skip_cap, "%.32s: tanpa parameter integer",
                         fn->name);
            goto skip_func;             /* tak ada parameter integer */
        }
        dom.points = product;
        dom.ok = 1;
        /* spec: "lo..hi" per dimensi (deterministik, urutan parameter) */
        {
            size_t off = 0;
            int q;
            for (q = 0; q < dom.nint; q++) {
                int r = snprintf(dom.spec + off,
                                 sizeof(dom.spec) - off,
                                 "%s%ld..%ld", q ? "," : "",
                                 dom.lo[q], dom.hi[q]);
                if (r > 0)
                    off += (size_t)r;
                if (off >= sizeof(dom.spec))
                    off = sizeof(dom.spec) - 1;
            }
        }
        if (d < maxdoms)
            doms[d++] = dom;
        continue;
skip_func:
        ;
    }
    *ndoms = d;
}

/* Ambil ensures PURE yang terikat ke fungsi (dari res->contract_clauses). */
static int ex_get_ensures(const myc_result *res, const char *func,
                          char out[][512], int maxout)
{
    int i, n = 0;
    if (!res)
        return 0;
    for (i = 0; i < res->contract_clause_count && n < maxout; i++) {
        const myc_contract_clause *cl = &res->contract_clauses[i];
        if (cl->kind != 1 || !cl->func || !cl->expr)
            continue;
        if (strcmp(cl->func, func) != 0)
            continue;
        if (cl->status != MYC_CLAUSE_OK)
            continue;                   /* hanya ekspresi pure */
        snprintf(out[n], 512, "%s", cl->expr);
        n++;
    }
    return n;
}

/* Generate harness enumerasi PENUH (odometer) + assert(ensures). */
static char *gen_exhaustive_harness(const char *src, size_t srclen,
                                    const drv_func *funcs,
                                    const ex_domain *doms, int ndoms,
                                    const myc_result *res,
                                    size_t *out_len, long *total_points)
{
    drv_buf b;
    int     d;
    int     gid = 0;
    memset(&b, 0, sizeof(b));
    *total_points = 0;

    drv_buf_puts(&b, "#include <stdio.h>\n#include <stdlib.h>\n"
                     "#include <string.h>\n#include <assert.h>\n");
    drv_buf_puts(&b, "#define main myc_exh_orig_main\n");
    drv_buf_putn(&b, src, srclen);
    drv_buf_puts(&b, "\n#undef main\n\n");
    drv_buf_puts(&b, "static int exh_run = 0;\n");
    drv_buf_puts(&b, "static int exh_skip = 0;\n");
    drv_buf_puts(&b, "static long exh_printed = 0;\n\n");
    drv_buf_puts(&b, "int main(void) {\n");
    drv_buf_puts(&b, "    setvbuf(stdout, NULL, _IONBF, 0);\n");

    for (d = 0; d < ndoms; d++) {
        const ex_domain *dom = &doms[d];
        const drv_func *fn = &funcs[dom->fi];
        long ix[DRV_MAX_PARAMS];
        long psize[DRV_MAX_PARAMS];
        char ensures[EXH_MAX_ENSURES][512];
        int  nens;
        int  p, q;
        long max_hi = 0;
        int  have_hi = 0;
        int  pp, ii;

        /* ukuran buffer pointer: batas atas terbesar di seluruh param */
        for (pp = 0; pp < fn->nparams; pp++) {
            drv_bounds bd;
            memset(&bd, 0, sizeof(bd));
            for (ii = 0; ii < fn->nreqs; ii++)
                parse_bound(fn->reqs[ii], fn->pname[pp], &bd);
            if (bd.has_hi) {
                if (!have_hi || bd.hi > max_hi)
                    max_hi = bd.hi;
                have_hi = 1;
            }
        }
        if (!have_hi)
            max_hi = 8;
        if (max_hi < 1)
            max_hi = 1;
        for (p = 0; p < fn->nparams; p++) {
            psize[p] = fn->is_ptr[p] ? max_hi * fn->elem[p] : 0;
            if (psize[p] > DRV_BUF_CAP)
                psize[p] = DRV_BUF_CAP;
            if (psize[p] < 1)
                psize[p] = 1;
        }

        nens = ex_get_ensures(res, fn->name, ensures, EXH_MAX_ENSURES);
        memset(ix, 0, sizeof(ix));
        for (;;) {
            gid++;
            drv_buf_puts(&b, "    {\n");
            for (p = 0; p < fn->nparams; p++) {
                if (fn->is_ptr[p]) {
                    drv_buf_printf(&b, "        %s %s = (%s)calloc(%ld, 1);\n",
                                   fn->type[p], fn->pname[p], fn->type[p],
                                   psize[p]);
                } else {
                    long v = dom->lo[0];
                    for (q = 0; q < dom->nint; q++)
                        if (dom->intp[q] == p)
                            v = dom->lo[q] + ix[q];
                    drv_buf_printf(&b, "        %s %s = %ld;\n",
                                   fn->type[p], fn->pname[p], v);
                }
            }
            /* guard: pointer non-NULL && semua requires */
            drv_buf_puts(&b, "        if (");
            {
                int first = 1;
                int r;
                for (p = 0; p < fn->nparams; p++) {
                    if (fn->is_ptr[p]) {
                        if (!first)
                            drv_buf_puts(&b, " && ");
                        drv_buf_printf(&b, "%s != NULL", fn->pname[p]);
                        first = 0;
                    }
                }
                for (r = 0; r < fn->nreqs; r++) {
                    if (!first)
                        drv_buf_puts(&b, " && ");
                    drv_buf_printf(&b, "(%s)", fn->reqs[r]);
                    first = 0;
                }
                if (first)
                    drv_buf_puts(&b, "1");
            }
            drv_buf_printf(&b, ") {\n            exh_run++;\n");
            drv_buf_printf(&b,
                "            if (exh_printed < %d) "
                "{ printf(\"EXH case=%d run\\n\", %d); "
                "exh_printed++; }\n",
                EXH_PRINT_CASES, gid, gid);
            drv_buf_puts(&b, "            (void)");
            drv_buf_puts(&b, fn->name);
            drv_buf_puts(&b, "(");
            for (p = 0; p < fn->nparams; p++) {
                if (p)
                    drv_buf_puts(&b, ", ");
                drv_buf_puts(&b, fn->pname[p]);
            }
            drv_buf_puts(&b, ");\n");
            /* ensures pure di-assert per titik domain (inti bukti A3) */
            for (q = 0; q < nens; q++) {
                drv_buf_printf(&b, "            assert(%s);\n", ensures[q]);
            }
            drv_buf_puts(&b, "        } else {\n            exh_skip++;\n");
            drv_buf_printf(&b,
                "            if (exh_printed < %d) "
                "{ printf(\"EXH case=%d skip\\n\", %d); "
                "exh_printed++; }\n",
                EXH_PRINT_CASES, gid, gid);
            drv_buf_puts(&b, "        }\n");
            for (p = 0; p < fn->nparams; p++) {
                if (fn->is_ptr[p])
                    drv_buf_printf(&b, "        free((void*)%s);\n",
                                   fn->pname[p]);
            }
            drv_buf_puts(&b, "    }\n");
            /* majukan odometer; carry keluar = enumerasi selesai */
            {
                int carry = 1;
                for (q = dom->nint - 1; q >= 0 && carry; q--) {
                    ix[q]++;
                    if (ix[q] > dom->hi[q] - dom->lo[q])
                        ix[q] = 0;
                    else
                        carry = 0;
                }
                if (carry)
                    break;
            }
        }
    }
    drv_buf_printf(&b, "    printf(\"EXH run=%%d skip=%%d\\n\", exh_run, "
                       "exh_skip);\n");
    drv_buf_puts(&b, "    return exh_run == 0 ? 3 : 0;\n");
    drv_buf_puts(&b, "}\n");

    *total_points = (long)gid;
    if (!b.data)
        return NULL;
    *out_len = b.len;
    return b.data;
}

/* --- DS-03 state: .myc/exhaustive.json (per-fungsi spec domain) --- */

static void ex_state_read(ex_state_entry *entries, int cap, int *n)
{
    FILE *f;
    long  sz;
    char *buf;
    json_value *root, *arr;
    int   i, cnt = 0;
    *n = 0;
    f = fopen(EXH_STATE_FILE, "rb");
    if (!f)
        return;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 4 * 1024 * 1024) {
        fclose(f);
        return;
    }
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return;
    }
    buf[sz] = '\0';
    fclose(f);
    if (!json_parse(buf, (size_t)sz, &root)) {
        free(buf);
        return;
    }
    arr = json_get(root, "entries");
    if (arr && arr->type == JSON_ARR) {
        for (i = 0; i < (int)arr->len && cnt < cap; i++) {
            json_value *e = arr->items[i];
            const char *fn, *sp;
            json_value *pt;
            if (!e || e->type != JSON_OBJ)
                continue;
            fn = json_get_str(e, "func");
            sp = json_get_str(e, "spec");
            pt = json_get(e, "points");
            if (!fn || !sp || !pt || pt->type != JSON_NUM)
                continue;
            snprintf(entries[cnt].func, sizeof(entries[cnt].func), "%s", fn);
            snprintf(entries[cnt].spec, sizeof(entries[cnt].spec), "%s", sp);
            entries[cnt].points = (long)pt->num;
            cnt++;
        }
    }
    json_free(root);
    free(buf);
    *n = cnt;
}

static void ex_state_write(const ex_state_entry *entries, int n)
{
    json_value *root, *arr;
    char *out;
    FILE *f;
    int   i;
    root = json_new_obj();
    if (!root)
        return;
    arr = json_new_arr();
    if (!arr) {
        json_free(root);
        return;
    }
    for (i = 0; i < n; i++) {
        json_value *e = json_new_obj();
        if (!e)
            break;
        json_obj_set(e, "func", json_new_str(entries[i].func));
        json_obj_set(e, "spec", json_new_str(entries[i].spec));
        json_obj_set(e, "points", json_new_num((int64_t)entries[i].points));
        json_arr_push(arr, e);
    }
    json_obj_set(root, "entries", arr);
    if (json_serialize(root, &out)) {
        f = fopen(EXH_STATE_FILE, "wb");
        if (f) {
            fputs(out, f);
            fclose(f);
        }
        free(out);
    }
    json_free(root);
}

/* Parse "lo..hi,lo..hi" ke larik rentang. Return jumlah dimensi. */
static int ex_parse_spec(const char *spec, long *lo, long *hi, int maxdim)
{
    const char *p = spec;
    int n = 0;
    while (p && *p && n < maxdim) {
        long a = 0, b = 0;
        int  m = sscanf(p, "%ld..%ld", &a, &b);
        if (m != 2)
            break;
        lo[n] = a;
        hi[n] = b;
        n++;
        p = strchr(p, ',');
        if (p)
            p++;
    }
    return n;
}

/* DS-03 Domain Firewall: deteksi penyempitan domain vs run sebelumnya
 * (SCOPE_LAUNDERING). Update state file (merge per fungsi). */
static void ex_domain_firewall(ex_domain *doms, int ndoms,
                               const drv_func *funcs, const char *source_sha)
{
    ex_state_entry entries[EXH_MAX_STATE];
    ex_state_entry newstate[EXH_MAX_STATE + DRV_MAX_FUNCS];
    int n = 0, nn = 0;
    int d, i, k;
    (void)source_sha;

    ex_state_read(entries, EXH_MAX_STATE, &n);
    /* salin state lama yang TIDAK ter-update */
    for (i = 0; i < n; i++) {
        int matched = 0;
        for (d = 0; d < ndoms; d++) {
            const drv_func *fn = &funcs[doms[d].fi];
            if (strcmp(entries[i].func, fn->name) == 0)
                matched = 1;
        }
        if (!matched && nn < EXH_MAX_STATE)
            newstate[nn++] = entries[i];
    }
    /* proses tiap domain: deteksi narrowing + simpan spec baru */
    for (d = 0; d < ndoms; d++) {
        ex_domain *dom = &doms[d];
        const drv_func *fn = &funcs[dom->fi];
        const ex_state_entry *prev = NULL;
        for (i = 0; i < n; i++) {
            if (strcmp(entries[i].func, fn->name) == 0) {
                prev = &entries[i];
                break;
            }
        }
        dom->narrowed = 0;
        dom->prev_spec[0] = '\0';
        if (prev && strcmp(prev->spec, dom->spec) != 0) {
            long olo[DRV_MAX_PARAMS], ohi[DRV_MAX_PARAMS];
            long nlo[DRV_MAX_PARAMS], nhi[DRV_MAX_PARAMS];
            int  on = ex_parse_spec(prev->spec, olo, ohi, DRV_MAX_PARAMS);
            int  dn = ex_parse_spec(dom->spec, nlo, nhi, DRV_MAX_PARAMS);
            if (on == dn && dn > 0) {
                int strictly = 0;
                int inside = 1;
                for (k = 0; k < dn; k++) {
                    if (nlo[k] < olo[k] || nhi[k] > ohi[k]) {
                        inside = 0;
                        break;
                    }
                    if (nlo[k] > olo[k] || nhi[k] < ohi[k])
                        strictly = 1;
                }
                if (inside && strictly) {
                    dom->narrowed = 1;
                    snprintf(dom->prev_spec, sizeof(dom->prev_spec), "%s",
                             prev->spec);
                }
            }
        }
        if (nn < EXH_MAX_STATE) {
            snprintf(newstate[nn].func, sizeof(newstate[nn].func), "%.63s",
                     fn->name);
            snprintf(newstate[nn].spec, sizeof(newstate[nn].spec), "%.159s",
                     dom->spec);
            newstate[nn].points = dom->points;
            nn++;
        }
    }
    ex_state_write(newstate, nn);
}

/* --- Gate A3: build + run harness enumerasi penuh (mirror driver) --- */
int myc_exhaustive_gate(const myc_request *req, const char *source,
                        size_t source_len, myc_result *res)
{
    drv_func funcs[DRV_MAX_FUNCS];
    ex_domain doms[DRV_MAX_FUNCS];
    int   nfuncs, ndoms;
    char *clang_path = NULL;
    char *harness = NULL;
    char *tmp_dir = NULL;
    char *exe_path = NULL;
    char *dll_src = NULL;
    char *dll_dst = NULL;
    size_t harness_len = 0;
    const char **build_argv = NULL;
    const char **run_argv = NULL;
    myc_proc_request preq;
    myc_proc_result  pres;
    int   ret = 0;
    int   n = 0, total = 0;
    long  total_points = 0;
    size_t max_out = req->max_output_bytes > 0
                         ? (size_t)req->max_output_bytes
                         : MYC_MAX_OUTPUT_BYTES;
    static const char *const BASE_FLAGS[] = {
        "-x", "c", "-", "-std=c11", "-O0", "-g",
        "-fsanitize=address,undefined",
        "-fno-sanitize-recover=all",
        NULL
    };
    static const char *const EXH_RUN_ENV[] = {
        "ASAN_OPTIONS=log_path=myc_exh_asan_rpt:abort_on_error=1:"
        "halt_on_error=1",
        "UBSAN_OPTIONS=log_path=myc_exh_ubsan_rpt:halt_on_error=1:"
        "print_stacktrace=1",
        "LC_ALL=C",
        NULL
    };

    myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_NOT_APPLICABLE,
                        NULL);

    /* 1. Scan fungsi ber-kontrak. */
    nfuncs = scan_contract_funcs(source, source_len, funcs, DRV_MAX_FUNCS);
    if (nfuncs == 0) {
        add_diag_drv(res, "exhaustive di-skip: tidak ada fungsi ber-kontrak");
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                            MYC_GATE_NOT_APPLICABLE,
                            "tidak ada fungsi ber-kontrak");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_SKIP,
                                "exhaustive di-skip: tanpa //@ requires");
        return 0;
    }

    /* 2. Pilih domain terbatas. */
    {
        char skip_note[256];
        skip_note[0] = '\0';
        ex_build_domains(funcs, nfuncs, doms, DRV_MAX_FUNCS, &ndoms,
                         skip_note, sizeof(skip_note));
        if (ndoms == 0) {
            add_diag_drv(res, skip_note[0]
                             ? skip_note
                             : "exhaustive di-skip: tidak ada fungsi "
                               "ber-domain enumerable");
            myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                MYC_GATE_NOT_APPLICABLE,
                                "domain tak ter-enumerasi");
            myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_EVIDENCE_SKIP,
                                    "exhaustive: domain tak ter-enumerasi");
            return 0;
        }
    }

    /* 3. Generate harness enumerasi penuh. */
    harness = gen_exhaustive_harness(source, source_len, funcs,
                                     doms, ndoms, res, &harness_len,
                                     &total_points);
    if (!harness) {
        add_diag_drv(res, "exhaustive di-skip: gagal generate harness");
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_INFRA_FAILED,
                            "gagal generate harness");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_ERROR,
                                "exhaustive: harness generation failed");
        return 0;
    }
    {
        char hex[65];
        sha256_hex(harness, harness_len, hex);
        res->exhaustive_harness_sha256 = myc_strdup(hex);
        if (!res->exhaustive_harness_sha256) {
            res->err = MYC_ERR_INTERNAL;
            free(harness);
            return 0;
        }
    }

    /* 4. Cari clang. */
    clang_path = myc_find_executable(req->clang_program
                                         ? req->clang_program : "clang");
    if (!clang_path) {
        res->err = MYC_ERR_CLANG_NOT_FOUND;
        add_diag_drv(res, "exhaustive di-skip: clang tidak ditemukan");
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_UNAVAILABLE,
                            "clang tidak ditemukan");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_SKIP,
                                "exhaustive di-skip: clang hilang");
        free(harness);
        return 0;
    }
    if (!res->clang_version)
        res->clang_version = myc_tool_version(clang_path);

    /* 5. Direktori temp + path exe. */
    tmp_dir = drv_make_temp_dir();
    if (!tmp_dir) {
        res->err = MYC_ERR_INTERNAL;
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_INFRA_FAILED,
                            "gagal membuat direktori temp");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_ERROR,
                                "exhaustive: temp dir gagal");
        free(harness);
        free(clang_path);
        return 0;
    }
    exe_path = drv_join_path(tmp_dir, "myc_exh.exe");
    if (!exe_path) {
        res->err = MYC_ERR_INTERNAL;
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_INFRA_FAILED,
                            "gagal membuat path exe");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_ERROR,
                                "exhaustive: exe path gagal");
        free(harness);
        free(clang_path);
        free(tmp_dir);
        return 0;
    }

    /* 6. Build harness (source via stdin). */
    {
        int bfl = 0;
        total = 1;
        while (BASE_FLAGS[bfl++])
            total++;
        total += 2 + 1;
        build_argv = (const char **)malloc(sizeof(char *) * (size_t)total);
        if (!build_argv) {
            res->err = MYC_ERR_INTERNAL;
            goto out;
        }
        build_argv[n++] = clang_path;
        for (bfl = 0; BASE_FLAGS[bfl]; bfl++)
            build_argv[n++] = BASE_FLAGS[bfl];
        build_argv[n++] = "-o";
        build_argv[n++] = exe_path;
        build_argv[n] = NULL;

        memset(&preq, 0, sizeof(preq));
        preq.argv = build_argv;
        preq.cwd = req->cwd;
        preq.stdin_data = harness;
        preq.stdin_len = harness_len;
        preq.timeout_ms = req->timeout_ms;
        preq.max_output_bytes = max_out;
        if (!myc_proc_run(&preq, &pres)) {
            res->err = pres.timed_out ? MYC_ERR_TIMEOUT
                                      : MYC_ERR_EXECUTE_FAILED;
            if (pres.timed_out) {
                res->verdict = MC_TIMEOUT;
                res->duration_ms += pres.duration_ms;
                myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_GATE_INCONCLUSIVE,
                                    "build harness timeout");
                myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                        MYC_EVIDENCE_ERROR,
                                        "exhaustive: build timeout");
            } else {
                myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_GATE_INFRA_FAILED,
                                    "build harness exec failed");
                myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                        MYC_EVIDENCE_ERROR,
                                        "exhaustive: build exec failed");
            }
            myc_proc_result_free(&pres);
            free(build_argv);
            goto out;
        }
        res->duration_ms += pres.duration_ms;
        if (pres.exit_code != 0) {
            char note[512];
            const char *fe = pres.stderr_data && pres.stderr_data[0]
                                 ? pres.stderr_data
                                 : "build harness exhaustive gagal";
            snprintf(note, sizeof(note),
                     "exhaustive di-skip: build harness gagal: %.300s", fe);
            add_diag_drv(res, note);
            myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                MYC_GATE_INFRA_FAILED, note);
            myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_EVIDENCE_SKIP, note);
            myc_proc_result_free(&pres);
            free(build_argv);
            goto out_skip;
        }
        myc_proc_result_free(&pres);
        free(build_argv);
    }

    /* 7. Windows: salin runtime DLL ASan. */
#ifdef _WIN32
    {
        dll_src = drv_asan_dll_path(clang_path);
        if (dll_src) {
            dll_dst = drv_join_path(tmp_dir, ASAN_DLL_NAME);
            if (dll_dst && !drv_copy_file(dll_src, dll_dst))
                add_diag_drv(res, "exhaustive: gagal menyalin ASan DLL");
        } else {
            add_diag_drv(res, "exhaustive: runtime ASan DLL tidak ditemukan");
        }
    }
#endif

    /* 8. Eksekusi terkendali. */
    run_argv = (const char **)malloc(sizeof(char *) * 2);
    if (!run_argv) {
        res->err = MYC_ERR_INTERNAL;
        goto out;
    }
    run_argv[0] = exe_path;
    run_argv[1] = NULL;
    memset(&preq, 0, sizeof(preq));
    preq.argv = run_argv;
    preq.cwd = tmp_dir;
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = max_out;
    preq.env = EXH_RUN_ENV;
    if (!myc_proc_run(&preq, &pres)) {
        res->err = pres.timed_out ? MYC_ERR_TIMEOUT
                                  : MYC_ERR_EXECUTE_FAILED;
        if (pres.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->duration_ms += pres.duration_ms;
            myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                MYC_GATE_INCONCLUSIVE, "run timeout");
            myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_EVIDENCE_ERROR,
                                    "exhaustive: run timeout");
        } else {
            myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                MYC_GATE_INFRA_FAILED, "run exec failed");
            myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_EVIDENCE_ERROR,
                                    "exhaustive: run exec failed");
        }
        myc_proc_result_free(&pres);
        free(run_argv);
        goto out;
    }
    res->duration_ms += pres.duration_ms;
    res->ran_exhaustive = 1;
    res->run_timed_out = pres.timed_out;
    res->exit_code = pres.exit_code;
    free(res->exhaustive_stdout_text);
    free(res->exhaustive_stderr_text);
    res->exhaustive_stdout_text = pres.stdout_data;
    pres.stdout_data = NULL;
    res->exhaustive_stderr_text = pres.stderr_data;
    pres.stderr_data = NULL;
    myc_proc_result_free(&pres);
    free(run_argv);

    /* 9. Parse summary "EXH run=N skip=M". */
    res->exhaustive_funcs = ndoms;
    res->exhaustive_cases = 0;
    res->exhaustive_skipped = 0;
    res->exhaustive_points = total_points;
    if (res->exhaustive_stdout_text) {
        const char *p = strstr(res->exhaustive_stdout_text, "EXH run=");
        if (p) {
            int run = 0, skip = 0;
            sscanf(p, "EXH run=%d skip=%d", &run, &skip);
            res->exhaustive_cases = run;
            res->exhaustive_skipped = skip;
        }
    }

    if (res->run_timed_out) {
        res->verdict = MC_TIMEOUT;
        res->err = MYC_ERR_TIMEOUT;
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                            MYC_GATE_INCONCLUSIVE, "run timeout");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_ERROR,
                                "exhaustive: run timeout");
        goto out;
    }

    /* 10. Finding = bukti report sanitizer / assert (non-spoofable). */
    {
        char *asan_rpt = myc_read_sanitizer_report(tmp_dir,
                                                   "myc_exh_asan_rpt");
        char *ubsan_rpt = myc_read_sanitizer_report(tmp_dir,
                                                    "myc_exh_ubsan_rpt");
        int   report_evidence = (asan_rpt != NULL) || (ubsan_rpt != NULL);
        int   omarker = drv_marker_found(res->exhaustive_stdout_text,
                                         res->exhaustive_stderr_text);
        free(asan_rpt);
        free(ubsan_rpt);
        myc_remove_sanitizer_reports(tmp_dir, "myc_exh_asan_rpt");
        myc_remove_sanitizer_reports(tmp_dir, "myc_exh_ubsan_rpt");
        if (report_evidence || (omarker && res->exit_code != 0)) {
            add_diag_drv(res, "exhaustive: counterexample ditemukan pada "
                              "domain dideklarasikan");
            res->verdict = MC_DRIVER_VIOLATION;
            res->err = MYC_ERR_DRIVER_VIOLATION;
            myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                MYC_GATE_COMPLETED_FINDINGS,
                                "counterexample pada domain dideklarasikan");
            myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_EVIDENCE_FINDING,
                                    "exhaustive: DRIVER_VIOLATION "
                                    "(counterexample enumeratif)");
            if (!res->witness) {
                res->witness = (myc_witness *)malloc(sizeof(myc_witness));
                if (res->witness) {
                    myc_witness_init(res->witness);
                    res->witness->violation_kind =
                        myc_result_arena_dup(res, "exhaustive-counterexample",
                                             0);
                    res->witness->violation_msg =
                        myc_result_arena_dup(res,
                            "exhaustive: counterexample pada domain "
                            "dideklarasikan (enumerasi penuh)", 0);
                    res->witness->backend =
                        myc_result_arena_dup(res, "exhaustive", 0);
                    res->witness->operation =
                        myc_result_arena_dup(res,
                            "exhaustive: enumerasi penuh domain", 0);
                    res->witness->pre_state =
                        myc_result_arena_dup(res,
                            "exhaustive: domain kontrak dideklarasikan", 0);
                }
            }
            goto out;
        }
        if (omarker) {
            add_diag_drv(res, "exhaustive: teks mirip marker sanitizer "
                              "tetapi exit 0 -- diabaikan");
        }
    }
    if (res->exit_code != 0) {
        add_diag_drv(res, "exhaustive: run keluar non-zero tanpa "
                          "laporan sanitizer");
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_INCONCLUSIVE,
                            "exit non-zero tanpa sanitizer");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_SKIP,
                                "exhaustive: exit non-zero tanpa marker");
        goto out_skip;
    }
    if (res->exhaustive_cases == 0) {
        add_diag_drv(res, "exhaustive: semua titik domain dilewati guard");
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                            MYC_GATE_NOT_APPLICABLE,
                            "semua titik dilewati guard requires");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_SKIP,
                                "exhaustive: 0 titik tereksekusi");
        goto out_skip;
    }

    /* 11. Bersih: P1 EXHAUSTIVE untuk domain dinyatakan. DS-03 firewall. */
    {
        char spec_all[512];
        size_t off = 0;
        int d;
        spec_all[0] = '\0';
        for (d = 0; d < ndoms; d++) {
            const drv_func *fn = &funcs[doms[d].fi];
            int r = snprintf(spec_all + off, sizeof(spec_all) - off,
                             "%s%s:%s", d ? ";" : "", fn->name,
                             doms[d].spec);
            if (r > 0)
                off += (size_t)r;
            if (off >= sizeof(spec_all))
                off = sizeof(spec_all) - 1;
        }
        sha256_hex(spec_all, off, res->exhaustive_domain_hash);
        ex_domain_firewall(doms, ndoms, funcs, res->source_sha256);
        {
            int d;
            int launder = 0;
            char rep[1024];
            size_t roff = 0;
            res->exhaustive_laundering = 0;
            roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
                "exhaustive (A3): P1 EXHAUSTIVE untuk domain dideklarasikan\n");
            for (d = 0; d < ndoms; d++) {
                const drv_func *fn = &funcs[doms[d].fi];
                if (doms[d].narrowed) {
                    launder = 1;
                    res->exhaustive_laundering = 1;
                }
                roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
                    "  %s: domain %s (%ld titik)%s\n", fn->name,
                    doms[d].spec, doms[d].points,
                    doms[d].narrowed ? " -- SCOPE_LAUNDERING "
                        "(dipersempit dari " : "");
                if (doms[d].narrowed && roff < sizeof(rep))
                    roff += (size_t)snprintf(rep + roff,
                                             sizeof(rep) - roff,
                                             "%s)", doms[d].prev_spec);
                if (roff >= sizeof(rep))
                    roff = sizeof(rep) - 1;
            }
            roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
                "  domain_hash: %s\n  bukan bukti di luar domain "
                "dideklarasikan\n", res->exhaustive_domain_hash);
            if (roff >= sizeof(rep))
                roff = sizeof(rep) - 1;
            res->exhaustive_report = myc_result_arena_dup(res, rep, 0);
            if (launder) {
                add_diag_drv(res, "exhaustive: SCOPE_LAUNDERING -- domain "
                                  "kontrak dipersempit vs run sebelumnya "
                                  "(proof laundering)");
                myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                        MYC_EVIDENCE_DIAGNOSTIC,
                                        "exhaustive: SCOPE_LAUNDERING");
            }
        }
    }

    ret = 1;
    myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_COMPLETED_CLEAN,
                        "P1 EXHAUSTIVE (domain dideklarasikan)");
    myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE, MYC_EVIDENCE_GATE_END,
                            "exhaustive: clean (enumerasi penuh)");
    goto out;

out_skip:
    ret = 0;

out:
    if (harness) free(harness);
    if (dll_dst) free(dll_dst);
    if (dll_src) free(dll_src);
    if (exe_path) {
        remove(exe_path);
        free(exe_path);
    }
    if (tmp_dir) {
        static const char *const artifacts[] = { ASAN_DLL_NAME,
                                                 "myc_exh.pdb", NULL };
        int ai;
        for (ai = 0; artifacts[ai]; ai++) {
            char *p = drv_join_path(tmp_dir, artifacts[ai]);
            if (p) {
                remove(p);
                free(p);
            }
        }
        myc_rmdir(tmp_dir);
        free(tmp_dir);
    }
    free(clang_path);
    return ret;
}

/* ================================================================== */
/* A4: Differential Oracle Pair (--compare, DS-04)                    */
/* Bandingkan PERILAKU dua versi fungsi ber-kontrak pada baterai      */
/* input bersama. Escrow DS-04: ret + errno + output digest + exit +  */
/* ABI signature + domain hash.                                      */
/* ================================================================== */

#define CMP_MAX_CASES   4096        /* budget kasus per fungsi */
#define CMP_MAX_FUNCS   DRV_MAX_FUNCS
#define CMP_DELTA_MAX   20          /* kasus divergen yang dicatat */
#define CMP_PRNG_SEED   0x9E3779B9u

/* Satu fungsi yang dibandingkan: baterai dibangkitkan dari UNION
 * kontrak kedua versi (deterministik, identik untuk keduanya). */
typedef struct {
    char  name[DRV_MAX_LEN];
    int   ref_fi;                   /* index di funcs_ref */
    int   new_fi;                   /* index di funcs_new */
    int   nint;                     /* jumlah param integer */
    int   intp[DRV_MAX_PARAMS];     /* index param integer */
    long *cases;                    /* ncases x nint (malloc'd) */
    int   ncases;
    int   abi_same;
    int   domain_same;
    char  spec[160];                /* domain spec "lo..hi,lo..hi" */
    char  abi_ref[192];
    char  abi_new[192];
} cmp_func;

/* PRNG deterministik (xorshift32). */
static unsigned cmp_rng_state = CMP_PRNG_SEED;
static unsigned cmp_rng_next(void)
{
    unsigned x = cmp_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    cmp_rng_state = x;
    return x;
}

/* Gabungkan kandidat kedua versi + boundary portfolio + PRNG dalam
 * rentang gabungan. Hasil di cands (dedup). */
static int cmp_param_candidates(const drv_func *fr, const drv_func *fn,
                                int pi, long *cands, int maxc)
{
    long local[DRV_MAX_CANDS * 2];
    int  nlocal = 0;
    long pf_lo = 0, pf_hi = 0;
    int  pf_has = 0;
    int  i, k;
    memset(local, 0, sizeof(local));
    build_candidates(fr, pi, local, &nlocal);
    {
        long extra[DRV_MAX_CANDS];
        int  ne = 0;
        build_candidates(fn, pi, extra, &ne);
        for (i = 0; i < ne && nlocal < (int)(sizeof(local) / sizeof(local[0]));
             i++) {
            int dup = 0;
            for (k = 0; k < nlocal; k++)
                if (local[k] == extra[i]) {
                    dup = 1;
                    break;
                }
            if (!dup)
                local[nlocal++] = extra[i];
        }
    }
    /* boundary portfolio: 0, 1, -1, INT_MAX, INT_MIN */
    cand_add(local, &nlocal, 0);
    cand_add(local, &nlocal, 1);
    cand_add(local, &nlocal, -1);
    cand_add(local, &nlocal, 2147483647LL);
    cand_add(local, &nlocal, -2147483647LL - 1);
    /* rentang gabungan untuk PRNG */
    {
        drv_bounds br, bn;
        memset(&br, 0, sizeof(br));
        memset(&bn, 0, sizeof(bn));
        for (i = 0; i < fr->nreqs; i++)
            parse_bound(fr->reqs[i], fr->pname[pi], &br);
        for (i = 0; i < fn->nreqs; i++)
            parse_bound(fn->reqs[i], fn->pname[pi], &bn);
        if (br.has_lo || bn.has_lo) {
            pf_lo = br.has_lo ? br.lo : bn.lo;
            if (bn.has_lo && bn.lo < pf_lo)
                pf_lo = bn.lo;
            pf_has = 1;
        }
        if (br.has_hi || bn.has_hi) {
            pf_hi = br.has_hi ? br.hi : bn.hi;
            if (bn.has_hi && bn.hi > pf_hi)
                pf_hi = bn.hi;
            pf_has = 1;
        }
        if (!pf_has) {
            pf_lo = -64;
            pf_hi = 64;
        }
    }
    /* 16 nilai PRNG deterministik dalam rentang (perluas 25%) */
    {
        long span = pf_hi - pf_lo + 1;
        long pad = (span + 3) / 4;
        long lo2 = pf_lo - pad, hi2 = pf_hi + pad;
        long long rspan = (long long)hi2 - lo2 + 1;
        long long step = rspan / 65536 + 1;
        for (i = 0; i < 16 && nlocal < (int)(sizeof(local) / sizeof(local[0]));
             i++) {
            long long v = lo2 + (long long)(cmp_rng_next() % 65536) * step;
            if (v < lo2)
                v = lo2;
            if (v > hi2)
                v = hi2;
            cand_add(local, &nlocal, v);
        }
    }
    /* pindahkan ke output (dedup sudah oleh cand_add) */
    if (nlocal > maxc)
        nlocal = maxc;
    for (i = 0; i < nlocal; i++)
        cands[i] = local[i];
    return nlocal;
}

/* Bangun baterai untuk satu fungsi: produk kartesian kandidat per param
 * (deterministik; terbatas CMP_MAX_CASES). Return 0 bila tak ada param
 * integer. */
static int cmp_build_battery(cmp_func *cf, const drv_func *fr,
                             const drv_func *fn)
{
    long cands[DRV_MAX_PARAMS][DRV_MAX_CANDS * 2];
    int  nc[DRV_MAX_PARAMS];
    int  p;
    long dim[DRV_MAX_PARAMS];
    long total = 1;
    long ix[DRV_MAX_PARAMS];
    int  q, c;
    memset(cands, 0, sizeof(cands));
    memset(nc, 0, sizeof(nc));
    memset(dim, 0, sizeof(dim));
    memset(ix, 0, sizeof(ix));
    cf->nint = 0;
    for (p = 0; p < fr->nparams && cf->nint < DRV_MAX_PARAMS; p++) {
        if (fr->is_ptr[p])
            continue;               /* pointer: bukan dimensi baterai */
        if (cf->nint >= DRV_MAX_PARAMS)
            break;
        nc[cf->nint] = cmp_param_candidates(fr, fn, p,
                                            cands[cf->nint],
                                            DRV_MAX_CANDS * 2);
        dim[cf->nint] = nc[cf->nint] > 0 ? nc[cf->nint] : 1;
        cf->intp[cf->nint] = p;
        cf->nint++;
    }
    if (cf->nint == 0)
        return 0;
    for (q = 0; q < cf->nint; q++) {
        if (total > CMP_MAX_CASES / dim[q]) {
            total = CMP_MAX_CASES;
            break;
        }
        total *= dim[q];
    }
    if (total > CMP_MAX_CASES)
        total = CMP_MAX_CASES;
    cf->ncases = (int)total;
    cf->cases = (long *)malloc(sizeof(long) * (size_t)cf->ncases *
                               (size_t)cf->nint);
    if (!cf->cases) {
        cf->ncases = 0;
        return 0;
    }
    for (c = 0; c < cf->ncases; c++) {
        for (q = 0; q < cf->nint; q++)
            cf->cases[(size_t)c * (size_t)cf->nint + q] =
                cands[q][ix[q]];
        /* majukan odometer */
        for (q = 0; q < cf->nint; q++) {
            ix[q]++;
            if (ix[q] < dim[q])
                break;
            ix[q] = 0;
        }
    }
    /* spec "lo..hi" per dim (pakai min/max dari baterai) */
    {
        size_t off = 0;
        for (q = 0; q < cf->nint; q++) {
            long lo = cands[q][0], hi = cands[q][0];
            int  k;
            for (k = 1; k < nc[q]; k++) {
                if (cands[q][k] < lo)
                    lo = cands[q][k];
                if (cands[q][k] > hi)
                    hi = cands[q][k];
            }
            {
                int r = snprintf(cf->spec + off, sizeof(cf->spec) - off,
                                 "%s%ld..%ld", q ? "," : "", lo, hi);
                if (r > 0)
                    off += (size_t)r;
                if (off >= sizeof(cf->spec))
                    off = sizeof(cf->spec) - 1;
            }
        }
    }
    return 1;
}

/* Generate harness compare untuk SATU versi (case table literal sama
 * untuk kedua versi — baterai identik). Rename main asli. */
static char *gen_compare_harness(const char *src, size_t srclen,
                                 const cmp_func *cf, const drv_func *f,
                                 int gid_base, size_t *out_len)
{
    drv_buf b;
    int     p, c;
    memset(&b, 0, sizeof(b));
    drv_buf_puts(&b, "#include <stdio.h>\n#include <stdlib.h>\n"
                     "#include <string.h>\n#include <errno.h>\n");
    drv_buf_puts(&b, "#define main myc_cmp_orig_main\n");
    drv_buf_putn(&b, src, srclen);
    drv_buf_puts(&b, "\n#undef main\n\n");
    drv_buf_puts(&b, "int main(void) {\n");
    drv_buf_puts(&b, "    setvbuf(stdout, NULL, _IONBF, 0);\n");
    /* case table literal */
    drv_buf_printf(&b, "    static const long long CMP_C[%d][%d] = {\n",
                   cf->ncases, cf->nint);
    for (c = 0; c < cf->ncases; c++) {
        drv_buf_puts(&b, "        {");
        for (p = 0; p < cf->nint; p++) {
            drv_buf_printf(&b, "%s%lld", p ? "," : "",
                           (long long)cf->cases[(size_t)c * (size_t)cf->nint
                                                + p]);
        }
        drv_buf_puts(&b, "},\n");
    }
    drv_buf_puts(&b, "    };\n");
    drv_buf_printf(&b,
        "    for (int i = 0; i < %d; i++) {\n", cf->ncases);
    for (p = 0; p < f->nparams; p++) {
        if (f->is_ptr[p]) {
            drv_buf_printf(&b,
                "        %s arg%d = (%s)calloc(64, 1);\n",
                f->type[p], p, f->type[p]);
        } else {
            int q;
            int found = -1;
            for (q = 0; q < cf->nint; q++)
                if (cf->intp[q] == p)
                    found = q;
            if (found >= 0)
                drv_buf_printf(&b,
                    "        %s arg%d = (%s)CMP_C[i][%d];\n",
                    f->type[p], p, f->type[p], found);
            else
                drv_buf_printf(&b, "        %s arg%d = 0;\n",
                               f->type[p], p);
        }
    }
    drv_buf_puts(&b, "        errno = 0;\n");
    drv_buf_printf(&b,
        "        printf(\"CASE %d_%%d \", i);\n", gid_base);
    drv_buf_printf(&b, "        %s(", f->name);
    for (p = 0; p < f->nparams; p++)
        drv_buf_printf(&b, "%sarg%d", p ? "," : "", p);
    drv_buf_puts(&b, ");\n");
    if (f->ret_void) {
        drv_buf_puts(&b, "        printf(\"ret=void errno=%d\\n\", errno);\n");
    } else if (f->ret_ptr) {
        drv_buf_puts(&b, "        printf(\"ret=ptr errno=%d\\n\", errno);\n");
    } else {
        drv_buf_printf(&b,
            "        printf(\"ret=%%lld errno=%%d\\n\", (long long)(%s(",
            f->name);
        for (p = 0; p < f->nparams; p++)
            drv_buf_printf(&b, "%sarg%d", p ? "," : "", p);
        drv_buf_puts(&b, ")), errno);\n");
    }
    /* free pointer args */
    for (p = 0; p < f->nparams; p++) {
        if (f->is_ptr[p])
            drv_buf_printf(&b, "        free((void*)arg%d);\n", p);
    }
    drv_buf_puts(&b, "    }\n");
    drv_buf_puts(&b, "    return 0;\n}\n");
    *out_len = b.len;
    return b.data;
}

/* Build + run satu harness compare; isi stdout/exit. Return 1 sukses. */
static int cmp_build_run(const myc_request *req, const char *harness,
                         size_t harness_len, const char *clang_path,
                         const char *tmp_dir, const char *exe_name,
                         char **out_stdout, int *out_exit,
                         size_t max_out, myc_result *res)
{
    const char **build_argv = NULL;
    const char **run_argv = NULL;
    char *exe_path = NULL;
    myc_proc_request preq;
    myc_proc_result  pres;
    static const char *const CMP_BASE_FLAGS[] = {
        "-x", "c", "-", "-std=c11", "-O0", "-g",
        "-fsanitize=address,undefined",
        "-fno-sanitize-recover=all",
        NULL
    };
    static const char *const CMP_RUN_ENV[] = {
        "ASAN_OPTIONS=log_path=myc_cmp_asan_rpt:abort_on_error=1:"
        "halt_on_error=1",
        "UBSAN_OPTIONS=log_path=myc_cmp_ubsan_rpt:halt_on_error=1:"
        "print_stacktrace=1",
        "LC_ALL=C",
        NULL
    };
    int bfl, n = 0, total = 0;
    int ret = 0;

    exe_path = drv_join_path(tmp_dir, exe_name);
    if (!exe_path)
        return 0;
    for (bfl = 0; CMP_BASE_FLAGS[bfl]; bfl++)
        total++;
    total += 2 + 1 + 1;   /* clang + flags + -o + exe + NULL */
    build_argv = (const char **)malloc(sizeof(char *) * (size_t)total);
    if (!build_argv) {
        free(exe_path);
        return 0;
    }
    build_argv[n++] = clang_path;
    for (bfl = 0; CMP_BASE_FLAGS[bfl]; bfl++)
        build_argv[n++] = CMP_BASE_FLAGS[bfl];
    build_argv[n++] = "-o";
    build_argv[n++] = exe_path;
    build_argv[n] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = build_argv;
    preq.cwd = req->cwd;
    preq.stdin_data = harness;
    preq.stdin_len = harness_len;
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = max_out;
    if (!myc_proc_run(&preq, &pres)) {
        res->err = pres.timed_out ? MYC_ERR_TIMEOUT
                                  : MYC_ERR_EXECUTE_FAILED;
        myc_proc_result_free(&pres);
        free(build_argv);
        free(exe_path);
        return 0;
    }
    res->duration_ms += pres.duration_ms;
    if (pres.exit_code != 0) {
        myc_proc_result_free(&pres);
        free(build_argv);
        free(exe_path);
        return 0;
    }
    myc_proc_result_free(&pres);
    free(build_argv);

#ifdef _WIN32
    {
        char *dll_src = drv_asan_dll_path(clang_path);
        char *dll_dst = NULL;
        if (dll_src) {
            dll_dst = drv_join_path(tmp_dir, ASAN_DLL_NAME);
            if (dll_dst)
                drv_copy_file(dll_src, dll_dst);
        }
        free(dll_src);
        free(dll_dst);
    }
#endif

    run_argv = (const char **)malloc(sizeof(char *) * 2);
    if (!run_argv) {
        free(exe_path);
        return 0;
    }
    run_argv[0] = exe_path;
    run_argv[1] = NULL;
    memset(&preq, 0, sizeof(preq));
    preq.argv = run_argv;
    preq.cwd = tmp_dir;
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = max_out;
    preq.env = CMP_RUN_ENV;
    if (!myc_proc_run(&preq, &pres)) {
        res->err = pres.timed_out ? MYC_ERR_TIMEOUT
                                  : MYC_ERR_EXECUTE_FAILED;
        myc_proc_result_free(&pres);
        free(run_argv);
        free(exe_path);
        return 0;
    }
    res->duration_ms += pres.duration_ms;
    *out_stdout = pres.stdout_data;
    pres.stdout_data = NULL;
    *out_exit = pres.exit_code;
    myc_proc_result_free(&pres);
    free(run_argv);
    free(exe_path);
    ret = 1;
    return ret;
}

/* ABI signature: "ret name(t1,t2,...)". */
static void cmp_abi_sig(const drv_func *f, char *out, size_t cap)
{
    size_t off = 0;
    int    p;
    off += (size_t)snprintf(out + off, cap - off, "%s %s(",
                            f->ret[0] ? f->ret : "int", f->name);
    for (p = 0; p < f->nparams && off < cap; p++)
        off += (size_t)snprintf(out + off, cap - off, "%s%s",
                                p ? "," : "", f->type[p]);
    if (off < cap)
        off += (size_t)snprintf(out + off, cap - off, ")");
}

/* --- Gate A4: differential oracle pair --- */
int myc_compare_gate(const myc_request *req,
                     const char *ref_src, size_t ref_len,
                     const char *new_src, size_t new_len,
                     const char *const *func_filter, int nfunc_filter,
                     myc_result *res)
{
    drv_func funcs_ref[DRV_MAX_FUNCS];
    drv_func funcs_new[DRV_MAX_FUNCS];
    cmp_func cf[CMP_MAX_FUNCS];
    int nref, nnew, ncfs = 0;
    int i, j, k;
    char *clang_path = NULL;
    char *tmp_dir = NULL;
    char *h_ref = NULL, *h_new = NULL;
    size_t hl_ref = 0, hl_new = 0;
    char *out_ref = NULL, *out_new = NULL;
    int exit_ref = 0, exit_new = 0;
    size_t max_out = req->max_output_bytes > 0
                         ? (size_t)req->max_output_bytes
                         : MYC_MAX_OUTPUT_BYTES;
    int identical_total = 0, divergent_total = 0;
    char rep[2048];
    size_t roff = 0;

    myc_gate_set_status(res, MYC_GATE_COMPARE, MYC_GATE_NOT_APPLICABLE,
                        NULL);
    res->compare_preserved = 0;
    res->compare_abi_same = 1;
    res->compare_domain_same = 1;
    res->compare_unobserved = 0;

    /* 1. Scan fungsi ber-kontrak kedua versi. */
    nref = scan_contract_funcs(ref_src, ref_len, funcs_ref, DRV_MAX_FUNCS);
    nnew = scan_contract_funcs(new_src, new_len, funcs_new, DRV_MAX_FUNCS);
    if (nref == 0 || nnew == 0) {
        add_diag_drv(res, "compare di-skip: salah satu file tanpa fungsi "
                          "ber-kontrak");
        myc_gate_set_status(res, MYC_GATE_COMPARE,
                            MYC_GATE_NOT_APPLICABLE,
                            "tanpa fungsi ber-kontrak");
        myc_result_add_evidence(res, MYC_GATE_COMPARE,
                                MYC_EVIDENCE_SKIP,
                                "compare: tanpa fungsi ber-kontrak");
        return 0;
    }

    /* 2. Pasangkan fungsi dengan nama sama (atau filter). */
    for (i = 0; i < nref && ncfs < CMP_MAX_FUNCS; i++) {
        const drv_func *fr = &funcs_ref[i];
        const drv_func *fn = NULL;
        int fidx = -1;
        if (fr->unsupported)
            continue;
        if (nfunc_filter > 0) {
            int hit = 0;
            for (k = 0; k < nfunc_filter; k++)
                if (func_filter[k] && strcmp(func_filter[k], fr->name) == 0)
                    hit = 1;
            if (!hit)
                continue;
        }
        for (j = 0; j < nnew; j++) {
            if (!funcs_new[j].unsupported &&
                strcmp(funcs_new[j].name, fr->name) == 0) {
                fn = &funcs_new[j];
                fidx = j;
                break;
            }
        }
        if (!fn) {
            res->compare_unobserved++;
            continue;
        }
        memset(&cf[ncfs], 0, sizeof(cf[ncfs]));
        snprintf(cf[ncfs].name, sizeof(cf[ncfs].name), "%.63s", fr->name);
        cf[ncfs].ref_fi = i;
        cf[ncfs].new_fi = fidx;
        if (!cmp_build_battery(&cf[ncfs], fr, fn)) {
            res->compare_unobserved++;
            continue;
        }
        cmp_abi_sig(fr, cf[ncfs].abi_ref, sizeof(cf[ncfs].abi_ref));
        cmp_abi_sig(fn, cf[ncfs].abi_new, sizeof(cf[ncfs].abi_new));
        cf[ncfs].abi_same =
            strcmp(cf[ncfs].abi_ref, cf[ncfs].abi_new) == 0;
        if (!cf[ncfs].abi_same)
            res->compare_abi_same = 0;
        {
            char sref[256], snew[256];
            int  r;
            sref[0] = snew[0] = '\0';
            for (r = 0; r < fr->nreqs && r < DRV_MAX_REQS; r++) {
                strncat(sref, fr->reqs[r], sizeof(sref) - strlen(sref) - 1);
                strncat(sref, ";", sizeof(sref) - strlen(sref) - 1);
            }
            for (r = 0; r < fn->nreqs && r < DRV_MAX_REQS; r++) {
                strncat(snew, fn->reqs[r], sizeof(snew) - strlen(snew) - 1);
                strncat(snew, ";", sizeof(snew) - strlen(snew) - 1);
            }
            if (strcmp(sref, snew) != 0)
                res->compare_domain_same = 0;
        }
        ncfs++;
    }
    if (ncfs == 0) {
        add_diag_drv(res, "compare di-skip: tidak ada fungsi ber-kontrak "
                          "dengan nama sama");
        myc_gate_set_status(res, MYC_GATE_COMPARE,
                            MYC_GATE_NOT_APPLICABLE,
                            "tanpa fungsi berpasangan");
        myc_result_add_evidence(res, MYC_GATE_COMPARE,
                                MYC_EVIDENCE_SKIP,
                                "compare: tanpa fungsi berpasangan");
        return 0;
    }

    /* 3. clang + tmp dir. */
    clang_path = myc_find_executable(req->clang_program
                                         ? req->clang_program : "clang");
    if (!clang_path) {
        res->err = MYC_ERR_CLANG_NOT_FOUND;
        add_diag_drv(res, "compare di-skip: clang tidak ditemukan");
        myc_gate_set_status(res, MYC_GATE_COMPARE, MYC_GATE_UNAVAILABLE,
                            "clang tidak ditemukan");
        myc_result_add_evidence(res, MYC_GATE_COMPARE,
                                MYC_EVIDENCE_SKIP,
                                "compare di-skip: clang hilang");
        goto out_free_cfs;
    }
    tmp_dir = drv_make_temp_dir();
    if (!tmp_dir) {
        res->err = MYC_ERR_INTERNAL;
        goto out_free_cfs;
    }

    /* 4. Build + run kedua versi (baterai sama). */
    res->ran_compare = 1;
    res->compare_funcs = ncfs;
    res->compare_cases = 0;
    for (i = 0; i < ncfs; i++) {
        h_ref = gen_compare_harness(ref_src, ref_len, &cf[i],
                                    &funcs_ref[cf[i].ref_fi], i,
                                    &hl_ref);
        h_new = gen_compare_harness(new_src, new_len, &cf[i],
                                    &funcs_new[cf[i].new_fi], i,
                                    &hl_new);
        if (!h_ref || !h_new) {
            free(h_ref);
            free(h_new);
            res->err = MYC_ERR_INTERNAL;
            goto out_cleanup;
        }
        if (!cmp_build_run(req, h_ref, hl_ref, clang_path, tmp_dir,
                           "myc_cmp_ref.exe", &out_ref, &exit_ref,
                           max_out, res) ||
            !cmp_build_run(req, h_new, hl_new, clang_path, tmp_dir,
                           "myc_cmp_new.exe", &out_new, &exit_new,
                           max_out, res)) {
            add_diag_drv(res, "compare di-skip: build/run harness gagal "
                              "(fungsi ini tidak ikut)");
            free(h_ref);
            free(h_new);
            free(out_ref);
            free(out_new);
            out_ref = out_new = NULL;
            res->compare_unobserved++;
            res->compare_funcs--;
            continue;
        }
        /* 5. Bandingkan per baris CASE. */
        {
            char line_ref[1024], line_new[1024];
            size_t pr = 0, pn = 0;
            int identical = 0, divergent = 0;
            char delta[2048];
            size_t doff = 0;
            delta[0] = '\0';
            while (pr < strlen(out_ref) && pn < strlen(out_new)) {
                size_t er = pr, en = pn;
                while (er < strlen(out_ref) && out_ref[er] != '\n')
                    er++;
                while (en < strlen(out_new) && out_new[en] != '\n')
                    en++;
                {
                    size_t nr = er - pr, nn = en - pn;
                    if (nr >= sizeof(line_ref))
                        nr = sizeof(line_ref) - 1;
                    if (nn >= sizeof(line_new))
                        nn = sizeof(line_new) - 1;
                    memcpy(line_ref, out_ref + pr, nr);
                    line_ref[nr] = '\0';
                    memcpy(line_new, out_new + pn, nn);
                    line_new[nn] = '\0';
                }
                if (strcmp(line_ref, line_new) == 0)
                    identical++;
                else {
                    divergent++;
                    if (doff < sizeof(delta) && divergent <= CMP_DELTA_MAX) {
                        int r = snprintf(delta + doff, sizeof(delta) - doff,
                                         "%s  %s\n    ref : %s\n"
                                         "    new : %s\n",
                                         doff ? "\n" : "", line_ref,
                                         line_ref, line_new);
                        if (r > 0)
                            doff += (size_t)r;
                        if (doff >= sizeof(delta))
                            doff = sizeof(delta) - 1;
                    }
                }
                pr = er + 1;
                pn = en + 1;
            }
            /* sisa baris yang tak tertandingi (jumlah baris beda) */
            while (pr < strlen(out_ref)) {
                size_t er = pr;
                while (er < strlen(out_ref) && out_ref[er] != '\n')
                    er++;
                divergent++;
                pr = er + 1;
            }
            while (pn < strlen(out_new)) {
                size_t en = pn;
                while (en < strlen(out_new) && out_new[en] != '\n')
                    en++;
                divergent++;
                pn = en + 1;
            }
            if (exit_ref != exit_new)
                divergent += 1;
            identical_total += identical;
            divergent_total += divergent;
            res->compare_cases += (long)(identical + divergent);
            if (divergent > 0) {
                char note[256];
                snprintf(note, sizeof(note),
                         "compare: %.63s divergen %d kasus",
                         cf[i].name, divergent);
                add_diag_drv(res, note);
                myc_result_add_evidence(res, MYC_GATE_COMPARE,
                                        MYC_EVIDENCE_FINDING, note);
                if (delta[0] && !res->compare_delta) {
                    res->compare_delta =
                        myc_result_arena_dup(res, delta, 0);
                }
            }
        }
        free(h_ref);
        free(h_new);
        free(out_ref);
        free(out_new);
        h_ref = h_new = NULL;
        out_ref = out_new = NULL;
    }

    /* 6. Digest stdout utuh (escrow) */
    {
        char hex[65];
        if (out_ref)
            sha256_hex(out_ref, strlen(out_ref), hex);
        else
            memset(hex, '0', 64), hex[64] = '\0';
        snprintf(res->compare_ref_digest, sizeof(res->compare_ref_digest),
                 "%s", hex);
        if (out_new)
            sha256_hex(out_new, strlen(out_new), hex);
        else
            memset(hex, '0', 64), hex[64] = '\0';
        snprintf(res->compare_new_digest, sizeof(res->compare_new_digest),
                 "%s", hex);
    }

    /* 7. Report ringkas. */
    res->compare_identical = identical_total;
    res->compare_divergent = divergent_total;
    res->compare_preserved =
        (divergent_total == 0 && ncfs > 0 &&
         res->compare_cases > 0);
    {
        int d;
        roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
            "compare (A4): %d fungsi, %ld kasus, %ld identik, %ld divergen\n",
            ncfs, res->compare_cases, (long)identical_total,
            (long)divergent_total);
        for (d = 0; d < ncfs; d++) {
            int r = snprintf(rep + roff, sizeof(rep) - roff,
                "  %s: %ld kasus%s\n", cf[d].name,
                res->compare_cases > 0
                    ? res->compare_cases / (long)ncfs : 0L,
                cf[d].abi_same ? "" : " -- ABI BERUBAH");
            if (r > 0)
                roff += (size_t)r;
            if (roff >= sizeof(rep))
                roff = sizeof(rep) - 1;
        }
        if (!res->compare_abi_same)
            roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
                "  ABI signature: BERUBAH (unexpected_change, DS-04)\n");
        if (!res->compare_domain_same)
            roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
                "  domain hash: BERUBAH (unexpected_change, DS-04)\n");
        if (res->compare_unobserved > 0)
            roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
                "  unobserved: %d fungsi (tak berpasangan / tanpa param "
                "integer / build gagal)\n", res->compare_unobserved);
        if (roff >= sizeof(rep))
            roff = sizeof(rep) - 1;
        res->compare_report = myc_result_arena_dup(res, rep, 0);
    }

    /* 8. Verdict + gate status. */
    if (res->compare_preserved) {
        myc_gate_set_status(res, MYC_GATE_COMPARE, MYC_GATE_COMPLETED_CLEAN,
                            "behavior-preserving (P1 DIFF)");
        myc_result_add_evidence(res, MYC_GATE_COMPARE,
                                MYC_EVIDENCE_GATE_END,
                                "compare: behavior-preserving (P1 DIFF)");
    } else {
        myc_gate_set_status(res, MYC_GATE_COMPARE,
                            MYC_GATE_COMPLETED_FINDINGS,
                            "divergen: unexpected_change (DS-04)");
        myc_result_add_evidence(res, MYC_GATE_COMPARE,
                                MYC_EVIDENCE_FINDING,
                                "compare: unexpected_change (DS-04)");
        add_diag_drv(res, "compare: perilaku BERUBAH antar versi "
                          "(unexpected_change, DS-04) -- daftar kasus "
                          "divergen di compare_delta");
    }

out_cleanup:
    free(h_ref);
    free(h_new);
    free(out_ref);
    free(out_new);
    if (tmp_dir) {
        {
            char *p = drv_join_path(tmp_dir, "myc_cmp_ref.exe");
            if (p) {
                remove(p);
                free(p);
            }
        }
        {
            char *p = drv_join_path(tmp_dir, "myc_cmp_new.exe");
            if (p) {
                remove(p);
                free(p);
            }
        }
        myc_rmdir(tmp_dir);
        free(tmp_dir);
    }
    free(clang_path);
out_free_cfs:
    for (i = 0; i < ncfs; i++)
        free(cf[i].cases);
    return res->compare_preserved ? 1 : 0;
}
