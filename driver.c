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
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define myc_mkdir(path) mkdir(path, 0700)
#define myc_rmdir(path) rmdir(path)
#define myc_getpid() getpid()
#endif

#include "proc.h"

#include "gate.h"

#define DRV_MAX_FUNCS  8
#define DRV_MAX_PARAMS 6
#define DRV_MAX_REQS   4
#define DRV_MAX_CASES  8
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
                         size_t *out_len)
{
    drv_buf b;
    int     f;
    memset(&b, 0, sizeof(b));

    drv_buf_puts(&b, "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n");
    drv_buf_puts(&b, "#define main myc_driver_orig_main\n");
    drv_buf_putn(&b, src, srclen);
    drv_buf_puts(&b, "\n#undef main\n\n");
    drv_buf_puts(&b, "static int drv_run = 0;\n");
    drv_buf_puts(&b, "static int drv_skip = 0;\n\n");
    drv_buf_puts(&b, "int main(void) {\n");

    for (f = 0; f < nfuncs; f++) {
        const drv_func *fn = &funcs[f];
        long cands[DRV_MAX_PARAMS][DRV_MAX_CANDS];
        int  nc[DRV_MAX_PARAMS];
        long psize[DRV_MAX_PARAMS];
        long ncases = 1;
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
            if (ncases < DRV_MAX_CASES)
                ncases *= nc[p];
            if (ncases > DRV_MAX_CASES)
                ncases = DRV_MAX_CASES;
        }
        if (ncases < 1)
            ncases = 1;

        for (ci = 0; ci < (int)ncases; ci++) {
            int idx[DRV_MAX_PARAMS];
            long v[DRV_MAX_PARAMS];
            int  rem = ci;
            int  p;
            for (p = 0; p < fn->nparams; p++) {
                idx[p] = rem % nc[p];
                rem /= nc[p];
            }
            for (p = 0; p < fn->nparams; p++) {
                if (fn->is_ptr[p]) {
                    v[p] = psize[p];
                } else {
                    v[p] = cands[p][idx[p]];
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
            drv_buf_puts(&b, ") {\n            drv_run++;\n            (void)");
            drv_buf_puts(&b, fn->name);
            drv_buf_puts(&b, "(");
            for (p = 0; p < fn->nparams; p++) {
                if (p)
                    drv_buf_puts(&b, ", ");
                drv_buf_puts(&b, fn->pname[p]);
            }
            drv_buf_puts(&b, ");\n        } else {\n");
            drv_buf_puts(&b, "            drv_skip++;\n        }\n");
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
    char       *dir;
    int         n = 0;
    size_t      bl;
#ifdef _WIN32
    if (!base || !*base)
        base = getenv("TMP");
#endif
    if (!base || !*base)
        base = ".";
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
    int      nfuncs;
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

    /* 2. Generate harness. */
    harness = gen_harness(source, source_len, funcs, nfuncs, &harness_len);
    if (!harness) {
        add_diag_drv(res, "driver di-skip: gagal generate harness");
        myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INFRA_FAILED,
                            "gagal generate harness");
        myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_ERROR,
                                "driver: harness generation failed");
        return 0;
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

    /* 8. Hitung jumlah fungsi yang benar-benar dipanggil & kasus. */
    res->driver_funcs = 0;
    res->driver_cases = 0;
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
