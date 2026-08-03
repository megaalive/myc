/*
 * proc.c -- Peluncur proses argv eksak untuk myc.
 *
 * Windows: CreateProcessA + command line yang dikonstruksi dengan aturan
 * CommandLineToArgvW, + Job Object untuk memastikan timeout membunuh
 * seluruh pohon proses. stdout/stderr di-drain dari thread terpisah
 * untuk menghindari deadlock. stdin ditulis sebagai data byte mentah.
 *
 * POSIX: fork + execvp + setpgid (process group, MYC-AUDIT-011) agar
 * timeout membunuh seluruh pohon child; drain serupa. Implementasi
 * POSIX memakai clock_gettime/setpgid yang butuh _POSIX_C_SOURCE.
 */
#ifndef _WIN32
/* Harus SEBELUM include sistem apa pun: clock_gettime, setpgid, strdup
 * (via myc_strdup di myc.h), nanosleep. -std=c11 menonaktifkan POSIX
 * extension glibc; gnu11 atau define ini wajib. */
#define _POSIX_C_SOURCE 200809L
#endif
#include "proc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>
#else
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

/* Marker sanitizer yang dicari pada output streaming.
 * Daftar ini harus konsisten dengan run.c. */
static const char *const STREAM_SANITIZER_MARKERS[] = {
    "ERROR: AddressSanitizer",
    "SUMMARY: AddressSanitizer",
    "AddressSanitizer:",
    "UndefinedBehaviorSanitizer",
    "LeakSanitizer",
    NULL
};

/* Periksa apakah sebuah chunk mengandung marker sanitizer.
 * Mengembalikan pointer ke marker yang cocok atau NULL. */
static const char *stream_sanitizer_match(const char *buf, size_t len)
{
    size_t i, j;
    for (i = 0; STREAM_SANITIZER_MARKERS[i]; i++) {
        size_t mlen = strlen(STREAM_SANITIZER_MARKERS[i]);
        if (mlen > len) continue;
        for (j = 0; j <= len - mlen; j++) {
            if (memcmp(buf + j, STREAM_SANITIZER_MARKERS[i], mlen) == 0)
                return STREAM_SANITIZER_MARKERS[i];
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Saluran laporan sanitizer (MYC-AUDIT-017)                            */
/* ------------------------------------------------------------------ */
/* ASan/UBSan dengan log_path=<base> menulis report ke "<base>.<pid>" di
 * direktori kerja child. Baca file pertama yang cocok <dir>/<base>.* dan
 * non-kosong. Path dibangun dinamis (panjang TEMP tak terbatas). */
char *myc_read_sanitizer_report(const char *dir, const char *base)
{
    char *content = NULL;
#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    HANDLE           h;
    size_t           plen = strlen(dir) + 1 + strlen(base) + 2 + 1;
    char            *pattern = (char *)malloc(plen);
    if (!pattern)
        return NULL;
    snprintf(pattern, plen, "%s/%s.*", dir, base);
    h = FindFirstFileA(pattern, &fd);
    free(pattern);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;
    do {
        size_t pathlen = strlen(dir) + 1 + strlen(fd.cFileName) + 1;
        char  *path = (char *)malloc(pathlen);
        FILE  *f;
        long   sz;
        if (!path)
            break;
        snprintf(path, pathlen, "%s/%s", dir, fd.cFileName);
        f = fopen(path, "rb");
        free(path);
        if (!f)
            continue;
        if (fseek(f, 0, SEEK_END) == 0) {
            sz = ftell(f);
            fseek(f, 0, SEEK_SET);
        } else {
            sz = 0;
        }
        if (sz > 0) {
            content = (char *)malloc((size_t)sz + 1);
            if (content) {
                if (fread(content, 1, (size_t)sz, f) == (size_t)sz) {
                    content[sz] = '\0';
                } else {
                    free(content);
                    content = NULL;
                }
            }
        }
        fclose(f);
        if (content)
            break;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR           *d = opendir(dir);
    struct dirent *e;
    size_t         bl = strlen(base);
    if (!d)
        return NULL;
    while ((e = readdir(d)) != NULL) {
        size_t nlen = strlen(e->d_name);
        size_t pathlen;
        char  *path;
        FILE  *f;
        long   sz;
        if (nlen < bl + 2 || memcmp(e->d_name, base, bl) != 0 ||
            e->d_name[bl] != '.')
            continue;
        pathlen = strlen(dir) + 1 + nlen + 1;
        path = (char *)malloc(pathlen);
        if (!path)
            break;
        snprintf(path, pathlen, "%s/%s", dir, e->d_name);
        f = fopen(path, "rb");
        free(path);
        if (!f)
            continue;
        if (fseek(f, 0, SEEK_END) == 0) {
            sz = ftell(f);
            fseek(f, 0, SEEK_SET);
        } else {
            sz = 0;
        }
        if (sz > 0) {
            content = (char *)malloc((size_t)sz + 1);
            if (content) {
                if (fread(content, 1, (size_t)sz, f) == (size_t)sz) {
                    content[sz] = '\0';
                } else {
                    free(content);
                    content = NULL;
                }
            }
        }
        fclose(f);
        if (content)
            break;
    }
    closedir(d);
#endif
    return content;
}

void myc_remove_sanitizer_reports(const char *dir, const char *base)
{
#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    HANDLE           h;
    size_t           plen = strlen(dir) + 1 + strlen(base) + 2 + 1;
    char            *pattern = (char *)malloc(plen);
    if (!pattern)
        return;
    snprintf(pattern, plen, "%s/%s.*", dir, base);
    h = FindFirstFileA(pattern, &fd);
    free(pattern);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do {
        size_t pathlen = strlen(dir) + 1 + strlen(fd.cFileName) + 1;
        char  *path = (char *)malloc(pathlen);
        if (path) {
            snprintf(path, pathlen, "%s/%s", dir, fd.cFileName);
            DeleteFileA(path);
            free(path);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR           *d = opendir(dir);
    struct dirent *e;
    size_t         bl = strlen(base);
    if (!d)
        return;
    while ((e = readdir(d)) != NULL) {
        size_t nlen = strlen(e->d_name);
        size_t pathlen;
        char  *path;
        if (nlen < bl + 2 || memcmp(e->d_name, base, bl) != 0 ||
            e->d_name[bl] != '.')
            continue;
        pathlen = strlen(dir) + 1 + nlen + 1;
        path = (char *)malloc(pathlen);
        if (path) {
            snprintf(path, pathlen, "%s/%s", dir, e->d_name);
            unlink(path);
            free(path);
        }
    }
    closedir(d);
#endif
}

/* ------------------------------------------------------------------ */
/* myc_strdup (portability MYC-AUDIT-011 enabler)                      */
/* ------------------------------------------------------------------ */
/* _strdup adalah MSVC/MinGW-only; POSIX memakai strdup (butuh
 * _POSIX_C_SOURCE/gnu11). Implementasi diletakkan di proc.c karena
 * modul ini selalu di-link (myc.exe, mcp.exe, dan test unit proc_flood /
 * verify_descendants yang hanya men-link proc.c). Memeriksa hasil malloc
 * (idiom aman, lolos lint myc). */
char *myc_strdup(const char *s)
{
    size_t n;
    char  *r;
    if (!s)
        return NULL;
    n = strlen(s) + 1;
    r = (char *)malloc(n);
    if (r)
        memcpy(r, s, n);
    return r;
}

/* ------------------------------------------------------------------ */
/* myc_tool_version (MYC-AUDIT-022, roadmap 7.1: exact tool identity)  */
/* ------------------------------------------------------------------ */
/* Jalankan <exe> --version, ambil BARIS PERTAMA non-kosong dari stdout
 * sebagai identitas versi tool (mis. "gcc.exe (...) 15.2.0" / "clang
 * version 22.1.6 (...)"). Diletakkan di proc.c karena modul ini selalu
 * di-link (myc.exe, mcp.exe, dan unit test yang hanya men-link proc.c).
 * Mengembalikan malloc'd string, atau NULL bila exec gagal / exit != 0 /
 * stdout kosong (backend tersedia tapi versi tidak terbaca -> NULL
 * ditangani pemanggil sebagai "tidak diketahui"). */
char *myc_tool_version(const char *exe)
{
    myc_proc_request preq;
    myc_proc_result  pr;
    const char      *argv[3];
    const char      *nl;
    size_t           n;
    char            *v;

    if (!exe)
        return NULL;
    argv[0] = exe;
    argv[1] = "--version";
    argv[2] = NULL;
    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.timeout_ms = 10000;
    preq.max_output_bytes = 16384;
    memset(&pr, 0, sizeof(pr));
    if (!myc_proc_run(&preq, &pr)) {
        /* konsisten dgn konvensi proyek: myc_proc_result_free walau
         * launch gagal (buffer kemungkinan NULL, tapi aman) */
        myc_proc_result_free(&pr);
        return NULL;
    }
    if (pr.exit_code != 0 || !pr.stdout_data || !pr.stdout_data[0]) {
        myc_proc_result_free(&pr);
        return NULL;
    }
    nl = strchr(pr.stdout_data, '\n');
    n = nl ? (size_t)(nl - pr.stdout_data) : strlen(pr.stdout_data);
    /* buang trailing \r (CRLF Windows) */
    while (n > 0 &&
           (pr.stdout_data[n - 1] == '\r' || pr.stdout_data[n - 1] == '\n'))
        n--;
    if (n == 0) {
        myc_proc_result_free(&pr);
        return NULL;
    }
    v = (char *)malloc(n + 1);
    if (v) {
        memcpy(v, pr.stdout_data, n);
        v[n] = '\0';
    }
    myc_proc_result_free(&pr);
    return v;
}

/* ------------------------------------------------------------------ */
/* Pencarian executable                                                */
/* ------------------------------------------------------------------ */

static int has_sep(const char *p)
{
    return strchr(p, '/') != NULL || strchr(p, '\\') != NULL;
}

#ifdef _WIN32
static char *path_join(const char *dir, const char *name, const char *ext)
{
    size_t dl = dir ? strlen(dir) : 0;
    size_t nl = strlen(name);
    size_t el = ext ? strlen(ext) : 0;
    size_t need = dl + 1 + nl + el + 1;
    char   *out = (char *)malloc(need);
    if (!out)
        return NULL;
    if (dir && dl) {
        memcpy(out, dir, dl);
        out[dl] = '\\';
        memcpy(out + dl + 1, name, nl);
        memcpy(out + dl + 1 + nl, ext, el);
        out[dl + 1 + nl + el] = '\0';
    } else {
        memcpy(out, name, nl);
        memcpy(out + nl, ext, el);
        out[nl + el] = '\0';
    }
    return out;
}
#endif

char *myc_find_executable(const char *program)
{
    if (!program || !*program)
        return NULL;

#ifdef _WIN32
    static const char *exts[] = { ".exe", "" };
    char *path_env;
    char *cand;
    DWORD attrs;
    int i;

    /* Bila ada separator, pakai langsung (tanpa scan PATH). */
    if (has_sep(program)) {
        cand = myc_strdup(program);
        if (!cand)
            return NULL;
        attrs = GetFileAttributesA(cand);
        if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY))
            return cand;
        free(cand);
        return NULL;
    }

    /* Cari di PATH. */
    path_env = getenv("PATH");
    if (!path_env)
        return NULL;

    {
        char *dup = myc_strdup(path_env);
        char *save = NULL;
        char *tok = strtok_s(dup, ";", &save);
        while (tok) {
            for (i = 0; i < 2; i++) {
                cand = path_join(tok, program, exts[i]);
                if (!cand) {
                    free(dup);
                    return NULL;
                }
                attrs = GetFileAttributesA(cand);
                if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                    free(dup);
                    return cand;
                }
                free(cand);
            }
            tok = strtok_s(NULL, ";", &save);
        }
        free(dup);
    }
    return NULL;
#else
    /* POSIX: gunakan execvp yang mencari PATH sendiri. */
    if (has_sep(program)) {
        if (access(program, X_OK) == 0)
            return myc_strdup(program);
        return NULL;
    }
    /* Delegasikan pencarian PATH ke execvp; tandai butuh PATH search. */
    return myc_strdup(program);
#endif
}

/* ------------------------------------------------------------------ */
/* Override environment (MYC-AUDIT-017)                                 */
/* ------------------------------------------------------------------ */
/* Bangun environment block Windows dari blok induk + override
 * "KEY=VALUE" (nilai dengan key yang sama MENGGANTI; sisanya diwarisi).
 * Mengembalikan malloc'd "K=V\0K=V\0\0"; NULL bila gagal. */
#ifdef _WIN32
static char *build_env_block(const char *const *overrides)
{
    char  *parent = GetEnvironmentStringsA();
    char  *out = NULL;
    size_t len = 0, need = 1;
    int    o;
    if (!parent)
        return NULL;
    {
        char *p = parent;
        while (*p) {
            need += strlen(p) + 1;
            p += strlen(p) + 1;
        }
        for (o = 0; overrides[o]; o++)
            need += strlen(overrides[o]) + 1;
    }
    out = (char *)malloc(need);
    if (!out) {
        FreeEnvironmentStringsA(parent);
        return NULL;
    }
    /* salin entri induk, ganti yang di-override */
    {
        char *p = parent;
        while (*p) {
            const char *eq = strchr(p, '=');
            size_t      klen = eq ? (size_t)(eq - p) : strlen(p);
            int         replaced = 0;
            for (o = 0; overrides[o]; o++) {
                const char *oeq = strchr(overrides[o], '=');
                if (oeq && (size_t)(oeq - overrides[o]) == klen &&
                    memcmp(p, overrides[o], klen) == 0) {
                    replaced = 1;
                    break;
                }
            }
            if (!replaced) {
                size_t n = strlen(p) + 1;
                memcpy(out + len, p, n);
                len += n;
            }
            p += strlen(p) + 1;
        }
    }
    /* Tambahkan SEMUA override: entri induk yang key-nya di-override sudah
     * di-skip di loop atas, jadi menambahkan semua override di sini = ganti
     * (bukan duplikat). BUG YANG DIPERBAIKI (review MYC-AUDIT-017): versi
     * lama hanya menambahkan override yang key-nya TIDAK ada di induk,
     * sehingga override yang menggantikan key induk (mis. ASAN_OPTIONS bila
     * user set di env) DROP total -- child malah kehilangan variabel. */
    for (o = 0; overrides[o]; o++) {
        size_t n = strlen(overrides[o]) + 1;
        memcpy(out + len, overrides[o], n);
        len += n;
    }
    out[len] = '\0';
    FreeEnvironmentStringsA(parent);
    return out;
}
#else
/* environ: di-deklarasi unistd.h pada sebagian sistem; pastikan tersedia. */
extern char **environ;

/* Bangun env array baru: environ + override (malloc'd; child meng-assign
 * ke `environ` sebelum execvp -- tanpa alokasi di dalam child). */
static char **build_env_array(const char *const *overrides)
{
    int   n = 0, n_ov = 0, i, k = 0;
    char **out;
    while (environ[n])
        n++;
    for (i = 0; overrides && overrides[i]; i++)
        n_ov++;
    out = (char **)malloc(sizeof(char *) * ((size_t)n + (size_t)n_ov + 1));
    if (!out)
        return NULL;
    for (i = 0; i < n; i++) {
        const char *eq = strchr(environ[i], '=');
        int         replaced = 0;
        if (eq) {
            size_t klen = (size_t)(eq - environ[i]);
            int    o;
            for (o = 0; o < n_ov; o++) {
                const char *oeq = strchr(overrides[o], '=');
                if (oeq && (size_t)(oeq - overrides[o]) == klen &&
                    memcmp(environ[i], overrides[o], klen) == 0) {
                    replaced = 1;
                    break;
                }
            }
        }
        if (!replaced)
            out[k++] = environ[i];
    }
    for (i = 0; i < n_ov; i++)
        out[k++] = (char *)overrides[i];
    out[k] = NULL;
    return out;
}
#endif /* _WIN32 */

/* ------------------------------------------------------------------ */
/* Konstruksi command line Windows (aturan CommandLineToArgvW)          */
/* ------------------------------------------------------------------ */

#ifdef _WIN32
static void append_arg(char **buf, size_t *cap, size_t *len, const char *arg)
{
    size_t n = strlen(arg);
    size_t need;
    int    has_space = 0;
    const char *p;
    size_t i;

    /* Cek apakah perlu dikutip. */
    if (*arg == '\0')
        has_space = 1;
    for (p = arg; *p; p++) {
        if (*p == ' ' || *p == '\t') {
            has_space = 1;
            break;
        }
    }

    /* Estimasi ruang: tanda kutip + isi + penutup. */
    need = *len + 2 + n + 2 + 1;
    if (need > *cap) {
        size_t ncap = *cap ? *cap * 2 : 64;
        while (ncap < need)
            ncap *= 2;
        *buf = (char *)realloc(*buf, ncap);
        if (!*buf) {
            *cap = 0;
            return;
        }
        *cap = ncap;
    }

    if (!has_space) {
        memcpy(*buf + *len, arg, n + 1);
        *len += n;
        return;
    }

    (*buf)[(*len)++] = '"';
    for (i = 0; i < n; i++) {
        size_t bslashes = 0;
        while (i < n && arg[i] == '\\') {
            bslashes++;
            i++;
        }
        if (i == n) {
            /* Trailing backslashes: gandakan sebelum kutip penutup. */
            for (size_t j = 0; j < bslashes * 2; j++)
                (*buf)[(*len)++] = '\\';
            break;
        } else if (arg[i] == '"') {
            for (size_t j = 0; j < bslashes * 2 + 1; j++)
                (*buf)[(*len)++] = '\\';
            (*buf)[(*len)++] = '"';
        } else {
            for (size_t j = 0; j < bslashes; j++)
                (*buf)[(*len)++] = '\\';
            (*buf)[(*len)++] = arg[i];
        }
    }
    (*buf)[(*len)++] = '"';
    (*buf)[*len] = '\0';
}

static char *build_cmdline(const char *const *argv)
{
    char  *buf = NULL;
    size_t cap = 0, len = 0;
    int    i;

    if (!argv || !argv[0])
        return NULL;

    for (i = 0; argv[i]; i++) {
        append_arg(&buf, &cap, &len, argv[i]);
        if (!buf)
            return NULL;
        if (argv[i + 1]) {
            /* sisip spasi pemisah */
            if (len + 2 > cap) {
                size_t ncap = cap ? cap * 2 : 64;
                buf = (char *)realloc(buf, ncap);
                if (!buf) {
                    cap = 0;
                    return NULL;
                }
                cap = ncap;
            }
            buf[len++] = ' ';
            buf[len] = '\0';
        }
    }
    return buf;
}
#endif /* _WIN32 */

/* ------------------------------------------------------------------ */
/* Struktur drain thread                                                */
/* ------------------------------------------------------------------ */

typedef struct {
#ifdef _WIN32
    HANDLE  handle;
#else
    int     fd;
#endif
    char   *hdr;        /* prefix terawetkan (bounded head) */
    size_t  head_cap;
    size_t  head_len;
    char   *tail;       /* ring buffer: N byte TERAKHIR (bounded tail) */
    size_t  tail_cap;
    size_t  tail_len;
    size_t  tail_pos;   /* penulis ring */
    size_t  total;      /* total byte dibaca (termasuk yang dibuang) */
    int     truncated;  /* ada byte di tengah yang dibuang */
    size_t  max;        /* budget total */
    int     finished;
    /* Streaming evidence detector: deteksi marker sanitizer
     * (ASan/UBSan/LeakSanitizer) pada output saat mengalir,
     * tanpa menunggu proses selesai. */
    int     sanitizer_detected;
    char    sanitizer_marker[64];
} drain_buf;

static int drain_init(drain_buf *d, size_t max)
{
    size_t head_cap, tail_cap;
    /* Sisihkan sebagian budget untuk tail (akhir output: sanitizer report). */
    d->head_cap = head_cap = (max / 3) * 2;
    d->tail_cap = tail_cap = max - head_cap;
    d->hdr = (char *)malloc(head_cap ? head_cap + 1 : 1);
    d->tail = (char *)malloc(tail_cap ? tail_cap + 1 : 1);
    if (!d->hdr || !d->tail) {
        free(d->hdr);
        free(d->tail);
        d->hdr = d->tail = NULL;
        return 0;
    }
    d->head_len = 0;
    d->tail_len = 0;
    d->tail_pos = 0;
    d->total = 0;
    d->truncated = 0;
    d->max = max;
    d->finished = 0;
    return 1;
}

/* Alirkan n byte ke penampung: head-lalu-tail. dipanggil oleh kedua drain
 * (Windows & POSIX) agar kebijakan bounded prefix + bounded tail sama. */
static void drain_feed(drain_buf *d, const char *src, size_t n)
{
    size_t i = 0;
    d->total += n;
    /* isi head sampai penuh */
    if (d->head_len < d->head_cap) {
        size_t space = d->head_cap - d->head_len;
        size_t take = n < space ? n : space;
        memcpy(d->hdr + d->head_len, src, take);
        d->head_len += take;
        i = take;
    }
    /* sisa ditampung di ring tail (selalu byte terakhir) */
    for (; i < n; i++) {
        if (d->tail_len < d->tail_cap) {
            d->tail[d->tail_len++] = src[i];
        } else {
            d->tail[d->tail_pos] = src[i];
            d->tail_pos = (d->tail_pos + 1) % d->tail_cap;
        }
    }
    /* Ada byte tengah yang terpaksa dibuang: head + tail tak menutup semuanya. */
    if (d->total > d->head_cap + d->tail_cap)
        d->truncated = 1;
    /* Streaming evidence detector: deteksi marker sanitizer
     * pada output yang mengalir. Bila ditemukan, catat marker
     * agar laporan bisa menyebutkan bukti secara streaming. */
    if (!d->sanitizer_detected) {
        const char *m = stream_sanitizer_match(src, n);
        if (m) {
            d->sanitizer_detected = 1;
            strncpy(d->sanitizer_marker, m, sizeof(d->sanitizer_marker) - 1);
            d->sanitizer_marker[sizeof(d->sanitizer_marker) - 1] = '\0';
        }
    }
}

/* Bangun C-string tunggal dari head + tail (urutan ring). Mengembalikan
 * buffer malloc'd (pemanggil membebaskan) atau NULL; menempatkan *out_len
 * dan *out_truncated. */
static char *drain_assemble(drain_buf *d, size_t *out_len, int *out_truncated)
{
    size_t total = d->head_len + d->tail_len;
    char  *buf;
    size_t i, j;
    *out_truncated = d->truncated;
    if (total < 1)
        total = 1;
    buf = (char *)malloc(total + 1);
    if (!buf)
        return NULL;
    memcpy(buf, d->hdr, d->head_len);
    /* tail: ring buffer, mulai tail_pos (tertua) hingga tail_len byte */
    for (i = 0; i < d->tail_len; i++) {
        j = (d->tail_pos + i) % d->tail_cap;
        buf[d->head_len + i] = d->tail[j];
    }
    buf[total] = '\0';
    *out_len = total;
    return buf;
}

#ifdef _WIN32
static unsigned __stdcall drain_thread(void *arg)
{
    drain_buf *d = (drain_buf *)arg;
    char       tmp[8192];
    DWORD      rd;
    while (1) {
        if (!ReadFile(d->handle, tmp, sizeof(tmp), &rd, NULL)) {
            if (GetLastError() == ERROR_BROKEN_PIPE)
                break;
            /* Bisa terjadi saat handle ditutup oleh pembersihan; hentikan. */
            break;
        }
        if (rd == 0)
            break;
        drain_feed(d, tmp, rd);
    }
    d->finished = 1;
    return 0;
}
#else
static void *drain_thread(void *arg)
{
    drain_buf *d = (drain_buf *)arg;
    char       tmp[8192];
    ssize_t    rd;
    while (1) {
        rd = read(d->fd, tmp, sizeof(tmp));
        if (rd <= 0)
            break;
        drain_feed(d, tmp, (size_t)rd);
    }
    d->finished = 1;
    return NULL;
}
#endif

void myc_proc_result_free(myc_proc_result *res)
{
    if (!res)
        return;
    free(res->stdout_data);
    free(res->stderr_data);
    res->stdout_data = NULL;
    res->stderr_data = NULL;
}

/* ------------------------------------------------------------------ */
/* Pelaksanaan utama                                                    */
/* ------------------------------------------------------------------ */

static unsigned long long now_ms(void)
{
#ifdef _WIN32
    return (unsigned long long)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

#ifdef _WIN32

static int proc_run_win(const myc_proc_request *req, myc_proc_result *res)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE  stdin_rd = NULL, stdin_wr = NULL;
    HANDLE  stdout_rd = NULL, stdout_wr = NULL;
    HANDLE  stderr_rd = NULL, stderr_wr = NULL;
    HANDLE  job = NULL;
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    char    *cmdline = NULL;
    char    *cmdline_copy = NULL;
    char    *env_block = NULL;
    drain_buf out = {0}, err = {0};
    unsigned long long t0;
    BOOL    started;
    int     done = 0;
    int     timed_out = 0;
    int     proc_alive = 1;
    HANDLE  drain_threads[2] = { NULL, NULL };
    size_t  max_out = req->max_output_bytes ? req->max_output_bytes : MYC_MAX_OUTPUT_BYTES;
    DWORD   timeout_ms = (DWORD)(req->timeout_ms > 0 ? req->timeout_ms : MYC_DEFAULT_TIMEOUT_MS);

    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    /* stdin pipe: child membaca stdin_rd */
    if (!CreatePipe(&stdin_rd, &stdin_wr, &sa, 0)) { res->err = MYC_ERR_INTERNAL; return 0; }
    SetHandleInformation(stdin_wr, HANDLE_FLAG_INHERIT, 0);
    /* stdout pipe: child menulis stdout_wr */
    if (!CreatePipe(&stdout_rd, &stdout_wr, &sa, 0)) { res->err = MYC_ERR_INTERNAL; goto cleanup; }
    SetHandleInformation(stdout_rd, HANDLE_FLAG_INHERIT, 0);
    if (!CreatePipe(&stderr_rd, &stderr_wr, &sa, 0)) { res->err = MYC_ERR_INTERNAL; goto cleanup; }
    SetHandleInformation(stderr_rd, HANDLE_FLAG_INHERIT, 0);

    /* Job Object: pastikan timeout membunuh seluruh pohon proses. */
    job = CreateJobObjectA(NULL, NULL);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
        memset(&jeli, 0, sizeof(jeli));
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    }

    memset(&pi, 0, sizeof(pi));
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = stdin_rd;
    si.hStdOutput = stdout_wr;
    si.hStdError = stderr_wr;

    cmdline = build_cmdline(req->argv);
    if (!cmdline) { res->err = MYC_ERR_INTERNAL; goto cleanup; }
    /* CreateProcessA dapat mengubah buffer; salin. */
    cmdline_copy = myc_strdup(cmdline);
    if (!cmdline_copy) { res->err = MYC_ERR_INTERNAL; goto cleanup; }
    /* Env override (MYC-AUDIT-017): blok env induk + override. */
    if (req->env) {
        env_block = build_env_block(req->env);
        if (!env_block) { res->err = MYC_ERR_INTERNAL; goto cleanup; }
    }

    t0 = now_ms();
    started = CreateProcessA(
        req->argv[0],
        cmdline_copy,
        NULL, NULL, TRUE,             /* bInheritHandles = TRUE */
        CREATE_NO_WINDOW,
        env_block,                    /* NULL = warisi env induk */
        req->cwd,
        &si, &pi);

    if (!started) {
        res->err = MYC_ERR_EXECUTE_FAILED;
        res->ok = 0;
        goto cleanup;
    }

    /* Assign proses ke Job Object (jika ada) untuk cleanup pohon. */
    if (job)
        AssignProcessToJobObject(job, pi.hProcess);

    /* Tutup sisi yang diwarisi oleh proses induk. */
    CloseHandle(stdin_rd); stdin_rd = NULL;
    CloseHandle(stdout_wr); stdout_wr = NULL;
    CloseHandle(stderr_wr); stderr_wr = NULL;

    /* Mulai thread drain. */
    if (!drain_init(&out, max_out) || !drain_init(&err, max_out)) {
        free(out.hdr);
        free(out.tail);
        free(err.hdr);
        free(err.tail);
        res->err = MYC_ERR_INTERNAL;
        res->ok = 0;
        goto cleanup_pi;
    }
    out.handle = stdout_rd;
    err.handle = stderr_rd;
    {
        HANDLE th[2];
        th[0] = (HANDLE)_beginthreadex(NULL, 0, drain_thread, &out, 0, NULL);
        th[1] = (HANDLE)_beginthreadex(NULL, 0, drain_thread, &err, 0, NULL);
        /* simpan untuk ditunggu nanti */
        drain_threads[0] = th[0];
        drain_threads[1] = th[1];
    }

    /* Tulis stdin. */
    if (req->stdin_len > 0) {
        DWORD total_written = 0;
        DWORD wr;
        while (total_written < (DWORD)req->stdin_len) {
            DWORD chunk = (DWORD)req->stdin_len - total_written;
            if (chunk > 65536)
                chunk = 65536;
            if (!WriteFile(stdin_wr, (const char *)req->stdin_data + total_written, chunk, &wr, NULL)) {
                if (GetLastError() == ERROR_BROKEN_PIPE)
                    break; /* child keluar lebih dulu */
                res->err = MYC_ERR_EXECUTE_FAILED;
                break;
            }
            total_written += wr;
        }
    }
    CloseHandle(stdin_wr); stdin_wr = NULL;

    /* Tunggu proses, dengan batas waktu. */
    while (1) {
        DWORD wait = WaitForSingleObject(pi.hProcess, 50);
        unsigned long long elapsed = now_ms() - t0;
        if (wait == WAIT_OBJECT_0) {
            done = 1;
            break;
        }
        if (wait == WAIT_TIMEOUT) {
            if (timeout_ms && elapsed >= timeout_ms) {
                timed_out = 1;
                break;
            }
        } else {
            res->err = MYC_ERR_INTERNAL;
            break;
        }
    }

    if (timed_out) {
        /* Bunuh seluruh pohon proses. */
        if (job) {
            TerminateJobObject(job, 1);
        } else {
            TerminateProcess(pi.hProcess, 1);
        }
        proc_alive = 0;
        WaitForSingleObject(pi.hProcess, 5000);
        res->timed_out = 1;
        res->err = MYC_ERR_TIMEOUT;
        res->ok = 0;
    } else {
        DWORD code = 1;
        GetExitCodeProcess(pi.hProcess, &code);
        res->exit_code = (int)code;
        res->ok = 1;
        res->timed_out = 0;
        res->err = MYC_ERR_NONE;
    }

    res->duration_ms = now_ms() - t0;
    (void)proc_alive;

    /* Tunggu thread drain selesai (hasilnya sudah lengkap). */
    if (drain_threads[0]) {
        WaitForSingleObject(drain_threads[0], 2000);
        CloseHandle(drain_threads[0]);
    }
    if (drain_threads[1]) {
        WaitForSingleObject(drain_threads[1], 2000);
        CloseHandle(drain_threads[1]);
    }

    res->stdout_total = out.total;
    res->stderr_total = err.total;
    res->stdout_data = drain_assemble(&out, &res->stdout_shown, &out.truncated);
    res->stderr_data = drain_assemble(&err, &res->stderr_shown, &err.truncated);
    res->truncated = out.truncated || err.truncated;
    res->sanitizer_detected = out.sanitizer_detected || err.sanitizer_detected;
    if (res->sanitizer_detected) {
        const char *m = out.sanitizer_detected ? out.sanitizer_marker : err.sanitizer_marker;
        strncpy(res->sanitizer_marker, m ? m : "", sizeof(res->sanitizer_marker) - 1);
        res->sanitizer_marker[sizeof(res->sanitizer_marker) - 1] = '\0';
    }
    if (!res->stdout_data)
        res->stdout_data = (char *)malloc(1);
    if (!res->stderr_data)
        res->stderr_data = (char *)malloc(1);
    if (res->stdout_data && !res->stdout_shown)
        res->stdout_data[0] = '\0';
    if (res->stderr_data && !res->stderr_shown)
        res->stderr_data[0] = '\0';

    free(out.hdr); out.hdr = NULL;
    free(out.tail); out.tail = NULL;
    free(err.hdr); err.hdr = NULL;
    free(err.tail); err.tail = NULL;

cleanup_pi:
    if (stdin_rd) CloseHandle(stdin_rd);
    if (stdout_rd) CloseHandle(stdout_rd);
    if (stderr_rd) CloseHandle(stderr_rd);
    if (stdin_wr) CloseHandle(stdin_wr);
    if (stdout_wr) CloseHandle(stdout_wr);
    if (stderr_wr) CloseHandle(stderr_wr);
    if (job) {
        CloseHandle(job);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

cleanup:
    free(cmdline);
    free(cmdline_copy);
    free(env_block);
    if (done) {
        /* hasil sudah disalin */
    }
    return res->ok ? 1 : (res->err != MYC_ERR_NONE ? 0 : 1);
}

#endif /* _WIN32 */

#ifndef _WIN32

static int proc_run_posix(const myc_proc_request *req, myc_proc_result *res)
{
    int     in_pipe[2]  = {-1,-1};
    int     out_pipe[2] = {-1,-1};
    int     err_pipe[2] = {-1,-1};
    int     exec_pipe[2] = {-1,-1}; /* MYC-AUDIT-003: deteksi execvp gagal */
    char  **child_env = NULL;
    pid_t   pid = -1;
    drain_buf out = {0}, err = {0};
    pthread_t to = 0, te = 0;
    int     to_created = 0, te_created = 0;
    size_t  max_out = req->max_output_bytes ? req->max_output_bytes : MYC_MAX_OUTPUT_BYTES;
    unsigned long long t0;
    int     status = 0;
    int     timed_out = 0;

    memset(&out, 0, sizeof(out));
    memset(&err, 0, sizeof(err));

    /* Buat semua pipe; tutup yang sudah terbuka jika gagal. */
    if (pipe(in_pipe) < 0 || pipe(out_pipe) < 0 || pipe(err_pipe) < 0 ||
        pipe(exec_pipe) < 0) {
        res->err = MYC_ERR_INTERNAL;
        goto cleanup_pipes;
    }

    /* exec_pipe: sisi write diwarisi child; FD_CLOEXEC agar otomatis
     * tertutup bila execvp sukses → parent membaca 0 byte = exec berhasil.
     * Bila execvp gagal, child menulis errno → parent tahu exec gagal. */
    {
        int fl = fcntl(exec_pipe[1], F_GETFD, 0);
        if (fl >= 0)
            fcntl(exec_pipe[1], F_SETFD, fl | FD_CLOEXEC);
    }

    /* Bangun env override SEBELUM fork (alokasi di parent; child hanya
     * meng-assign pointer ke `environ` -- tanpa malloc di dalam child). */
    if (req->env) {
        child_env = build_env_array(req->env);
        if (!child_env) {
            res->err = MYC_ERR_INTERNAL;
            goto cleanup_pipes;
        }
    }

    t0 = now_ms();
    pid = fork();
    if (pid < 0) {
        res->err = MYC_ERR_EXECUTE_FAILED;
        goto cleanup_pipes;
    }

    if (pid == 0) {
        /* === CHILD === */
        /* Bentuk process group sendiri agar kill(-pgid) efektif.
         * MYC-AUDIT-011: setpgid sebelum exec. */
        setpgid(0, 0);

        /* Hubungkan pipe ke stdin/stdout/stderr. */
        dup2(in_pipe[0], 0);
        dup2(out_pipe[1], 1);
        dup2(err_pipe[1], 2);

        /* Tutup semua fd pipe di child (dup2 sudah menyalin). */
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        close(exec_pipe[0]); /* sisi read tidak dibutuhkan child */
        /* exec_pipe[1] tetap terbuka, FD_CLOEXEC akan menutupnya saat exec
         * berhasil. Bila exec gagal, kita write errno lalu _exit. */

        if (req->cwd) {
            if (chdir(req->cwd) != 0) {
                int e = errno;
                ssize_t wr = write(exec_pipe[1], &e, sizeof(e));
                (void)wr;
                _exit(127);
            }
        }
        if (child_env)
            environ = child_env;
        execvp(req->argv[0], (char *const *)req->argv);
        /* execvp gagal: kirim errno ke parent. */
        {
            int e = errno;
            ssize_t wr = write(exec_pipe[1], &e, sizeof(e));
            (void)wr;
        }
        _exit(127);
    }

    /* === PARENT === */
    /* MYC-AUDIT-011 (race-safe): child memanggil setpgid(0,0) di atas, TAPI
     * ada window antara fork() dan eksekusi setpgid child. Bila timeout
     * sangat pendek menembak kill(-pid) di window itu, group belum terbentuk
     * -> ESRCH (kill gagal) atau salah group. Panggilan setpgid(pid,pid)
     * dari PARENT menutup window: siapa yang menang (parent atau child),
     * group terbentuk sedini mungkin; yang kalah mendapat EACCES/ESRCH
     * (wajar, diabaikan). */
    (void)setpgid(pid, pid);

    /* Tutup sisi child dari semua pipe. */
    close(in_pipe[0]);  in_pipe[0] = -1;
    close(out_pipe[1]); out_pipe[1] = -1;
    close(err_pipe[1]); err_pipe[1] = -1;
    close(exec_pipe[1]); exec_pipe[1] = -1;

    /* Inisialisasi drain buffer dan mulai thread drain SEBELUM menulis
     * stdin. MYC-AUDIT-002: memulai drain dulu mencegah deadlock bila
     * child mengisi pipe output sebelum selesai membaca stdin. */
    if (!drain_init(&out, max_out) || !drain_init(&err, max_out)) {
        res->err = MYC_ERR_INTERNAL;
        goto cleanup_kill;
    }
    out.fd = out_pipe[0];
    err.fd = err_pipe[0];

    /* MYC-AUDIT-001: simpan pthread_t dan periksa return value. */
    if (pthread_create(&to, NULL, drain_thread, &out) != 0) {
        res->err = MYC_ERR_INTERNAL;
        goto cleanup_kill;
    }
    to_created = 1;
    if (pthread_create(&te, NULL, drain_thread, &err) != 0) {
        res->err = MYC_ERR_INTERNAL;
        goto cleanup_kill;
    }
    te_created = 1;

    /* Tulis stdin SETELAH drain thread sudah berjalan. */
    if (req->stdin_len > 0) {
        struct sigaction sa, oldsa;
        size_t off = 0;
        /* SIGPIPE: child bisa mati sebelum selesai membaca stdin (exec
         * gagal / crash dini / chdir(cwd) gagal). Default SIGPIPE =
         * terminate PARENT -- bug: myc/mcp/proc_flood ikut mati padahal
         * write() cukup return EPIPE. Tahan SIGPIPE selama menulis,
         * pulihkan handler lama setelahnya. */
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sa, &oldsa);
        while (off < req->stdin_len) {
            ssize_t w = write(in_pipe[1], (const char *)req->stdin_data + off,
                              req->stdin_len - off);
            if (w <= 0)
                break; /* broken pipe: child mungkin sudah exit */
            off += (size_t)w;
        }
        sigaction(SIGPIPE, &oldsa, NULL);
    }
    close(in_pipe[1]); in_pipe[1] = -1;

    /* Periksa apakah execvp berhasil: baca dari exec_pipe[0].
     * Jika exec berhasil, pipe ditutup oleh FD_CLOEXEC → read() = 0.
     * Jika exec gagal, child menulis errno. */
    {
        int exec_errno = 0;
        ssize_t r = read(exec_pipe[0], &exec_errno, sizeof(exec_errno));
        if (r == (ssize_t)sizeof(exec_errno)) {
            /* exec gagal: child tidak pernah berjalan */
            res->err = MYC_ERR_EXECUTE_FAILED;
            res->ok = 0;
            goto cleanup_kill;
        }
        /* r==0: exec berhasil. r<0: error read, tetap lanjut. */
    }
    close(exec_pipe[0]); exec_pipe[0] = -1;

    /* Tunggu child selesai atau timeout. */
    while (1) {
        unsigned long long elapsed = now_ms() - t0;
        int r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            pid = -1; /* sudah dipanen */
            break;
        }
        if (req->timeout_ms > 0 && elapsed >= (unsigned long long)req->timeout_ms) {
            timed_out = 1;
            /* MYC-AUDIT-011: bunuh seluruh process group child. */
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            pid = -1;
            break;
        }
        {
            struct timespec ts = {0, 10 * 1000000};
            nanosleep(&ts, NULL);
        }
    }

    /* Tutup sisi read pipe sehingga drain thread mendapat EOF. */
    if (out_pipe[0] >= 0) { close(out_pipe[0]); out_pipe[0] = -1; }
    if (err_pipe[0] >= 0) { close(err_pipe[0]); err_pipe[0] = -1; }

    /* MYC-AUDIT-001: join kedua thread sebelum menyentuh buffer hasil. */
    if (to_created) { pthread_join(to, NULL); to_created = 0; }
    if (te_created) { pthread_join(te, NULL); te_created = 0; }

    if (timed_out) {
        res->timed_out = 1;
        res->err = MYC_ERR_TIMEOUT;
        res->ok = 0;
    } else if (WIFEXITED(status)) {
        res->exit_code = WEXITSTATUS(status);
        res->ok = 1;
        res->err = MYC_ERR_NONE;
    } else if (WIFSIGNALED(status)) {
        /* Program berjalan lalu dihentikan sinyal (mis. SIGABRT dari
         * sanitizer). Ini hasil VALID: exit_code = 128+sig tersedia untuk
         * caller. Konsisten dengan Windows (proses berjalan selalu ok=1). */
        res->exit_code = 128 + WTERMSIG(status);
        res->ok = 1;
        res->err = MYC_ERR_NONE;
    } else {
        res->exit_code = 1;
        res->ok = 0;
        res->err = MYC_ERR_EXECUTE_FAILED;
    }

    res->duration_ms = now_ms() - t0;
    res->stdout_data = drain_assemble(&out, &res->stdout_shown, &out.truncated);
    res->stderr_data = drain_assemble(&err, &res->stderr_shown, &err.truncated);
    res->stdout_total = out.total;
    res->stderr_total = err.total;
    res->truncated = out.truncated || err.truncated;
    res->sanitizer_detected = out.sanitizer_detected || err.sanitizer_detected;
    if (res->sanitizer_detected) {
        const char *m = out.sanitizer_detected ? out.sanitizer_marker : err.sanitizer_marker;
        strncpy(res->sanitizer_marker, m ? m : "", sizeof(res->sanitizer_marker) - 1);
        res->sanitizer_marker[sizeof(res->sanitizer_marker) - 1] = '\0';
    }
    res->truncated = out.truncated || err.truncated;
    if (!res->stdout_data) { res->stdout_data = (char *)malloc(1); if (res->stdout_data) res->stdout_data[0] = '\0'; }
    if (!res->stderr_data) { res->stderr_data = (char *)malloc(1); if (res->stderr_data) res->stderr_data[0] = '\0'; }

    /* hdr + tail dibebaskan (data hasil sudah ter-amount di atas). */
    free(out.hdr); out.hdr = NULL;
    free(out.tail); out.tail = NULL;
    free(err.hdr); err.hdr = NULL;
    free(err.tail); err.tail = NULL;
    free(child_env);  /* env array dibangun di parent; bebas di jalur sukses */
    return res->ok ? 1 : 0;

cleanup_kill:
    if (pid > 0) {
        kill(-pid, SIGKILL);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
cleanup_pipes:
    /* Tutup sisi read pipe agar drain thread (jika sempat dibuat) mendapat EOF. */
    if (out_pipe[0] >= 0) { close(out_pipe[0]); out_pipe[0] = -1; }
    if (err_pipe[0] >= 0) { close(err_pipe[0]); err_pipe[0] = -1; }
    if (to_created) { pthread_join(to, NULL); }
    if (te_created) { pthread_join(te, NULL); }
    /* Tutup semua fd yang tersisa. */
    if (in_pipe[0]  >= 0) close(in_pipe[0]);
    if (in_pipe[1]  >= 0) close(in_pipe[1]);
    if (out_pipe[1] >= 0) close(out_pipe[1]);
    if (err_pipe[1] >= 0) close(err_pipe[1]);
    if (exec_pipe[0] >= 0) close(exec_pipe[0]);
    if (exec_pipe[1] >= 0) close(exec_pipe[1]);
    free(out.hdr); free(out.tail);
    free(err.hdr); free(err.tail);
    free(child_env);
    return 0;
}

#endif /* !_WIN32 */

int myc_proc_run(const myc_proc_request *req, myc_proc_result *res)
{
    memset(res, 0, sizeof(*res));
    if (!req || !req->argv || !req->argv[0]) {
        res->err = MYC_ERR_INVALID_REQUEST;
        return 0;
    }
#ifdef _WIN32
    return proc_run_win(req, res);
#else
    return proc_run_posix(req, res);
#endif
}
