/*
 * compile.c -- Pipeline myc.
 *
 * Urutan (pivot memory-safety 2026-08-01: policy NON-BLOCKING):
 *   1. scan include mentah (lapis 1)  -> warning (non-blocking)
 *   2. lint memory-safety (P5, D1.3+D1.4) -> observasi + confidence
 *      (MYC-AUDIT-014: heuristik teks TIDAK pernah hard verdict)
 *   3. gcc -E (argv eksak, source via stdin) -> output preprocessed
 *   4. scan markers (lapis 2)         -> warning (non-blocking)
 *   5. scan calls (lapis 3)           -> warning (non-blocking)
 *   6. gcc -c -O2 (gate, tier dasar memori) -> COMPILE_ERROR
 *   7. (opsional) gcc -c -fanalyzer -o <null_device>
 *   8. verdict MC_OK + assurance
 *
 * MYC-AUDIT-015: target `-o` memakai device null PORTABEL ("NUL" di
 * Windows, "/dev/null" di POSIX) -- "NUL" di POSIX adalah file biasa.
 *
 * Tidak pernah menyusun shell string; source tidak pernah jadi argumen.
 * Catatan ownership: req->input.data/len dimiliki caller (myc.c); loading
 * dilakukan di myc.c/myc_source_load (MYC-AUDIT-029), bukan di sini.
 */
#include "compile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "contract.h"
#include "driver.h"
#include "filc.h"
#include "gate.h"
#include "json.h"
#include "lint.h"
#include "negative.h"
#include "policy.h"
#include "state.h"
#include "proc.h"
#include "prove.h"
#include "report.h"
#include "run.h"
#include "scanner.h"
#include "sha256.h"
#include "stack.h"
#include "mutate.h"
#include "matrix.h"
#include "concur.h"

/* ------------------------------------------------------------------ */
/* Tabel flags gcc terpusat (P4.3).                                    */
/* ------------------------------------------------------------------ */

/* Revisi runtime checked-buffer (myc_buf.h) yang ikut masuk fingerprint
 * (MYC-AUDIT-012): 1 = fat-struct D1.2 asli (data/cap); 2 = typed struct
 * dengan elem_size/byte_capacity/generation/cookie + checked multiplication.
 * Naikkan saat semantic myc_buf.h berubah agar receipt berubah juga. */
#define MYC_BUF_RUNTIME_REV 2

/* ------------------------------------------------------------------ */
/* Fingerprint incremental — cache base fingerprint (semua komponen
 * kecuali source_sha256) agar perubahan source saja tidak perlu
 * recompute gcc_path/cwd/policy/flags. */
/* ------------------------------------------------------------------ */
typedef struct {
    char gcc_path[512];
    char cwd[4096];
    char policy_hex[65];
    char flags[256];
    int  buf_rev;
    char base_sha256[65]; /* SHA-256 dari string base (tanpa src) */
    int  valid;
} fingerprint_cache_t;

static _Thread_local fingerprint_cache_t fp_cache = {0};

static void fingerprint_cache_invalidate(void)
{
    fp_cache.valid = 0;
}

static void fingerprint_cache_update(const char *gcc_path,
                                     const char *cwd,
                                     const char *policy_hex,
                                     const char *flags_str,
                                     int buf_rev)
{
    if (fp_cache.valid &&
        strcmp(fp_cache.gcc_path, gcc_path) == 0 &&
        (!cwd || strcmp(fp_cache.cwd, cwd) == 0) &&
        strcmp(fp_cache.policy_hex, policy_hex) == 0 &&
        strcmp(fp_cache.flags, flags_str) == 0 &&
        fp_cache.buf_rev == buf_rev) {
        return; /* cache masih valid */
    }
    {
        char base_buf[8192];
        int  base_len;
        snprintf(base_buf, sizeof(base_buf),
                 "v12|gcc:%s|cwd:%s|pol:%s|flags:%s|buf:%d|",
                 gcc_path, cwd ? cwd : "", policy_hex,
                 flags_str, buf_rev);
        base_len = (int)strlen(base_buf);
        sha256_hex(base_buf, (size_t)base_len, fp_cache.base_sha256);
    }
    strncpy(fp_cache.gcc_path, gcc_path, sizeof(fp_cache.gcc_path) - 1);
    fp_cache.gcc_path[sizeof(fp_cache.gcc_path) - 1] = '\0';
    strncpy(fp_cache.cwd, cwd ? cwd : "", sizeof(fp_cache.cwd) - 1);
    fp_cache.cwd[sizeof(fp_cache.cwd) - 1] = '\0';
    strncpy(fp_cache.policy_hex, policy_hex, sizeof(fp_cache.policy_hex) - 1);
    fp_cache.policy_hex[sizeof(fp_cache.policy_hex) - 1] = '\0';
    strncpy(fp_cache.flags, flags_str, sizeof(fp_cache.flags) - 1);
    fp_cache.flags[sizeof(fp_cache.flags) - 1] = '\0';
    fp_cache.buf_rev = buf_rev;
    fp_cache.valid = 1;
}

static void fingerprint_compute_incremental(const char *source_sha256,
                                             char *out_hex)
{
    char fp_buf[8192];
    int  fp_len;
    if (!fp_cache.valid) {
        /* fallback: hitung full fingerprint (sebelum cache diisi) */
        fingerprint_cache_invalidate();
        return;
    }
    fp_len = snprintf(fp_buf, sizeof(fp_buf),
                      "%s|src:%s", fp_cache.base_sha256,
                      source_sha256 ? source_sha256 : "");
    sha256_hex(fp_buf, (size_t)fp_len, out_hex);
}

/* Device null portabel (MYC-AUDIT-015): "NUL" hanya null device di Windows;
 * di POSIX itu file biasa (artefak literal `NUL` di repo lama). `/dev/null`
 * adalah null device yang benar di POSIX. Dipakai sebagai target `-o` pada
 * gate compile-only (hasil object dibuang). */
static const char *myc_null_device(void)
{
#if defined(_WIN32)
    return "NUL";
#else
    return "/dev/null";
#endif
}

/* Tier dasar -- default, nol false-positive pd kode sah, semua -Werror. */
static const char *const MEMORY_WARNINGS[] = {
    "-Warray-bounds",
    "-Wstringop-overflow",
    "-Wuse-after-free",
    "-Wfree-nonheap-object",
    "-Wformat-overflow",
    "-Wformat-truncation",
    NULL
};

/* Tier ketat -- opsional (--strict), BISING, bukan default (keputusan 1). */
static const char *const STRICT_WARNINGS[] = {
    "-Wconversion",
    "-Wsign-conversion",
    "-Wint-conversion",
    NULL
};

/* Flags syntax-only yang selalu dipakai (sanity dasar). */
static const char *const SYNTAX_BASE[] = {
    "-std=c11", "-Wall", "-Wextra", "-Werror",
    "-pedantic", "-Werror=implicit-function-declaration", NULL
};

/* Gate memori: perlu -c + -O2 agar -Warray-bounds/-Wstringop-overflow aktif
 * (gcc menjalankan analisis GIMPLE hanya saat kompilasi dengan optimisasi).
 * MYC-AUDIT-022: stderr gcc dalam format teks biasa diparse oleh
 * ingest_gcc_diagnostics sebagai fallback (<stdin>:<line>:<col>: message). */
static const char *const MEMORY_GATE[] = {
    "-c", "-O2", "-o", "NUL",
    NULL
};

/* Flags analyzer: MEMORY_GATE + -fanalyzer. */
static const char *const ANALYZER_EXTRA[] = {
    "-c", "-O2", "-fanalyzer", "-o", "NUL",
    NULL
};

/* Susun satu array argv gabungan (semua pointer statis, tak perlu bebas).
 * count = jumlah argumen setelah gcc_path.
 * MYC-AUDIT-015: literal "NUL" pada daftar (target -o) diganti dengan
 * myc_null_device() -- daftar flags tetap statis, device null diresolusi
 * runtime sesuai platform. */
static const char **merge_args(const char *const *lists[], size_t nlists,
                               size_t *count)
{
    size_t total = 0;
    size_t li, ai, idx = 0;
    const char **out;
    for (li = 0; li < nlists; li++) {
        if (!lists[li])
            continue;               /* list opsional yang tak diaktifkan */
        for (ai = 0; lists[li][ai]; ai++)
            total++;
    }
    out = (const char **)malloc(sizeof(char *) * (total + 1));
    if (!out)
        return NULL;
    for (li = 0; li < nlists; li++) {
        if (!lists[li])
            continue;
        for (ai = 0; lists[li][ai]; ai++) {
            const char *arg = lists[li][ai];
            out[idx++] = strcmp(arg, "NUL") == 0 ? myc_null_device() : arg;
        }
    }
    out[idx] = NULL;
    *count = idx;
    return out;
}

/* helper agar add_diag bisa menerima pesan dinamis dari stderr gcc.
 * Confidence = CONFIRMED: gcc diagnostic adalah bukti SEMANTIK
 * (AST/dataflow), bukan heuristik teks (MYC-AUDIT-014). */
static void add_diag_copy(myc_result *res, int line, int col, const char *msg)
{
    char *copy;
    if (res->diag_count >= MYC_MAX_DIAGNOSTICS)
        return;
    copy = myc_result_arena_dup(res, msg, 0);
    if (!copy)
        return;
    res->diags[res->diag_count].line = line;
    res->diags[res->diag_count].col = col;
    res->diags[res->diag_count].message = copy;
    res->diags[res->diag_count].confidence = MYC_CONF_CONFIRMED;
    res->diag_count++;
}

/* Tambah diagnostic dari stderr gcc.
 *
 * MYC-AUDIT-022 (roadmap 7.1): ingest_gcc_diagnostics memiliki dua jalur:
 * 1. JSON — dipicu jika stderr dimulai '[' (mis. gcc mendukung
 *    -fdiagnostics-format=json di masa depan atau platform lain).
 * 2. Teks — fallback default untuk output teks gcc biasa
 *    ("<stdin>:<line>:<col>: warning: ...").
 *
 * Keduanya menghasilkan diagnostic confidence CONFIRMED (bukti SEMANTIK
 * compiler, bukan heuristik teks). */
static void ingest_gcc_diagnostics(myc_result *res, const char *text)
{
    size_t      len;
    json_value *root = NULL;

    if (!text || !text[0])
        return;
    len = strlen(text);

    /* 1. Jalur JSON (jika stderr berupa array JSON). */
    if (text[0] == '[' && json_parse(text, len, &root) && root &&
        root->type == JSON_ARR) {
        size_t i;
        for (i = 0; i < root->len &&
                    res->diag_count < MYC_MAX_DIAGNOSTICS; i++) {
            json_value *d = root->items[i];
            json_value *kind, *msg, *locs;
            int         line = 0, col = 0;
            if (!d || d->type != JSON_OBJ)
                continue;
            kind = json_get(d, "kind");
            if (kind && kind->type == JSON_STR &&
                strcmp(kind->str, "note") == 0)
                continue;
            msg = json_get(d, "message");
            locs = json_get(d, "locations");
            if (locs && locs->type == JSON_ARR && locs->len > 0) {
                json_value *loc = locs->items[0];
                if (loc && loc->type == JSON_OBJ) {
                    json_value *caret = json_get(loc, "caret");
                    if (caret && caret->type == JSON_OBJ) {
                        json_value *lv = json_get(caret, "line");
                        json_value *cv = json_get(caret, "column");
                        if (lv && lv->type == JSON_NUM)
                            line = (int)lv->num;
                        if (cv && cv->type == JSON_NUM)
                            col = (int)cv->num;
                    }
                }
            }
            if (msg && msg->type == JSON_STR && msg->str[0])
                add_diag_copy(res, line, col, msg->str);
        }
        json_free(root);
        return;
    }
    if (root) {
        json_free(root);
        root = NULL;
    }

    /* 2. Fallback: format teks (mis. gcc -E preprocess). Hanya baris yang
     * memuat "<stdin>:<line>:<col>:" yang diambil; baris lanjutan gcc
     * ("cc1.exe:...", "  'main': events", "<stdin>: In function")
     * dilewati agar laporan tidak bising. */
    {
        const char *p = text;
        while (p && *p) {
            const char *nl = strchr(p, '\n');
            size_t      linelen = nl ? (size_t)(nl - p) : strlen(p);
            char       *linebuf = (char *)malloc(linelen + 1);
            int         line = 0, col = 0;
            const char *msg = NULL;

            if (linebuf) {
                memcpy(linebuf, p, linelen);
                linebuf[linelen] = '\0';
                if (strncmp(linebuf, "<stdin>:", 8) == 0) {
                    char *rest = linebuf + 8;
                    char *endptr;
                    line = (int)strtol(rest, &endptr, 10);
                    if (endptr && *endptr == ':') {
                        col = (int)strtol(endptr + 1, &endptr, 10);
                        if (endptr && *endptr == ':') {
                            msg = endptr + 1;
                            add_diag_copy(res, line, col, msg);
                        }
                    }
                }
                free(linebuf);
            }
            if (!nl)
                break;
            p = nl + 1;
        }
    }

    /* Isi witness dari diagnostic yang pertama match (Fase 1).
     * Witness hanya diisi bila belum ada (prioritas: sanitizer > gcc > eva).
     * Iterasi semua diagnostic karena note biasanya di akhir.
     * Kronologi (Fase 1, pre-state → operation → violation):
     *   - operation = pesan dari diagnostic error (violation_msg)
     *   - pre_state = pesan dari diagnostic note terdekat (mis. "call to 'free' here") */
    if (res->diag_count > 0 && !res->witness) {
        int di;
        const myc_diagnostic *d = NULL;
        const char *code = NULL;
        for (di = 0; di < res->diag_count; di++) {
            code = repair_find_code(res->diags[di].message);
            if (code) { d = &res->diags[di]; break; }
        }
        if (code) {
            res->witness = (myc_witness *)malloc(sizeof(myc_witness));
            if (res->witness) {
                myc_witness_init(res->witness);
                res->witness->violation_kind = myc_result_arena_dup(res, code, 0);
                res->witness->violation_msg = myc_result_arena_dup(res, d->message, 0);
                res->witness->violation_line = d->line;
                res->witness->violation_col = d->col;
                res->witness->backend = myc_result_arena_dup(res, "gcc", 0);
                /* operation: deskripsi operasi pelanggaran dari error message */
                res->witness->operation = myc_result_arena_dup(res, d->message, 0);
                /* pre_state: cari note diagnostic terdekat (sebelum atau sesudah error) */
                for (di = 0; di < res->diag_count; di++) {
                    const myc_diagnostic *n = &res->diags[di];
                    if (n != d && n->message &&
                        (strstr(n->message, "note:") || strstr(n->message, "call to"))) {
                        res->witness->pre_state = myc_result_arena_dup(res, n->message, 0);
                        break;
                    }
                }
            }
        }
    }
}

/* Jalankan gcc dengan argumen tertentu; return hasil proses. */
static void run_gcc(const myc_request *req,
                    const char *gcc_path,
                    const char *const *extra_args,
                    const char *stdin_data, size_t stdin_len,
                    size_t max_out,
                    myc_proc_result *pr)
{
    int    argc = 0;
    int    total;
    int    n = 0;
    int    i;
    const char **argv;
    myc_proc_request preq;

    while (extra_args[argc])
        argc++;
    total = 1 + argc + 3 + 1;
    argv = (const char **)malloc(sizeof(char *) * (size_t)total);
    if (!argv) {
        memset(pr, 0, sizeof(*pr));
        pr->err = MYC_ERR_INTERNAL;
        return;
    }
    argv[n++] = gcc_path;
    for (i = 0; i < argc; i++)
        argv[n++] = extra_args[i];
    argv[n++] = "-x";
    argv[n++] = "c";
    argv[n++] = "-";
    argv[n] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.cwd = req->cwd;
    preq.stdin_data = stdin_data;
    preq.stdin_len = stdin_len;
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = max_out;

    myc_proc_run(&preq, pr);
    /* Kegagalan launch (gcc tak terjangkau, CreateProcessA gagal, dst.)
     * meninggalkan exit_code=0 dari memset -> gate di bawah akan salah
     * klaim kompilasi bersih (false OK). Tandai sebagai gagal bila proses
     * tidak benar-benar berjalan dan bukan timeout. */
    if (!pr->ok && !pr->timed_out)
        pr->exit_code = 1;
    free(argv);
}

/* Pindahkan isi myc_proc_result ke res. */
static void adopt_proc(myc_result *res, myc_proc_result *pr)
{
    free(res->stdout_text);
    free(res->stderr_text);
    res->stdout_text = pr->stdout_data; pr->stdout_data = NULL;
    res->stderr_text = pr->stderr_data; pr->stderr_data = NULL;
    res->total_stdout_bytes = pr->stdout_total;
    res->total_stderr_bytes = pr->stderr_total;
    res->shown_stdout_bytes = pr->stdout_shown;
    res->shown_stderr_bytes = pr->stderr_shown;
    res->truncated = pr->truncated;
    res->exit_code = pr->exit_code;
    res->duration_ms += pr->duration_ms;
}

/* Karakter pembentuk identifier (untuk skimmer D1.2). */
static int ident_char(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/* C1 (--freestanding): hosted-API trap. API libc HOSTED yang dilarang di
 * firmware (stdio/stdio FILE, heap dinamis, proses/exit, string dinamik,
 * time). Bukan denylist keamanan: di mode ini arti temuan BERUBAH menjadi
 * finding observasi (printf = bug firmware), NON-blocking. */
static const char *const HOSTED_API[] = {
    "printf", "fprintf", "sprintf", "snprintf", "puts", "putchar",
    "fputs", "fputc", "getchar", "gets", "getc", "scanf", "fscanf",
    "sscanf", "fopen", "fclose", "fread", "fwrite", "fseek", "ftell",
    "rewind", "fflush", "fgetc", "fgets", "fputc", "fputs", "feof",
    "ferror", "fgetpos", "fsetpos", "perror", "tmpfile", "tmpnam",
    "remove", "rename", "freopen", "setbuf", "setvbuf", "fdopen",
    "getline", "malloc", "calloc", "realloc", "free", "strdup",
    "strndup", "aligned_alloc", "posix_memalign", "alloca", "exit",
    "abort", "atexit", "atof", "atoi", "atol", "strtol", "strtoul",
    "rand", "srand", "qsort", "bsearch", "getenv", "system",
    "time", "clock", "difftime", "mktime", "localtime", "gmtime",
    "asctime", "strftime", "signal", "raise", "assert",
    NULL
};

/* C1: scan source untuk panggilan API hosted (di luar komentar/string).
 * Menambah diagnostic OBSERVATION per hit (maks 12) + counter. */
static int scan_hosted_api(const char *src, size_t len, myc_result *res)
{
    int    hits = 0;
    size_t i = 0;
    (void)res;
    while (i < len) {
        char c = src[i];
        if (c == '/' && i + 1 < len && src[i + 1] == '/') {
            while (i < len && src[i] != '\n')
                i++;
            continue;
        }
        if (c == '/' && i + 1 < len && src[i + 1] == '*') {
            size_t e = i + 2;
            while (e + 1 < len && !(src[e] == '*' && src[e + 1] == '/'))
                e++;
            i = (e + 1 < len) ? e + 2 : e;
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
        if (ident_char((unsigned char)c)) {
            size_t j = i;
            char   name[64];
            size_t n;
            int    k;
            while (j < len && ident_char((unsigned char)src[j]))
                j++;
            n = j - i;
            if (n >= sizeof(name))
                n = sizeof(name) - 1;
            memcpy(name, src + i, n);
            name[n] = '\0';
            /* harus panggilan: diikuti '(' */
            {
                size_t cj = j;
                while (cj < len && (src[cj] == ' ' || src[cj] == '\t'))
                    cj++;
                if (cj < len && src[cj] == '(') {
                    for (k = 0; HOSTED_API[k]; k++) {
                        if (strcmp(HOSTED_API[k], name) == 0) {
                            char msg[160];
                            hits++;
                            if (hits <= 12 &&
                                res->diag_count < MYC_MAX_DIAGNOSTICS) {
                                snprintf(msg, sizeof(msg),
                                    "freestanding: %s() dipanggil -- API "
                                    "hosted TIDAK tersedia di target ini "
                                    "(observasi)", name);
                                {
                                    char *slot = myc_result_arena_dup(res,
                                                                      msg, 0);
                                    if (slot) {
                                        res->diags[res->diag_count].line = 0;
                                        res->diags[res->diag_count].col = 0;
                                        res->diags[res->diag_count].message =
                                            slot;
                                        res->diags[res->diag_count].confidence =
                                            MYC_CONF_OBSERVATION;
                                        res->diag_count++;
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            }
            i = j;
            continue;
        }
        i++;
    }
    return hits;
}

/* Skimmer coverage checked-build (MYC-AUDIT-026, roadmap 7.3): hitung
 * jumlah makro checked-build yang BENAR-BENAR terpakai di source (di luar
 * komentar, string, char literal, baris preprocessor):
 *   buffers     = deklarasi `MYC_BUF(T) b;` (ident MYC_BUF diikuti '(')
 *   allocations = invokasi MYC_NEW
 *   accesses    = invokasi MYC_AT   (titik akses yang mendapat cek batas)
 *   frees       = invokasi MYC_FREE
 * Coverage = metrik cakupan transformasi fat-pointer: bila build
 * -DMYC_CHECKED lolos, tiap buffer MYC_BUF dan tiap akses via MYC_AT terbukti
 * tunduk pada cek batas (akses langsung b[i] pada fat-struct = error
 * kompilasi), sehingga `accesses` adalah jumlah titik akses yang terlindungi.
 * Mengembalikan 1 bila ada >= 1 deklarasi MYC_BUF (source memakai
 * checked-build), 0 bila tidak. Deteksi uses_buf DAN perhitungan coverage
 * memakai SATU scanner (sumber kebenaran tunggal, tanpa duplikasi logika
 * skip komentar). Tidak menghitung referensi "MYC_BUF" di komentar (mencegah
 * over-claim L4).
 *
 * Catatan jujur: scanner LEXICAL — menghitung invokasi bahkan di dalam
 * cabang preprocessor yang TIDAK aktif (mis. `#ifndef MYC_CHECKED` fallback
 * produksi yang memakai akses langsung b[i]); untuk source semacam itu
 * angka accesses bisa over-state. Batasan yang sama dengan scanner leksikal
 * lain (lint/negative) — untuk pola umum (semua akses via MYC_AT) angkanya
 * tepat. */
static int scan_checked_coverage(const char *src, size_t len,
                                 int *buffers, int *allocs,
                                 int *accesses, int *frees)
{
    /* auto storage (bukan static): initializer memakai parameter fungsi
     * (bukan konstanta) sehingga `static` tidak valid di C. */
    const struct {
        const char *name;
        size_t      n;
        int        *dst;
        int         is_buf; /* MYC_BUF = deklarasi -> uses_buf */
    } macros[] = {
        { "MYC_BUF",  7, buffers,  1 },
        { "MYC_NEW",  7, allocs,   0 },
        { "MYC_AT",   6, accesses, 0 },
        { "MYC_FREE", 8, frees,    0 },
    };
    size_t i = 0;
    int    uses = 0;
    size_t nmac = sizeof(macros) / sizeof(macros[0]);

    *buffers = *allocs = *accesses = *frees = 0;
    while (i < len) {
        char c = src[i];
        if (c == '/' && i + 1 < len) {
            if (src[i + 1] == '/') {
                while (i < len && src[i] != '\n')
                    i++;
                continue;
            }
            if (src[i + 1] == '*') {
                i += 2;
                while (i + 1 < len && !(src[i] == '*' && src[i + 1] == '/'))
                    i++;
                i += 2;
                continue;
            }
        }
        if (c == '"' || c == '\'') {
            char q = c;
            i++;
            while (i < len && src[i] != q) {
                if (src[i] == '\\')
                    i++;
                i++;
            }
            i++;
            continue;
        }
        if (c == '#') {
            while (i < len && src[i] != '\n')
                i++;
            continue;
        }
        if (c >= 'A' && c <= 'Z') {
            size_t m;
            for (m = 0; m < nmac; m++) {
                if (i + macros[m].n <= len &&
                    memcmp(src + i, macros[m].name, macros[m].n) == 0) {
                    char before = i > 0 ? src[i - 1] : ' ';
                    char after  = i + macros[m].n < len
                                      ? src[i + macros[m].n] : ' ';
                    /* batas identifier: MYC_BUF_COOKIE tidak terhitung */
                    if (!ident_char((unsigned char)before) &&
                        !ident_char((unsigned char)after)) {
                        size_t j = i + macros[m].n;
                        while (j < len && (src[j] == ' ' || src[j] == '\t'))
                            j++;
                        if (j < len && src[j] == '(') {
                            (*macros[m].dst)++;
                            if (macros[m].is_buf)
                                uses = 1;
                        }
                    }
                    i += macros[m].n;
                    break;
                }
            }
            if (m < nmac)
                continue;
        }
        i++;
    }
    return uses;
}

/* ------------------------------------------------------------------ */
/* Gate checked-build (D1.2, --checked) -> L4 SPATIAL.                  */
/* ------------------------------------------------------------------ */
/*
 * Bangun source dua kali: (1) produksi normal (T* polos, sudah di-gate
 * gcc di atas), (2) -DMYC_CHECKED=1 sehingga MYC_BUF menjadi fat-struct
 * yang memaksa semua akses lewat MYC_AT (akses langsung b[i] = error
 * kompilasi). Bila build checked lolos, transformasi fat-pointer terbukti
 * berlaku -> assurance L4 SPATIAL untuk buffer MYC_BUF.
 *
 * Non-blocking (sesuai arah): source tanpa pola MYC_BUF -> gate di-skip,
 * assurance statis dipertahankan + diagnostic. Bila build checked GAGAL
 * (mis. akses langsung pada fat-struct), itu COMPILE_ERROR -- artinya kode
 * tidak memenuhi disiplin checked build.
 */
static void run_checked_gate(const myc_request *req, const char *gcc_path,
                             const char *src, size_t srclen,
                             size_t max_out, myc_result *res)
{
    static const char *const CHECKED_EXTRA[] = {
        "-c", "-O2", "-o", "NUL",
        "-DMYC_CHECKED=1",
        NULL
    };
    const char *const *lists[4];
    const char **args;
    size_t      nargs;
    myc_proc_request preq;
    myc_proc_result  pr;
    int   n = 0;
    int   argc = 0;
    int   total;
    int   i;
    const char **argv;

    {
        int n_buf = 0, n_alloc = 0, n_at = 0, n_free = 0;
        if (!scan_checked_coverage(src, srclen, &n_buf, &n_alloc, &n_at,
                                   &n_free)) {
            add_diag_copy(res, 0, 0,
                          "checked build di-skip: tidak ada pola MYC_BUF di source");
            /* verdict sukses (gate kompilasi sudah lolos); jangan biarkan
             * nilai awal MC_ERROR terbawa ke guard pipeline. */
            res->verdict = MC_OK;
            res->err = MYC_ERR_NONE;
            return;
        }
        /* MYC-AUDIT-026: coverage count — cakupan transformasi. */
        res->checked_buffers = n_buf;
        res->checked_allocations = n_alloc;
        res->checked_accesses = n_at;
        res->checked_frees = n_free;
    }

    /* susun argv: gcc + CHECKED_EXTRA + syntax base + mem warnings (+strict)
     * + -I<checked_header_dir> agar myc_buf.h ditemukan. */
    lists[0] = CHECKED_EXTRA;
    lists[1] = SYNTAX_BASE;
    lists[2] = MEMORY_WARNINGS;
    lists[3] = req->strict ? STRICT_WARNINGS : NULL;
    args = merge_args(lists, req->strict ? 4 : 3, &nargs);
    if (!args) {
        res->err = MYC_ERR_INTERNAL;
        res->verdict = MC_ERROR;
        return;
    }
    argc = (int)nargs;
    total = 1 + argc + (req->checked_header_dir ? 2 : 0) + 3 + 1;
    /* 1(gcc) + argc + [-I dir] + "-x","c","-" + NULL */
    argv = (const char **)malloc(sizeof(char *) * (size_t)total);
    if (!argv) {
        free((void *)args);
        res->err = MYC_ERR_INTERNAL;
        res->verdict = MC_ERROR;
        return;
    }
    argv[n++] = gcc_path;
    for (i = 0; i < argc; i++)
        argv[n++] = args[i];
    if (req->checked_header_dir) {
        argv[n++] = "-I";
        argv[n++] = req->checked_header_dir;
    }
    argv[n++] = "-x";
    argv[n++] = "c";
    argv[n++] = "-";
    argv[n] = NULL;
    free((void *)args);

    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.cwd = req->cwd;
    preq.stdin_data = src;
    preq.stdin_len = srclen;
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = max_out;
    if (!myc_proc_run(&preq, &pr)) {
        /* launch gagal: jangan salah klaim L4 (pr.exit_code=0 palsu) */
        free((void *)argv);
        if (pr.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->err = MYC_ERR_TIMEOUT;
            res->duration_ms += pr.duration_ms;
            myc_proc_result_free(&pr);
            return;
        }
        res->err = MYC_ERR_EXECUTE_FAILED;
        res->verdict = MC_ERROR;
        myc_proc_result_free(&pr);
        return;
    }
    free((void *)argv);

    res->ran_checked = 1;
    res->checked_uses_buf = 1;
    if (pr.timed_out) {
        res->verdict = MC_TIMEOUT;
        res->err = MYC_ERR_TIMEOUT;
        res->duration_ms += pr.duration_ms;
        myc_proc_result_free(&pr);
        return;
    }
    res->duration_ms += pr.duration_ms;
    if (pr.exit_code != 0) {
        /* kode tidak memenuhi disiplin checked build (mis. akses langsung
         * pada fat-struct, atau tipe tidak cocok dengan MYC_AT) */
        res->verdict = MC_COMPILE_ERROR;
        res->err = MYC_ERR_COMPILE_ERROR;
        res->checked_build_ok = 0;
        adopt_proc(res, &pr);
        if (res->stderr_text)
            ingest_gcc_diagnostics(res, res->stderr_text);
        myc_proc_result_free(&pr);
        return;
    }
    myc_proc_result_free(&pr);
    res->checked_build_ok = 1;
    /* gate ini "memiliki" verdict-nya sendiri (pola sama dengan prove/run):
     * nilai awal MC_ERROR tidak boleh terbawa. */
    res->verdict = MC_OK;
    res->err = MYC_ERR_NONE;
    res->exit_code = 0;
    add_diag_copy(res, 0, 0,
                  "checked build OK: transformasi fat-pointer (MYC_BUF) -> L4 SPATIAL");
}

void myc_pipeline(const myc_request *req, myc_result *res)
{
    char *gcc_path = NULL;
    myc_proc_result pr;
    size_t max_out = req->max_output_bytes > 0
                         ? (size_t)req->max_output_bytes
                         : MYC_MAX_OUTPUT_BYTES;
    const char *src;
    size_t      srclen;
    char        hex[65];

    src = req->input.data;
    srclen = req->input.len;

    /* Inisialisasi gate status (Fase 3). */
    myc_gate_set_status(res, MYC_GATE_PREPROCESS, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_COMPILE, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_ANALYZER, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_PROVE, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_CHECKED, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_FILC, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_METAMORPHIC, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_NEGATIVE, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_LINT, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_DIVERGENCE, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_COMPARE, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_STACK, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_FUZZ, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_MUTATE, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_FREESTANDING, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_MATRIX, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_NOT_APPLICABLE, NULL);

    /* hash source */
    sha256_hex(src, srclen, hex);
    res->source_sha256 = myc_strdup(hex);

    /* cari gcc */
    gcc_path = myc_find_executable(req->gcc_program ? req->gcc_program : "gcc");
    if (!gcc_path) {
        res->err = MYC_ERR_GCC_NOT_FOUND;
        res->verdict = MC_ERROR;
        return;
    }
    res->resolved_gcc = myc_strdup(gcc_path);
    /* MYC-AUDIT-022 (roadmap 7.1): exact tool identity — baris pertama
     * `gcc --version` (mis. "gcc.exe (...) 15.2.0"). NULL bila gagal. */
    res->gcc_version = myc_tool_version(gcc_path);

    /* fingerprint kanonik (incremental — cache base components
     * agar perubahan source saja tidak perlu recompute gcc_path/
     * cwd/policy/flags). MYC-AUDIT-005: snprintf(NULL,0,...)
     * menghitung panjang exact sebelum alokasi. */
    {
        char  policy_hex[65];
        char  flags_str[256];
        myc_policy_hash(policy_hex);
        snprintf(flags_str, sizeof(flags_str),
                      "c11;Wall;Werror;pedantic;mem;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s",
                      req->strict ? "strict" : "default",
                      req->run ? "run" : "norun",
                      req->prove ? "prove" : "noprove",
                      req->checked ? "checked" : "nochecked",
                      req->filc ? "filc" : "nofilc",
                      req->driver ? "driver" : "nodriver",
                      req->metamorphic ? "meta" : "nometa",
                      req->negative ? "neg" : "noneg",
                      req->divergence ? "div" : "nodiv",
                      req->require_complete ? "reqc" : "noreqc",
                      req->freestanding ? "free" : "nofree");
        fingerprint_cache_update(gcc_path, req->cwd, policy_hex,
                                     flags_str, MYC_BUF_RUNTIME_REV);
        fingerprint_compute_incremental(res->source_sha256, hex);
        res->fingerprint = myc_strdup(hex);
    }

    /* --- Lapis 1: include mentah (warning, non-blocking) --- */
    myc_scan_include_raw(src, srclen, res);

    /* --- Scan kontrak //@ requires/ensures (D1.5; info, non-blocking) --- */
    myc_contract_scan(src, srclen, res);

    /* --- B4 (Comments-as-Contracts, DS-08): panen kandidat kontrak dari
     * komentar biasa (bukan //@). NON-blocking observasi murni. */
    myc_contract_harvest(src, srclen, res);

    /* --- Fase 5 (Relational contracts): klasifikasi klausa kontrak
     * relasional (>=2 variabel) vs unary + binding check. NON-blocking
     * observasi murni (analisis teks deterministik). */
    myc_contract_relational(src, srclen, res);

    /* --- Fase 5 (SOL-13): ghost state machine dari //@ sm -- sink /
     * unreachable / no-recovery / undeclared / unused + witness BFS.
     * NON-blocking observasi murni. */
    myc_sm_scan(src, srclen, res);

    /* --- Lint memory-safety (P5; default aktif, mati via --no-lint) ---
     * MYC-AUDIT-014: heuristik teks TIDAK boleh hard verdict. Hasil lint
     * = observasi + confidence (OBSERVATION/SUSPICIOUS), NON-blocking.
     * Gate status: COMPLETED_CLEAN bila tanpa observasi, COMPLETED_
     * OBSERVATIONS bila ada -- benign terhadap verdict/assurance/finding
     * (sama dengan negative-space 9.8). Hard evidence tetap dari gate
     * semantik: gcc -Wuse-after-free / -fanalyzer, sanitizer, dst. */
    if (req->run_lint) {
        res->lint_observations =
            myc_lint_source(src, srclen, req->freestanding, res);
        if (res->lint_observations > 0) {
            myc_gate_set_status(res, MYC_GATE_LINT,
                                MYC_GATE_COMPLETED_OBSERVATIONS,
                                "lint heuristik: observasi (non-blocking)");
            myc_result_add_evidence(res, MYC_GATE_LINT,
                                    MYC_EVIDENCE_DIAGNOSTIC,
                                    "lint: observasi heuristik (bukan finding)");
        } else {
            myc_gate_set_status(res, MYC_GATE_LINT, MYC_GATE_COMPLETED_CLEAN,
                                "lint bersih");
            myc_result_add_evidence(res, MYC_GATE_LINT, MYC_EVIDENCE_GATE_END,
                                    "lint: bersih");
        }
    }

    /* --- Gate opsional: Negative-Space Analysis (9.8, --negative) ---
     * Structural mining pola yang hilang: konvensi pemeriksaan hasil
     * fungsi alokasi per callsite. HANYA observasi (diagnostic +
     * confidence) -- TIDAK pernah hard verdict (prinsip MYC-AUDIT-014:
     * heuristik teks bukan bukti semantik). Non-blocking: tanpa callsite
     * yang cocok -> NOT_APPLICABLE, tidak ada klaim. Status gate:
     *   - 0 callsite               -> NOT_APPLICABLE
     *   - semua memeriksa          -> COMPLETED_CLEAN
     *   - ada yang tidak memeriksa -> COMPLETED_OBSERVATIONS (bukan
     *     FINDINGS: observasi, bukan finding terkonfirmasi). */
    if (req->negative) {
        myc_negative_space(src, srclen, res);
        res->ran_negative = 1;
        if (res->negative_callsites == 0) {
            myc_gate_set_status(res, MYC_GATE_NEGATIVE, MYC_GATE_NOT_APPLICABLE,
                                "tidak ada callsite alokasi");
            myc_result_add_evidence(res, MYC_GATE_NEGATIVE, MYC_EVIDENCE_SKIP,
                                    "negative-space: 0 callsite");
        } else if (res->negative_deviations == 0) {
            myc_gate_set_status(res, MYC_GATE_NEGATIVE, MYC_GATE_COMPLETED_CLEAN,
                                "semua callsite memeriksa hasil");
            myc_result_add_evidence(res, MYC_GATE_NEGATIVE, MYC_EVIDENCE_GATE_END,
                                    "negative-space: clean");
        } else {
            myc_gate_set_status(res, MYC_GATE_NEGATIVE,
                                MYC_GATE_COMPLETED_OBSERVATIONS,
                                "konvensi menyimpang terdeteksi");
            myc_result_add_evidence(res, MYC_GATE_NEGATIVE,
                                    MYC_EVIDENCE_DIAGNOSTIC,
                                    "negative-space: deviation (observasi)");
        }
        /* Non-blocking: lanjut pipeline normal (tidak return). */
    }

    /* --- gcc -E --- */
    {
        static const char *const pre_args[] = { "-E", "-std=c11", NULL };
        run_gcc(req, gcc_path, pre_args, src, srclen, max_out, &pr);
    }
    if (pr.timed_out) {
        res->verdict = MC_TIMEOUT;
        res->err = MYC_ERR_TIMEOUT;
        myc_proc_result_free(&pr);
        free(gcc_path);
        myc_gate_set_status(res, MYC_GATE_PREPROCESS, MYC_GATE_INCONCLUSIVE,
                            "preprocess timeout");
        myc_result_add_evidence(res, MYC_GATE_PREPROCESS, MYC_EVIDENCE_ERROR,
                                "gcc -E timeout");
        myc_reduce_verdict(res);
        return;
    }
    res->ran_preprocess = 1;
    adopt_proc(res, &pr);
    myc_proc_result_free(&pr);

    if (res->exit_code != 0) {
        /* preprocess gagal (mis. makro rusak) */
        res->verdict = MC_COMPILE_ERROR;
        res->err = MYC_ERR_PREPROCESS_ERROR;
        myc_gate_set_status(res, MYC_GATE_PREPROCESS, MYC_GATE_COMPLETED_FINDINGS,
                            res->stderr_text ? res->stderr_text : "preprocess error");
        myc_result_add_evidence(res, MYC_GATE_PREPROCESS, MYC_EVIDENCE_FINDING,
                                "preprocess gagal");
        if (res->stderr_text)
            ingest_gcc_diagnostics(res, res->stderr_text);
        free(gcc_path);
        myc_reduce_verdict(res);
        return;
    }
    myc_gate_set_status(res, MYC_GATE_PREPROCESS, MYC_GATE_COMPLETED_CLEAN,
                        "preprocess clean");
    myc_result_add_evidence(res, MYC_GATE_PREPROCESS, MYC_EVIDENCE_GATE_END,
                            "gcc -E clean");

    /* --- Lapis 2 + 3: markers & calls (warning, non-blocking) --- */
    {
        /* pre = buffer yang TERSIMPAN (mungkin terpotong 1MB); panjangnya
         * harus shown_stdout_bytes, BUKAN total (gcc bisa menulis jauh lebih
         * banyak). Memakai total -> out-of-bounds read (bug dogfooding). */
        const char *pre = res->stdout_text ? res->stdout_text : "";
        size_t      prelen = res->stdout_text ? res->shown_stdout_bytes : 0;
        myc_scan_markers(pre, prelen, res);
        myc_scan_calls(pre, prelen, res);
    }

    /* --- Gate: kompilasi + tier dasar memori (perlu -O2 utk memori) ---
     * C1 (--freestanding): tambah -ffreestanding -fno-builtin sehingga
     * kompilasi mensimulasikan C tanpa OS (libc hosted tak diasumsikan).
     * Bila gagal di mode ini = HARD (sama seperti compile biasa). */
    {
        static const char *const FREE_EXTRA[] = {
            "-ffreestanding", "-fno-builtin", NULL
        };
        const char *const *lists[5];
        const char **args;
        size_t      nargs;
        lists[0] = MEMORY_GATE;
        lists[1] = SYNTAX_BASE;
        lists[2] = MEMORY_WARNINGS;
        lists[3] = req->strict ? STRICT_WARNINGS : NULL;
        lists[4] = req->freestanding ? FREE_EXTRA : NULL;
        args = merge_args(lists,
                          (req->strict ? 4 : 3) + (req->freestanding ? 1 : 0),
                          &nargs);
        if (!args) {
            res->verdict = MC_ERROR;
            res->err = MYC_ERR_INTERNAL;
            free(gcc_path);
            return;
        }
        run_gcc(req, gcc_path, args, src, srclen, max_out, &pr);
        free((void *)args);
    }
    if (req->freestanding) {
        res->ran_freestanding = 1;
        res->freestanding_api_hits = scan_hosted_api(src, srclen, res);
        myc_gate_set_status(res, MYC_GATE_FREESTANDING,
                            res->freestanding_api_hits > 0
                                ? MYC_GATE_COMPLETED_OBSERVATIONS
                                : MYC_GATE_COMPLETED_CLEAN,
                            res->freestanding_api_hits > 0
                                ? "hosted API terdeteksi (observasi)"
                                : "freestanding hygiene bersih");
        myc_result_add_evidence(res, MYC_GATE_FREESTANDING,
                                res->freestanding_api_hits > 0
                                    ? MYC_EVIDENCE_DIAGNOSTIC
                                    : MYC_EVIDENCE_GATE_END,
                                "freestanding: hygiene scan selesai");
        {
            char rep[512];
            snprintf(rep, sizeof(rep),
                     "freestanding (C1): %d panggilan API hosted (observasi "
                     "NON-blocking; compile memakai -ffreestanding "
                     "-fno-builtin)\n", res->freestanding_api_hits);
            res->freestanding_report = myc_result_arena_dup(res, rep, 0);
        }
    }
    if (pr.timed_out) {
        res->verdict = MC_TIMEOUT;
        res->err = MYC_ERR_TIMEOUT;
        myc_proc_result_free(&pr);
        free(gcc_path);
        myc_gate_set_status(res, MYC_GATE_COMPILE, MYC_GATE_INCONCLUSIVE,
                            "compile timeout");
        myc_result_add_evidence(res, MYC_GATE_COMPILE, MYC_EVIDENCE_ERROR,
                                "gcc -c timeout");
        myc_reduce_verdict(res);
        return;
    }
    res->ran_compile = 1;
    adopt_proc(res, &pr);
    myc_proc_result_free(&pr);

    if (res->exit_code != 0) {
        res->verdict = MC_COMPILE_ERROR;
        res->err = MYC_ERR_COMPILE_ERROR;
        myc_gate_set_status(res, MYC_GATE_COMPILE, MYC_GATE_COMPLETED_FINDINGS,
                            res->stderr_text ? res->stderr_text : "compile error");
        myc_result_add_evidence(res, MYC_GATE_COMPILE, MYC_EVIDENCE_FINDING,
                                "compile gagal");
        if (res->stderr_text)
            ingest_gcc_diagnostics(res, res->stderr_text);
        free(gcc_path);
        myc_reduce_verdict(res);
        return;
    }
    myc_gate_set_status(res, MYC_GATE_COMPILE, MYC_GATE_COMPLETED_CLEAN,
                        "compile clean");
    myc_result_add_evidence(res, MYC_GATE_COMPILE, MYC_EVIDENCE_GATE_END,
                            "gcc -c clean");

    /* --- Gate opsional: -fanalyzer --- */
    if (req->run_analyzer) {
        const char *const *lists[4];
        const char **args;
        size_t      nargs;
        lists[0] = ANALYZER_EXTRA;
        lists[1] = SYNTAX_BASE;
        lists[2] = MEMORY_WARNINGS;
        lists[3] = req->strict ? STRICT_WARNINGS : NULL;
        args = merge_args(lists, req->strict ? 4 : 3, &nargs);
        if (!args) {
            res->verdict = MC_ERROR;
            res->err = MYC_ERR_INTERNAL;
            free(gcc_path);
            return;
        }
        run_gcc(req, gcc_path, args, src, srclen, max_out, &pr);
        free((void *)args);
        if (pr.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->err = MYC_ERR_TIMEOUT;
            myc_proc_result_free(&pr);
            free(gcc_path);
            myc_gate_set_status(res, MYC_GATE_ANALYZER, MYC_GATE_INCONCLUSIVE,
                                "analyzer timeout");
            myc_result_add_evidence(res, MYC_GATE_ANALYZER, MYC_EVIDENCE_ERROR,
                                    "gcc -fanalyzer timeout");
            myc_reduce_verdict(res);
            return;
        }
        res->ran_analyzer = 1;
        if (pr.exit_code != 0) {
            res->verdict = MC_COMPILE_ERROR;
            res->err = MYC_ERR_COMPILE_ERROR;
            adopt_proc(res, &pr);
            myc_gate_set_status(res, MYC_GATE_ANALYZER, MYC_GATE_COMPLETED_FINDINGS,
                                res->stderr_text ? res->stderr_text : "analyzer finding");
            myc_result_add_evidence(res, MYC_GATE_ANALYZER, MYC_EVIDENCE_FINDING,
                                    "gcc -fanalyzer finding");
            if (res->stderr_text)
                ingest_gcc_diagnostics(res, res->stderr_text);
            myc_proc_result_free(&pr);
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        myc_gate_set_status(res, MYC_GATE_ANALYZER, MYC_GATE_COMPLETED_CLEAN,
                            "analyzer clean");
        myc_result_add_evidence(res, MYC_GATE_ANALYZER, MYC_EVIDENCE_GATE_END,
                                "gcc -fanalyzer clean");
        myc_proc_result_free(&pr);
    }

    /* --- Gate opsional: checked build (D1.2, --checked) -> L4 SPATIAL ---
     * Bangun source kedua dengan -DMYC_CHECKED=1 (fat-pointer). Lolos =
     * transformasi berlaku. Gagal (COMPILE_ERROR) = kode tidak mematuhi
     * disiplin checked build. Di-skip bila source tidak memakai MYC_BUF.
     * Catatan: bila --prove juga diminta, jangan return dulu -- prove tetap
     * dijalankan (PROVE_VIOLATION tetap harus dilaporkan); L4 > L2 jadi
     * assurance tidak diturunkan. */
    if (req->checked) {
        run_checked_gate(req, gcc_path, src, srclen, max_out, res);
        if (res->verdict == MC_TIMEOUT || res->verdict == MC_COMPILE_ERROR ||
            res->verdict == MC_ERROR) {
            myc_gate_set_status(res, MYC_GATE_CHECKED,
                                res->verdict == MC_COMPILE_ERROR
                                    ? MYC_GATE_COMPLETED_FINDINGS
                                    : MYC_GATE_INCONCLUSIVE,
                                res->stderr_text ? res->stderr_text : "checked build error");
            myc_result_add_evidence(res, MYC_GATE_CHECKED,
                                    res->verdict == MC_COMPILE_ERROR
                                        ? MYC_EVIDENCE_FINDING
                                        : MYC_EVIDENCE_ERROR,
                                    "checked build gagal/timeout");
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (res->checked_build_ok) {
            myc_gate_set_status(res, MYC_GATE_CHECKED, MYC_GATE_COMPLETED_CLEAN,
                                "checked build OK");
            myc_result_add_evidence(res, MYC_GATE_CHECKED, MYC_EVIDENCE_GATE_END,
                                    "checked build lolos");
        } else {
            myc_gate_set_status(res, MYC_GATE_CHECKED, MYC_GATE_NOT_APPLICABLE,
                                "tidak ada pola MYC_BUF");
            myc_result_add_evidence(res, MYC_GATE_CHECKED, MYC_EVIDENCE_SKIP,
                                    "checked build di-skip: tanpa MYC_BUF");
        }
        if (!req->run && !req->prove && !req->filc && !req->driver &&
            !req->metamorphic && !req->divergence) {
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
    }

    /* --- Gate opsional: Frama-C Eva (D3.1, --prove) -> L2 EVA ---
     * Non-blocking: bila wsl/frama-c hilang atau Eva tidak menganalisis,
     * assurance statis dipertahankan (bukan error). Bila --run/--filc juga
     * diminta, jangan return dulu: lanjut ke gate berikut (L5 > L3 > L2).
     * MYC-AUDIT-013: L2 EVA = 0 alarm RTE di bawah model Eva (abstract
     * interpretation), BUKAN proof obligation WP. */
    if (req->prove) {
        int ok = myc_prove_gate(req, src, srclen, res);
        if (res->verdict == MC_TIMEOUT || res->verdict == MC_PROVE_VIOLATION) {
            /* violation = bug terbukti -> assurance turun ke NONE
             * (konsisten dengan fixture bad_run_* -> L0) */
            if (res->verdict == MC_PROVE_VIOLATION) {
                res->assurance = MYC_ASSURANCE_NONE;
                myc_gate_set_status(res, MYC_GATE_PROVE, MYC_GATE_COMPLETED_FINDINGS,
                                    res->prove_stderr_text ? res->prove_stderr_text : "prove violation");
                myc_result_add_evidence(res, MYC_GATE_PROVE, MYC_EVIDENCE_FINDING,
                                        "Frama-C Eva: PROVE_VIOLATION");
            } else {
                myc_gate_set_status(res, MYC_GATE_PROVE, MYC_GATE_INCONCLUSIVE,
                                    "prove timeout");
                myc_result_add_evidence(res, MYC_GATE_PROVE, MYC_EVIDENCE_ERROR,
                                        "Frama-C Eva timeout");
            }
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (ok && res->ran_prove && res->prove_alarms == 0) {
            myc_gate_set_status(res, MYC_GATE_PROVE, MYC_GATE_COMPLETED_CLEAN,
                                "Eva: 0 alarm");
            myc_result_add_evidence(res, MYC_GATE_PROVE, MYC_EVIDENCE_GATE_END,
                                    "Frama-C Eva clean");
        } else {
            /* 9.10/AUDIT-004: gate DIMINTA tapi bukti tidak diproduksi
             * (wsl/frama-c hilang, Eva tidak menganalisis) -> UNAVAILABLE
             * + debt, BUKAN NOT_APPLICABLE (kesunyian). Assurance statis
             * tetap dipertahankan (non-blocking), tapi gap terlihat.
             * Bila prove.c sudah mencatat INFRA_FAILED (gagal infra,
             * bukan backend hilang), pertahankan status yang lebih
             * spesifik itu (kode debt berbeda). */
            const myc_gate_result *pg =
                myc_gate_get(res, MYC_GATE_PROVE);
            if (pg && pg->status == MYC_GATE_INFRA_FAILED) {
                myc_result_add_evidence(res, MYC_GATE_PROVE,
                                        MYC_EVIDENCE_SKIP,
                                        "Frama-C Eva infra failed (gap)");
            } else {
                myc_gate_set_status(res, MYC_GATE_PROVE, MYC_GATE_UNAVAILABLE,
                                    "Eva tidak tersedia / tidak menganalisis");
                myc_result_add_evidence(res, MYC_GATE_PROVE,
                                        MYC_EVIDENCE_SKIP,
                                        "Frama-C Eva unavailable (gap)");
            }
        }
        if (!req->run && !req->filc && !req->driver && !req->metamorphic &&
            !req->divergence) {
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
    }

    /* --- Gate opsional: Fil-C (D4.1, --filc) -> L5 FILC ---
     * Non-blocking: bila filc-clang tidak tersedia (PATH/WSL), gate di-skip,
     * assurance statis dipertahankan + diagnostic. Bila tersedia dan run
     * bersih (tanpa marker panic) -> L5. Bila --run juga diminta, jangan
     * return dulu: lanjut ke gate run (L3 > L2; L5 tetap dipertahankan).
     * MYC-AUDIT-013: L5 FILC = eksekusi terkendali Fil-C bersih, bukan
     * "FULL" (label lama melebihi bukti). */
    if (req->filc) {
        int ok = myc_filc_gate(req, src, srclen, res);
        if (res->verdict == MC_TIMEOUT || res->verdict == MC_FILC_VIOLATION) {
            if (res->verdict == MC_FILC_VIOLATION) {
                res->assurance = MYC_ASSURANCE_NONE;
                myc_gate_set_status(res, MYC_GATE_FILC, MYC_GATE_COMPLETED_FINDINGS,
                                    res->filc_stderr_text ? res->filc_stderr_text : "filc violation");
                myc_result_add_evidence(res, MYC_GATE_FILC, MYC_EVIDENCE_FINDING,
                                        "Fil-C: VIOLATION");
            } else {
                myc_gate_set_status(res, MYC_GATE_FILC, MYC_GATE_INCONCLUSIVE,
                                    "filc timeout");
                myc_result_add_evidence(res, MYC_GATE_FILC, MYC_EVIDENCE_ERROR,
                                        "Fil-C timeout");
            }
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (ok && res->ran_filc && res->filc_panics == 0) {
            myc_gate_set_status(res, MYC_GATE_FILC, MYC_GATE_COMPLETED_CLEAN,
                                "filc clean");
            myc_result_add_evidence(res, MYC_GATE_FILC, MYC_EVIDENCE_GATE_END,
                                    "Fil-C clean");
        } else {
            /* 9.10/AUDIT-004: gate DIMINTA tapi backend filc-clang tidak
             * tersedia -> UNAVAILABLE + debt (bukan kesunyian). */
            myc_gate_set_status(res, MYC_GATE_FILC, MYC_GATE_UNAVAILABLE,
                                "filc-clang tidak tersedia");
            myc_result_add_evidence(res, MYC_GATE_FILC, MYC_EVIDENCE_SKIP,
                                    "Fil-C unavailable (gap)");
        }
        if (!req->run && !req->driver && !req->metamorphic &&
            !req->divergence) {
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
    }

    /* --- Gate opsional: verification run (P6, --run) -> L3 RUNTIME --- */
    if (req->run) {
        int ok = myc_run_gate(req, src, srclen, res);
        if (res->verdict == MC_TIMEOUT || res->verdict == MC_RUNTIME_VIOLATION ||
            res->err == MYC_ERR_EXECUTE_FAILED || res->err == MYC_ERR_INTERNAL) {
            /* violation = bug terbukti -> assurance turun ke NONE
             * (konsisten dengan fixture bad_run_* -> L0) */
            if (res->verdict == MC_RUNTIME_VIOLATION) {
                res->assurance = MYC_ASSURANCE_NONE;
                myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_COMPLETED_FINDINGS,
                                    res->run_stderr_text ? res->run_stderr_text : "runtime violation");
                myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_FINDING,
                                        "verification run: RUNTIME_VIOLATION");
            } else {
                myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INFRA_FAILED,
                                    "runtime infra failed");
                myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_ERROR,
                                        "verification run: infra failed");
            }
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (ok && res->ran_runtime && !res->run_timed_out) {
            /* clean run: gate status sudah di-set oleh myc_run_gate */
        } else {
            myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INCONCLUSIVE,
                                "runtime di-skip");
            myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_SKIP,
                                    "verification run di-skip");
        }
        if (!req->driver && !req->metamorphic && !req->divergence) {
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
    }

    /* --- Gate opsional: Metamorphic Verification (9.7, --metamorphic) ---
     * Bangun source sama di -O0 dan -O2 (clang ASan+UBSan), jalankan,
     * bandingkan. Hanya satu build yang menemukan sanitizer -> inconsistent
     * (kemungkinan UB/toolchain-sensitive) -> RUNTIME_VIOLATION. Keduanya
     * bersih -> COMPLETED_CLEAN (L3, konsisten dengan gate run).
     * Non-blocking: clang hilang / build gagal / canary mati -> di-skip
     * atau INCONCLUSIVE, assurance statis dipertahankan. */
    if (req->metamorphic) {
        int ok = myc_metamorphic_gate(req, src, srclen, res);
        if (res->verdict == MC_TIMEOUT ||
            res->verdict == MC_RUNTIME_VIOLATION ||
            res->err == MYC_ERR_EXECUTE_FAILED ||
            res->err == MYC_ERR_INTERNAL) {
            if (res->verdict == MC_RUNTIME_VIOLATION) {
                /* finding nyata (sanitizer pada salah satu/both build) */
                res->assurance = MYC_ASSURANCE_NONE;
                myc_gate_set_status(res, MYC_GATE_METAMORPHIC,
                                    MYC_GATE_COMPLETED_FINDINGS,
                                    res->run_stderr_text ? res->run_stderr_text
                                        : "metamorphic finding");
                myc_result_add_evidence(res, MYC_GATE_METAMORPHIC,
                                        MYC_EVIDENCE_FINDING,
                                        "metamorphic: RUNTIME_VIOLATION");
            } else {
                myc_gate_set_status(res, MYC_GATE_METAMORPHIC,
                                    MYC_GATE_INFRA_FAILED,
                                    "metamorphic infra failed");
                myc_result_add_evidence(res, MYC_GATE_METAMORPHIC,
                                        MYC_EVIDENCE_ERROR,
                                        "metamorphic: infra failed");
            }
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (ok && res->ran_metamorphic && !res->meta_timed_out) {
            /* status sudah di-set oleh myc_metamorphic_gate */
        } else {
            myc_gate_set_status(res, MYC_GATE_METAMORPHIC,
                                MYC_GATE_INCONCLUSIVE,
                                "metamorphic di-skip");
            myc_result_add_evidence(res, MYC_GATE_METAMORPHIC,
                                    MYC_EVIDENCE_SKIP,
                                    "metamorphic di-skip");
        }
        if (!req->driver && !req->divergence) {
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
    }

    /* --- Gate opsional: Cross-Toolchain Divergence (Fase 4, A2/DS-02,
     * --divergence) ---
     * Bangun + jalankan source SAMA dengan matriks {gcc, clang, [tcc]}
     * x {-O0,-O2}; bandingkan exit / sanitizer finding / sha256 stdout /
     * set warning per sel. Klasifikasi DS-02: sanitizer_divergence (satu
     * sel finding, lain clean -> HARD RUNTIME_VIOLATION, bug toolchain-
     * sensitive), all_findings (semua sel menemukan -> bug konsisten),
     * semantic_divergence / diagnostic_divergence -> OBSERVASI NON-
     * blocking (tidak menurunkan verdict). Hanya bukti sanitizer = hard.
     * Non-blocking: toolchain hilang / build gagal = sel di-skip. */
    if (req->divergence) {
        int ok = myc_divergence_gate(req, src, srclen, res);
        if (res->verdict == MC_TIMEOUT ||
            res->verdict == MC_RUNTIME_VIOLATION ||
            res->err == MYC_ERR_EXECUTE_FAILED ||
            res->err == MYC_ERR_INTERNAL) {
            if (res->verdict == MC_RUNTIME_VIOLATION) {
                /* finding nyata (sanitizer divergence antar toolchain) */
                res->assurance = MYC_ASSURANCE_NONE;
                myc_gate_set_status(res, MYC_GATE_DIVERGENCE,
                                    MYC_GATE_COMPLETED_FINDINGS,
                                    res->divergence_report
                                        ? res->divergence_report
                                        : "divergence finding");
                myc_result_add_evidence(res, MYC_GATE_DIVERGENCE,
                                        MYC_EVIDENCE_FINDING,
                                        "divergence: RUNTIME_VIOLATION");
            } else {
                myc_gate_set_status(res, MYC_GATE_DIVERGENCE,
                                    MYC_GATE_INFRA_FAILED,
                                    "divergence infra failed");
                myc_result_add_evidence(res, MYC_GATE_DIVERGENCE,
                                        MYC_EVIDENCE_ERROR,
                                        "divergence: infra failed");
            }
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (ok && res->ran_divergence) {
            /* status sudah di-set oleh myc_divergence_gate */
        } else {
            myc_gate_set_status(res, MYC_GATE_DIVERGENCE,
                                MYC_GATE_INCONCLUSIVE,
                                "divergence di-skip");
            myc_result_add_evidence(res, MYC_GATE_DIVERGENCE,
                                    MYC_EVIDENCE_SKIP,
                                    "divergence di-skip");
        }
        if (!req->driver) {
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
    }

    /* --- Gate opsional: driver-generator (D2.2, --driver) -> L3 RUNTIME ---
     * Non-blocking: bila clang hilang / tidak ada fungsi ber-kontrak / build
     * harness gagal, assurance statis dipertahankan + diagnostic. Bila run
     * bersih dengan >= 1 kasus tereksekusi -> L3 (runtime via sanitizer).
     * Marker sanitizer -> MC_DRIVER_VIOLATION (bug nyata pada kasus tepi). */
    if (req->driver) {
        int ok = myc_driver_gate(req, src, srclen, res);
        if (res->verdict == MC_TIMEOUT || res->verdict == MC_DRIVER_VIOLATION) {
            if (res->verdict == MC_DRIVER_VIOLATION) {
                res->assurance = MYC_ASSURANCE_NONE;
                myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_COMPLETED_FINDINGS,
                                    res->driver_stderr_text ? res->driver_stderr_text : "driver violation");
                myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_FINDING,
                                        "driver: DRIVER_VIOLATION");
            } else {
                myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INCONCLUSIVE,
                                    "driver timeout");
                myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_ERROR,
                                        "driver timeout");
            }
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (ok && res->ran_driver && res->driver_cases > 0) {
            myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_COMPLETED_CLEAN,
                                "driver clean");
            myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_GATE_END,
                                    "driver: clean");
        } else if (res->contract_requires == 0) {
            /* Benar-benar tidak berlaku: source tanpa fungsi ber-kontrak. */
            myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_NOT_APPLICABLE,
                                "tidak ada fungsi ber-kontrak");
            myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_SKIP,
                                    "driver di-skip: tanpa kontrak");
        } else {
            /* 9.10/AUDIT-004: kontrak ada tapi backend/harness tidak
             * memproduksi kasus -> UNAVAILABLE + debt (bukan kesunyian). */
            myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_UNAVAILABLE,
                                "driver tidak tersedia / 0 kasus");
            myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_SKIP,
                                    "driver unavailable (gap)");
        }
        free(gcc_path);
        myc_reduce_verdict(res);
        return;
    }

    /* --- Gate opsional: small-domain exhaustive proof (Fase 5, A3) ---
     * Enumerasi PENUH domain fungsi ber-kontrak yang terbatas = bukti
     * riil (P1 EXHAUSTIVE) untuk domain dideklarasikan. Non-blocking:
     * clang absen / tanpa fungsi domain kecil -> di-skip (UNAVAILABLE /
     * NOT_APPLICABLE). Violation = counterexample enumeratif. */
    if (req->exhaustive) {
        int ok = myc_exhaustive_gate(req, src, srclen, res);
        if (res->verdict == MC_TIMEOUT ||
            res->verdict == MC_DRIVER_VIOLATION) {
            if (res->verdict == MC_DRIVER_VIOLATION) {
                res->assurance = MYC_ASSURANCE_NONE;
                myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_GATE_COMPLETED_FINDINGS,
                                    res->exhaustive_stderr_text
                                        ? res->exhaustive_stderr_text
                                        : "exhaustive counterexample");
                myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                        MYC_EVIDENCE_FINDING,
                                        "exhaustive: counterexample");
            } else {
                myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_GATE_INCONCLUSIVE,
                                    "exhaustive timeout");
                myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                        MYC_EVIDENCE_ERROR,
                                        "exhaustive timeout");
            }
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (ok && res->ran_exhaustive && res->exhaustive_cases > 0) {
            myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                MYC_GATE_COMPLETED_CLEAN,
                                "P1 EXHAUSTIVE (domain dideklarasikan)");
            myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_EVIDENCE_GATE_END,
                                    "exhaustive: clean (enumerasi penuh)");
        } else if (res->contract_requires == 0) {
            myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                MYC_GATE_NOT_APPLICABLE,
                                "tidak ada fungsi ber-kontrak");
            myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_EVIDENCE_SKIP,
                                    "exhaustive di-skip: tanpa kontrak");
        } else {
            myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                MYC_GATE_UNAVAILABLE,
                                "exhaustive tidak tersedia / 0 titik");
            myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_EVIDENCE_SKIP,
                                    "exhaustive unavailable (gap)");
        }
        free(gcc_path);
        myc_reduce_verdict(res);
        return;
    }

    /* --- Gate opsional: stack budget analyzer (Fase 5, C2/DS-10) ---
     * gcc -fstack-usage + call graph -> worst-case stack depth vs
     * --stack-budget; deteksi rekursi/alloca/VLA. NON-blocking
     * observasi (static worst-case != dynamic; claim compiler). */
    /* Fase 6 (--thread-probe): concurrency probe (lock-order + TSan).
     * NON-blocking observasi, independen dari gate lain. */
    if (req->thread_probe)
        myc_concur_gate(req, res, src, srclen);

    if (req->stack) {
        int ok = myc_stack_gate(req, src, srclen, res);
        if (ok && res->ran_stack) {
            if (res->stack_recursion ||
                (res->stack_budget > 0 &&
                 res->stack_worst_bytes > res->stack_budget)) {
                myc_gate_set_status(res, MYC_GATE_STACK,
                                    MYC_GATE_COMPLETED_OBSERVATIONS,
                                    "stack over budget / rekursi "
                                    "(observasi non-blocking)");
                myc_result_add_evidence(res, MYC_GATE_STACK,
                                        MYC_EVIDENCE_DIAGNOSTIC,
                                        "stack: over budget / recursion "
                                        "(observasi non-blocking)");
            } else {
                myc_gate_set_status(res, MYC_GATE_STACK,
                                    MYC_GATE_COMPLETED_CLEAN,
                                    "stack dalam budget");
                myc_result_add_evidence(res, MYC_GATE_STACK,
                                        MYC_EVIDENCE_GATE_END,
                                        "stack: dalam budget");
            }
        }
    }

    /* --- Gate opsional: mutation audit (Fase 5, B5/DS-09) ---
     * Verifier mengaudit diri: mutasi pola error LLM dijalankan ulang
     * lewat pipeline; mutan lolos semua gate = coverage gap. NON-blocking
     * observasi (verdict program tidak berubah). */
    if (req->mutate_audit) {
        myc_mutate_gate(req, src, srclen, res);
    }

    /* --- Gate opsional: fuzz-lite (Fase 5, D1/DS-13) ---
     * PRNG deterministik + loop terikat pada fungsi ber-kontrak, input
     * dibatasi kontrak requires. Crash sanitizer = DRIVER_VIOLATION
     * (bukti). */
    if (req->fuzz) {
        int ok = myc_fuzz_gate(req, src, srclen, res);
        if (res->verdict == MC_TIMEOUT ||
            res->verdict == MC_DRIVER_VIOLATION) {
            if (res->verdict == MC_DRIVER_VIOLATION) {
                res->assurance = MYC_ASSURANCE_NONE;
                myc_gate_set_status(res, MYC_GATE_FUZZ,
                                    MYC_GATE_COMPLETED_FINDINGS,
                                    "fuzz crash (bukti)");
                myc_result_add_evidence(res, MYC_GATE_FUZZ,
                                        MYC_EVIDENCE_FINDING,
                                        "fuzz: crash (hard)");
            } else {
                myc_gate_set_status(res, MYC_GATE_FUZZ,
                                    MYC_GATE_INCONCLUSIVE,
                                    "fuzz timeout");
                myc_result_add_evidence(res, MYC_GATE_FUZZ,
                                        MYC_EVIDENCE_ERROR,
                                        "fuzz timeout");
            }
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (ok && res->ran_fuzz && res->fuzz_cases > 0) {
            myc_gate_set_status(res, MYC_GATE_FUZZ,
                                MYC_GATE_COMPLETED_CLEAN,
                                "fuzz bersih (loop terikat)");
            myc_result_add_evidence(res, MYC_GATE_FUZZ,
                                    MYC_EVIDENCE_GATE_END,
                                    "fuzz: bersih");
        }
    }

    /* --- Gate opsional: target matrix bare metal (Fase 5, C4) ---
     * Cross-compile dengan arm-none-eabi-gcc / riscv*-elf bila tersedia,
     * dump macro target, bandingkan dgn host: portability matrix
     * (asumsi yang berubah antar target). NON-blocking penuh: status
     * sudah di-set di myc_matrix_gate (observasi); cross-compiler absen
     * = sel di-skip + catatan host-only. */
    if (req->matrix) {
        myc_matrix_gate(req, src, srclen, res);
        if (res->err == MYC_ERR_INTERNAL) {
            myc_gate_set_status(res, MYC_GATE_MATRIX,
                                MYC_GATE_INFRA_FAILED,
                                "matrix infra failed");
            myc_result_add_evidence(res, MYC_GATE_MATRIX,
                                    MYC_EVIDENCE_ERROR,
                                    "matrix: infra failed");
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
    }

    myc_reduce_verdict(res);
    free(gcc_path);
}

/* Quorum analysis (#3): dijalankan di myc_run() setelah pipeline
 * selesai, agar selalu terpanggil terlepas dari early return
 * di dalam pipeline. */
void myc_quorum_analysis(const myc_request *req, myc_result *res)
{
    size_t qi;

    if (!req->quorum) {
        res->quorum_status = MYC_QUORUM_NOT_REQUESTED;
        return;
    }

    res->quorum_status = MYC_QUORUM_CLEAN;
    {
        char qreport[2048];
        size_t qoff = 0;
        int any_findings = 0;
        int any_incomplete = 0;
        int any_clean = 0;
        int any_result = 0;

        /* Aksen: snprintf chaining + clamp qoff agar tidak pernah
         * melewati batas buffer (misi memory-safety myc). */
#define QAPPEND(...) do {                                            \
            int _r = snprintf(qreport + qoff, sizeof(qreport) - qoff, \
                              __VA_ARGS__);                           \
            if (_r > 0)                                              \
                qoff += (size_t)_r;                                  \
            if (qoff >= sizeof(qreport))                             \
                qoff = sizeof(qreport) - 1;                          \
        } while (0)

        QAPPEND("quorum: backend comparison\n");

        for (qi = 0; qi < res->gate_count; qi++) {
            const myc_gate_result *g = &res->gates[qi];
            if (!g->requested)
                continue;
            QAPPEND("  %s: %s\n",
                    myc_gate_id_short(g->id),
                    myc_gate_status_name(g->status));
            switch (g->status) {
            case MYC_GATE_COMPLETED_FINDINGS:
                any_findings = 1;
                any_result = 1;
                break;
            case MYC_GATE_COMPLETED_CLEAN:
                any_clean = 1;
                any_result = 1;
                break;
            case MYC_GATE_COMPLETED_OBSERVATIONS:
                /* Observasi (negative-space 9.8): bukan finding
                 * terkonfirmasi, tidak memecah konsensus backend. */
                any_clean = 1;
                any_result = 1;
                break;
            case MYC_GATE_INCONCLUSIVE:
            case MYC_GATE_UNAVAILABLE:
            case MYC_GATE_INFRA_FAILED:
                any_incomplete = 1;
                any_result = 1;
                break;
            default:
                break;
            }
        }

        if (!any_result) {
            /* Tidak ada gate yang benar-benar menghasilkan status
             * (mis. lint memblokir pipeline sebelum gate apa pun berjalan).
             * Jujur: ini bukan "semua setuju clean". */
            res->quorum_status = MYC_QUORUM_INCONCLUSIVE;
            QAPPEND("inconclusive: tidak ada hasil "
                    "backend yang dapat dibandingkan\n");
        } else if (any_findings && any_clean) {
            res->quorum_status = MYC_QUORUM_CONFLICT;
            QAPPEND("conflict: backend tidak sepakat "
                    "(findings vs clean)\n");
        } else if (any_incomplete) {
            res->quorum_status = MYC_QUORUM_INCONCLUSIVE;
            QAPPEND("inconclusive: backend tidak "
                    "lengkap\n");
        } else if (any_findings) {
            /* Status CLEAN di sini bermakna "semua backend setuju"
             * (bersepakat findings), bukan "kode bersih" -- lihat
             * komentar myc_quorum_status di myc.h. */
            res->quorum_status = MYC_QUORUM_CLEAN;
            QAPPEND("all backends agree: findings\n");
        } else {
            res->quorum_status = MYC_QUORUM_CLEAN;
            QAPPEND("all backends agree: clean\n");
        }

#undef QAPPEND
        res->quorum_report = myc_result_arena_dup(res, qreport, qoff);
    }
}

/* ------------------------- repair: minimal patch untuk finding tertentu ------------------------- */

const repair_template_t REPAIR_TEMPLATES[] = {
    {
        "gcc-use-after-free",
        "Gunakan variabel sementara untuk menghindari use-after-free:\n"
        "  void *tmp = realloc(p, new_size);\n"
        "  if (!tmp) { /* handle error */ }\n"
        "  p = tmp;",
        2
    },
    {
        "gcc-free-nonheap-object",
        "Pastikan free() hanya dipanggil pada pointer dari malloc/calloc/realloc.\n"
        "Jika variabel berada di stack, jangan free().",
        2
    },
    {
        "gcc-null-dereference",
        "Tambahkan pemeriksaan NULL sebelum dereference:\n"
        "  if (p == NULL) {\n"
        "      /* handle error */\n"
        "      return -1;\n"
        "  }",
        1
    },
    {
        "gcc-array-bounds",
        "Periksa batas array sebelum akses:\n"
        "  if (index < 0 || index >= ARRAY_SIZE) {\n"
        "      /* handle error */\n"
        "      return -1;\n"
        "  }",
        1
    },
    {
        "gcc-stringop-overflow",
        "Gunakan snprintf atau periksa ukuran buffer sebelum operasi string:\n"
        "  snprintf(dst, sizeof(dst), \"%s\", src);",
        1
    }
};

const size_t REPAIR_TEMPLATES_COUNT = sizeof(REPAIR_TEMPLATES) / sizeof(REPAIR_TEMPLATES[0]);

const char *repair_find_code(const char *message)
{
    if (!message)
        return NULL;
    if (strstr(message, "used after 'realloc'") || strstr(message, "use-after-free"))
        return "gcc-use-after-free";
    if (strstr(message, "free of non-heap"))
        return "gcc-free-nonheap-object";
    if (strstr(message, "null pointer") || strstr(message, "NULL") ||
        strstr(message, "dereference of null"))
        return "gcc-null-dereference";
    if (strstr(message, "array bounds") || strstr(message, "outside array bounds"))
        return "gcc-array-bounds";
    if (strstr(message, "stringop-overflow") || strstr(message, "overflow"))
        return "gcc-stringop-overflow";
    return NULL;
}

/* Dapatkan patch untuk finding tertentu. Mengembalikan string malloc'd
 * atau NULL bila tidak ada template yang cocok. Caller harus free(). */
char *myc_repair_get_patch(const char *finding_code)
{
    size_t i;
    if (!finding_code)
        return NULL;
    for (i = 0; i < REPAIR_TEMPLATES_COUNT; i++) {
        if (strcmp(REPAIR_TEMPLATES[i].finding_code, finding_code) == 0) {
            return myc_strdup(REPAIR_TEMPLATES[i].patch_template);
        }
    }
    return NULL;
}

/* Cari patch berdasarkan diagnostic message. */
char *myc_repair_from_diagnostic(const char *message)
{
    const char *code = repair_find_code(message);
    return myc_repair_get_patch(code);
}
