/*
 * compile.c -- Pipeline myc.
 *
 * Urutan (pivot memory-safety 2026-08-01: policy NON-BLOCKING):
 *   1. scan include mentah (lapis 1)  -> warning (non-blocking)
 *   2. lint memory-safety (P5, D1.3+D1.4) -> LINT_VIOLATION stop (gate hard)
 *   3. gcc -E (argv eksak, source via stdin) -> output preprocessed
 *   4. scan markers (lapis 2)         -> warning (non-blocking)
 *   5. scan calls (lapis 3)           -> warning (non-blocking)
 *   6. gcc -c -O2 (gate, tier dasar memori) -> COMPILE_ERROR
 *   7. (opsional) gcc -c -fanalyzer -o NUL
 *   8. verdict MC_OK + assurance
 *
 * Tidak pernah menyusun shell string; source tidak pernah jadi argumen.
 * Catatan ownership: req->source dimiliki caller (myc.c); file loading
 * dilakukan di myc.c, bukan di sini.
 */
#include "compile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lint.h"
#include "policy.h"
#include "proc.h"
#include "run.h"
#include "scanner.h"
#include "sha256.h"

/* ------------------------------------------------------------------ */
/* Tabel flags gcc terpusat (P4.3).                                    */
/* ------------------------------------------------------------------ */

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
 * (gcc menjalankan analisis GIMPLE hanya saat kompilasi dengan optimisasi). */
static const char *const MEMORY_GATE[] = {
    "-c", "-O2", "-o", "NUL", NULL
};

/* Flags analyzer: MEMORY_GATE + -fanalyzer. */
static const char *const ANALYZER_EXTRA[] = {
    "-c", "-O2", "-fanalyzer", "-o", "NUL", NULL
};

/* Susun satu array argv gabungan (semua pointer statis, tak perlu bebas).
 * count = jumlah argumen setelah gcc_path. */
static const char **merge_args(const char *const *lists[], size_t nlists,
                               size_t *count)
{
    size_t total = 0;
    size_t li, ai, idx = 0;
    const char **out;
    for (li = 0; li < nlists; li++)
        for (ai = 0; lists[li][ai]; ai++)
            total++;
    out = (const char **)malloc(sizeof(char *) * (total + 1));
    if (!out)
        return NULL;
    for (li = 0; li < nlists; li++)
        for (ai = 0; lists[li][ai]; ai++)
            out[idx++] = lists[li][ai];
    out[idx] = NULL;
    *count = idx;
    return out;
}

/* helper agar add_diag bisa menerima pesan dinamis dari stderr gcc.
 * Pesan disalin ke slot statis bergilir (cukup untuk laporan). */
static void add_diag_copy(myc_result *res, int line, int col, const char *msg)
{
    if (res->diag_count >= MYC_MAX_DIAGNOSTICS)
        return;
    {
        static char pool[MYC_MAX_DIAGNOSTICS][256];
        static int  idx = 0;
        char       *slot = pool[idx];
        size_t      n;
        idx = (idx + 1) % MYC_MAX_DIAGNOSTICS;
        n = strlen(msg);
        if (n > 255)
            n = 255;
        memcpy(slot, msg, n);
        slot[n] = '\0';
        res->diags[res->diag_count].line = line;
        res->diags[res->diag_count].col = col;
        res->diags[res->diag_count].message = slot;
        res->diag_count++;
    }
}

/* Tambah diagnostic dari stderr gcc (parsing baris sederhana).
 * Hanya baris yang memuat "<stdin>:<line>:<col>:" yang diambil sebagai
 * diagnostic; baris lanjutan gcc ("cc1.exe:...", "  'main': events",
 * "<stdin>: In function") dilewati agar laporan tidak bising. */
static void ingest_gcc_diagnostics(myc_result *res, const char *text)
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

    src = req->source;
    srclen = req->source_len;

    /* hash source */
    sha256_hex(src, srclen, hex);
    res->source_sha256 = _strdup(hex);

    /* cari gcc */
    gcc_path = myc_find_executable(req->gcc_program ? req->gcc_program : "gcc");
    if (!gcc_path) {
        res->err = MYC_ERR_GCC_NOT_FOUND;
        res->verdict = MC_ERROR;
        return;
    }
    res->resolved_gcc = _strdup(gcc_path);

    /* fingerprint kanonik */
    {
        char policy_hex[65];
        char buf[512];
        int  n;
        myc_policy_hash(policy_hex);
        n = snprintf(buf, sizeof(buf),
                     "v3|gcc:%s|cwd:%s|pol:%s|flags:c11;Wall;Werror;pedantic;mem;%s;%s|src:%s",
                     gcc_path,
                     req->cwd ? req->cwd : "",
                     policy_hex,
                     req->strict ? "strict" : "default",
                     req->run ? "run" : "norun",
                     res->source_sha256 ? res->source_sha256 : "");
        sha256_hex(buf, (size_t)n, hex);
        res->fingerprint = _strdup(hex);
    }

    /* --- Lapis 1: include mentah (warning, non-blocking) --- */
    myc_scan_include_raw(src, srclen, res);

    /* --- Lint memory-safety (P5; default aktif, mati via --no-lint) --- */
    if (req->run_lint) {
        if (!myc_lint_source(src, srclen, res)) {
            res->verdict = MC_VIOLATION;
            res->err = MYC_ERR_LINT_VIOLATION;
            res->exit_code = 1;
            free(gcc_path);
            return;
        }
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
        return;
    }
    res->ran_preprocess = 1;
    adopt_proc(res, &pr);
    myc_proc_result_free(&pr);

    if (res->exit_code != 0) {
        /* preprocess gagal (mis. makro rusak) */
        res->verdict = MC_COMPILE_ERROR;
        res->err = MYC_ERR_PREPROCESS_ERROR;
        if (res->stderr_text)
            ingest_gcc_diagnostics(res, res->stderr_text);
        free(gcc_path);
        return;
    }

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

    /* --- Gate: kompilasi + tier dasar memori (perlu -O2 utk memori) --- */
    {
        const char *const *lists[4];
        const char **args;
        size_t      nargs;
        lists[0] = MEMORY_GATE;
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
    }
    if (pr.timed_out) {
        res->verdict = MC_TIMEOUT;
        res->err = MYC_ERR_TIMEOUT;
        myc_proc_result_free(&pr);
        free(gcc_path);
        return;
    }
    res->ran_compile = 1;
    adopt_proc(res, &pr);
    myc_proc_result_free(&pr);

    if (res->exit_code != 0) {
        res->verdict = MC_COMPILE_ERROR;
        res->err = MYC_ERR_COMPILE_ERROR;
        if (res->stderr_text)
            ingest_gcc_diagnostics(res, res->stderr_text);
        free(gcc_path);
        return;
    }

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
            return;
        }
        res->ran_analyzer = 1;
        if (pr.exit_code != 0) {
            res->verdict = MC_COMPILE_ERROR;
            res->err = MYC_ERR_COMPILE_ERROR;
            adopt_proc(res, &pr);
            if (res->stderr_text)
                ingest_gcc_diagnostics(res, res->stderr_text);
            myc_proc_result_free(&pr);
            free(gcc_path);
            return;
        }
        myc_proc_result_free(&pr);
    }

    /* --- Gate opsional: verification run (P6, --run) -> L3 RUNTIME --- */
    if (req->run) {
        int ok = myc_run_gate(req, src, srclen, res);
        if (res->verdict == MC_TIMEOUT || res->verdict == MC_RUNTIME_VIOLATION ||
            res->err == MYC_ERR_EXECUTE_FAILED || res->err == MYC_ERR_INTERNAL) {
            free(gcc_path);
            return;
        }
        if (ok && res->ran_runtime && !res->run_timed_out) {
            res->verdict = MC_OK;
            res->err = MYC_ERR_NONE;
            res->assurance = MYC_ASSURANCE_L3_RUNTIME;
            free(gcc_path);
            return;
        }
        /* gate di-skip (build gagal / clang hilang): pertahankan level statis */
        res->verdict = MC_OK;
        res->err = MYC_ERR_NONE;
        res->assurance = MYC_ASSURANCE_L1_SANE;
        free(gcc_path);
        return;
    }

    res->verdict = MC_OK;
    res->err = MYC_ERR_NONE;
    res->exit_code = 0;
    res->assurance = MYC_ASSURANCE_L1_SANE;

    free(gcc_path);
}
