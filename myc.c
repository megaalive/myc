/*
 * myc.c -- Entry point CLI myc.
 *
 * Usage:
 *   myc check <file.c>            -- periksa file
 *   myc check -                   -- baca source dari stdin
 *   myc check <file.c> --json     -- output JSON
 *   myc check <file.c> --analyze  -- jalankan gate -fanalyzer
 *   myc check <file.c> --strict   -- tier ketat (-Wconversion dll)
 *   myc check <file.c> --no-lint  -- matikan lint memory-safety
 *   myc policy                     -- tampilkan whitelist header
 *   myc probe                      -- self-test boundary argv (argv_probe)
 *   myc version                    -- tampilkan versi & gcc
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#define my_getcwd _getcwd
#else
#include <unistd.h>
#define my_getcwd getcwd
#endif

#include "myc.h"
#include "compile.h"
#include "policy.h"
#include "proc.h"
#include "report.h"

/* ------------------------------------------------------------------ */
/* Implementasi kontrak inti myc                                       */
/* ------------------------------------------------------------------ */

void myc_request_init(myc_request *req)
{
    memset(req, 0, sizeof(*req));
    req->timeout_ms = MYC_DEFAULT_TIMEOUT_MS;
}

myc_error_code myc_request_validate(const myc_request *req)
{
    if (!req)
        return MYC_ERR_INVALID_REQUEST;
    if (!req->source && !req->file_path)
        return MYC_ERR_INVALID_REQUEST;
    if (req->source && memchr(req->source, '\0', req->source_len))
        return MYC_ERR_NUL_IN_INPUT;
    if (req->source_len > MYC_MAX_CODE_BYTES)
        return MYC_ERR_INPUT_TOO_LARGE;
    return MYC_ERR_NONE;
}

void myc_result_init(myc_result *res)
{
    memset(res, 0, sizeof(*res));
    res->verdict = MC_ERROR;
    res->err = MYC_ERR_NONE;
    res->completeness = MYC_COMPLETENESS_UNKNOWN;
}

void myc_result_free(myc_result *res)
{
    size_t i;
    if (!res)
        return;
    free(res->stdout_text);
    free(res->stderr_text);
    free(res->run_stdout_text);
    free(res->run_stderr_text);
    free(res->prove_stdout_text);
    free(res->prove_stderr_text);
    free(res->filc_stdout_text);
    free(res->filc_stderr_text);
    free(res->driver_stdout_text);
    free(res->driver_stderr_text);
    free(res->resolved_gcc);
    free(res->fingerprint);
    free(res->source_sha256);
    for (i = 0; i < res->gate_count; i++)
        free(res->gates[i].output);
    for (i = 0; i < res->evidence_count; i++)
        free(res->evidence[i].message);
    res->stdout_text = NULL;
    res->stderr_text = NULL;
    res->run_stdout_text = NULL;
    res->run_stderr_text = NULL;
    res->prove_stdout_text = NULL;
    res->prove_stderr_text = NULL;
    res->filc_stdout_text = NULL;
    res->filc_stderr_text = NULL;
    res->driver_stdout_text = NULL;
    res->driver_stderr_text = NULL;
    res->resolved_gcc = NULL;
    res->fingerprint = NULL;
    res->source_sha256 = NULL;
    res->gate_count = 0;
    res->evidence_count = 0;
    res->debt_count = 0;
    res->completeness = MYC_COMPLETENESS_UNKNOWN;
}

void myc_run(const myc_request *req, myc_result *res)
{
    myc_error_code ve = myc_request_validate(req);
    if (ve != MYC_ERR_NONE) {
        res->verdict = MC_ERROR;
        res->err = ve;
        return;
    }

    /* MYC-AUDIT-007: bila caller memakai file_path tanpa source,
     * load file di sini sebelum masuk pipeline. Pipeline selalu
     * menerima source in-memory; tidak ada NULL dereference di bawah. */
    if (!req->source && req->file_path) {
        FILE  *f = fopen(req->file_path, "rb");
        long   sz;
        char  *buf;
        myc_request req2;
        if (!f) {
            res->verdict = MC_ERROR;
            res->err = MYC_ERR_INVALID_PATH;
            return;
        }
        fseek(f, 0, SEEK_END);
        sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (sz < 0 || (size_t)sz > MYC_MAX_CODE_BYTES) {
            fclose(f);
            res->verdict = MC_ERROR;
            res->err = sz < 0 ? MYC_ERR_INVALID_PATH : MYC_ERR_INPUT_TOO_LARGE;
            return;
        }
        buf = (char *)malloc((size_t)sz + 1);
        if (!buf) {
            fclose(f);
            res->verdict = MC_ERROR;
            res->err = MYC_ERR_INTERNAL;
            return;
        }
        if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
            free(buf);
            fclose(f);
            res->verdict = MC_ERROR;
            res->err = MYC_ERR_INVALID_PATH;
            return;
        }
        buf[sz] = '\0';
        fclose(f);
        req2 = *req;
        req2.source = buf;
        req2.source_len = (size_t)sz;
        myc_pipeline(&req2, res);
        free(buf);
        return;
    }

    myc_pipeline(req, res);
}

/* Direktori yang memuat myc.exe (tempat myc_buf.h diharapkan ada).
 * Mengembalikan string malloc'd atau NULL. Dipakai oleh gate checked-build
 * (D1.2) untuk menambah -I sehingga `#include "myc_buf.h"` ditemukan, dan
 * oleh MCP server (P9, mcp.exe). */
char *myc_exe_dirname(const char *argv0)
{
    char *self = _strdup(argv0);
    char *slash;
    char *fwd;
    char *last;
    char *dir;
    if (!self)
        return NULL;
    slash = strrchr(self, '\\');
    fwd = strrchr(self, '/');
    last = slash > fwd ? slash : fwd;
    if (last)
        *last = '\0';
    else {
        free(self);
        return _strdup(".");
    }
    dir = self;
    /* samakan separator ke '/' agar aman sebagai argumen gcc/clang */
    for (slash = dir; *slash; slash++)
        if (*slash == '\\')
            *slash = '/';
    return dir;
}

/* ================================================================== */
/* Bagian CLI myc (main) -- TIDAK ikut dibangun bila MYC_NO_MAIN        */
/* (dipakai mcp.exe yang punya main sendiri, P9).                      */
/* ================================================================== */
#ifndef MYC_NO_MAIN

static void usage(void)
{
    printf(
        "myc -- verifikator C aman untuk agent (structured, no shell)\n\n"
        "usage:\n"
        "  myc check <file.c> [--json] [--analyze] [--strict] [--no-lint] [--cwd DIR]\n"
        "  myc check <file.c> [--run [--run-stdin FILE]] [--prove] [--checked] [--filc] [--driver]\n"
        "  myc check -          [--json] [--analyze] [--strict] [--no-lint]\n"
        "                        (source dari stdin)\n"
        "  myc policy\n"
        "  myc probe\n"
        "  myc version\n");
}

static int read_stdin(char **out, size_t *out_len)
{
    size_t cap = 65536, len = 0;
    char  *buf = (char *)malloc(cap);
    int    ch;
    if (!buf)
        return 0;
    while ((ch = getchar()) != EOF) {
        if (len + 2 > cap) {
            size_t ncap = cap * 2;
            char  *nb = (char *)realloc(buf, ncap);
            if (!nb) {
                free(buf);
                return 0;
            }
            buf = nb;
            cap = ncap;
        }
        buf[len++] = (char)ch;
    }
    buf[len] = '\0';
    *out = buf;
    *out_len = len;
    return 1;
}

static int read_file(const char *path, char **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    long  sz;
    char *buf;
    if (!f)
        return 0;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) {
        fclose(f);
        return 0;
    }
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return 0;
    }
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return 0;
    }
    buf[sz] = '\0';
    fclose(f);
    *out = buf;
    *out_len = (size_t)sz;
    return 1;
}

/* --- probe: jalankan argv_probe yang sudah dibangun --- */
static int cmd_probe(const char *argv0)
{
    char *self = NULL;
    char *dir = NULL;
    char *probe = NULL;
    myc_proc_request preq;
    myc_proc_result pres;
    const char *argv[4];
    char       cwd[4096];
    size_t     dl;
    int        rc;

    /* cari dirname dari argv0 */
    self = _strdup(argv0);
    if (!self)
        return 2;
    {
        char *slash = strrchr(self, '\\');
        char *fwd = strrchr(self, '/');
        char *last = slash > fwd ? slash : fwd;
        if (last)
            *last = '\0';
        else
            strcpy(self, ".");
    }
    dir = self;

    dl = strlen(dir);
    probe = (char *)malloc(dl + 16);
    if (!probe) {
        free(self);
        return 2;
    }
    snprintf(probe, dl + 16, "%s\\argv_probe.exe", dir);

    argv[0] = probe;
    argv[1] = "value with spaces";
    argv[2] = "\"literal quote\"";
    argv[3] = NULL;

    if (!my_getcwd(cwd, sizeof(cwd)))
        strcpy(cwd, ".");

    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.cwd = cwd;
    preq.timeout_ms = 15000;
    preq.max_output_bytes = MYC_MAX_OUTPUT_BYTES;

    rc = myc_proc_run(&preq, &pres);
    if (!rc) {
        printf("probe: gagal menjalankan argv_probe (error=%s)\n",
               myc_error_name(pres.err));
        myc_proc_result_free(&pres);
        free(probe);
        free(self);
        return 1;
    }
    printf("probe exit=%d dur=%llums\n", pres.exit_code, pres.duration_ms);
    if (pres.stdout_data)
        printf("%s", pres.stdout_data);
    myc_proc_result_free(&pres);
    free(probe);
    free(self);
    return 0;
}

static int cmd_version(void)
{
    char *gcc = myc_find_executable("gcc");
    char *clang = myc_find_executable("clang");
    printf("myc 0.1.0\n");
    if (gcc) {
        printf("gcc: %s\n", gcc);
        free(gcc);
    } else {
        printf("gcc: TIDAK DITEMUKAN\n");
    }
    if (clang) {
        printf("clang: %s\n", clang);
        free(clang);
    } else {
        printf("clang: TIDAK DITEMUKAN (verification run --run tidak tersedia)\n");
    }
    return 0;
}

static int cmd_policy(void)
{
    size_t n = 0;
    const char *const *h = myc_policy_allowed_headers(&n);
    size_t i;
    printf("whitelist header (%llu):\n", (unsigned long long)n);
    for (i = 0; i < n; i++)
        printf("  <%s>\n", h[i]);
    return 0;
}

int main(int argc, char **argv)
{
    myc_request req;
    myc_result  res;

    if (argc < 2) {
        usage();
        return 2;
    }

    if (strcmp(argv[1], "version") == 0 || strcmp(argv[1], "--version") == 0)
        return cmd_version();
    if (strcmp(argv[1], "policy") == 0)
        return cmd_policy();
    if (strcmp(argv[1], "probe") == 0)
        return cmd_probe(argv[0]);

    if (strcmp(argv[1], "check") != 0) {
        usage();
        return 2;
    }

    if (argc < 3) {
        usage();
        return 2;
    }

    myc_request_init(&req);
    myc_result_init(&res);
    req.run_lint = 1;               /* lint memory-safety default ON */
    req.checked_header_dir = myc_exe_dirname(argv[0]);

    /* parse flags */
    {
        int i;
        for (i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--json") == 0)
                req.as_json = 1;
            else if (strcmp(argv[i], "--analyze") == 0)
                req.run_analyzer = 1;
            else if (strcmp(argv[i], "--strict") == 0)
                req.strict = 1;
            else if (strcmp(argv[i], "--level") == 0) {
                /* --level L1 | --level strict : sama-sama menyalakan tier ketat */
                req.strict = 1;
                if (i + 1 < argc && strcmp(argv[i + 1], "strict") == 0)
                    i++;
            }
            else if (strcmp(argv[i], "--no-lint") == 0)
                req.run_lint = 0;
            else if (strcmp(argv[i], "--run") == 0)
                req.run = 1;
            else if (strcmp(argv[i], "--prove") == 0)
                req.prove = 1;
            else if (strcmp(argv[i], "--checked") == 0)
                req.checked = 1;
            else if (strcmp(argv[i], "--filc") == 0)
                req.filc = 1;
            else if (strcmp(argv[i], "--driver") == 0)
                req.driver = 1;
            else if (strcmp(argv[i], "--run-stdin") == 0 && i + 1 < argc) {
                char *buf;
                size_t len;
                if (!read_file(argv[++i], &buf, &len)) {
                    fprintf(stderr, "myc: tidak dapat membaca run-stdin %s\n", argv[i]);
                    myc_result_free(&res);
                    return 1;
                }
                req.run_stdin = buf;
                req.run_stdin_len = len;
                req.run = 1;
            }
            else if (strcmp(argv[i], "--cwd") == 0 && i + 1 < argc) {
                req.cwd = argv[++i];
            }
        }
    }

    if (strcmp(argv[2], "-") == 0) {
        char *src;
        size_t len;
        if (!read_stdin(&src, &len)) {
            fprintf(stderr, "myc: gagal membaca stdin\n");
            return 1;
        }
        req.source = src;
        req.source_len = len;
        myc_run(&req, &res);
        free(src);
    } else {
        char *src;
        size_t len;
        if (!read_file(argv[2], &src, &len)) {
            fprintf(stderr, "myc: tidak dapat membaca %s\n", argv[2]);
            return 1;
        }
        req.source = src;
        req.source_len = len;
        myc_run(&req, &res);
        free(src);
    }

    if (req.as_json)
        myc_report_json(&res);
    else
        myc_report_text(&res);

    myc_result_free(&res);
    if (req.run_stdin)
        free((void *)req.run_stdin);
    return res.verdict == MC_OK ? 0 : 1;
}

#endif /* MYC_NO_MAIN */
