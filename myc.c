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
#include <stdint.h>
#include <limits.h>
#include <errno.h>

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
#include "sha256.h"

/* ------------------------------------------------------------------ */
/* Implementasi kontrak inti myc                                       */
/* ------------------------------------------------------------------ */

/* Arena bump milik hasil (Fase 5, MYC-AUDIT-008). */
struct myc_arena {
    struct myc_arena *next;   /* blok berikutnya (list) */
    char   *cur;              /* posisi alokasi berikutnya */
    char   *end;              /* ujung blok */
    char    data[];           /* payload */
};

/* Alokasi blok arena dengan payload eksplisit (MYC-AUDIT-018): payload
 * bisa melebihi MYC_ARENA_BLOCK (string raksasa) atau lebih kecil (blok
 * kecil). Overflow dicek di pemanggil. */
static struct myc_arena *arena_alloc(size_t payload)
{
    struct myc_arena *a = (struct myc_arena *)malloc(
        sizeof(struct myc_arena) + payload);
    if (!a)
        return NULL;
    a->next = NULL;
    a->cur = a->data;
    a->end = a->data + payload;
    return a;
}

void myc_result_init(myc_result *res)
{
    memset(res, 0, sizeof(*res));
    res->verdict = MC_ERROR;
    res->err = MYC_ERR_NONE;
    res->completeness = MYC_COMPLETENESS_UNKNOWN;
}

char *myc_result_arena_dup(myc_result *res, const char *s, size_t string_len)
{
    struct myc_arena *a = res->arena;
    size_t n = string_len ? string_len : strlen(s);
    size_t payload;

    /* MYC-AUDIT-018: string_len adalah parameter eksternal — pastikan
     * n+1 tidak wrap ke 0 (n == SIZE_MAX → memcpy OOB raksasa di blok
     * kecil). Bila n raksasa, arena mencanangkan blok eksak; bila alokasi
     * gagal (OOM) → NULL, tidak pernah menulis sebagian. */
    if (n == SIZE_MAX)
        return NULL;
    payload = n + 1;
    if (!a || (size_t)(a->end - a->cur) < payload) {
        size_t block = payload > MYC_ARENA_BLOCK ? payload : MYC_ARENA_BLOCK;
        struct myc_arena *na;
        /* guard kedua (test oom_guards menangkap): sizeof(arena) + block
         * sendiri bisa overflow (mis. payload = SIZE_MAX-8) dan wrap ke
         * ukuran kecil -> malloc sukses lalu memcpy OOB. */
        if (block > SIZE_MAX - sizeof(struct myc_arena))
            return NULL;
        na = arena_alloc(block);
        if (!na)
            return NULL;
        na->next = a;
        res->arena = a = na;
    }
    {
        char *slot = a->cur;
        memcpy(slot, s, n);
        slot[n] = '\0';
        a->cur += payload;
        return slot;
    }
}

void myc_request_init(myc_request *req)
{
    memset(req, 0, sizeof(*req));
    req->timeout_ms = MYC_DEFAULT_TIMEOUT_MS;
}

myc_error_code myc_request_validate(const myc_request *req)
{
    size_t nul_pos;
    size_t nul_count;
    size_t i;

    if (!req)
        return MYC_ERR_INVALID_REQUEST;
    if (!req->source && !req->file_path)
        return MYC_ERR_INVALID_REQUEST;
    if (req->source && req->source_len > 0) {
        nul_count = 0;
        nul_pos = SIZE_MAX;
        for (i = 0; i < req->source_len; i++) {
            if (req->source[i] == '\0') {
                nul_count++;
                if (i < nul_pos)
                    nul_pos = i;
            }
        }
        if (nul_count > 0)
            return MYC_ERR_NUL_IN_INPUT;
    }
    if (req->source_len > MYC_MAX_CODE_BYTES)
        return MYC_ERR_INPUT_TOO_LARGE;
    if (req->timeout_ms < 0 || (int)req->timeout_ms > MYC_MAX_TIMEOUT_MS)
        return MYC_ERR_INVALID_TIMEOUT;
    /* MYC-AUDIT-020: nilai NEGATIF juga ditolak -- tanpa ini, -N yang
     * dikonversi ke size_t di proc.c menjadi raksasa (alokasi drain buffer
     * OOM saat --run). Rentang sah: 0 (default 1 MiB) s.d. 100 MiB. */
    if (req->max_output_bytes < 0 ||
        req->max_output_bytes > (int)MYC_MAX_OUTPUT_CAP_BYTES)
        return MYC_ERR_INVALID_OUTPUT_CAP;
    if (req->cwd && req->cwd[0] == '\0')
        return MYC_ERR_INVALID_CWD;
    return MYC_ERR_NONE;
}

void myc_result_free(myc_result *res)
{
    size_t i;
    struct myc_arena *a;
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
    free(res->filc_version);
    free(res->driver_stdout_text);
    free(res->driver_stderr_text);
    free(res->resolved_gcc);
    free(res->gcc_version);
    free(res->clang_version);
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
    res->filc_version = NULL;
    res->driver_stdout_text = NULL;
    res->driver_stderr_text = NULL;
    res->resolved_gcc = NULL;
    res->gcc_version = NULL;
    res->clang_version = NULL;
    res->fingerprint = NULL;
    res->source_sha256 = NULL;
    res->gate_count = 0;
    res->evidence_count = 0;
    res->debt_count = 0;
    res->completeness = MYC_COMPLETENESS_UNKNOWN;
    /* bebaskan arena utuh (Fase 5) */
    a = res->arena;
    while (a) {
        struct myc_arena *nxt = a->next;
        free(a);
        a = nxt;
    }
    res->arena = NULL;
    /* bebaskan capsule (#2) */
    if (res->capsule) {
        free(res->capsule->source_sha256);
        free(res->capsule->stdin_sha256);
        free(res->capsule->clang_path);
        free(res->capsule->gcc_path);
        free(res->capsule->cwd);
        free(res->capsule);
        res->capsule = NULL;
    }
    /* quorum_report (#3) TIDAK di-free di sini: ia dialokasikan dari
     * arena milik hasil (myc_result_arena_dup) dan ikut dibebaskan utuh
     * oleh arena di atas. free() individual = invalid free (bug #3). */
    res->quorum_report = NULL;
    res->quorum_status = MYC_QUORUM_NOT_REQUESTED;
}

/* ================================================================== */
/* Counterexample Replay Capsule (#2)                             */
/* ================================================================== */
/*
 * Bangun capsule yang berisi semua informasi untuk mereplay
 * satu verifikasi run: source identity, stdin identity, backend,
 * flags, dan hasil eksekusi. Dibebaskan oleh myc_result_free().
 */
static myc_replay_capsule *myc_build_capsule(const myc_request *req,
                                             const myc_result *res)
{
    myc_replay_capsule *cap;
    size_t i;

    cap = (myc_replay_capsule *)calloc(1, sizeof(*cap));
    if (!cap)
        return NULL;

    /* Source identity */
    if (res->source_sha256) {
        cap->source_sha256 = myc_strdup(res->source_sha256);
        if (!cap->source_sha256) goto fail;
    }

    /* Stdin identity: hash dari data yang diberikan ke program
     * verification via --run-stdin. NULL bila tidak ada stdin. */
    if (req->run_stdin && req->run_stdin_len > 0) {
        char hex[65];
        sha256_hex(req->run_stdin, req->run_stdin_len, hex);
        cap->stdin_sha256 = myc_strdup(hex);
        if (!cap->stdin_sha256) goto fail;
        cap->stdin_len = req->run_stdin_len;
    }

    /* Backend identity */
    if (req->clang_program) {
        cap->clang_path = myc_strdup(req->clang_program);
        if (!cap->clang_path) goto fail;
    }
    if (req->gcc_program) {
        cap->gcc_path = myc_strdup(req->gcc_program);
        if (!cap->gcc_path) goto fail;
    }
    if (req->cwd) {
        cap->cwd = myc_strdup(req->cwd);
        if (!cap->cwd) goto fail;
    }

    /* Request parameters */
    cap->timeout_ms = req->timeout_ms;
    cap->max_output_bytes = req->max_output_bytes;
    cap->strict = req->strict;
    cap->run_analyzer = req->run_analyzer;
    cap->run = req->run;
    cap->prove = req->prove;
    cap->checked = req->checked;
    cap->filc = req->filc;
    cap->driver = req->driver;
    cap->metamorphic = req->metamorphic;
    cap->negative = req->negative;
    cap->require_complete = req->require_complete;

    /* Execution result */
    cap->verdict = res->verdict;
    cap->exit_code = res->exit_code;
    cap->timed_out = res->run_timed_out;
    cap->sanitizer_detected = res->run_sanitizer_detected;
    cap->metamorphic_inconsistent = res->metamorphic_inconsistent;
    cap->meta_o0_exit = res->meta_o0_exit;
    cap->meta_o2_exit = res->meta_o2_exit;
    cap->meta_o0_finding = res->meta_o0_finding;
    cap->meta_o2_finding = res->meta_o2_finding;
    cap->negative_callsites = res->negative_callsites;
    cap->negative_deviations = res->negative_deviations;
    if (res->run_sanitizer_detected) {
        size_t slen = strlen(res->run_sanitizer_marker);
        if (slen >= sizeof(cap->sanitizer_marker))
            slen = sizeof(cap->sanitizer_marker) - 1;
        memcpy(cap->sanitizer_marker, res->run_sanitizer_marker, slen);
        cap->sanitizer_marker[slen] = '\0';
    } else {
        cap->sanitizer_marker[0] = '\0';
    }

    /* Gate summary: salin status setiap gate yang diminta. */
    for (i = 0; i < res->gate_count; i++) {
        const myc_gate_result *g = &res->gates[i];
        if (g->id < MYC_GATE_COUNT)
            cap->gate_status[g->id] = g->status;
    }

    /* Finding / completeness / claim */
    cap->finding = res->finding;
    cap->completeness = res->completeness;
    cap->claim_status = res->claim_status;
    cap->quorum_status = res->quorum_status;

    return cap;

fail:
    free(cap->source_sha256);
    free(cap->stdin_sha256);
    free(cap->clang_path);
    free(cap->gcc_path);
    free(cap->cwd);
    free(cap);
    return NULL;
}

/* 9.10 Silence Is a Finding: enforcement --require-complete.
 * Verification gap (unverified_debt) menjadikan hasil GAGAL di CI
 * (verdict INCONCLUSIVE + exit 1), bukan kesunyian. Hanya menaikkan
 * MC_OK -> INCONCLUSIVE; finding/completeness diselaraskan. Real
 * finding (VIOLATION) atau error tetap dipertahankan (sudah gagal). */
static void enforce_require_complete(const myc_request *req, myc_result *res)
{
    if (!req->require_complete)
        return;
    if (res->debt_count == 0 || res->verdict != MC_OK)
        return;
    res->verdict = MC_INCONCLUSIVE;
    if (res->finding == MYC_FINDING_CLEAN)
        res->finding = MYC_FINDING_INCONCLUSIVE;
    if (res->completeness == MYC_COMPLETENESS_COMPLETE)
        res->completeness = MYC_COMPLETENESS_INCOMPLETE;
    /* Receipt di-hash di dalam myc_reduce_verdict (akhir pipeline),
     * SEBELUM flip ini. Bangun ulang agar sidik jari sesuai dengan
     * hasil akhir (9.10) -- TANPA menjalankan reducer lagi. */
    myc_rebuild_receipt(res);
}

void myc_run(const myc_request *req, myc_result *res)
{
    myc_error_code ve = myc_request_validate(req);
    if (ve != MYC_ERR_NONE) {
        res->verdict = MC_ERROR;
        res->err = ve;
        if (ve == MYC_ERR_NUL_IN_INPUT && req->source && req->source_len > 0) {
            size_t nul_pos = SIZE_MAX;
            size_t nul_count = 0;
            size_t i;
            for (i = 0; i < req->source_len; i++) {
                if (req->source[i] == '\0') {
                    nul_count++;
                    if (i < nul_pos)
                        nul_pos = i;
                }
            }
            if (nul_pos != SIZE_MAX && res->diag_count < MYC_MAX_DIAGNOSTICS) {
                char note[192];
                snprintf(note, sizeof(note),
                         "embedded NUL ditemukan pada posisi %zu (total %zu byte NUL)",
                         nul_pos, nul_count);
                res->diags[res->diag_count].line = 0;
                res->diags[res->diag_count].col = 0;
                res->diags[res->diag_count].message = myc_result_arena_dup(res, note, 0);
                res->diags[res->diag_count].confidence = MYC_CONF_OBSERVATION;
                res->diag_count++;
            }
        }
        if (ve == MYC_ERR_INVALID_TIMEOUT && res->diag_count < MYC_MAX_DIAGNOSTICS) {
            const char *msg = "timeout_ms di luar rentang valid (0-600000)";
            res->diags[res->diag_count].line = 0;
            res->diags[res->diag_count].col = 0;
            res->diags[res->diag_count].message = myc_result_arena_dup(res, msg, 0);
            res->diags[res->diag_count].confidence = MYC_CONF_CONFIRMED;
            res->diag_count++;
        }
        if (ve == MYC_ERR_INVALID_OUTPUT_CAP && res->diag_count < MYC_MAX_DIAGNOSTICS) {
            const char *msg = "max_output_bytes di luar rentang valid (0-104857600)";
            res->diags[res->diag_count].line = 0;
            res->diags[res->diag_count].col = 0;
            res->diags[res->diag_count].message = myc_result_arena_dup(res, msg, 0);
            res->diags[res->diag_count].confidence = MYC_CONF_CONFIRMED;
            res->diag_count++;
        }
        if (ve == MYC_ERR_INVALID_CWD && res->diag_count < MYC_MAX_DIAGNOSTICS) {
            const char *msg = "cwd tidak boleh kosong";
            res->diags[res->diag_count].line = 0;
            res->diags[res->diag_count].col = 0;
            res->diags[res->diag_count].message = myc_result_arena_dup(res, msg, 0);
            res->diags[res->diag_count].confidence = MYC_CONF_CONFIRMED;
            res->diag_count++;
        }
        return;
    }
    res->require_complete = req->require_complete;

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
        /* #3: quorum juga dihitung di jalur file_path-only (API/MCP),
         * konsisten dengan jalur source in-memory. */
        myc_quorum_analysis(&req2, res);
        enforce_require_complete(&req2, res);
        free(buf);
        res->capsule = myc_build_capsule(&req2, res);
        return;
    }

    myc_pipeline(req, res);
    myc_quorum_analysis(req, res);
    enforce_require_complete(req, res);
    res->capsule = myc_build_capsule(req, res);
}

/* Direktori yang memuat myc.exe (tempat myc_buf.h diharapkan ada).
 * Mengembalikan string malloc'd atau NULL. Dipakai oleh gate checked-build
 * (D1.2) untuk menambah -I sehingga `#include "myc_buf.h"` ditemukan, dan
 * oleh MCP server (P9, mcp.exe). */
char *myc_exe_dirname(const char *argv0)
{
    char *self = myc_strdup(argv0);
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
        return myc_strdup(".");
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
        "  myc check <file.c> [--run [--run-stdin FILE]] [--prove] [--checked] [--filc] [--driver] [--metamorphic] [--negative] [--quorum] [--require-complete]\n"
        "  myc check <file.c> [--timeout MS] [--output-cap BYTES]\n"
        "                        (timeout 0-600000 ms, 0 = default 30000; output-cap 0-104857600 byte, 0 = default 1 MiB)\n"
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

/* Parse bilangan bulat ketat (MYC-AUDIT-020): seluruh string harus angka
 * (tanda opsional), tanpa trailing garbage, tanpa overflow. Mengembalikan
 * 1 sukses, 0 gagal. Fail-fast konsisten dengan ingress Fase-2/AUDIT-019:
 * "abc" tidak boleh diam-diam menjadi 0 (default) seperti atoi lama. */
static int parse_int_arg(const char *s, int *out)
{
    char *end;
    long  v;
    if (!s || !*s)
        return 0;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno == ERANGE)
        return 0;                   /* overflow long (strtol set ERANGE) */
    if (end == s || *end != '\0')
        return 0;                   /* bukan angka / ada sisa karakter */
    if (v < INT_MIN || v > INT_MAX)
        return 0;                   /* overflow int */
    *out = (int)v;
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
    self = myc_strdup(argv0);
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
    /* MYC-AUDIT-022 (roadmap 7.1): `myc version` kini memberi EXACT tool
     * identity — versi persis backend (baris pertama `<exe> --version`),
     * bukan hanya path. Roadmap lama: "version belum memberi exact
     * toolchain identity" (docs/myc-serious-review-and-roadmap.md). */
    char *gcc = myc_find_executable("gcc");
    char *clang = myc_find_executable("clang");
    char *gv, *cv;
    printf("myc 0.1.0\n");
    if (gcc) {
        printf("gcc: %s\n", gcc);
        gv = myc_tool_version(gcc);
        printf("gcc version: %s\n", gv ? gv : "(tidak terbaca)");
        free(gv);
        free(gcc);
    } else {
        printf("gcc: TIDAK DITEMUKAN\n");
    }
    if (clang) {
        printf("clang: %s\n", clang);
        cv = myc_tool_version(clang);
        printf("clang version: %s\n", cv ? cv : "(tidak terbaca)");
        free(cv);
        free(clang);
    } else {
        printf("clang: TIDAK DITEMUKAN (verification run --run tidak tersedia)\n");
    }
    /* MYC-AUDIT-024 (roadmap 7.7): exact tool identity untuk Fil-C.
     * filc-clang hanya Linux; di Windows akan TIDAK DITEMUKAN (jujur,
     * bukan salah). */
    {
        char *filc = myc_find_executable("filc-clang");
        char *fv;
        if (filc) {
            printf("filc: %s\n", filc);
            fv = myc_tool_version(filc);
            printf("filc version: %s\n", fv ? fv : "(tidak terbaca)");
            free(fv);
            free(filc);
        } else {
            printf("filc: TIDAK DITEMUKAN (Fil-C hanya Linux; instal "
                   "filc-clang di PATH atau WSL)\n");
        }
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

    /* Parse flags. Fase-2 (canonical ingress): unknown flag = error
     * (fail-fast), konsisten dengan reject unknown flag pada MCP server
     * (AUDIT-016: -32602). CLI tidak lagi diam-diam mengabaikan flag yang
     * tidak dikenal -- menyembunyikannya membuat hasil tampak OK padahal
     * permintaan bisa salah ketik (mis. --rnu). */
    {
        int i;
        for (i = 3; i < argc; i++) {
            int known = 0;
            if (strcmp(argv[i], "--json") == 0) {
                req.as_json = 1; known = 1;
            } else if (strcmp(argv[i], "--analyze") == 0) {
                req.run_analyzer = 1; known = 1;
            } else if (strcmp(argv[i], "--strict") == 0) {
                req.strict = 1; known = 1;
            } else if (strcmp(argv[i], "--level") == 0) {
                /* --level L1 | --level strict : sama-sama menyalakan tier ketat */
                req.strict = 1; known = 1;
                if (i + 1 < argc && strcmp(argv[i + 1], "strict") == 0)
                    i++;
            } else if (strcmp(argv[i], "--no-lint") == 0) {
                req.run_lint = 0; known = 1;
            } else if (strcmp(argv[i], "--run") == 0) {
                req.run = 1; known = 1;
            } else if (strcmp(argv[i], "--prove") == 0) {
                req.prove = 1; known = 1;
            } else if (strcmp(argv[i], "--checked") == 0) {
                req.checked = 1; known = 1;
            } else if (strcmp(argv[i], "--filc") == 0) {
                req.filc = 1; known = 1;
            } else if (strcmp(argv[i], "--driver") == 0) {
                req.driver = 1; known = 1;
            } else if (strcmp(argv[i], "--quorum") == 0) {
                req.quorum = 1; known = 1;
            } else if (strcmp(argv[i], "--metamorphic") == 0) {
                req.metamorphic = 1; known = 1;
            } else if (strcmp(argv[i], "--negative") == 0) {
                req.negative = 1; known = 1;
            } else if (strcmp(argv[i], "--require-complete") == 0) {
                req.require_complete = 1; known = 1;
            } else if (strcmp(argv[i], "--run-stdin") == 0) {
                char *buf;
                size_t len;
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --run-stdin membutuhkan argumen FILE\n");
                    myc_result_free(&res);
                    return 2;
                }
                if (!read_file(argv[i + 1], &buf, &len)) {
                    fprintf(stderr, "myc: tidak dapat membaca run-stdin %s\n", argv[i + 1]);
                    myc_result_free(&res);
                    return 1;
                }
                req.run_stdin = buf;
                req.run_stdin_len = len;
                req.run = 1;
                i++;  /* konsumsi argumen nilai */
                known = 1;
            } else if (strcmp(argv[i], "--cwd") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --cwd membutuhkan argumen DIR\n");
                    myc_result_free(&res);
                    return 2;
                }
                req.cwd = argv[i + 1];
                i++;  /* konsumsi argumen nilai */
                known = 1;
            } else if (strcmp(argv[i], "--timeout") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --timeout membutuhkan argumen MILIS\n");
                    myc_result_free(&res);
                    return 2;
                }
                /* MYC-AUDIT-020: fail-fast angka (konsisten AUDIT-019).
                 * atoi lama diam-diam mengubah "abc" menjadi 0 (default)
                 * dan overflow tidak terdeteksi. */
                if (!parse_int_arg(argv[i + 1], &req.timeout_ms)) {
                    fprintf(stderr, "myc: --timeout: nilai bukan angka valid: %s\n",
                            argv[i + 1]);
                    myc_result_free(&res);
                    return 2;
                }
                i++;  /* konsumsi argumen nilai */
                known = 1;
            } else if (strcmp(argv[i], "--output-cap") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --output-cap membutuhkan argumen BYTES\n");
                    myc_result_free(&res);
                    return 2;
                }
                if (!parse_int_arg(argv[i + 1], &req.max_output_bytes)) {
                    fprintf(stderr, "myc: --output-cap: nilai bukan angka valid: %s\n",
                            argv[i + 1]);
                    myc_result_free(&res);
                    return 2;
                }
                i++;  /* konsumsi argumen nilai */
                known = 1;
            }
            if (!known) {
                /* fail-fast: tolak flag tidak dikenal (Fase-2 / AUDIT-016). */
                fprintf(stderr, "myc: unknown option: %s\n", argv[i]);
                myc_result_free(&res);
                return 2;
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
