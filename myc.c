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
 *   myc check <file.c> --write-repro -- tulis .myc-witness/ repro dir
 *   myc check <file.c> --tx-verify <patch.c --finding-id ID --edit-region R>
 *                          -- verifikasi patch dalam transaksi (Fase 2)
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
#include "witness.h"
#include "ledger.h"
#include "cache.h"
#include "transaction.h"
#include "sha256.h"
#include "agent.h"
#include "context.h"
#include "budget.h"
#include "assume.h"
#include "taxonomy.h"

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

void myc_witness_init(myc_witness *w)
{
    memset(w, 0, sizeof(*w));
}

void myc_witness_free(myc_witness *w)
{
    if (!w) return;
    /* SELURUH string witness dialokasikan dari ARENA milik hasil
     * (myc_result_arena_dup di compile.c/run.c/prove.c/filc.c/driver.c) --
     * arena bump dibebaskan UTUH oleh myc_result_free. free() individual
     * di sini = invalid free (bug c0000374 ditemukan saat Fase 3).
     * Struct witness sendiri di-malloc terpisah dan di-free oleh
     * myc_result_free setelah fungsi ini. */
    memset(w, 0, sizeof(*w));
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
    /* MYC-AUDIT-029: ingress canonical via myc_source_input. Validasi
     * struktur input (NUL/cap di-load oleh myc_source_load, bukan di sini,
     * agar jalur FILE juga mendapat policy yang sama). */
    switch (req->input.kind) {
    case MYC_SOURCE_MEMORY:
        if (!req->input.data)
            return MYC_ERR_INVALID_REQUEST;
        break;
    case MYC_SOURCE_FILE:
        if (!req->input.file_path || req->input.file_path[0] == '\0')
            return MYC_ERR_INVALID_REQUEST;
        break;
    case MYC_SOURCE_STDIN:
        break;
    default:
        return MYC_ERR_INVALID_REQUEST;
    }
    if (req->input.kind == MYC_SOURCE_MEMORY) {
        nul_count = 0;
        nul_pos = SIZE_MAX;
        for (i = 0; i < req->input.len; i++) {
            if (req->input.data[i] == '\0') {
                nul_count++;
                if (i < nul_pos)
                    nul_pos = i;
            }
        }
        if (nul_count > 0)
            return MYC_ERR_NUL_IN_INPUT;
        if (req->input.len > MYC_MAX_CODE_BYTES)
            return MYC_ERR_INPUT_TOO_LARGE;
    }
    /* MYC-AUDIT-028 (Fase 2): cap run_stdin -- CLI fail-fast + API/MCP
     * divalidasi di ingress, bukan setelah buffer raksasa dialokasikan. */
    if (req->run_stdin && req->run_stdin_len > MYC_MAX_STDIN_BYTES)
        return MYC_ERR_STDIN_TOO_LARGE;
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

/* Baca stdin dengan cap (Fase 2): berhenti segera saat cap terlampaui,
 * JANGAN membaca penuh dulu baru menolak -- file raksasa tidak boleh
 * dialokasikan seluruhnya. Return: 1 sukses, 0 gagal, 2 terlalu besar. */
static int read_stdin_capped(size_t cap, char **out, size_t *out_len)
{
    size_t bufcap = 65536, len = 0;
    char  *buf;
    int    ch;
    if (bufcap > cap)
        bufcap = cap < 1 ? 1 : cap;
    buf = (char *)malloc(bufcap);
    if (!buf)
        return 0;
    while ((ch = getchar()) != EOF) {
        if (len + 2 > cap)
            goto too_large;
        if (len + 2 > bufcap) {
            size_t ncap = bufcap * 2;
            char  *nb;
            if (ncap > cap)
                ncap = cap;
            nb = (char *)realloc(buf, ncap);
            if (!nb) {
                free(buf);
                return 0;
            }
            buf = nb;
            bufcap = ncap;
        }
        buf[len++] = (char)ch;
    }
    buf[len] = '\0';
    *out = buf;
    *out_len = len;
    return 1;
too_large:
    free(buf);
    return 2;
}

/* Baca file dengan cap (Fase 2): baca bertahap, tolak segera saat cap
 * terlampaui (bukan malloc penuh dulu). Return: 1 sukses, 0 gagal,
 * 2 terlalu besar. */
static int read_file_capped(const char *path, size_t cap, char **out,
                            size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    size_t bufcap = 65536;
    size_t len = 0;
    char  *buf;
    if (!f)
        return 0;
    if (bufcap > cap)
        bufcap = cap < 1 ? 1 : cap;
    buf = (char *)malloc(bufcap);
    if (!buf) {
        fclose(f);
        return 0;
    }
    for (;;) {
        size_t chunk = bufcap - len;
        size_t got;
        if (chunk == 0) {
            if (len + 1 > cap)
                goto too_large;
            {
                size_t ncap = bufcap * 2;
                char  *nb;
                if (ncap > cap)
                    ncap = cap;
                nb = (char *)realloc(buf, ncap);
                if (!nb) {
                    free(buf);
                    fclose(f);
                    return 0;
                }
                buf = nb;
                bufcap = ncap;
                chunk = bufcap - len;
            }
        }
        got = fread(buf + len, 1, chunk, f);
        len += got;
        if (got < chunk) {
            if (ferror(f)) {
                free(buf);
                fclose(f);
                return 0;
            }
            break; /* EOF */
        }
        if (len + 1 > cap)
            goto too_large;
    }
    buf[len] = '\0';
    fclose(f);
    *out = buf;
    *out_len = len;
    return 1;
too_large:
    free(buf);
    fclose(f);
    return 2;
}

/* MYC-AUDIT-029 (Fase 2): muat input canonical ke memory dengan cap + NUL
 * policy + error typed. MEMORY = pointer asli tanpa alokasi; FILE = baca
 * ber-cap (read_file_capped); STDIN = baca ber-cap (read_stdin_capped).
 * Untuk FILE/STDIN caller harus free(*out) bila return NONE. */
myc_error_code myc_source_load(const myc_source_input *in,
                               const char **out, size_t *out_len,
                               int *needs_free)
{
    size_t nul_count, nul_pos, i;
    if (!in || !out || !out_len || !needs_free)
        return MYC_ERR_INVALID_REQUEST;
    switch (in->kind) {
    case MYC_SOURCE_MEMORY:
        if (!in->data)
            return MYC_ERR_INVALID_REQUEST;
        nul_count = 0;
        nul_pos = SIZE_MAX;
        for (i = 0; i < in->len; i++) {
            if (in->data[i] == '\0') {
                nul_count++;
                if (i < nul_pos)
                    nul_pos = i;
            }
        }
        if (nul_count > 0)
            return MYC_ERR_NUL_IN_INPUT;
        if (in->len > MYC_MAX_CODE_BYTES)
            return MYC_ERR_INPUT_TOO_LARGE;
        *out = in->data;
        *out_len = in->len;
        *needs_free = 0;
        return MYC_ERR_NONE;
    case MYC_SOURCE_FILE: {
        char  *buf;
        size_t len;
        int    rr;
        if (!in->file_path || in->file_path[0] == '\0')
            return MYC_ERR_INVALID_REQUEST;
        rr = read_file_capped(in->file_path, MYC_MAX_CODE_BYTES, &buf, &len);
        if (rr == 2)
            return MYC_ERR_INPUT_TOO_LARGE;
        if (rr == 0)
            return MYC_ERR_INVALID_PATH;
        *out = buf;
        *out_len = len;
        *needs_free = 1;
        return MYC_ERR_NONE;
    }
    case MYC_SOURCE_STDIN: {
        char  *buf;
        size_t len;
        int    rr = read_stdin_capped(MYC_MAX_CODE_BYTES, &buf, &len);
        if (rr == 2)
            return MYC_ERR_INPUT_TOO_LARGE;
        if (rr == 0)
            return MYC_ERR_INTERNAL;
        *out = buf;
        *out_len = len;
        *needs_free = 1;
        return MYC_ERR_NONE;
    }
    default:
        return MYC_ERR_INVALID_REQUEST;
    }
}

/* MYC-AUDIT-030 (Fase 2): canonicalize path lexical -- absolutize bila
 * relatif (terhadap cwd proses), samakan separator (Windows -> '/'),
 * resolve "." dan ".." TANPA menyentuh filesystem (cwd boleh belum ada,
 * mis. request fingerprint panjang). Return malloc'd string atau NULL
 * (getcwd gagal / OOM) -- non-blocking: caller memakai nilai asli. */
static char *myc_absolutize(const char *path)
{
    size_t plen, blen, cap, i, j, k;
    const char *base = NULL;
    char  cwdbuf[4096];
    char *work;
    char *out;
    int   is_abs = 0;
    int   has_drive = 0;
    int   has_root = 0;
    size_t *starts, *lens, nseg = 0;
    size_t  outlen, o;

    if (!path || !*path)
        return NULL;
    plen = strlen(path);

#ifdef _WIN32
    if (path[0] == '/' || path[0] == '\\' ||
        (((path[0] >= 'A' && path[0] <= 'Z') ||
          (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':'))
        is_abs = 1;
#else
    if (path[0] == '/')
        is_abs = 1;
#endif

    if (!is_abs) {
        if (!my_getcwd(cwdbuf, sizeof(cwdbuf)))
            return NULL;
        base = cwdbuf;
    }
    blen = base ? strlen(base) : 0;

    cap = blen + 1 + plen + 1;
    work = (char *)malloc(cap);
    if (!work)
        return NULL;
    j = 0;
    if (blen) {
        memcpy(work, base, blen);
        j = blen;
        if (j > 0 && work[j - 1] != '/' && work[j - 1] != '\\')
            work[j++] = '/';
    }
    memcpy(work + j, path, plen + 1);

#ifdef _WIN32
    for (i = 0; work[i]; i++)
        if (work[i] == '\\')
            work[i] = '/';
#endif

    /* prefix: drive "X:" dan/atau root '/' */
    i = 0;
#ifdef _WIN32
    if (((work[0] >= 'A' && work[0] <= 'Z') ||
         (work[0] >= 'a' && work[0] <= 'z')) && work[1] == ':') {
        has_drive = 1;
        i = 2;
    }
#endif
    if (work[i] == '/') {
        has_root = 1;
        i++;
    }

    starts = (size_t *)malloc((strlen(work) + 1) * sizeof(size_t));
    lens   = (size_t *)malloc((strlen(work) + 1) * sizeof(size_t));
    if (!starts || !lens) {
        free(starts);
        free(lens);
        free(work);
        return NULL;
    }

    while (work[i]) {
        size_t ss, sl;
        if (work[i] == '/') {
            i++;
            continue;
        }
        ss = i;
        while (work[i] && work[i] != '/')
            i++;
        sl = i - ss;
        if (sl == 1 && work[ss] == '.')
            continue;                       /* "." */
        if (sl == 2 && work[ss] == '.' && work[ss + 1] == '.') {
            if (nseg > 0)
                nseg--;                     /* ".." pop, tidak melewati root */
            continue;
        }
        starts[nseg] = ss;
        lens[nseg]   = sl;
        nseg++;
    }

    outlen = (has_drive ? 2 : 0) + (has_root ? 1 : 0);
    if ((has_drive || has_root) && nseg > 0)
        outlen += 1;                        /* separator setelah prefix */
    for (k = 0; k < nseg; k++)
        outlen += lens[k] + (k ? 1 : 0);
    outlen += 1;                            /* NUL */
    out = (char *)malloc(outlen);
    if (!out) {
        free(starts);
        free(lens);
        free(work);
        return NULL;
    }
    o = 0;
    if (has_drive) {
        out[o++] = work[0];
        out[o++] = ':';
    }
    if (has_root)
        out[o++] = '/';
    for (k = 0; k < nseg; k++) {
        if (k)
            out[o++] = '/';
        memcpy(out + o, work + starts[k], lens[k]);
        o += lens[k];
    }
    out[o] = '\0';

    free(starts);
    free(lens);
    free(work);
    return out;
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
    free(res->driver_harness_sha256);
    res->driver_harness_sha256 = NULL;
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
        myc_replay_capsule *cap = res->capsule;
        int ci;
        free(cap->source_sha256);
        free(cap->stdin_sha256);
        free(cap->clang_path);
        free(cap->gcc_path);
        free(cap->cwd);
        /* Roadmap 7.5: per-case driver records di-strdup ke capsule. */
        free(cap->driver_harness_sha256);
        for (ci = 0; ci < cap->driver_case_count; ci++) {
            free(cap->driver_case_records[ci].func);
            free(cap->driver_case_records[ci].params);
        }
        free(cap);
        res->capsule = NULL;
    }
    /* bebaskan witness (Fase 1) */
    if (res->witness) {
        myc_witness_free(res->witness);
        free(res->witness);
        res->witness = NULL;
    }
    /* bebaskan ledger fields (Fase 2) */
    free(res->receipt_parent);
    /* bebaskan cache delta report (Fase 3, SOL-18) */
    free(res->cache_delta_report);
    res->cache_delta_report = NULL;
    res->cache_hit = 0;
    free(res->delta_kind);
    free(res->delta_gate);
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
    cap->budget_active = res->budget_active;
    cap->budget_met = res->budget_met;

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
    /* Fase 4 A2/DS-02: ringkasan divergence di capsule. */
    cap->divergence_ran = res->divergence_ran;
    cap->divergence_sanitizer_div = res->divergence_sanitizer_div;
    cap->divergence_all_findings = res->divergence_all_findings;
    cap->divergence_semantic_div = res->divergence_semantic_div;
    cap->divergence_diag_div = res->divergence_diag_div;
    cap->negative_callsites = res->negative_callsites;
    cap->negative_deviations = res->negative_deviations;
    cap->checked_buffers = res->checked_buffers;
    cap->checked_allocations = res->checked_allocations;
    cap->checked_accesses = res->checked_accesses;
    cap->checked_frees = res->checked_frees;
    /* Driver (roadmap 7.5): ringkasan + per-case record utk replay. */
    cap->driver_funcs = res->driver_funcs;
    cap->driver_cases = res->driver_cases;
    cap->driver_skipped = res->driver_skipped;
    cap->driver_case_count = res->driver_case_count;
    cap->driver_max_product = res->driver_max_product;
    cap->driver_bounded = res->driver_bounded;
    if (res->driver_harness_sha256) {
        cap->driver_harness_sha256 = myc_strdup(res->driver_harness_sha256);
        if (!cap->driver_harness_sha256) goto fail;
    }
    for (i = 0; i < (size_t)res->driver_case_count &&
                 i < (size_t)MYC_MAX_DRIVER_RECORDS; i++) {
        cap->driver_case_records[i].case_id = res->driver_case_records[i].case_id;
        cap->driver_case_records[i].executed = res->driver_case_records[i].executed;
        cap->driver_case_records[i].alloc_bytes = res->driver_case_records[i].alloc_bytes;
        if (res->driver_case_records[i].func) {
            cap->driver_case_records[i].func =
                myc_strdup(res->driver_case_records[i].func);
            if (!cap->driver_case_records[i].func) goto fail;
        }
        if (res->driver_case_records[i].params) {
            cap->driver_case_records[i].params =
                myc_strdup(res->driver_case_records[i].params);
            if (!cap->driver_case_records[i].params) goto fail;
        }
    }
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
    free(cap->driver_harness_sha256);
    for (i = 0; i < (size_t)MYC_MAX_DRIVER_RECORDS; i++) {
        free(cap->driver_case_records[i].func);
        free(cap->driver_case_records[i].params);
    }
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

/* Temporal ledger integration (Fase 2): cari parent receipt di .myc/ledger.json,
 * hitung delta vs run sebelumnya, tulis entry baru. Non-blocking. */
static void myc_ledger_integrate(const myc_request *req, myc_result *res)
{
    myc_ledger ledger;
    const myc_ledger_entry *prev;
    myc_ledger_entry entry;
    char *scenario_hash;
    const char *curr_verdict;
    const char *curr_gate_status;
    const char *dn;

    if (!res->source_sha256)
        return;

    memset(&ledger, 0, sizeof(ledger));
    myc_ledger_read(&ledger);

    prev = myc_ledger_find(&ledger, res->source_sha256);
    if (prev && prev->receipt_sha256[0]) {
        res->receipt_parent = myc_strdup(prev->receipt_sha256);
        res->ledger_parent_found = 1;
    }

    /* Bangun scenario hash dari request. */
    scenario_hash = myc_ledger_build_scenario_hash(req, NULL);

    /* Compute delta: bandingkan verdict string vs run sebelumnya. */
    curr_verdict = myc_verdict_name(res->verdict);
    res->delta_kind = NULL;
    res->delta_gate = NULL;
    res->delta_changed = 0;

    if (prev && prev->verdict) {
        myc_delta_kind delta;
        if (strcmp(prev->verdict, curr_verdict) == 0) {
            delta = MYC_DELTA_PERSISTENT;
        } else if (strstr(prev->verdict, "VIOLATION") &&
                   strcmp(curr_verdict, "OK") == 0) {
            delta = MYC_DELTA_FIXED;
        } else if (strstr(curr_verdict, "VIOLATION") &&
                   strcmp(prev->verdict, "OK") == 0) {
            delta = MYC_DELTA_NEW;
        } else {
            delta = MYC_DELTA_CHURN;
        }
        dn = delta == MYC_DELTA_FIXED ? "fixed" :
             delta == MYC_DELTA_NEW ? "new" :
             delta == MYC_DELTA_PERSISTENT ? "persistent" : "churn";
        res->delta_kind = myc_strdup(dn);
        res->delta_changed = (delta != MYC_DELTA_PERSISTENT) ? 1 : 0;
    }

    /* Tulis entry ke ledger */
    memset(&entry, 0, sizeof(entry));
    entry.source_sha256 = res->source_sha256;
    entry.receipt_sha256 = res->receipt_sha256;
    entry.receipt_parent = res->receipt_parent;
    entry.scenario_hash = scenario_hash;
    entry.timestamp = myc_ledger_timestamp();
    if (res->delta_kind) {
        if (strcmp(res->delta_kind, "fixed") == 0) entry.delta = MYC_DELTA_FIXED;
        else if (strcmp(res->delta_kind, "new") == 0) entry.delta = MYC_DELTA_NEW;
        else if (strcmp(res->delta_kind, "persistent") == 0) entry.delta = MYC_DELTA_PERSISTENT;
        else entry.delta = MYC_DELTA_CHURN;
    }
    curr_gate_status = myc_gate_status_name(
        res->gates[0].status);
    entry.gate_status = myc_strdup(curr_gate_status ? curr_gate_status : "");
    entry.verdict = myc_strdup(curr_verdict);
    entry.finding = myc_strdup(myc_finding_name(res->finding));

    myc_ledger_write(&entry);

    free(scenario_hash);
    free(entry.gate_status);
    free(entry.verdict);
    free(entry.finding);
    myc_ledger_free(&ledger);
}

void myc_run(const myc_request *req, myc_result *res)
{
    myc_error_code ve = myc_request_validate(req);
    if (ve != MYC_ERR_NONE) {
        res->verdict = MC_ERROR;
        res->err = ve;
        if (ve == MYC_ERR_NUL_IN_INPUT && req->input.kind == MYC_SOURCE_MEMORY) {
            size_t nul_pos = SIZE_MAX;
            size_t nul_count = 0;
            size_t i;
            for (i = 0; i < req->input.len; i++) {
                if (req->input.data[i] == '\0') {
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

    /* MYC-AUDIT-030 (Fase 2): canonicalize cwd di ingress. cwd relatif
     * (".", "./test/../test", dll) disamakan ke bentuk absolut+lexical
     * agar fingerprint (`cwd:%s` di compile.c) dan chdir child (proc.c)
     * deterministik terhadap representasi. Canonicalization lexical
     * (tidak menyentuh filesystem) -- cwd boleh belum ada. Bila gagal
     * (getcwd gagal/OOM) NON-blocking: pakai nilai asli + jalur normal. */
    {
        myc_request  reqc;
        const myc_request *eff = req;
        char        *canon_cwd = NULL;

        if (req->cwd) {
            canon_cwd = myc_absolutize(req->cwd);
            if (canon_cwd) {
                reqc = *req;
                reqc.cwd = canon_cwd;
                eff = &reqc;
            }
        }

        /* MYC-AUDIT-029 (Fase 2): canonical ingress -- muat input MEMORY/FILE/
         * STDIN via SATU loader terpusat (myc_source_load: cap + NUL policy +
         * error typed). Pipeline HANYA menerima source in-memory
         * (MYC_SOURCE_MEMORY); tidak ada NULL dereference, tidak ada jalur
         * file_path yang membaca penuh tanpa cap (MYC-AUDIT-007/028). */
        if (eff->input.kind == MYC_SOURCE_FILE ||
            eff->input.kind == MYC_SOURCE_STDIN) {
            const char  *buf;
            size_t       len;
            int          needs_free;
            myc_error_code le = myc_source_load(&eff->input, &buf, &len, &needs_free);
            if (le != MYC_ERR_NONE) {
                res->verdict = MC_ERROR;
                res->err = le;
                free(canon_cwd);
                return;
            }
            {
                myc_request req2;
                req2 = *eff;
                req2.input.kind = MYC_SOURCE_MEMORY;
                req2.input.data = buf;
                req2.input.len = len;
                /* SOL-18: incremental evidence cache — bila input + scenario
                 * + tool identity sama dengan run sebelumnya, REPLAY hasil
                 * (skip seluruh pipeline/backend). NON-blocking: miss /
                 * .myc/ tak terbaca = jalur normal. Delta report di-set
                 * bila source berubah (fungsi berubah + dependents). */
                if (!myc_cache_try_replay(&req2, res, buf, len)) {
                    myc_pipeline(&req2, res);
                    /* Fase 4 A1: ledger asumsi portabilitas — deteksi +
                     * state + ack (NON-blocking; facts dari macro dump
                     * gcc; jalur cache-hit memakai facts dari entry). */
                    if (!req2.no_assumptions)
                        myc_assume_run(&req2, res, buf, len, NULL);
                    /* #3: quorum juga dihitung di jalur file_path/STDIN
                     * (API/MCP), konsisten dengan jalur source in-memory. */
                    myc_quorum_analysis(&req2, res);
                    /* Fase 5 B3 (DS-07): coaching transcript untuk model. */
                    myc_coach_build(res);
                    enforce_require_complete(&req2, res);
                    /* Fase 4 A1/DS-01: asumsi terbuka = gap verifikasi
                     * bila --require-assumptions-closed (pola 9.10). */
                    if (req2.require_assumptions_closed)
                        myc_assume_enforce(&req2, res);
                    /* SOL-30: assurance budget contract — target eksplisit
                     * user/harness; enforcement TERAKHIR (setelah
                     * require-complete) supaya kontrak dilihat pada hasil
                     * final. NON-blocking bila kontrak tidak aktif. */
                    myc_budget_enforce(&req2, res);
                    myc_ledger_integrate(&req2, res);
                    myc_cache_store(&req2, res, buf, len);
                } else {
                    /* A1: pada cache-hit asumsi SELALU di-scan ulang
                     * (murni teks, ~ms, tanpa exec gcc — facts di-replay
                     * dari entry) supaya status .myc/assumptions.json
                     * selalu segar; tidak disimpan di cache entry. */
                    if (!req2.no_assumptions)
                        myc_assume_run(&req2, res, buf, len,
                                       res->assumption_facts_ok
                                           ? &res->host_facts : NULL);
                    myc_quorum_analysis(&req2, res);
                    /* Fase 5 B3 (DS-07): coaching transcript untuk model. */
                    myc_coach_build(res);
                    enforce_require_complete(&req2, res);
                    /* SOL-30: pada cache-hit, hasil enforcement budget
                     * contract sudah di-replay utuh dari entry (verdict/
                     * debt/budget_report asli); TIDAK di-re-enforce agar
                     * deterministik & tanpa duplikat debt. */
                    if (req2.require_assumptions_closed)
                        myc_assume_enforce(&req2, res);
                }
                 if (needs_free)
                     free((void *)buf);
                 res->capsule = myc_build_capsule(&req2, res);
             }
             free(canon_cwd);
             return;
         }

        if (!myc_cache_try_replay(eff, res, eff->input.data,
                                  eff->input.len)) {
            myc_pipeline(eff, res);
            /* Fase 4 A1: ledger asumsi portabilitas (non-blocking). */
            if (!eff->no_assumptions)
                myc_assume_run(eff, res, eff->input.data, eff->input.len,
                               NULL);
            myc_quorum_analysis(eff, res);
            /* Fase 5 B3 (DS-07): coaching transcript untuk model. */
            myc_coach_build(res);
            enforce_require_complete(eff, res);
            if (eff->require_assumptions_closed)
                myc_assume_enforce(eff, res);
            myc_budget_enforce(eff, res);
            myc_ledger_integrate(eff, res);
            myc_cache_store(eff, res, eff->input.data, eff->input.len);
        } else {
            if (!eff->no_assumptions)
                myc_assume_run(eff, res, eff->input.data, eff->input.len,
                               res->assumption_facts_ok
                                   ? &res->host_facts : NULL);
            myc_quorum_analysis(eff, res);
            /* Fase 5 B3 (DS-07): coaching transcript untuk model. */
            myc_coach_build(res);
            enforce_require_complete(eff, res);
            /* SOL-30: cache-hit — enforcement budget sudah di-replay. */
            if (eff->require_assumptions_closed)
                myc_assume_enforce(eff, res);
        }
        res->capsule = myc_build_capsule(eff, res);
        free(canon_cwd);
    }
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
        "  myc check <file.c> [--json] [--json-summary] [--agent] [--analyze] [--strict] [--no-lint] [--no-cache] [--no-assumptions] [--cwd DIR]\n"
        "  myc check <file.c> [--run [--run-stdin FILE]] [--prove] [--checked] [--filc] [--driver] [--metamorphic] [--divergence] [--negative] [--quorum] [--require-complete]\n"
        "  myc check <file.c> --divergence   (Fase 4 A2: matriks toolchain {gcc,clang,tcc} x {-O0,-O2}, klasifikasi DS-02)\n"
        "  myc check <file.c> [--require-assumptions-closed] [--assumption-ack id:status,...]   (Fase 4 A1: ledger asumsi portabilitas)\n"
        "  myc check <file.c> [--timeout MS] [--output-cap BYTES]\n"
        "                        (timeout 0-600000 ms, 0 = default 30000; output-cap 0-104857600 byte, 0 = default 1 MiB)\n"
        "  myc check <file.c> --budget-contract '{\"required\":{\"runtime\":\"clean\"},\"max_time_ms\":10000}'\n"
        "                        (SOL-30: target assurance eksplisit; tak tercapai = INCONCLUSIVE + report)\n"
        "  myc check -          [--json] [--json-summary] [--agent] [--analyze] [--strict] [--no-lint] [--no-cache]\n"
        "                        (source dari stdin)\n"
        "  myc context <file.c> [--finding-id ID] [--budget 4K|8K|16K] [gate flags...]\n"
        "                        (paket konteks minimal untuk model: function slice,\n"
        "                        callers/callees, contracts, witness, one action,\n"
        "                        preservation obligations, verify command; SOL-22)\n"
        "  myc policy\n"
        "  myc probe\n"
        "  myc version\n");
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
    int         context_budget_tokens = 0;
    int         is_context = 0;

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

    if (strcmp(argv[1], "check") != 0 && strcmp(argv[1], "context") != 0) {
        usage();
        return 2;
    }
    is_context = (strcmp(argv[1], "context") == 0);

    if (argc < 3) {
        usage();
        return 2;
    }

    myc_request_init(&req);
    myc_result_init(&res);
    req.run_lint = 1;               /* lint memory-safety default ON */
    req.checked_header_dir = myc_exe_dirname(argv[0]);

    /* SOL-22: budget token default untuk `myc context` (8K). */
    context_budget_tokens = 0;

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
            } else if (strcmp(argv[i], "--no-cache") == 0) {
                req.no_cache = 1; known = 1;
            } else if (strcmp(argv[i], "--no-assumptions") == 0) {
                req.no_assumptions = 1; known = 1;
            } else if (strcmp(argv[i], "--require-assumptions-closed") == 0) {
                req.require_assumptions_closed = 1; known = 1;
            } else if (strcmp(argv[i], "--assumption-ack") == 0) {
                /* Fase 4 A1/DS-01: tutup asumsi "id:status,..." — format
                 * salah = fail-fast exit 2 (konsisten MYC-AUDIT-019). */
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --assumption-ack membutuhkan "
                                    "argumen (id:status,...)\n");
                    myc_result_free(&res);
                    return 2;
                }
                if (myc_assume_ack_validate(argv[i + 1]) != 0) {
                    fprintf(stderr, "myc: --assumption-ack format salah; "
                                    "harus \"id:status\" dengan status "
                                    "declared|tested|contradicted|"
                                    "eliminated|accepted-risk\n");
                    myc_result_free(&res);
                    return 2;
                }
                req.assumption_acks = myc_strdup(argv[i + 1]);
                i++; known = 1;
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
            } else if (strcmp(argv[i], "--divergence") == 0) {
                req.divergence = 1; known = 1;
            } else if (strcmp(argv[i], "--negative") == 0) {
                req.negative = 1; known = 1;
            } else if (strcmp(argv[i], "--require-complete") == 0) {
                req.require_complete = 1; known = 1;
            } else if (strcmp(argv[i], "--agent") == 0) {
                req.agent = 1; known = 1;
            } else if (strcmp(argv[i], "--write-repro") == 0) {
                req.write_repro = 1; known = 1;
            } else if (strcmp(argv[i], "--tx-verify") == 0) {
                req.tx_verify = 1; known = 1;
            } else if (strcmp(argv[i], "--finding-id") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --finding-id membutuhkan argumen ID\n");
                    myc_result_free(&res);
                    return 2;
                }
                req.tx_finding_id = myc_strdup(argv[i + 1]);
                i++; known = 1;
            } else if (strcmp(argv[i], "--edit-region") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --edit-region membutuhkan argumen\n");
                    myc_result_free(&res);
                    return 2;
                }
                req.tx_edit_region = myc_strdup(argv[i + 1]);
                i++; known = 1;
            } else if (strcmp(argv[i], "--budget-contract") == 0) {
                /* SOL-30: target assurance eksplisit (JSON). Parse KETAT
                 * (reuse json.c); invalid = fail-fast exit 2 (konsisten
                 * MYC-AUDIT-019/020). */
                const char *a;
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --budget-contract membutuhkan "
                                    "argumen JSON\n");
                    myc_result_free(&res);
                    return 2;
                }
                a = argv[i + 1];
                if (myc_budget_parse(a, strlen(a), &req.budget) != 0) {
                    fprintf(stderr, "myc: --budget-contract JSON tidak valid\n"
                                    "  format: {\"required\":{\"runtime\":\"clean\"}"
                                    ",\"max_time_ms\":10000}\n");
                    myc_result_free(&res);
                    return 2;
                }
                i++; known = 1;
            } else if (strcmp(argv[i], "--json-summary") == 0) {
                req.json_summary = 1; known = 1;
            } else if (strcmp(argv[i], "--budget") == 0) {
                /* SOL-22: budget token paket context (4K/8K/16K, default 8K).
                 * Hanya bermakna pada subcommand context; pada check flag ini
                 * ditolak fail-fast (konsisten MYC-AUDIT-019: flag yang
                 * dipakai di subcommand salah = exit 2, bukan diam-diam). */
                if (!is_context) {
                    fprintf(stderr,
                            "myc: --budget hanya berlaku pada subcommand context\n");
                    myc_result_free(&res);
                    return 2;
                }
                const char *a;
                char       *end;
                long        v;
                int         mult = 1;
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --budget membutuhkan argumen (mis. 8K)\n");
                    myc_result_free(&res);
                    return 2;
                }
                a = argv[i + 1];
                errno = 0;
                v = strtol(a, &end, 10);
                if (errno == ERANGE || end == a)
                    v = -1;
                if (v >= 1 && end && (*end == 'K' || *end == 'k')) {
                    mult = 1024;
                    end++;
                }
                if (v < 1 || v > 64 || !end || *end != '\0') {
                    fprintf(stderr,
                            "myc: --budget harus 1K..64K (mis. 4K, 8K, 16K)\n");
                    myc_result_free(&res);
                    return 2;
                }
                context_budget_tokens = (int)(v * (long)mult);
                i++;
                known = 1;
            } else if (strcmp(argv[i], "--run-stdin") == 0) {
                char *buf;
                size_t len;
                int   rr;
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --run-stdin membutuhkan argumen FILE\n");
                    myc_result_free(&res);
                    return 2;
                }
                rr = read_file_capped(argv[i + 1], MYC_MAX_STDIN_BYTES,
                                      &buf, &len);
                if (rr == 2) {
                    fprintf(stderr, "myc: --run-stdin %s: ukuran melebihi "
                                    "cap %u byte\n", argv[i + 1],
                            (unsigned)MYC_MAX_STDIN_BYTES);
                    myc_result_free(&res);
                    return 2;
                }
                if (!rr) {
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

    /* Fase 4 A1: --no-assumptions + --require-assumptions-closed adalah
     * kontradiksi (tidak ada yang bisa ditutup) -> fail-fast (konsisten
     * MYC-AUDIT-019). */
    if (req.no_assumptions && req.require_assumptions_closed) {
        fprintf(stderr, "myc: --no-assumptions tidak dapat dipakai bersama "
                        "--require-assumptions-closed\n");
        myc_result_free(&res);
        return 2;
    }

    /* MYC-AUDIT-029: CLI memakai loader canonical yang sama dengan API
     * (myc_source_load: cap + NUL policy + error typed). Tidak ada duplikasi
     * logika baca file/stdin di CLI dan pipeline. */
    {
        const char *src;
        size_t      len;
        int         needs_free = 0;
        myc_source_input in;
        myc_error_code   le;
        int              is_stdin = (strcmp(argv[2], "-") == 0);
        if (is_stdin) {
            in.kind = MYC_SOURCE_STDIN;
            in.data = NULL; in.len = 0; in.file_path = NULL;
        } else {
            in.kind = MYC_SOURCE_FILE;
            in.data = NULL; in.len = 0; in.file_path = argv[2];
        }
        le = myc_source_load(&in, &src, &len, &needs_free);
        if (le == MYC_ERR_INPUT_TOO_LARGE) {
            fprintf(stderr, "myc: %s: ukuran melebihi cap %u byte\n",
                    is_stdin ? "source stdin" : argv[2],
                    (unsigned)MYC_MAX_CODE_BYTES);
            myc_result_free(&res);
            return 2;
        }
        if (le == MYC_ERR_INVALID_PATH) {
            fprintf(stderr, "myc: tidak dapat membaca %s\n", argv[2]);
            return 1;
        }
        if (le != MYC_ERR_NONE) {
            fprintf(stderr, "myc: gagal memuat source (error %d)\n", (int)le);
            myc_result_free(&res);
            return 1;
        }
        req.input.kind = MYC_SOURCE_MEMORY;
        req.input.data = src;
        req.input.len = len;
        /* Metadata path asli untuk cache delta (path matching + label
         * report). Aman: kind=MEMORY tidak membaca file_path di loader;
         * hanya dipakai sebagai identitas sumber asal (SOL-18). */
        req.input.file_path = is_stdin ? NULL : argv[2];
        myc_run(&req, &res);
        /* --write-repro: tulis .myc-witness/ repro directory (Fase 1).
         * Harus sebelum free(src) karena membutuhkan source. */
        if (req.write_repro && res.witness) {
            char *repro_dir = myc_witness_write_repro(res.witness,
                                                      src, len,
                                                      req.cwd ? req.cwd : ".");
            if (repro_dir) {
                fprintf(stderr, "[myc] witness repro written to %s\n", repro_dir);
                free(repro_dir);
            }
        }
        /* SOL-22: paket context dibangun DI SINI karena butuh source
         * (sebelum free(src)). Murni derivasi hasil run; deterministik. */
        if (is_context) {
            char  ctx_hash[65];
            char *pkg = myc_context_build(&res, src, len, &req,
                                          req.tx_finding_id,
                                          context_budget_tokens > 0
                                              ? context_budget_tokens
                                              : MYC_CONTEXT_BUDGET_DEFAULT,
                                          ctx_hash);
            if (pkg) {
                printf("%s", pkg);
                free(pkg);
            } else {
                fprintf(stderr, "myc: gagal membangun context paket\n");
                if (needs_free)
                    free((void *)src);
                myc_result_free(&res);
                return 1;
            }
        }
        if (needs_free)
            free((void *)src);
    }

    if (is_context) {
        /* paket sudah dicetak di atas (membutuhkan source); tanpa report */
    } else if (req.as_json)
        myc_report_json(&res);
    else if (req.json_summary)
        myc_report_json_summary(&res);
    else if (req.agent)
        myc_report_agent(&res);
    else
        myc_report_text(&res);

    myc_result_free(&res);
    free(req.tx_finding_id);
    myc_budget_free(&req.budget);
    free(req.assumption_acks);
    free(req.tx_edit_region);
    if (req.run_stdin)
        free((void *)req.run_stdin);
    return res.verdict == MC_OK ? 0 : 1;
}

#endif /* MYC_NO_MAIN */
