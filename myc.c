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
 *   myc compare-candidates <base.c> <c1.c> [c2.c ...]
 *                                   -- tournament Pareto frontier (SOL-10)
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
#include "abi.h"
#include "ledger.h"
#include "cache.h"
#include "transaction.h"
#include "sha256.h"
#include "agent.h"
#include "context.h"
#include "budget.h"
#include "assume.h"
#include "taxonomy.h"
#include "prompt.h"
#include "driver.h"
#include "contract.h"
#include "state.h"
#include "resource.h"
#include "units.h"
#include "profile.h"
#include "calibrate.h"
#include "eig.h"
#include "candidate.h"
#include "scenario.h"
#include "canary.h"
#include "testaudit.h"
#include "regress.h"
#include "limit.h"

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
    struct myc_arena *a = (struct myc_arena *)myc_malloc(
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
    /* Fase 7 (privacy/size): agent_payload_cap divalidasi di ingress juga
     * (bukan hanya CLI) supaya jalur API/MCP tidak bisa lewatkan nilai di
     * luar rentang -- konsisten pola MYC-AUDIT-020 (max_output_bytes).
     * Rentang sah: 0 (default MYC_AGENT_PAYLOAD_CAP 16384) atau
     * 1024..MYC_MAX_AGENT_PAYLOAD_CAP_BYTES. Negatif otomatis tertolak. */
    if (req->agent_payload_cap != 0 &&
        (req->agent_payload_cap < MYC_MIN_AGENT_PAYLOAD_CAP_BYTES ||
         req->agent_payload_cap > (int)MYC_MAX_AGENT_PAYLOAD_CAP_BYTES))
        return MYC_ERR_INVALID_AGENT_CAP;
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
    buf = (char *)myc_malloc(bufcap);
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
            nb = (char *)myc_realloc(buf, ncap);
            if (!nb) {
                myc_free(buf);
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
    myc_free(buf);
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
    buf = (char *)myc_malloc(bufcap);
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
                nb = (char *)myc_realloc(buf, ncap);
                if (!nb) {
                    myc_free(buf);
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
                myc_free(buf);
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
    myc_free(buf);
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
    work = (char *)myc_malloc(cap);
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

    starts = (size_t *)myc_malloc((strlen(work) + 1) * sizeof(size_t));
    lens   = (size_t *)myc_malloc((strlen(work) + 1) * sizeof(size_t));
    if (!starts || !lens) {
        myc_free(starts);
        myc_free(lens);
        myc_free(work);
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
    out = (char *)myc_malloc(outlen);
    if (!out) {
        myc_free(starts);
        myc_free(lens);
        myc_free(work);
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

    myc_free(starts);
    myc_free(lens);
    myc_free(work);
    return out;
}

void myc_result_free(myc_result *res)
{
    size_t i;
    struct myc_arena *a;
    if (!res)
        return;
    myc_free(res->stdout_text);
    myc_free(res->stderr_text);
    myc_free(res->run_stdout_text);
    myc_free(res->run_stderr_text);
    myc_free(res->prove_stdout_text);
    myc_free(res->prove_stderr_text);
    myc_free(res->filc_stdout_text);
    myc_free(res->filc_stderr_text);
    myc_free(res->filc_version);
    myc_free(res->driver_stdout_text);
    myc_free(res->driver_stderr_text);
    myc_free(res->driver_harness_sha256);
    res->driver_harness_sha256 = NULL;
    myc_free(res->exhaustive_stdout_text);
    myc_free(res->exhaustive_stderr_text);
    myc_free(res->exhaustive_harness_sha256);
    res->exhaustive_stdout_text = NULL;
    res->exhaustive_stderr_text = NULL;
    res->exhaustive_harness_sha256 = NULL;
    myc_free(res->fuzz_stdout_text);
    myc_free(res->fuzz_stderr_text);
    res->fuzz_stdout_text = NULL;
    res->fuzz_stderr_text = NULL;
    myc_free(res->resolved_gcc);
    myc_free(res->gcc_version);
    myc_free(res->clang_version);
    myc_free(res->fingerprint);
    myc_free(res->source_sha256);
    for (i = 0; i < res->gate_count; i++)
        myc_free(res->gates[i].output);
    for (i = 0; i < res->evidence_count; i++)
        myc_free(res->evidence[i].message);
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
        myc_free(a);
        a = nxt;
    }
    res->arena = NULL;
    /* bebaskan capsule (#2) */
    if (res->capsule) {
        myc_replay_capsule *cap = res->capsule;
        int ci;
        myc_free(cap->source_sha256);
        myc_free(cap->stdin_sha256);
        myc_free(cap->clang_path);
        myc_free(cap->gcc_path);
        myc_free(cap->cwd);
        /* Roadmap 7.5: per-case driver records di-strdup ke capsule. */
        myc_free(cap->driver_harness_sha256);
        for (ci = 0; ci < cap->driver_case_count; ci++) {
            myc_free(cap->driver_case_records[ci].func);
            myc_free(cap->driver_case_records[ci].params);
        }
        myc_free(cap);
        res->capsule = NULL;
    }
    /* bebaskan witness (Fase 1) */
    if (res->witness) {
        myc_witness_free(res->witness);
        myc_free(res->witness);
        res->witness = NULL;
    }
    /* bebaskan ledger fields (Fase 2) */
    myc_free(res->receipt_parent);
    /* bebaskan cache delta report (Fase 3, SOL-18) */
    myc_free(res->cache_delta_report);
    res->cache_delta_report = NULL;
    res->cache_hit = 0;
    myc_free(res->delta_kind);
    myc_free(res->delta_gate);
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

    cap = (myc_replay_capsule *)myc_calloc(1, sizeof(*cap));
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
    /* MYC-AUDIT-040: buffer biasa di luar MYC_BUF. */
    cap->checked_raw_buffers = res->checked_raw_buffers;
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
    myc_free(cap->source_sha256);
    myc_free(cap->stdin_sha256);
    myc_free(cap->clang_path);
    myc_free(cap->gcc_path);
    myc_free(cap->cwd);
    myc_free(cap->driver_harness_sha256);
    for (i = 0; i < (size_t)MYC_MAX_DRIVER_RECORDS; i++) {
        myc_free(cap->driver_case_records[i].func);
        myc_free(cap->driver_case_records[i].params);
    }
    myc_free(cap);
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

    myc_free(scenario_hash);
    myc_free(entry.timestamp);
    myc_free(entry.gate_status);
    myc_free(entry.verdict);
    myc_free(entry.finding);
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
        if (ve == MYC_ERR_INVALID_AGENT_CAP && res->diag_count < MYC_MAX_DIAGNOSTICS) {
            const char *msg = "agent_payload_cap di luar rentang valid (0 atau 1024-1048576)";
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
    /* Fase 7 (privacy/size controls): cap payload agent di-wire ke hasil
     * SEBELUM branch cache -- jalur cache-hit pun memakainya (agent output
     * selalu dibangun ulang dari res, tidak di-replay dari cache). */
    res->agent_payload_cap = req->agent_payload_cap;
    /* IDE-6 (--watch-diff): tandai diminta agar report bisa berkata jujur
     * saat baseline belum ada (delta kosong, bukan error). */
    res->watch_diff_requested = req->watch_diff;

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
                myc_free(canon_cwd);
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
                    if (!req2.no_assumptions && !req2.no_persist)
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
                    /* Fase 7 (privacy/size): --no-persist = tanpa jejak
                     * disk -- ledger temporal & cache tidak ditulis. */
                    if (!req2.no_persist) {
                        myc_ledger_integrate(&req2, res);
                        myc_cache_store(&req2, res, buf, len);
                    }
                } else {
                    /* A1: pada cache-hit asumsi SELALU di-scan ulang
                     * (murni teks, ~ms, tanpa exec gcc — facts di-replay
                     * dari entry) supaya status .myc/assumptions.json
                     * selalu segar; tidak disimpan di cache entry. */
                    if (!req2.no_assumptions && !req2.no_persist)
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
                     myc_free((void *)buf);
                 res->capsule = myc_build_capsule(&req2, res);
             }
             myc_free(canon_cwd);
             return;
         }

        if (!myc_cache_try_replay(eff, res, eff->input.data,
                                  eff->input.len)) {
            myc_pipeline(eff, res);
            /* Fase 4 A1: ledger asumsi portabilitas (non-blocking). */
            if (!eff->no_assumptions && !eff->no_persist)
                myc_assume_run(eff, res, eff->input.data, eff->input.len,
                               NULL);
            myc_quorum_analysis(eff, res);
            /* Fase 5 B3 (DS-07): coaching transcript untuk model. */
            myc_coach_build(res);
            enforce_require_complete(eff, res);
            if (eff->require_assumptions_closed)
                myc_assume_enforce(eff, res);
            myc_budget_enforce(eff, res);
            /* Fase 7 (privacy/size): --no-persist = tanpa jejak disk. */
            if (!eff->no_persist) {
                myc_ledger_integrate(eff, res);
                myc_cache_store(eff, res, eff->input.data, eff->input.len);
            }
        } else {
            if (!eff->no_assumptions && !eff->no_persist)
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
        myc_free(canon_cwd);
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
        myc_free(self);
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
        "  myc check <file.c> [--json] [--json-summary] [--agent] [--analyze] [--strict] [--no-lint] [--no-cache] [--no-assumptions] [--cwd DIR] [--profile ID] [--calibrate] [--watch-diff]\n"
        "  myc check <file.c> [--run [--run-stdin FILE]] [--prove] [--checked] [--filc] [--driver] [--exhaustive] [--stack [--stack-budget N]] [--fuzz [--fuzz-iters N] [--fuzz-seed S]] [--mutate-audit [--mutate-max N]] [--freestanding] [--metamorphic] [--divergence] [--negative] [--quorum] [--require-complete] [--scenario NAME [--scenario-file PATH]] [--matrix] [--abi]\n"
        "  myc check <file.c> [--watch-diff | --delta]   (IDE-6: fast inner loop per-fungsi --\n"
        "                        delta assurance terstruktur vs baseline cache (fungsi\n"
        "                        berubah/identik/baru/hilang/dependents) + timing;\n"
        "                        NON-blocking penuh, verdict TIDAK berubah)\n"
        "  myc check <file.c> --divergence   (Fase 4 A2: matriks toolchain {gcc,clang,tcc} x {-O0,-O2}, klasifikasi DS-02)\n"
        "  myc check <file.c> [--require-assumptions-closed] [--assumption-ack id:status,...]   (Fase 4 A1: ledger asumsi portabilitas)\n"
        "  myc check <file.c> [--timeout MS] [--output-cap BYTES]\n"
        "                        (timeout 0-600000 ms, 0 = default 30000; output-cap 0-104857600 byte, 0 = default 1 MiB)\n");
    printf(
        "  myc check <file.c> [--agent-payload-cap BYTES] [--no-persist]\n"
        "                        (Fase 7 privacy/size: cap payload --agent 0|1024-1048576,\n"
        "                        0 = default 16384; --no-persist = tanpa jejak disk,\n"
        "                        ledger/cache/asumsi/profil TIDAK ditulis)\n"
        "  myc check <file.c> [--pack-dir DIR] [--no-pack]\n"
        "                        (pack proyek lokal myc.prompt.md + myc.spec.json\n"
        "                        utk output --agent; NON-blocking, Fase 7)\n"
        "  myc check <file.c> --budget-contract '{\"required\":{\"runtime\":\"clean\"},\"max_time_ms\":10000}'\n"
        "                        (SOL-30: target assurance eksplisit; tak tercapai = INCONCLUSIVE + report)\n"
        "  myc check -          [--json] [--json-summary] [--agent] [--analyze] [--strict] [--no-lint] [--no-cache]\n"
        "                        (source dari stdin)\n"
        "  myc context <file.c> [--finding-id ID] [--budget 4K|8K|16K] [--pack-dir DIR] [--no-pack] [gate flags...]\n"
        "                        (paket konteks minimal untuk model: function slice,\n"
        "                        callers/callees, contracts, witness, one action,\n"
        "                        preservation obligations, verify command, project\n"
        "                        pack; SOL-22 + pack Fase 7 NON-blocking)\n"
        "  myc policy\n"
        "  myc probe\n"
        "  myc prompt <file.c> [--pack-dir DIR] [--no-pack]\n"
        "                        (D4/DS-15: system-prompt snippet deterministik\n"
        "                        dari fakta target + kebijakan proyek; pack\n"
        "                        proyek lokal myc.prompt.md + myc.spec.json,\n"
        "                        NON-blocking, Fase 7)\n"
        "  myc compare <ref.c> <new.c> [func...]\n"
        "                        (A4/DS-04: differential oracle pair --\n"
        "                        baterai input bersama dijalankan pada KEDUA\n"
        "                        versi; identik = behavior-preserving (P1 DIFF),\n"
        "                        divergen = unexpected_change)\n"
        "  myc contract-delta <before.c> <after.c>\n"
        "                        (Fase 2: delta kontrak //@ requires/ensures --\n"
        "                        NARROWED = domain menyempit (laundering),\n"
        "                        WEAKENED = kontrak melemah; exit 1 bila preservation\n"
        "                        dilanggar)\n"
        "  myc scenario list\n"
        "  myc scenario info <name>\n"
        "                        (C5/DS-12: scenario packs -- resep verifikasi\n"
        "                        per domain dari profil JSON; D3: --scenario auto\n"
        "                        menebak resep dari struktur source)\n"
        "  myc profile list\n"
        "  myc profile show <id>\n"
        "  myc profile reset <id>\n"
        "                        (Fase 7/SOL-20: opt-in Model/Harness Error\n"
        "                        Fingerprint -- agregat lokal tanpa source;\n"
"                        aktif juga via --profile <id> atau\n"
         "                        env MYC_PROFILE_ID)\n"
         "  myc calibrate mark <rule> <accepted|rejected|confirmed_later|missed|useful_fix|harmful_fix> [--match <fragmen>]\n"
         "  myc calibrate show <rule>\n"
         "  myc calibrate list\n"
         "  myc calibrate reset [<rule>]\n"
         "                        (Fase 7/SOL-21: opt-in Trust Calibration\n"
         "                        Ledger -- feedback per rule, lokal, tanpa\n"
         "                        source; rule dikalibrasi LOW tidak menghasilkan\n"
         "                        hard finding)\n"
         "  myc check <file.c> [--calibrate] ...\n"
         "                        (meng-anotasi rule LOW/DISABLED: observasi\n"
         "                        NON-blocking; juga via env MYC_CALIBRATE=1)\n"
         "  myc eig <file.c> [--profile <id>] [--budget-ms N] [--unchanged] [--json]\n"
         "                        (Fase 7/#2029 DS-14: Expected-Information-Gain\n"
         "                        scheduler -- rekomendasi eksperimen terurut\n"
         "                        skor expected_value = P(new-evidence) x\n"
         "                        severity x scope / (time x token); prior tabel\n"
         "                        deterministik dikalibrasi dari ledger SOL-21 +\n"
         "                        profil SOL-20; NON-blocking, verdict tetap)\n");
    /* PR-017: blok usage backends dipisah ke printf tersendiri — string
     * literal yang BERTETANGGA digabung compiler (overlength-strings),
     * dan gabungan usage utama sudah mendekati batas 4095 C99. */
    printf(
         "  myc backends [--canary]\n"
         "                        (PR-017/P5-T01: backend qualification registry\n"
         "                        -- tier kebijakan A/B/C + path + versi exact\n"
         "                        tiap backend; --canary jalankan canary per\n"
         "                        backend (kualifikasi hidup; mahal). NON-blocking)\n"
         "  myc limits [--json]\n"
         "                        (PR-018/P7-T01: resource limits -- tabel batas\n"
         "                        resource yang diberlakukan + kelas enforcement\n"
         "                        HARD=ingress fail-fast, soft=cap+debt; --json\n"
         "                        objek myc.limits.v1. NON-blocking, laporan)\n"
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
    probe = (char *)myc_malloc(dl + 16);
    if (!probe) {
        myc_free(self);
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
        myc_free(probe);
        myc_free(self);
        return 1;
    }
    printf("probe exit=%d dur=%llums\n", pres.exit_code, pres.duration_ms);
    if (pres.stdout_data)
        printf("%s", pres.stdout_data);
    myc_proc_result_free(&pres);
    myc_free(probe);
    myc_free(self);
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
        myc_free(gv);
        myc_free(gcc);
    } else {
        printf("gcc: TIDAK DITEMUKAN\n");
    }
    if (clang) {
        printf("clang: %s\n", clang);
        cv = myc_tool_version(clang);
        printf("clang version: %s\n", cv ? cv : "(tidak terbaca)");
        myc_free(cv);
        myc_free(clang);
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
            myc_free(fv);
            myc_free(filc);
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

/* D4 (DS-15): system-prompt snippet deterministik untuk harness LLM. */
static int cmd_compare(const char *ref_path, const char *new_path,
                       char **funcs, int nfuncs)
{
    myc_source_input in;
    const char *buf_ref, *buf_new;
    size_t      len_ref, len_new;
    int         free_ref = 0, free_new = 0;
    myc_error_code le;
    myc_request req;
    myc_result  res;
    int         rc = 0;

    memset(&in, 0, sizeof(in));
    in.kind = MYC_SOURCE_FILE;
    in.file_path = ref_path;
    le = myc_source_load(&in, &buf_ref, &len_ref, &free_ref);
    if (le != MYC_ERR_NONE) {
        fprintf(stderr, "myc: compare: tidak dapat membaca %s (error=%s)\n",
                ref_path, myc_error_name(le));
        return 1;
    }
    memset(&in, 0, sizeof(in));
    in.kind = MYC_SOURCE_FILE;
    in.file_path = new_path;
    le = myc_source_load(&in, &buf_new, &len_new, &free_new);
    if (le != MYC_ERR_NONE) {
        fprintf(stderr, "myc: compare: tidak dapat membaca %s (error=%s)\n",
                new_path, myc_error_name(le));
        if (free_ref)
            myc_free((void *)buf_ref);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    myc_result_init(&res);
    myc_compare_gate(&req, buf_ref, len_ref, buf_new, len_new,
                     (const char *const *)funcs, nfuncs, &res);
    printf("%s\n", res.compare_report ? res.compare_report
                                       : "compare: (tanpa laporan)");
    if (res.compare_delta) {
        printf("  kasus divergen (detail):\n%s\n", res.compare_delta);
    }
    if (res.compare_preserved)
        printf("compare: behavior-preserving (P1 DIFF) -- refactor aman\n");
    else
        printf("compare: unexpected_change (DS-04) -- PERILAKU BERUBAH\n");
    rc = res.compare_preserved ? 0 : 1;

    myc_result_free(&res);
    if (free_ref)
        myc_free((void *)buf_ref);
    if (free_new)
        myc_free((void *)buf_new);
    return rc;
}

/* Fase 2: Contract/domain delta — myc contract-delta <before.c> <after.c>
 * Bandingkan kontrak //@ requires/ensures dua versi. Kelas hasil:
 * CLEAN (kontrak sama), NARROWED (requires bertambah = domain menyempit,
 * scope-laundering — wajib ditolak di repair transaction), WEAKENED
 * (ensures berkurang = kontrak melemah), CHANGED (perubahan lain).
 * Exit 1 untuk NARROWED/WEAKENED (preservation dilanggar), 0 selainnya. */
static int cmd_contract_delta(const char *before_path, const char *after_path)
{
    myc_source_input in;
    const char *buf_before, *buf_after;
    size_t      len_before, len_after;
    int         free_before = 0, free_after = 0;
    myc_error_code le;
    myc_contract_delta d;
    int i;

    memset(&in, 0, sizeof(in));
    in.kind = MYC_SOURCE_FILE;
    in.file_path = before_path;
    le = myc_source_load(&in, &buf_before, &len_before, &free_before);
    if (le != MYC_ERR_NONE) {
        fprintf(stderr, "myc: contract-delta: tidak dapat membaca %s (error=%s)\n",
                before_path, myc_error_name(le));
        return 2;
    }
    memset(&in, 0, sizeof(in));
    in.kind = MYC_SOURCE_FILE;
    in.file_path = after_path;
    le = myc_source_load(&in, &buf_after, &len_after, &free_after);
    if (le != MYC_ERR_NONE) {
        fprintf(stderr, "myc: contract-delta: tidak dapat membaca %s (error=%s)\n",
                after_path, myc_error_name(le));
        if (free_before)
            myc_free((void *)buf_before);
        return 2;
    }

    if (!myc_contract_delta_compare(buf_before, len_before,
                                    buf_after, len_after, &d)) {
        fprintf(stderr,
                "myc: contract-delta: gagal membandingkan (OOM) -- "
                "hasil TIDAK valid, jangan dipercaya\n");
        if (free_before)
            myc_free((void *)buf_before);
        if (free_after)
            myc_free((void *)buf_after);
        return 2;
    }
    printf("contract-delta: %s (before=%s after=%s)\n",
           myc_contract_delta_name(d.kind),
           before_path, after_path);
    for (i = 0; i < d.n_added_requires; i++)
        printf("  + requires %s  [domain menyempit]\n", d.added_requires[i]);
    for (i = 0; i < d.n_removed_requires; i++)
        printf("  - requires %s  [domain meluas]\n", d.removed_requires[i]);
    for (i = 0; i < d.n_added_ensures; i++)
        printf("  + ensures  %s  [jaminan bertambah]\n", d.added_ensures[i]);
    for (i = 0; i < d.n_removed_ensures; i++)
        printf("  - ensures  %s  [jaminan berkurang]\n", d.removed_ensures[i]);

    /* NARROWED / WEAKENED = preservation dilanggar (laundering/melemah). */
    i = (d.kind == MYC_DELTA_NARROWED || d.kind == MYC_DELTA_WEAKENED) ? 1 : 0;
    myc_contract_delta_free(&d);
    if (free_before)
        myc_free((void *)buf_before);
    if (free_after)
        myc_free((void *)buf_after);
    return i;
}

/* Fase 5 (SOL-13): myc sm <file> — ghost state machine dari deklarasi
 * //@ sm state/event/trans. Observasi NON-blocking: cetak machine + temuan
 * (sink/unreachable/no-recovery/undeclared/unused) + witness urutan event. */
static int cmd_sm(const char *path)
{
    myc_source_input in;
    const char *buf;
    size_t      len;
    int         needs_free = 0;
    myc_error_code le;
    myc_result res;

    memset(&in, 0, sizeof(in));
    in.kind = MYC_SOURCE_FILE;
    in.file_path = path;
    le = myc_source_load(&in, &buf, &len, &needs_free);
    if (le != MYC_ERR_NONE) {
        fprintf(stderr, "myc: sm: tidak dapat membaca %s (error=%s)\n",
                path, myc_error_name(le));
        return 2;
    }
    myc_result_init(&res);
    myc_sm_scan(buf, len, &res);
    if (res.sm_report)
        printf("%s", res.sm_report);
    else
        printf("state machine (SOL-13): tidak ada deklarasi //@ sm di "
               "%s\n", path);
    myc_result_free(&res);
    if (needs_free)
        myc_free((void *)buf);
    return 0;
}

/* Fase 5 (SOL-12): myc resource <file> — Resource Linearity Ledger.
 * Profil acquire/release (default + //@ resource ACQ -> REL) ditelusuri
 * per fungsi: leaked / double-release / transferred / unknown.
 * Observasi NON-blocking teks deterministik; verdict tak pernah turun. */
static int cmd_rsrc(const char *path)
{
    myc_source_input in;
    const char *buf;
    size_t      len;
    int         needs_free = 0;
    myc_error_code le;
    myc_result res;

    memset(&in, 0, sizeof(in));
    in.kind = MYC_SOURCE_FILE;
    in.file_path = path;
    le = myc_source_load(&in, &buf, &len, &needs_free);
    if (le != MYC_ERR_NONE) {
        fprintf(stderr, "myc: resource: tidak dapat membaca %s (error=%s)\n",
                path, myc_error_name(le));
        return 2;
    }
    myc_result_init(&res);
    myc_resource_scan(buf, len, &res);
    if (res.rsrc_report)
        printf("%s", res.rsrc_report);
    else
        printf("resource ledger (SOL-12): profil acquire/release di %s "
               "tanpa temuan\n", path);
    myc_result_free(&res);
    if (needs_free)
        myc_free((void *)buf);
    return 0;
}

/* Fase 5 (SOL-11): myc units <file> — Units / Shape / Provenance
 * contracts. Annotation //@ unit|shape|provenance|endian ditelusuri
 * lewat assignment; temuan unbound/unit-mismatch/shape-dim/dup.
 * Observasi NON-blocking teks deterministik; verdict tak pernah turun. */
static int cmd_units(const char *path)
{
    myc_source_input in;
    const char *buf;
    size_t      len;
    int         needs_free = 0;
    myc_error_code le;
    myc_result res;

    memset(&in, 0, sizeof(in));
    in.kind = MYC_SOURCE_FILE;
    in.file_path = path;
    le = myc_source_load(&in, &buf, &len, &needs_free);
    if (le != MYC_ERR_NONE) {
        fprintf(stderr, "myc: units: tidak dapat membaca %s (error=%s)\n",
                path, myc_error_name(le));
        return 2;
    }
    myc_result_init(&res);
    myc_units_scan(buf, len, &res);
    if (res.units_report)
        printf("%s", res.units_report);
    else
        printf("units (SOL-11): annotation %s tanpa temuan\n", path);
    myc_result_free(&res);
    if (needs_free)
        myc_free((void *)buf);
    return 0;
}

/* Fase 7 (#2029, DS-14): myc eig <file> [--profile <id>] [--budget-ms N]
 * [--unchanged] [--json] — Expected-Information-Gain scheduler.
 * Jalankan check penuh (compile gate) -> frontier + observasi -> rekomendasi
 * eksperimen terurut skor expected_value = P(new_evidence) x severity x
 * scope / (time_cost x token_cost); prior tabel deterministik yang
 * dikalibrasi dari ledger SOL-21 (rule `eig-<slug>`) + profil SOL-20
 * (--profile). Observasi NON-blocking murni: verdict tidak pernah berubah. */
static int cmd_eig(const char *path, const char *profile_id,
                   int budget_ms, int source_changed, int as_json,
                   const char *argv0)
{
    myc_request req;
    myc_result  res;
    myc_frontier_set fs;
    myc_experiment_set exps;
    myc_eig_set eig;
    myc_eig_input in;
    char *js = NULL;
    char *exe_dir = NULL;
    int rc = 0;

    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_FILE;
    req.input.file_path = path;
    req.no_cache = 1;   /* deterministik: selalu jalankan pipeline penuh */
    req.run_lint = 1;
    exe_dir = myc_exe_dirname(argv0);
    req.checked_header_dir = exe_dir;

    myc_result_init(&res);
    myc_run(&req, &res);
    myc_free(exe_dir);
    if (res.verdict == MC_ERROR) {
        fprintf(stderr, "myc: eig: gagal memeriksa %s (error=%s)\n",
                path, myc_error_name(res.err));
        rc = 2;
        myc_result_free(&res);
        return rc;
    }

    memset(&fs, 0, sizeof(fs));
    memset(&exps, 0, sizeof(exps));
    memset(&eig, 0, sizeof(eig));
    myc_frontier_build(&res, &fs);
    myc_observation_to_experiment(&res, &exps);
    memset(&in, 0, sizeof(in));
    in.profile_id = profile_id;
    in.source_changed = source_changed;
    in.budget_time_ms = budget_ms;
    myc_eig_plan(&fs, &exps, &in, &eig);

    /* Wire ringkasan ke myc_result (pola cmd_sm/cmd_units: report di arena
     * hasil + counts; dipakai replay cache di masa depan). */
    res.eig_ran = 1;
    res.eig_recommendations = eig.count;
    res.eig_calibrated_rules = eig.calibrated_rules;
    res.eig_within_budget = eig.within_budget_count;
    res.eig_profile_used = eig.profile_used;
    res.eig_top_expected_value =
        eig.count > 0 ? eig.items[0].expected_value : 0;
    if (eig.report)
        res.eig_report = myc_result_arena_dup(&res, eig.report, 0);

    if (as_json) {
        js = myc_eig_json(&eig);
        if (js) {
            printf("%s\n", js);
            myc_free(js);
        }
    } else if (res.eig_report) {
        printf("%s", res.eig_report);
    } else {
        printf("eig scheduler (Fase 7, DS-14): tidak ada rekomendasi\n");
    }

    myc_eig_free(&eig);
    myc_experiment_free(&exps);
    myc_frontier_free(&fs);
    myc_result_free(&res);
    return rc;
}

/* Fase 7 (SOL-10): myc compare-candidates <baseline.c> <c1.c> [c2.c ...]
 * Candidate Tournament dengan Pareto Frontier. Menilai tiap kandidat pada
 * dimensi terukur deterministik (hard_gate/findings/obligations_lost/churn/
 * verification_cost/runtime_proxy/portability/readability; stack_impact =
 * UNMEASURED v1, gap terlihat). Frontier = TIDAK didominasi pada dimensi
 * yang terukur (anti-overclaim: bukan klaim "terbaik umum"; harness/user
 * memilih final). NON-blocking observasi; exit 0. */
static int cmd_candidates(const char *baseline, const char *const *cands,
                          int ncands, int as_json, const char *argv0)
{
    myc_candidate_set cs;
    myc_result wr;
    char *js = NULL;
    char *exe_dir = NULL;
    int rc = 0;

    memset(&cs, 0, sizeof(cs));
    exe_dir = myc_exe_dirname(argv0);
    if (myc_candidate_tournament(baseline, cands, ncands, exe_dir,
                                 &cs) != 0) {
        fprintf(stderr, "%s",
                cs.report ? cs.report : "compare-candidates: gagal\n");
        myc_free(exe_dir);
        myc_candidate_free(&cs);
        return 2;
    }
    myc_free(exe_dir);

    /* Wire ringkasan ke myc_result (pola cmd_eig/cmd_sm/cmd_units: report
     * di arena + counts; dipakai replay cache di masa depan). */
    myc_result_init(&wr);
    wr.cand_ran = 1;
    wr.cand_candidates = cs.ncandidates;
    wr.cand_frontier = cs.frontier_count;
    if (cs.report)
        wr.cand_report = myc_result_arena_dup(&wr, cs.report, 0);
    myc_result_free(&wr);

    if (as_json) {
        js = myc_candidate_json(&cs);
        if (js) {
            printf("%s\n", js);
            myc_free(js);
        }
    } else if (cs.report) {
        printf("%s", cs.report);
    } else {
        printf("compare-candidates: tanpa laporan\n");
    }

    myc_candidate_free(&cs);
    return rc;
}

/* --- Fase 5 (SOL-14): ABI/FFI Surface Certificate --- */
static int cmd_abi_load(const char *path, const char **buf, size_t *len,
                        int *needs_free)
{
    myc_source_input in;
    myc_error_code le;

    memset(&in, 0, sizeof(in));
    in.kind = MYC_SOURCE_FILE;
    in.file_path = path;
    *needs_free = 0;
    le = myc_source_load(&in, buf, len, needs_free);
    if (le != MYC_ERR_NONE) {
        fprintf(stderr, "myc: abi: tidak dapat membaca %s (error=%s)\n",
                path, myc_error_name(le));
        return -1;
    }
    return 0;
}

static int cmd_abi_snapshot(const char *path, const char *cc)
{
    const char *buf = NULL;
    size_t      len = 0;
    int         nf = 0;
    myc_result  res;

    if (cmd_abi_load(path, &buf, &len, &nf) != 0)
        return 2;
    myc_result_init(&res);
    myc_abi_snapshot(buf, len, cc, &res);
    if (res.abi_snapshot)
        printf("%s", res.abi_snapshot);
    else
        printf("abi: tanpa snapshot (observasi non-blocking)\n");
    myc_result_free(&res);
    if (nf)
        myc_free((void *)buf);
    return 0;
}

static int cmd_abi_diff(const char *old_path, const char *new_path)
{
    const char *oa = NULL, *na = NULL;
    size_t      ol = 0, nl = 0;
    int         of = 0, nf = 0;
    myc_result  res;
    int         changed;

    if (cmd_abi_load(old_path, &oa, &ol, &of) != 0)
        return 2;
    if (cmd_abi_load(new_path, &na, &nl, &nf) != 0) {
        if (of)
            myc_free((void *)oa);
        return 2;
    }
    myc_result_init(&res);
    myc_abi_delta(oa, na, &res);
    printf("abi delta: %d perubahan%s (baris HEADER sha diabaikan)\n",
           res.abi_n_delta,
           res.abi_changed ? " -- ABI BERUBAH" : " -- sama");
    if (res.abi_delta)
        printf("%s", res.abi_delta);
    changed = res.abi_changed;
    myc_result_free(&res);
    if (of)
        myc_free((void *)oa);
    if (nf)
        myc_free((void *)na);
    return changed ? 1 : 0;
}

static int cmd_abi_pair(const char *a_path, const char *b_path)
{
    const char *a = NULL, *b = NULL;
    size_t      al = 0, bl = 0;
    int         af = 0, bf = 0;
    myc_result  ra, rb, rd;
    int         changed;

    if (cmd_abi_load(a_path, &a, &al, &af) != 0)
        return 2;
    if (cmd_abi_load(b_path, &b, &bl, &bf) != 0) {
        if (af)
            myc_free((void *)a);
        return 2;
    }
    myc_result_init(&ra);
    myc_result_init(&rb);
    myc_result_init(&rd);
    myc_abi_snapshot(a, al, NULL, &ra);
    myc_abi_snapshot(b, bl, NULL, &rb);
    myc_abi_delta(ra.abi_snapshot, rb.abi_snapshot, &rd);
    printf("abi: %s vs %s -- %d perubahan%s\n", a_path, b_path,
           rd.abi_n_delta, rd.abi_changed ? " (ABI BERUBAH)" : " (sama)");
    if (rd.abi_delta)
        printf("%s", rd.abi_delta);
    changed = rd.abi_changed;
    myc_result_free(&ra);
    myc_result_free(&rb);
    myc_result_free(&rd);
    if (af)
        myc_free((void *)a);
    if (bf)
        myc_free((void *)b);
    return changed ? 1 : 0;
}

static int cmd_prompt(const char *path, const char *pack_dir, int no_pack)
{
    myc_source_input in;
    const char *buf;
    size_t      len;
    int         needs_free;
    myc_error_code le;
    myc_pack_info info;
    int         prc;
    char       *prompt;

    memset(&in, 0, sizeof(in));
    in.kind = MYC_SOURCE_FILE;
    in.file_path = path;
    le = myc_source_load(&in, &buf, &len, &needs_free);
    if (le != MYC_ERR_NONE) {
        fprintf(stderr, "myc: prompt: tidak dapat membaca %s (error=%s)\n",
                path, myc_error_name(le));
        return 1;
    }
    /* Project-local pack: myc.prompt.md + myc.spec.json (Fase 7).
     * spec.json ADA tapi invalid = fail-fast exit 2 (pola scenario). */
    prc = myc_pack_load(pack_dir, no_pack, &info);
    if (prc == -1) {
        fprintf(stderr,
                "myc: prompt: %s invalid (skema: version=1, name wajib, "
                "domain opsional; rules/allow_headers/deny_functions = "
                "array string, batas jumlah/panjang sesuai prompt.h)\n",
                MYC_PACK_SPEC_FILE);
        if (needs_free)
            myc_free((void *)buf);
        return 2;
    }
    if (prc == -2) {
        fprintf(stderr, "myc: prompt: gagal membaca pack proyek (OOM/IO)\n");
        if (needs_free)
            myc_free((void *)buf);
        return 1;
    }
    prompt = myc_prompt_build_packed(buf, len, &info);
    myc_free(info.prompt_text);
    if (needs_free)
        myc_free((void *)buf);
    if (!prompt) {
        fprintf(stderr, "myc: prompt: gagal membangun prompt (OOM)\n");
        return 1;
    }
    printf("%s", prompt);
    myc_free(prompt);
    return 0;
}

int main(int argc, char **argv)
{
    myc_request req;
    myc_result  res;
    int         context_budget_tokens = 0;
    int         is_context = 0;
    const char *profile_id = NULL;   /* Fase 7 (SOL-20): --profile / env */
    int         use_calibrate = 0;       /* Fase 7 (SOL-21): --calibrate */
    myc_pack_info pinfo;                 /* Fase 7 (DS-15 wiring): pack
                                            proyek lokal utk --agent & context */
    int         pinfo_loaded = 0;

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
    /* D4 (DS-15): myc prompt <file.c> [--pack-dir DIR] [--no-pack]
     * system-prompt snippet + project-local pack (Fase 7, item terakhir). */
    if (strcmp(argv[1], "prompt") == 0) {
        const char *ppack_dir = NULL;
        int         pno_pack = 0;
        int         pi;
        if (argc < 3) {
            fprintf(stderr, "myc: prompt membutuhkan argumen file.c\n");
            return 2;
        }
        for (pi = 3; pi < argc; pi++) {
            if (strcmp(argv[pi], "--pack-dir") == 0 && pi + 1 < argc) {
                ppack_dir = argv[pi + 1];
                pi++;
            } else if (strcmp(argv[pi], "--no-pack") == 0) {
                pno_pack = 1;
            } else {
                fprintf(stderr, "myc: prompt: flag tidak dikenal: %s\n",
                        argv[pi]);
                return 2;
            }
        }
        return cmd_prompt(argv[2], ppack_dir, pno_pack);
    }

    /* A4 (DS-04): myc compare <ref.c> <new.c> [func...]. */
    if (strcmp(argv[1], "compare") == 0) {
        if (argc < 4) {
            fprintf(stderr, "myc: compare membutuhkan ref.c dan new.c\n");
            return 2;
        }
        return cmd_compare(argv[2], argv[3], argv + 4, argc - 4);
    }

    /* Fase 2: myc contract-delta <before.c> <after.c> — delta kontrak/domain. */
    if (strcmp(argv[1], "contract-delta") == 0) {
        if (argc < 4) {
            fprintf(stderr,
                    "myc: contract-delta membutuhkan before.c dan after.c\n");
            return 2;
        }
        return cmd_contract_delta(argv[2], argv[3]);
    }

    /* Fase 5 (SOL-13): myc sm <file> — ghost state machine dari //@ sm. */
    if (strcmp(argv[1], "sm") == 0) {
        if (argc < 3) {
            fprintf(stderr, "myc: sm membutuhkan file\n");
            return 2;
        }
        return cmd_sm(argv[2]);
    }

    /* Fase 5 (SOL-12): myc resource <file> — Resource Linearity Ledger. */
    if (strcmp(argv[1], "resource") == 0) {
        if (argc < 3) {
            fprintf(stderr, "myc: resource membutuhkan file\n");
            return 2;
        }
        return cmd_rsrc(argv[2]);
    }

    /* Fase 5 (SOL-11): myc units <file> — Units/Shape/Provenance. */
    if (strcmp(argv[1], "units") == 0) {
        if (argc < 3) {
            fprintf(stderr, "myc: units membutuhkan file\n");
            return 2;
        }
        return cmd_units(argv[2]);
    }

    /* Fase 7 (#2029/DS-14): myc eig <file> [--profile <id>] [--budget-ms N]
     * [--unchanged] [--json] — Expected-Information-Gain scheduler. */
    if (strcmp(argv[1], "eig") == 0) {
        const char *eig_profile = NULL;
        int eig_budget = 0;
        int eig_changed = 1;
        int eig_json = 0;
        int ei;
        if (argc < 3) {
            fprintf(stderr, "myc: eig membutuhkan file\n");
            return 2;
        }
        for (ei = 3; ei < argc; ei++) {
            if (strcmp(argv[ei], "--profile") == 0 && ei + 1 < argc) {
                eig_profile = argv[ei + 1];
                if (!myc_profile_id_valid(eig_profile)) {
                    fprintf(stderr,
                            "myc: eig --profile id invalid (charset "
                            "[A-Za-z0-9._-], panjang <= 63)\n");
                    return 2;
                }
                ei++;
            } else if (strcmp(argv[ei], "--budget-ms") == 0 &&
                       ei + 1 < argc) {
                if (!parse_int_arg(argv[ei + 1], &eig_budget) ||
                    eig_budget < 0) {
                    fprintf(stderr,
                            "myc: eig --budget-ms harus bilangan >= 0\n");
                    return 2;
                }
                ei++;
            } else if (strcmp(argv[ei], "--unchanged") == 0) {
                eig_changed = 0;
            } else if (strcmp(argv[ei], "--json") == 0) {
                eig_json = 1;
            } else {
                fprintf(stderr, "myc: eig: flag tidak dikenal: %s\n",
                        argv[ei]);
                return 2;
            }
        }
        return cmd_eig(argv[2], eig_profile, eig_budget, eig_changed,
                       eig_json, argv[0]);
    }

    /* Fase 7 (SOL-10): myc compare-candidates <base.c> <c1.c> [c2.c ...]
     * Candidate Tournament dengan Pareto Frontier (--json). */
    if (strcmp(argv[1], "compare-candidates") == 0) {
        const char *cands[MYC_MAX_CANDIDATES - 1];
        int cand_json = 0;
        int nc = 0;
        int k;
        if (argc < 4) {
            fprintf(stderr,
                    "myc: compare-candidates membutuhkan baseline.c dan "
                    "minimal satu kandidat\n");
            return 2;
        }
        for (k = 3; k < argc; k++) {
            if (argv[k][0] == '-' && argv[k][1] == '-') {
                if (strcmp(argv[k], "--json") == 0) {
                    cand_json = 1;
                } else {
                    fprintf(stderr,
                            "myc: compare-candidates: flag tidak dikenal: "
                            "%s\n", argv[k]);
                    return 2;
                }
            } else {
                if (nc >= MYC_MAX_CANDIDATES - 1) {
                    fprintf(stderr,
                            "myc: compare-candidates: maksimal %d kandidat\n",
                            MYC_MAX_CANDIDATES - 1);
                    return 2;
                }
                cands[nc++] = argv[k];
            }
        }
        if (nc < 1) {
            fprintf(stderr,
                    "myc: compare-candidates membutuhkan minimal satu "
                    "kandidat\n");
            return 2;
        }
        return cmd_candidates(argv[2], cands, nc, cand_json, argv[0]);
    }

    /* Fase 7 (SOL-20): myc profile list|show <id>|reset <id> —
     * Model/Harness Error Fingerprint (opt-in, lokal, tanpa source). */
    if (strcmp(argv[1], "profile") == 0) {
        char buf[4096];
        int  rc;
        if (argc < 3) {
            fprintf(stderr, "myc: profile membutuhkan `list`, `show <id>`, "
                            "atau `reset <id>`\n");
            return 2;
        }
        if (strcmp(argv[2], "list") == 0) {
            rc = myc_profile_list(buf, sizeof(buf));
            printf("%s", buf);
            return rc;
        }
        if (strcmp(argv[2], "show") == 0) {
            if (argc < 4) {
                fprintf(stderr, "myc: profile show membutuhkan <id>\n");
                return 2;
            }
            rc = myc_profile_show(argv[3], buf, sizeof(buf));
            if (rc == -2) {
                fprintf(stderr, "myc: id profile invalid\n");
                return 2;
            }
            if (rc == -1) {
                fprintf(stderr, "myc: profile tak ada: %s\n", argv[3]);
                return 1;
            }
            printf("%s", buf);
            return 0;
        }
        if (strcmp(argv[2], "reset") == 0) {
            if (argc < 4) {
                fprintf(stderr, "myc: profile reset membutuhkan <id>\n");
                return 2;
            }
            rc = myc_profile_reset(argv[3]);
            if (rc == -2) {
                fprintf(stderr, "myc: id profile invalid\n");
                return 2;
            }
            if (rc == -1) {
                fprintf(stderr, "myc: profile tak ada: %s\n", argv[3]);
                return 1;
            }
            printf("profile %s direset\n", argv[3]);
            return 0;
        }
        fprintf(stderr, "myc: profile membutuhkan `list`, `show <id>`, "
                        "atau `reset <id>`\n");
        return 2;
    }

    /* Fase 7 (SOL-21): myc calibrate mark <rule> <outcome> [--match <fragmen>]
     * | show <rule> | list | reset [rule] — Trust Calibration Ledger
     * (opt-in, lokal, tanpa source). */
    if (strcmp(argv[1], "calibrate") == 0) {
        char buf[8192];
        int  rc;
        if (argc < 3) {
            fprintf(stderr, "myc: calibrate membutuhkan `mark <rule> <outcome> [--match <fragmen>]`, "
                            "`show <rule>`, `list`, atau `reset [rule]`\n");
            return 2;
        }
        if (strcmp(argv[2], "mark") == 0) {
            if (argc < 5) {
                fprintf(stderr, "myc: calibrate mark membutuhkan <rule> <outcome> [--match <fragmen>]\n");
                return 2;
            }
            const char *match = NULL;
            if (argc >= 7 && strcmp(argv[5], "--match") == 0)
                match = argv[6];
            rc = myc_calib_mark(argv[3], argv[4], match);
            if (rc == -2) {
                fprintf(stderr, "myc: rule id invalid atau outcome tidak dikenal\n");
                return 2;
            }
            printf("rule %s: %s (%lld)\n", argv[3], argv[4], 1LL);
            return 0;
        }
        if (strcmp(argv[2], "show") == 0) {
            if (argc < 4) {
                fprintf(stderr, "myc: calibrate show membutuhkan <rule>\n");
                return 2;
            }
            rc = myc_calib_show(argv[3], buf, sizeof(buf));
            if (rc == -2) {
                fprintf(stderr, "myc: rule id invalid\n");
                return 2;
            }
            if (rc == -1) {
                fprintf(stderr, "myc: rule tidak ada: %s\n", argv[3]);
                return 1;
            }
            printf("%s", buf);
            return 0;
        }
        if (strcmp(argv[2], "list") == 0) {
            rc = myc_calib_list(buf, sizeof(buf));
            printf("%s", buf);
            return 0;
        }
        if (strcmp(argv[2], "reset") == 0) {
            const char *rule = (argc >= 4) ? argv[3] : NULL;
            rc = myc_calib_reset(rule);
            if (rc == -2) {
                fprintf(stderr, "myc: rule id invalid\n");
                return 2;
            }
            if (rc == -1) {
                if (rule)
                    fprintf(stderr, "myc: rule tidak ada: %s\n", rule);
                else
                    fprintf(stderr, "myc: ledger kosong\n");
                return 1;
            }
            if (rule)
                printf("rule %s direset\n", rule);
            else
                printf("ledger direset\n");
            return 0;
        }
        fprintf(stderr, "myc: calibrate membutuhkan `mark <rule> <outcome> [--match <fragmen>]`, "
                        "`show <rule>`, `list`, atau `reset [rule]`\n");
        return 2;
    }

    /* Fase 5 (SOL-14): myc abi snapshot|diff|<f1.c> <f2.c> — ABI/FFI
     * Surface Certificate (observasi NON-blocking). */
    if (strcmp(argv[1], "abi") == 0) {
        if (argc >= 4 && strcmp(argv[2], "snapshot") == 0) {
            const char *cc = NULL;
            if (argc >= 6 && strcmp(argv[4], "--cc") == 0)
                cc = argv[5];
            return cmd_abi_snapshot(argv[3], cc);
        }
        if (argc >= 5 && strcmp(argv[2], "diff") == 0)
            return cmd_abi_diff(argv[3], argv[4]);
        if (argc >= 4)
            return cmd_abi_pair(argv[2], argv[3]);
        fprintf(stderr, "myc: abi membutuhkan: snapshot <file> [--cc X] | "
                        "diff <old.txt> <new.txt> | <file1.c> <file2.c>\n");
        return 2;
    }

    /* Fase 6 (Self-Challenge): myc regression list | run. */
    if (strcmp(argv[1], "regression") == 0) {
        if (argc >= 3 && strcmp(argv[2], "list") == 0)
            return myc_regress_list(stdout);
        if (argc >= 3 && strcmp(argv[2], "run") == 0)
            return myc_regress_run(stdout,
                                   argc >= 4 ? argv[3] : NULL);
        fprintf(stderr,
                "myc: regression membutuhkan `list` atau `run [file.c]`\n");
        return 2;
    }

    /* Fase 6 (Self-Challenge): myc audit-tests -- kualitas corpus test. */
    if (strcmp(argv[1], "audit-tests") == 0) {
        return myc_testaudit_report(stdout);
    }

    /* Fase 6 (Self-Challenge): myc canary list | run [backend]. */
    if (strcmp(argv[1], "canary") == 0) {
        int nc = 0;
        int nback = 0;
        int i;
        const myc_canary *t;
        const char *want = NULL;
        if (argc >= 3 && strcmp(argv[2], "list") == 0) {
            myc_canary_backends(&nback);
            t = myc_canary_table(&nc);
            printf("canary swarm: %d canary untuk %d backend\n\n",
                   nc, nback);
            for (i = 0; i < nc; i++) {
                if (i == 0 || strcmp(t[i].backend, t[i - 1].backend) != 0)
                    printf("  [%s]\n", t[i].backend);
                printf("      %-28s %s\n", t[i].name, t[i].desc);
            }
            return 0;
        }
        if (argc >= 3 && strcmp(argv[2], "run") == 0) {
            if (argc >= 4)
                want = argv[3];
            return myc_canary_run(want, stdout);
        }
        fprintf(stderr, "myc: canary membutuhkan `list` atau `run [backend]`\n");
        return 2;
    }

    /* PR-017 (P5-T01/P5-T02): myc backends [--canary] — backend
     * qualification registry: tier kebijakan + identitas exact (path +
     * versi) per backend + status canary. `--canary` menjalankan canary
     * per backend (mahal). NON-blocking: registry adalah laporan, verdict
     * target tidak terpengaruh. */
    if (strcmp(argv[1], "backends") == 0) {
        int run_canary = 0;
        int bi;
        for (bi = 2; bi < argc; bi++) {
            if (strcmp(argv[bi], "--canary") == 0)
                run_canary = 1;
            else {
                fprintf(stderr, "myc: backends: flag tak dikenal: %s\n",
                        argv[bi]);
                return 2;
            }
        }
        return myc_backends_report(stdout, run_canary);
    }

    /* PR-018 (P7-T01): myc limits [--json] — resource limits (tabel
     * kebenaran + kelas enforcement HARD/soft). NON-blocking: laporan
     * observasi, verdict target tidak terpengaruh. Flag tak dikenal
     * fail-fast exit 2 (pola backends/scenario). */
    if (strcmp(argv[1], "limits") == 0) {
        int want_json = 0;
        int li;
        for (li = 2; li < argc; li++) {
            if (strcmp(argv[li], "--json") == 0)
                want_json = 1;
            else {
                fprintf(stderr, "myc: limits: flag tak dikenal: %s\n",
                        argv[li]);
                return 2;
            }
        }
        if (want_json)
            return myc_limits_report_json(stdout);
        return myc_limits_report(stdout);
    }

    /* C5 (DS-12): myc scenario list | info <name>. */
    if (strcmp(argv[1], "scenario") == 0) {
        char buf[2048];
        int  rc;
        if (argc < 3 || (strcmp(argv[2], "list") != 0 &&
                         strcmp(argv[2], "info") != 0)) {
            fprintf(stderr, "myc: scenario membutuhkan `list` atau "
                            "`info <name>\n");
            return 2;
        }
        if (strcmp(argv[2], "info") == 0 && argc < 4) {
            fprintf(stderr, "myc: scenario info membutuhkan nama profil\n");
            return 2;
        }
        if (strcmp(argv[2], "list") == 0)
            rc = myc_scenario_list(NULL, buf, sizeof(buf));
        else
            rc = myc_scenario_info(argv[3], NULL, buf, sizeof(buf));
        if (rc == -2) {
            fprintf(stderr, "myc: profil scenario (scenarios.json) "
                            "invalid\n");
            return 1;
        }
        if (rc != 0) {
            fprintf(stderr, "myc: scenario tak dikenal: %s\n", argv[3]);
            return 1;
        }
        printf("%s", buf);
        return 0;
    }

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
    /* Fase 7 (SOL-20): fingerprint opt-in diidentifikasi via flag
     * --profile <id> ATAU env MYC_PROFILE_ID (flag menang atas env). */
    profile_id = NULL;
    {
        const char *pe = getenv("MYC_PROFILE_ID");
        if (pe && *pe && myc_profile_id_valid(pe))
            profile_id = pe;
    }
    /* Fase 7 (SOL-21): calibration opt-in via --calibrate atau env MYC_CALIBRATE. */
    use_calibrate = 0;
    {
        const char *ce = getenv("MYC_CALIBRATE");
        if (ce && *ce && (strcmp(ce, "1") == 0 || strcmp(ce, "true") == 0))
            use_calibrate = 1;
    }

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
            } else if (strcmp(argv[i], "--watch-diff") == 0 ||
                       strcmp(argv[i], "--delta") == 0) {
                /* IDE-6 (T5, qwen-review): fast inner loop per-fungsi.
                 * Output-only: delta assurance terstruktur (fungsi
                 * berubah/identik/baru/hilang/dependents vs baseline
                 * cache) + timing; TIDAK masuk scenario hash (verdict
                 * TIDAK berubah, NON-blocking penuh). `--delta` alias
                 * untuk perintah yang sudah disarankan prompt.c. */
                req.watch_diff = 1; known = 1;
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
            } else if (strcmp(argv[i], "--exhaustive") == 0) {
                /* Fase 5 A3: small-domain exhaustive proof. */
                req.exhaustive = 1; known = 1;
            } else if (strcmp(argv[i], "--stack") == 0) {
                /* Fase 5 C2: stack budget analyzer (DS-10). */
                req.stack = 1; known = 1;
            } else if (strcmp(argv[i], "--stack-budget") == 0) {
                /* Fase 5 C2: budget stack target (bytes). */
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --stack-budget membutuhkan "
                                    "argumen (bytes, mis. 4096)\n");
                    return 2;
                }
                req.stack = 1;
                req.stack_budget = atoi(argv[++i]);
                known = 1;
            } else if (strcmp(argv[i], "--abi") == 0) {
                /* Fase 5 (SOL-14): ABI/FFI Surface Certificate. */
                req.abi = 1; known = 1;
            } else if (strcmp(argv[i], "--fuzz") == 0) {
                /* Fase 5 D1: fuzz-lite gate (DS-13). */
                req.fuzz = 1;
                known = 1;
            } else if (strcmp(argv[i], "--fuzz-iters") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --fuzz-iters membutuhkan "
                                    "argumen (loop per fungsi)\n");
                    return 2;
                }
                req.fuzz = 1;
                req.fuzz_iters = atoi(argv[++i]);
                known = 1;
            } else if (strcmp(argv[i], "--fuzz-seed") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --fuzz-seed membutuhkan "
                                    "argumen (seed reproduksibel)\n");
                    return 2;
                }
                req.fuzz = 1;
                req.fuzz_seed = (unsigned)strtoul(argv[++i], NULL, 0);
                known = 1;
            } else if (strcmp(argv[i], "--mutate-audit") == 0) {
                /* Fase 5 B5: mutation-audited verification (DS-09). */
                req.mutate_audit = 1;
                known = 1;
            } else if (strcmp(argv[i], "--mutate-max") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --mutate-max membutuhkan "
                                    "argumen (budget mutan)\n");
                    return 2;
                }
                req.mutate_audit = 1;
                req.mutate_max = atoi(argv[++i]);
                known = 1;
            } else if (strcmp(argv[i], "--freestanding") == 0) {
                /* Fase 5 C1: mode C tanpa OS (firmware). */
                req.freestanding = 1;
                known = 1;
            } else if (strcmp(argv[i], "--scenario") == 0) {
                /* Fase 5 C5 (DS-12): scenario pack per domain; "auto"
                 * = D3 (tebak resep dari struktur source). */
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --scenario membutuhkan "
                                    "argumen (nama profil)\n");
                    return 2;
                }
                req.scenario = argv[++i];
                known = 1;
            } else if (strcmp(argv[i], "--scenario-file") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --scenario-file membutuhkan "
                                    "argumen (path profil JSON)\n");
                    return 2;
                }
                req.scenario_file = argv[++i];
                known = 1;
            } else if (strcmp(argv[i], "--profile") == 0) {
                /* Fase 7 (SOL-20): Model/Harness Error Fingerprint.
                 * Opt-in identifier harness/model. Bila id invalid =
                 * fail-fast (konsisten MYC-AUDIT-019). */
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --profile membutuhkan argumen "
                                    "(id model/harness, alias/hash)\n");
                    return 2;
                }
                if (!myc_profile_id_valid(argv[i + 1])) {
                    fprintf(stderr, "myc: --profile id invalid (charset "
                                    "[A-Za-z0-9._-], max %d)\n",
                            MYC_PROFILE_ID_MAX);
                    return 2;
                }
                profile_id = argv[i + 1];
                i++; known = 1;
            } else if (strcmp(argv[i], "--calibrate") == 0) {
                /* Fase 7 (SOL-21): Trust Calibration Ledger opt-in. Bila
                 * active, check meng-anotasi diagnostic yang merupakan
                 * rule yang dikalibrasi LOW/DISABLED (observasi, NON-blocking). */
                use_calibrate = 1;
                known = 1;
            } else if (strcmp(argv[i], "--matrix") == 0) {
                /* Fase 5 C4: target matrix bare metal (cross-compiler). */
                req.matrix = 1;
                known = 1;
            } else if (strcmp(argv[i], "--perturb") == 0) {
                /* Fase 6: environment perturbation -- determinisme lintas
                 * env (TZ/locale/PATH/HOME); NON-blocking observasi. */
                req.perturb = 1;
                known = 1;
            } else if (strcmp(argv[i], "--thread-probe") == 0) {
                /* Fase 6: concurrency probe -- lock-order statis + TSan
                 * runtime; NON-blocking observasi. */
                req.thread_probe = 1;
                known = 1;
            } else if (strcmp(argv[i], "--negative") == 0) {
                req.negative = 1; known = 1;
            } else if (strcmp(argv[i], "--require-complete") == 0) {
                req.require_complete = 1; known = 1;
            } else if (strcmp(argv[i], "--agent") == 0) {
                req.agent = 1; known = 1;
            } else if (strcmp(argv[i], "--pack-dir") == 0) {
                /* Fase 7 (DS-15 wiring): pack proyek lokal utk --agent
                 * dan context (myc.prompt.md + myc.spec.json). */
                if (i + 1 >= argc) {
                    fprintf(stderr,
                            "myc: --pack-dir membutuhkan argumen DIR\n");
                    myc_result_free(&res);
                    return 2;
                }
                myc_free(req.pack_dir);
                req.pack_dir = myc_strdup(argv[i + 1]);
                i++; known = 1;
            } else if (strcmp(argv[i], "--no-pack") == 0) {
                req.no_pack = 1; known = 1;
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
            } else if (strcmp(argv[i], "--agent-payload-cap") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "myc: --agent-payload-cap membutuhkan argumen BYTES\n");
                    myc_result_free(&res);
                    return 2;
                }
                if (!parse_int_arg(argv[i + 1], &req.agent_payload_cap)) {
                    fprintf(stderr, "myc: --agent-payload-cap: nilai bukan angka valid: %s\n",
                            argv[i + 1]);
                    myc_result_free(&res);
                    return 2;
                }
                /* Fase 7 (privacy/size): 0 = default MYC_AGENT_PAYLOAD_CAP
                 * (16384); 1024..MYC_MAX_AGENT_PAYLOAD_CAP_BYTES = override
                 * eksplisit. Di luar itu fail-fast (pola
                 * MYC_AUDIT-019/020); rentang sama dgn myc_request_validate
                 * (jalur API/MCP). */
                if (req.agent_payload_cap != 0 &&
                    (req.agent_payload_cap < MYC_MIN_AGENT_PAYLOAD_CAP_BYTES ||
                     req.agent_payload_cap > (int)MYC_MAX_AGENT_PAYLOAD_CAP_BYTES)) {
                    fprintf(stderr, "myc: --agent-payload-cap di luar rentang "
                                    "valid (0 atau 1024-%u): %d\n",
                            (unsigned)MYC_MAX_AGENT_PAYLOAD_CAP_BYTES,
                            req.agent_payload_cap);
                    myc_result_free(&res);
                    return 2;
                }
                i++;  /* konsumsi argumen nilai */
                known = 1;
            } else if (strcmp(argv[i], "--no-persist") == 0) {
                req.no_persist = 1;
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

    /* Fase 7 (privacy/size): --no-persist = tanpa jejak disk; kombinasinya
     * dengan fitur yang EKSPLISIT menulis ke disk = kontradiksi, fail-fast
     * (pola A1). Profil SOL-20 menulis .myc/profiles/<id>.json; repro
     * witness menulis .myc-witness/; require-assumptions-closed butuh
     * asumsi di-scan (yang dimatikan --no-persist) sehingga menjadi
     * trivially-closed -- semua ditolak. */
    if (req.no_persist && profile_id) {
        fprintf(stderr, "myc: --no-persist tidak dapat dipakai bersama "
                        "--profile\n");
        myc_result_free(&res);
        return 2;
    }
    if (req.no_persist && req.write_repro) {
        fprintf(stderr, "myc: --no-persist tidak dapat dipakai bersama "
                        "--write-repro (repro menulis .myc-witness/)\n");
        myc_result_free(&res);
        return 2;
    }
    if (req.no_persist && req.require_assumptions_closed) {
        fprintf(stderr, "myc: --no-persist tidak dapat dipakai bersama "
                        "--require-assumptions-closed (asumsi tidak di-scan)\n");
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
        /* C5/D3 (DS-12): terapkan scenario pack SEBELUM pipeline -- ia
         * mengubah request (mengaktifkan resep gate). auto membaca source
         * untuk menebak resep. Error profil/skenario = fail-fast. */
        if (req.scenario) {
            int serc = myc_scenario_apply(&req, req.scenario, src, len,
                                          req.scenario_file, &res);
            if (serc == -2) {
                fprintf(stderr, "myc: profil scenario invalid\n");
                myc_result_free(&res);
                return 1;
            }
            if (serc != 0) {
                fprintf(stderr, "myc: scenario tak dikenal: %s\n",
                        req.scenario);
                myc_result_free(&res);
                return 1;
            }
        }
        myc_run(&req, &res);
        /* Fase 7 (SOL-20): fingerprint opt-in. Selalu tercatat bila
         * --profile/env aktif (cache-hit tetap = permintaan check).
         * NON-blocking; gagal tulis tanpa dampak pada hasil/exit.
         * Fase 7 (privacy/size): --no-persist mematikan profil juga
         * (kontradiksi sudah fail-fast; guard ganda defensif). */
        if (profile_id && !req.no_persist)
            myc_profile_record(&res, profile_id);
        /* Fase 7 (SOL-21): Trust Calibration Ledger. Bila --calibrate/
         * env aktif, anotasi diagnostic yang merupakan rule dikalibrasi
         * LOW/DISABLED -- observasi NON-blocking, verdict TIDAK berubah
         * (trust rule 1-3). Cetak ke stderr sebagai evidence saja. */
        if (use_calibrate) {
            char cabuf[4096];
            int n = myc_calib_apply(&res, cabuf, sizeof(cabuf));
            if (n > 0) {
                fprintf(stderr, "[myc] calibration: %d diagnostic dicalibrate"
                        " (observation-only, verdict tidak berubah)\n%s",
                        n, cabuf);
            } else {
                fprintf(stderr, "[myc] calibration: tidak ada rule LOW/DISABLED"
                        " yang terpicu\n");
            }
        }
        /* --write-repro: tulis .myc-witness/ repro directory (Fase 1).
         * Harus sebelum free(src) karena membutuhkan source. */
        if (req.write_repro && res.witness) {
            char *repro_dir = myc_witness_write_repro(res.witness,
                                                      src, len,
                                                      req.cwd ? req.cwd : ".");
            if (repro_dir) {
                fprintf(stderr, "[myc] witness repro written to %s\n", repro_dir);
                myc_free(repro_dir);
            }
        }
        /* Fase 7 (DS-15 wiring): pack proyek lokal utk output --agent
         * dan paket context SOL-22. NON-blocking: pack hanya memperkaya
         * output, verdict TIDAK pernah berubah. spec.json ADA tapi
         * invalid = fail-fast exit 2 (pola cmd_prompt). Tidak masuk
         * cache key (output agent/context dibangun ulang dari res). */
        if (is_context || req.agent) {
            int prc = myc_pack_load(req.pack_dir, req.no_pack, &pinfo);
            if (prc == -1) {
                fprintf(stderr,
                        "myc: %s invalid (skema: version=1, name wajib, "
                        "domain opsional; rules/allow_headers/deny_functions "
                        "= array string, batas sesuai prompt.h)\n",
                        MYC_PACK_SPEC_FILE);
                if (needs_free)
                    myc_free((void *)src);
                myc_result_free(&res);
                return 2;
            }
            if (prc == -2) {
                fprintf(stderr,
                        "myc: gagal membaca pack proyek (OOM/IO)\n");
                if (needs_free)
                    myc_free((void *)src);
                myc_result_free(&res);
                return 1;
            }
            pinfo_loaded = 1;
        }
        /* SOL-22: paket context dibangun DI SINI karena butuh source
         * (sebelum free(src)). Murni derivasi hasil run; deterministik. */
        if (is_context) {
            char  ctx_hash[65];
            char *pkg = myc_context_build(&res, src, len, &req,
                                          pinfo_loaded ? &pinfo : NULL,
                                          req.tx_finding_id,
                                          context_budget_tokens > 0
                                              ? context_budget_tokens
                                              : MYC_CONTEXT_BUDGET_DEFAULT,
                                          ctx_hash);
            if (pkg) {
                printf("%s", pkg);
                myc_free(pkg);
            } else {
                fprintf(stderr, "myc: gagal membangun context paket\n");
                if (needs_free)
                    myc_free((void *)src);
                if (pinfo_loaded) {
                    myc_free(pinfo.prompt_text);
                    pinfo_loaded = 0;
                }
                myc_result_free(&res);
                return 1;
            }
        }
        /* NEMO-2: --agent butuh source untuk repair template; defer free. */
        {
            const char *agent_src = NULL;
            size_t      agent_len = 0;
            int         agent_free = 0;

            if (req.agent && !is_context) {
                agent_src = src;
                agent_len = len;
                agent_free = needs_free;
                needs_free = 0;
            }
            if (needs_free)
                myc_free((void *)src);

            if (is_context) {
                /* paket sudah dicetak di atas (membutuhkan source) */
            } else if (req.as_json)
                myc_report_json(&res);
            else if (req.json_summary)
                myc_report_json_summary(&res);
            else if (req.agent) {
                myc_report_agent(&res, pinfo_loaded ? &pinfo : NULL,
                                 agent_src, agent_len);
                if (agent_free)
                    myc_free((void *)agent_src);
            } else
                myc_report_text(&res);
        }
    }

    myc_result_free(&res);
    if (pinfo_loaded)
        myc_free(pinfo.prompt_text);
    myc_free(req.tx_finding_id);
    myc_budget_free(&req.budget);
    myc_free(req.assumption_acks);
    myc_free(req.tx_edit_region);
    myc_free(req.pack_dir);
    if (req.run_stdin)
        myc_free((void *)req.run_stdin);
    return res.verdict == MC_OK ? 0 : 1;
}

#endif /* MYC_NO_MAIN */
