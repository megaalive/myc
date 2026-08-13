/*
 * cache.c -- Incremental Evidence Cache (Fase 3, SOL-18).
 */
#include "cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "ledger.h"
#include "persist.h"
#include "policy.h"
#include "proc.h"
#include "sha256.h"

/* mkdir portabel (pola sama dengan driver.c/filc.c). */
#if defined(_WIN32)
#include <direct.h>
#define cache_mkdir(p) _mkdir(p)
#else
#include <sys/stat.h>
#define cache_mkdir(p) mkdir(p, 0700)
#endif

/* PR-013 (MYC-AUDIT-045, P3-T04): sidecar integrity hash dari file cache.
 * Berisi sha256 HEX atas byte MENTAH evidence_cache.json (64 hex). Ditulis
 * atomik SETELAH file cache; pembaca membandingkan hash byte file. */
#define MYC_CACHE_SHA_FILE ".myc/evidence_cache.sha256"

/* ------------------------------------------------------------------ */
/* Key + tool identity                                                 */
/* ------------------------------------------------------------------ */

/* Tool identity: versi gcc + clang (untuk memastikan cache tidak dipakai
 * bila toolchain berubah). Menjalankan `<exe> --version` via myc_tool_version;
 * non-blocking: gagal = string kosong (key tetap deterministik untuk input
 * yang sama, hanya kurang tool-version granularity). */
static void cache_tool_key(const myc_request *req, char *out, size_t cap)
{
    char *gcc = NULL;
    char *gcc_ver = NULL;
    char *clang = NULL;
    char *clang_ver = NULL;

    if (cap == 0)
        return;
    out[0] = '\0';

    gcc = myc_find_executable(req->gcc_program ? req->gcc_program : "gcc");
    if (gcc)
        gcc_ver = myc_tool_version(gcc);

    /* clang dipakai bila gate runtime/driver/metamorphic/divergence
     * diminta (divergence Fase 4 A2 membangun matriks dengan clang). */
    if (req->run || req->driver || req->metamorphic || req->divergence) {
        clang = myc_find_executable(
            req->clang_program ? req->clang_program : "clang");
        if (clang)
            clang_ver = myc_tool_version(clang);
    }

    snprintf(out, cap, "gcc:%s|clang:%s",
             gcc_ver ? gcc_ver : (gcc ? gcc : "?"),
             clang_ver ? clang_ver : (clang ? clang : "?"));

    myc_free(gcc);
    myc_free(gcc_ver);
    myc_free(clang);
    myc_free(clang_ver);
}

/* PR-011 (MYC-AUDIT-043): hash deterministik flag gate Fase 5/6 yang
 * MENGUBAH HASIL tetapi belum tercakup myc_ledger_build_scenario_hash
 * (lint, exhaustive, stack + stack_budget, fuzz + iters + seed,
 * mutate-audit + max, freestanding, matrix, abi, perturb, thread-probe).
 * Tanpa dimensi ini dua run dgn resep gate berbeda berbagi cache entry:
 * replay lintas-flag = stale/lossy (mis. --fuzz hit dari entry polos =
 * gate fuzz HILANG dari output; --exhaustive hit dari entry polos =
 * ex_* = 0; --stack --stack-budget beda = observasi stack stale). */
static void cache_gates2_hash(const myc_request *req, char out[33])
{
    sha256_ctx gctx;
    uint8_t    gmd[32];
    char       ghex[65];
    char       gbuf[512];
    int        gn = 0;

    gn += snprintf(gbuf + gn, sizeof(gbuf) - gn,
                   "lint=%d|exh=%d|stk=%d|stb=%d|fz=%d|fzi=%d|fzs=%u|mut=%d|"
                   "mutm=%d|free=%d|mat=%d|abi=%d|pert=%d|tp=%d",
                   req->run_lint, req->exhaustive, req->stack,
                   req->stack_budget, req->fuzz, req->fuzz_iters,
                   req->fuzz_seed, req->mutate_audit, req->mutate_max,
                   req->freestanding, req->matrix, req->abi, req->perturb,
                   req->thread_probe);
    if (gn >= (int)sizeof(gbuf))
        gn = (int)sizeof(gbuf) - 1;
    sha256_init(&gctx);
    sha256_update(&gctx, gbuf, (size_t)gn);
    sha256_final(&gctx, gmd);
    sha256_hex(gmd, 32, ghex);
    memcpy(out, ghex, 16);   /* potong eksplisit: hindari -Wformat-truncation */
    out[16] = '\0';
}

/* Key kanonik v2: sha256(source + scenario + tool + cwd + stdin +
 * timeout + output cap + header dir + flags gate Fase 5/6).
 *
 * Spesifikasi lengkap per dimensi: docs/cache-key.md (PR-011).
 * Perubahan v1→v2 (MYC-AUDIT-043): tambah `stdin` (--run-stdin mengubah
 * hasil gate run), `t` (timeout_ms), `o` (max_output_bytes), `hdir`
 * (checked_header_dir — myc_buf.h berbeda = hasil L4 berbeda), dan `g2`
 * (hash flags gate Fase 5/6 di atas). Entry v1 lama otomatis MISS pada
 * v2 (upgrade mulus — replay stale tidak pernah terjadi). */
static void cache_build_key(const myc_request *req,
                            const char *src, size_t srclen,
                            const char *tool_key, char out[65])
{
    char source_hex[65];
    char scenario[17];
    char stdin_hex[33];
    char gates2[33];
    char *scen_full;
    char buf[8192];
    int  n;

    sha256_hex(src, srclen, source_hex);

    scen_full = myc_ledger_build_scenario_hash(req, NULL);
    if (scen_full) {
        snprintf(scenario, sizeof(scenario), "%s", scen_full);
        myc_free(scen_full);
    } else {
        snprintf(scenario, sizeof(scenario), "?");
    }

    /* PR-011: --run-stdin mengubah PERILAKU program verifikasi → hasil
     * gate run berbeda; wajib jadi dimensi key (sebelumnya absen = dua
     * run dgn stdin berbeda berbagi entry = replay stale). */
    if (req->run_stdin && req->run_stdin_len > 0) {
        char sh[65];
        sha256_hex(req->run_stdin, req->run_stdin_len, sh);
        memcpy(stdin_hex, sh, 16);   /* potong eksplisit: hindari -Wformat-truncation */
        stdin_hex[16] = '\0';
    } else {
        snprintf(stdin_hex, sizeof(stdin_hex), "-");
    }

    cache_gates2_hash(req, gates2);

    n = snprintf(buf, sizeof(buf),
                 "v2|src:%s|scen:%s|tool:%s|cwd:%s|stdin:%s|t:%d|o:%d|"
                 "hdir:%s|g2:%s|",
                 source_hex, scenario, tool_key ? tool_key : "",
                 req->cwd ? req->cwd : "",
                 stdin_hex,
                 req->timeout_ms, req->max_output_bytes,
                 req->checked_header_dir ? req->checked_header_dir : "",
                 gates2);
    if (n < 0)
        n = 0;
    if ((size_t)n >= sizeof(buf))
        n = (int)sizeof(buf) - 1;
    sha256_hex(buf, (size_t)n, out);
}

/* ------------------------------------------------------------------ */
/* Persistence: .myc/evidence_cache.json                              */
/* ------------------------------------------------------------------ */

static void cache_write_all(const myc_cache_entry *entries, int count);

/* PR-013 (MYC-AUDIT-045, P3-T04): cache corruption recovery. Integritas
 * file diverifikasi via sidecar sha256 atas byte MENTAH (MYC_CACHE_SHA_FILE)
 * — bukan re-serialisasi JSON (teks backend bisa berisi byte non-UTF8 yang
 * tidak round-trip stabil). Entry yang lolos hash tetap divalidasi SEMANTIK
 * sebelum di-parse ke struct (fail-closed): truncated JSON, flip bit,
 * field asing, hash salah, entry duplikat, versi backend basi, timestamp
 * mustahil, state gate mustahil TIDAK boleh pernah di-replay sebagai
 * bukti. Entry korup dikarantina: dilewati, dihitung, file di-heal
 * (rewrite tanpa entry tsb), replay menjadi MISS -> pipeline menghitung
 * ulang (recompute). "Never crash and never trust it" (P3-T04). */

/* 64 karakter hex (sha256 hex). */
static int cache_hex64(const char *s)
{
    size_t i;
    if (!s || strlen(s) != 64)
        return 0;
    for (i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

/* Baca hex sha256 dari file sidecar. Return 1 bila 64-hex terbaca. */
static int cache_sidecar_read(char out[65])
{
    FILE *f;
    char tmp[96];
    size_t n;

    f = fopen(MYC_CACHE_SHA_FILE, "rb");
    if (!f)
        return 0;
    n = fread(tmp, 1, sizeof(tmp) - 1, f);
    fclose(f);
    if (n == 0)
        return 0;
    tmp[n] = '\0';
    while (n > 0 && (tmp[n - 1] == '\n' || tmp[n - 1] == '\r' ||
                     tmp[n - 1] == ' '))
        tmp[--n] = '\0';
    if (n != 64)
        return 0;
    memcpy(out, tmp, 65);
    out[64] = '\0';
    return cache_hex64(out);
}

/* Semantik: skema field wajib, enum di range (BUKAN di-clamp ke 0 = OK!),
 * state mustahil ditolak. Dijalankan SETELAH integritas byte file lolos
 * (sidecar): walau hash sah, nilai mustahil tetap dikarantina (anti
 * false-clean replay). */
static int cache_entry_semantic_ok(const json_value *e, char *why,
                                   size_t whycap)
{
    const char *key = json_get_str(e, "key");
    const char *src = json_get_str(e, "source");
    json_value *v;
    int64_t verdict, err;

    if (!key || !cache_hex64(key)) {
        snprintf(why, whycap, "key bukan sha256 hex64");
        return 0;
    }
    if (!src || !cache_hex64(src)) {
        snprintf(why, whycap, "source bukan sha256 hex64");
        return 0;
    }
    v = json_get(e, "verdict");
    if (!v || v->type != JSON_NUM || v->num < 0 || v->num > MC_INCONCLUSIVE) {
        snprintf(why, whycap, "verdict hilang/out-of-range");
        return 0;
    }
    verdict = v->num;
    v = json_get(e, "err");
    if (!v || v->type != JSON_NUM || v->num < 0 ||
        v->num >= (int64_t)MYC_ERR_INTERNAL) {
        snprintf(why, whycap, "err hilang/out-of-range");
        return 0;
    }
    err = v->num;
    /* State mustahil: store menolak verdict MC_ERROR (hasil error bukan
     * bukti), jadi MC_ERROR + err NONE tidak mungkin pernah sah. */
    if (verdict == MC_ERROR && err == MYC_ERR_NONE) {
        snprintf(why, whycap, "state mustahil: MC_ERROR tanpa err");
        return 0;
    }
    v = json_get(e, "assurance");
    if (v && (v->type != JSON_NUM || v->num < 0 ||
              v->num > MYC_ASSURANCE_L5_FILC)) {
        snprintf(why, whycap, "assurance out-of-range");
        return 0;
    }
    v = json_get(e, "finding");
    if (v && (v->type != JSON_NUM || v->num < 0 ||
              v->num > MYC_FINDING_INCONCLUSIVE)) {
        snprintf(why, whycap, "finding out-of-range");
        return 0;
    }
    v = json_get(e, "completeness");
    if (v && (v->type != JSON_NUM || v->num < 0 ||
              v->num > MYC_COMPLETENESS_INCOMPLETE)) {
        snprintf(why, whycap, "completeness out-of-range");
        return 0;
    }
    v = json_get(e, "claim");
    if (v && (v->type != JSON_NUM || v->num < 0 ||
              v->num > MYC_CLAIM_UNVERIFIED)) {
        snprintf(why, whycap, "claim out-of-range");
        return 0;
    }
    /* Timestamp: duration_ms mustahil negatif / raksasa. */
    v = json_get(e, "duration_ms");
    if (v && (v->type != JSON_NUM || v->num < 0 ||
              v->num > ((int64_t)1 << 40))) {
        snprintf(why, whycap, "duration_ms mustahil");
        return 0;
    }
    /* Gates: id/status wajib di range bila ada (anti impossible gate state). */
    v = json_get(e, "gates");
    if (v) {
        size_t gi;
        if (v->type != JSON_ARR) {
            snprintf(why, whycap, "gates bukan array");
            return 0;
        }
        for (gi = 0; gi < v->len; gi++) {
            json_value *go = v->items[gi];
            json_value *gv;
            if (!go || go->type != JSON_OBJ)
                continue;
            gv = json_get(go, "id");
            if (gv && (gv->type != JSON_NUM || gv->num < 0 ||
                       gv->num >= (int64_t)MYC_GATE_COUNT)) {
                snprintf(why, whycap, "gate id out-of-range");
                return 0;
            }
            gv = json_get(go, "status");
            if (gv && (gv->type != JSON_NUM || gv->num < 0 ||
                       gv->num > MYC_GATE_COMPLETED_OBSERVATIONS)) {
                snprintf(why, whycap, "gate status out-of-range");
                return 0;
            }
        }
    }
    return 1;
}

static int cache_read_all(myc_cache_entry *out, int cap)
{
    FILE *f;
    long  sz;
    char *buf;
    json_value *root, *arr;
    int i, n = 0, qbad = 0;
    char qwhy[96];

    qwhy[0] = '\0';

    if (cap <= 0)
        return 0;
    f = fopen(MYC_CACHE_FILE, "rb");
    if (!f)
        return 0;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 32 * 1024 * 1024) {
        fclose(f);
        return 0;
    }
    buf = (char *)myc_malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return 0;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        myc_free(buf);
        fclose(f);
        return 0;
    }
    buf[sz] = '\0';
    fclose(f);

    /* PR-013 (MYC-AUDIT-045, P3-T04): integritas via sidecar sha256 atas
     * byte MENTAH file. Sidecar hilang/stale/tampered = seluruh file
     * di-ignore (fail-closed) -> replay MISS -> recompute. Hash atas byte
     * mentah (bukan re-serialisasi JSON) stabil untuk konten apa pun. */
    {
        char hex[65];
        char fhex[65];
        sha256_hex(buf, (size_t)sz, hex);
        if (!cache_sidecar_read(fhex) || strcmp(hex, fhex) != 0) {
            myc_free(buf);
            fprintf(stderr,
                    "myc: cache: %s corrupt (integrity sha256 mismatch) - "
                    "ignored; evidence recomputed\n", MYC_CACHE_FILE);
            return 0;
        }
    }

    if (!json_parse(buf, (size_t)sz, &root) || !root ||
        root->type != JSON_OBJ) {
        if (root)
            json_free(root);
        myc_free(buf);
        fprintf(stderr,
                "myc: cache: %s corrupt (JSON parse failed) - ignored; "
                "evidence recomputed\n", MYC_CACHE_FILE);
        return 0;
    }
    arr = json_get(root, "entries");
    if (!arr || arr->type != JSON_ARR) {
        /* Schema korup: file cache tanpa array entries (fail-closed). */
        json_free(root);
        myc_free(buf);
        fprintf(stderr,
                "myc: cache: %s corrupt (entries schema) - ignored; "
                "evidence recomputed\n", MYC_CACHE_FILE);
        return 0;
    }
    for (i = 0; i < (int)arr->len && n < cap; i++) {
        json_value *e = arr->items[i];
        json_value *v;
        myc_cache_entry *ce = &out[n];
        int k;

        if (!e || e->type != JSON_OBJ) {
            snprintf(qwhy, sizeof(qwhy), "entry bukan objek");
            qbad++;
            continue;
        }
        /* PR-013 (MYC-AUDIT-045, P3-T04): validasi semantik SEBELUM parse
         * (fail-closed) — integritas byte file sudah diverifikasi sidecar.
         * Entry mustahil dikarantina: dilewati, dihitung, file di-heal
         * setelah loop; replay MISS -> recompute. */
        if (!cache_entry_semantic_ok(e, qwhy, sizeof(qwhy))) {
            qbad++;
            continue;
        }
        /* Dedup: key sama = entry duplikat (pertahankan yang pertama). */
        v = json_get(e, "key");
        if (v && v->type == JSON_STR) {
            int di, dup = 0;
            for (di = 0; di < n; di++)
                if (strcmp(out[di].key_sha256, v->str) == 0) {
                    dup = 1;
                    break;
                }
            if (dup) {
                snprintf(qwhy, sizeof(qwhy), "duplicate key");
                qbad++;
                continue;
            }
        }
        memset(ce, 0, sizeof(*ce));

            v = json_get(e, "key");   if (v && v->type == JSON_STR) snprintf(ce->key_sha256, sizeof(ce->key_sha256), "%s", v->str);
            v = json_get(e, "source"); if (v && v->type == JSON_STR) snprintf(ce->source_sha256, sizeof(ce->source_sha256), "%s", v->str);
            v = json_get(e, "scenario"); if (v && v->type == JSON_STR) snprintf(ce->scenario_hash, sizeof(ce->scenario_hash), "%s", v->str);
            v = json_get(e, "tool");  if (v && v->type == JSON_STR) snprintf(ce->tool_key, sizeof(ce->tool_key), "%s", v->str);
            v = json_get(e, "cwd");   if (v && v->type == JSON_STR) snprintf(ce->cwd, sizeof(ce->cwd), "%s", v->str);
            v = json_get(e, "path");  if (v && v->type == JSON_STR) snprintf(ce->path, sizeof(ce->path), "%s", v->str);
            v = json_get(e, "receipt"); if (v && v->type == JSON_STR) snprintf(ce->receipt_sha256, sizeof(ce->receipt_sha256), "%s", v->str);
            v = json_get(e, "fingerprint"); if (v && v->type == JSON_STR) snprintf(ce->fingerprint, sizeof(ce->fingerprint), "%s", v->str);

            /* Enum di-clamp ke range valid (file cache = input eksternal;
             * nilai di luar range -> UNKNOWN/0, bukan UB di name-function). */
            /* MC_INCONCLUSIVE (10) adalah nilai TERAKHIR dari myc_verdict;
             * clamp salah memakai MC_DRIVER_VIOLATION (9) akan MENOLAK
             * verdict INCONCLUSIVE -> replay mengubahnya jadi OK (false-
             * clean). Kunci: batas atas harus nilai enum terakhir. */
            v = json_get(e, "verdict"); if (v && v->type == JSON_NUM && v->num >= 0 && v->num <= MC_INCONCLUSIVE) ce->verdict = (myc_verdict)v->num;
            v = json_get(e, "err");    if (v && v->type == JSON_NUM && v->num >= 0 && v->num < (int64_t)MYC_ERR_INTERNAL) ce->err = (myc_error_code)v->num;
            v = json_get(e, "assurance"); if (v && v->type == JSON_NUM && v->num >= 0 && v->num <= MYC_ASSURANCE_L5_FILC) ce->assurance = (myc_assurance)v->num;
            v = json_get(e, "finding"); if (v && v->type == JSON_NUM && v->num >= 0 && v->num <= MYC_FINDING_INCONCLUSIVE) ce->finding = (myc_finding)v->num;
            v = json_get(e, "completeness"); if (v && v->type == JSON_NUM && v->num >= 0 && v->num <= MYC_COMPLETENESS_INCOMPLETE) ce->completeness = (myc_completeness)v->num;
            v = json_get(e, "claim");  if (v && v->type == JSON_NUM && v->num >= 0 && v->num <= MYC_CLAIM_UNVERIFIED) ce->claim = (myc_claim_status)v->num;
            v = json_get(e, "duration_ms"); if (v && v->type == JSON_NUM) ce->duration_ms = (unsigned long long)v->num;

            v = json_get(e, "lint_obs"); if (v && v->type == JSON_NUM) ce->lint_observations = (int)v->num;
            v = json_get(e, "neg_calls"); if (v && v->type == JSON_NUM) ce->negative_callsites = (int)v->num;
            v = json_get(e, "neg_dev"); if (v && v->type == JSON_NUM) ce->negative_deviations = (int)v->num;
            v = json_get(e, "chk_b"); if (v && v->type == JSON_NUM) ce->checked_buffers = (int)v->num;
            v = json_get(e, "chk_a"); if (v && v->type == JSON_NUM) ce->checked_allocations = (int)v->num;
            v = json_get(e, "chk_at"); if (v && v->type == JSON_NUM) ce->checked_accesses = (int)v->num;
            v = json_get(e, "chk_f"); if (v && v->type == JSON_NUM) ce->checked_frees = (int)v->num;
            v = json_get(e, "chk_rb"); if (v && v->type == JSON_NUM) ce->checked_raw_buffers = (int)v->num;
            v = json_get(e, "budget_active"); if (v && v->type == JSON_NUM) ce->budget_active = (int)v->num;
            v = json_get(e, "budget_met"); if (v && v->type == JSON_NUM) ce->budget_met = (int)v->num;
            v = json_get(e, "budget_report"); if (v && v->type == JSON_STR) snprintf(ce->budget_report, sizeof(ce->budget_report), "%s", v->str);
            /* Fase 4 A1: host facts toolchain (replay tanpa exec gcc). */
            v = json_get(e, "asm_f_ok"); if (v && v->type == JSON_NUM) ce->host_facts_ok = (int)v->num;
            v = json_get(e, "asm_cu"); if (v && v->type == JSON_NUM) ce->host_char_unsigned = (int)v->num;
            v = json_get(e, "asm_ib"); if (v && v->type == JSON_NUM) ce->host_int_bits = (int)v->num;
            v = json_get(e, "asm_pb"); if (v && v->type == JSON_NUM) ce->host_ptr_bits = (int)v->num;
            v = json_get(e, "asm_le"); if (v && v->type == JSON_NUM) ce->host_little_endian = (int)v->num;
            v = json_get(e, "asm_stdc"); if (v && v->type == JSON_NUM) ce->host_stdc_version = (long)v->num;
            v = json_get(e, "asm_cb"); if (v && v->type == JSON_NUM) ce->host_char_bit = (int)v->num;
            /* Fase 4 A2/DS-02: hasil gate divergence (replay identik). */
            v = json_get(e, "div_ran"); if (v && v->type == JSON_NUM) ce->divergence_ran = (int)v->num;
            v = json_get(e, "div_planned"); if (v && v->type == JSON_NUM) ce->divergence_planned = (int)v->num;
            v = json_get(e, "div_ncells"); if (v && v->type == JSON_NUM) ce->divergence_ncells = (int)v->num;
            v = json_get(e, "div_san"); if (v && v->type == JSON_NUM) ce->divergence_sanitizer_div = (int)v->num;
            v = json_get(e, "div_all"); if (v && v->type == JSON_NUM) ce->divergence_all_findings = (int)v->num;
            v = json_get(e, "div_sem"); if (v && v->type == JSON_NUM) ce->divergence_semantic_div = (int)v->num;
            v = json_get(e, "div_diag"); if (v && v->type == JSON_NUM) ce->divergence_diag_div = (int)v->num;
            v = json_get(e, "div_report"); if (v && v->type == JSON_STR) snprintf(ce->divergence_report, sizeof(ce->divergence_report), "%s", v->str);
            {
                json_value *dc = json_get(e, "div_cells");
                if (dc && dc->type == JSON_ARR) {
                    for (k = 0; k < (int)dc->len && k < MYC_DIVERGENCE_MAX_CELLS; k++) {
                        json_value *co = dc->items[k];
                        json_value *cv;
                        if (!co || co->type != JSON_OBJ)
                            continue;
                        cv = json_get(co, "t"); if (cv && cv->type == JSON_STR) snprintf(ce->divergence_cells[k].tool, sizeof(ce->divergence_cells[k].tool), "%s", cv->str);
                        cv = json_get(co, "ol"); if (cv && cv->type == JSON_NUM) ce->divergence_cells[k].opt_level = (char)cv->num;
                        cv = json_get(co, "av"); if (cv && cv->type == JSON_NUM) ce->divergence_cells[k].available = (char)cv->num;
                        cv = json_get(co, "sn"); if (cv && cv->type == JSON_NUM) ce->divergence_cells[k].san = (char)cv->num;
                        cv = json_get(co, "bu"); if (cv && cv->type == JSON_NUM) ce->divergence_cells[k].built = (char)cv->num;
                        cv = json_get(co, "rn"); if (cv && cv->type == JSON_NUM) ce->divergence_cells[k].ran = (char)cv->num;
                        cv = json_get(co, "to"); if (cv && cv->type == JSON_NUM) ce->divergence_cells[k].timed_out = (char)cv->num;
                        cv = json_get(co, "fn"); if (cv && cv->type == JSON_NUM) ce->divergence_cells[k].finding = (char)cv->num;
                        cv = json_get(co, "dw"); if (cv && cv->type == JSON_NUM) ce->divergence_cells[k].diag_warn = (char)cv->num;
                        cv = json_get(co, "ec"); if (cv && cv->type == JSON_NUM) ce->divergence_cells[k].exit_code = (int)cv->num;
                        cv = json_get(co, "mk"); if (cv && cv->type == JSON_STR) snprintf(ce->divergence_cells[k].marker, sizeof(ce->divergence_cells[k].marker), "%s", cv->str);
                        cv = json_get(co, "sh"); if (cv && cv->type == JSON_STR) snprintf(ce->divergence_cells[k].stdout_sha256, sizeof(ce->divergence_cells[k].stdout_sha256), "%s", cv->str);
                    }
                }
            }
            v = json_get(e, "drv_funcs"); if (v && v->type == JSON_NUM) ce->driver_funcs = (int)v->num;
            v = json_get(e, "drv_cases"); if (v && v->type == JSON_NUM) ce->driver_cases = (int)v->num;
            v = json_get(e, "drv_skip"); if (v && v->type == JSON_NUM) ce->driver_skipped = (int)v->num;
            v = json_get(e, "ran_neg"); if (v && v->type == JSON_NUM) ce->ran_negative = (int)v->num;
            v = json_get(e, "ran_chk"); if (v && v->type == JSON_NUM) ce->ran_checked = (int)v->num;
            v = json_get(e, "ran_drv"); if (v && v->type == JSON_NUM) ce->ran_driver = (int)v->num;

            /* snapshot lengkap field hasil (SOL-18 replay identik). */
            v = json_get(e, "exit_code"); if (v && v->type == JSON_NUM) ce->exit_code = (int)v->num;
            v = json_get(e, "req_complete"); if (v && v->type == JSON_NUM) ce->require_complete = (int)v->num;
            v = json_get(e, "truncated"); if (v && v->type == JSON_NUM) ce->truncated = (int)v->num;
            v = json_get(e, "run_timed_out"); if (v && v->type == JSON_NUM) ce->run_timed_out = (int)v->num;
            v = json_get(e, "san_detected"); if (v && v->type == JSON_NUM) ce->run_sanitizer_detected = (int)v->num;
            v = json_get(e, "ran_rt"); if (v && v->type == JSON_NUM) ce->ran_runtime = (int)v->num;
            v = json_get(e, "ran_prove"); if (v && v->type == JSON_NUM) ce->ran_prove = (int)v->num;
            v = json_get(e, "ran_filc"); if (v && v->type == JSON_NUM) ce->ran_filc = (int)v->num;
            v = json_get(e, "ran_meta"); if (v && v->type == JSON_NUM) ce->ran_metamorphic = (int)v->num;
            v = json_get(e, "ran_pre"); if (v && v->type == JSON_NUM) ce->ran_preprocess = (int)v->num;
            v = json_get(e, "ran_comp"); if (v && v->type == JSON_NUM) ce->ran_compile = (int)v->num;
            v = json_get(e, "ran_anl"); if (v && v->type == JSON_NUM) ce->ran_analyzer = (int)v->num;
            v = json_get(e, "chk_uses"); if (v && v->type == JSON_NUM) ce->checked_uses_buf = (int)v->num;
            v = json_get(e, "chk_ok"); if (v && v->type == JSON_NUM) ce->checked_build_ok = (int)v->num;
            v = json_get(e, "prov_alarms"); if (v && v->type == JSON_NUM) ce->prove_alarms = (int)v->num;
            v = json_get(e, "prov_po"); if (v && v->type == JSON_NUM) ce->prove_proof_obligations = (int)v->num;
            v = json_get(e, "filc_panics"); if (v && v->type == JSON_NUM) ce->filc_panics = (int)v->num;
            v = json_get(e, "m0_exit"); if (v && v->type == JSON_NUM) ce->meta_o0_exit = (int)v->num;
            v = json_get(e, "m2_exit"); if (v && v->type == JSON_NUM) ce->meta_o2_exit = (int)v->num;
            v = json_get(e, "m0_fnd"); if (v && v->type == JSON_NUM) ce->meta_o0_finding = (int)v->num;
            v = json_get(e, "m2_fnd"); if (v && v->type == JSON_NUM) ce->meta_o2_finding = (int)v->num;
            v = json_get(e, "m_inc"); if (v && v->type == JSON_NUM) ce->metamorphic_inconsistent = (int)v->num;
            v = json_get(e, "drv_max"); if (v && v->type == JSON_NUM) ce->driver_max_product = (long)v->num;
            v = json_get(e, "drv_bnd"); if (v && v->type == JSON_NUM) ce->driver_bounded = (int)v->num;
            v = json_get(e, "out_bytes"); if (v && v->type == JSON_NUM) ce->total_stdout_bytes = (unsigned long long)v->num;
            v = json_get(e, "err_bytes"); if (v && v->type == JSON_NUM) ce->total_stderr_bytes = (unsigned long long)v->num;
            v = json_get(e, "ct_req"); if (v && v->type == JSON_NUM) ce->contract_requires = (int)v->num;
            v = json_get(e, "ct_ens"); if (v && v->type == JSON_NUM) ce->contract_ensures = (int)v->num;
            v = json_get(e, "hv_c"); if (v && v->type == JSON_NUM) ce->harvest_candidates = (int)v->num;
            v = json_get(e, "hv_v"); if (v && v->type == JSON_NUM) ce->harvest_validated = (int)v->num;
            v = json_get(e, "hv_u"); if (v && v->type == JSON_NUM) ce->harvest_unbound = (int)v->num;
            /* Fase 5: relational contracts (observasi). */
            v = json_get(e, "rel_a"); if (v && v->type == JSON_NUM) ce->rel_analyzed = (int)v->num;
            v = json_get(e, "rel_n"); if (v && v->type == JSON_NUM) ce->rel_relations = (int)v->num;
            v = json_get(e, "rel_u"); if (v && v->type == JSON_NUM) ce->rel_unary = (int)v->num;
            v = json_get(e, "rel_b"); if (v && v->type == JSON_NUM) ce->rel_unbound = (int)v->num;
            /* Fase 5 (SOL-13): ghost state machine (observasi). */
            v = json_get(e, "sm_s"); if (v && v->type == JSON_NUM) ce->sm_states = (int)v->num;
            v = json_get(e, "sm_e"); if (v && v->type == JSON_NUM) ce->sm_events = (int)v->num;
            v = json_get(e, "sm_t"); if (v && v->type == JSON_NUM) ce->sm_transitions = (int)v->num;
            v = json_get(e, "sm_f"); if (v && v->type == JSON_NUM) ce->sm_findings = (int)v->num;
            /* Fase 5 (SOL-14): ABI certificate (observasi). */
            v = json_get(e, "abi_r"); if (v && v->type == JSON_NUM) ce->abi_ran = (int)v->num;
            v = json_get(e, "abi_s"); if (v && v->type == JSON_NUM) ce->abi_n_structs = (int)v->num;
            v = json_get(e, "abi_e"); if (v && v->type == JSON_NUM) ce->abi_n_enums = (int)v->num;
            v = json_get(e, "abi_y"); if (v && v->type == JSON_NUM) ce->abi_n_symbols = (int)v->num;
            v = json_get(e, "abi_d"); if (v && v->type == JSON_NUM) ce->abi_n_delta = (int)v->num;
            /* Fase 5 (SOL-12): Resource Linearity Ledger (observasi). */
            v = json_get(e, "rsrc_r"); if (v && v->type == JSON_NUM) ce->rsrc_ran = (int)v->num;
            v = json_get(e, "rsrc_p"); if (v && v->type == JSON_NUM) ce->rsrc_pairs = (int)v->num;
            v = json_get(e, "rsrc_a"); if (v && v->type == JSON_NUM) ce->rsrc_acquires = (int)v->num;
            v = json_get(e, "rsrc_re"); if (v && v->type == JSON_NUM) ce->rsrc_releases = (int)v->num;
            v = json_get(e, "rsrc_t"); if (v && v->type == JSON_NUM) ce->rsrc_transferred = (int)v->num;
            v = json_get(e, "rsrc_l"); if (v && v->type == JSON_NUM) ce->rsrc_leaks = (int)v->num;
            v = json_get(e, "rsrc_d"); if (v && v->type == JSON_NUM) ce->rsrc_double_releases = (int)v->num;
            v = json_get(e, "rsrc_u"); if (v && v->type == JSON_NUM) ce->rsrc_release_unknown = (int)v->num;
            /* Fase 5 (SOL-11): Units / Shape / Provenance (observasi). */
            v = json_get(e, "unt_r"); if (v && v->type == JSON_NUM) ce->units_ran = (int)v->num;
            v = json_get(e, "unt_a"); if (v && v->type == JSON_NUM) ce->units_annotations = (int)v->num;
            v = json_get(e, "unt_u"); if (v && v->type == JSON_NUM) ce->units_unbound = (int)v->num;
            v = json_get(e, "unt_m"); if (v && v->type == JSON_NUM) ce->units_mismatches = (int)v->num;
            v = json_get(e, "unt_s"); if (v && v->type == JSON_NUM) ce->units_shape_dims = (int)v->num;
            v = json_get(e, "unt_d"); if (v && v->type == JSON_NUM) ce->units_duplicates = (int)v->num;
            v = json_get(e, "ex_r"); if (v && v->type == JSON_NUM) ce->ex_ran = (int)v->num;
            v = json_get(e, "ex_f"); if (v && v->type == JSON_NUM) ce->ex_funcs = (int)v->num;
            v = json_get(e, "ex_c"); if (v && v->type == JSON_NUM) ce->ex_cases = (int)v->num;
            v = json_get(e, "ex_s"); if (v && v->type == JSON_NUM) ce->ex_skip = (int)v->num;
            v = json_get(e, "ex_p"); if (v && v->type == JSON_NUM) ce->ex_points = (long)v->num;
            v = json_get(e, "ex_l"); if (v && v->type == JSON_NUM) ce->ex_laund = (int)v->num;
            v = json_get(e, "ex_h"); if (v && v->type == JSON_STR) snprintf(ce->ex_dhash, sizeof(ce->ex_dhash), "%s", v->str);
            v = json_get(e, "san_marker"); if (v && v->type == JSON_STR) snprintf(ce->sanitizer_marker, sizeof(ce->sanitizer_marker), "%s", v->str);
            v = json_get(e, "prov_mode"); if (v && v->type == JSON_STR) snprintf(ce->prove_mode, sizeof(ce->prove_mode), "%s", v->str);
            v = json_get(e, "prov_ver"); if (v && v->type == JSON_STR) snprintf(ce->prove_version, sizeof(ce->prove_version), "%s", v->str);
            v = json_get(e, "filc_ver"); if (v && v->type == JSON_STR) snprintf(ce->filc_version, sizeof(ce->filc_version), "%s", v->str);
            v = json_get(e, "drv_hsha"); if (v && v->type == JSON_STR) snprintf(ce->driver_harness_sha256, sizeof(ce->driver_harness_sha256), "%s", v->str);
            v = json_get(e, "stderr_text"); if (v && v->type == JSON_STR) snprintf(ce->stderr_text, sizeof(ce->stderr_text), "%s", v->str);
            v = json_get(e, "run_stdout"); if (v && v->type == JSON_STR) snprintf(ce->run_stdout_text, sizeof(ce->run_stdout_text), "%s", v->str);
            v = json_get(e, "run_stderr"); if (v && v->type == JSON_STR) snprintf(ce->run_stderr_text, sizeof(ce->run_stderr_text), "%s", v->str);
            v = json_get(e, "prov_stdout"); if (v && v->type == JSON_STR) snprintf(ce->prove_stdout_text, sizeof(ce->prove_stdout_text), "%s", v->str);
            v = json_get(e, "prov_stderr"); if (v && v->type == JSON_STR) snprintf(ce->prove_stderr_text, sizeof(ce->prove_stderr_text), "%s", v->str);
            v = json_get(e, "filc_stdout"); if (v && v->type == JSON_STR) snprintf(ce->filc_stdout_text, sizeof(ce->filc_stdout_text), "%s", v->str);
            v = json_get(e, "filc_stderr"); if (v && v->type == JSON_STR) snprintf(ce->filc_stderr_text, sizeof(ce->filc_stderr_text), "%s", v->str);
            v = json_get(e, "drv_stdout"); if (v && v->type == JSON_STR) snprintf(ce->driver_stdout_text, sizeof(ce->driver_stdout_text), "%s", v->str);
            v = json_get(e, "drv_stderr"); if (v && v->type == JSON_STR) snprintf(ce->driver_stderr_text, sizeof(ce->driver_stderr_text), "%s", v->str);
            v = json_get(e, "resolved_gcc"); if (v && v->type == JSON_STR) snprintf(ce->resolved_gcc, sizeof(ce->resolved_gcc), "%s", v->str);
            v = json_get(e, "gcc_version"); if (v && v->type == JSON_STR) snprintf(ce->gcc_version, sizeof(ce->gcc_version), "%s", v->str);
            v = json_get(e, "clang_version"); if (v && v->type == JSON_STR) snprintf(ce->clang_version, sizeof(ce->clang_version), "%s", v->str);

            /* driver case records */
            {
                json_value *dc = json_get(e, "drv_records");
                if (dc && dc->type == JSON_ARR) {
                    for (k = 0; k < (int)dc->len && k < 64; k++) {
                        json_value *ro = dc->items[k];
                        json_value *rv;
                        if (!ro || ro->type != JSON_OBJ)
                            continue;
                        rv = json_get(ro, "id"); if (rv && rv->type == JSON_NUM) ce->driver_records[k].case_id = (int)rv->num;
                        rv = json_get(ro, "alloc"); if (rv && rv->type == JSON_NUM) ce->driver_records[k].alloc_bytes = (long)rv->num;
                        rv = json_get(ro, "exec"); if (rv && rv->type == JSON_NUM) ce->driver_records[k].executed = (int)rv->num;
                        rv = json_get(ro, "func"); if (rv && rv->type == JSON_STR) snprintf(ce->driver_records[k].func, sizeof(ce->driver_records[k].func), "%s", rv->str);
                        rv = json_get(ro, "params"); if (rv && rv->type == JSON_STR) snprintf(ce->driver_records[k].params, sizeof(ce->driver_records[k].params), "%s", rv->str);
                        ce->driver_case_count++;
                    }
                }
            }

            /* filc cases */
            {
                json_value *fc = json_get(e, "filc_cases");
                if (fc && fc->type == JSON_ARR) {
                    for (k = 0; k < (int)fc->len && k < 16; k++) {
                        json_value *fo = fc->items[k];
                        json_value *fv;
                        if (!fo || fo->type != JSON_OBJ)
                            continue;
                        fv = json_get(fo, "line"); if (fv && fv->type == JSON_NUM) ce->filc_cases[k].line = (int)fv->num;
                        fv = json_get(fo, "col"); if (fv && fv->type == JSON_NUM) ce->filc_cases[k].col = (int)fv->num;
                        fv = json_get(fo, "msg"); if (fv && fv->type == JSON_STR) snprintf(ce->filc_cases[k].message, sizeof(ce->filc_cases[k].message), "%s", fv->str);
                        fv = json_get(fo, "file"); if (fv && fv->type == JSON_STR) snprintf(ce->filc_cases[k].file, sizeof(ce->filc_cases[k].file), "%s", fv->str);
                        fv = json_get(fo, "func"); if (fv && fv->type == JSON_STR) snprintf(ce->filc_cases[k].function, sizeof(ce->filc_cases[k].function), "%s", fv->str);
                        ce->filc_case_count++;
                    }
                }
            }

            /* contract clauses */
            {
                json_value *cc = json_get(e, "clauses");
                if (cc && cc->type == JSON_ARR) {
                    for (k = 0; k < (int)cc->len && k < 16; k++) {
                        json_value *co = cc->items[k];
                        json_value *cv;
                        if (!co || co->type != JSON_OBJ)
                            continue;
                        cv = json_get(co, "kind"); if (cv && cv->type == JSON_NUM) ce->contract_clauses[k].kind = (int)cv->num;
                        cv = json_get(co, "line"); if (cv && cv->type == JSON_NUM) ce->contract_clauses[k].line = (int)cv->num;
                        cv = json_get(co, "col"); if (cv && cv->type == JSON_NUM) ce->contract_clauses[k].col = (int)cv->num;
                        cv = json_get(co, "status"); if (cv && cv->type == JSON_NUM) ce->contract_clauses[k].status = (int)cv->num;
                        cv = json_get(co, "func"); if (cv && cv->type == JSON_STR) snprintf(ce->contract_clauses[k].func, sizeof(ce->contract_clauses[k].func), "%s", cv->str);
                        cv = json_get(co, "expr"); if (cv && cv->type == JSON_STR) snprintf(ce->contract_clauses[k].expr, sizeof(ce->contract_clauses[k].expr), "%s", cv->str);
                        ce->contract_clause_count++;
                    }
                }
            }

            /* evidence events */
            {
                json_value *ev = json_get(e, "evidence");
                if (ev && ev->type == JSON_ARR) {
                    for (k = 0; k < (int)ev->len && k < 32; k++) {
                        json_value *eo = ev->items[k];
                        json_value *e2;
                        if (!eo || eo->type != JSON_OBJ)
                            continue;
                        e2 = json_get(eo, "gate"); if (e2 && e2->type == JSON_NUM) ce->evidence[k].gate_id = (int)e2->num;
                        e2 = json_get(eo, "type"); if (e2 && e2->type == JSON_NUM) ce->evidence[k].event_type = (int)e2->num;
                        e2 = json_get(eo, "msg"); if (e2 && e2->type == JSON_STR) snprintf(ce->evidence[k].message, sizeof(ce->evidence[k].message), "%s", e2->str);
                        ce->evidence_count++;
                    }
                }
            }

            /* assurance vector (array 7) */
            {
                json_value *av = json_get(e, "av");
                if (av && av->type == JSON_ARR) {
                    for (k = 0; k < MYC_DIM_COUNT && k < (int)av->len; k++) {
                        if (av->items[k] && av->items[k]->type == JSON_NUM)
                            ce->av.status[k] = (myc_dim_status)av->items[k]->num;
                    }
                }
            }

            /* gates (status/id di-clamp ke range valid; requested = bool) */
            {
                json_value *g = json_get(e, "gates");
                if (g && g->type == JSON_ARR) {
                    for (k = 0; k < (int)g->len && k < MYC_MAX_GATES; k++) {
                        json_value *go = g->items[k];
                        json_value *gv;
                        if (!go || go->type != JSON_OBJ)
                            continue;
                        gv = json_get(go, "id");        if (gv && gv->type == JSON_NUM && gv->num >= 0 && gv->num < MYC_GATE_COUNT) ce->gate_id[k] = (int)gv->num;
                        gv = json_get(go, "requested"); if (gv && gv->type == JSON_NUM) ce->gate_requested[k] = (int)(gv->num != 0);
                        gv = json_get(go, "status");    if (gv && gv->type == JSON_NUM && gv->num >= 0 && gv->num <= MYC_GATE_COMPLETED_OBSERVATIONS) ce->gate_status[k] = (myc_gate_status)gv->num;
                        gv = json_get(go, "findings");  if (gv && gv->type == JSON_NUM) ce->gate_findings[k] = (int)gv->num;
                        ce->gate_count++;
                    }
                }
            }

            /* debt (type di-clamp ke range valid — myc_debt_type_name/
             * myc_debt_code harus selalu punya default untuk nilai valid). */
            {
                json_value *d = json_get(e, "debt");
                if (d && d->type == JSON_ARR) {
                    for (k = 0; k < (int)d->len && k < MYC_MAX_DEBT; k++) {
                        if (d->items[k] && d->items[k]->type == JSON_NUM &&
                            d->items[k]->num >= 0 &&
                            d->items[k]->num < (int64_t)MYC_DEBT_COUNT)
                            ce->debt[ce->debt_count++].type =
                                (myc_debt_type)d->items[k]->num;
                    }
                }
                /* MYC-AUDIT-042: teks deskriptif debt (paralel dgn type;
                 * entry cache LAMA tanpa field ini -> kosong, replay
                 * fallback ke myc_debt_type_name seperti sebelumnya). */
                d = json_get(e, "debt_text");
                if (d && d->type == JSON_ARR) {
                    for (k = 0; k < (int)d->len && k < MYC_MAX_DEBT; k++) {
                        if (d->items[k] && d->items[k]->type == JSON_STR)
                            snprintf(ce->debt_text[k],
                                     sizeof(ce->debt_text[k]), "%s",
                                     d->items[k]->str);
                    }
                }
            }

            /* diagnostics */
            {
                json_value *d = json_get(e, "diags");
                if (d && d->type == JSON_ARR) {
                    for (k = 0; k < (int)d->len && k < MYC_MAX_DIAGNOSTICS; k++) {
                        json_value *do_ = d->items[k];
                        json_value *dv;
                        if (!do_ || do_->type != JSON_OBJ)
                            continue;
                        dv = json_get(do_, "line"); if (dv && dv->type == JSON_NUM) ce->diag_line[k] = (int)dv->num;
                        dv = json_get(do_, "col");  if (dv && dv->type == JSON_NUM) ce->diag_col[k] = (int)dv->num;
                        dv = json_get(do_, "conf"); if (dv && dv->type == JSON_NUM) ce->diag_conf[k] = (myc_confidence)dv->num;
                        dv = json_get(do_, "msg");  if (dv && dv->type == JSON_STR) snprintf(ce->diag_msg[k], sizeof(ce->diag_msg[k]), "%s", dv->str);
                        ce->diag_count++;
                    }
                }
            }

            /* functions */
            {
                json_value *fn = json_get(e, "funcs");
                if (fn && fn->type == JSON_ARR) {
                    for (k = 0; k < (int)fn->len && k < MYC_CACHE_MAX_FUNCS; k++) {
                        json_value *fo = fn->items[k];
                        json_value *fv;
                        if (!fo || fo->type != JSON_OBJ)
                            continue;
                        fv = json_get(fo, "name"); if (fv && fv->type == JSON_STR) snprintf(ce->funcs[k].name, sizeof(ce->funcs[k].name), "%s", fv->str);
                        fv = json_get(fo, "line"); if (fv && fv->type == JSON_NUM) ce->funcs[k].line = (int)fv->num;
                        fv = json_get(fo, "hash"); if (fv && fv->type == JSON_STR) snprintf(ce->funcs[k].hash, sizeof(ce->funcs[k].hash), "%s", fv->str);
                        ce->func_count++;
                    }
                }
            }

            n++;
        }
    json_free(root);
    myc_free(buf);
    if (qbad > 0) {
        /* Karantina + self-heal: tulis ulang file TANPA entry korup agar
         * korupsi tidak dibaca berulang. Entry tersisa tetap valid (hash
         * dihitung ulang oleh cache_write_all). NON-blocking. */
        fprintf(stderr,
                "myc: cache: quarantined %d corrupt cache entr%s (%s) - "
                "recomputing evidence\n",
                qbad, qbad == 1 ? "y" : "ies",
                qwhy[0] ? qwhy : "?");
        cache_write_all(out, n);
    }
    return n;
}

/* Tulis ulang cache file (ukuran kecil, rewrite penuh seperti ledger). */
static void cache_write_all(const myc_cache_entry *entries, int count)
{
    json_value *root, *arr;
    char *out;
    int ok, i, k;

    cache_mkdir(".myc");

    root = json_new_obj();
    if (!root)
        return;
    arr = json_new_arr();
    if (!arr) { json_free(root); return; }

    for (i = 0; i < count; i++) {
        const myc_cache_entry *ce = &entries[i];
        json_value *e = json_new_obj();
        json_value *tmp;
        if (!e)
            continue;
        json_obj_set(e, "key", json_new_str(ce->key_sha256));
        json_obj_set(e, "source", json_new_str(ce->source_sha256));
        json_obj_set(e, "scenario", json_new_str(ce->scenario_hash));
        json_obj_set(e, "tool", json_new_str(ce->tool_key));
        json_obj_set(e, "cwd", json_new_str(ce->cwd));
        json_obj_set(e, "path", json_new_str(ce->path));
        json_obj_set(e, "receipt", json_new_str(ce->receipt_sha256));
        json_obj_set(e, "fingerprint", json_new_str(ce->fingerprint));
        json_obj_set(e, "verdict", json_new_num((int64_t)ce->verdict));
        json_obj_set(e, "err", json_new_num((int64_t)ce->err));
        json_obj_set(e, "assurance", json_new_num((int64_t)ce->assurance));
        json_obj_set(e, "finding", json_new_num((int64_t)ce->finding));
        json_obj_set(e, "completeness", json_new_num((int64_t)ce->completeness));
        json_obj_set(e, "claim", json_new_num((int64_t)ce->claim));
        json_obj_set(e, "duration_ms", json_new_num((int64_t)ce->duration_ms));
        json_obj_set(e, "lint_obs", json_new_num((int64_t)ce->lint_observations));
        json_obj_set(e, "neg_calls", json_new_num((int64_t)ce->negative_callsites));
        json_obj_set(e, "neg_dev", json_new_num((int64_t)ce->negative_deviations));
        json_obj_set(e, "chk_b", json_new_num((int64_t)ce->checked_buffers));
        json_obj_set(e, "chk_a", json_new_num((int64_t)ce->checked_allocations));
        json_obj_set(e, "chk_at", json_new_num((int64_t)ce->checked_accesses));
        json_obj_set(e, "chk_f", json_new_num((int64_t)ce->checked_frees));
        json_obj_set(e, "chk_rb", json_new_num((int64_t)ce->checked_raw_buffers));
        json_obj_set(e, "budget_active", json_new_num((int64_t)ce->budget_active));
        json_obj_set(e, "budget_met", json_new_num((int64_t)ce->budget_met));
        json_obj_set(e, "budget_report", json_new_str(ce->budget_report));
        /* Fase 4 A1: host facts toolchain. */
        json_obj_set(e, "asm_f_ok", json_new_num((int64_t)ce->host_facts_ok));
        json_obj_set(e, "asm_cu", json_new_num((int64_t)ce->host_char_unsigned));
        json_obj_set(e, "asm_ib", json_new_num((int64_t)ce->host_int_bits));
        json_obj_set(e, "asm_pb", json_new_num((int64_t)ce->host_ptr_bits));
        json_obj_set(e, "asm_le", json_new_num((int64_t)ce->host_little_endian));
        json_obj_set(e, "asm_stdc", json_new_num((int64_t)ce->host_stdc_version));
        json_obj_set(e, "asm_cb", json_new_num((int64_t)ce->host_char_bit));
        /* Fase 4 A2/DS-02: hasil gate divergence. */
        json_obj_set(e, "div_ran", json_new_num((int64_t)ce->divergence_ran));
        json_obj_set(e, "div_planned", json_new_num((int64_t)ce->divergence_planned));
        json_obj_set(e, "div_ncells", json_new_num((int64_t)ce->divergence_ncells));
        json_obj_set(e, "div_san", json_new_num((int64_t)ce->divergence_sanitizer_div));
        json_obj_set(e, "div_all", json_new_num((int64_t)ce->divergence_all_findings));
        json_obj_set(e, "div_sem", json_new_num((int64_t)ce->divergence_semantic_div));
        json_obj_set(e, "div_diag", json_new_num((int64_t)ce->divergence_diag_div));
        json_obj_set(e, "div_report", json_new_str(ce->divergence_report));
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < MYC_DIVERGENCE_MAX_CELLS && k < (int)ce->divergence_ncells; k++) {
                json_value *co = json_new_obj();
                if (!co)
                    continue;
                json_obj_set(co, "t", json_new_str(ce->divergence_cells[k].tool));
                json_obj_set(co, "ol", json_new_num((int64_t)ce->divergence_cells[k].opt_level));
                json_obj_set(co, "av", json_new_num((int64_t)ce->divergence_cells[k].available));
                json_obj_set(co, "sn", json_new_num((int64_t)ce->divergence_cells[k].san));
                json_obj_set(co, "bu", json_new_num((int64_t)ce->divergence_cells[k].built));
                json_obj_set(co, "rn", json_new_num((int64_t)ce->divergence_cells[k].ran));
                json_obj_set(co, "to", json_new_num((int64_t)ce->divergence_cells[k].timed_out));
                json_obj_set(co, "fn", json_new_num((int64_t)ce->divergence_cells[k].finding));
                json_obj_set(co, "dw", json_new_num((int64_t)ce->divergence_cells[k].diag_warn));
                json_obj_set(co, "ec", json_new_num((int64_t)ce->divergence_cells[k].exit_code));
                json_obj_set(co, "mk", json_new_str(ce->divergence_cells[k].marker));
                json_obj_set(co, "sh", json_new_str(ce->divergence_cells[k].stdout_sha256));
                json_arr_push(tmp, co);
            }
            json_obj_set(e, "div_cells", tmp);
        }
        json_obj_set(e, "drv_funcs", json_new_num((int64_t)ce->driver_funcs));
        json_obj_set(e, "drv_cases", json_new_num((int64_t)ce->driver_cases));
        json_obj_set(e, "drv_skip", json_new_num((int64_t)ce->driver_skipped));
        json_obj_set(e, "ran_neg", json_new_num((int64_t)ce->ran_negative));
        json_obj_set(e, "ran_chk", json_new_num((int64_t)ce->ran_checked));
        json_obj_set(e, "ran_drv", json_new_num((int64_t)ce->ran_driver));

        /* snapshot lengkap field hasil (SOL-18 replay identik). */
        json_obj_set(e, "exit_code", json_new_num((int64_t)ce->exit_code));
        json_obj_set(e, "req_complete", json_new_num((int64_t)ce->require_complete));
        json_obj_set(e, "truncated", json_new_num((int64_t)ce->truncated));
        json_obj_set(e, "run_timed_out", json_new_num((int64_t)ce->run_timed_out));
        json_obj_set(e, "san_detected", json_new_num((int64_t)ce->run_sanitizer_detected));
        json_obj_set(e, "ran_rt", json_new_num((int64_t)ce->ran_runtime));
        json_obj_set(e, "ran_prove", json_new_num((int64_t)ce->ran_prove));
        json_obj_set(e, "ran_filc", json_new_num((int64_t)ce->ran_filc));
        json_obj_set(e, "ran_meta", json_new_num((int64_t)ce->ran_metamorphic));
        json_obj_set(e, "ran_pre", json_new_num((int64_t)ce->ran_preprocess));
        json_obj_set(e, "ran_comp", json_new_num((int64_t)ce->ran_compile));
        json_obj_set(e, "ran_anl", json_new_num((int64_t)ce->ran_analyzer));
        json_obj_set(e, "chk_uses", json_new_num((int64_t)ce->checked_uses_buf));
        json_obj_set(e, "chk_ok", json_new_num((int64_t)ce->checked_build_ok));
        json_obj_set(e, "prov_alarms", json_new_num((int64_t)ce->prove_alarms));
        json_obj_set(e, "prov_po", json_new_num((int64_t)ce->prove_proof_obligations));
        json_obj_set(e, "filc_panics", json_new_num((int64_t)ce->filc_panics));
        json_obj_set(e, "m0_exit", json_new_num((int64_t)ce->meta_o0_exit));
        json_obj_set(e, "m2_exit", json_new_num((int64_t)ce->meta_o2_exit));
        json_obj_set(e, "m0_fnd", json_new_num((int64_t)ce->meta_o0_finding));
        json_obj_set(e, "m2_fnd", json_new_num((int64_t)ce->meta_o2_finding));
        json_obj_set(e, "m_inc", json_new_num((int64_t)ce->metamorphic_inconsistent));
        json_obj_set(e, "drv_max", json_new_num((int64_t)ce->driver_max_product));
        json_obj_set(e, "drv_bnd", json_new_num((int64_t)ce->driver_bounded));
        json_obj_set(e, "out_bytes", json_new_num((int64_t)ce->total_stdout_bytes));
        json_obj_set(e, "err_bytes", json_new_num((int64_t)ce->total_stderr_bytes));
        json_obj_set(e, "ct_req", json_new_num((int64_t)ce->contract_requires));
        json_obj_set(e, "ct_ens", json_new_num((int64_t)ce->contract_ensures));
        json_obj_set(e, "hv_c", json_new_num((int64_t)ce->harvest_candidates));
        json_obj_set(e, "hv_v", json_new_num((int64_t)ce->harvest_validated));
        json_obj_set(e, "hv_u", json_new_num((int64_t)ce->harvest_unbound));
        /* Fase 5: relational contracts (observasi). */
        json_obj_set(e, "rel_a", json_new_num((int64_t)ce->rel_analyzed));
        json_obj_set(e, "rel_n", json_new_num((int64_t)ce->rel_relations));
        json_obj_set(e, "rel_u", json_new_num((int64_t)ce->rel_unary));
        json_obj_set(e, "rel_b", json_new_num((int64_t)ce->rel_unbound));
        /* Fase 5 (SOL-13): ghost state machine (observasi). */
        json_obj_set(e, "sm_s", json_new_num((int64_t)ce->sm_states));
        json_obj_set(e, "sm_e", json_new_num((int64_t)ce->sm_events));
        json_obj_set(e, "sm_t", json_new_num((int64_t)ce->sm_transitions));
        json_obj_set(e, "sm_f", json_new_num((int64_t)ce->sm_findings));
        /* Fase 5 (SOL-14): ABI certificate (observasi). */
        json_obj_set(e, "abi_r", json_new_num((int64_t)ce->abi_ran));
        json_obj_set(e, "abi_s", json_new_num((int64_t)ce->abi_n_structs));
        json_obj_set(e, "abi_e", json_new_num((int64_t)ce->abi_n_enums));
        json_obj_set(e, "abi_y", json_new_num((int64_t)ce->abi_n_symbols));
        json_obj_set(e, "abi_c", json_new_num((int64_t)ce->abi_changed));
        json_obj_set(e, "abi_d", json_new_num((int64_t)ce->abi_n_delta));
        /* Fase 5 (SOL-12): Resource Linearity Ledger (observasi). */
        json_obj_set(e, "rsrc_r", json_new_num((int64_t)ce->rsrc_ran));
        json_obj_set(e, "rsrc_p", json_new_num((int64_t)ce->rsrc_pairs));
        json_obj_set(e, "rsrc_a", json_new_num((int64_t)ce->rsrc_acquires));
        json_obj_set(e, "rsrc_re", json_new_num((int64_t)ce->rsrc_releases));
        json_obj_set(e, "rsrc_t", json_new_num((int64_t)ce->rsrc_transferred));
        json_obj_set(e, "rsrc_l", json_new_num((int64_t)ce->rsrc_leaks));
        json_obj_set(e, "rsrc_d", json_new_num((int64_t)ce->rsrc_double_releases));
        /* Fase 5 (SOL-11): Units / Shape / Provenance (observasi). */
        json_obj_set(e, "unt_r", json_new_num((int64_t)ce->units_ran));
        json_obj_set(e, "unt_a", json_new_num((int64_t)ce->units_annotations));
        json_obj_set(e, "unt_u", json_new_num((int64_t)ce->units_unbound));
        json_obj_set(e, "unt_m", json_new_num((int64_t)ce->units_mismatches));
        json_obj_set(e, "unt_s", json_new_num((int64_t)ce->units_shape_dims));
        json_obj_set(e, "unt_d", json_new_num((int64_t)ce->units_duplicates));
        json_obj_set(e, "rsrc_u", json_new_num((int64_t)ce->rsrc_release_unknown));
        json_obj_set(e, "ex_r", json_new_num((int64_t)ce->ex_ran));
        json_obj_set(e, "ex_f", json_new_num((int64_t)ce->ex_funcs));
        json_obj_set(e, "ex_c", json_new_num((int64_t)ce->ex_cases));
        json_obj_set(e, "ex_s", json_new_num((int64_t)ce->ex_skip));
        json_obj_set(e, "ex_p", json_new_num((int64_t)ce->ex_points));
        json_obj_set(e, "ex_l", json_new_num((int64_t)ce->ex_laund));
        json_obj_set(e, "ex_h", json_new_str(ce->ex_dhash));
        json_obj_set(e, "san_marker", json_new_str(ce->sanitizer_marker));
        json_obj_set(e, "prov_mode", json_new_str(ce->prove_mode));
        json_obj_set(e, "prov_ver", json_new_str(ce->prove_version));
        json_obj_set(e, "filc_ver", json_new_str(ce->filc_version));
        json_obj_set(e, "drv_hsha", json_new_str(ce->driver_harness_sha256));
        json_obj_set(e, "stderr_text", json_new_str(ce->stderr_text));
        json_obj_set(e, "run_stdout", json_new_str(ce->run_stdout_text));
        json_obj_set(e, "run_stderr", json_new_str(ce->run_stderr_text));
        json_obj_set(e, "prov_stdout", json_new_str(ce->prove_stdout_text));
        json_obj_set(e, "prov_stderr", json_new_str(ce->prove_stderr_text));
        json_obj_set(e, "filc_stdout", json_new_str(ce->filc_stdout_text));
        json_obj_set(e, "filc_stderr", json_new_str(ce->filc_stderr_text));
        json_obj_set(e, "drv_stdout", json_new_str(ce->driver_stdout_text));
        json_obj_set(e, "drv_stderr", json_new_str(ce->driver_stderr_text));
        json_obj_set(e, "resolved_gcc", json_new_str(ce->resolved_gcc));
        json_obj_set(e, "gcc_version", json_new_str(ce->gcc_version));
        json_obj_set(e, "clang_version", json_new_str(ce->clang_version));

        /* driver case records */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->driver_case_count && k < 64; k++) {
                json_value *ro = json_new_obj();
                if (!ro)
                    continue;
                json_obj_set(ro, "id", json_new_num((int64_t)ce->driver_records[k].case_id));
                json_obj_set(ro, "alloc", json_new_num((int64_t)ce->driver_records[k].alloc_bytes));
                json_obj_set(ro, "exec", json_new_num((int64_t)ce->driver_records[k].executed));
                json_obj_set(ro, "func", json_new_str(ce->driver_records[k].func));
                json_obj_set(ro, "params", json_new_str(ce->driver_records[k].params));
                json_arr_push(tmp, ro);
            }
            json_obj_set(e, "drv_records", tmp);
        }

        /* filc cases */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->filc_case_count && k < 16; k++) {
                json_value *fo = json_new_obj();
                if (!fo)
                    continue;
                json_obj_set(fo, "line", json_new_num((int64_t)ce->filc_cases[k].line));
                json_obj_set(fo, "col", json_new_num((int64_t)ce->filc_cases[k].col));
                json_obj_set(fo, "msg", json_new_str(ce->filc_cases[k].message));
                json_obj_set(fo, "file", json_new_str(ce->filc_cases[k].file));
                json_obj_set(fo, "func", json_new_str(ce->filc_cases[k].function));
                json_arr_push(tmp, fo);
            }
            json_obj_set(e, "filc_cases", tmp);
        }

        /* contract clauses */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->contract_clause_count && k < 16; k++) {
                json_value *co = json_new_obj();
                if (!co)
                    continue;
                json_obj_set(co, "kind", json_new_num((int64_t)ce->contract_clauses[k].kind));
                json_obj_set(co, "line", json_new_num((int64_t)ce->contract_clauses[k].line));
                json_obj_set(co, "col", json_new_num((int64_t)ce->contract_clauses[k].col));
                json_obj_set(co, "status", json_new_num((int64_t)ce->contract_clauses[k].status));
                json_obj_set(co, "func", json_new_str(ce->contract_clauses[k].func));
                json_obj_set(co, "expr", json_new_str(ce->contract_clauses[k].expr));
                json_arr_push(tmp, co);
            }
            json_obj_set(e, "clauses", tmp);
        }

        /* evidence events */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->evidence_count && k < 32; k++) {
                json_value *eo = json_new_obj();
                if (!eo)
                    continue;
                json_obj_set(eo, "gate", json_new_num((int64_t)ce->evidence[k].gate_id));
                json_obj_set(eo, "type", json_new_num((int64_t)ce->evidence[k].event_type));
                json_obj_set(eo, "msg", json_new_str(ce->evidence[k].message));
                json_arr_push(tmp, eo);
            }
            json_obj_set(e, "evidence", tmp);
        }

        /* assurance vector */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < MYC_DIM_COUNT; k++)
                json_arr_push(tmp, json_new_num((int64_t)ce->av.status[k]));
            json_obj_set(e, "av", tmp);
        }

        /* gates */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->gate_count; k++) {
                json_value *go = json_new_obj();
                if (!go)
                    continue;
                json_obj_set(go, "id", json_new_num((int64_t)ce->gate_id[k]));
                json_obj_set(go, "requested",
                             json_new_num((int64_t)ce->gate_requested[k]));
                json_obj_set(go, "status", json_new_num((int64_t)ce->gate_status[k]));
                json_obj_set(go, "findings", json_new_num((int64_t)ce->gate_findings[k]));
                json_arr_push(tmp, go);
            }
            json_obj_set(e, "gates", tmp);
        }

        /* debt */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->debt_count; k++)
                json_arr_push(tmp, json_new_num((int64_t)ce->debt[k].type));
            json_obj_set(e, "debt", tmp);
        }
        /* MYC-AUDIT-042: teks deskriptif debt (replay identik SOL-18). */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->debt_count; k++)
                json_arr_push(tmp, json_new_str(ce->debt_text[k]));
            json_obj_set(e, "debt_text", tmp);
        }

        /* diagnostics */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->diag_count; k++) {
                json_value *do_ = json_new_obj();
                if (!do_)
                    continue;
                json_obj_set(do_, "line", json_new_num((int64_t)ce->diag_line[k]));
                json_obj_set(do_, "col", json_new_num((int64_t)ce->diag_col[k]));
                json_obj_set(do_, "conf", json_new_num((int64_t)ce->diag_conf[k]));
                json_obj_set(do_, "msg", json_new_str(ce->diag_msg[k]));
                json_arr_push(tmp, do_);
            }
            json_obj_set(e, "diags", tmp);
        }

        /* functions */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->func_count; k++) {
                json_value *fo = json_new_obj();
                if (!fo)
                    continue;
                json_obj_set(fo, "name", json_new_str(ce->funcs[k].name));
                json_obj_set(fo, "line", json_new_num((int64_t)ce->funcs[k].line));
                json_obj_set(fo, "hash", json_new_str(ce->funcs[k].hash));
                json_arr_push(tmp, fo);
            }
            json_obj_set(e, "funcs", tmp);
        }

        json_arr_push(arr, e);
    }
    json_obj_set(root, "entries", arr);

    ok = json_serialize(root, &out);
    json_free(root);
    if (!ok || !out)
        return;

    /* PR-012 (MYC-AUDIT-044, P3-T03): tulis ATOMIK (temp+flush+fsync+
     * rename). Crash kapan pun -> evidence_cache.json OLD valid ATAU
     * NEW valid, tidak pernah setengah (replay tidak pernah melihat
     * JSON korup). NON-blocking: gagal tulis diabaikan (seperti dulu). */
    (void)myc_persist_atomic_write_str(MYC_CACHE_FILE, out);
    /* PR-013 (MYC-AUDIT-045, P3-T04): sidecar sha256 atas byte mentah
     * file, ditulis SETELAH file cache (crash di antara keduanya =
     * sidecar stale -> pembaca meng-ignore + recompute; aman, bukan
     * trust). NON-blocking. */
    {
        char hex[65];
        sha256_hex(out, strlen(out), hex);
        (void)myc_persist_atomic_write_str(MYC_CACHE_SHA_FILE, hex);
    }
    myc_free(out);
}

/* ------------------------------------------------------------------ */
/* Function extraction                                                 */
/* ------------------------------------------------------------------ */

/* Ekstrak fungsi dari source (skimmer leksikal sederhana): cari pola
 * `<name>(...){ ... }` di brace level 0. Hash = sha256 isi fungsi. */
static int is_ident_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

static int is_keyword(const char *s, size_t n)
{
    static const char *const K[] = {
        "if", "for", "while", "switch", "do", "return", "sizeof",
        "case", "goto", "else", "typedef", "struct", "union", "enum",
        "static", "extern", "const", "volatile", "int", "char", "void",
        "unsigned", "signed", "long", "short", "double", "float", "ifdef",
        NULL
    };
    int i;
    for (i = 0; K[i]; i++) {
        size_t l = strlen(K[i]);
        if (l == n && strncmp(s, K[i], l) == 0)
            return 1;
    }
    return 0;
}

/* Skip whitespace (termasuk newline — dukung gaya Allman: ')' di satu
 * baris, '{' di baris berikutnya, gaya yang dipakai seluruh source myc)
 * + komentar. Mengembalikan posisi pertama non-whitespace/non-komentar. */
static size_t skip_ws_comments(const char *src, size_t srclen, size_t j)
{
    for (;;) {
        while (j < srclen &&
               (src[j] == ' ' || src[j] == '\t' || src[j] == '\n' ||
                src[j] == '\r'))
            j++;
        if (j + 1 < srclen && src[j] == '/' && src[j + 1] == '/') {
            while (j < srclen && src[j] != '\n')
                j++;
            continue;
        }
        if (j + 1 < srclen && src[j] == '/' && src[j + 1] == '*') {
            j += 2;
            while (j + 1 < srclen &&
                   !(src[j] == '*' && src[j + 1] == '/'))
                j++;
            j += 2;
            continue;
        }
        break;
    }
    return j;
}

int myc_cache_extract_functions(const char *src, size_t srclen,
                                myc_cache_function *out, int cap)
{
    size_t i = 0;
    int    depth = 0;
    int    line = 1;
    int    n = 0;

    if (!src || !out || cap <= 0)
        return -1;

    while (i < srclen) {
        char c = src[i];

        if (c == '\n')
            line++;

        /* skip komentar */
        if (c == '/' && i + 1 < srclen) {
            if (src[i + 1] == '/') {
                while (i < srclen && src[i] != '\n')
                    i++;
                continue;
            }
            if (src[i + 1] == '*') {
                i += 2;
                while (i + 1 < srclen &&
                       !(src[i] == '*' && src[i + 1] == '/'))
                    i++;
                i += 2;
                continue;
            }
        }
        /* skip string/char literal */
        if (c == '"' || c == '\'') {
            char q = c;
            i++;
            while (i < srclen && src[i] != q) {
                if (src[i] == '\\')
                    i++;
                i++;
            }
            i++;
            continue;
        }

        if (c == '{') {
            depth++;
            i++;
            continue;
        }
        if (c == '}') {
            if (depth > 0)
                depth--;
            i++;
            continue;
        }
        if (c == '#') {
            while (i < srclen && src[i] != '\n')
                i++;
            continue;
        }

        /* cari nama fungsi di level 0: ident( lalu ... ) lalu { */
        if (depth == 0 && (is_ident_char(c) &&
                           !(c >= '0' && c <= '9'))) {
            size_t start = i;
            size_t name_end;
            size_t j;

            while (i < srclen && is_ident_char(src[i]))
                i++;
            name_end = i;

            /* bukan keyword */
            if (is_keyword(src + start, name_end - start))
                continue;

            /* skip whitespace + komentar lalu cek '(' */
            j = skip_ws_comments(src, srclen, i);
            if (j >= srclen || src[j] != '(')
                continue;

            /* skip sampai ')' (matching paren) */
            {
                int paren = 1;
                j++;
                while (j < srclen && paren > 0) {
                    if (src[j] == '(') paren++;
                    else if (src[j] == ')') paren--;
                    j++;
                }
            }
            /* skip whitespace + komentar lalu cek '{' (dukung gaya
             * Allman: brace di baris berikutnya). */
            j = skip_ws_comments(src, srclen, j);
            if (j >= srclen || src[j] != '{')
                continue;

            /* ini fungsi: cari '}' penutup (brace depth mulai 1) */
            {
                size_t body_start = j;   /* posisi '{' */
                int    bd = 1;
                size_t k = j + 1;
                while (k < srclen && bd > 0) {
                    if (src[k] == '{') bd++;
                    else if (src[k] == '}') bd--;
                    k++;
                }
                if (bd == 0) {
                    /* nama + line + hash isi fungsi */
                    myc_cache_function *fn = &out[n];
                    char hashbuf[65];
                    size_t len;
                    if (name_end - start >= sizeof(fn->name))
                        name_end = start + sizeof(fn->name) - 1;
                    memcpy(fn->name, src + start, name_end - start);
                    fn->name[name_end - start] = '\0';
                    fn->line = line;
                    len = k - body_start;   /* "{ ... }" */
                    sha256_hex(src + body_start, len, hashbuf);
                    memcpy(fn->hash, hashbuf, 65);
                    n++;
                    if (n >= cap)
                        return n;
                }
            }
            /* lanjut scan dari akhir body */
            continue;
        }

        i++;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Replay                                                              */
/* ------------------------------------------------------------------ */

/* Isi res dari entry cache. Replay harus mengisi SEMUA komponen receipt
 * (verdict/completeness/gates/debt/fingerprint/source) agar receipt_sha256
 * konsisten dengan hasil yang pernah dihitung. */
static void cache_replay_into(const myc_cache_entry *e, myc_result *res)
{
    int i;

    res->verdict = e->verdict;
    res->err = e->err;
    res->assurance = e->assurance;
    res->assurance_vector = e->av;
    res->finding = e->finding;
    res->completeness = e->completeness;
    res->claim_status = e->claim;

    /* gates (id + requested ASLI dari cache, bukan index) */
    res->gate_count = 0;
    for (i = 0; i < e->gate_count && i < MYC_MAX_GATES; i++) {
        myc_gate_result *g = &res->gates[res->gate_count];
        g->id = (myc_gate_id)e->gate_id[i];
        g->status = e->gate_status[i];
        g->requested = e->gate_requested[i];
        g->findings = e->gate_findings[i];
        g->output = NULL;
        res->gate_count++;
    }

    /* debt (MYC-AUDIT-042: teks deskriptif asli di-replay identik;
     * entry cache lama tanpa debt_text -> fallback nama kode). */
    res->debt_count = 0;
    for (i = 0; i < e->debt_count && i < MYC_MAX_DEBT; i++) {
        res->debt[res->debt_count].type = e->debt[i].type;
        if (e->debt_text[i][0])
            res->debt[res->debt_count].text =
                myc_result_arena_dup(res, e->debt_text[i], 0);
        else
            res->debt[res->debt_count].text =
                myc_debt_type_name(e->debt[i].type);
        res->debt_count++;
    }

    /* diagnostics (ke arena milik hasil) */
    for (i = 0; i < e->diag_count && i < MYC_MAX_DIAGNOSTICS; i++) {
        res->diags[i].line = e->diag_line[i];
        res->diags[i].col = e->diag_col[i];
        res->diags[i].confidence = e->diag_conf[i];
        res->diags[i].message = myc_result_arena_dup(res, e->diag_msg[i], 0);
        res->diag_count = i + 1;
    }

    /* counts */
    res->lint_observations = e->lint_observations;
    res->negative_callsites = e->negative_callsites;
    res->negative_deviations = e->negative_deviations;
    res->checked_buffers = e->checked_buffers;
    res->checked_allocations = e->checked_allocations;
    res->checked_accesses = e->checked_accesses;
    res->checked_frees = e->checked_frees;
    res->checked_raw_buffers = e->checked_raw_buffers;
    res->driver_funcs = e->driver_funcs;
    res->driver_cases = e->driver_cases;
    res->driver_skipped = e->driver_skipped;
    res->ran_negative = e->ran_negative;
    res->ran_checked = e->ran_checked;
    res->ran_driver = e->ran_driver;

    /* snapshot lengkap field hasil (SOL-18 replay identik). */
    res->exit_code = e->exit_code;
    res->require_complete = e->require_complete;
    res->truncated = e->truncated;
    res->run_timed_out = e->run_timed_out;
    res->run_sanitizer_detected = e->run_sanitizer_detected;
    res->ran_runtime = e->ran_runtime;
    res->ran_prove = e->ran_prove;
    res->ran_filc = e->ran_filc;
    res->ran_metamorphic = e->ran_metamorphic;
    res->ran_preprocess = e->ran_preprocess;
    res->ran_compile = e->ran_compile;
    res->ran_analyzer = e->ran_analyzer;
    res->checked_uses_buf = e->checked_uses_buf;
    res->checked_build_ok = e->checked_build_ok;
    res->prove_alarms = e->prove_alarms;
    res->prove_proof_obligations = e->prove_proof_obligations;
    res->filc_panics = e->filc_panics;
    res->meta_o0_exit = e->meta_o0_exit;
    res->meta_o2_exit = e->meta_o2_exit;
    res->meta_o0_finding = e->meta_o0_finding;
    res->meta_o2_finding = e->meta_o2_finding;
    res->metamorphic_inconsistent = e->metamorphic_inconsistent;
    res->driver_max_product = e->driver_max_product;
    res->driver_bounded = e->driver_bounded;
    res->total_stdout_bytes = e->total_stdout_bytes;
    res->total_stderr_bytes = e->total_stderr_bytes;
    res->contract_requires = e->contract_requires;
    res->contract_ensures = e->contract_ensures;
    res->harvest_candidates = e->harvest_candidates;
    res->harvest_validated = e->harvest_validated;
    res->harvest_unbound = e->harvest_unbound;
    /* Fase 5: relational contracts (observasi, replay identik). */
    res->rel_analyzed = e->rel_analyzed;
    res->rel_relations = e->rel_relations;
    res->rel_unary = e->rel_unary;
    res->rel_unbound = e->rel_unbound;
    /* Fase 5 (SOL-13): ghost state machine (observasi, replay identik). */
    res->sm_states = e->sm_states;
    res->sm_events = e->sm_events;
    res->sm_transitions = e->sm_transitions;
    res->sm_findings = e->sm_findings;
    /* Fase 5 (SOL-14): ABI certificate (observasi, replay identik). */
    res->abi_ran = e->abi_ran;
    res->abi_n_structs = e->abi_n_structs;
    res->abi_n_enums = e->abi_n_enums;
    res->abi_n_symbols = e->abi_n_symbols;
    res->abi_changed = e->abi_changed;
    res->abi_n_delta = e->abi_n_delta;
    /* Fase 5 (SOL-12): Resource Linearity Ledger (replay identik counts). */
    res->rsrc_ran = e->rsrc_ran;
    res->rsrc_pairs = e->rsrc_pairs;
    res->rsrc_acquires = e->rsrc_acquires;
    res->rsrc_releases = e->rsrc_releases;
    res->rsrc_transferred = e->rsrc_transferred;
    res->rsrc_leaks = e->rsrc_leaks;
    res->rsrc_double_releases = e->rsrc_double_releases;
    res->rsrc_release_unknown = e->rsrc_release_unknown;
    /* Fase 5 (SOL-11): Units / Shape / Provenance (replay identik counts). */
    res->units_ran = e->units_ran;
    res->units_annotations = e->units_annotations;
    res->units_unbound = e->units_unbound;
    res->units_mismatches = e->units_mismatches;
    res->units_shape_dims = e->units_shape_dims;
    res->units_duplicates = e->units_duplicates;
    res->ran_exhaustive = e->ex_ran;
    res->exhaustive_funcs = e->ex_funcs;
    res->exhaustive_cases = e->ex_cases;
    res->exhaustive_skipped = e->ex_skip;
    res->exhaustive_points = e->ex_points;
    res->exhaustive_laundering = e->ex_laund;
    memcpy(res->exhaustive_domain_hash, e->ex_dhash,
           sizeof(res->exhaustive_domain_hash));
    /* SOL-30: hasil enforcement budget contract di-replay utuh (verdict/
     * debt/report sudah mencerminkan run asli; kontrak ada di cache key,
     * jadi re-enforce di jalur cache-hit TIDAK dilakukan). */
    res->budget_active = e->budget_active;
    res->budget_met = e->budget_met;
    if (e->budget_report[0]) {
        res->budget_report = myc_result_arena_dup(res, e->budget_report, 0);
        if (!res->budget_report)
            res->budget_report = NULL;
    }
    /* Fase 4 A1: replay host facts — deteksi asumsi tetap di-scan ulang
     * di jalur cache-hit (myc.c) memakai facts ini (tanpa exec gcc). */
    res->assumption_facts_ok = e->host_facts_ok;
    res->host_facts.ok = e->host_facts_ok;
    res->host_facts.char_unsigned = e->host_char_unsigned;
    res->host_facts.int_bits = e->host_int_bits;
    res->host_facts.ptr_bits = e->host_ptr_bits;
    res->host_facts.little_endian = e->host_little_endian;
    res->host_facts.stdc_version = e->host_stdc_version;
    res->host_facts.char_bit = e->host_char_bit;

    /* Fase 4 A2/DS-02: replay hasil gate divergence (sel matriks). */
    res->ran_divergence = e->divergence_ran > 0 ? 1 : 0;
    res->divergence_ran = e->divergence_ran;
    res->divergence_planned = e->divergence_planned;
    res->divergence_sanitizer_div = e->divergence_sanitizer_div;
    res->divergence_all_findings = e->divergence_all_findings;
    res->divergence_semantic_div = e->divergence_semantic_div;
    res->divergence_diag_div = e->divergence_diag_div;
    if (e->divergence_report[0]) {
        res->divergence_report =
            myc_result_arena_dup(res, e->divergence_report, 0);
    }
    res->divergence_ncells = e->divergence_ncells > MYC_DIVERGENCE_MAX_CELLS
                                ? MYC_DIVERGENCE_MAX_CELLS
                                : e->divergence_ncells;
    for (i = 0; i < res->divergence_ncells; i++) {
        myc_divergence_cell *c = &res->divergence_cells[i];
        memset(c, 0, sizeof(*c));
        c->opt_level = (int)e->divergence_cells[i].opt_level;
        c->available = (int)e->divergence_cells[i].available;
        c->san = (int)e->divergence_cells[i].san;
        c->built = (int)e->divergence_cells[i].built;
        c->ran = (int)e->divergence_cells[i].ran;
        c->timed_out = (int)e->divergence_cells[i].timed_out;
        c->finding = (int)e->divergence_cells[i].finding;
        c->diag_warn = (int)e->divergence_cells[i].diag_warn;
        c->exit_code = e->divergence_cells[i].exit_code;
        snprintf(c->tool, sizeof(c->tool), "%s",
                 e->divergence_cells[i].tool);
        /* tool_path: kosong pada replay — path absolut toolchain asli
         * TIDAK disimpan di cache (hanya nama tool). Jangan isi dengan
         * nama tool (menyesatkan: field bernama path berisi nama). */
        c->tool_path[0] = '\0';
        snprintf(c->marker, sizeof(c->marker), "%s",
                 e->divergence_cells[i].marker);
        snprintf(c->stdout_sha256, sizeof(c->stdout_sha256), "%s",
                 e->divergence_cells[i].stdout_sha256);
    }

    snprintf(res->run_sanitizer_marker,
             sizeof(res->run_sanitizer_marker), "%s", e->sanitizer_marker);
    /* PENTING (SOL-18): myc_result_free memanggil free() INDIVIDUAL pada
     * field-field ini (lihat myc_result_free). Karena itu replay WAJIB
     * memakai myc_strdup (malloc), BUKAN myc_result_arena_dup — arena
     * dibebaskan utuh oleh myc_result_free, free() individual pada
     * pointer arena = invalid free (heap corruption c0000374, pola sama
     * dengan bug witness Fase 3). */
    /* prove_mode/prove_version TIDAK di-free individual oleh
     * myc_result_free (arena-based) -> tetap arena dup. */
    res->prove_mode = myc_result_arena_dup(res, e->prove_mode, 0);
    res->prove_version = myc_result_arena_dup(res, e->prove_version, 0);
    res->filc_version = myc_strdup(e->filc_version);
    res->driver_harness_sha256 = myc_strdup(e->driver_harness_sha256);
    res->stderr_text = myc_strdup(e->stderr_text);
    res->run_stdout_text = myc_strdup(e->run_stdout_text);
    res->run_stderr_text = myc_strdup(e->run_stderr_text);
    res->prove_stdout_text = myc_strdup(e->prove_stdout_text);
    res->prove_stderr_text = myc_strdup(e->prove_stderr_text);
    res->filc_stdout_text = myc_strdup(e->filc_stdout_text);
    res->filc_stderr_text = myc_strdup(e->filc_stderr_text);
    res->driver_stdout_text = myc_strdup(e->driver_stdout_text);
    res->driver_stderr_text = myc_strdup(e->driver_stderr_text);

    /* resolved_gcc/gcc_version/clang_version: malloc di pipeline (di-free
     * individual oleh myc_result_free) -> strdup. */
    res->resolved_gcc = myc_strdup(e->resolved_gcc);
    res->gcc_version = myc_strdup(e->gcc_version);
    res->clang_version = myc_strdup(e->clang_version);

    /* driver case records: func/params arena-based di pipeline. */
    res->driver_case_count = 0;
    for (i = 0; i < e->driver_case_count && i < 64; i++) {
        myc_driver_case *r = &res->driver_case_records[res->driver_case_count];
        r->case_id = e->driver_records[i].case_id;
        r->alloc_bytes = e->driver_records[i].alloc_bytes;
        r->executed = e->driver_records[i].executed;
        r->func = myc_result_arena_dup(res, e->driver_records[i].func, 0);
        r->params = e->driver_records[i].params[0]
                        ? myc_result_arena_dup(res, e->driver_records[i].params, 0)
                        : NULL;
        res->driver_case_count++;
    }

    /* filc cases (arena-based). */
    res->filc_case_count = 0;
    for (i = 0; i < e->filc_case_count && i < 16; i++) {
        myc_filc_case *c = &res->filc_cases[res->filc_case_count];
        memset(c, 0, sizeof(*c));
        c->line = e->filc_cases[i].line;
        c->col = e->filc_cases[i].col;
        c->message = myc_result_arena_dup(res, e->filc_cases[i].message, 0);
        c->file = myc_result_arena_dup(res, e->filc_cases[i].file, 0);
        c->function = myc_result_arena_dup(res, e->filc_cases[i].function, 0);
        res->filc_case_count++;
    }

    /* contract clauses (arena-based). */
    res->contract_clause_count = 0;
    for (i = 0; i < e->contract_clause_count && i < 16; i++) {
        myc_contract_clause *cl =
            &res->contract_clauses[res->contract_clause_count];
        memset(cl, 0, sizeof(*cl));
        cl->kind = e->contract_clauses[i].kind;
        cl->line = e->contract_clauses[i].line;
        cl->col = e->contract_clauses[i].col;
        cl->status = (myc_clause_status)e->contract_clauses[i].status;
        cl->func = myc_result_arena_dup(res, e->contract_clauses[i].func, 0);
        cl->expr = myc_result_arena_dup(res, e->contract_clauses[i].expr, 0);
        res->contract_clause_count++;
    }

    /* evidence events: message malloc di pipeline (di-free individual) ->
     * strdup. */
    res->evidence_count = 0;
    for (i = 0; i < e->evidence_count && i < 32; i++) {
        myc_evidence_event *ev = &res->evidence[res->evidence_count++];
        ev->gate_id = (uint32_t)e->evidence[i].gate_id;
        ev->event_type = (uint32_t)e->evidence[i].event_type;
        ev->message = myc_strdup(e->evidence[i].message);
    }

    /* identity + receipt (agar deterministik) */
    res->source_sha256 = myc_strdup(e->source_sha256);
    res->fingerprint = myc_strdup(e->fingerprint);
    memcpy(res->receipt_sha256, e->receipt_sha256, 65);

    res->cache_hit = 1;
}

/* Cari entry dengan scenario+tool+cwd SAMA tapi source BERBEDA
 * (untuk delta report saat source berubah). Saat kedua sisi punya path
 * file, path harus cocok juga supaya tidak membandingkan file BERBEDA.
 * Return index atau -1. */
static int cache_find_stale(const myc_cache_entry *entries, int n,
                            const char *source_sha256,
                            const char *scenario_hash,
                            const char *tool_key,
                            const char *cwd,
                            const char *path)
{
    int i;
    for (i = 0; i < n; i++) {
        if (strcmp(entries[i].scenario_hash, scenario_hash) != 0 ||
            strcmp(entries[i].tool_key, tool_key) != 0 ||
            strcmp(entries[i].cwd, cwd) != 0 ||
            strcmp(entries[i].source_sha256, source_sha256) == 0)
            continue;
        /* bila path tersedia di kedua sisi, harus cocok (file yang sama). */
        if (path && path[0] && entries[i].path[0] &&
            strcmp(entries[i].path, path) != 0)
            continue;
        return i;
    }
    return -1;
}

int myc_cache_try_replay(const myc_request *req, myc_result *res,
                         const char *src, size_t srclen)
{
    /* Entry cache besar (~100KB): array harus di HEAP, bukan stack
     * (64 entries di stack = stack overflow, crash c00000fd). */
    myc_cache_entry *entries;
    char tool[129];
    char key[65];
    char source_hex[65];
    char scenario[17];
    char *scen_full;
    int  n, i, ret = 0;

    if (!req || !res || !src)
        return 0;
    if (req->no_cache)
        return 0;
    if (srclen == 0)
        return 0;
    /* Fase 4 A1 (review fix): run yang MENGUBAH/menggantung pada state
     * eksternal .myc/assumptions.json (--assumption-ack menulis state;
     * --require-assumptions-closed menegakkan atas state) TIDAK boleh
     * di-replay: entry lama bisa memuat verdict/debt/receipt dari state
     * yang sudah berubah (mis. ack menutup asumsi setelah entry dibuat)
     * -> hasil stale yang kontradiktif. Run ini selalu lewat pipeline
     * (filosofi sama dgn fix SOL-30: enforcement stateful tak di-replay). */
    if (req->require_assumptions_closed || req->assumption_acks)
        return 0;

    entries = (myc_cache_entry *)myc_calloc(MYC_CACHE_MAX_ENTRIES,
                                        sizeof(*entries));
    if (!entries)
        return 0;

    sha256_hex(src, srclen, source_hex);
    cache_tool_key(req, tool, sizeof(tool));
    cache_build_key(req, src, srclen, tool, key);

    scen_full = myc_ledger_build_scenario_hash(req, NULL);
    if (scen_full) {
        snprintf(scenario, sizeof(scenario), "%s", scen_full);
        myc_free(scen_full);
    } else {
        snprintf(scenario, sizeof(scenario), "?");
    }

    n = cache_read_all(entries, MYC_CACHE_MAX_ENTRIES);
    for (i = 0; i < n; i++) {
        if (strcmp(entries[i].key_sha256, key) == 0) {
            cache_replay_into(&entries[i], res);
            ret = 1;
            goto done;
        }
    }

    /* Miss tapi source BERUBAH dengan scenario sama: hitung delta
     * (fungsi berubah + dependents) agar edit satu fungsi terlihat
     * scope-nya tanpa harus membandingkan seluruh output. */
    {
        int stale = cache_find_stale(entries, n, source_hex, scenario, tool,
                                     req->cwd ? req->cwd : "",
                                     req->input.file_path ?
                                         req->input.file_path : "");
        if (stale >= 0) {
            res->cache_delta_report =
                myc_cache_delta_report(src, srclen, &entries[stale]);
        }
    }

done:
    myc_free(entries);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Store                                                               */
/* ------------------------------------------------------------------ */

void myc_cache_store(const myc_request *req, const myc_result *res,
                     const char *src, size_t srclen)
{
    /* Fase 4 A1 (review fix): konsisten dgn try_replay — run stateful
     * (--assumption-ack / --require-assumptions-closed) tidak disimpan
     * ke cache (state eksternal .myc/assumptions.json bisa berubah;
     * replay entry lama = hasil stale). */
    if (req && (req->require_assumptions_closed || req->assumption_acks))
        return;
    /* Entry cache besar (~100KB): SEMUA di HEAP, bukan stack
     * (64 entries di stack = stack overflow c00000fd). */
    myc_cache_entry *entries;
    myc_cache_entry *ne;
    char tool[129];
    char key[65];
    int  n, i;

    if (!req || !res || !src)
        return;
    if (req->no_cache)
        return;
    if (srclen == 0)
        return;

    /* jangan cache hasil error/timeout (bukan bukti valid untuk replay) */
    if (res->verdict == MC_ERROR || res->err == MYC_ERR_TIMEOUT ||
        res->err == MYC_ERR_INTERNAL)
        return;

    entries = (myc_cache_entry *)myc_calloc(MYC_CACHE_MAX_ENTRIES,
                                        sizeof(*entries));
    ne = (myc_cache_entry *)myc_calloc(1, sizeof(*ne));
    if (!entries || !ne) {
        myc_free(entries);
        myc_free(ne);
        return;
    }
    cache_tool_key(req, tool, sizeof(tool));
    cache_build_key(req, src, srclen, tool, key);
    memcpy(ne->key_sha256, key, 65);
    sha256_hex(src, srclen, ne->source_sha256);
    {
        char *scen = myc_ledger_build_scenario_hash(req, NULL);
        snprintf(ne->scenario_hash, sizeof(ne->scenario_hash), "%s",
                 scen ? scen : "?");
        myc_free(scen);
    }
    snprintf(ne->tool_key, sizeof(ne->tool_key), "%s", tool);
    snprintf(ne->cwd, sizeof(ne->cwd), "%s", req->cwd ? req->cwd : "");
    snprintf(ne->path, sizeof(ne->path), "%s",
             req->input.file_path ? req->input.file_path : "");
    memcpy(ne->receipt_sha256, res->receipt_sha256, 65);
    snprintf(ne->fingerprint, sizeof(ne->fingerprint), "%s",
             res->fingerprint ? res->fingerprint : "");

    ne->verdict = res->verdict;
    ne->err = res->err;
    ne->assurance = res->assurance;
    ne->av = res->assurance_vector;
    ne->finding = res->finding;
    ne->completeness = res->completeness;
    ne->claim = res->claim_status;
    ne->duration_ms = res->duration_ms;

    ne->lint_observations = res->lint_observations;
    ne->negative_callsites = res->negative_callsites;
    ne->negative_deviations = res->negative_deviations;
    ne->checked_buffers = res->checked_buffers;
    ne->checked_allocations = res->checked_allocations;
    ne->checked_accesses = res->checked_accesses;
    ne->checked_frees = res->checked_frees;
    ne->checked_raw_buffers = res->checked_raw_buffers;
    ne->budget_active = res->budget_active;
    ne->budget_met = res->budget_met;
    if (res->budget_report)
        snprintf(ne->budget_report, sizeof(ne->budget_report), "%s",
                 res->budget_report);
    /* Fase 4 A1: host facts toolchain (replay tanpa exec gcc). */
    ne->host_facts_ok = res->assumption_facts_ok;
    ne->host_char_unsigned = res->host_facts.char_unsigned;
    ne->host_int_bits = res->host_facts.int_bits;
    ne->host_ptr_bits = res->host_facts.ptr_bits;
    ne->host_little_endian = res->host_facts.little_endian;
    ne->host_stdc_version = res->host_facts.stdc_version;
    ne->host_char_bit = res->host_facts.char_bit;
    /* Fase 4 A2/DS-02: snapshot hasil gate divergence. */
    ne->divergence_ran = res->divergence_ran;
    ne->divergence_planned = res->divergence_planned;
    ne->divergence_ncells = res->divergence_ncells;
    ne->divergence_sanitizer_div = res->divergence_sanitizer_div;
    ne->divergence_all_findings = res->divergence_all_findings;
    ne->divergence_semantic_div = res->divergence_semantic_div;
    ne->divergence_diag_div = res->divergence_diag_div;
    if (res->divergence_report)
        snprintf(ne->divergence_report, sizeof(ne->divergence_report), "%s",
                 res->divergence_report);
    for (i = 0; i < (int)res->divergence_ncells &&
                i < MYC_DIVERGENCE_MAX_CELLS; i++) {
        const myc_divergence_cell *c = &res->divergence_cells[i];
        ne->divergence_cells[i].opt_level = (char)c->opt_level;
        ne->divergence_cells[i].available = (char)c->available;
        ne->divergence_cells[i].san = (char)c->san;
        ne->divergence_cells[i].built = (char)c->built;
        ne->divergence_cells[i].ran = (char)c->ran;
        ne->divergence_cells[i].timed_out = (char)c->timed_out;
        ne->divergence_cells[i].finding = (char)c->finding;
        ne->divergence_cells[i].diag_warn = (char)c->diag_warn;
        ne->divergence_cells[i].exit_code = c->exit_code;
        snprintf(ne->divergence_cells[i].tool,
                 sizeof(ne->divergence_cells[i].tool), "%s", c->tool);
        snprintf(ne->divergence_cells[i].marker,
                 sizeof(ne->divergence_cells[i].marker), "%s", c->marker);
        snprintf(ne->divergence_cells[i].stdout_sha256,
                 sizeof(ne->divergence_cells[i].stdout_sha256), "%s",
                 c->stdout_sha256);
    }
    ne->driver_funcs = res->driver_funcs;
    ne->driver_cases = res->driver_cases;
    ne->driver_skipped = res->driver_skipped;
    ne->ran_negative = res->ran_negative;
    ne->ran_checked = res->ran_checked;
    ne->ran_driver = res->ran_driver;

    /* snapshot lengkap field hasil (SOL-18 replay identik). */
    ne->exit_code = res->exit_code;
    ne->require_complete = res->require_complete;
    ne->truncated = res->truncated;
    ne->run_timed_out = res->run_timed_out;
    ne->run_sanitizer_detected = res->run_sanitizer_detected;
    ne->ran_runtime = res->ran_runtime;
    ne->ran_prove = res->ran_prove;
    ne->ran_filc = res->ran_filc;
    ne->ran_metamorphic = res->ran_metamorphic;
    ne->ran_preprocess = res->ran_preprocess;
    ne->ran_compile = res->ran_compile;
    ne->ran_analyzer = res->ran_analyzer;
    ne->checked_uses_buf = res->checked_uses_buf;
    ne->checked_build_ok = res->checked_build_ok;
    ne->prove_alarms = res->prove_alarms;
    ne->prove_proof_obligations = res->prove_proof_obligations;
    ne->filc_panics = res->filc_panics;
    ne->meta_o0_exit = res->meta_o0_exit;
    ne->meta_o2_exit = res->meta_o2_exit;
    ne->meta_o0_finding = res->meta_o0_finding;
    ne->meta_o2_finding = res->meta_o2_finding;
    ne->metamorphic_inconsistent = res->metamorphic_inconsistent;
    ne->driver_max_product = res->driver_max_product;
    ne->driver_bounded = res->driver_bounded;
    ne->total_stdout_bytes = res->total_stdout_bytes;
    ne->total_stderr_bytes = res->total_stderr_bytes;
    ne->contract_requires = res->contract_requires;
    ne->contract_ensures = res->contract_ensures;
    ne->harvest_candidates = res->harvest_candidates;
    ne->harvest_validated = res->harvest_validated;
    ne->harvest_unbound = res->harvest_unbound;
    /* Fase 5: relational contracts (observasi, replay identik). */
    ne->rel_analyzed = res->rel_analyzed;
    ne->rel_relations = res->rel_relations;
    ne->rel_unary = res->rel_unary;
    ne->rel_unbound = res->rel_unbound;
    /* Fase 5 (SOL-13): ghost state machine (observasi, replay identik). */
    ne->sm_states = res->sm_states;
    ne->sm_events = res->sm_events;
    ne->sm_transitions = res->sm_transitions;
    ne->sm_findings = res->sm_findings;
    /* Fase 5 (SOL-14): ABI certificate (observasi, replay identik). */
    ne->abi_ran = res->abi_ran;
    ne->abi_n_structs = res->abi_n_structs;
    ne->abi_n_enums = res->abi_n_enums;
    ne->abi_n_symbols = res->abi_n_symbols;
    ne->abi_changed = res->abi_changed;
    ne->abi_n_delta = res->abi_n_delta;
    /* Fase 5 (SOL-12): Resource Lineary Ledger (replay identik counts). */
    ne->rsrc_ran = res->rsrc_ran;
    ne->rsrc_pairs = res->rsrc_pairs;
    ne->rsrc_acquires = res->rsrc_acquires;
    ne->rsrc_releases = res->rsrc_releases;
    ne->rsrc_transferred = res->rsrc_transferred;
    ne->rsrc_leaks = res->rsrc_leaks;
    ne->rsrc_double_releases = res->rsrc_double_releases;
    ne->rsrc_release_unknown = res->rsrc_release_unknown;
    /* Fase 5 (SOL-11): Units / Shape / Provenance (replay identik counts). */
    ne->units_ran = res->units_ran;
    ne->units_annotations = res->units_annotations;
    ne->units_unbound = res->units_unbound;
    ne->units_mismatches = res->units_mismatches;
    ne->units_shape_dims = res->units_shape_dims;
    ne->units_duplicates = res->units_duplicates;
    ne->ex_ran = res->ran_exhaustive;
    ne->ex_funcs = res->exhaustive_funcs;
    ne->ex_cases = res->exhaustive_cases;
    ne->ex_skip = res->exhaustive_skipped;
    ne->ex_points = res->exhaustive_points;
    ne->ex_laund = res->exhaustive_laundering;
    memcpy(ne->ex_dhash, res->exhaustive_domain_hash,
           sizeof(ne->ex_dhash));

    snprintf(ne->sanitizer_marker, sizeof(ne->sanitizer_marker), "%s",
             res->run_sanitizer_marker);
    snprintf(ne->prove_mode, sizeof(ne->prove_mode), "%s",
             res->prove_mode ? res->prove_mode : "");
    snprintf(ne->prove_version, sizeof(ne->prove_version), "%s",
             res->prove_version ? res->prove_version : "");
    snprintf(ne->filc_version, sizeof(ne->filc_version), "%s",
             res->filc_version ? res->filc_version : "");
    snprintf(ne->driver_harness_sha256, sizeof(ne->driver_harness_sha256),
             "%s", res->driver_harness_sha256 ? res->driver_harness_sha256 : "");
    snprintf(ne->stderr_text, sizeof(ne->stderr_text), "%s",
             res->stderr_text ? res->stderr_text : "");
    snprintf(ne->run_stdout_text, sizeof(ne->run_stdout_text), "%s",
             res->run_stdout_text ? res->run_stdout_text : "");
    snprintf(ne->run_stderr_text, sizeof(ne->run_stderr_text), "%s",
             res->run_stderr_text ? res->run_stderr_text : "");
    snprintf(ne->prove_stdout_text, sizeof(ne->prove_stdout_text), "%s",
             res->prove_stdout_text ? res->prove_stdout_text : "");
    snprintf(ne->prove_stderr_text, sizeof(ne->prove_stderr_text), "%s",
             res->prove_stderr_text ? res->prove_stderr_text : "");
    snprintf(ne->filc_stdout_text, sizeof(ne->filc_stdout_text), "%s",
             res->filc_stdout_text ? res->filc_stdout_text : "");
    snprintf(ne->filc_stderr_text, sizeof(ne->filc_stderr_text), "%s",
             res->filc_stderr_text ? res->filc_stderr_text : "");
    snprintf(ne->driver_stdout_text, sizeof(ne->driver_stdout_text), "%s",
             res->driver_stdout_text ? res->driver_stdout_text : "");
    snprintf(ne->driver_stderr_text, sizeof(ne->driver_stderr_text), "%s",
             res->driver_stderr_text ? res->driver_stderr_text : "");
    snprintf(ne->resolved_gcc, sizeof(ne->resolved_gcc), "%s",
             res->resolved_gcc ? res->resolved_gcc : "");
    snprintf(ne->gcc_version, sizeof(ne->gcc_version), "%s",
             res->gcc_version ? res->gcc_version : "");
    snprintf(ne->clang_version, sizeof(ne->clang_version), "%s",
             res->clang_version ? res->clang_version : "");

    /* driver case records */
    ne->driver_case_count = 0;
    for (i = 0; i < (int)res->driver_case_count && i < 64; i++) {
        const myc_driver_case *r = &res->driver_case_records[i];
        ne->driver_records[ne->driver_case_count].case_id = r->case_id;
        ne->driver_records[ne->driver_case_count].alloc_bytes = r->alloc_bytes;
        ne->driver_records[ne->driver_case_count].executed = r->executed;
        snprintf(ne->driver_records[ne->driver_case_count].func,
                 sizeof(ne->driver_records[ne->driver_case_count].func),
                 "%s", r->func ? r->func : "");
        snprintf(ne->driver_records[ne->driver_case_count].params,
                 sizeof(ne->driver_records[ne->driver_case_count].params),
                 "%s", r->params ? r->params : "");
        ne->driver_case_count++;
    }

    /* filc cases */
    ne->filc_case_count = 0;
    for (i = 0; i < (int)res->filc_case_count && i < 16; i++) {
        const myc_filc_case *c = &res->filc_cases[i];
        ne->filc_cases[ne->filc_case_count].line = c->line;
        ne->filc_cases[ne->filc_case_count].col = c->col;
        snprintf(ne->filc_cases[ne->filc_case_count].message,
                 sizeof(ne->filc_cases[ne->filc_case_count].message),
                 "%s", c->message ? c->message : "");
        snprintf(ne->filc_cases[ne->filc_case_count].file,
                 sizeof(ne->filc_cases[ne->filc_case_count].file),
                 "%s", c->file ? c->file : "");
        snprintf(ne->filc_cases[ne->filc_case_count].function,
                 sizeof(ne->filc_cases[ne->filc_case_count].function),
                 "%s", c->function ? c->function : "");
        ne->filc_case_count++;
    }

    /* contract clauses */
    ne->contract_clause_count = 0;
    for (i = 0; i < (int)res->contract_clause_count && i < 16; i++) {
        const myc_contract_clause *cl = &res->contract_clauses[i];
        ne->contract_clauses[ne->contract_clause_count].kind = cl->kind;
        ne->contract_clauses[ne->contract_clause_count].line = cl->line;
        ne->contract_clauses[ne->contract_clause_count].col = cl->col;
        ne->contract_clauses[ne->contract_clause_count].status = cl->status;
        snprintf(ne->contract_clauses[ne->contract_clause_count].func,
                 sizeof(ne->contract_clauses[ne->contract_clause_count].func),
                 "%s", cl->func ? cl->func : "");
        snprintf(ne->contract_clauses[ne->contract_clause_count].expr,
                 sizeof(ne->contract_clauses[ne->contract_clause_count].expr),
                 "%s", cl->expr ? cl->expr : "");
        ne->contract_clause_count++;
    }

    /* evidence events */
    ne->evidence_count = 0;
    for (i = 0; i < (int)res->evidence_count && i < 32; i++) {
        const myc_evidence_event *ev = &res->evidence[i];
        ne->evidence[ne->evidence_count].gate_id = (int)ev->gate_id;
        ne->evidence[ne->evidence_count].event_type = (int)ev->event_type;
        snprintf(ne->evidence[ne->evidence_count].message,
                 sizeof(ne->evidence[ne->evidence_count].message),
                 "%s", ev->message ? ev->message : "");
        ne->evidence_count++;
    }

    for (i = 0; i < (int)res->gate_count && i < MYC_MAX_GATES; i++) {
        ne->gate_status[i] = res->gates[i].status;
        ne->gate_requested[i] = res->gates[i].requested;
        ne->gate_id[i] = (int)res->gates[i].id;
        ne->gate_findings[i] = res->gates[i].findings;
        ne->gate_count++;
    }
    for (i = 0; i < (int)res->debt_count && i < MYC_MAX_DEBT; i++) {
        ne->debt[ne->debt_count].type = res->debt[i].type;
        /* MYC-AUDIT-042: simpan teks deskriptif (replay identik). */
        snprintf(ne->debt_text[ne->debt_count],
                 sizeof(ne->debt_text[ne->debt_count]), "%s",
                 res->debt[i].text ? res->debt[i].text : "");
        ne->debt_count++;
    }
    for (i = 0; i < (int)res->diag_count && i < MYC_MAX_DIAGNOSTICS; i++) {
        ne->diag_line[i] = res->diags[i].line;
        ne->diag_col[i] = res->diags[i].col;
        ne->diag_conf[i] = res->diags[i].confidence;
        snprintf(ne->diag_msg[i], sizeof(ne->diag_msg[i]), "%s",
                 res->diags[i].message ? res->diags[i].message : "");
        ne->diag_count++;
    }
    ne->func_count = myc_cache_extract_functions(src, srclen, ne->funcs,
                                                 MYC_CACHE_MAX_FUNCS);
    if (ne->func_count < 0)
        ne->func_count = 0;

    /* merge: replace bila key sama, append bila baru, cap entries */
    n = cache_read_all(entries, MYC_CACHE_MAX_ENTRIES);
    {
        int found = -1;
        for (i = 0; i < n; i++) {
            if (strcmp(entries[i].key_sha256, key) == 0) {
                found = i;
                break;
            }
        }
        if (found >= 0) {
            entries[found] = *ne;
        } else if (n < MYC_CACHE_MAX_ENTRIES) {
            entries[n] = *ne;
            n++;
        } else {
            /* buang entry tertua (index 0) */
            memmove(&entries[0], &entries[1],
                    sizeof(entries[0]) * (size_t)(n - 1));
            entries[n - 1] = *ne;
        }
    }
    cache_write_all(entries, n);
    myc_free(ne);
    myc_free(entries);
}

void myc_cache_entry_free(myc_cache_entry *e)
{
    /* Semua field flat (tidak ada heap string di luar struct) — memset
     * cukup. Dijaga untuk kompatibilitas masa depan. */
    if (e)
        memset(e, 0, sizeof(*e));
}

/* ------------------------------------------------------------------ */
/* Delta report                                                        */
/* ------------------------------------------------------------------ */

/* Cari fungsi bernama `name` di daftar; return index atau -1. */
static int find_func(const myc_cache_function *f, int n, const char *name)
{
    int i;
    for (i = 0; i < n; i++) {
        if (strcmp(f[i].name, name) == 0)
            return i;
    }
    return -1;
}

/* Cari nama di daftar nama (char[][64]); return 1 bila ada. */
static int find_name(char (*names)[64], int n, const char *name)
{
    int i;
    for (i = 0; i < n; i++) {
        if (strcmp(names[i], name) == 0)
            return 1;
    }
    return 0;
}

/* Rentang fungsi (untuk deteksi dependents yang benar). */
typedef struct {
    char   name[64];
    int    line;
    size_t start;   /* posisi '{' */
    size_t end;     /* posisi SETELAH '}' penutup */
    char   hash[65];
} range_func;

/* Cari nama di daftar range_func; return index atau -1. */
static int find_range_func(const range_func *f, int n, const char *name)
{
    int i;
    for (i = 0; i < n; i++) {
        if (strcmp(f[i].name, name) == 0)
            return i;
    }
    return -1;
}

/* Ekstrak fungsi + rentang body (varian lokal myc_cache_extract_functions). */
static int extract_ranges(const char *src, size_t srclen,
                          range_func *out, int cap)
{
    size_t i = 0;
    int    depth = 0;
    int    line = 1;
    int    n = 0;

    while (i < srclen) {
        char c = src[i];
        if (c == '\n')
            line++;
        if (c == '/' && i + 1 < srclen) {
            if (src[i + 1] == '/') {
                while (i < srclen && src[i] != '\n') i++;
                continue;
            }
            if (src[i + 1] == '*') {
                i += 2;
                while (i + 1 < srclen && !(src[i] == '*' && src[i+1] == '/')) i++;
                i += 2;
                continue;
            }
        }
        if (c == '"' || c == '\'') {
            char q = c;
            i++;
            while (i < srclen && src[i] != q) {
                if (src[i] == '\\') i++;
                i++;
            }
            i++;
            continue;
        }
        if (c == '{') { depth++; i++; continue; }
        if (c == '}') { if (depth > 0) depth--; i++; continue; }
        if (c == '#') { while (i < srclen && src[i] != '\n') i++; continue; }

        if (depth == 0 && is_ident_char(c) && !(c >= '0' && c <= '9')) {
            size_t start = i, name_end, j;
            while (i < srclen && is_ident_char(src[i])) i++;
            name_end = i;
            if (is_keyword(src + start, name_end - start))
                continue;
            j = skip_ws_comments(src, srclen, i);
            if (j >= srclen || src[j] != '(')
                continue;
            { int paren = 1; j++; while (j < srclen && paren > 0) {
                if (src[j] == '(') paren++;
                else if (src[j] == ')') paren--;
                j++; } }
            j = skip_ws_comments(src, srclen, j);
            if (j >= srclen || src[j] != '{')
                continue;
            {
                size_t body_start = j;
                int bd = 1;
                size_t k = j + 1;
                while (k < srclen && bd > 0) {
                    if (src[k] == '{') bd++;
                    else if (src[k] == '}') bd--;
                    k++;
                }
                if (bd == 0 && n < cap) {
                    range_func *fn = &out[n];
                    size_t len = name_end - start;
                    if (len >= sizeof(fn->name)) len = sizeof(fn->name) - 1;
                    memcpy(fn->name, src + start, len);
                    fn->name[len] = '\0';
                    fn->line = line;
                    fn->start = body_start;
                    fn->end = k;
                    sha256_hex(src + body_start, k - body_start, fn->hash);
                    n++;
                }
            }
            continue;
        }
        i++;
    }
    return n;
}

/* Apakah token `needle` muncul di rentang [start,end) sebagai identifier
 * utuh (bukan substring, mis. foo vs foo_bar)? */
static int token_in_range(const char *src, size_t start, size_t end,
                          const char *needle)
{
    size_t nl = strlen(needle);
    size_t p = start;
    if (nl == 0 || end <= start)
        return 0;
    while (p + nl <= end) {
        const char *hit = memchr(src + p, needle[0], end - p);
        if (!hit)
            return 0;
        p = (size_t)(hit - src);
        if (p + nl <= end &&
            strncmp(src + p, needle, nl) == 0 &&
            (p == start || !is_ident_char(src[p - 1])) &&
            (p + nl >= end || !is_ident_char(src[p + nl]))) {
            return 1;
        }
        p += 1;
    }
    return 0;
}

char *myc_cache_delta_report(const char *src, size_t srclen,
                             const myc_cache_entry *old_entry)
{
    range_func cur[MYC_CACHE_MAX_FUNCS];
    char changed[1024];
    char identical[1024];
    char added[1024];
    char removed[1024];
    char dependents[1024];
    char changed_names[MYC_CACHE_MAX_FUNCS][64];
    int  cur_n, changed_n = 0, i, j;
    int  n_changed = 0, n_identical = 0, n_added = 0, n_removed = 0, n_dep = 0;
    size_t co = 0, io = 0, ao = 0, ro = 0, dp = 0;

    if (!src || !old_entry)
        return NULL;

    cur_n = extract_ranges(src, srclen, cur, MYC_CACHE_MAX_FUNCS);
    if (cur_n < 0)
        return NULL;

    changed[0] = identical[0] = added[0] = removed[0] = dependents[0] = '\0';

    /* fungsi berubah / identik / BARU (bandingkan vs cache), dan
     * kumpulkan nama fungsi berubah. */
    for (i = 0; i < cur_n; i++) {
        int oi = find_func(old_entry->funcs, old_entry->func_count,
                           cur[i].name);
        if (oi >= 0 && strcmp(cur[i].hash, old_entry->funcs[oi].hash) == 0) {
            n_identical++;
            if (io < sizeof(identical) - 64) {
                int r = snprintf(identical + io, sizeof(identical) - io,
                                 "%s%s", io ? "," : "", cur[i].name);
                if (r > 0) io += (size_t)r;
            }
        } else if (oi >= 0) {
            n_changed++;
            if (co < sizeof(changed) - 64) {
                int r = snprintf(changed + co, sizeof(changed) - co,
                                 "%s%s", co ? "," : "", cur[i].name);
                if (r > 0) co += (size_t)r;
            }
            if (changed_n < MYC_CACHE_MAX_FUNCS) {
                size_t nl = strlen(cur[i].name);
                if (nl >= 64)
                    nl = 63;
                memcpy(changed_names[changed_n], cur[i].name, nl);
                changed_names[changed_n][nl] = '\0';
                changed_n++;
            }
        } else {
            n_added++;
            if (ao < sizeof(added) - 64) {
                int r = snprintf(added + ao, sizeof(added) - ao,
                                 "%s%s", ao ? "," : "", cur[i].name);
                if (r > 0) ao += (size_t)r;
            }
            /* fungsi baru juga perlu dependents (memanggil fungsi lain). */
            if (changed_n < MYC_CACHE_MAX_FUNCS) {
                size_t nl = strlen(cur[i].name);
                if (nl >= 64)
                    nl = 63;
                memcpy(changed_names[changed_n], cur[i].name, nl);
                changed_names[changed_n][nl] = '\0';
                changed_n++;
            }
        }
    }

    /* fungsi yang HILANG dari cache (sudah dihapus/rename di source). */
    for (i = 0; i < old_entry->func_count; i++) {
        if (find_range_func(cur, cur_n, old_entry->funcs[i].name) < 0) {
            n_removed++;
            if (ro < sizeof(removed) - 64) {
                int r = snprintf(removed + ro, sizeof(removed) - ro,
                                 "%s%s", ro ? "," : "",
                                 old_entry->funcs[i].name);
                if (r > 0) ro += (size_t)r;
            }
        }
    }

    /* dependents: fungsi (yang TIDAK berubah) yang body-nya memanggil
     * salah satu fungsi berubah/baru -> perlu diverifikasi ulang. */
    for (i = 0; i < cur_n; i++) {
        int self_changed = 0;
        if (find_name(changed_names, changed_n, cur[i].name))
            self_changed = 1;
        if (self_changed)
            continue;
        for (j = 0; j < changed_n; j++) {
            if (token_in_range(src, cur[i].start, cur[i].end,
                               changed_names[j])) {
                n_dep++;
                if (dp < sizeof(dependents) - 64) {
                    int r = snprintf(dependents + dp, sizeof(dependents) - dp,
                                     "%s%s", dp ? "," : "", cur[i].name);
                    if (r > 0) dp += (size_t)r;
                }
                break;
            }
        }
    }

    {
        char *out = (char *)myc_malloc(3072);
        if (!out)
            return NULL;
        snprintf(out, 3072,
                 "%d berubah (%s); %d identik (%s); %d baru (%s); "
                 "%d hilang (%s)%s%s",
                 n_changed, n_changed ? changed : "-",
                 n_identical, n_identical ? identical : "-",
                 n_added, n_added ? added : "-",
                 n_removed, n_removed ? removed : "-",
                 n_dep ? "; dependents: " : "",
                 n_dep ? dependents : "");
        return out;
    }
}
