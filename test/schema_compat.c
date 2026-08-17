/*
 * schema_compat.c -- PR-015 (MYC-AUDIT-047): schema compatibility —
 * freeze machine API schemas + golden files.
 *
 * Skema JSON yang dipertukarkan antara komponen myc dan konsumen mesin
 * (CLI, MCP client, agent harness, CI, state .myc/) dibekukan di
 * `docs/schema-registry.md` dengan **golden file** di `test/golden/`.
 * Test ini membuktikan (registry, aturan golden #2):
 *
 *   T1  Semua golden file ter-parse oleh json.c (golden tidak busuk).
 *   T2  myc.result.v1  (--json-summary): 38 field wajib + tipe + enum
 *       (verdict/assurance_vector/gate_matrix) dalam himpunan beku.
 *   T3  myc.agent.v2   (--agent): field wajib + tipe (sha256 hex64,
 *       payload_cap, assurance_vector int, next_check, frontier).
 *   T4  myc.calibration.v1: field + enum outcome beku + konsumen
 *       (myc_calib_read_counts) MENERIMA golden.
 *   T5  evidence_cache: entry golden diterima pembaca cache (sidecar
 *       sha256 byte-mentah sah, replay MISS hanya karena key beda,
 *       entry TIDAK dikarantina / file tidak di-heal).
 *   T6  myc.scenario.v1: field + konsumen (myc_scenario_info) menerima
 *       golden; version != 1 = fail-closed -2 (INV-011).
 *   T7  myc.spec.v1: field + konsumen (myc_pack_load) menerima golden;
 *       version != 1 = fail-fast -1.
 *   T8  MCP JSON-RPC 2.0 envelope request/response: jsonrpc "2.0",
 *       id, method/params dan result/content/structuredContent/isError.
 *       Fail-closed konsumen: cache verdict out-of-range + sidecar sah
 *       = dikarantina (L2, PR-013); calib korup = 0 entry tanpa crash.
 *   T9  Evolution additive: field ASING pada golden TETAP diterima
 *       konsumen lama (calib/cache/scenario/spec) — konsumen tidak
 *       boleh menolak dokumen dengan field baru.
 *   T10 Produsen masih memancarkan SEMUA field beku (backward compat):
 *       myc_result_to_json memuat semua key top-level golden
 *       myc.result.v1; myc_agent_result_json memuat semua key golden
 *       myc.agent.v2. (Catatan: serializer penuh --json memakai bentuk
 *       nested assurance_vector {"status":...} vs summary flat — dua
 *       skema berbeda; T10 menguji KEBERADAAN key, T2 menguji bentuk
 *       summary.)
 *
 * Jalankan di direktori temp (test/.schema_compat_tmp); golden dibaca
 * dari <root>/test/golden/ (root = cwd proses saat start). Build
 * portabel (Windows MinGW + POSIX):
 *   gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
 *       -o schema_compat schema_compat.c <seluruh SRCS myc>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#define T_MKDIR(p) _mkdir(p)
#define T_CHDIR(p) _chdir(p)
#define T_RMDIR(p) _rmdir(p)
#define T_GETCWD(b, n) _getcwd((b), (n))
#else
#include <sys/stat.h>
#include <unistd.h>
#define T_MKDIR(p) mkdir((p), 0700)
#define T_CHDIR(p) chdir(p)
#define T_RMDIR(p) rmdir(p)
#define T_GETCWD(b, n) getcwd((b), (n))
#endif

#include "agent.h"
#include "cache.h"
#include "calibrate.h"
#include "json.h"
#include "myc.h"
#include "prompt.h"
#include "report.h"
#include "scenario.h"
#include "sha256.h"

static int g_ok = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_ok++; } \
    else { g_fail++; fprintf(stderr, "[FAIL] %s (line %d)\n", (msg), __LINE__); } \
} while (0)

/* ------------------------------------------------------------------ */
/* Infra: root proyek, path golden, baca file, direktori temp          */
/* ------------------------------------------------------------------ */

static char        g_root[1024];
static char        g_old_cwd[1024];
static const char *g_dir = "test/.schema_compat_tmp";
static const char *g_cache = ".myc/evidence_cache.json";
static const char *g_sha = ".myc/evidence_cache.sha256";
static const char *g_calib = ".myc/calibration.json";

static void save_cwd(void)
{
    if (T_GETCWD(g_old_cwd, sizeof(g_old_cwd)) == NULL)
        g_old_cwd[0] = '\0';
    snprintf(g_root, sizeof(g_root), "%s", g_old_cwd);
}

static void golden_path(char *out, size_t cap, const char *name)
{
    /* root sebagai pointer (bukan array global): kompiler tidak bisa
     * membuktikan truncation -> tanpa -Wformat-truncation palsu. */
    const char *root = g_root;
    if (snprintf(out, cap, "%s/test/golden/%s", root, name) >= (int)cap)
        out[0] = '\0';
}

/* Baca file teks; return malloc'd NUL-terminated, *len diisi. */
static char *read_file(const char *path, size_t *len)
{
    FILE *f;
    long  sz;
    char *buf;

    *len = 0;
    f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (32 << 20)) {
        fclose(f);
        return NULL;
    }
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[sz] = '\0';
    fclose(f);
    *len = (size_t)sz;
    return buf;
}

static void write_file_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (f) {
        fputs(text, f);
        fclose(f);
    }
}

static char *t_strdup(const char *s)
{
    char *d = (char *)malloc(strlen(s) + 1);
    if (d)
        strcpy(d, s);
    return d;
}

/* 1 bila string 64 hex (sha256 hex). */
static int hex64(const char *s)
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

/* ------------------------------------------------------------------ */
/* Type helpers atas json_value                                        */
/* ------------------------------------------------------------------ */

static int is_str(const json_value *v)  { return v && v->type == JSON_STR; }
static int is_num(const json_value *v)  { return v && v->type == JSON_NUM; }
static int is_bool(const json_value *v) { return v && v->type == JSON_BOOL; }
static int is_arr(const json_value *v)  { return v && v->type == JSON_ARR; }
static int is_obj(const json_value *v)  { return v && v->type == JSON_OBJ; }

static int str_in(const char *s, const char *const *set, int n)
{
    int i;
    for (i = 0; i < n; i++)
        if (strcmp(s, set[i]) == 0)
            return 1;
    return 0;
}

/* Parse golden file -> root JSON (T1 helper). */
static json_value *parse_golden(const char *name)
{
    char  path[2100];
    size_t len;
    char *text;
    json_value *root = NULL;

    golden_path(path, sizeof(path), name);
    text = read_file(path, &len);
    if (!text)
        return NULL;
    if (!json_parse_cstr(text, &root))
        root = NULL;
    free(text);
    return root;
}

/* ------------------------------------------------------------------ */
/* T1: semua golden ter-parse                                           */
/* ------------------------------------------------------------------ */

static void test_goldens_parse(void)
{
    static const char *const files[] = {
        "myc.result.v1.json",
        "myc.agent.v2.json",
        "myc.lite.v1.json",
        "myc.calibration.v1.json",
        "myc.evidence_cache.v1.json",
        "myc.scenario.v1.json",
        "myc.spec.v1.json",
        "mcp.request.tools-call.v1.json",
        "mcp.response.tools-call.v1.json"
    };
    size_t i;

    for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        json_value *root = parse_golden(files[i]);
        char label[160];
        snprintf(label, sizeof(label), "T1: golden %s ter-parse (objek)", files[i]);
        CHECK(root && root->type == JSON_OBJ, label);
        if (root)
            json_free(root);
    }
}

/* ------------------------------------------------------------------ */
/* T2: myc.result.v1 (summary) field/type/enum conformance              */
/* ------------------------------------------------------------------ */

static void test_result_v1(void)
{
    json_value *root = parse_golden("myc.result.v1.json");
    json_value *v, *av;
    char label[160];
    static const char dims[MYC_DIM_COUNT] = { 'C', 'S', 'R', 'B', 'P', 'D', 'F' };
    static const char *const dim_status[] = {
        "not_requested", "not_applicable", "clean", "findings",
        "inconclusive", "observations"
    };
    static const char *const gate_status[] = {
        "not_requested", "not_applicable", "unavailable", "infra_failed",
        "inconclusive", "completed_clean", "completed_findings",
        "completed_observations"
    };
    static const char *const ran_flags[] = {
        "ran_runtime", "ran_checked", "ran_prove", "ran_filc", "ran_driver",
        "ran_negative", "ran_metamorphic", "ran_exhaustive", "ran_compare",
        "ran_stack", "ran_fuzz", "ran_mutate", "ran_freestanding",
        "ran_divergence"
    };
    size_t i;

    CHECK(root != NULL, "T2: golden result.v1 ter-parse");
    if (!root)
        return;

    v = json_get(root, "verdict");
    CHECK(is_str(v) && strcmp(v->str, "OK") == 0, "T2: verdict = enum OK");
    v = json_get(root, "finding");
    CHECK(is_str(v) && strcmp(v->str, "clean") == 0, "T2: finding = clean");
    v = json_get(root, "completeness");
    CHECK(is_str(v) && strcmp(v->str, "complete") == 0, "T2: completeness = complete");
    v = json_get(root, "error");
    CHECK(is_str(v) && strcmp(v->str, "none") == 0, "T2: error = none");
    v = json_get(root, "exit_code");
    CHECK(is_num(v), "T2: exit_code numerik");
    v = json_get(root, "duration_ms");
    CHECK(is_num(v) && v->num >= 0, "T2: duration_ms numerik >= 0");
    v = json_get(root, "lint_observations");
    CHECK(is_num(v), "T2: lint_observations numerik");
    v = json_get(root, "lint_embedded_hits");
    CHECK(is_num(v), "T2: lint_embedded_hits numerik");
    v = json_get(root, "receipt_sha256");
    CHECK(is_str(v) && hex64(v->str), "T2: receipt_sha256 = sha256 hex64");

    /* assurance_vector: peta flat C/S/R/B/P/D/F -> status string beku. */
    av = json_get(root, "assurance_vector");
    CHECK(is_obj(av), "T2: assurance_vector objek");
    if (av) {
        for (i = 0; i < MYC_DIM_COUNT; i++) {
            char key[2] = { dims[i], '\0' };
            json_value *d = json_get(av, key);
            snprintf(label, sizeof(label),
                     "T2: assurance_vector[%s] = status string beku", key);
            CHECK(is_str(d) && str_in(d->str, dim_status, 6), label);
        }
    }

    v = json_get(root, "harvest");
    CHECK(is_obj(v) && is_num(json_get(v, "candidates")) &&
          is_num(json_get(v, "validated")) && is_num(json_get(v, "unbound")),
          "T2: harvest {candidates, validated, unbound}");
    v = json_get(root, "relational");
    CHECK(is_obj(v) && is_num(json_get(v, "analyzed")) &&
          is_num(json_get(v, "relations")) && is_num(json_get(v, "unbound")),
          "T2: relational {analyzed, relations, unbound}");
    v = json_get(root, "state_machine");
    CHECK(is_obj(v) && is_num(json_get(v, "states")) &&
          is_num(json_get(v, "events")) && is_num(json_get(v, "transitions")) &&
          is_num(json_get(v, "findings")),
          "T2: state_machine {states, events, transitions, findings}");
    v = json_get(root, "abi");
    CHECK(is_obj(v) && is_bool(json_get(v, "ran")) &&
          is_num(json_get(v, "structs")) && is_num(json_get(v, "enums")) &&
          is_num(json_get(v, "symbols")) && is_bool(json_get(v, "changed")) &&
          is_num(json_get(v, "delta")),
          "T2: abi {ran, structs, enums, symbols, changed, delta}");
    v = json_get(root, "resource");
    CHECK(is_obj(v) && is_bool(json_get(v, "ran")) &&
          is_num(json_get(v, "pairs")) && is_num(json_get(v, "acquires")) &&
          is_num(json_get(v, "releases")) && is_num(json_get(v, "transferred")) &&
          is_num(json_get(v, "leaks")) && is_num(json_get(v, "double_releases")) &&
          is_num(json_get(v, "release_unknown")),
          "T2: resource {ran, pairs..release_unknown}");
    v = json_get(root, "units");
    CHECK(is_obj(v) && is_bool(json_get(v, "ran")) &&
          is_num(json_get(v, "annotations")) && is_num(json_get(v, "unbound")) &&
          is_num(json_get(v, "unit_mismatches")) &&
          is_num(json_get(v, "shape_dims")) && is_num(json_get(v, "duplicates")),
          "T2: units {ran, annotations..duplicates}");
    v = json_get(root, "coaching");
    CHECK(is_arr(v), "T2: coaching array");

    for (i = 0; i < sizeof(ran_flags) / sizeof(ran_flags[0]); i++) {
        v = json_get(root, ran_flags[i]);
        snprintf(label, sizeof(label), "T2: %s boolean", ran_flags[i]);
        CHECK(is_bool(v), label);
    }

    v = json_get(root, "diagnostics");
    CHECK(is_arr(v), "T2: diagnostics array");
    v = json_get(root, "unverified_debt");
    CHECK(is_arr(v), "T2: unverified_debt array");
    v = json_get(root, "budget_met");
    CHECK(is_bool(v), "T2: budget_met boolean");
    v = json_get(root, "budget_report");
    CHECK(v == NULL || v->type == JSON_NULL, "T2: budget_report null bila tak aktif");
    v = json_get(root, "quorum_status");
    CHECK(is_str(v) && strcmp(v->str, "not_requested") == 0,
          "T2: quorum_status = not_requested");
    v = json_get(root, "assumptions");
    CHECK(is_obj(v) && is_num(json_get(v, "count")) &&
          is_num(json_get(v, "unclosed")) && is_bool(json_get(v, "ok")),
          "T2: assumptions {count, unclosed, ok}");

    /* gate_matrix: array {id, status} — id/status enum beku. */
    v = json_get(root, "gate_matrix");
    CHECK(is_arr(v) && v->len > 0, "T2: gate_matrix array non-kosong");
    if (is_arr(v)) {
        for (i = 0; i < v->len; i++) {
            json_value *g = v->items[i];
            json_value *id = json_get(g, "id");
            json_value *st = json_get(g, "status");
            snprintf(label, sizeof(label),
                     "T2: gate_matrix[%d] {id, status} valid", (int)i);
            CHECK(is_obj(g) && is_str(id) && id->str[0] &&
                  is_str(st) && str_in(st->str, gate_status, 8), label);
        }
    }

    json_free(root);
}

/* ------------------------------------------------------------------ */
/* T3: myc.agent.v2 conformance                                         */
/* ------------------------------------------------------------------ */

static void test_agent_v2(void)
{
    json_value *root = parse_golden("myc.agent.v2.json");
    json_value *v, *av, *nc;
    char label[160];
    static const char dims[MYC_DIM_COUNT] = { 'C', 'S', 'R', 'B', 'P', 'D', 'F' };
    size_t i;

    CHECK(root != NULL, "T3: golden agent.v2 ter-parse");
    if (!root)
        return;

    v = json_get(root, "schema");
    CHECK(is_str(v) && strcmp(v->str, "myc.agent.v2") == 0,
          "T3: schema = myc.agent.v2");
    v = json_get(root, "source_sha256");
    CHECK(is_str(v) && hex64(v->str), "T3: source_sha256 hex64");
    v = json_get(root, "receipt_sha256");
    CHECK(is_str(v) && hex64(v->str), "T3: receipt_sha256 hex64");
    v = json_get(root, "payload_cap");
    CHECK(is_num(v) && v->num >= 1024, "T3: payload_cap numerik");
    v = json_get(root, "finding");
    CHECK(is_num(v) && v->num >= 0 && v->num <= 3, "T3: finding ordinal dalam range");
    v = json_get(root, "verdict");
    CHECK(is_num(v) && v->num >= 0 && v->num <= 10, "T3: verdict ordinal dalam range");
    v = json_get(root, "witness_text");
    CHECK(is_str(v), "T3: witness_text string");
    v = json_get(root, "allowed_edits");
    CHECK(is_arr(v), "T3: allowed_edits array");
    v = json_get(root, "preserve");
    CHECK(is_arr(v), "T3: preserve array");
    v = json_get(root, "forbidden_changes");
    CHECK(is_arr(v), "T3: forbidden_changes array");
    v = json_get(root, "frontier");
    CHECK(is_arr(v), "T3: frontier array");
    if (is_arr(v)) {
        for (i = 0; i < v->len; i++)
            CHECK(is_str(v->items[i]), "T3: frontier[i] string");
    }
    nc = json_get(root, "next_check");
    CHECK(is_obj(nc) && is_str(json_get(nc, "command")),
          "T3: next_check {command}");
    av = json_get(root, "assurance_vector");
    CHECK(is_obj(av), "T3: assurance_vector objek");
    if (av) {
        for (i = 0; i < MYC_DIM_COUNT; i++) {
            char key[2] = { dims[i], '\0' };
            json_value *d = json_get(av, key);
            snprintf(label, sizeof(label),
                     "T3: assurance_vector[%s] ordinal", key);
            CHECK(is_num(d) && d->num >= 0 && d->num <= 5, label);
        }
    }

    json_free(root);
}

/* ------------------------------------------------------------------ */
/* T3b: myc.lite.v1 conformance (additive, agen lemah)                  */
/* ------------------------------------------------------------------ */

static void test_lite_v1(void)
{
    json_value *root = parse_golden("myc.lite.v1.json");
    json_value *v, *av;
    static const char *const actions[] = {
        "STOP_COMPILE_CLEAN", "FIX_ONE", "ESCALATE_RUNTIME",
        "ESCALATE_CONTRACT", "GIVE_UP_NO_TEMPLATE"
    };
    static const char *const keys[] = {
        "schema", "verdict", "claim", "action", "finding_id", "line",
        "function", "why", "fix_or_null", "allowed_span", "next_command",
        "assurance_vector", "receipt_sha256", "source_sha256",
        "source_anchor"
    };
    size_t i;
    char label[160];

    CHECK(root != NULL, "T3b: golden lite.v1 ter-parse");
    if (!root)
        return;
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        v = json_get(root, keys[i]);
        snprintf(label, sizeof(label), "T3b: field %s ada", keys[i]);
        CHECK(v != NULL, label);
    }
    v = json_get(root, "schema");
    CHECK(is_str(v) && strcmp(v->str, "myc.lite.v1") == 0,
          "T3b: schema = myc.lite.v1");
    v = json_get(root, "action");
    CHECK(is_str(v) && str_in(v->str, actions, 5), "T3b: action enum");
    v = json_get(root, "fix_or_null");
    CHECK(v && v->type == JSON_NULL, "T3b: fix_or_null boleh null");
    av = json_get(root, "assurance_vector");
    CHECK(is_obj(av), "T3b: assurance_vector objek");
    json_free(root);
}

/* ------------------------------------------------------------------ */
/* T4: myc.calibration.v1 + konsumen                                    */
/* ------------------------------------------------------------------ */

static void test_calibration_v1(void)
{
    json_value *root = parse_golden("myc.calibration.v1.json");
    json_value *v, *arr;
    static const char *const outcomes[] = {
        "accepted", "rejected", "confirmed_later",
        "missed", "useful_fix", "harmful_fix"
    };
    size_t i, j;
    long long counts[MYC_CALIB_OUTCOME_COUNT];
    int found = 0;

    CHECK(root != NULL, "T4: golden calibration.v1 ter-parse");
    if (root) {
        v = json_get(root, "schema");
        CHECK(is_str(v) && strcmp(v->str, "myc.calibration.v1") == 0,
              "T4: schema = myc.calibration.v1");
        arr = json_get(root, "entries");
        CHECK(is_arr(arr) && arr->len >= 2, "T4: entries array >= 2");
        if (is_arr(arr)) {
            for (i = 0; i < arr->len; i++) {
                json_value *e = arr->items[i];
                CHECK(is_obj(e) && is_str(json_get(e, "rule")),
                      "T4: entry {rule}");
                for (j = 0; j < sizeof(outcomes) / sizeof(outcomes[0]); j++)
                    CHECK(is_num(json_get(e, outcomes[j])),
                          "T4: entry outcome counter numerik");
            }
        }
        json_free(root);
    }

    /* Konsumen: calib_load (calibrate.c) MENERIMA golden. */
    {
        char  path[2100];
        size_t len;
        char *text;

        golden_path(path, sizeof(path), "myc.calibration.v1.json");
        text = read_file(path, &len);
        CHECK(text != NULL, "T4: baca golden calibration");
        if (text) {
            write_file_text(g_calib, text);
            free(text);
        }
        memset(counts, 0, sizeof(counts));
        CHECK(myc_calib_read_counts("lint-oob", counts, &found) == 0 && found,
              "T4: konsumen calib membaca entry lint-oob");
        CHECK(counts[MYC_CALIB_ACCEPTED] == 12, "T4: accepted = 12 (round-trip)");
        CHECK(counts[MYC_CALIB_CONFIRMED_LATER] == 2,
              "T4: confirmed_later = 2 (round-trip)");
        CHECK(counts[MYC_CALIB_HARMFUL_FIX] == 0,
              "T4: harmful_fix = 0 (round-trip)");
    }
}

/* ------------------------------------------------------------------ */
/* T5: evidence cache — entry golden diterima pembaca (tidak karantina) */
/* ------------------------------------------------------------------ */

/* Tulis sidecar sha256 atas byte mentah file cache (algoritma SAMA dengan
 * cache_write_all: sha256_hex atas byte file). */
static void write_sidecar(void)
{
    FILE *f, *g;
    long  sz;
    char *buf;
    char hex[65];

    f = fopen(g_cache, "rb");
    if (!f)
        return;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
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
    fclose(f);
    sha256_hex(buf, (size_t)sz, hex);
    free(buf);
    g = fopen(g_sha, "wb");
    if (g) {
        fputs(hex, g);
        fclose(g);
    }
}

/* Jumlah entry di .myc/evidence_cache.json; -1 = file tak ter-parse. */
static int cache_entry_count(void)
{
    FILE *f;
    long  sz;
    char *buf;
    json_value *root, *arr;
    int n = -1;

    f = fopen(g_cache, "rb");
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (32 << 20)) {
        fclose(f);
        return -1;
    }
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return -1;
    }
    buf[sz] = '\0';
    fclose(f);

    if (!json_parse(buf, (size_t)sz, &root) || !root ||
        root->type != JSON_OBJ) {
        if (root)
            json_free(root);
        free(buf);
        return -1;
    }
    arr = json_get(root, "entries");
    if (arr && arr->type == JSON_ARR)
        n = (int)arr->len;
    json_free(root);
    free(buf);
    return n;
}

static void base_req(myc_request *r)
{
    myc_request_init(r);
    r->input.kind = MYC_SOURCE_MEMORY;
    r->input.data = NULL;
    r->input.len = 0;
    r->run_lint = 1;
    r->cwd = g_dir;
}

static const char SRC_A[] = "int f(void){return 0;}\n";
#define SL(x) (sizeof(x) - 1)

static int cache_replay_ex(const myc_request *req, const char *src, size_t len)
{
    myc_result res;
    int rc;
    myc_result_init(&res);
    rc = myc_cache_try_replay(req, &res, src, len);
    myc_result_free(&res);
    return rc;
}

static void test_evidence_cache(void)
{
    myc_request a;
    char  path[2100];
    size_t len;
    char *text;

    base_req(&a);

    /* golden ditulis ke .myc/evidence_cache.json + sidecar sah -> pembaca
     * menerima entry (TIDAK dikarantina), replay MISS hanya karena key
     * berbeda (bukan korupsi). */
    golden_path(path, sizeof(path), "myc.evidence_cache.v1.json");
    text = read_file(path, &len);
    CHECK(text != NULL, "T5: baca golden evidence_cache");
    if (text) {
        write_file_text(g_cache, text);
        free(text);
        write_sidecar();
    }
    CHECK(cache_entry_count() == 1, "T5: satu entry golden di file");
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T5: replay MISS (key beda, bukan korupsi)");
    CHECK(cache_entry_count() == 1,
          "T5: entry golden TIDAK dikarantina (diterima pembaca)");
}

/* ------------------------------------------------------------------ */
/* T6: myc.scenario.v1 + konsumen + fail-closed versi                   */
/* ------------------------------------------------------------------ */

static void test_scenario_v1(void)
{
    json_value *root = parse_golden("myc.scenario.v1.json");
    json_value *v, *arr;
    char out[4096];
    size_t i;

    CHECK(root != NULL, "T6: golden scenario.v1 ter-parse");
    if (root) {
        v = json_get(root, "version");
        CHECK(is_num(v) && v->num == 1, "T6: version == 1");
        arr = json_get(root, "scenarios");
        CHECK(is_arr(arr) && arr->len > 0, "T6: scenarios array non-kosong");
        if (is_arr(arr)) {
            for (i = 0; i < arr->len; i++) {
                json_value *s = arr->items[i];
                CHECK(is_obj(s) && is_str(json_get(s, "name")) &&
                      is_str(json_get(s, "desc")),
                      "T6: scenario {name, desc}");
            }
        }
        json_free(root);
    }

    /* Konsumen: myc_scenario_info menerima golden (2 profil). */
    {
        char path[2100];
        golden_path(path, sizeof(path), "myc.scenario.v1.json");
        CHECK(myc_scenario_info("cli-daily", path, out, sizeof(out)) == 0,
              "T6: konsumen scenario: cli-daily dikenal");
        CHECK(myc_scenario_info("firmware", path, out, sizeof(out)) == 0,
              "T6: konsumen scenario: firmware dikenal");
        CHECK(myc_scenario_info("tidak-ada", path, out, sizeof(out)) == -1,
              "T6: scenario tak dikenal = -1");
    }

    /* Fail-closed: version != 1 -> profil USER di-ignore (fallback ke
     * bawaan, effective_root tidak pernah NULL) — scenario user TIDAK
     * pernah terlihat/di-apply; tanpa crash (INV-011). */
    write_file_text("scen_v2.json",
                    "{\"version\":2,\"scenarios\":[{\"name\":\"x\","
                    "\"desc\":\"y\",\"flags\":[],\"env\":{}}]}");
    CHECK(myc_scenario_info("x", "scen_v2.json", out, sizeof(out)) == -1,
          "T6: version 2 = profil user di-ignore (scenario x tak terlihat)");
}

/* ------------------------------------------------------------------ */
/* T7: myc.spec.v1 + konsumen + fail-fast versi                         */
/* ------------------------------------------------------------------ */

static void test_spec_v1(void)
{
    json_value *root = parse_golden("myc.spec.v1.json");
    json_value *v;
    myc_pack_info info;
    char path[2100];
    size_t len;
    char *text;

    CHECK(root != NULL, "T7: golden spec.v1 ter-parse");
    if (root) {
        v = json_get(root, "version");
        CHECK(is_num(v) && v->num == 1, "T7: version == 1");
        v = json_get(root, "name");
        CHECK(is_str(v) && v->str[0], "T7: name string non-kosong");
        v = json_get(root, "rules");
        CHECK(is_arr(v) && v->len == 2, "T7: rules array (2)");
        v = json_get(root, "allow_headers");
        CHECK(is_arr(v) && v->len == 2, "T7: allow_headers array (2)");
        v = json_get(root, "deny_functions");
        CHECK(is_arr(v) && v->len == 2, "T7: deny_functions array (2)");
        json_free(root);
    }

    /* Konsumen: myc_pack_load (prompt.c pack_parse_spec) menerima golden. */
    {
        T_MKDIR("packtmp");
        golden_path(path, sizeof(path), "myc.spec.v1.json");
        text = read_file(path, &len);
        CHECK(text != NULL, "T7: baca golden spec");
        if (text) {
            write_file_text("packtmp/myc.spec.json", text);
            free(text);
        }
        CHECK(myc_pack_load("packtmp", 0, &info) == 0,
              "T7: konsumen pack menerima spec golden");
        CHECK(info.spec_present == 1, "T7: spec_present == 1");
        CHECK(info.spec_n_rules == 2 && info.spec_n_allow == 2 &&
              info.spec_n_deny == 2,
              "T7: rules/allow/deny ter-parse (2/2/2)");
        CHECK(strcmp(info.spec_name, "pack-fixture") == 0,
              "T7: spec name round-trip");
        CHECK(strcmp(info.spec_domain, "embedded") == 0,
              "T7: spec domain round-trip");
        free(info.prompt_text);
    }

    /* Fail-fast: spec ADA tapi invalid (version 99) = -1 (pola scenario). */
    {
        T_MKDIR("packtmp_bad");
        write_file_text("packtmp_bad/myc.spec.json",
                        "{\"version\":99,\"name\":\"x\"}");
        CHECK(myc_pack_load("packtmp_bad", 0, &info) == -1,
              "T7: spec version 99 = fail-fast -1");
        free(info.prompt_text);
    }
}

/* ------------------------------------------------------------------ */
/* T8: MCP JSON-RPC 2.0 envelope + fail-closed konsumen                 */
/* ------------------------------------------------------------------ */

static void test_mcp_envelope(void)
{
    json_value *root, *v, *p, *res, *content, *sc;

    /* Request tools/call */
    root = parse_golden("mcp.request.tools-call.v1.json");
    CHECK(root != NULL, "T8: golden MCP request ter-parse");
    if (root) {
        v = json_get(root, "jsonrpc");
        CHECK(is_str(v) && strcmp(v->str, "2.0") == 0,
              "T8: request jsonrpc == 2.0");
        v = json_get(root, "id");
        CHECK(v && (v->type == JSON_NUM || v->type == JSON_STR ||
                    v->type == JSON_NULL),
              "T8: request id string/angka/null");
        v = json_get(root, "method");
        CHECK(is_str(v) && strcmp(v->str, "tools/call") == 0,
              "T8: request method tools/call");
        p = json_get(root, "params");
        CHECK(is_obj(p) && is_str(json_get(p, "name")) &&
              is_obj(json_get(p, "arguments")),
              "T8: request params {name, arguments}");
        json_free(root);
    }

    /* Response tools/call */
    root = parse_golden("mcp.response.tools-call.v1.json");
    CHECK(root != NULL, "T8: golden MCP response ter-parse");
    if (root) {
        v = json_get(root, "jsonrpc");
        CHECK(is_str(v) && strcmp(v->str, "2.0") == 0,
              "T8: response jsonrpc == 2.0");
        res = json_get(root, "result");
        CHECK(is_obj(res), "T8: response result objek");
        if (is_obj(res)) {
            content = json_get(res, "content");
            CHECK(is_arr(content) && content->len == 1 &&
                  is_obj(content->items[0]) &&
                  is_str(json_get(content->items[0], "type")) &&
                  strcmp(json_get_str(content->items[0], "type"), "text") == 0,
                  "T8: response content [{type: text}]");
            sc = json_get(res, "structuredContent");
            CHECK(is_obj(sc) && is_str(json_get(sc, "schema")) &&
                  strcmp(json_get_str(sc, "schema"), "myc.result.v1") == 0,
                  "T8: structuredContent.schema = myc.result.v1");
            v = json_get(res, "isError");
            CHECK(is_bool(v), "T8: isError boolean");
        }
        json_free(root);
    }

    /* Fail-closed konsumen state:
     * (a) cache entry verdict out-of-range + sidecar SAH -> L2 karantina
     *     (file di-heal ke 0 entry) — INV-011, lanjutan PR-013. */
    {
        myc_request a;
        char  path[2100];
        size_t len;
        char *text;
        json_value *r2, *arr2, *e2;

        base_req(&a);
        golden_path(path, sizeof(path), "myc.evidence_cache.v1.json");
        text = read_file(path, &len);
        CHECK(text != NULL, "T8a: baca golden evidence_cache");
        if (text && json_parse_cstr(text, &r2) && r2) {
            arr2 = json_get(r2, "entries");
            if (is_arr(arr2) && arr2->len > 0 && is_obj(arr2->items[0])) {
                e2 = arr2->items[0];
                json_obj_set(e2, "verdict", json_new_num(999));
            }
            {
                char *s = NULL;
                if (json_serialize(r2, &s) && s) {
                    write_file_text(g_cache, s);
                    free(s);
                }
            }
            json_free(r2);
            free(text);
            write_sidecar();
            CHECK(cache_entry_count() == 1, "T8a: entry out-of-range di file");
            CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
                  "T8a: replay MISS (verdict out-of-range ditolak)");
            CHECK(cache_entry_count() == 0,
                  "T8a: entry mustahil dikarantina (file di-heal) — INV-011");
        } else if (text) {
            free(text);
        }
    }

    /* (b) calib korup (bukan JSON) -> calib_load ignore, 0 entry tanpa
     *     crash. */
    write_file_text(g_calib, "{{{ ini bukan json sama sekali ");
    {
        long long counts[MYC_CALIB_OUTCOME_COUNT];
        int found = 0;
        memset(counts, 0, sizeof(counts));
        CHECK(myc_calib_read_counts("lint-oob", counts, &found) == 0 &&
              !found,
              "T8b: calib korup di-ignore (0 entry, tidak crash)");
    }
}

/* ------------------------------------------------------------------ */
/* T9: evolution additive — field asing diterima konsumen lama          */
/* ------------------------------------------------------------------ */

static void test_additive(void)
{
    json_value *root, *arr, *v;
    char *s = NULL;
    char out[4096];
    long long counts[MYC_CALIB_OUTCOME_COUNT];
    int found = 0;
    myc_pack_info info;
    myc_request a;

    /* calib: field asing di root + entry -> tetap terbaca. */
    {
        char  path[2100];
        size_t len;
        char *text;

        golden_path(path, sizeof(path), "myc.calibration.v1.json");
        text = read_file(path, &len);
        CHECK(text != NULL, "T9: baca golden calibration");
        if (text && json_parse_cstr(text, &root) && root) {
            json_obj_set(root, "future_field", json_new_num(1));
            arr = json_get(root, "entries");
            if (is_arr(arr) && arr->len > 0 && is_obj(arr->items[0]))
                json_obj_set(arr->items[0], "future_entry_field",
                             json_new_str("x"));
            if (json_serialize(root, &s) && s) {
                write_file_text(g_calib, s);
                free(s);
            }
            json_free(root);
            free(text);
        } else if (text) {
            free(text);
        }
        memset(counts, 0, sizeof(counts));
        CHECK(myc_calib_read_counts("lint-oob", counts, &found) == 0 && found,
              "T9: calib dgn field asing tetap terbaca (additive-only)");
    }

    /* cache: field asing di entry + sidecar sah -> tetap diterima. */
    {
        char  path[2100];
        size_t len;
        char *text;

        base_req(&a);
        golden_path(path, sizeof(path), "myc.evidence_cache.v1.json");
        text = read_file(path, &len);
        CHECK(text != NULL, "T9: baca golden evidence_cache");
        if (text && json_parse_cstr(text, &root) && root) {
            arr = json_get(root, "entries");
            if (is_arr(arr) && arr->len > 0 && is_obj(arr->items[0]))
                json_obj_set(arr->items[0], "future_field", json_new_str("x"));
            s = NULL;
            if (json_serialize(root, &s) && s) {
                write_file_text(g_cache, s);
                free(s);
            }
            json_free(root);
            free(text);
            write_sidecar();
            CHECK(cache_entry_count() == 1, "T9: cache field asing di file");
            CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
                  "T9: cache replay MISS (key beda)");
            CHECK(cache_entry_count() == 1,
                  "T9: cache entry field asing TIDAK dikarantina");
        } else if (text) {
            free(text);
        }
    }

    /* scenario: field asing di root + scenario, PLUS scenario baru yang
     * HANYA ada di file user (bukti file benar-benar diterima & di-merge,
     * bukan fallback builtin). */
    {
        char  path[2100];
        size_t len;
        char *text;

        golden_path(path, sizeof(path), "myc.scenario.v1.json");
        text = read_file(path, &len);
        CHECK(text != NULL, "T9: baca golden scenario");
        if (text && json_parse_cstr(text, &root) && root) {
            json_obj_set(root, "future_field", json_new_bool(1));
            arr = json_get(root, "scenarios");
            if (is_arr(arr) && arr->len > 0 && is_obj(arr->items[0]))
                json_obj_set(arr->items[0], "future_scenario_field",
                             json_new_num(2));
            if (is_arr(arr)) {
                json_value *ns = json_new_obj();
                json_obj_set(ns, "name",
                             json_new_str("additive-extra"));
                json_obj_set(ns, "desc",
                             json_new_str("hanya ada di user file"));
                json_arr_push(arr, ns);
            }
            s = NULL;
            if (json_serialize(root, &s) && s) {
                write_file_text("scen_additive.json", s);
                free(s);
            }
            json_free(root);
            free(text);
        } else if (text) {
            free(text);
        }
        CHECK(myc_scenario_info("cli-daily", "scen_additive.json",
                                out, sizeof(out)) == 0,
              "T9: scenario dgn field asing tetap dikenal (additive-only)");
        CHECK(myc_scenario_info("additive-extra", "scen_additive.json",
                                out, sizeof(out)) == 0,
              "T9: scenario user-only diterima & di-merge (bukan builtin)");
    }

    /* spec: field asing di root -> tetap valid (fail-fast TIDAK terjadi). */
    {
        T_MKDIR("packtmp_add");
        golden_path(out, sizeof(out), "myc.spec.v1.json");
        {
            size_t len;
            char *text = read_file(out, &len);
            CHECK(text != NULL, "T9: baca golden spec");
            if (text && json_parse_cstr(text, &root) && root) {
                json_obj_set(root, "future_field", json_new_str("y"));
                s = NULL;
                if (json_serialize(root, &s) && s) {
                    write_file_text("packtmp_add/myc.spec.json", s);
                    free(s);
                }
                json_free(root);
                free(text);
            } else if (text) {
                free(text);
            }
        }
        CHECK(myc_pack_load("packtmp_add", 0, &info) == 0,
              "T9: spec dgn field asing tetap valid (additive-only)");
        free(info.prompt_text);
    }

    /* sanity: field asing yang SAMA tidak membuat golden asli gagal. */
    v = parse_golden("myc.spec.v1.json");
    CHECK(v != NULL, "T9: golden asli tetap utuh");
    if (v)
        json_free(v);
}

/* ------------------------------------------------------------------ */
/* T10: produsen memancarkan semua field beku (backward compat)         */
/* ------------------------------------------------------------------ */

static const char HEX64[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static void test_producers(void)
{
    json_value *root, *v, *av;
    char label[160];
    /* Daftar key = top-level golden myc.result.v1 — JAGA SINKRON dengan
     * test/golden/myc.result.v1.json (aturan registry #3). */
    static const char *const result_keys[] = {
        "verdict", "assurance_vector", "receipt_sha256", "finding",
        "completeness", "error", "exit_code", "duration_ms",
        "lint_observations", "lint_embedded_hits", "harvest", "relational",
        "state_machine", "abi", "resource", "units", "coaching",
        "ran_runtime", "ran_checked", "ran_prove", "ran_filc", "ran_driver",
        "ran_negative", "ran_metamorphic", "ran_exhaustive", "ran_compare",
        "ran_stack", "ran_fuzz", "ran_mutate", "ran_freestanding",
        "ran_divergence", "diagnostics", "gate_matrix", "unverified_debt",
        "budget_met", "budget_report", "assumptions", "quorum_status"
    };
    /* Daftar key = top-level golden myc.agent.v2 — JAGA SINKRON dengan
     * test/golden/myc.agent.v2.json (aturan registry #3). */
    static const char *const agent_keys[] = {
        "schema", "source_sha256", "receipt_sha256", "payload_cap",
        "finding", "verdict", "assurance_vector", "witness_text",
        "allowed_edits", "preserve", "forbidden_changes", "next_check",
        "frontier"
    };
    size_t i;

    /* --- result: myc_result_to_json memuat semua key golden result.v1 --- */
    {
        myc_result res;
        char *js;
        char rcpt[65];

        myc_result_init(&res);
        res.verdict = MC_OK;
        res.err = MYC_ERR_NONE;
        res.exit_code = 0;
        res.duration_ms = 42;
        res.lint_observations = 3;
        res.lint_embedded_hits = 1;
        snprintf(rcpt, sizeof(rcpt), "%s", HEX64);
        memcpy(res.receipt_sha256, rcpt, 65);
        js = myc_result_to_json(&res);
        CHECK(js != NULL, "T10: myc_result_to_json menghasilkan JSON");
        if (js) {
            CHECK(json_parse_cstr(js, &root) && root, "T10: JSON ter-parse");
            if (root) {
                for (i = 0; i < sizeof(result_keys) / sizeof(result_keys[0]); i++) {
                    v = json_get(root, result_keys[i]);
                    snprintf(label, sizeof(label),
                             "T10: result memancarkan field beku %s",
                             result_keys[i]);
                    CHECK(v != NULL, label);
                }
                av = json_get(root, "assurance_vector");
                CHECK(is_obj(av), "T10: result assurance_vector objek");
                json_free(root);
            }
            free(js);
        }
        myc_result_free(&res);
    }

    /* --- agent: myc_agent_result_json memuat semua key golden agent.v2 --- */
    {
        myc_agent_result ar;
        const char *js;

        myc_agent_result_init(&ar);
        ar.payload_cap = MYC_AGENT_PAYLOAD_CAP;
        ar.finding = MYC_FINDING_CLEAN;
        ar.verdict = MC_OK;
        ar.assurance.status[MYC_DIM_COMPILE] = MYC_DIM_CLEAN;
        ar.assurance.status[MYC_DIM_STATIC] = MYC_DIM_NOT_APPLICABLE;
        ar.assurance.status[MYC_DIM_RUNTIME] = MYC_DIM_NOT_APPLICABLE;
        ar.assurance.status[MYC_DIM_CHECKED] = MYC_DIM_NOT_APPLICABLE;
        ar.assurance.status[MYC_DIM_PROOF] = MYC_DIM_NOT_APPLICABLE;
        ar.assurance.status[MYC_DIM_DRIVER] = MYC_DIM_NOT_APPLICABLE;
        ar.assurance.status[MYC_DIM_FILC] = MYC_DIM_NOT_APPLICABLE;
        ar.source_sha256 = t_strdup(HEX64);
        ar.receipt_sha256 = t_strdup(HEX64);
        ar.witness_text = t_strdup(HEX64);
        ar.has_next_check = 1;
        ar.next_check.command = t_strdup("myc check <file> --agent");
        ar.frontier_count = 1;
        ar.frontier[0] = t_strdup(
            "integer/bounds (static): tested (gcc) -- clean");

        js = myc_agent_result_json(&ar);
        CHECK(js != NULL, "T10: myc_agent_result_json menghasilkan JSON");
        if (js) {
            CHECK(json_parse_cstr(js, &root) && root, "T10: agent JSON ter-parse");
            if (root) {
                for (i = 0; i < sizeof(agent_keys) / sizeof(agent_keys[0]); i++) {
                    v = json_get(root, agent_keys[i]);
                    snprintf(label, sizeof(label),
                             "T10: agent memancarkan field beku %s",
                             agent_keys[i]);
                    CHECK(v != NULL, label);
                }
                json_free(root);
            }
        }
        myc_agent_result_free(&ar);
    }

    /* --- lite: myc_lite_result_json memancarkan field wajib --- */
    {
        myc_lite_result lr;
        char *js;
        static const char *const lite_keys[] = {
            "schema", "verdict", "claim", "action", "finding_id", "line",
            "function", "why", "fix_or_null", "allowed_span",
            "next_command", "assurance_vector"
        };

        myc_lite_result_init(&lr);
        lr.verdict = MC_OK;
        lr.action = MYC_LITE_STOP_COMPILE_CLEAN;
        lr.claim = t_strdup("compile_clean (runtime not run)");
        lr.finding_id = t_strdup("f-00000000");
        lr.next_command = t_strdup("STOP_COMPILE_CLEAN");
        js = myc_lite_result_json(&lr);
        CHECK(js != NULL, "T10: myc_lite_result_json menghasilkan JSON");
        if (js) {
            CHECK(json_parse_cstr(js, &root) && root, "T10: lite JSON ter-parse");
            if (root) {
                for (i = 0; i < sizeof(lite_keys) / sizeof(lite_keys[0]); i++) {
                    v = json_get(root, lite_keys[i]);
                    snprintf(label, sizeof(label),
                             "T10: lite memancarkan field %s", lite_keys[i]);
                    CHECK(v != NULL, label);
                }
                json_free(root);
            }
            myc_free(js);
        }
        myc_lite_result_free(&lr);
    }
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    save_cwd();
    T_MKDIR(g_dir);
    if (T_CHDIR(g_dir) != 0) {
        fprintf(stderr, "[FAIL] chdir %s gagal\n", g_dir);
        return 1;
    }
    T_MKDIR(".myc");
    T_MKDIR("packtmp");
    T_MKDIR("packtmp_bad");
    T_MKDIR("packtmp_add");

    test_goldens_parse();
    test_result_v1();
    test_agent_v2();
    test_lite_v1();
    test_calibration_v1();
    test_evidence_cache();
    test_scenario_v1();
    test_spec_v1();
    test_mcp_envelope();
    test_additive();
    test_producers();

    if (g_old_cwd[0]) {
        if (T_CHDIR(g_old_cwd) != 0) {
            /* restore cwd gagal: non-critical di test */
        }
    }

    remove("test/.schema_compat_tmp/.myc/evidence_cache.json");
    remove("test/.schema_compat_tmp/.myc/evidence_cache.sha256");
    remove("test/.schema_compat_tmp/.myc/calibration.json");
    remove("test/.schema_compat_tmp/scen_v2.json");
    remove("test/.schema_compat_tmp/scen_additive.json");
    remove("test/.schema_compat_tmp/packtmp/myc.spec.json");
    remove("test/.schema_compat_tmp/packtmp_bad/myc.spec.json");
    remove("test/.schema_compat_tmp/packtmp_add/myc.spec.json");
    T_RMDIR("test/.schema_compat_tmp/packtmp");
    T_RMDIR("test/.schema_compat_tmp/packtmp_bad");
    T_RMDIR("test/.schema_compat_tmp/packtmp_add");
    T_RMDIR("test/.schema_compat_tmp/.myc");
    T_RMDIR(g_dir);

    printf("schema_compat: %d OK, %d FAIL\n", g_ok, g_fail);
    return g_fail == 0 ? 0 : 1;
}
