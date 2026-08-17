/*
 * cache_key_matrix.c -- PR-011 (MYC-AUDIT-043): cache key specification —
 * dimension-by-dimension hit/miss tests.
 *
 * Mengunci perilaku Incremental Evidence Cache (cache.c, SOL-18): key
 * kanonik v2 (spesifikasi: docs/cache-key.md) HARUS berubah bila salah
 * satu dimensi yang mengubah hasil verifikasi berubah, dan HARUS tetap
 * sama bila semua dimensi sama (determinisme + replay identik SOL-18).
 *
 * Dimensi yang diuji (tiap dimensi: store dengan nilai A -> replay dgn
 * nilai A = HIT, replay dgn nilai B = MISS):
 *   T1  determinisme + dedup (store 2x key sama = 1 entry, last-write-wins)
 *   T2  dimensi source (byte berbeda -> miss)
 *   T3  dimensi flag gate inti (scenario hash): strict / run_analyzer /
 *       run / prove / checked / filc / driver / metamorphic / divergence /
 *       negative / quorum / require_complete / no_assumptions
 *   T4  dimensi flag gate Fase 5/6 (g2 hash, PR-011): no_lint /
 *       exhaustive / stack / stack_budget / fuzz / fuzz_iters / fuzz_seed /
 *       mutate_audit / mutate_max / freestanding / matrix / abi / perturb /
 *       thread_probe
 *   T5  dimensi budget contract (active / level / max_time / max_output)
 *   T6  dimensi eksekusi (PR-011): timeout_ms / max_output_bytes /
 *       run_stdin / checked_header_dir
 *   T7  dimensi cwd
 *   T8  dimensi tool identity (gcc_program berbeda -> miss; SKIP bila gcc
 *       tidak ada di PATH)
 *   T9  run stateful TIDAK di-store/di-replay: require_assumptions_closed
 *       dan assumption_acks (store di-skip -> replay selalu miss)
 *   T10 hasil MC_ERROR tidak di-store (replay miss)
 *   T11 no_cache=1 menonaktifkan replay
 *
 * Jalankan di direktori temp (test/.cache_key_tmp) agar file cache
 * `.myc/evidence_cache.json` tidak menyentuh repo; dibersihkan sendiri.
 * Build (portabel, Windows MinGW + POSIX):
 *   gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
 *       -o cache_key_matrix cache_key_matrix.c <seluruh SRCS myc>
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

#include "cache.h"
#include "json.h"
#include "myc.h"
#include "proc.h"

static int g_ok = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_ok++; } \
    else { g_fail++; fprintf(stderr, "[FAIL] %s (line %d)\n", (msg), __LINE__); } \
} while (0)

/* ------------------------------------------------------------------ */
/* Infra: direktori temp + helper store/replay                         */
/* ------------------------------------------------------------------ */

static char      g_old_cwd[1024];
static const char *g_dir = "test/.cache_key_tmp";

static void save_cwd(void)
{
    if (T_GETCWD(g_old_cwd, sizeof(g_old_cwd)) == NULL)
        g_old_cwd[0] = '\0';
}

static int chdir_one(const char *p)
{
    if (T_CHDIR(p) != 0) {
        fprintf(stderr, "[FAIL] chdir %s gagal\n", p);
        return -1;
    }
    return 0;
}

static void mkdir_one(const char *p)
{
    /* EEXIST wajar; error lain dibiarkan (store cache NON-blocking). */
    T_MKDIR(p);
}

static void rmdir_one(const char *p)
{
    T_RMDIR(p);
}

/* PENTING: tiap grup test memakai source UNIK (tidak pernah di-store oleh
 * grup lain). Bila dua test berbagi source dengan request identik, replay
 * akan HIT entry milik test lain (bukan bug cache — collision test). */
static const char SRC_A[]    = "int f(void){return 0;}\n";   /* source dim */
static const char SRC_NEW[]  = "int g(void){return 1;}\n";   /* miss-check source (tak pernah di-store) */
static const char SRC_G[]    = "int z(void){return 9;}\n";   /* gate dims */
static const char SRC_DET[]  = "int h(void){return 2;}\n";   /* determinism */
static const char SRC_ERR[]  = "int k(void){return 3;}\n";   /* error skip */
static const char SRC_NOC[]  = "int m(void){return 4;}\n";   /* no_cache */
static const char SRC_BUD[]  = "int b(void){return 5;}\n";   /* budget */
static const char SRC_EXEC[] = "int p(void){return 6;}\n";   /* exec dims */
static const char SRC_CWD[]  = "int q(void){return 7;}\n";   /* cwd dim */
static const char SRC_TOOL[] = "int t(void){return 8;}\n";   /* tool dim */
static const char SRC_SKIP[] = "int s(void){return 9;}\n";   /* stateful skip */
#define SL(x) (sizeof(x) - 1)

/* Base request meniru default CLI `myc check` (myc.c main): run_lint ON,
 * timeout default, tanpa flag gate. cwd dipakai sebagai teks key. */
static void base_req(myc_request *r, const char *cwd)
{
    myc_request_init(r);
    r->input.kind = MYC_SOURCE_MEMORY;
    r->input.data = NULL;
    r->input.len = 0;
    r->run_lint = 1;
    r->cwd = cwd;
}

/* Store hasil valid (MC_OK) dengan marker pembeda lint_observations agar
 * replay identik (SOL-18) bisa diverifikasi nilainya. */
static void cache_store_ex(const myc_request *req, const char *src,
                           size_t len, int marker)
{
    myc_result res;
    myc_result_init(&res);
    res.verdict = MC_OK;
    res.err = MYC_ERR_NONE;
    res.lint_observations = 1000 + marker;
    memset(res.receipt_sha256, 'a', 64);
    res.receipt_sha256[64] = '\0';
    myc_cache_store(req, &res, src, len);
    myc_result_free(&res);
}

static int cache_replay_ex(const myc_request *req, const char *src,
                           size_t len, int *out_marker)
{
    myc_result res;
    int rc;
    myc_result_init(&res);
    rc = myc_cache_try_replay(req, &res, src, len);
    if (out_marker)
        *out_marker = res.lint_observations;
    myc_result_free(&res);
    return rc;
}

/* Jumlah entry di .myc/evidence_cache.json (via json_parse internal). */
static int cache_entry_count(void)
{
    FILE *f;
    long  sz;
    char *buf;
    json_value *root, *arr;
    int n = -1;

    f = fopen(".myc/evidence_cache.json", "rb");
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

/* ------------------------------------------------------------------ */
/* T1: determinisme + dedup key sama                                   */
/* ------------------------------------------------------------------ */

static void test_determinism(void)
{
    myc_request a;
    int m = 0;

    base_req(&a, g_dir);
    cache_store_ex(&a, SRC_DET, SL(SRC_DET), 1);
    cache_store_ex(&a, SRC_DET, SL(SRC_DET), 2);   /* key sama -> replace */

    CHECK(cache_replay_ex(&a, SRC_DET, SL(SRC_DET), &m) == 1,
          "T1: store 2x key sama -> replay HIT");
    CHECK(m == 1002,
          "T1: replay identik last-write-wins (marker 1002)");
    CHECK(cache_entry_count() == 1,
          "T1: dua store key sama = SATU entry (dedup)");
}

/* ------------------------------------------------------------------ */
/* T2: dimensi source                                                  */
/* ------------------------------------------------------------------ */

static void test_source_dim(void)
{
    myc_request a;

    base_req(&a, g_dir);
    cache_store_ex(&a, SRC_A, SL(SRC_A), 1);
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A), NULL) == 1,
          "T2: source sama -> HIT");
    CHECK(cache_replay_ex(&a, SRC_NEW, SL(SRC_NEW), NULL) == 0,
          "T2: source byte beda -> MISS");
}

/* ------------------------------------------------------------------ */
/* T3 + T4: dimensi flag gate                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *label;
    void (*set)(myc_request *r);
} dim_case;

static void d_strict(myc_request *r)  { r->strict = 1; }
static void d_analyzer(myc_request *r){ r->run_analyzer = 1; }
static void d_run(myc_request *r)     { r->run = 1; }
static void d_prove(myc_request *r)   { r->prove = 1; }
static void d_checked(myc_request *r) { r->checked = 1; }
static void d_filc(myc_request *r)    { r->filc = 1; }
static void d_driver(myc_request *r)  { r->driver = 1; }
static void d_meta(myc_request *r)    { r->metamorphic = 1; }
static void d_div(myc_request *r)     { r->divergence = 1; }
static void d_neg(myc_request *r)     { r->negative = 1; }
static void d_quorum(myc_request *r)  { r->quorum = 1; }
static void d_reqc(myc_request *r)    { r->require_complete = 1; }
static void d_noasm(myc_request *r)   { r->no_assumptions = 1; }
static void d_nolint(myc_request *r)  { r->run_lint = 0; }
static void d_exh(myc_request *r)     { r->exhaustive = 1; }
static void d_stk(myc_request *r)     { r->stack = 1; }
static void d_fz(myc_request *r)      { r->fuzz = 1; }
static void d_fzi(myc_request *r)     { r->fuzz = 1; r->fuzz_iters = 500; }
static void d_fzs(myc_request *r)     { r->fuzz = 1; r->fuzz_seed = 0x1234u; }
static void d_stb(myc_request *r)     { r->stack = 1; r->stack_budget = 8192; }
static void d_mut(myc_request *r)     { r->mutate_audit = 1; }
static void d_mutm(myc_request *r)    { r->mutate_audit = 1; r->mutate_max = 4; }
static void d_free(myc_request *r)    { r->freestanding = 1; }
static void d_mat(myc_request *r)     { r->matrix = 1; }
static void d_abi(myc_request *r)     { r->abi = 1; }
static void d_pert(myc_request *r)    { r->perturb = 1; }
static void d_tp(myc_request *r)      { r->thread_probe = 1; }
static void d_eig(myc_request *r)     { r->eig_apply = 1; }
static void d_eigb(myc_request *r)    { r->eig_apply = 1; r->eig_budget_ms = 1000; }

static const dim_case GATE_DIMS[] = {
    /* T3: flag gate inti (scenario hash — sudah ada sejak v1) */
    { "strict", d_strict },
    { "run_analyzer", d_analyzer },
    { "run", d_run },
    { "prove", d_prove },
    { "checked", d_checked },
    { "filc", d_filc },
    { "driver", d_driver },
    { "metamorphic", d_meta },
    { "divergence", d_div },
    { "negative", d_neg },
    { "quorum", d_quorum },
    { "require_complete", d_reqc },
    { "no_assumptions", d_noasm },
    /* T4: flag gate Fase 5/6 (dimensi g2 — gap v1, fix PR-011) */
    { "no_lint", d_nolint },
    { "exhaustive", d_exh },
    { "stack", d_stk },
    { "stack_budget", d_stb },
    { "fuzz", d_fz },
    { "fuzz_iters", d_fzi },
    { "fuzz_seed", d_fzs },
    { "mutate_audit", d_mut },
    { "mutate_max", d_mutm },
    { "freestanding", d_free },
    { "matrix", d_mat },
    { "abi", d_abi },
    { "perturb", d_pert },
    { "thread_probe", d_tp },
    { "eig_apply", d_eig },
    { "eig_budget_ms", d_eigb },
};
#define N_GATE_DIMS (int)(sizeof(GATE_DIMS) / sizeof(GATE_DIMS[0]))

static void test_gate_dims(void)
{
    int i;
    for (i = 0; i < N_GATE_DIMS; i++) {
        myc_request on, off;
        char msg[192];

        base_req(&on, g_dir);
        base_req(&off, g_dir);
        GATE_DIMS[i].set(&on);

        cache_store_ex(&on, SRC_G, SL(SRC_G), 1);
        snprintf(msg, sizeof(msg),
                 "T3/T4 gate dim '%s': flag beda -> MISS", GATE_DIMS[i].label);
        CHECK(cache_replay_ex(&off, SRC_G, SL(SRC_G), NULL) == 0, msg);
        snprintf(msg, sizeof(msg),
                 "T3/T4 gate dim '%s': flag sama -> HIT", GATE_DIMS[i].label);
        CHECK(cache_replay_ex(&on, SRC_G, SL(SRC_G), NULL) == 1, msg);
    }
}

/* ------------------------------------------------------------------ */
/* T5: dimensi budget contract                                         */
/* ------------------------------------------------------------------ */

static void budget_req(myc_request *r, myc_budget_level lvl, int t, int o)
{
    base_req(r, g_dir);
    r->budget.active = 1;
    r->budget.level[MYC_GATE_COMPILE] = lvl;
    r->budget.max_time_ms = t;
    r->budget.max_output_bytes = o;
}

static void test_budget_dims(void)
{
    myc_request a, plain, t2, o2, lvl2;

    budget_req(&a, MYC_BUDGET_CLEAN, 5000, 4096);
    base_req(&plain, g_dir);
    budget_req(&t2, MYC_BUDGET_CLEAN, 9999, 4096);
    budget_req(&o2, MYC_BUDGET_CLEAN, 5000, 9999);
    budget_req(&lvl2, MYC_BUDGET_OPTIONAL, 5000, 4096);

    cache_store_ex(&a, SRC_BUD, SL(SRC_BUD), 1);
    CHECK(cache_replay_ex(&a, SRC_BUD, SL(SRC_BUD), NULL) == 1,
          "T5: budget kontrak sama -> HIT");
    CHECK(cache_replay_ex(&plain, SRC_BUD, SL(SRC_BUD), NULL) == 0,
          "T5: budget aktif vs tanpa kontrak -> MISS");
    CHECK(cache_replay_ex(&t2, SRC_BUD, SL(SRC_BUD), NULL) == 0,
          "T5: budget max_time_ms beda -> MISS");
    CHECK(cache_replay_ex(&o2, SRC_BUD, SL(SRC_BUD), NULL) == 0,
          "T5: budget max_output_bytes beda -> MISS");
    CHECK(cache_replay_ex(&lvl2, SRC_BUD, SL(SRC_BUD), NULL) == 0,
          "T5: budget level gate beda -> MISS");
}

/* ------------------------------------------------------------------ */
/* T6: dimensi eksekusi (stdin/timeout/output cap/header dir)          */
/* ------------------------------------------------------------------ */

static void test_exec_dims(void)
{
    myc_request base, t5, o8, s1, s2, h1;

    base_req(&base, g_dir);
    base_req(&t5, g_dir);  t5.timeout_ms = 5000;
    base_req(&o8, g_dir);  o8.max_output_bytes = 8192;
    base_req(&s1, g_dir);  s1.run_stdin = "abc"; s1.run_stdin_len = 3;
    base_req(&s2, g_dir);  s2.run_stdin = "xyz"; s2.run_stdin_len = 3;
    base_req(&h1, g_dir);  h1.checked_header_dir = "test/fixtures";

    cache_store_ex(&base, SRC_EXEC, SL(SRC_EXEC), 1);
    CHECK(cache_replay_ex(&base, SRC_EXEC, SL(SRC_EXEC), NULL) == 1,
          "T6: baseline -> HIT");
    CHECK(cache_replay_ex(&t5, SRC_EXEC, SL(SRC_EXEC), NULL) == 0,
          "T6: timeout_ms beda -> MISS (gap v1, fix PR-011)");
    CHECK(cache_replay_ex(&o8, SRC_EXEC, SL(SRC_EXEC), NULL) == 0,
          "T6: max_output_bytes beda -> MISS (gap v1, fix PR-011)");
    CHECK(cache_replay_ex(&s1, SRC_EXEC, SL(SRC_EXEC), NULL) == 0,
          "T6: run_stdin ada vs kosong -> MISS (gap v1, fix PR-011)");
    CHECK(cache_replay_ex(&h1, SRC_EXEC, SL(SRC_EXEC), NULL) == 0,
          "T6: checked_header_dir beda -> MISS (gap v1, fix PR-011)");

    cache_store_ex(&s1, SRC_EXEC, SL(SRC_EXEC), 2);
    CHECK(cache_replay_ex(&s1, SRC_EXEC, SL(SRC_EXEC), NULL) == 1,
          "T6: run_stdin sama -> HIT");
    CHECK(cache_replay_ex(&s2, SRC_EXEC, SL(SRC_EXEC), NULL) == 0,
          "T6: run_stdin byte beda -> MISS (gap v1, fix PR-011)");
}

/* ------------------------------------------------------------------ */
/* T7: dimensi cwd                                                     */
/* ------------------------------------------------------------------ */

static void test_cwd_dim(void)
{
    myc_request a, b;

    base_req(&a, g_dir);
    base_req(&b, "test/.cache_key_tmp2");   /* cwd = teks key; dir tak perlu ada */
    cache_store_ex(&a, SRC_CWD, SL(SRC_CWD), 1);
    CHECK(cache_replay_ex(&a, SRC_CWD, SL(SRC_CWD), NULL) == 1,
          "T7: cwd sama -> HIT");
    CHECK(cache_replay_ex(&b, SRC_CWD, SL(SRC_CWD), NULL) == 0,
          "T7: cwd beda -> MISS");
}

/* ------------------------------------------------------------------ */
/* T8: dimensi tool identity (gcc_program beda -> miss)                */
/* ------------------------------------------------------------------ */

static void test_tool_dim(void)
{
    myc_request base, bogus;
    char *gcc;

    gcc = myc_find_executable("gcc");
    if (!gcc) {
        printf("[SKIP] T8 tool dim: gcc tidak ditemukan di PATH\n");
        return;
    }
    free(gcc);

    base_req(&base, g_dir);
    base_req(&bogus, g_dir);
    bogus.gcc_program = "myc-no-such-gcc-987654";
    cache_store_ex(&base, SRC_TOOL, SL(SRC_TOOL), 1);
    CHECK(cache_replay_ex(&base, SRC_TOOL, SL(SRC_TOOL), NULL) == 1,
          "T8: tool sama -> HIT");
    CHECK(cache_replay_ex(&bogus, SRC_TOOL, SL(SRC_TOOL), NULL) == 0,
          "T8: gcc_program beda (tool identity) -> MISS");
}

/* ------------------------------------------------------------------ */
/* T9: run stateful tidak di-store / di-replay                         */
/* ------------------------------------------------------------------ */

static void test_store_skip(void)
{
    myc_request a, b;
    static char acks[] = "asm-x:declared";

    base_req(&a, g_dir);
    base_req(&b, g_dir);
    a.require_assumptions_closed = 1;
    cache_store_ex(&a, SRC_SKIP, SL(SRC_SKIP), 1);
    CHECK(cache_replay_ex(&a, SRC_SKIP, SL(SRC_SKIP), NULL) == 0,
          "T9: require_assumptions_closed (stateful) -> store skip, MISS");
    CHECK(cache_replay_ex(&b, SRC_SKIP, SL(SRC_SKIP), NULL) == 0,
          "T9: entry stateful TIDAK tersimpan -> MISS");

    base_req(&a, g_dir);
    a.assumption_acks = acks;
    cache_store_ex(&a, SRC_SKIP, SL(SRC_SKIP), 1);
    CHECK(cache_replay_ex(&a, SRC_SKIP, SL(SRC_SKIP), NULL) == 0,
          "T9: assumption_acks (stateful) -> store skip, MISS");
}

/* ------------------------------------------------------------------ */
/* T10: hasil error tidak di-store                                     */
/* ------------------------------------------------------------------ */

static void test_error_skip(void)
{
    myc_request a;
    myc_result res;

    base_req(&a, g_dir);
    myc_result_init(&res);
    res.verdict = MC_ERROR;              /* hasil error: bukan bukti valid */
    res.err = MYC_ERR_COMPILE_ERROR;
    myc_cache_store(&a, &res, SRC_ERR, SL(SRC_ERR));
    myc_result_free(&res);
    CHECK(cache_replay_ex(&a, SRC_ERR, SL(SRC_ERR), NULL) == 0,
          "T10: hasil MC_ERROR tidak di-store -> MISS");
}

/* ------------------------------------------------------------------ */
/* T11: no_cache menonaktifkan replay                                  */
/* ------------------------------------------------------------------ */

static void test_no_cache(void)
{
    myc_request a, n;

    base_req(&a, g_dir);
    base_req(&n, g_dir);
    n.no_cache = 1;
    cache_store_ex(&a, SRC_NOC, SL(SRC_NOC), 1);
    CHECK(cache_replay_ex(&a, SRC_NOC, SL(SRC_NOC), NULL) == 1,
          "T11: cache aktif -> HIT");
    CHECK(cache_replay_ex(&n, SRC_NOC, SL(SRC_NOC), NULL) == 0,
          "T11: no_cache=1 menonaktifkan replay -> MISS");
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    save_cwd();
    mkdir_one(g_dir);
    if (chdir_one(g_dir) != 0)
        return 1;

    test_determinism();
    test_source_dim();
    test_gate_dims();
    test_budget_dims();
    test_exec_dims();
    test_cwd_dim();
    test_tool_dim();
    test_store_skip();
    test_error_skip();
    test_no_cache();

    if (g_old_cwd[0])
        chdir_one(g_old_cwd);
    remove("test/.cache_key_tmp/.myc/evidence_cache.json");
    rmdir_one("test/.cache_key_tmp/.myc");
    rmdir_one(g_dir);

    printf("cache_key_matrix: %d OK, %d FAIL\n", g_ok, g_fail);
    return g_fail == 0 ? 0 : 1;
}
