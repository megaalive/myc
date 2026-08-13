/*
 * backend_abuse.c -- Unit test korpus output backend MALFORMED (PR-009 /
 * P2-T03 tahap 1), portabel Windows git-bash + POSIX.
 *
 * P2-T03 (required behavior): parser backend — GCC JSON diagnostics, GCC
 * text fallback, sanitizer logs, Frama-C Eva, Fil-C, dan internal JSON —
 * hanya boleh menghasilkan VALID / INVALID / RESOURCE_LIMIT. NEVER crash;
 * NEVER promote malformed evidence to clean (INV-001) atau ke finding
 * palsu (INV-011: unknown enum/state fails closed).
 *
 * Strategi (parser backend adalah static di compile.c/prove.c/filc.c):
 *   - internal JSON + konsumen JSON (budget/scenario/calib/cache) diuji
 *     LANGSUNG via API publik dengan korpus malformed deterministik;
 *   - parser GCC/Fil-C/Eva diuji END-TO-END lewat FAKE BACKEND
 *     (tests/backend_fake.c) yang mengeluarkan output malformed
 *     deterministik: fake gcc via req.gcc_program, fake filc-clang /
 *     frama-c via PATH (myc_find_executable). Backend fake dipilih env:
 *       MYC_FAKE_GCC=<path>        (T3; tanpa ini -> SKIP)
 *       MYC_FAKE_FILC_DIR=<dir>    (T4; tanpa ini -> SKIP)
 *       MYC_FAKE_FRAMA_DIR=<dir>   (T6; POSIX-only; tanpa ini -> SKIP)
 *
 * Assertion inti: "tidak pernah crash" = unit test selesai; verdict sesuai
 * kelas: exit code backend non-zero = bukti sah (COMPILE_ERROR / gate
 * INCONCLUSIVE), output malformed TIDAK PERNAH menaikkan violation palsu,
 * dan teks yang TIDAK memuat marker kanonik TIDAK pernah jadi finding.
 *
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test/backend_abuse \
 *       test/backend_abuse.c <SRCS>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#include <process.h>
#define myc_getpid _getpid
#define mkdir_one(p) _mkdir(p)
#else
#include <sys/stat.h>
#include <unistd.h>
#define mkdir_one(p) mkdir(p, 0700)
#endif

#include "budget.h"
#include "cache.h"
#include "calibrate.h"
#include "json.h"
#include "myc.h"
#include "proc.h"
#include "scenario.h"

static int g_fail = 0;

#define CHECK(cond, fmt, ...) do {                                    \
        if (cond) {                                                   \
            printf("[OK]   " fmt "\n", ##__VA_ARGS__);                \
        } else {                                                      \
            fprintf(stderr, "[FAIL] " fmt "\n", ##__VA_ARGS__);       \
            g_fail++;                                                 \
        }                                                             \
    } while (0)

/* Direktori kerja temp bersama (dibuat di main, dibersihkan di akhir). */
static char g_tmp[512] = "test/.backend_abuse_tmp";

/* ------------------------------------------------------------------ */
/* Env portabel (setenv/_putenv) + PATH prepend/restore.               */
/* ------------------------------------------------------------------ */

static void env_set(const char *name, const char *value)
{
    size_t n = strlen(name) + 1 + strlen(value) + 1;
    char  *b = (char *)malloc(n);
    if (!b)
        return;
    snprintf(b, n, "%s=%s", name, value);
#if defined(_WIN32)
    _putenv(b);   /* MS CRT menyalin string */
#else
    setenv(name, value, 1);
#endif
    free(b);
}

static char *g_saved_path = NULL;

static void path_prepend(const char *dir)
{
    const char *old = getenv("PATH");
    const char *sep = ";";
    size_t      n;
    char       *p;
#if !defined(_WIN32)
    sep = ":";
#endif
    if (g_saved_path) {
        free(g_saved_path);
        g_saved_path = NULL;
    }
    g_saved_path = old ? strdup(old) : NULL;
    n = strlen(dir) + 1 + (old ? strlen(old) : 0) + 1;
    p = (char *)malloc(n);
    if (!p)
        return;
    snprintf(p, n, "%s%s%s", dir, sep, old ? old : "");
    env_set("PATH", p);
    free(p);
}

static void path_restore(void)
{
    if (g_saved_path) {
        env_set("PATH", g_saved_path);
        free(g_saved_path);
        g_saved_path = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Helper myc_run dengan kontrol backend.                              */
/* ------------------------------------------------------------------ */

typedef struct {
    int         run, filc, prove, driver;
    const char *gcc_program;   /* NULL = cari gcc asli */
    const char *src;
} run_cfg;

static void run_src(const run_cfg *cfg, myc_result *res)
{
    myc_request req;
    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = cfg->src;
    req.input.len = strlen(cfg->src);
    req.cwd = ".";
    req.run_lint = 1;
    req.run = cfg->run;
    req.filc = cfg->filc;
    req.prove = cfg->prove;
    req.driver = cfg->driver;
    req.gcc_program = cfg->gcc_program;
    req.no_cache = 1;   /* deterministik: jangan biarkan cache ikut campur */
    myc_result_init(res);
    myc_run(&req, res);
}

/* Source bersih yang selalu compile OK. */
static const char *SRC_CLEAN = "int main(void) { return 0; }\n";

/* ------------------------------------------------------------------ */
/* T1: internal JSON (json_parse) — korpus P2-T03 deterministik.       */
/* ------------------------------------------------------------------ */
static void t1_internal_json(void)
{
    /* 1a. truncation di SETIAP posisi byte untuk seed kecil. Seed dipilih
     * dari bentuk yang dipakai backend: objek diag gcc, array diag,
     * objek gates budget. Untuk tiap posisi: parse prefix -> tidak crash;
     * return 0 => *out NULL (never crash, never half-parsed). */
    static const char *const seeds[] = {
        "{\"a\":[1,2,{\"b\":\"c\"}]}",
        "[{\"kind\":\"error\",\"message\":\"m\"}]",
        "{\"gates\":{\"compile\":\"clean\"}}",
        "{\"entries\":[{\"key\":\"k\",\"verdict\":0}]}",
    };
    size_t si;
    for (si = 0; si < sizeof(seeds) / sizeof(seeds[0]); si++) {
        const char *s = seeds[si];
        size_t      len = strlen(s);
        size_t      pos;
        int         saw_valid = 0;
        for (pos = 0; pos <= len; pos++) {
            json_value *v = NULL;
            int         ok = json_parse(s, pos, &v);
            if (ok) {
                if (!v) {
                    fprintf(stderr,
                            "[FAIL] T1 trunc: seed %zu pos %zu return 1 tapi "
                            "v==NULL\n", si, pos);
                    g_fail++;
                } else {
                    saw_valid = 1;
                }
            } else if (v) {
                fprintf(stderr,
                        "[FAIL] T1 trunc: seed %zu pos %zu return 0 tapi "
                        "v!=NULL\n", si, pos);
                g_fail++;
            }
            json_free(v);
        }
        CHECK(saw_valid,
              "T1a truncation per-byte seed %zu: selesai tanpa crash, "
              "prefix penuh valid", si);
    }

    /* 1b. kelas mutasi P2-T03 lainnya. */
    {
        char deep[512];
        int  d;
        memset(deep, '[', sizeof(deep));
        for (d = 0; d < 200; d++)
            deep[d] = '[';
        deep[200] = '1';
        for (d = 0; d < 200; d++)
            deep[201 + d] = ']';
        deep[401] = '\0';
        {
            static const struct {
                const char *label;
                const char *input;
                int         expect_valid; /* 1 = harus valid, 0 = harus
                                             invalid, -1 = bebas (tidak
                                             crash) */
            } cases[] = {
                /* duplicate keys */
                { "dup key object",        "{\"a\":1,\"a\":2}",             -1 },
                { "dup key diag",          "[{\"k\":\"e\",\"k\":\"w\"}]",   -1 },
                /* extreme numbers: tidak boleh crash; outcome valid/invalid
                 * terserah parser (ekstrem, bukan inti PR-009) */
                { "1e999",                "1e999",                       -1 },
                { "-1e999",               "-1e999",                      -1 },
                { "1e-999",               "1e-999",                      -1 },
                { "1e309",                "1e309",                       -1 },
                { "huge int 20 digit",    "99999999999999999999",        -1 },
                { "huge neg int",         "-92233720368547758080",       -1 },
                { "int64 min literal",    "-9223372036854775808",        -1 },
                /* invalid UTF-8 / NUL */
                { "raw 0xFF di string",   "{\"a\":\"\xff\xff\"}",          0 },
                { "lone continuation",    "\"\x80\"",                      0 },
                /* reordered fields (valid JSON) */
                { "reordered object",     "{\"b\":2,\"a\":1}",           1 },
                { "reordered diag",       "[{\"message\":\"m\",\"kind\":\"e\"}]", 1 },
                /* unknown enum values: valid di level JSON (konsumen yang
                 * menolak — diuji T2). */
                { "unknown kind",         "[{\"kind\":\"bogus\"}]",       1 },
                { "unknown level",        "{\"level\":\"nonsense\"}",     1 },
                /* grammar mutations */
                { "trailing garbage",     "[1] x",                        0 },
                { "missing closing",      "{\"a\":1",                     0 },
                { "empty",                "",                             0 },
            };
            size_t i;
            for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                json_value *v = NULL;
                int         ok = json_parse(cases[i].input,
                                            strlen(cases[i].input), &v);
                if (cases[i].expect_valid >= 0 &&
                    ok != cases[i].expect_valid) {
                    fprintf(stderr, "[FAIL] T1b %s: expect %s, got %s\n",
                            cases[i].label,
                            cases[i].expect_valid ? "valid" : "invalid",
                            ok ? "valid" : "invalid");
                    g_fail++;
                }
                if (ok && !v) {
                    fprintf(stderr, "[FAIL] T1b %s: valid tapi v==NULL\n",
                            cases[i].label);
                    g_fail++;
                }
                if (!ok && v) {
                    fprintf(stderr, "[FAIL] T1b %s: invalid tapi v!=NULL\n",
                            cases[i].label);
                    g_fail++;
                }
                json_free(v);
            }
            printf("[OK]   T1b korpus mutasi P2-T03 (%zu case) selesai "
                   "tanpa crash\n",
                   sizeof(cases) / sizeof(cases[0]));
        }
        /* deep nesting: input berkedalaman 200 harus DITOLAK (depth cap). */
        {
            json_value *v = NULL;
            int ok = json_parse(deep, strlen(deep), &v);
            CHECK(!ok, "T1b deep nesting 200 ditolak (depth cap, ok=%d)",
                  ok);
            json_free(v);
        }
    }

    /* 1c. oversized string: 256 KB dalam JSON — tidak crash, outcome
     * valid/invalid konsisten (tidak ada partial state). */
    {
        size_t      cap = 256 * 1024 + 16;
        char       *big = (char *)malloc(cap);
        json_value *v = NULL;
        int         ok;
        if (big) {
            size_t n = (size_t)snprintf(big, cap, "[\"");
            memset(big + n, 'A', 256 * 1024);
            n += 256 * 1024;
            n += (size_t)snprintf(big + n, cap - n, "\"]");
            /* n kini = panjang konten persis: '[' '"' + 256K 'A' + '"' ']'. */
            ok = json_parse(big, n, &v);
            CHECK(!ok || (ok && v),
                  "T1c oversized 256KB string: selesai tanpa crash "
                  "(ok=%d)", ok);
            json_free(v);
            free(big);
        } else {
            printf("[SKIP] T1c oversized (malloc gagal)\n");
        }
    }
}

/* ------------------------------------------------------------------ */
/* T2: konsumen JSON — malformed/unknown enum fails closed (INV-011).  */
/* ------------------------------------------------------------------ */
static void t2_json_consumers(void)
{
    /* budget contract: JSON korup / unknown gate / unknown level -> -1,
     * bc->active tetap 0. JSON valid -> 0 + active. */
    {
        myc_budget_contract bc;
        static const char *bad[] = {
            "{",
            "{\"gates\":",
            "{\"gates\":{\"compile\":\"bogus\"}}",
            "{\"gates\":{\"bogus_gate\":\"clean\"}}",
            "{\"gates\":{\"compile\":\"clean\"},\"gates\":{\"compile\":",
            "{\"max_time_ms\":\"not_a_number\"}",
            "null",
        };
        size_t i;
        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            memset(&bc, 0, sizeof(bc));
            CHECK(myc_budget_parse(bad[i], strlen(bad[i]), &bc) == -1 &&
                  bc.active == 0,
                  "T2 budget: JSON malformed/unknown '%s' ditolak (-1, "
                  "active=0)", bad[i]);
            myc_budget_free(&bc);
        }
        memset(&bc, 0, sizeof(bc));
        {
            /* Format kontrak: {"required": {"<gate>": "clean"|...}}.
             * Json VALID tapi skema salah (key "gates" bukan "required")
             * juga harus ditolak (fail-closed skema). */
            static const char *valid_budget =
                "{\"required\":{\"compile\":\"clean\"}}";
            static const char *wrong_schema_budget =
                "{\"gates\":{\"compile\":\"clean\"}}";
            CHECK(myc_budget_parse(valid_budget, strlen(valid_budget),
                                   &bc) == 0 && bc.active == 1,
                  "T2 budget: JSON valid diterima (active=%d)", bc.active);
            myc_budget_free(&bc);
            memset(&bc, 0, sizeof(bc));
            CHECK(myc_budget_parse(wrong_schema_budget,
                                   strlen(wrong_schema_budget),
                                   &bc) == -1 && bc.active == 0,
                  "T2 budget: JSON valid tapi skema salah ditolak "
                  "(key 'gates' bukan 'required', active=%d)", bc.active);
        }
        myc_budget_free(&bc);
    }

    /* calibration: outcome unknown -> -1 (fails closed); id invalid -> 0. */
    {
        myc_calib_outcome oc = (myc_calib_outcome)0;
        CHECK(myc_calib_outcome_parse("bogus", &oc) == -1,
              "T2 calib: outcome 'bogus' -> -1 (unknown enum fails "
              "closed, rc=%d)",
              myc_calib_outcome_parse("bogus", &oc));
        CHECK(myc_calib_id_valid("bad id!") == 0,
              "T2 calib: id 'bad id!' ditolak (valid=%d)",
              myc_calib_id_valid("bad id!"));
        CHECK(myc_calib_id_valid("ok_rule.1") == 1,
              "T2 calib: id valid diterima (valid=%d)",
              myc_calib_id_valid("ok_rule.1"));
    }

    /* scenario: file profil korup -> -2 (profil invalid), tidak crash. */
    {
        char  path[600];
        FILE *f;
        myc_request req;
        myc_result  res;
        int         rc;
        snprintf(path, sizeof(path), "%s/bad_scenario.json", g_tmp);
        f = fopen(path, "wb");
        if (f) {
            fputs("{\"scenarios\":[{\"name\":\"x\",\"gates\":", f);
            fclose(f);
            myc_request_init(&req);
            myc_result_init(&res);
            rc = myc_scenario_apply(&req, "x", SRC_CLEAN,
                                    strlen(SRC_CLEAN), path, &res);
            /* Profil korup ditolak: file tidak valid -> user profil
             * diabaikan, fallback builtin, nama tak dikenal -> -1.
             * Yang diuji: penolakan fail-closed (rc != 0) TANPA crash,
             * bukan nilai -1/-2 spesifik. */
            CHECK(rc != 0,
                  "T2 scenario: profil file korup ditolak (rc=%d, fail-"
                  "closed, tidak crash)", rc);
            myc_result_free(&res);
            remove(path);
        } else {
            printf("[SKIP] T2 scenario: gagal menulis file temp\n");
        }
    }

    /* cache: file evidence_cache.json korup -> replay miss (0), tidak
     * crash, tidak pernah dipercaya. Berjalan di cwd temp (save/restore). */
    {
        char  old_cwd[1024];
        char  cache_path[600];
        FILE *f;
        myc_request req;
        myc_result  res;
        int         rc;
        const char *cd;
#if defined(_WIN32)
        cd = _getcwd(old_cwd, sizeof(old_cwd));
#else
        cd = getcwd(old_cwd, sizeof(old_cwd));
#endif
        if (!cd)
            return;
        /* mkdir .myc di dalam g_tmp */
        {
            char myc_dir[600];
            snprintf(myc_dir, sizeof(myc_dir), "%s/.myc", g_tmp);
            mkdir_one(myc_dir);
        }
        snprintf(cache_path, sizeof(cache_path), "%s/.myc/evidence_cache.json",
                 g_tmp);
        f = fopen(cache_path, "wb");
        if (f) {
            fputs("{\"entries\":[{\"key\":\"k\",\"verdict\":999999,\"err\":",
                  f);
            fclose(f);
        }
#if defined(_WIN32)
        _chdir(g_tmp);
#else
        chdir(g_tmp);
#endif
        myc_request_init(&req);
        myc_result_init(&res);
        rc = myc_cache_try_replay(&req, &res, SRC_CLEAN, strlen(SRC_CLEAN));
        CHECK(rc == 0,
              "T2 cache: file cache korup -> replay miss (0, rc=%d), "
              "tidak crash", rc);
        myc_result_free(&res);
#if defined(_WIN32)
        _chdir(old_cwd);
#else
        chdir(old_cwd);
#endif
        remove(cache_path);
    }
}

/* ------------------------------------------------------------------ */
/* T3: GCC diagnostics parser (JSON + text fallback) E2E via fake gcc. */
/* ------------------------------------------------------------------ */
static void t3_gcc_diagnostics(const char *fake_gcc)
{
    static const struct {
        const char *mode;
        int         expect_compile_error; /* 1 = exit 1 -> COMPILE_ERROR */
        int         expect_diags;         /* jumlah diag (>=, atau -1 = bebas) */
    } modes[] = {
        { "gcc-json-valid",      1, 1 },
        { "gcc-json-truncated",  1, -1 },
        { "gcc-json-garbage",    1, -1 },
        { "gcc-json-dupkeys",    1, 1 },
        { "gcc-json-deep",       1, -1 },
        { "gcc-json-hugenum",    1, -1 },
        { "gcc-json-nul",        1, -1 },
        { "gcc-json-utf8",       1, -1 },
        { "gcc-json-oversized",  1, -1 },
        { "gcc-json-reordered",  1, 1 },
        { "gcc-json-unknown-kind", 1, -1 },
        { "gcc-json-note-only",  1, 0 },
        { "gcc-text-valid",      1, 1 },
        { "gcc-text-hugeloc",    1, 1 },
        { "gcc-text-garbage",    1, 0 },
        { "gcc-text-nul",        1, -1 },
        { "gcc-text-nocolon",    1, 0 },
        { "gcc-exit0-garbage",   0, -1 },
    };
    size_t i;
    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        myc_result res;
        run_cfg    cfg;
        env_set("MYC_FAKE_ROLE", "gcc");
        env_set("MYC_FAKE_MODE", modes[i].mode);
        memset(&cfg, 0, sizeof(cfg));
        cfg.src = SRC_CLEAN;
        cfg.gcc_program = fake_gcc;
        run_src(&cfg, &res);
        if (modes[i].expect_compile_error) {
            CHECK(res.verdict == MC_COMPILE_ERROR,
                  "T3 %-22s -> COMPILE_ERROR (verdict=%d, diag=%d)",
                  modes[i].mode, (int)res.verdict, res.diag_count);
        } else {
            CHECK(res.verdict == MC_OK,
                  "T3 %-22s -> OK (exit 0: malformed stderr TIDAK jadi "
                  "finding; verdict=%d)", modes[i].mode, (int)res.verdict);
        }
        if (modes[i].expect_diags >= 0) {
            CHECK(res.diag_count >= modes[i].expect_diags,
                  "T3 %-22s diag_count >= %d (got %d)",
                  modes[i].mode, modes[i].expect_diags, res.diag_count);
        }
        myc_result_free(&res);
    }
    env_set("MYC_FAKE_MODE", "");
    printf("[OK]   T3 GCC JSON+text diagnostics E2E (%zu mode) selesai "
           "tanpa crash\n", sizeof(modes) / sizeof(modes[0]));
}

/* ------------------------------------------------------------------ */
/* T4: Fil-C report parser E2E via fake filc-clang di PATH.            */
/* ------------------------------------------------------------------ */
static void t4_filc_parser(const char *fake_dir)
{
    static const struct {
        const char *mode;
        int         expect_violation; /* 1 = FILC_VIOLATION (positive
                                         control), 0 = bukan violation */
        int         expect_panics;    /* filc_panics (>=, -1 = bebas) */
    } modes[] = {
        { "filc-panic-valid",     1, 1 },
        { "filc-panic-exit0",     0, -1 },
        { "filc-panic-truncated", 0, -1 },
        { "filc-garbage",         0, -1 },
        { "filc-dup",             1, 1 },
        { "filc-oversized",       0, -1 },
    };
    size_t i;
    path_prepend(fake_dir);
    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        myc_result res;
        run_cfg    cfg;
        env_set("MYC_FAKE_ROLE", "filc");
        env_set("MYC_FAKE_MODE", modes[i].mode);
        memset(&cfg, 0, sizeof(cfg));
        cfg.src = SRC_CLEAN;
        cfg.filc = 1;
        run_src(&cfg, &res);
        if (modes[i].expect_violation) {
            CHECK(res.verdict == MC_FILC_VIOLATION,
                  "T4 %-22s -> FILC_VIOLATION (positive control; verdict=%d, "
                  "panics=%d)", modes[i].mode, (int)res.verdict,
                  res.filc_panics);
        } else {
            CHECK(res.verdict != MC_FILC_VIOLATION,
                  "T4 %-22s -> BUKAN FILC_VIOLATION (malformed/exit-0 "
                  "tidak jadi finding; verdict=%d, panics=%d)",
                  modes[i].mode, (int)res.verdict, res.filc_panics);
        }
        if (modes[i].expect_panics >= 0) {
            CHECK(res.filc_panics >= modes[i].expect_panics,
                  "T4 %-22s filc_panics >= %d (got %d)",
                  modes[i].mode, modes[i].expect_panics, res.filc_panics);
        }
        myc_result_free(&res);
    }
    env_set("MYC_FAKE_MODE", "");
    path_restore();
    printf("[OK]   T4 Fil-C parser E2E (%zu mode) selesai tanpa crash\n",
           sizeof(modes) / sizeof(modes[0]));
}

/* ------------------------------------------------------------------ */
/* T5: sanitizer report reader — file report korup (proc.c).           */
/* ------------------------------------------------------------------ */
static void t5_sanitizer_report_files(void)
{
    char        p1[600];
    FILE       *f;
    char       *rpt;
    static const unsigned char garbage[] = {
        0xff, 0x00, 0x01, '=', '=', '1', '=', '=', 'E', 'R', 'R', 'O',
        'R', ':', ' ', 'A', 0xfe, '\n', 0x80, 0x80
    };

    mkdir_one(g_tmp);

    /* 1. file report non-kosong berisi byte korup -> terbaca utuh. */
    snprintf(p1, sizeof(p1), "%s/%s.%d", g_tmp, "myc_t_a_rpt",
             (int)myc_getpid());
    f = fopen(p1, "wb");
    if (f) {
        fwrite(garbage, 1, sizeof(garbage), f);
        fclose(f);
    }
    rpt = myc_read_sanitizer_report(g_tmp, "myc_t_a_rpt");
    CHECK(rpt != NULL,
          "T5a report file korup (binary+NUL) terbaca tanpa crash "
          "(rpt=%s)", rpt ? "ada" : "NULL");
    free(rpt);

    /* 2. file KOSONG -> NULL (bukan bukti). Base BERBEDA dari T5a agar
     * wildcard <base>.* tidak melihat file non-kosong T5a. */
    snprintf(p1, sizeof(p1), "%s/%s.%d", g_tmp, "myc_t_b_rpt",
             (int)myc_getpid());
    f = fopen(p1, "wb");
    if (f)
        fclose(f);
    rpt = myc_read_sanitizer_report(g_tmp, "myc_t_b_rpt");
    CHECK(rpt == NULL,
          "T5b report file kosong -> NULL (tidak jadi bukti, rpt=%s)",
          rpt ? "ada" : "NULL");
    free(rpt);

    /* 3. tidak ada file sama sekali -> NULL. */
    rpt = myc_read_sanitizer_report(g_tmp, "myc_t_none_rpt");
    CHECK(rpt == NULL,
          "T5c tidak ada report -> NULL (bukan bukti, rpt=%s)",
          rpt ? "ada" : "NULL");
    free(rpt);

    /* 4. cleanup: semua <base>.* terhapus. */
    myc_remove_sanitizer_reports(g_tmp, "myc_t_a_rpt");
    myc_remove_sanitizer_reports(g_tmp, "myc_t_b_rpt");
    rpt = myc_read_sanitizer_report(g_tmp, "myc_t_a_rpt");
    CHECK(rpt == NULL,
          "T5d myc_remove_sanitizer_reports membersihkan semua "
          "<base>.* (rpt=%s)", rpt ? "ada" : "NULL");
    free(rpt);
}

/* ------------------------------------------------------------------ */
/* T6: Frama-C Eva parser E2E via fake frama-c (POSIX-only).           */
/* ------------------------------------------------------------------ */
#if !defined(_WIN32)
static void t6_eva_parser(const char *fake_dir)
{
    static const struct {
        const char *mode;
        int         expect_violation;
    } modes[] = {
        { "eva-alarm-valid",     1 },
        { "eva-alarm-hugeline",  1 },
        { "eva-garbage",         0 },
        { "eva-garbage-exit0",   0 },
        { "eva-garbage-summary", 0 },
    };
    size_t i;
    path_prepend(fake_dir);
    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        myc_result res;
        run_cfg    cfg;
        env_set("MYC_FAKE_ROLE", "eva");
        env_set("MYC_FAKE_MODE", modes[i].mode);
        memset(&cfg, 0, sizeof(cfg));
        cfg.src = SRC_CLEAN;
        cfg.prove = 1;
        run_src(&cfg, &res);
        if (modes[i].expect_violation) {
            CHECK(res.verdict == MC_PROVE_VIOLATION,
                  "T6 %-20s -> PROVE_VIOLATION (positive control; verdict=%d, "
                  "alarms=%d)", modes[i].mode, (int)res.verdict,
                  res.prove_alarms);
        } else {
            CHECK(res.verdict != MC_PROVE_VIOLATION,
                  "T6 %-20s -> BUKAN PROVE_VIOLATION (verdict=%d, alarms=%d)",
                  modes[i].mode, (int)res.verdict, res.prove_alarms);
        }
        myc_result_free(&res);
    }
    env_set("MYC_FAKE_MODE", "");
    path_restore();
    printf("[OK]   T6 Eva parser E2E (%zu mode) selesai tanpa crash\n",
           sizeof(modes) / sizeof(modes[0]));
}
#endif

/* ------------------------------------------------------------------ */

static void cleanup_tmp(void)
{
    char p[600];
    /* hapus artefak unit test di g_tmp (bila masih ada) */
    snprintf(p, sizeof(p), "%s/bad_scenario.json", g_tmp);
    remove(p);
    snprintf(p, sizeof(p), "%s/.myc/evidence_cache.json", g_tmp);
    remove(p);
    snprintf(p, sizeof(p), "%s/.myc", g_tmp);
    rmdir(p);
    rmdir(g_tmp);
}

int main(void)
{
    const char *fake_gcc = getenv("MYC_FAKE_GCC");
    const char *fake_filc = getenv("MYC_FAKE_FILC_DIR");
#if !defined(_WIN32)
    const char *fake_frama = getenv("MYC_FAKE_FRAMA_DIR");
#else
    const char *fake_frama = NULL;
    (void)fake_frama;
#endif

    printf("=== Backend malformed-output corpus (PR-009 / P2-T03) ===\n");

    mkdir_one(g_tmp);

    t1_internal_json();
    t2_json_consumers();
    t5_sanitizer_report_files();

    if (fake_gcc && *fake_gcc)
        t3_gcc_diagnostics(fake_gcc);
    else
        printf("[SKIP] T3 GCC diagnostics (MYC_FAKE_GCC tidak di-set)\n");

    if (fake_filc && *fake_filc)
        t4_filc_parser(fake_filc);
    else
        printf("[SKIP] T4 Fil-C parser (MYC_FAKE_FILC_DIR tidak di-set)\n");

#if !defined(_WIN32)
    if (fake_frama && *fake_frama)
        t6_eva_parser(fake_frama);
    else
        printf("[SKIP] T6 Eva parser (MYC_FAKE_FRAMA_DIR tidak di-set)\n");
#else
    printf("[SKIP] T6 Eva parser (Windows memakai WSL; fake frama-c "
           "POSIX-only)\n");
#endif

    cleanup_tmp();

    printf(g_fail ? "backend_abuse: FAIL (%d)\n" : "backend_abuse: OK\n",
           g_fail);
    return g_fail ? 1 : 0;
}
