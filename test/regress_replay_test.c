/* regress_replay_test.c -- IDE-4 (qwen-review): regression replay
 * pasca-repair (in-process).
 *
 * Menguji myc_regress_replay_mem: replay seluruh corpus terhadap source
 * IN-MEMORY (kode baru setelah patch). Jalur nyata:
 *   T1 fuzz crash -> seed tersimpan otomatis (fuzz_div0 buggy)
 *   T2 replay_mem(source buggy)  -> failing >= 1 (bug lama masih ada)
 *   T3 replay_mem(source fixed)  -> failing == 0, resolved >= 1 (RESOLVED)
 *   T4 corpus kosong             -> total == 0, failing == 0
 *   T5 deterministik             -> dua panggilan identik = hasil sama
 *
 * Jalankan di direktori temp (test/.replay_tmp) agar .myc tidak menyentuh
 * repo. Membutuhkan clang (gate fuzz/ASan) — sama seperti e2e `myc
 * regression run` yang sudah berjalan di CI. Build (portabel):
 *   gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
 *       -o regress_replay_test regress_replay_test.c <seluruh SRCS myc>
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
static int t_chdir(const char *p)
{
    return chdir(p);
}
#define T_MKDIR(p) mkdir((p), 0700)
#define T_CHDIR(p) t_chdir(p)
#define T_RMDIR(p) rmdir(p)
#define T_GETCWD(b, n) getcwd((b), (n))
#endif

#include "regress.h"
#include "sha256.h"

static int PASS = 0;
static int FAIL = 0;

#define CHECK(cond, msg)                                              \
    do {                                                              \
        if (cond) {                                                   \
            PASS++;                                                   \
        } else {                                                      \
            FAIL++;                                                   \
            fprintf(stderr, "[FAIL] %s (%s:%d)\n", msg, __FILE__,     \
                    __LINE__);                                        \
        }                                                             \
    } while (0)

static char       g_old_cwd[1024];
static const char *g_dir = "test/.replay_tmp";

static void save_cwd(void)
{
    if (T_GETCWD(g_old_cwd, sizeof(g_old_cwd)) == NULL)
        g_old_cwd[0] = '\0';
}

/* fuzz_div0 buggy: 10/(n-2), domain n in [0,3] -> n==2 crash */
static const char SRC_BUGGY[] =
    "//@ requires n >= 0 && n <= 3;\n"
    "int fdiv(int n)\n"
    "{\n"
    "    return 10 / (n - 2);\n"
    "}\n";

/* versi fixed: guard n == 2 */
static const char SRC_FIXED[] =
    "//@ requires n >= 0 && n <= 3;\n"
    "int fdiv(int n)\n"
    "{\n"
    "    return n == 2 ? 0 : 10 / (n - 2);\n"
    "}\n";

/* Seed files yang mungkin dibuat (content-addressed, sha8). Dihapus
 * eksplisit agar rmdir berhasil dan re-run bersih (tanpa polusi). */
static void regress_seed_path(const char *src, size_t len, char *out,
                              size_t cap)
{
    char hex[65];
    sha256_hex(src, len, hex);
    snprintf(out, cap, "test/.replay_tmp/.myc/regression/fuzz_%.8s.c",
             hex);
}

static void rmdir_recursive(const char *base)
{
    char seed1[520], seed2[520];
    regress_seed_path(SRC_BUGGY, sizeof(SRC_BUGGY) - 1, seed1,
                      sizeof(seed1));
    regress_seed_path(SRC_FIXED, sizeof(SRC_FIXED) - 1, seed2,
                      sizeof(seed2));
    remove("test/.replay_tmp/.myc/regression/index.txt");
    remove(seed1);
    remove(seed2);
    /* myc_run menulis state lain ke .myc (ledger/cache/dll); bersihkan
     * agar re-run deterministik dan tidak ada leftover. */
    remove("test/.replay_tmp/.myc/ledger.json");
    remove("test/.replay_tmp/.myc/evidence_cache.json");
    remove("test/.replay_tmp/.myc/evidence_cache.sha256");
    T_RMDIR("test/.replay_tmp/.myc/regression");
    T_RMDIR("test/.replay_tmp/.myc");
    (void)base;
}

static void t1_seed_saved(void)
{
    myc_request req;
    myc_result res;
    FILE *idx;

    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = SRC_BUGGY;
    req.input.len = sizeof(SRC_BUGGY) - 1;
    req.fuzz = 1;
    req.fuzz_iters = 2000;
    req.no_cache = 1;
    myc_result_init(&res);
    myc_run(&req, &res);

    CHECK(res.verdict == MC_DRIVER_VIOLATION,
          "T1: fuzz menemukan crash (fuzz_div0)");
    idx = fopen(".myc/regression/index.txt", "rb");
    CHECK(idx != NULL, "T1: seed regression tersimpan otomatis");
    if (idx)
        fclose(idx);

    myc_result_free(&res);
}

static void t2_replay_buggy(void)
{
    int total = 0, resolved = 0, failing = 0;
    int rc;

    rc = myc_regress_replay_mem(SRC_BUGGY, sizeof(SRC_BUGGY) - 1,
                                &total, &resolved, &failing);
    CHECK(total >= 1, "T2: corpus terbaca");
    CHECK(failing >= 1, "T2: source buggy masih gagal");
    CHECK(rc == failing, "T2: return = jumlah gagal");
    CHECK(resolved + failing == total,
          "T2: resolved+failing == total");
}

static void t3_replay_fixed(void)
{
    int total = 0, resolved = 0, failing = 0;
    int rc;

    rc = myc_regress_replay_mem(SRC_FIXED, sizeof(SRC_FIXED) - 1,
                                &total, &resolved, &failing);
    CHECK(total >= 1, "T3: corpus terbaca");
    CHECK(failing == 0, "T3: source fixed bersih (failing=0)");
    CHECK(resolved == total, "T3: semua seed RESOLVED");
    CHECK(rc == 0, "T3: return 0");
}

static void t4_empty_corpus(void)
{
    int total = 99, resolved = 99, failing = 99;
    int rc;

    remove(".myc/regression/index.txt");
    rc = myc_regress_replay_mem(SRC_FIXED, sizeof(SRC_FIXED) - 1,
                                &total, &resolved, &failing);
    CHECK(rc == 0 && total == 0 && resolved == 0 && failing == 0,
          "T4: corpus kosong -> 0/0 (anti-overclaim, bukan clean palsu)");
}

static void t5_deterministic(void)
{
    int t1 = 0, r1 = 0, f1 = 0;
    int t2 = 0, r2 = 0, f2 = 0;

    /* t4 menghapus index; seed ulang lewat save langsung */
    myc_result res;
    myc_result_init(&res);
    myc_regress_save(&res, SRC_FIXED, sizeof(SRC_FIXED) - 1,
                     MYC_REG_FUZZ, "replay-det", 42u);
    myc_result_free(&res);

    myc_regress_replay_mem(SRC_FIXED, sizeof(SRC_FIXED) - 1,
                           &t1, &r1, &f1);
    myc_regress_replay_mem(SRC_FIXED, sizeof(SRC_FIXED) - 1,
                           &t2, &r2, &f2);
    CHECK(t1 == t2 && r1 == r2 && f1 == f2,
          "T5: replay deterministik (input+tool sama -> hasil sama)");
}

int main(void)
{
    printf("regress_replay_test: IDE-4 regression replay pasca-repair\n");
    save_cwd();
    T_MKDIR(g_dir);
    T_MKDIR("test/.replay_tmp/.myc");
    T_MKDIR("test/.replay_tmp/.myc/regression");
    if (T_CHDIR(g_dir) != 0) {
        fprintf(stderr, "[FAIL] chdir %s gagal\n", g_dir);
        FAIL++;
        printf("regress_replay_test: PASS=%d FAIL=%d\n", PASS, FAIL);
        return 1;
    }

    t1_seed_saved();
    t2_replay_buggy();
    t3_replay_fixed();
    t4_empty_corpus();
    t5_deterministic();

    if (g_old_cwd[0])
        T_CHDIR(g_old_cwd);
    rmdir_recursive(g_dir);
    T_RMDIR(g_dir);

    printf("regress_replay_test: PASS=%d FAIL=%d\n", PASS, FAIL);
    return FAIL == 0 ? 0 : 1;
}
