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
 *   T6 repair parsial (multi-seed, beda kind): patch memperbaiki bug fuzz
 *      tapi TIDAK bug exhaustive -> replay jujur 1 masih gagal, 1 resolved
 *      (anti-overclaim: patch yang tidak tuntas TIDAK pernah "clean").
 *   T7 corpus multi-kind (fuzz + exhaustive + driver): ketiga gate di-replay
 *      bersama; fix lengkap -> resolved == total; semua buggy -> failing ==
 *      total; save ulang idempoten (seed file ada -> tidak duplikat index).
 *   T8 source tak terkait (anti-false-positive): source bersih yang tidak
 *      mengandung bug corpus -> SEMUA seed resolved, 0 failing (replay
 *      tidak menuduh source asing).
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

/* bug exhaustive (MYC-AUDIT-065, T6/T7): ensures n < 64 GAGAL di n==64
 * (counterexample enumeratif; tidak crash runtime -> tidak terdeteksi
 * gate fuzz, jadi kind ini independen dari bug fdiv). */
static const char SRC_EXH_BUGGY[] =
    "//@ requires n >= 0 && n <= 64;\n"
    "//@ ensures n < 64;\n"
    "int clamp_wrong(int n)\n"
    "{\n"
    "    if (n < 0)\n"
    "        return 0;\n"
    "    if (n > 64)\n"
    "        return 64;\n"
    "    return n;\n"
    "}\n";

/* bug driver (MYC-AUDIT-065, T7): a[n] OOB saat n==4 (buffer 4 elemen
 * int, kontrak n <= 4). Indepneden dari bug fuzz/exhaustive. */
static const char SRC_DRV_BUGGY[] =
    "//@ requires n <= 4;\n"
    "int bad_read(const int *a, int n)\n"
    "{\n"
    "    return a[n];\n"
    "}\n";

/* T6: repair PARSIAL -- fdiv diperbaiki, clamp_wrong MASIH buggy. */
static const char SRC_PARTIAL[] =
    "//@ requires n >= 0 && n <= 3;\n"
    "int fdiv(int n)\n"
    "{\n"
    "    return n == 2 ? 0 : 10 / (n - 2);\n"
    "}\n"
    "//@ requires n >= 0 && n <= 64;\n"
    "//@ ensures n < 64;\n"
    "int clamp_wrong(int n)\n"
    "{\n"
    "    if (n < 0)\n"
    "        return 0;\n"
    "    if (n > 64)\n"
    "        return 64;\n"
    "    return n;\n"
    "}\n";

/* T6: fix LENGKAP -- fdiv + clamp_wrong keduanya benar. Fix kontrak
 * clamp_wrong: ensures disamakan dengan domain (pola ok_exhaustive.c) --
 * gate exhaustive mengevaluasi klausa ensures terhadap PARAMETER input
 * (return value di-(void)-kan), jadi `ensures n < 64` tidak bisa valid
 * bila n==64 ada di domain. */
static const char SRC_FULL_FIX[] =
    "//@ requires n >= 0 && n <= 3;\n"
    "int fdiv(int n)\n"
    "{\n"
    "    return n == 2 ? 0 : 10 / (n - 2);\n"
    "}\n"
    "//@ requires n >= 0 && n <= 64;\n"
    "//@ ensures n >= 0 && n <= 64;\n"
    "int clamp_wrong(int n)\n"
    "{\n"
    "    if (n < 0)\n"
    "        return 0;\n"
    "    if (n > 64)\n"
    "        return 64;\n"
    "    return n;\n"
    "}\n";

/* T6: kedua bug masih hidup. */
static const char SRC_BOTH_BUGGY[] =
    "//@ requires n >= 0 && n <= 3;\n"
    "int fdiv(int n)\n"
    "{\n"
    "    return 10 / (n - 2);\n"
    "}\n"
    "//@ requires n >= 0 && n <= 64;\n"
    "//@ ensures n < 64;\n"
    "int clamp_wrong(int n)\n"
    "{\n"
    "    if (n < 0)\n"
    "        return 0;\n"
    "    if (n > 64)\n"
    "        return 64;\n"
    "    return n;\n"
    "}\n";

/* T7: corpus multi-kind -- ketiga bug digabung (semua buggy). */
static const char SRC_ALL_BUGGY[] =
    "//@ requires n >= 0 && n <= 3;\n"
    "int fdiv(int n)\n"
    "{\n"
    "    return 10 / (n - 2);\n"
    "}\n"
    "//@ requires n >= 0 && n <= 64;\n"
    "//@ ensures n < 64;\n"
    "int clamp_wrong(int n)\n"
    "{\n"
    "    if (n < 0)\n"
    "        return 0;\n"
    "    if (n > 64)\n"
    "        return 64;\n"
    "    return n;\n"
    "}\n"
    "//@ requires n <= 4;\n"
    "int bad_read(const int *a, int n)\n"
    "{\n"
    "    return a[n];\n"
    "}\n";

/* T7: ketiga bug diperbaiki. */
static const char SRC_ALL_FIXED[] =
    "//@ requires n >= 0 && n <= 3;\n"
    "int fdiv(int n)\n"
    "{\n"
    "    return n == 2 ? 0 : 10 / (n - 2);\n"
    "}\n"
    "//@ requires n >= 0 && n <= 64;\n"
    "//@ ensures n >= 0 && n <= 64;\n"
    "int clamp_wrong(int n)\n"
    "{\n"
    "    if (n < 0)\n"
    "        return 0;\n"
    "    if (n > 64)\n"
    "        return 64;\n"
    "    return n;\n"
    "}\n"
    "//@ requires n <= 4;\n"
    "int bad_read(const int *a, int n)\n"
    "{\n"
    "    return (n >= 0 && n < 4) ? a[n] : a[3];\n"
    "}\n";

/* T8: source TIDAK TERKAIT dengan corpus (fungsi bersih, bug yang sama
 * tidak ada). Replay harus 0 failing (anti-false-positive). */
static const char SRC_UNRELATED[] =
    "//@ requires n >= 0 && n <= 1024;\n"
    "int double_it(int n)\n"
    "{\n"
    "    return 2 * n;\n"
    "}\n"
    "int main(void)\n"
    "{\n"
    "    return 0;\n"
    "}\n";

/* Seed files yang mungkin dibuat (content-addressed, sha8). Dihapus
 * eksplisit agar rmdir berhasil dan re-run bersih (tanpa polusi). */
static void regress_seed_path_kind(const char *kind, const char *src,
                                   size_t len, char *out, size_t cap)
{
    char hex[65];
    sha256_hex(src, len, hex);
    snprintf(out, cap, "test/.replay_tmp/.myc/regression/%s_%.8s.c",
             kind, hex);
}

static void regress_seed_path(const char *src, size_t len, char *out,
                              size_t cap)
{
    regress_seed_path_kind("fuzz", src, len, out, cap);
}

/* Reset corpus: hapus index + semua seed file yang dikenal (konten-
 * addressed) agar tiap test dimulai dari state bersih. */
static void corpus_reset(void)
{
    char p[520];
    remove("test/.replay_tmp/.myc/regression/index.txt");
    regress_seed_path_kind("fuzz", SRC_BUGGY, sizeof(SRC_BUGGY) - 1,
                           p, sizeof(p));
    remove(p);
    regress_seed_path_kind("fuzz", SRC_FIXED, sizeof(SRC_FIXED) - 1,
                           p, sizeof(p));
    remove(p);
    regress_seed_path_kind("exhaustive", SRC_EXH_BUGGY,
                           sizeof(SRC_EXH_BUGGY) - 1, p, sizeof(p));
    remove(p);
    regress_seed_path_kind("driver", SRC_DRV_BUGGY,
                           sizeof(SRC_DRV_BUGGY) - 1, p, sizeof(p));
    remove(p);
}

static void rmdir_recursive(const char *base)
{
    char seed1[520], seed2[520];
    regress_seed_path(SRC_BUGGY, sizeof(SRC_BUGGY) - 1, seed1,
                      sizeof(seed1));
    regress_seed_path(SRC_FIXED, sizeof(SRC_FIXED) - 1, seed2,
                      sizeof(seed2));
    corpus_reset();
    /* myc_run menulis state lain ke .myc (ledger/cache/dll); bersihkan
     * agar re-run deterministik dan tidak ada leftover. */
    remove("test/.replay_tmp/.myc/ledger.json");
    remove("test/.replay_tmp/.myc/evidence_cache.json");
    remove("test/.replay_tmp/.myc/evidence_cache.sha256");
    T_RMDIR("test/.replay_tmp/.myc/regression");
    T_RMDIR("test/.replay_tmp/.myc");
    (void)base;
}

/* Jalankan fuzz pada source (persis T1) dan simpan seed otomatis.
 * return 1 = DRIVER_VIOLATION ditemukan. */
static int fuzz_seed_saved(const char *src, size_t len)
{
    myc_request req;
    myc_result res;
    int found = 0;

    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = src;
    req.input.len = len;
    req.fuzz = 1;
    req.fuzz_iters = 2000;
    req.no_cache = 1;
    myc_result_init(&res);
    myc_run(&req, &res);

    found = (res.verdict == MC_DRIVER_VIOLATION);
    myc_result_free(&res);
    return found;
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

/* T6 (MYC-AUDIT-065): repair PARSIAL. Corpus berisi 2 seed beda kind:
 * fuzz (fdiv div-by-zero) + exhaustive (clamp_wrong ensures). Patch yang
 * memperbaiki HANYA bug fuzz -> replay harus jujur: 1 resolved, 1 masih
 * gagal (bukan "clean" palsu). Patch lengkap -> 0 gagal. Patch kosong ->
 * 2 gagal. */
static void t6_partial_repair(void)
{
    int total = 0, resolved = 0, failing = 0;
    int rc;
    myc_result res;

    corpus_reset();
    CHECK(fuzz_seed_saved(SRC_BUGGY, sizeof(SRC_BUGGY) - 1),
          "T6: seed fuzz fdiv tersimpan");
    myc_result_init(&res);
    myc_regress_save(&res, SRC_EXH_BUGGY, sizeof(SRC_EXH_BUGGY) - 1,
                     MYC_REG_EXHAUSTIVE, "counterexample", 0);
    myc_result_free(&res);

    /* repair parsial: fdiv fixed, clamp_wrong masih buggy */
    rc = myc_regress_replay_mem(SRC_PARTIAL, sizeof(SRC_PARTIAL) - 1,
                                &total, &resolved, &failing);
    CHECK(total == 2, "T6: corpus 2 seed (fuzz + exhaustive)");
    CHECK(failing == 1, "T6: repair parsial -> 1 masih gagal (jujur)");
    CHECK(resolved == 1, "T6: repair parsial -> 1 resolved");
    CHECK(rc == 1, "T6: return = jumlah gagal (1)");

    /* repair lengkap */
    rc = myc_regress_replay_mem(SRC_FULL_FIX, sizeof(SRC_FULL_FIX) - 1,
                                &total, &resolved, &failing);
    CHECK(failing == 0, "T6: fix lengkap -> 0 masih gagal");
    CHECK(resolved == 2, "T6: fix lengkap -> 2 resolved");
    CHECK(rc == 0, "T6: fix lengkap -> return 0");

    /* tidak ada perbaikan sama sekali */
    rc = myc_regress_replay_mem(SRC_BOTH_BUGGY,
                                sizeof(SRC_BOTH_BUGGY) - 1,
                                &total, &resolved, &failing);
    CHECK(failing == 2, "T6: tanpa fix -> 2 masih gagal");
    CHECK(resolved == 0, "T6: tanpa fix -> 0 resolved");

    /* deterministik lintas kind (perpanjangan T5) */
    {
        int tA = 0, rA = 0, fA = 0, tB = 0, rB = 0, fB = 0;
        myc_regress_replay_mem(SRC_FULL_FIX, sizeof(SRC_FULL_FIX) - 1,
                               &tA, &rA, &fA);
        myc_regress_replay_mem(SRC_FULL_FIX, sizeof(SRC_FULL_FIX) - 1,
                               &tB, &rB, &fB);
        CHECK(tA == tB && rA == rB && fA == fB,
              "T6: deterministik corpus multi-kind");
    }
}

/* T7 (MYC-AUDIT-065): corpus MULTI-KIND (fuzz + exhaustive + driver)
 * di-replay bersama; tiap seed memakai gate-nya sendiri. Fix lengkap ->
 * resolved == total. Semua buggy -> failing == total. Save ulang seed
 * yang sama -> idempoten (tidak menduplikasi index). */
static void t7_multi_kind(void)
{
    int total = 0, resolved = 0, failing = 0;
    int rc;
    myc_result res;

    corpus_reset();
    CHECK(fuzz_seed_saved(SRC_BUGGY, sizeof(SRC_BUGGY) - 1),
          "T7: seed fuzz fdiv tersimpan");
    myc_result_init(&res);
    myc_regress_save(&res, SRC_EXH_BUGGY, sizeof(SRC_EXH_BUGGY) - 1,
                     MYC_REG_EXHAUSTIVE, "counterexample", 0);
    myc_regress_save(&res, SRC_DRV_BUGGY, sizeof(SRC_DRV_BUGGY) - 1,
                     MYC_REG_DRIVER, "driver-violation", 0);
    /* save ulang driver seed -> idempoten (file sudah ada) */
    myc_regress_save(&res, SRC_DRV_BUGGY, sizeof(SRC_DRV_BUGGY) - 1,
                     MYC_REG_DRIVER, "driver-violation", 0);
    myc_result_free(&res);

    /* fix lengkap: ketiga gate bersih */
    rc = myc_regress_replay_mem(SRC_ALL_FIXED, sizeof(SRC_ALL_FIXED) - 1,
                                &total, &resolved, &failing);
    CHECK(total == 3, "T7: corpus 3 seed (fuzz+exhaustive+driver)");
    CHECK(resolved == 3, "T7: fix lengkap -> semua seed RESOLVED");
    CHECK(failing == 0, "T7: fix lengkap -> 0 masih gagal");
    CHECK(rc == 0, "T7: return 0");

    /* semua buggy: ketiga gate menangkap bugnya sendiri */
    rc = myc_regress_replay_mem(SRC_ALL_BUGGY, sizeof(SRC_ALL_BUGGY) - 1,
                                &total, &resolved, &failing);
    CHECK(failing == 3, "T7: semua buggy -> 3 masih gagal");
    CHECK(resolved == 0, "T7: semua buggy -> 0 resolved");
    CHECK(rc == 3, "T7: return 3");

    /* save ulang idempoten: total tetap 3, bukan 4 */
    rc = myc_regress_replay_mem(SRC_ALL_FIXED, sizeof(SRC_ALL_FIXED) - 1,
                                &total, &resolved, &failing);
    CHECK(total == 3, "T7: save ulang seed idempoten (total tetap 3)");
}

/* T8 (MYC-AUDIT-065): source TAK TERKAIT (anti-false-positive). Corpus
 * multi-kind berisi bug fdiv/clamp/bad_read; source asing yang bersih
 * tidak mengandung bug itu -> SEMUA seed resolved, 0 failing. Replay
 * tidak boleh menuduh source yang tidak terkait. */
static void t8_unrelated_source(void)
{
    int total = 0, resolved = 0, failing = 0;
    int rc;

    rc = myc_regress_replay_mem(SRC_UNRELATED,
                                sizeof(SRC_UNRELATED) - 1,
                                &total, &resolved, &failing);
    CHECK(total >= 3, "T8: corpus terbaca (warisan T7)");
    CHECK(failing == 0, "T8: source tak terkait -> 0 gagal (anti-FP)");
    CHECK(resolved == total, "T8: semua seed resolved pada source asing");
    CHECK(rc == 0, "T8: return 0");
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
    t6_partial_repair();
    t7_multi_kind();
    t8_unrelated_source();

    if (g_old_cwd[0])
        T_CHDIR(g_old_cwd);
    rmdir_recursive(g_dir);
    T_RMDIR(g_dir);

    printf("regress_replay_test: PASS=%d FAIL=%d\n", PASS, FAIL);
    return FAIL == 0 ? 0 : 1;
}
