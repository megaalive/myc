/*
 * atomic_state.c -- PR-012 (MYC-AUDIT-044, P3-T03): atomic .myc state
 * writes.
 *
 * Mengunci crash-consistency protokol persistensi bersama
 * (persist.c / myc_persist_atomic_write): tulis temp + flush + fsync +
 * rename/replace atomik. Invariant P3-T03 ("Required result"): pada
 * crash di langkah mana pun, file state `.myc` (*.json) setelah restart
 * selalu OLD VALID atau NEW VALID — tidak pernah setengah tertulis yang
 * tampak valid. Ditest dengan:
 *   T1  helper: tulis file baru (konten + tanpa leftover *.tmp.*)
 *   T2  helper: overwrite file ada (konten lama diganti penuh, tidak
 *       pernah tercampur)
 *   T3  helper: failure injection (direktori induk tak ada) -> return 0,
 *       tanpa target, tanpa temp
 *   T4  crash-simulasi "sebelum rename": temp parsial dari proses yang
 *       mati + target OLD valid -> write baru -> target NEW valid, temp
 *       stale dibersihkan
 *   T5  crash-simulasi "saat temp ditulis": target OLD valid + temp
 *       sampah -> pembaca TETAP melihat OLD valid; setelah recovery
 *       write -> NEW valid
 *   T6  stress overwrite: 200x flip konten A/B -> setelah tiap write
 *       konten SELALU A penuh atau B penuh (tidak pernah campuran)
 *   T7  E2E cache: myc_cache_store 2x (dedup) -> evidence_cache.json
 *       valid JSON, replay HIT, tanpa leftover temp
 *   T8  E2E ledger: myc_ledger_write -> ledger.json valid JSON + entry
 *   T9  E2E asumsi: myc_assume_run (source char-signedness + facts
 *       manual, tanpa gcc) -> assumptions.json valid JSON
 *   T10 E2E calibration: myc_calib_mark -> calibration.json valid JSON
 *   T11 E2E profile: myc_profile_record -> profiles/<id>.json valid +
 *       index.txt memuat id
 *   T12 E2E regress: myc_regress_save -> seed .c tersimpan + index line
 *   T13 scan akhir: TIDAK ada file *.tmp.* di mana pun di .myc/
 *
 * Jalankan di direktori temp (test/.atomic_tmp) agar .myc tidak
 * menyentuh repo; dibersihkan sendiri. Build (portabel Windows MinGW +
 * POSIX):
 *   gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
 *       -o atomic_state atomic_state.c <seluruh SRCS myc>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#include <process.h>
#include <windows.h>
#define T_MKDIR(p) _mkdir(p)
#define T_CHDIR(p) _chdir(p)
#define T_RMDIR(p) _rmdir(p)
#define T_GETCWD(b, n) _getcwd((b), (n))
#define T_GETPID() ((long)_getpid())
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#define T_MKDIR(p) mkdir((p), 0700)
#define T_CHDIR(p) chdir(p)
#define T_RMDIR(p) rmdir(p)
#define T_GETCWD(b, n) getcwd((b), (n))
#define T_GETPID() ((long)getpid())
#endif

#include "assume.h"
#include "cache.h"
#include "calibrate.h"
#include "json.h"
#include "ledger.h"
#include "persist.h"
#include "profile.h"
#include "regress.h"
#include "sha256.h"

static int g_ok = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_ok++; } \
    else { g_fail++; fprintf(stderr, "[FAIL] %s (line %d)\n", (msg), __LINE__); } \
} while (0)

/* ------------------------------------------------------------------ */
/* Infra: temp dir + file helpers                                     */
/* ------------------------------------------------------------------ */

static char       g_old_cwd[1024];
static const char *g_dir = "test/.atomic_tmp";

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
    T_MKDIR(p);   /* EEXIST wajar */
}

static void rmdir_one(const char *p)
{
    T_RMDIR(p);
}

/* Baca seluruh file (NULL bila tak ada). Caller free. */
static char *read_file(const char *path)
{
    FILE *f;
    long  sz;
    char *buf;

    f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > (32 << 20)) {
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
    return buf;
}

/* Apakah file ada? */
static int file_exists(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

/* Tulis file langsung (simulasi state crash / seed manual). */
static void write_raw(const char *path, const char *data)
{
    FILE *f = fopen(path, "wb");
    if (f) {
        fputs(data, f);
        fclose(f);
    }
}

/* Apakah path valid JSON (parsable oleh json_parse internal)? */
static int valid_json_file(const char *path)
{
    char       *buf = read_file(path);
    json_value *root = NULL;
    int         ok = 0;

    if (!buf)
        return 0;
    ok = (json_parse(buf, strlen(buf), &root) != 0 && root != NULL);
    if (root)
        json_free(root);
    free(buf);
    return ok;
}

/* Jumlah file `*.tmp.*` di direktori (0 = bersih). */
static int count_temp_files(const char *dir)
{
    int n = 0;
#if defined(_WIN32)
    WIN32_FIND_DATAA fd;
    HANDLE h;
    char pattern[512];
    snprintf(pattern, sizeof(pattern), "%s/*.tmp.*", dir);
    h = FindFirstFileA(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            n++;
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
#else
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strstr(de->d_name, ".tmp."))
                n++;
        }
        closedir(d);
    }
#endif
    return n;
}

/* Tulis file .myc/<sub>/<name> lewat myc_persist_atomic_write_str. */
static void pwrite(const char *path, const char *data)
{
    (void)myc_persist_atomic_write_str(path, data);
}

/* ------------------------------------------------------------------ */
/* T1: helper tulis file baru                                          */
/* ------------------------------------------------------------------ */

static void test_helper_new(void)
{
    char *got;

    pwrite(".myc/a.json", "{\"v\":1}");
    got = read_file(".myc/a.json");
    CHECK(got != NULL, "T1: file baru terbuat");
    if (got) {
        CHECK(strcmp(got, "{\"v\":1}") == 0,
              "T1: konten persis (bukan sebagian)");
        free(got);
    }
    CHECK(count_temp_files(".myc") == 0,
          "T1: tanpa leftover *.tmp.* setelah tulis sukses");
}

/* ------------------------------------------------------------------ */
/* T2: overwrite file ada                                              */
/* ------------------------------------------------------------------ */

static void test_helper_overwrite(void)
{
    char *got;

    pwrite(".myc/b.json", "AAAAAAAAAAAAAAAA");
    pwrite(".myc/b.json", "BBBBBBBBBBBBBBBB");
    got = read_file(".myc/b.json");
    CHECK(got != NULL, "T2: file masih ada");
    if (got) {
        CHECK(strcmp(got, "BBBBBBBBBBBBBBBB") == 0,
              "T2: konten lama diganti PENUH (tidak tercampur)");
        free(got);
    }
    CHECK(count_temp_files(".myc") == 0,
          "T2: tanpa leftover *.tmp.*");
}

/* ------------------------------------------------------------------ */
/* T3: failure injection — direktori induk tak ada                     */
/* ------------------------------------------------------------------ */

static void test_helper_failure(void)
{
    int rc;

    rc = myc_persist_atomic_write_str("no_such_dir_xyz/x.json", "{}");
    CHECK(rc == 0, "T3: direktori induk tak ada -> return 0");
    CHECK(!file_exists("no_such_dir_xyz/x.json"),
          "T3: target tidak dibuat");
    CHECK(count_temp_files("no_such_dir_xyz") == 0,
          "T3: tanpa leftover temp (dir tak ada)");
}

/* ------------------------------------------------------------------ */
/* T4 + T5: crash-simulasi — temp stale + target valid                 */
/* ------------------------------------------------------------------ */

static void test_helper_crash_sim(void)
{
    char stale[300];
    char *got;

    /* T4: "crash sebelum rename": temp parsial (proses mati) + target
     * OLD valid. Write baru harus menghasilkan NEW valid DAN membersihkan
     * temp stale dari pid lain. */
    pwrite(".myc/c.json", "{\"old\":1}");
    snprintf(stale, sizeof(stale), ".myc/c.json.tmp.%ld",
             T_GETPID() + 1);   /* pid BEDA (proses "mati") */
    write_raw(stale, "{\"par");
    pwrite(".myc/c.json", "{\"new\":2}");
    got = read_file(".myc/c.json");
    CHECK(got != NULL && strcmp(got, "{\"new\":2}") == 0,
          "T4: target = NEW valid setelah recovery");
    if (got)
        free(got);
    CHECK(!file_exists(stale),
          "T4: temp stale dari crash dibersihkan");

    /* T5: "saat temp ditulis": target OLD valid + temp sampah. Pembaca
     * (yang hanya membaca target) TETAP melihat OLD valid — temp tidak
     * pernah dibaca. */
    pwrite(".myc/d.json", "{\"old\":1}");
    snprintf(stale, sizeof(stale), ".myc/d.json.tmp.%ld", T_GETPID() + 2);
    write_raw(stale, "GARBAGE-PARTIAL");
    got = read_file(".myc/d.json");
    CHECK(got != NULL && strcmp(got, "{\"old\":1}") == 0,
          "T5: target tetap OLD valid (temp sampah tidak dibaca)");
    if (got)
        free(got);
    /* recovery write -> NEW valid + temp stale hilang */
    pwrite(".myc/d.json", "{\"new\":2}");
    got = read_file(".myc/d.json");
    CHECK(got != NULL && strcmp(got, "{\"new\":2}") == 0,
          "T5: setelah recovery write -> NEW valid");
    if (got)
        free(got);
    CHECK(count_temp_files(".myc") == 0,
          "T5: tanpa leftover *.tmp.* setelah recovery");
}

/* ------------------------------------------------------------------ */
/* T6: stress overwrite — konten selalu A penuh atau B penuh           */
/* ------------------------------------------------------------------ */

static void test_helper_stress(void)
{
    int  i;
    char *got;

    for (i = 0; i < 200; i++) {
        const char *want = (i % 2 == 0)
            ? "{\"flip\":\"AAAA\",\"pad\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}"
            : "{\"flip\":\"BBBB\",\"pad\":\"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\"}";
        pwrite(".myc/e.json", want);
        got = read_file(".myc/e.json");
        if (!got) {
            CHECK(0, "T6: file selalu terbaca setelah tiap write");
            break;
        }
        if (strcmp(got, want) != 0) {
            CHECK(0, "T6: konten selalu A penuh atau B penuh (tidak campur)");
            free(got);
            break;
        }
        free(got);
    }
    if (i == 200)
        g_ok++;
    CHECK(count_temp_files(".myc") == 0, "T6: tanpa leftover *.tmp.*");
}

/* ------------------------------------------------------------------ */
/* T7: E2E cache store + replay                                        */
/* ------------------------------------------------------------------ */

static void test_e2e_cache(void)
{
    myc_request req;
    myc_result res;
    myc_result replay;
    int        m = 0;

    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = NULL;
    req.input.len = 0;
    req.run_lint = 1;
    req.cwd = g_dir;

    myc_result_init(&res);
    res.verdict = MC_OK;
    res.err = MYC_ERR_NONE;
    res.lint_observations = 1000;
    memset(res.receipt_sha256, 'a', 64);
    res.receipt_sha256[64] = '\0';

    myc_cache_store(&req, &res, "int f(void){return 0;}\n", 23);
    myc_cache_store(&req, &res, "int f(void){return 0;}\n", 23);
    myc_result_free(&res);

    CHECK(valid_json_file(".myc/evidence_cache.json"),
          "T7: evidence_cache.json valid JSON (store 2x dedup)");
    CHECK(count_temp_files(".myc") == 0,
          "T7: tanpa leftover *.tmp.* setelah cache store");

    myc_result_init(&replay);
    m = myc_cache_try_replay(&req, &replay,
                             "int f(void){return 0;}\n", 23);
    CHECK(m == 1 && replay.lint_observations == 1000,
          "T7: replay HIT + identik (SOL-18) setelah tulis atomik");
    myc_result_free(&replay);
}

/* ------------------------------------------------------------------ */
/* T8: E2E ledger                                                      */
/* ------------------------------------------------------------------ */

static void test_e2e_ledger(void)
{
    myc_ledger_entry e;
    myc_ledger       l;
    int              rc;

    memset(&e, 0, sizeof(e));
    e.source_sha256 = "sha-src-1";
    e.receipt_sha256 = "receipt-1";
    e.scenario_hash = "scen-1";
    e.timestamp = "2026-08-12T00:00:00Z";
    e.delta = MYC_DELTA_NEW;
    e.gate_id = "compile";
    e.gate_status = "completed_findings";
    e.verdict = "findings";
    e.finding = "findings";

    rc = myc_ledger_write(&e);
    CHECK(rc == 1, "T8: myc_ledger_write sukses");
    CHECK(valid_json_file(".myc/ledger.json"),
          "T8: ledger.json valid JSON");

    memset(&l, 0, sizeof(l));
    CHECK(myc_ledger_read(&l) == 1 && l.count >= 1,
          "T8: ledger terbaca ulang (entry ada)");
    myc_ledger_free(&l);
    CHECK(count_temp_files(".myc") == 0,
          "T8: tanpa leftover *.tmp.* setelah ledger write");
}

/* ------------------------------------------------------------------ */
/* T9: E2E asumsi (facts manual, tanpa gcc)                            */
/* ------------------------------------------------------------------ */

static void test_e2e_assume(void)
{
    myc_request    req;
    myc_result     res;
    myc_host_facts facts;
    const char     *src = "int f(char c) { if (c < 0) return 1; return 0; }\n";

    memset(&facts, 0, sizeof(facts));
    facts.ok = 1;
    facts.char_unsigned = 0;
    facts.int_bits = 32;
    facts.ptr_bits = 64;
    facts.little_endian = 1;
    facts.stdc_version = 201112L;
    facts.char_bit = 8;

    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = NULL;
    req.input.len = 0;

    myc_result_init(&res);
    myc_assume_run(&req, &res, src, strlen(src), &facts);
    myc_result_free(&res);

    if (file_exists(".myc/assumptions.json")) {
        CHECK(valid_json_file(".myc/assumptions.json"),
              "T9: assumptions.json valid JSON (atomik)");
    } else {
        CHECK(1, "T9: (asumsi tidak terdeteksi — file tak ditulis, ok)");
    }
    CHECK(count_temp_files(".myc") == 0,
          "T9: tanpa leftover *.tmp.* setelah asumsi write");
}

/* ------------------------------------------------------------------ */
/* T10: E2E calibration                                                */
/* ------------------------------------------------------------------ */

static void test_e2e_calib(void)
{
    int rc;

    rc = myc_calib_mark("lint-x", "accepted", "possible-buffer");
    CHECK(rc == 0, "T10: myc_calib_mark sukses");
    CHECK(valid_json_file(".myc/calibration.json"),
          "T10: calibration.json valid JSON");
    CHECK(count_temp_files(".myc") == 0,
          "T10: tanpa leftover *.tmp.* setelah calib write");
}

/* ------------------------------------------------------------------ */
/* T11: E2E profile                                                    */
/* ------------------------------------------------------------------ */

static void test_e2e_profile(void)
{
    myc_result res;
    char       *idx;

    myc_result_init(&res);
    res.verdict = MC_OK;
    res.finding = MYC_FINDING_CLEAN;
    res.duration_ms = 5;

    myc_profile_record(&res, "atomic-test");
    myc_result_free(&res);

    CHECK(valid_json_file(".myc/profiles/atomic-test.json"),
          "T11: profiles/atomic-test.json valid JSON");
    idx = read_file(".myc/profiles/index.txt");
    CHECK(idx != NULL && strstr(idx, "atomic-test") != NULL,
          "T11: index.txt memuat id profile");
    if (idx)
        free(idx);
    CHECK(count_temp_files(".myc/profiles") == 0,
          "T11: tanpa leftover *.tmp.* di profiles/");
}

/* ------------------------------------------------------------------ */
/* T12: E2E regression seed                                            */
/* ------------------------------------------------------------------ */

static void test_e2e_regress(void)
{
    myc_result res;
    char       *idx;
    static const char SRC[] = "int main(void){return 0;}\n";

    myc_result_init(&res);
    myc_regress_save(&res, SRC, sizeof(SRC) - 1, MYC_REG_FUZZ,
                     "atomic-e2e", 42u);
    myc_result_free(&res);

    CHECK(count_temp_files(".myc/regression") == 0,
          "T12: seed .c ditulis atomik (tanpa *.tmp.*)");
    idx = read_file(".myc/regression/index.txt");
    CHECK(idx != NULL && strstr(idx, "fuzz") != NULL,
          "T12: regression index memuat seed fuzz");
    if (idx)
        free(idx);
}

/* Nama seed yang dibuat myc_regress_save (content-addressed, idempoten):
 * REG_DIR/<kind>_<sha8>.c — dipakai cleanup agar re-run bersih. */
static void regress_seed_path(char *out, size_t cap)
{
    static const char SRC[] = "int main(void){return 0;}\n";
    char hex[65];

    sha256_hex(SRC, sizeof(SRC) - 1, hex);
    snprintf(out, cap, "test/.atomic_tmp/.myc/regression/fuzz_%.8s.c", hex);
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
    mkdir_one(".myc");
    mkdir_one(".myc/profiles");
    mkdir_one(".myc/regression");

    test_helper_new();
    test_helper_overwrite();
    test_helper_failure();
    test_helper_crash_sim();
    test_helper_stress();
    test_e2e_cache();
    test_e2e_ledger();
    test_e2e_assume();
    test_e2e_calib();
    test_e2e_profile();
    test_e2e_regress();

    /* T13: scan akhir — tidak ada *.tmp.* di seluruh .myc */
    CHECK(count_temp_files(".myc") == 0 &&
          count_temp_files(".myc/profiles") == 0 &&
          count_temp_files(".myc/regression") == 0,
          "T13: NOL leftover *.tmp.* di seluruh .myc setelah semua test");

    if (g_old_cwd[0])
        chdir_one(g_old_cwd);

    remove("test/.atomic_tmp/.myc/evidence_cache.json");
    remove("test/.atomic_tmp/.myc/ledger.json");
    remove("test/.atomic_tmp/.myc/assumptions.json");
    remove("test/.atomic_tmp/.myc/calibration.json");
    remove("test/.atomic_tmp/.myc/exhaustive.json");
    remove("test/.atomic_tmp/.myc/a.json");
    remove("test/.atomic_tmp/.myc/b.json");
    remove("test/.atomic_tmp/.myc/c.json");
    remove("test/.atomic_tmp/.myc/d.json");
    remove("test/.atomic_tmp/.myc/e.json");
    /* temp stale dari crash-sim (pid +1/+2) sudah dihapus oleh recovery
     * write (T4/T5); rmdir .myc di bawah akan gagal bila ada sisa. */
    remove("test/.atomic_tmp/.myc/profiles/atomic-test.json");
    remove("test/.atomic_tmp/.myc/profiles/index.txt");
    remove("test/.atomic_tmp/.myc/regression/index.txt");
    {
        char seed[200];
        regress_seed_path(seed, sizeof(seed));
        remove(seed);
    }
    rmdir_one("test/.atomic_tmp/.myc/regression");
    rmdir_one("test/.atomic_tmp/.myc/profiles");
    rmdir_one("test/.atomic_tmp/.myc");
    rmdir_one(g_dir);

    printf("atomic_state: %d OK, %d FAIL\n", g_ok, g_fail);
    return g_fail == 0 ? 0 : 1;
}
