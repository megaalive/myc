/*
 * pra01_soak.c -- PR-A01: beban verifikasi berulang tanpa verdict drift
 * atau cache basi.
 *
 * Production-ready (docs/production-readiness.md PR-3) mensyaratkan myc
 * bertahan self-hosted check berulang tanpa leak/deadlock/cache basi/
 * verdict drift. Deadlock/process-tree sudah diuji PR-006/007; leak =
 * job linux-asan. Pecahan ini mengunci:
 *   T1  N× myc_run --no-cache --no-persist: verdict + receipt identik
 *   T2  1× miss (persist) lalu N× hit: cache_hit=1, receipt/verdict
 *       sama dengan miss (bukan replay yang mengubah hasil)
 *   T3  receipt jalur no-cache == receipt miss persist (identitas sama)
 *
 * Direktori temp test/.pra01_tmp agar .myc/ tidak menyentuh repo.
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
 *       -o pra01_soak pra01_soak.c <seluruh SRCS myc>
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

#include "myc.h"

#define SOAK_N 8

static int g_ok = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_ok++; } \
    else { g_fail++; fprintf(stderr, "[FAIL] %s (line %d)\n", (msg), __LINE__); } \
} while (0)

static char        g_old_cwd[1024];
static const char *g_dir = "test/.pra01_tmp";

/* Source unik (tidak berbagi dengan cache_key_matrix / cache_corrupt). */
static const char SRC[] =
    "static int g_soak[8];\n"
    "int main(void){int i,s=0;for(i=0;i<8;i++)s+=g_soak[i];return s&1;}\n";

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

static void run_once(int no_cache, int no_persist,
                     myc_verdict *vout, char receipt[65], int *hit)
{
    myc_request req;
    myc_result  res;

    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = SRC;
    req.input.len = strlen(SRC);
    req.run_lint = 1;
    req.no_cache = no_cache;
    req.no_persist = no_persist;
    req.cwd = ".";
    myc_result_init(&res);
    myc_run(&req, &res);
    *vout = res.verdict;
    memcpy(receipt, res.receipt_sha256, 65);
    receipt[64] = '\0';
    *hit = res.cache_hit;
    myc_result_free(&res);
}

static void cleanup_myc(void)
{
    remove(".myc/evidence_cache.json");
    remove(".myc/evidence_cache.sha256");
    remove(".myc/ledger.json");
    remove(".myc/assumptions.json");
    T_RMDIR(".myc");
}

int main(void)
{
    myc_verdict v0, v;
    char        r0[65], r[65], r_miss[65];
    int         hit, i;

    save_cwd();
    T_MKDIR(g_dir);
    if (chdir_one(g_dir) != 0)
        return 1;
    T_MKDIR(".myc");

    /* T1: no-cache berulang — tidak ada drift. */
    run_once(1, 1, &v0, r0, &hit);
    CHECK(v0 == MC_OK, "T1: iter 1 no-cache MC_OK");
    CHECK(r0[0] != '\0', "T1: receipt terisi");
    CHECK(hit == 0, "T1: no-cache bukan hit");
    for (i = 2; i <= SOAK_N; i++) {
        run_once(1, 1, &v, r, &hit);
        CHECK(v == v0, "T1: verdict identik no-cache");
        CHECK(strcmp(r, r0) == 0, "T1: receipt identik no-cache");
        CHECK(hit == 0, "T1: tetap miss");
    }

    cleanup_myc();
    T_MKDIR(".myc");

    /* T2: miss lalu hit — replay tidak mengubah hasil. */
    run_once(0, 0, &v, r_miss, &hit);
    CHECK(v == MC_OK, "T2: miss persist MC_OK");
    CHECK(hit == 0, "T2: store pertama adalah miss");
    CHECK(r_miss[0] != '\0', "T2: receipt miss terisi");
    for (i = 1; i <= SOAK_N; i++) {
        run_once(0, 0, &v, r, &hit);
        CHECK(hit == 1, "T2: iterasi berikutnya cache hit");
        CHECK(v == MC_OK, "T2: hit tetap MC_OK");
        CHECK(strcmp(r, r_miss) == 0, "T2: receipt hit == miss (anti drift)");
    }

    /* T3: identitas no-cache == miss persist. */
    CHECK(strcmp(r0, r_miss) == 0,
          "T3: receipt no-cache == receipt miss persist");

    cleanup_myc();
    if (g_old_cwd[0])
        chdir_one(g_old_cwd);
    T_RMDIR(g_dir);

    printf("pra01_soak: %d OK, FAIL=%d\n", g_ok, g_fail);
    return g_fail == 0 ? 0 : 1;
}
