/*
 * production_mode.c -- P12 / P5-T03: --production + floor versi backend.
 *
 * T1  myc_tool_version_major: gcc 9+ / clang version line / garbage
 * T2  myc_run --production pada source bersih → MC_OK (gcc CI >= 9)
 */
#include <stdio.h>
#include <string.h>

#include "myc.h"
#include "canary.h"

static int g_ok, g_fail;

#define CHECK(cond, msg) do { \
    if (cond) { g_ok++; } \
    else { g_fail++; fprintf(stderr, "[FAIL] %s (line %d)\n", (msg), __LINE__); } \
} while (0)

static const char SRC[] =
    "int main(void){return 0;}\n";

int main(void)
{
    myc_request req;
    myc_result  res;

    CHECK(myc_tool_version_major("gcc 9+") == 9, "T1: min gcc 9+");
    CHECK(myc_tool_version_major("gcc 10+ (fanalyzer)") == 10,
          "T1: min gcc 10+");
    CHECK(myc_tool_version_major("clang 11+ (ASan/UBSan)") == 11,
          "T1: min clang 11+");
    CHECK(myc_tool_version_major("frama-c 28+") == 28, "T1: min frama-c 28+");
    CHECK(myc_tool_version_major("15.2.0") == 15, "T1: 15.2.0 bukan 2");
    CHECK(myc_tool_version_major(
              "gcc.exe (x86_64-posix-seh-rev0, Built by MinGW-Builds project) 15.2.0") == 15,
          "T1: gcc --version 15.2.0");
    CHECK(myc_tool_version_major("clang version 20.1.8") == 20,
          "T1: clang --version");
    CHECK(myc_tool_version_major(NULL) == -1, "T1: NULL");
    CHECK(myc_tool_version_major("no-digits") == -1, "T1: tanpa angka");

    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = SRC;
    req.input.len = strlen(SRC);
    req.run_lint = 1;
    req.production = 1;
    req.require_complete = 1;
    req.no_persist = 1;
    myc_result_init(&res);
    myc_run(&req, &res);
    CHECK(res.verdict == MC_OK, "T2: --production source bersih MC_OK");
    myc_result_free(&res);

    printf("production_mode: %d OK, FAIL=%d\n", g_ok, g_fail);
    return g_fail == 0 ? 0 : 1;
}
