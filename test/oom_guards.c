/*
 * oom_guards.c -- Regression MYC-AUDIT-018: guard OOM/overflow (portabel).
 *
 * Memaksa jalur kegagalan alokasi / ukuran ekstrem pada API level:
 *   1. myc_result_arena_dup dengan string_len raksasa (SIZE_MAX dan
 *      SIZE_MAX-10) -> NULL, BUKAN memcpy out-of-bounds (bug yang
 *      diperbaiki: n+1 wrap ke 0 di arena_dup).
 *   2. myc_run source > MYC_MAX_CODE_BYTES -> MC_ERROR/INPUT_TOO_LARGE,
 *      tanpa crash.
 *   3. myc_run source memuat NUL -> MC_ERROR/NUL_IN_INPUT.
 *   4. myc_run request invalid (tanpa source & file_path) -> MC_ERROR.
 *   5. Kontrol: source valid kecil -> MC_OK.
 *
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o oom_guards \
 *       oom_guards.c myc.c proc.c scanner.c policy.c compile.c report.c \
 *       sha256.c lint.c run.c contract.c prove.c filc.c driver.c json.c \
 *       gate.c negative.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myc.h"

static int g_fail = 0;

#define CHECK(cond, fmt, ...) do {                                    \
        if (cond) {                                                   \
            printf("[OK]   " fmt "\n", ##__VA_ARGS__);                \
        } else {                                                      \
            fprintf(stderr, "[FAIL] " fmt "\n", ##__VA_ARGS__);       \
            g_fail++;                                                 \
        }                                                             \
    } while (0)

int main(void)
{
    /* T1: arena_dup panjang raksasa -> NULL (overflow guard). */
    {
        myc_result res;
        myc_result_init(&res);
        CHECK(myc_result_arena_dup(&res, "abc", (size_t)-1) == NULL,
              "arena_dup SIZE_MAX -> NULL (n+1 overflow guard)");
        CHECK(myc_result_arena_dup(&res, "abc", (size_t)-10) == NULL,
              "arena_dup SIZE_MAX-10 -> NULL (alokasi raksasa gagal)");
        myc_result_free(&res);
    }

    /* T2: source > 1 MiB -> MC_ERROR/INPUT_TOO_LARGE, tanpa crash. */
    {
        size_t big = (size_t)MYC_MAX_CODE_BYTES + 1;
        char  *src = (char *)malloc(big);
        if (src) {
            myc_request req;
            myc_result  res;
            memset(src, 'x', big);   /* tanpa NUL: source_len eksplisit,
                                         validasi harus INPUT_TOO_LARGE */
            myc_request_init(&req);
            req.source = src;
            req.source_len = big;
            myc_result_init(&res);
            myc_run(&req, &res);
            CHECK(res.verdict == MC_ERROR && res.err == MYC_ERR_INPUT_TOO_LARGE,
                  "source > 1MiB -> MC_ERROR/INPUT_TOO_LARGE (verdict=%d err=%d)",
                  (int)res.verdict, (int)res.err);
            myc_result_free(&res);
            free(src);
        } else {
            fprintf(stderr, "[FAIL] T2: alokasi source 1MiB+1 gagal\n");
            g_fail++;
        }
    }

    /* T3: NUL di source -> MC_ERROR/NUL_IN_INPUT. */
    {
        static const char src[] = "int main(void){return 0;}\0evil";
        myc_request req;
        myc_result  res;
        myc_request_init(&req);
        req.source = src;
        req.source_len = sizeof(src);   /* termasuk NUL + trailing */
        myc_result_init(&res);
        myc_run(&req, &res);
        CHECK(res.verdict == MC_ERROR && res.err == MYC_ERR_NUL_IN_INPUT,
              "NUL di source -> MC_ERROR/NUL_IN_INPUT (verdict=%d err=%d)",
              (int)res.verdict, (int)res.err);
        myc_result_free(&res);
    }

    /* T4: request tanpa source & file_path -> MC_ERROR/INVALID_REQUEST. */
    {
        myc_request req;
        myc_result  res;
        myc_request_init(&req);
        myc_result_init(&res);
        myc_run(&req, &res);
        CHECK(res.verdict == MC_ERROR && res.err == MYC_ERR_INVALID_REQUEST,
              "request kosong -> MC_ERROR/INVALID_REQUEST (verdict=%d err=%d)",
              (int)res.verdict, (int)res.err);
        myc_result_free(&res);
    }

    /* T5: kontrol -- source valid kecil -> MC_OK (pipeline hidup). */
    {
        static const char src[] = "int main(void){return 0;}\n";
        myc_request req;
        myc_result  res;
        myc_request_init(&req);
        req.source = src;
        req.source_len = strlen(src);
        req.run_lint = 1;
        myc_result_init(&res);
        myc_run(&req, &res);
        CHECK(res.verdict == MC_OK, "kontrol: source kecil -> MC_OK (verdict=%d)",
              (int)res.verdict);
        myc_result_free(&res);
    }

    printf(g_fail ? "oom_guards: FAIL (%d)\n" : "oom_guards: OK (guard OOM/overflow)\n",
           g_fail);
    return g_fail ? 1 : 0;
}
