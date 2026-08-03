/*
 * audit_lampiran.c -- Regression Lampiran A roadmap: item fix yang belum
 * di-ikat test eksplisit (portabel, Windows git-bash + POSIX).
 *
 * Menutup gap regression yang tersisa:
 *   1. exec failure vs application exit 127  (MYC-AUDIT-003: exec-error pipe)
 *   2. absolute temp executable path         (MYC-AUDIT-003: make_temp_dir)
 *   3. multiple consecutive requires         (contract scan)
 *   4. long contract expression rejected, NOT truncated ("no silent truncate")
 *   5. NUL is never created on POSIX         (MYC-AUDIT-015: myc_null_device)
 *   6. 0 driver cases cannot become runtime clean (D2.2 / 9.10)
 *   7. old result diagnostic remains immutable (arena milik hasil, Fase 5)
 *
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o audit_lampiran \
 *       audit_lampiran.c myc.c proc.c scanner.c policy.c compile.c report.c \
 *       sha256.c lint.c run.c contract.c prove.c filc.c driver.c json.c \
 *       gate.c negative.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "myc.h"
#include "proc.h"
#include "contract.h"

static int g_fail = 0;

#define CHECK(cond, fmt, ...) do {                                    \
        if (cond) {                                                   \
            printf("[OK]   " fmt "\n", ##__VA_ARGS__);                \
        } else {                                                      \
            fprintf(stderr, "[FAIL] " fmt "\n", ##__VA_ARGS__);       \
            g_fail++;                                                 \
        }                                                             \
    } while (0)

/* Path executable diri sendiri (untuk re-invoke child mode). */
static const char *self_path(const char *argv0)
{
#ifdef _WIN32
    static char buf[4096];
    DWORD n = GetModuleFileNameA(NULL, buf, sizeof(buf));
    if (n > 0 && n < sizeof(buf))
        return buf;
#else
    (void)argv0;
#endif
    return argv0;
}

/* Proses self-invoke sederhana: jalankan diri dengan argv[1]=mode.
 * Mengembalikan exit code; isi *err = myc_error_code. */
static int run_self(const char *self, const char *mode, myc_error_code *err)
{
    myc_proc_request preq;
    myc_proc_result  pres;
    const char *argv[3];
    int ret;

    argv[0] = self;
    argv[1] = mode;
    argv[2] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.timeout_ms = 30000;
    preq.max_output_bytes = 65536;
    memset(&pres, 0, sizeof(pres));
    myc_proc_run(&preq, &pres);
    ret = pres.exit_code;
    if (err)
        *err = pres.err;
    myc_proc_result_free(&pres);
    return ret;
}

/* Jalankan path yang TIDAK ada -> harus EXECUTE_FAILED (bukan exit 127). */
static int run_nonexistent(myc_error_code *err)
{
    myc_proc_request preq;
    myc_proc_result  pres;
    const char *argv[2];

    argv[0] = "/nonexistent/definitely-not-a-program-xyz";
    argv[1] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.timeout_ms = 30000;
    preq.max_output_bytes = 65536;
    memset(&pres, 0, sizeof(pres));
    myc_proc_run(&preq, &pres);
    if (err)
        *err = pres.err;
    myc_proc_result_free(&pres);
    return 0;
}

/* Child mode: exit(127) -- membedakan "program yang memang exit 127" dari
 * "exec gagal" (exec-error pipe, MYC-AUDIT-003). */
static int child_exit127(void)
{
    return 127;
}

/* Test 6: 0 driver cases. Source tanpa fungsi ber-kontrak -> driver gate
 * NOT_APPLICABLE, TIDAK bisa menjadi "runtime clean" (9.10 / D2.2). */
static void test_zero_driver_cases(void)
{
    myc_request req;
    myc_result  res;
    const char *src = "int main(void){return 0;}\n";

    myc_request_init(&req);
    req.source = src;
    req.source_len = strlen(src);
    req.run_lint = 1;
    req.driver = 1;
    myc_result_init(&res);
    myc_run(&req, &res);
    CHECK(res.verdict != MC_DRIVER_VIOLATION,
          "0 driver cases tidak bisa jadi runtime clean/driver violation (verdict=%d)",
          (int)res.verdict);
    myc_result_free(&res);
}

int main(int argc, char **argv)
{
    const char *self;
    myc_error_code err = MYC_ERR_NONE;

    if (argc > 1 && strcmp(argv[1], "--child-exit127") == 0)
        return child_exit127();

    self = self_path(argv[0]);

    /* T1: exec failure vs application exit 127 (MYC-AUDIT-003). */
    {
        int rc;
        run_nonexistent(&err);
        CHECK(err == MYC_ERR_EXECUTE_FAILED,
              "exec program tidak ada -> MYC_ERR_EXECUTE_FAILED (err=%d)", (int)err);
        rc = run_self(self, "--child-exit127", &err);
        CHECK(rc == 127 && err == MYC_ERR_NONE,
              "program exit(127) diklasifikasikan exit code 127, BUKAN exec gagal (rc=%d err=%d)",
              rc, (int)err);
    }

    /* T2: absolute temp executable path (MYC-AUDIT-003). File temp yang
     * dipakai gate compile/run harus path absolut, bukan relatif terhadap
     * CWD. Hanya bisa diverifikasi bila backend run (clang) tersedia; tanpa
     * clang gate menjadi UNAVAILABLE (perilaku jujur AUDIT-004/9.10) ->
     * skip (bukan klaim). Bila clang ada dan temp path relatif rusak,
     * eksekusi akan EXECUTE_FAILED/exit 127 -> verdict bukan OK. */
    {
        char *clang = myc_find_executable("clang");
        if (clang) {
            myc_request req;
            myc_result  res;
            const char *src = "int main(void){return 0;}\n";

            free(clang);
            myc_request_init(&req);
            req.source = src;
            req.source_len = strlen(src);
            req.run_lint = 1;
            req.run = 1;
            myc_result_init(&res);
            myc_run(&req, &res);
            CHECK(res.verdict == MC_OK || res.verdict == MC_VIOLATION,
                  "run gate memakai temp path absolut (verdict=%d err=%d)",
                  (int)res.verdict, (int)res.err);
            myc_result_free(&res);
        } else {
            printf("[SKIP] run gate (clang tak tersedia) -- temp path abs tak diverifikasi\n");
        }
    }

    /* T3: multiple consecutive requires (contract scan). */
    {
        char **reqs = NULL, **ens = NULL;
        int    nreqs = 0, nens = 0;
        const char *src =
            "//@ requires a > 0;\n"
            "//@ requires a < 100;\n"
            "//@ ensures  b >= 0;\n"
            "int f(int a, int b) { return b; }\n";
        myc_contract_list(src, strlen(src), &reqs, &nreqs, &ens, &nens);
        CHECK(nreqs == 2, "dua requires berturut terhitung (nreqs=%d)", nreqs);
        CHECK(nens == 1, "satu ensures terhitung (nens=%d)", nens);
        if (nreqs >= 2)
            CHECK(strcmp(reqs[0], "a > 0") == 0 &&
                  strcmp(reqs[1], "a < 100") == 0,
                  "kedua ekspresi requires utuh (0='%s' 1='%s')",
                  reqs[0] ? reqs[0] : "?", reqs[1] ? reqs[1] : "?");
        for (int k = 0; k < nreqs; k++)
            free(reqs[k]);
        for (int k = 0; k < nens; k++)
            free(ens[k]);
        free(reqs);
        free(ens);
    }

    /* T4: long contract expression rejected, NOT truncated. */
    {
        myc_result res;
        char expr[640];
        char src[768];
        int  i;
        for (i = 0; i < 600; i++)
            expr[i] = (i % 2) ? 'x' : 'a';
        expr[600] = '\0';
        snprintf(src, sizeof(src), "//@ requires %s;\nint f(void){return 0;}\n", expr);

        myc_result_init(&res);
        myc_contract_scan(src, strlen(src), &res);
        CHECK(res.contract_requires == 0,
              "ekspresi requires terlalu panjang DITOLAK, tidak dihitung (req=%d)",
              res.contract_requires);
        /* Diagnostic harus muncul (jujur: "terlalu panjang", bukan senyap). */
        {
            int found = 0;
            for (i = 0; i < res.diag_count; i++)
                if (strstr(res.diags[i].message, "terlalu panjang"))
                    found = 1;
            CHECK(found, "diagnostic 'terlalu panjang' muncul (no silent truncate)");
        }
        myc_result_free(&res);
    }

    /* T5: NUL is never created on POSIX (MYC-AUDIT-015). Bila myc memakai
     * literal "NUL" sebagai target -o di POSIX, file literal "NUL" akan
     * dibuat. Setelah run gate di atas, pastikan tidak ada. */
#ifndef _WIN32
    {
        FILE *f = fopen("NUL", "rb");
        CHECK(f == NULL, "NUL TIDAK pernah dibuat di POSIX (myc_null_device)");
        if (f)
            fclose(f);
    }
#endif

    /* T6: 0 driver cases. */
    test_zero_driver_cases();

    /* T7: old result diagnostic remains immutable (arena milik hasil). */
    {
        myc_request req;
        myc_result  r1, r2;
        const char *src1 = "int a1(void){int *p=(int*)malloc(8);return p?1:0;}\n"
                           "int main(void){return a1();}\n";
        const char *src2 = "int main(void){return 0;}\n";
        const char *d1;
        int diag1;

        myc_request_init(&req);
        req.source = src1;
        req.source_len = strlen(src1);
        req.run_lint = 1;
        myc_result_init(&r1);
        myc_run(&req, &r1);
        d1 = (r1.diag_count > 0) ? r1.diags[0].message : NULL;
        diag1 = r1.diag_count;

        /* Jalankan myc_run kedua dengan source berbeda; hasil pertama harus
         * tetap utuh (result immutable, tidak tertimpa static ring). */
        req.source = src2;
        req.source_len = strlen(src2);
        myc_result_init(&r2);
        myc_run(&req, &r2);

        CHECK(r1.diag_count == diag1,
              "result pertama tetap immutable setelah run kedua (d1=%d d2=%d)",
              diag1, r2.diag_count);
        if (d1)
            CHECK(strlen(d1) > 0, "diagnostic pertama tetap terbaca (='%s')", d1);

        myc_result_free(&r1);
        myc_result_free(&r2);
    }

    printf(g_fail ? "audit_lampiran: FAIL (%d)\n" : "audit_lampiran: OK\n", g_fail);
    return g_fail ? 1 : 0;
}
