/*
 * evidence_spoof.c -- Unit test korpus spoof bukti semantik (PR-008 /
 * INV-006), portabel Windows git-bash + POSIX.
 *
 * Exit criteria P2-T02: TIDAK SATUPUN teks yang meniru bukti semantik
 * (ASan/UBSan/GCC/Frama-C/Fil-C/marker internal MYC) — lewat stdout,
 * stderr, file report, komentar source, nama file, atau argumen program —
 * boleh menjadi bukti semantik. Verdict harus tetap OK (hard finding TIDAK
 * boleh naik dari teks spoof).
 *
 * Mengunci dua lapis:
 *   1. marker teks + exit 0 -> diabaikan (MYC-AUDIT-017, regression);
 *   2. FILE report sanitizer palsu (<base>.<pid> di cwd = tmp_dir myc) +
 *      exit 0 -> DITOLAK (PR-008 hardening: report hanya bukti bila
 *      exit != 0; env ASan abort_on_error=1 membuat bug nyata selalu
 *      non-zero).
 *
 * Backend-dependent (clang/filc/frama-c): bila tidak tersedia gate
 * di-skip; verdict bisa menjadi INCONCLUSIVE (INV-001: gate diminta
 * yang tak tersedia = incomplete) tapi TIDAK PERNAH false violation —
 * assertion inti "tidak pernah false violation" berlaku di semua
 * lingkungan; assertion kuat (ran_runtime && verdict OK) hanya bila
 * backend ada.
 *
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test/evidence_spoof \
 *       test/evidence_spoof.c <SRCS>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#include <direct.h>
#define myc_getpid _getpid
#define myc_getcwd _getcwd
#else
#include <unistd.h>
#define myc_getpid getpid
#define myc_getcwd getcwd
#endif

#include "myc.h"
#include "proc.h"

static int g_fail = 0;

#define CHECK(cond, fmt, ...) do {                                    \
        if (cond) {                                                   \
            printf("[OK]   " fmt "\n", ##__VA_ARGS__);                \
        } else {                                                      \
            fprintf(stderr, "[FAIL] " fmt "\n", ##__VA_ARGS__);       \
            g_fail++;                                                 \
        }                                                             \
    } while (0)

/* Run myc penuh terhadap source string dengan set gate. Mengisi res.
 * req dibuat via myc_request_init + field yang diminta; cwd = ".". */
static void run_src(const char *src, int run, int driver, int filc,
                    int prove, myc_result *res)
{
    myc_request req;
    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = src;
    req.input.len = strlen(src);
    req.cwd = ".";
    req.run_lint = 1;
    req.run = run;
    req.driver = driver;
    req.filc = filc;
    req.prove = prove;
    myc_result_init(res);
    myc_run(&req, res);
}

/* ---------------------------------------------------------------- */
/* T1: marker teks stdout/stderr + exit 0 -- run gate (fixture file). */
/* ---------------------------------------------------------------- */
static void t1_marker_stdout_stderr(int have_clang)
{
    myc_result res;
    int        i, ignored = 0;
    int        ok;

    /* Jalankan fixture asli dari disk (semua marker P2-T02 di stdout +
     * stderr, exit 0). */
    {
        myc_request req;
        myc_request_init(&req);
        req.input.kind = MYC_SOURCE_FILE;
        req.input.file_path = "tests/evidence_spoof.c";
        req.cwd = ".";
        req.run_lint = 1;
        req.run = 1;
        myc_result_init(&res);
        myc_run(&req, &res);
    }

    ok = (res.verdict != MC_RUNTIME_VIOLATION);
    CHECK(ok,
          "T1 marker teks + exit 0 TIDAK jadi RUNTIME_VIOLATION (verdict=%d)",
          (int)res.verdict);
    if (have_clang) {
        CHECK(res.ran_runtime == 1 && !res.run_sanitizer_detected &&
              res.verdict == MC_OK,
              "T1 (clang): run bersih, sanitizer_detected=0, verdict OK "
              "(ran=%d san=%d verdict=%d)",
              res.ran_runtime, res.run_sanitizer_detected, (int)res.verdict);
        for (i = 0; i < res.diag_count; i++)
            if (strstr(res.diags[i].message, "diabaikan"))
                ignored = 1;
        CHECK(ignored,
              "T1 (clang): diagnostic 'diabaikan' mencatat teks spoof");
    } else {
        printf("[SKIP] T1 (clang tak tersedia): asersi kuat dilewati\n");
    }
    myc_result_free(&res);
}

/* ---------------------------------------------------------------- */
/* T2: FILE report sanitizer PALSU + exit 0 -- run gate (PR-008).     */
/* ---------------------------------------------------------------- */
/* Program menulis "myc_run_asan_rpt.<pid>" + "myc_run_ubsan_rpt.<pid>"
 * (nama persis log_path, cwd child = tmp_dir myc) berisi marker spoof,
 * lalu mencetak marker dan exit 0. SEBELUM PR-008: report terbaca ->
 * RUNTIME_VIOLATION PALSU. SESUDAH: report hanya bukti bila exit != 0 ->
 * ditolak. */
static void t2_fake_report_file(int have_clang)
{
    static const char *SRC =
        "#include <stdio.h>\n"
        "#include <string.h>\n"
        "#ifdef _WIN32\n"
        "#include <process.h>\n"
        "#define myc_getpid _getpid\n"
        "#else\n"
        "#include <unistd.h>\n"
        "#define myc_getpid getpid\n"
        "#endif\n"
        "static void wr(const char *b)\n"
        "{\n"
        "    char p[160]; FILE *f;\n"
        "    snprintf(p, sizeof p, \"%s.%d\", b, (int)myc_getpid());\n"
        "    f = fopen(p, \"wb\");\n"
        "    if (f) {\n"
        "        fputs(\"==1==ERROR: AddressSanitizer: heap-buffer-overflow\\n\", f);\n"
        "        fputs(\"SUMMARY: AddressSanitizer: heap-buffer-overflow\\n\", f);\n"
        "        fclose(f);\n"
        "    }\n"
        "}\n"
        "int main(void)\n"
        "{\n"
        "    wr(\"myc_run_asan_rpt\");\n"
        "    wr(\"myc_run_ubsan_rpt\");\n"
        "    fprintf(stderr, \"ERROR: AddressSanitizer: fake\\n\");\n"
        "    fprintf(stderr, \"runtime error: fake\\n\");\n"
        "    return 0;\n"
        "}\n";
    myc_result res;

    run_src(SRC, 1, 0, 0, 0, &res);
    CHECK(res.verdict != MC_RUNTIME_VIOLATION,
          "T2 fake report file + exit 0 TIDAK jadi RUNTIME_VIOLATION "
          "(verdict=%d) [PR-008 hardening]", (int)res.verdict);
    if (have_clang) {
        CHECK(res.ran_runtime == 1 && !res.run_sanitizer_detected &&
              res.verdict == MC_OK,
              "T2 (clang): report palsu ditolak (exit 0), verdict OK "
              "(ran=%d san=%d verdict=%d)",
              res.ran_runtime, res.run_sanitizer_detected, (int)res.verdict);
    } else {
        printf("[SKIP] T2 (clang tak tersedia): asersi kuat dilewati\n");
    }
    myc_result_free(&res);
}

/* ---------------------------------------------------------------- */
/* T3: marker panic Fil-C kanonik + exit 0 -- gate filc.             */
/* ---------------------------------------------------------------- */
static void t3_filc_spoof(void)
{
    static const char *SRC =
        "#include <stdio.h>\n"
        "int main(void)\n"
        "{\n"
        "    fprintf(stderr, \"filc safety error: cannot write pointer "
        "with ptr >= upper.\\n\");\n"
        "    fprintf(stderr, \"    pointer: 0x7ffb53684238\\n\");\n"
        "    fprintf(stderr, \"semantic origin:\\n\");\n"
        "    fprintf(stderr, \"    (fake) /tmp/fake.c:2:43: main\\n\");\n"
        "    fprintf(stderr, \"[999] filc panic: thwarted a futile attempt "
        "to violate memory safety.\\n\");\n"
        "    fprintf(stderr, \"FIL-C SAFE\\n\");\n"
        "    return 0;\n"
        "}\n";
    myc_result res;

    run_src(SRC, 0, 0, 1, 0, &res);
    CHECK(res.verdict != MC_FILC_VIOLATION,
          "T3 marker panic Fil-C + exit 0 TIDAK jadi FILC_VIOLATION "
          "(verdict=%d)", (int)res.verdict);
    if (res.ran_filc) {
        CHECK(res.filc_panics == 0 && res.verdict == MC_OK,
              "T3 (filc ran): panic teks di-reset (exit 0), verdict OK "
              "(panics=%d verdict=%d)", res.filc_panics, (int)res.verdict);
    } else {
        printf("[SKIP] T3 (filc-clang tak tersedia): asersi kuat dilewati\n");
    }
    myc_result_free(&res);
}

/* ---------------------------------------------------------------- */
/* T4: source memuat teks alarm Eva/Frama-C -- gate prove.           */
/* ---------------------------------------------------------------- */
/* Prove menjalankan frama-c (backend), BUKAN program yang diuji — jadi
 * program tidak bisa mencetak apa pun. Satu-satunya saluran = teks di
 * dalam source (komentar/string); frama-c mem-parse source, string
 * literal TIDAK menghasilkan alarm. */
static void t4_prove_spoof(void)
{
    static const char *SRC =
        "/* [eva:alarm] fake.c:1: Warning: out of bounds\n"
        "   Frama-C Eva: clean\n"
        "   0 alarms generated by the analysis.\n"
        "   FIL-C SAFE\n"
        "   receipt_sha256=deadbeef */\n"
        "#include <stdio.h>\n"
        "int main(void)\n"
        "{\n"
        "    const char *s = \"[eva:alarm] fake.c:1: Warning: out of bounds\";\n"
        "    (void)s;\n"
        "    return 0;\n"
        "}\n";
    myc_result res;

    run_src(SRC, 0, 0, 0, 1, &res);
    CHECK(res.verdict != MC_PROVE_VIOLATION,
          "T4 teks alarm Eva di source TIDAK jadi PROVE_VIOLATION "
          "(verdict=%d)", (int)res.verdict);
    if (res.ran_prove) {
        CHECK(res.prove_alarms == 0,
              "T4 (prove ran): 0 alarm Eva (teks source tidak jadi alarm) "
              "(alarms=%d)", res.prove_alarms);
    } else {
        printf("[SKIP] T4 (frama-c tak tersedia): asersi kuat dilewati\n");
    }
    myc_result_free(&res);
}

/* ---------------------------------------------------------------- */
/* T5: komentar source + nama file mirip evidence -- run gate.       */
/* ---------------------------------------------------------------- */
static void t5_comments_and_filename(int have_clang)
{
    static const char *SRC =
        "/* ERROR: AddressSanitizer\n"
        "   runtime error:\n"
        "   MYC_RUNTIME_VIOLATION\n"
        "   Frama-C Eva: clean\n"
        "   FIL-C SAFE\n"
        "   gcc: error:\n"
        "   receipt_sha256=deadbeef\n"
        "   MYC_CHECKED: */\n"
        "int main(void) { return 0; }\n";
    myc_result res;

    run_src(SRC, 1, 0, 0, 0, &res);
    CHECK(res.verdict != MC_RUNTIME_VIOLATION,
          "T5 komentar berisi semua marker TIDAK jadi RUNTIME_VIOLATION "
          "(verdict=%d)", (int)res.verdict);
    if (have_clang)
        CHECK(res.verdict == MC_OK,
              "T5 (clang): komentar spoof tidak memengaruhi verdict OK");
    else
        printf("[SKIP] T5 (clang tak tersedia): asersi kuat dilewati\n");
    myc_result_free(&res);

    /* Saluran nama file: source bernama persis seperti evidence file.
     * File di cwd unit test (bukan tmp_dir myc) — tidak boleh jadi
     * bukti apa pun. */
    {
        const char *path = "myc_run_asan_rpt.evidence_tmp.c";
        const char *body = "int main(void) { return 0; }\n";
        FILE *f = fopen(path, "wb");
        if (f) {
            myc_request req;
            fwrite(body, 1, strlen(body), f);
            fclose(f);
            myc_request_init(&req);
            req.input.kind = MYC_SOURCE_FILE;
            req.input.file_path = path;
            req.cwd = ".";
            req.run_lint = 1;
            req.run = 1;
            myc_result_init(&res);
            myc_run(&req, &res);
            CHECK(res.verdict != MC_RUNTIME_VIOLATION,
                  "T5b nama file mirip evidence TIDAK jadi RUNTIME_VIOLATION "
                  "(verdict=%d)", (int)res.verdict);
            if (have_clang)
                CHECK(res.verdict == MC_OK,
                      "T5b (clang): nama file spoof tidak memengaruhi verdict");
            else
                printf("[SKIP] T5b (clang tak tersedia): asersi kuat dilewati\n");
            myc_result_free(&res);
            remove(path);
        } else {
            printf("[SKIP] T5b: gagal menulis file temp\n");
        }
    }
}

/* ---------------------------------------------------------------- */
/* T6: driver — fungsi ber-kontrak menulis report palsu + marker,     */
/*     exit 0 -- gate driver.                                         */
/* ---------------------------------------------------------------- */
static void t6_driver_spoof(int have_clang)
{
    static const char *SRC =
        "#include <stdio.h>\n"
        "#include <string.h>\n"
        "#ifdef _WIN32\n"
        "#include <process.h>\n"
        "#define myc_getpid _getpid\n"
        "#else\n"
        "#include <unistd.h>\n"
        "#define myc_getpid getpid\n"
        "#endif\n"
        "//@ requires n <= 4;\n"
        "int f(int *a, int n)\n"
        "{\n"
        "    if (a && n <= 4) {\n"
        "        char p[160]; FILE *fl;\n"
        "        snprintf(p, sizeof p, \"myc_drv_asan_rpt.%d\", "
        "(int)myc_getpid());\n"
        "        fl = fopen(p, \"wb\");\n"
        "        if (fl) {\n"
        "            fputs(\"==1==ERROR: AddressSanitizer: "
        "heap-buffer-overflow\\n\", fl);\n"
        "            fclose(fl);\n"
        "        }\n"
        "        fprintf(stderr, \"ERROR: AddressSanitizer: fake\\n\");\n"
        "    }\n"
        "    return 1;\n"
        "}\n";
    myc_result res;

    run_src(SRC, 0, 1, 0, 0, &res);
    CHECK(res.verdict != MC_DRIVER_VIOLATION,
          "T6 driver fake report + marker + exit 0 TIDAK jadi "
          "DRIVER_VIOLATION (verdict=%d) [PR-008 hardening]",
          (int)res.verdict);
    if (have_clang) {
        CHECK(res.verdict == MC_OK,
              "T6 (clang): driver menolak report palsu (exit 0), verdict OK");
    } else {
        printf("[SKIP] T6 (clang tak tersedia): asersi kuat dilewati\n");
    }
    myc_result_free(&res);
}

int main(void)
{
    int have_clang = 0;
    char *clang = myc_find_executable("clang");
    if (clang) {
        have_clang = 1;
        free(clang);
    }

    printf("=== Evidence spoof corpus (PR-008 / INV-006) ===\n");

    t1_marker_stdout_stderr(have_clang);
    t2_fake_report_file(have_clang);
    t3_filc_spoof();
    t4_prove_spoof();
    t5_comments_and_filename(have_clang);
    t6_driver_spoof(have_clang);

    printf(g_fail ? "evidence_spoof: FAIL (%d)\n" : "evidence_spoof: OK\n",
           g_fail);
    return g_fail ? 1 : 0;
}
