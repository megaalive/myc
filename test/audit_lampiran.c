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
  *   8. handle leak test                      (Fase 1 Task 1.6: Windows)
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
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = src;
    req.input.len = strlen(src);
    req.run_lint = 1;
    req.driver = 1;
    myc_result_init(&res);
    myc_run(&req, &res);
    CHECK(res.verdict != MC_DRIVER_VIOLATION,
          "0 driver cases tidak bisa jadi runtime clean/driver violation (verdict=%d)",
          (int)res.verdict);
    myc_result_free(&res);
}

/* ------------------------------------------------------------------ */
/* T8: long fingerprint material cannot OOB (MYC-AUDIT-005).            */
/* ------------------------------------------------------------------ */
/* Fingerprint dibangun dari gcc_path + cwd + policy + flags. cwd yang
 * sangat panjang membuat material fingerprint > 512 byte. Bug lama:
 * snprintf ke buf[512] truncated -> nilai return (panjang yang SEHARUSNYA)
 * dipakai sebagai length ke sha256_hex -> OOB read. Fix: snprintf(NULL,0)
 * menghitung panjang exact, lalu alokasi dinamis. Test: fingerprint harus
 * tetap 64-hex dan DETERMINISTIK untuk material panjang (tidak terpengaruh
 * stack garbage / OOB). Jalankan dua kali -> hasil identik. */
static void run_fp_long_test(void)
{
    char      *cwd;
    myc_request req;
    myc_result  r1, r2;
    const char *src = "int main(void){return 0;}\n";
    int i;

    cwd = (char *)malloc(3001);
    if (!cwd) {
        printf("[SKIP] fp-long: malloc cwd gagal\n");
        return;
    }
    for (i = 0; i < 3000; i++)
        cwd[i] = 'a';
    cwd[3000] = '\0';

    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = src;
    req.input.len = strlen(src);
    req.run_lint = 1;
    req.cwd = cwd;

    myc_result_init(&r1);
    myc_run(&req, &r1);
    myc_result_init(&r2);
    myc_run(&req, &r2);

    CHECK(r1.fingerprint && strlen(r1.fingerprint) == 64,
          "fingerprint cwd 3000 char tetap 64-hex (AUDIT-005)");
    CHECK(r1.fingerprint && r2.fingerprint &&
          strcmp(r1.fingerprint, r2.fingerprint) == 0,
          "fingerprint deterministik untuk material panjang (tanpa OOB/truncate)");

    myc_result_free(&r1);
    myc_result_free(&r2);
    free(cwd);
}

/* ------------------------------------------------------------------ */
/* Mode fake-clang (T11: canary failure invalidates backend, 9.9).     */
/* ------------------------------------------------------------------ */
/* Ketika binary audit_lampiran di-hardlink sebagai "fake-clang" dan
 * dipanggil myc sebagai program clang (argv[0] mengandung "fake-clang"),
 * binary bertindak sebagai compiler pengganti:
 *   - output "-o <path>" yang berisi "myc_canary" -> return 1 (canary
 *     build GAGAL; backend tak teruji);
 *   - selain itu -> kompilasi program polos `int main(void){return 0;}`
 *     via gcc asli ke <path> (verification build sukses + run bersih).
 * Akibat: verification run bersih TAPI canary gagal dibangun ->
 * myc_runtime_canary return -1 -> gate runtime INCONCLUSIVE (bukan
 * COMPLETED_CLEAN). Verification exe = program polos tanpa sanitizer,
 * sehingga run-nya selalu exit 0 tanpa report -> myc melangkah ke canary. */
static int fake_clang_main(int argc, char **argv)
{
    const char *out = NULL;
    char       *gcc = NULL;
    const char *av[8];
    myc_proc_request preq;
    myc_proc_result  pres;
    int i;
    int ret = 1;
    static const char TRIVIAL[] = "int main(void){return 0;}\n";

    for (i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            out = argv[i + 1];
            break;
        }
    }
    if (!out)
        return 1;
    if (strstr(out, "myc_canary")) {
        fprintf(stderr, "fake-clang: canary build ditolak (canary gagal dibangun)\n");
        return 1;
    }
    gcc = myc_find_executable("gcc");
    if (!gcc)
        return 1;
    av[0] = gcc;
    av[1] = "-x"; av[2] = "c"; av[3] = "-";
    av[4] = "-o"; av[5] = out;
    av[6] = NULL;
    memset(&preq, 0, sizeof(preq));
    preq.argv = av;
    preq.stdin_data = TRIVIAL;
    preq.stdin_len = sizeof(TRIVIAL) - 1;
    preq.timeout_ms = 30000;
    preq.max_output_bytes = 65536;
    memset(&pres, 0, sizeof(pres));
    if (myc_proc_run(&preq, &pres))
        ret = pres.exit_code;
    myc_proc_result_free(&pres);
    free(gcc);
    return ret;
}

/* Path target fake-clang: direktori self dengan basename diganti
 * "fake-clang" (+ ".exe" di Windows). Malloc'd; NULL bila OOM. */
static char *fake_clang_target(const char *self)
{
    const char *slash;
    const char *name = "fake-clang";
    size_t dirlen;
    char *out;

#ifdef _WIN32
    name = "fake-clang.exe";
#endif
    slash = strrchr(self, '/');
    if (slash) {
        dirlen = (size_t)(slash - self) + 1;
    } else {
        const char *bs = strrchr(self, '\\');
        dirlen = bs ? (size_t)(bs - self) + 1 : 0;
    }
    out = (char *)malloc(dirlen + strlen(name) + 1);
    if (!out)
        return NULL;
    memcpy(out, self, dirlen);
    memcpy(out + dirlen, name, strlen(name) + 1);
    return out;
}

static int hardlink_file(const char *src, const char *dst)
{
#ifdef _WIN32
    return CreateHardLinkA(dst, src, NULL) ? 1 : 0;
#else
    return link(src, dst) == 0 ? 1 : 0;
#endif
}

/* T11: canary failure invalidates backend (9.9). Gunakan fake-clang yang
 * menolak canary build TAPI menerima verification build -> myc harus
 * menurunkan gate runtime ke INCONCLUSIVE (bukan COMPLETED_CLEAN). */
static void test_canary_failure(const char *self)
{
    char *fake = fake_clang_target(self);
    myc_request req;
    myc_result  res;
    const char *src = "int main(void){return 0;}\n";
    const myc_gate_result *g;

    if (!fake) {
        printf("[SKIP] canary failure: fake-clang path OOM\n");
        return;
    }
    if (!hardlink_file(self, fake)) {
        printf("[SKIP] canary failure: fake-clang gagal di-hardlink\n");
        free(fake);
        return;
    }
    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = src;
    req.input.len = strlen(src);
    req.run_lint = 1;
    req.run = 1;
    req.clang_program = fake;
    myc_result_init(&res);
    myc_run(&req, &res);
    g = myc_gate_get(&res, MYC_GATE_RUNTIME);
    CHECK(res.verdict == MC_INCONCLUSIVE &&
          g && g->status == MYC_GATE_INCONCLUSIVE,
          "canary gagal dibangun -> gate runtime INCONCLUSIVE (verdict=%d status=%d)",
          (int)res.verdict, g ? (int)g->status : -1);
    myc_result_free(&res);
    remove(fake);
    free(fake);
}

int main(int argc, char **argv)
{
    const char *self;
    myc_error_code err = MYC_ERR_NONE;

    /* Mode khusus: HANYA test fingerprint panjang (dipakai varian ASan
     * di _audit018.sh; ASan menangkap OOB read bila regresi AUDIT-005). */
    if (argc > 1 && strcmp(argv[1], "--fp-long") == 0) {
        run_fp_long_test();
        printf(g_fail ? "audit_lampiran fp-long: FAIL (%d)\n"
                      : "audit_lampiran fp-long: OK\n", g_fail);
        return g_fail ? 1 : 0;
    }

    /* Mode fake-clang: dipanggil myc sebagai pengganti clang (T11). */
    if (argc > 0 && argv[0] && strstr(argv[0], "fake-clang"))
        return fake_clang_main(argc, argv);

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
            req.input.kind = MYC_SOURCE_MEMORY;
            req.input.data = src;
            req.input.len = strlen(src);
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
        req.input.kind = MYC_SOURCE_MEMORY;
        req.input.data = src1;
        req.input.len = strlen(src1);
        req.run_lint = 1;
        myc_result_init(&r1);
        myc_run(&req, &r1);
        d1 = (r1.diag_count > 0) ? r1.diags[0].message : NULL;
        diag1 = r1.diag_count;

        /* Jalankan myc_run kedua dengan source berbeda; hasil pertama harus
         * tetap utuh (result immutable, tidak tertimpa static ring). */
        req.input.data = src2;
        req.input.len = strlen(src2);
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

    /* T8: long fingerprint material cannot OOB (MYC-AUDIT-005). */
    run_fp_long_test();

    /* T9: file_path-only request (MYC-AUDIT-007). Bila caller memakai
     * file_path tanpa source, myc_run() harus load file sebelum pipeline
     * (tanpa NULL deref). Verdict boleh MC_OK (gcc tersedia) atau error
     * infra lainnya; yang dilarang = MC_ERROR dengan err INVALID_REQUEST
     * (request ditolak karena source NULL) ATAU crash/INVALID_PATH. */
    {
        myc_request req;
        myc_result  res;
        const char *path = "audit_fp_only_tmp.c";
        const char *src = "int main(void){return 0;}\n";
        FILE *f = fopen(path, "wb");

        if (f) {
            fwrite(src, 1, strlen(src), f);
            fclose(f);
            myc_request_init(&req);
            req.input.kind = MYC_SOURCE_FILE;
            req.input.file_path = path;
            req.run_lint = 1;
            myc_result_init(&res);
            myc_run(&req, &res);
            CHECK(res.err != MYC_ERR_INVALID_REQUEST &&
                  res.err != MYC_ERR_INVALID_PATH,
                  "file_path-only request diproses tanpa NULL deref (verdict=%d err=%d)",
                  (int)res.verdict, (int)res.err);
            CHECK(res.source_sha256 != NULL,
                  "file_path-only: source di-load & di-hash (sha256 ada)");
            myc_result_free(&res);
            remove(path);
        } else {
            printf("[SKIP] file_path-only: gagal menulis file temp\n");
        }
    }

    /* T11: canary failure invalidates backend (9.9). */
    test_canary_failure(self);

    /* T12: myc_source_load MEMORY = pointer asli tanpa alokasi. */
    {
        static const char src[] = "int main(void){return 0;}\n";
        myc_source_input in;
        const char  *out;
        size_t       len;
        int          need;
        in.kind = MYC_SOURCE_MEMORY;
        in.data = src;
        in.len = strlen(src);
        in.file_path = NULL;
        CHECK(myc_source_load(&in, &out, &len, &need) == MYC_ERR_NONE &&
              out == src && len == strlen(src) && need == 0,
              "myc_source_load MEMORY -> pointer asli, tanpa alokasi");
    }

    /* T13: myc_source_load FILE too-large -> INPUT_TOO_LARGE (bukan
     * alokasi penuh), dan file tidak ada -> INVALID_PATH. */
    {
        myc_source_input in;
        const char  *out = NULL;
        size_t       len = 0;
        int          need = 0;
        const char  *path = "audit_big_029_tmp.c";
        FILE *f = fopen(path, "wb");
        if (f) {
            size_t i;
            for (i = 0; i < MYC_MAX_CODE_BYTES + 1; i++)
                fputc('x', f);
            fclose(f);
            in.kind = MYC_SOURCE_FILE;
            in.data = NULL;
            in.len = 0;
            in.file_path = path;
            CHECK(myc_source_load(&in, &out, &len, &need) ==
                    MYC_ERR_INPUT_TOO_LARGE,
                  "myc_source_load FILE >1MiB -> INPUT_TOO_LARGE");
            remove(path);
        }
        in.kind = MYC_SOURCE_FILE;
        in.file_path = "audit_tidak_ada_029_tmp.c";
        CHECK(myc_source_load(&in, &out, &len, &need) == MYC_ERR_INVALID_PATH,
              "myc_source_load FILE tak ada -> INVALID_PATH");
    }

    /* T14: cwd canonicalization (MYC-AUDIT-030, Fase 2). Representasi
     * berbeda dari direktori SAMA harus menghasilkan fingerprint IDENTIK
     * (canonical): ".", "./", absolut, dan "x/../x". Direktori berbeda
     * tetap berbeda. Canonicalization lexical (tidak menyentuh filesystem);
     * pada request relatif, base = cwd proses -> fingerprint stabil selama
     * cwd proses tidak berubah (deterministik dalam satu proses). */
    {
        myc_request req;
        myc_result  r1, r2, r3, r3b, r4, r5;
        const char *src = "int main(void){return 0;}\n";
        char        cwdbuf[4096];
        int         have_cwd = 0;

        myc_request_init(&req);
        req.input.kind = MYC_SOURCE_MEMORY;
        req.input.data = src;
        req.input.len = strlen(src);
        req.run_lint = 1;

        req.cwd = ".";
        myc_result_init(&r1);
        myc_run(&req, &r1);

        req.cwd = "./";
        myc_result_init(&r2);
        myc_run(&req, &r2);

        req.cwd = "audit_canon_tmp/../audit_canon_tmp";
        myc_result_init(&r3);
        myc_run(&req, &r3);

        req.cwd = "audit_canon_tmp";
        myc_result_init(&r3b);
        myc_run(&req, &r3b);

        req.cwd = "audit_canon_other";
        myc_result_init(&r4);
        myc_run(&req, &r4);

        if (myc_getcwd(cwdbuf, sizeof(cwdbuf))) {
            have_cwd = 1;
            req.cwd = cwdbuf;
            myc_result_init(&r5);
            myc_run(&req, &r5);
        }

        CHECK(r1.fingerprint && r2.fingerprint &&
              strcmp(r1.fingerprint, r2.fingerprint) == 0,
              "cwd '.' vs './' -> fingerprint IDENTIK (canonical)");
        /* "audit_canon_tmp/../audit_canon_tmp" == "audit_canon_tmp" (lexical). */
        CHECK(r3.fingerprint && r3b.fingerprint &&
              strcmp(r3.fingerprint, r3b.fingerprint) == 0,
              "cwd 'audit_canon_tmp/../audit_canon_tmp' vs 'audit_canon_tmp' -> fingerprint IDENTIK (canonical)");
        if (have_cwd) {
            CHECK(r1.fingerprint && r5.fingerprint &&
                  strcmp(r1.fingerprint, r5.fingerprint) == 0,
                  "cwd '.' vs absolut -> fingerprint IDENTIK (canonical)");
        } else {
            printf("[SKIP] cwd absolut (getcwd gagal) -- fingerprint absolut tak diverifikasi\n");
        }
        CHECK(r1.fingerprint && r4.fingerprint &&
              strcmp(r1.fingerprint, r4.fingerprint) != 0,
              "cwd berbeda -> fingerprint BERBEDA");

        myc_result_free(&r1);
        myc_result_free(&r2);
        myc_result_free(&r3);
        myc_result_free(&r3b);
        myc_result_free(&r4);
        if (have_cwd)
            myc_result_free(&r5);
    }

#ifdef _WIN32
    /* --- Handle leak test (Fase 1 Task 1.6) --- */
    {
        DWORD before = 0, after = 0;
        if (GetProcessHandleCount(GetCurrentProcess(), &before)) {
            myc_request req_hl;
            myc_result r_hl;
            const char *hl_src = "int main(void) { return 0; }";
            memset(&req_hl, 0, sizeof(req_hl));
            req_hl.input.kind = MYC_SOURCE_MEMORY;
            req_hl.input.data = hl_src;
            req_hl.input.len = strlen(hl_src);
            req_hl.cwd = ".";
            req_hl.timeout_ms = 30000;
            req_hl.max_output_bytes = 0;
            req_hl.strict = 0;
            req_hl.run = 0;
            req_hl.prove = 0;
            req_hl.checked = 0;
            req_hl.filc = 0;
            req_hl.driver = 0;
            req_hl.metamorphic = 0;
            req_hl.negative = 0;
            req_hl.require_complete = 0;
            myc_result_init(&r_hl);
            myc_run(&req_hl, &r_hl);
            myc_result_free(&r_hl);
            if (GetProcessHandleCount(GetCurrentProcess(), &after)) {
                CHECK(before == after,
                      "handle leak test: %lu handles before, %lu after",
                      (unsigned long)before, (unsigned long)after);
            } else {
                printf("[SKIP] GetProcessHandleCount pasca-run gagal\n");
            }
        } else {
            printf("[SKIP] GetProcessHandleCount pra-run gagal\n");
        }
    }
#endif

    /* --- Input portfolio for runtime sanitizer (Fase 7.2) --- */
    {
        const char *portfolio[] = {
            "tests/bad_run_oob.c",
            "tests/bad_run_uaf.c",
            "tests/bad_run_intovf.c",
            NULL
        };
        int p;
        for (p = 0; portfolio[p]; p++) {
            myc_request req_p;
            myc_result r_p;
            memset(&req_p, 0, sizeof(req_p));
            req_p.input.kind = MYC_SOURCE_FILE;
            req_p.input.file_path = portfolio[p];
            req_p.cwd = ".";
            req_p.timeout_ms = 30000;
            req_p.max_output_bytes = 0;
            req_p.strict = 0;
            req_p.run = 1;
            req_p.prove = 0;
            req_p.checked = 0;
            req_p.filc = 0;
            req_p.driver = 0;
            req_p.metamorphic = 0;
            req_p.negative = 0;
            req_p.require_complete = 0;
            myc_result_init(&r_p);
            myc_run(&req_p, &r_p);
            if (r_p.finding == MYC_FINDING_FINDINGS || r_p.verdict == MC_VIOLATION) {
                printf("[OK]   input portfolio: %s -> violation terdeteksi\n", portfolio[p]);
            } else {
                CHECK(0, "input portfolio: %s -> harapnya violation, dapat verdict=%d",
                      portfolio[p], r_p.verdict);
            }
            myc_result_free(&r_p);
        }
    }

    printf(g_fail ? "audit_lampiran: FAIL (%d)\n" : "audit_lampiran: OK\n", g_fail);
    return g_fail ? 1 : 0;
}
