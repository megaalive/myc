/*
 * run.c -- Gate verification run (P6): build + eksekusi terkendali.
 *
 * Alur:
 *   1. Cari clang (PATH atau req->clang_program).
 *   2. Buat direktori temp kerja.
 *   3. Verification build: clang -x c - -std=c11 -O0 -g
 *        -fsanitize=address,undefined -fno-sanitize-recover=all -o <exe>
 *      source dikirim via stdin (tidak pernah menjadi argumen).
 *   4. Windows: salin runtime DLL ASan (dari clang -print-file-name) ke
 *      samping exe (tanpa itu exe gagal run 0xC0000135).
 *   5. Jalankan exe via myc_proc_run (Job Object + timeout).
 *   6. Deteksi laporan sanitizer (ASan/UBSan) pada stdout+stderr.
 *
 * Jujur: L3 RUNTIME hanya dinaikkan bila build sukses, eksekusi bersih
 * (exit 0), dan tidak ada marker sanitizer. Build gagal (mis. tanpa main,
 * clang tidak ditemukan, link gagal) => gate di-skip, assurance statis
 * dipertahankan, ditulis warning diagnostic.
 */
#include "run.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <direct.h>
#include <process.h>
#define myc_mkdir(path) _mkdir(path)
#define myc_rmdir(path) _rmdir(path)
#define myc_getpid() _getpid()
#define my_getcwd(buf,sz) _getcwd(buf,sz)
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define myc_mkdir(path) mkdir(path, 0700)
#define myc_rmdir(path) rmdir(path)
#define myc_getpid() getpid()
#define my_getcwd(buf,sz) getcwd(buf,sz)
#endif

#include "contract.h"
#include "gate.h"
#include "proc.h"

/* Nama runtime DLL ASan untuk target x86_64-windows-msvc. */
#define ASAN_DLL_NAME "clang_rt.asan_dynamic-x86_64.dll"

/* Marker laporan sanitizer (ASan/UBSan) pada output program. */
static const char *const SANITIZER_MARKERS[] = {
    "ERROR: AddressSanitizer",
    "SUMMARY: AddressSanitizer",
    "AddressSanitizer:",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "LeakSanitizer",
    "heap-buffer-overflow",
    "heap-use-after-free",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "use-after-poison",
    "Assertion failed",
    "MYC_CHECKED:",
    NULL
};

/* Env deterministik untuk program verification (MYC-AUDIT-017):
 * ASan/UBSan diarahkan menulis report ke FILE unik (log_path=<base>,
 * relatif terhadap cwd child = tmp_dir; ASan menambah .<pid>) — saluran
 * bukti yang TIDAK bisa dipalsukan program secara tidak sengaja (report
 * ditulis runtime sanitizer sendiri, bukan stdout/stderr program).
 * LC_ALL=C menstabilkan output lintas locale. Nama base dipilih unik per
 * fase agar tidak tabrakan antar run di tmp_dir yang sama. */
static const char *const RUN_ENV[] = {
    "ASAN_OPTIONS=log_path=myc_run_asan_rpt:abort_on_error=1:halt_on_error=1",
    "UBSAN_OPTIONS=log_path=myc_run_ubsan_rpt:halt_on_error=1:print_stacktrace=1",
    "LC_ALL=C",
    NULL
};

static const char *const CANARY_RUN_ENV[] = {
    "ASAN_OPTIONS=log_path=myc_canary_asan_rpt:abort_on_error=1:halt_on_error=1",
    "UBSAN_OPTIONS=log_path=myc_canary_ubsan_rpt:halt_on_error=1:print_stacktrace=1",
    "LC_ALL=C",
    NULL
};

/* Ekstrak marker standar dari isi report sanitizer (untuk evidence).
 * NULL bila tidak ada marker dikenal (report tetap bukti). */
static const char *report_marker_of(const char *rpt)
{
    int i;
    if (!rpt)
        return NULL;
    for (i = 0; SANITIZER_MARKERS[i]; i++) {
        if (strstr(rpt, SANITIZER_MARKERS[i]))
            return SANITIZER_MARKERS[i];
    }
    return NULL;
}

static const char *marker_found(const char *out, const char *err)
{
    int i;
    for (i = 0; SANITIZER_MARKERS[i]; i++) {
        if ((out && strstr(out, SANITIZER_MARKERS[i])) ||
            (err && strstr(err, SANITIZER_MARKERS[i])))
            return SANITIZER_MARKERS[i];
    }
    return NULL;
}

/* Tambah diagnostic ringan (string disalin ke pool statis bergilir). */
static void add_diag_run(myc_result *res, const char *msg)
{
    char *slot;
    if (res->diag_count >= MYC_MAX_DIAGNOSTICS)
        return;
    slot = myc_result_arena_dup(res, msg, 0);
    if (!slot)
        return;
    res->diags[res->diag_count].line = 0;
    res->diags[res->diag_count].col = 0;
    res->diags[res->diag_count].message = slot;
    /* fakta eksekusi/sanitizer = bukti semantik (MYC-AUDIT-014) */
    res->diags[res->diag_count].confidence = MYC_CONF_CONFIRMED;
    res->diag_count++;
}

/* Buat path direktori temp unik: <base>/myc_run_<pid>_<n>.
 * MYC-AUDIT-003: selalu kembalikan path absolut agar exe_path
 * tidak menjadi path relatif saat cwd diubah ke tmp_dir. */
static char *make_temp_dir(void)
{
    const char *base = getenv("TEMP");
    char        cwdbuf[4096];
    char       *dir;
    int         n = 0;
    size_t      bl;

#ifdef _WIN32
    if (!base || !*base)
        base = getenv("TMP");
#else
    if (!base || !*base)
        base = getenv("TMPDIR");
#endif
    if (!base || !*base) {
#ifdef _WIN32
        base = "C:/Temp";
#else
        base = "/tmp";
#endif
    }
    /* Jika base relatif, canonicalize via getcwd agar path absolut. */
    if (base[0] != '/' && !(base[0] && base[1] == ':')) {
        if (my_getcwd(cwdbuf, sizeof(cwdbuf))) {
            base = cwdbuf;
        }
    }
    bl = strlen(base);

    while (n < 100) {
        char   buf[32];
        size_t need;
        snprintf(buf, sizeof(buf), "myc_run_%lu_%d",
                 (unsigned long)myc_getpid(), n);
        need = bl + 1 + strlen(buf) + 1;
        dir = (char *)malloc(need);
        if (!dir)
            return NULL;
        snprintf(dir, need, "%s/%s", base, buf);
        if (myc_mkdir(dir) == 0)
            return dir;
        free(dir);
        n++;
    }
    return NULL;
}

/* Path gabungan dir + "/" + name (malloc'd). */
static char *join_path(const char *dir, const char *name)
{
    size_t dl = strlen(dir);
    size_t nl = strlen(name);
    char  *out = (char *)malloc(dl + 1 + nl + 1);
    if (!out)
        return NULL;
    memcpy(out, dir, dl);
    out[dl] = '/';
    memcpy(out + dl + 1, name, nl);
    out[dl + 1 + nl] = '\0';
    return out;
}

#ifdef _WIN32
/* Salin file biner; 1 sukses, 0 gagal. */
static int copy_file(const char *src, const char *dst)
{
    FILE *f = fopen(src, "rb");
    FILE *g;
    char  buf[65536];
    size_t rd;
    if (!f)
        return 0;
    g = fopen(dst, "wb");
    if (!g) {
        fclose(f);
        return 0;
    }
    while ((rd = fread(buf, 1, sizeof(buf), f)) > 0)
        fwrite(buf, 1, rd, g);
    fclose(f);
    fclose(g);
    return 1;
}

/* Baca path lengkap runtime DLL via `clang -print-file-name=...`.
 * Mengembalikan string malloc'd atau NULL bila tidak ditemukan. */
static char *asan_dll_path(const char *clang_path)
{
    const char *argv_use[3];
    myc_proc_request preq;
    myc_proc_result  pres;
    char            *out = NULL;
    char            *nl;
    size_t           len;

    argv_use[0] = clang_path;
    argv_use[1] = "-print-file-name=" ASAN_DLL_NAME;
    argv_use[2] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = argv_use;
    preq.timeout_ms = 15000;
    preq.max_output_bytes = 65536;

    if (!myc_proc_run(&preq, &pres))
        return NULL;
    if (!pres.stdout_data || !pres.stdout_shown) {
        myc_proc_result_free(&pres);
        return NULL;
    }
    nl = strpbrk(pres.stdout_data, "\r\n");
    if (nl)
        *nl = '\0';
    len = strlen(pres.stdout_data);
    /* clang mengembalikan argumen polos bila file tidak ditemukan. */
    if (len == 0 || strstr(pres.stdout_data, ASAN_DLL_NAME) == NULL) {
        myc_proc_result_free(&pres);
        return NULL;
    }
    out = myc_strdup(pres.stdout_data);
    myc_proc_result_free(&pres);
    return out;
}
#endif /* _WIN32 */

/* Path eksekutabel hasil build dari direktori temp. Nama tanpa ekstensi;
 * Windows menambahkan .exe. */
static char *exe_path_for(const char *dir, const char *name)
{
#ifdef _WIN32
    static char winname[64];
    snprintf(winname, sizeof(winname), "%s.exe", name);
    return join_path(dir, winname);
#else
    return join_path(dir, name);
#endif
}

/* ------------------------------------------------------------------ */
/* Semantic canary (gagasan pembeda 9.9, Fase 7.2)                     */
/* ------------------------------------------------------------------ */
/*
 * Sebelum mempercayai hasil run 'bersih', verifikasi bahwa backend ASan
 * benar-benar aktif: kompilasi + jalankan source kecil yang PASTI membuat
 * out-of-bounds. Bila canary TIDAK terdeteksi (gagal / clean), berarti
 * sanitizer tidak ter-pasang/link/env menonaktifkan report -> hasil bersih
 * yang baru diperoleh TIDAK dapat dipercaya -> gate jadi INCONCLUSIVE.
 *
 * Return: 1 = canary terdeteksi (backend sehat), 0 = bersih (backend bodoh),
 *        -1 = infrastruktur canary gagal dibangun/dijalankan.
 */
static const char *const CANARY_SRC =
    "volatile int myc_canary_keep;\n"
    "int main(void) {\n"
    "    volatile int a[1];\n"
    "    a[1] = 7;\n"
    "    myc_canary_keep = a[1];\n"
    "    return 0;\n"
    "}\n";

static int myc_runtime_canary(const char *clang_path, const char *tmp_dir,
                              const char *checked_dir, int checked,
                              int timeout_ms, size_t max_out,
                              const char *cwd)
{
    char *can_exe = NULL;
    const char **bargv = NULL;
    const char **rargv = NULL;
    myc_proc_request preq;
    myc_proc_result  pres;
    int   n = 0, total, bfl = 0;
    int   ret = -1;

    static const char *const base_flags[] = {
        "-x", "c", "-", "-std=c11", "-O0", "-g",
        "-fsanitize=address,undefined",
        "-fno-sanitize-recover=all",
        NULL
    };

    can_exe = exe_path_for(tmp_dir, "myc_canary.exe");
    if (!can_exe)
        return -1;

    {
        int extra = checked ? 3 : 0;
        total = 1;
        while (base_flags[bfl++]) total++;
        total += extra + 2 + 1;
        bfl = 0;
        bargv = (const char **)malloc(sizeof(char *) * (size_t)total);
        if (!bargv) { free(can_exe); return -1; }
        bargv[n++] = clang_path;
        for (bfl = 0; base_flags[bfl]; bfl++) bargv[n++] = base_flags[bfl];
        if (checked) {
            bargv[n++] = "-DMYC_CHECKED=1";
            bargv[n++] = "-I";
            bargv[n++] = checked_dir ? checked_dir : ".";
        }
        bargv[n++] = "-o";
        bargv[n++] = can_exe;
        bargv[n] = NULL;
    }

    memset(&preq, 0, sizeof(preq));
    preq.argv = bargv;
    preq.cwd = cwd;
    preq.stdin_data = CANARY_SRC;
    preq.stdin_len = strlen(CANARY_SRC);
    preq.timeout_ms = timeout_ms;
    preq.max_output_bytes = max_out;
    if (!myc_proc_run(&preq, &pres)) {
        myc_proc_result_free(&pres);
        free(bargv);
        free(can_exe);
        return -1;
    }
    {
        int ec = pres.exit_code;
        int to = pres.timed_out;
        myc_proc_result_free(&pres);
        free(bargv);
        if (to || ec != 0) {
            /* build/run canary gagal -> backend tak teruji. */
            free(can_exe);
            return -1;
        }
    }

    /* Jalankan canary; harus ada marker sanitizer (atau exit non-zero). */
    rargv = (const char **)malloc(sizeof(char *) * 2);
    if (!rargv) { free(can_exe); return -1; }
    rargv[0] = can_exe;
    rargv[1] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = rargv;
    preq.cwd = tmp_dir;
    preq.stdin_data = NULL;
    preq.stdin_len = 0;
    preq.timeout_ms = timeout_ms;
    preq.max_output_bytes = max_out;
    preq.env = CANARY_RUN_ENV;
    if (!myc_proc_run(&preq, &pres)) {
        myc_proc_result_free(&pres);
        free(rargv);
        free(can_exe);
        return -1;
    }
    {
        const char *m = marker_found(pres.stdout_data, pres.stderr_data);
        char       *rpt = myc_read_sanitizer_report(tmp_dir,
                                                    "myc_canary_asan_rpt");
        if (!rpt)
            rpt = myc_read_sanitizer_report(tmp_dir, "myc_canary_ubsan_rpt");
        int ec = pres.exit_code;
        ret = (rpt || m || ec != 0) ? 1 : 0;
        free(rpt);
        myc_remove_sanitizer_reports(tmp_dir, "myc_canary_asan_rpt");
        myc_remove_sanitizer_reports(tmp_dir, "myc_canary_ubsan_rpt");
        myc_proc_result_free(&pres);
    }
    free(rargv);
    free(can_exe);
    return ret;
}

int myc_run_gate(const myc_request *req, const char *source, size_t source_len,
                 myc_result *res)
{
    char *clang_path = NULL;
    char *tmp_dir = NULL;
    char *exe_path = NULL;
    char *dll_src = NULL;
    char *dll_dst = NULL;
    char *injected = NULL;
    const char **build_argv = NULL;
    const char **run_argv = NULL;
    const char *build_src = source;
    size_t      build_src_len = source_len;
    size_t      injected_len = 0;
    myc_proc_request preq;
    myc_proc_result  pres;
    int   ret = 0;
    int   n = 0, total, bfl = 0;
    size_t max_out = req->max_output_bytes > 0
                         ? (size_t)req->max_output_bytes
                         : MYC_MAX_OUTPUT_BYTES;

    myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_NOT_APPLICABLE, NULL);

    /* 1. Cari clang. */
    clang_path = myc_find_executable(req->clang_program ? req->clang_program : "clang");
    if (!clang_path) {
        res->err = MYC_ERR_CLANG_NOT_FOUND;
        myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_UNAVAILABLE,
                            "clang tidak ditemukan");
        myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_SKIP,
                                "verification run di-skip: clang tidak ditemukan");
        return 0;
    }
    /* MYC-AUDIT-022 (roadmap 7.1): exact tool identity — baris pertama
     * `clang --version`. Hanya diisi bila belum ada (bila --driver juga
     * berjalan, jangan timpa/double-free). */
    if (!res->clang_version)
        res->clang_version = myc_tool_version(clang_path);

    /* 1b. Inject assert(requires) (D1.5) untuk verification build.
     * Catatan: myc_contract_inject TIDAK menulis *out_len saat tidak ada
     * kontrak (return NULL) -- jadi injected_len tetap 0 dan build_src_len
     * (source asli) TIDAK boleh ter-clobber. */
    injected = myc_contract_inject(source, source_len, &injected_len);
    if (injected) {
        build_src = injected;
        build_src_len = injected_len;
        add_diag_run(res, "verification run: kontrak requires di-inject (assert)");
    }

    /* 2. Direktori temp. */
    tmp_dir = make_temp_dir();
    if (!tmp_dir) {
        res->err = MYC_ERR_INTERNAL;
        myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INFRA_FAILED,
                            "gagal membuat direktori temp");
        myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_ERROR,
                                "verification run di-skip: direktori temp gagal");
        free(clang_path);
        return 0;
    }
    exe_path = exe_path_for(tmp_dir, "myc_run.exe");
    if (!exe_path) {
        res->err = MYC_ERR_INTERNAL;
        myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INFRA_FAILED,
                            "gagal membuat path executable");
        myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_ERROR,
                                "verification run di-skip: path exe gagal");
        free(clang_path);
        free(tmp_dir);
        return 0;
    }

    /* 3. Verification build (source via stdin). Bila --checked, definisikan
     * MYC_CHECKED (fat-pointer aktif) dan tambah -I ke direktori myc_buf.h
     * sehingga runtime fat MYC_AT ikut di-sanitize. */
    {
        static const char *const base_flags[] = {
            "-x", "c", "-", "-std=c11", "-O0", "-g",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all",
            NULL
        };
        int extra = 0;
        if (req->checked)
            extra += 3;                 /* -DMYC_CHECKED=1, -I, <dir> */
        total = 1;
        while (base_flags[bfl++])
            total++;
        total += extra + 2 + 1;         /* (+extra) "-o", exe_path, NULL */
        bfl = 0;
        build_argv = (const char **)malloc(sizeof(char *) * (size_t)total);
        if (!build_argv) {
            res->err = MYC_ERR_INTERNAL;
            goto out;
        }
        build_argv[n++] = clang_path;
        for (bfl = 0; base_flags[bfl]; bfl++)
            build_argv[n++] = base_flags[bfl];
        if (req->checked) {
            build_argv[n++] = "-DMYC_CHECKED=1";
            build_argv[n++] = "-I";
            build_argv[n++] = req->checked_header_dir ? req->checked_header_dir
                                                       : ".";
        }
        build_argv[n++] = "-o";
        build_argv[n++] = exe_path;
        build_argv[n] = NULL;

        memset(&preq, 0, sizeof(preq));
        preq.argv = build_argv;
        preq.cwd = req->cwd;
        preq.stdin_data = build_src;
        preq.stdin_len = build_src_len;
        preq.timeout_ms = req->timeout_ms;
        preq.max_output_bytes = max_out;
        if (!myc_proc_run(&preq, &pres)) {
            if (pres.timed_out) {
                res->verdict = MC_TIMEOUT;
                res->err = MYC_ERR_TIMEOUT;
                res->duration_ms += pres.duration_ms;
                myc_proc_result_free(&pres);
                free(build_argv);
                myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INCONCLUSIVE,
                                    "build timeout");
                myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_ERROR,
                                        "verification build timeout");
                goto out;
            }
            res->err = MYC_ERR_EXECUTE_FAILED;
            myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INFRA_FAILED,
                                "build launch gagal");
            myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_ERROR,
                                    "verification build launch gagal");
            free(build_argv);
            goto out;
        }
        res->duration_ms += pres.duration_ms;
        if (pres.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->err = MYC_ERR_TIMEOUT;
            myc_proc_result_free(&pres);
            free(build_argv);
            myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INCONCLUSIVE,
                                "build timeout");
            myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_ERROR,
                                    "verification build timeout");
            goto out;
        }
        if (pres.exit_code != 0) {
            /* Build verifikasi gagal (mis. tanpa main / link gagal).
             * Bukan pelanggaran; gate di-skip, verification incomplete. */
            char note[512];
            const char *fe = pres.stderr_data && pres.stderr_data[0]
                                 ? pres.stderr_data : "build verifikasi gagal";
            if (strlen(fe) > 400)
                snprintf(note, sizeof(note), "verification run di-skip: %.*s...", 400, fe);
            else
                snprintf(note, sizeof(note), "verification run di-skip: %s", fe);
            add_diag_run(res, note);
            myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INFRA_FAILED,
                                note);
            myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_SKIP,
                                    note);
            myc_proc_result_free(&pres);
            free(build_argv);
            goto out;
        }
        myc_proc_result_free(&pres);
        free(build_argv);
    }

    /* 4. Windows: salin runtime DLL ASan ke samping exe. */
#ifdef _WIN32
    {
        dll_src = asan_dll_path(clang_path);
        if (dll_src) {
            dll_dst = join_path(tmp_dir, ASAN_DLL_NAME);
            if (dll_dst && !copy_file(dll_src, dll_dst))
                add_diag_run(res, "verification run: gagal menyalin ASan DLL");
        } else {
            add_diag_run(res, "verification run: runtime ASan DLL tidak ditemukan");
        }
    }
#endif

    /* 5. Eksekusi terkendali. */
    run_argv = (const char **)malloc(sizeof(char *) * 2);
    if (!run_argv) {
        res->err = MYC_ERR_INTERNAL;
        goto out;
    }
    run_argv[0] = exe_path;
    run_argv[1] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = run_argv;
    preq.cwd = tmp_dir;
    preq.stdin_data = req->run_stdin;
    preq.stdin_len = req->run_stdin_len;
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = max_out;
    preq.env = RUN_ENV;
    if (!myc_proc_run(&preq, &pres)) {
        if (pres.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->err = MYC_ERR_TIMEOUT;
            res->duration_ms += pres.duration_ms;
            myc_proc_result_free(&pres);
            free(run_argv);
            myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INCONCLUSIVE,
                                "exec timeout");
            myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_ERROR,
                                    "verification run timeout");
            goto out;
        }
        res->err = MYC_ERR_EXECUTE_FAILED;
        myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INFRA_FAILED,
                            "exec gagal");
        myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_ERROR,
                                "verification run exec gagal");
        free(run_argv);
        goto out;
    }
    res->duration_ms += pres.duration_ms;
    res->ran_runtime = 1;
    res->run_timed_out = pres.timed_out;
    res->exit_code = pres.exit_code;

    /* Adopsi output run ke res. */
    free(res->run_stdout_text);
    free(res->run_stderr_text);
    res->run_stdout_text = pres.stdout_data; pres.stdout_data = NULL;
    res->run_stderr_text = pres.stderr_data; pres.stderr_data = NULL;
    res->run_total_stdout_bytes = pres.stdout_total;
    res->run_total_stderr_bytes = pres.stderr_total;
    res->run_shown_stdout_bytes = pres.stdout_shown;
    res->run_shown_stderr_bytes = pres.stderr_shown;
    res->run_truncated = pres.truncated;
    res->run_sanitizer_detected = pres.sanitizer_detected;
    strncpy(res->run_sanitizer_marker, pres.sanitizer_marker,
            sizeof(res->run_sanitizer_marker) - 1);
    res->run_sanitizer_marker[sizeof(res->run_sanitizer_marker) - 1] = '\0';
    myc_proc_result_free(&pres);
    free(run_argv);

    if (res->run_timed_out) {
        res->verdict = MC_TIMEOUT;
        res->err = MYC_ERR_TIMEOUT;
        goto out;
    }

    /* 6. Deteksi laporan sanitizer — saluran NON-SPOOFABLE (MYC-AUDIT-017).
     * Bukti utama = FILE report yang ditulis runtime sanitizer (log_path,
     * dibaca dari tmp_dir); program tidak bisa memalsukannya secara tidak
     * sengaja. Marker teks pada stdout/stderr hanya bukti SEKUNDER dan
     * WAJIB dikonfirmasi exit code != 0 (mekanisme myc sendiri -- assert
     * kontrak & trap MYC_CHECKED -- menulis ke stderr + abort, jadi tetap
     * terdeteksi via marker + exit != 0). Teks mirip marker dengan exit 0
     * diabaikan (bukan bukti; kemungkinan program mencetaknya sendiri). */
    {
        char        *asan_rpt = myc_read_sanitizer_report(tmp_dir,
                                                          "myc_run_asan_rpt");
        char        *ubsan_rpt = myc_read_sanitizer_report(tmp_dir,
                                                           "myc_run_ubsan_rpt");
        const char  *rpt = asan_rpt ? asan_rpt : ubsan_rpt;
        const char  *omarker = marker_found(res->run_stdout_text,
                                            res->run_stderr_text);
        int          report_evidence = (asan_rpt != NULL) ||
                                       (ubsan_rpt != NULL);

        if (report_evidence || (omarker && res->exit_code != 0)) {
            /* finding: bukti saluran report, atau marker terkonfirmasi
             * exit != 0. Marker evidence diambil dari report bila ada. */
            char note[512];
            const char *ev = report_evidence ? report_marker_of(rpt)
                                             : omarker;
            if (report_evidence) {
                res->run_sanitizer_detected = 1;
                if (ev)
                    strncpy(res->run_sanitizer_marker, ev,
                            sizeof(res->run_sanitizer_marker) - 1);
                res->run_sanitizer_marker[
                    sizeof(res->run_sanitizer_marker) - 1] = '\0';
                snprintf(note, sizeof(note),
                         "sanitizer runtime: %s (report: log_path di tmp dir)",
                         ev ? ev : "laporan sanitizer");
            } else {
                snprintf(note, sizeof(note), "sanitizer runtime: %s",
                         omarker ? omarker : "marker sanitizer");
            }
            add_diag_run(res, note);
            res->verdict = MC_RUNTIME_VIOLATION;
            res->err = MYC_ERR_RUNTIME_VIOLATION;
            myc_gate_set_status(res, MYC_GATE_RUNTIME,
                                MYC_GATE_COMPLETED_FINDINGS, note);
            myc_result_add_evidence(res, MYC_GATE_RUNTIME,
                                    MYC_EVIDENCE_FINDING, note);
            /* Isi witness dari sanitizer (Fase 1). Sanitizer punya
             * prioritas tertinggi karena bukti non-spoofable. */
            if (!res->witness && ev) {
                res->witness = (myc_witness *)malloc(sizeof(myc_witness));
                if (res->witness) {
                    myc_witness_init(res->witness);
                    /* Map sanitizer marker ke violation kind */
                    if (strstr(ev, "use-after-free"))
                        res->witness->violation_kind =
                            myc_result_arena_dup(res, "use-after-free", 0);
                    else if (strstr(ev, "out-of-bounds") ||
                             strstr(ev, "heap-buffer-overflow"))
                        res->witness->violation_kind =
                            myc_result_arena_dup(res, "out-of-bounds", 0);
                    else if (strstr(ev, "null") || strstr(ev, "nonnull"))
                        res->witness->violation_kind =
                            myc_result_arena_dup(res, "null-deref", 0);
                    else if (strstr(ev, "double-free"))
                        res->witness->violation_kind =
                            myc_result_arena_dup(res, "double-free", 0);
                    else if (strstr(ev, "stack-overflow"))
                        res->witness->violation_kind =
                            myc_result_arena_dup(res, "stack-overflow", 0);
                    else
                        res->witness->violation_kind =
                            myc_result_arena_dup(res, ev, 0);
                    res->witness->violation_msg =
                        myc_result_arena_dup(res, note, 0);
                    res->witness->backend =
                        myc_result_arena_dup(res, "clang-asan", 0);
                    /* Kronologi: sanitizer memberikan stack trace */
                    res->witness->operation = myc_result_arena_dup(res, ev, 0);
                    res->witness->pre_state = myc_result_arena_dup(res, note, 0);
                }
            }
            free(asan_rpt);
            free(ubsan_rpt);
            myc_remove_sanitizer_reports(tmp_dir, "myc_run_asan_rpt");
            myc_remove_sanitizer_reports(tmp_dir, "myc_run_ubsan_rpt");
            goto out;
        }
        free(asan_rpt);
        free(ubsan_rpt);
        myc_remove_sanitizer_reports(tmp_dir, "myc_run_asan_rpt");
        myc_remove_sanitizer_reports(tmp_dir, "myc_run_ubsan_rpt");
        if (omarker) {
            /* teks mirip marker tetapi exit 0: BUKAN bukti (kemungkinan
             * program mencetaknya sendiri / spoof) — bersihkan flag agar
             * laporan tidak menyiratkan finding. */
            char note[256];
            snprintf(note, sizeof(note),
                     "output memuat teks mirip marker sanitizer (%s) tetapi "
                     "exit=0 — diabaikan (bukan bukti finding; kemungkinan "
                     "program mencetaknya sendiri)", omarker);
            add_diag_run(res, note);
            myc_result_add_evidence(res, MYC_GATE_RUNTIME,
                                    MYC_EVIDENCE_DIAGNOSTIC, note);
            res->run_sanitizer_detected = 0;
            res->run_sanitizer_marker[0] = '\0';
        }
        if (res->exit_code != 0) {
            /* keluar non-zero tanpa laporan sanitizer & tanpa marker:
             * bukan bukti bug memori, tapi run tidak bersih. */
            char note[128];
            snprintf(note, sizeof(note),
                     "verification run: exit=%d (tanpa laporan sanitizer)",
                     res->exit_code);
            add_diag_run(res, note);
            myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INCONCLUSIVE,
                                note);
            myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_SKIP,
                                    note);
            goto out;
        }
    }

    /* 6b. Semantic canary (gagasan pembeda 9.9): sebelum mempercayai hasil
     * 'bersih', verifikasi bahwa backend ASan benar-benar menangkap OOB.
     * Bila canary tidak terdeteksi, hasil bersih tidak dapat dipercaya ->
     * gate runtime turun menjadi INCONCLUSIVE (bukan COMPLETED_CLEAN). */
    {
        int canary = myc_runtime_canary(clang_path, tmp_dir,
                                        req->checked_header_dir,
                                        req->checked,
                                        req->timeout_ms, max_out, req->cwd);
        if (canary == 1) {
            myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_GATE_END,
                                    "semantic canary terdeteksi: backend ASan sehat");
        } else {
            char note[160];
            snprintf(note, sizeof(note),
                     "backend health: canary ASan %s -> hasil bersih TIDAK dipercaya",
                     canary == 0 ? "clean (tak terdeteksi)" : "gagal dibangun");
            add_diag_run(res, note);
            myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INCONCLUSIVE,
                                note);
            myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_ERROR,
                                    note);
            res->verdict = MC_INCONCLUSIVE;
            goto out;
        }
    }

    ret = 1;
    myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_COMPLETED_CLEAN,
                        "run bersih");
    myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_GATE_END,
                            "verification run selesai: clean");
    goto out;

out:
    if (injected) free(injected);
    if (dll_dst) free(dll_dst);
    if (dll_src) free(dll_src);
    if (exe_path) {
        remove(exe_path);
        free(exe_path);
    }
    if (tmp_dir) {
        /* clang -g menghasilkan <exe>.pdb (dan DLL di Windows): hapus semua
         * artefak agar direktori temp bisa di-rmdir. */
        static const char *const artifacts[] = {
            ASAN_DLL_NAME, "myc_run.pdb", "myc_canary.exe", "myc_canary.pdb",
            NULL
        };
        int ai;
        for (ai = 0; artifacts[ai]; ai++) {
            char *p = join_path(tmp_dir, artifacts[ai]);
            if (p) {
                remove(p);
                free(p);
            }
        }
        myc_rmdir(tmp_dir);
        free(tmp_dir);
    }
    free(clang_path);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Metamorphic Verification (gagasan pembeda 9.7, --metamorphic)        */
/* ------------------------------------------------------------------ */
/*
 * Bangun source yang SAMA dua kali dengan clang ASan+UBSan pada level
 * optimisasi berbeda (-O0 vs -O2), jalankan keduanya dengan input yang
 * sama, lalu bandingkan hasil. Bila salah satu build menemukan sanitizer
 * finding dan yang lain tidak -> kemungkinan undefined behavior atau bug
 * yang toolchain-sensitive -> `metamorphic_inconsistent` + verdict
 * RUNTIME_VIOLATION (finding nyata tetap finding). Bila keduanya bersih ->
 * COMPLETED_CLEAN (L3 RUNTIME, konsisten dengan gate run).
 *
 * Non-blocking: clang hilang / build gagal / canary mati -> gate di-skip
 * atau INCONCLUSIVE, assurance statis dipertahankan + diagnostic.
 *
 * Return: 0 = di-skip/gagal (bukan error), 1 = selesai.
 */
int myc_metamorphic_gate(const myc_request *req, const char *source,
                         size_t source_len, myc_result *res)
{
    char *clang_path = NULL;
    char *tmp_dir = NULL;
    char *exe0 = NULL;      /* build -O0 */
    char *exe2 = NULL;      /* build -O2 */
    char *dll_src = NULL;
    char *dll_dst = NULL;
    char *injected = NULL;
    const char **argv_b = NULL;
    const char **argv_r = NULL;
    const char *build_src = source;
    size_t      build_src_len = source_len;
    size_t      injected_len = 0;
    myc_proc_request preq;
    myc_proc_result  pres;
    int   ret = 0;
    int   n, total, bfl;
    int   step;             /* 0 = -O0, 1 = -O2 */
    int   canary;
    size_t max_out = req->max_output_bytes > 0
                         ? (size_t)req->max_output_bytes
                         : MYC_MAX_OUTPUT_BYTES;

    /* Env per step untuk eksekusi (MYC-AUDIT-017): buffer di SCOPE FUNGSI
     * (bukan blok) agar preq.env tetap valid saat myc_proc_run dipanggil —
     * buffer stack blok yang keluar scope = use-after-scope (segfault). */
    char        meta_env_asan[2][160];
    char        meta_env_ubsan[2][160];
    const char *meta_env[2][4];

    static const char *const BASE_FLAGS[] = {
        "-x", "c", "-", "-std=c11", "-g",
        "-fsanitize=address,undefined",
        "-fno-sanitize-recover=all",
        NULL
    };

    myc_gate_set_status(res, MYC_GATE_METAMORPHIC, MYC_GATE_NOT_APPLICABLE,
                        NULL);

    /* 1. Cari clang. */
    clang_path = myc_find_executable(req->clang_program ? req->clang_program
                                                        : "clang");
    if (!clang_path) {
        res->err = MYC_ERR_CLANG_NOT_FOUND;
        myc_gate_set_status(res, MYC_GATE_METAMORPHIC, MYC_GATE_UNAVAILABLE,
                            "clang tidak ditemukan");
        myc_result_add_evidence(res, MYC_GATE_METAMORPHIC, MYC_EVIDENCE_SKIP,
                                "metamorphic di-skip: clang tidak ditemukan");
        return 0;
    }

    /* 1b. Inject assert(requires) (D1.5) bila ada kontrak. */
    injected = myc_contract_inject(source, source_len, &injected_len);
    if (injected) {
        build_src = injected;
        build_src_len = injected_len;
        add_diag_run(res, "metamorphic: kontrak requires di-inject (assert)");
    }

    /* 2. Direktori temp. */
    tmp_dir = make_temp_dir();
    if (!tmp_dir) {
        res->err = MYC_ERR_INTERNAL;
        myc_gate_set_status(res, MYC_GATE_METAMORPHIC, MYC_GATE_INFRA_FAILED,
                            "gagal membuat direktori temp");
        myc_result_add_evidence(res, MYC_GATE_METAMORPHIC, MYC_EVIDENCE_ERROR,
                                "metamorphic di-skip: direktori temp gagal");
        free(clang_path);
        return 0;
    }
    exe0 = exe_path_for(tmp_dir, "meta_o0.exe");
    exe2 = exe_path_for(tmp_dir, "meta_o2.exe");
    if (!exe0 || !exe2) {
        res->err = MYC_ERR_INTERNAL;
        myc_gate_set_status(res, MYC_GATE_METAMORPHIC, MYC_GATE_INFRA_FAILED,
                            "gagal membuat path executable");
        myc_result_add_evidence(res, MYC_GATE_METAMORPHIC, MYC_EVIDENCE_ERROR,
                                "metamorphic di-skip: path exe gagal");
        goto out;
    }

    /* 3. Build -O0 dan -O2 (source via stdin; -DMYC_CHECKED bila diminta). */
    for (step = 0; step < 2; step++) {
        const char *exe = step == 0 ? exe0 : exe2;
        const char *opt = step == 0 ? "-O0" : "-O2";
        int extra = req->checked ? 3 : 0;
        n = 0;
        bfl = 0;
        total = 1;
        while (BASE_FLAGS[bfl++])
            total++;
        total += 1 + extra + 2 + 1;   /* opt + extra + "-o" exe NULL */
        bfl = 0;
        argv_b = (const char **)malloc(sizeof(char *) * (size_t)total);
        if (!argv_b) {
            res->err = MYC_ERR_INTERNAL;
            goto out;
        }
        argv_b[n++] = clang_path;
        for (bfl = 0; BASE_FLAGS[bfl]; bfl++)
            argv_b[n++] = BASE_FLAGS[bfl];
        argv_b[n++] = opt;
        if (req->checked) {
            argv_b[n++] = "-DMYC_CHECKED=1";
            argv_b[n++] = "-I";
            argv_b[n++] = req->checked_header_dir ? req->checked_header_dir
                                                  : ".";
        }
        argv_b[n++] = "-o";
        argv_b[n++] = exe;
        argv_b[n] = NULL;

        memset(&preq, 0, sizeof(preq));
        preq.argv = argv_b;
        preq.cwd = req->cwd;
        preq.stdin_data = build_src;
        preq.stdin_len = build_src_len;
        preq.timeout_ms = req->timeout_ms;
        preq.max_output_bytes = max_out;
        if (!myc_proc_run(&preq, &pres)) {
            myc_proc_result_free(&pres);
            free(argv_b);
            argv_b = NULL;
            res->err = MYC_ERR_EXECUTE_FAILED;
            myc_gate_set_status(res, MYC_GATE_METAMORPHIC, MYC_GATE_INFRA_FAILED,
                                "build launch gagal");
            myc_result_add_evidence(res, MYC_GATE_METAMORPHIC, MYC_EVIDENCE_ERROR,
                                    "metamorphic di-skip: build launch gagal");
            goto out;
        }
        res->duration_ms += pres.duration_ms;
        if (pres.timed_out || pres.exit_code != 0) {
            /* build verifikasi gagal (mis. tanpa main / link gagal):
             * bukan pelanggaran; gate di-skip, assurance statis dipertahankan. */
            char note[512];
            const char *fe = pres.stderr_data && pres.stderr_data[0]
                                 ? pres.stderr_data : "build verifikasi gagal";
            if (strlen(fe) > 400)
                snprintf(note, sizeof(note),
                         "metamorphic di-skip (%s): %.*s...", opt, 400, fe);
            else
                snprintf(note, sizeof(note),
                         "metamorphic di-skip (%s): %s", opt, fe);
            add_diag_run(res, note);
            myc_gate_set_status(res, MYC_GATE_METAMORPHIC,
                                MYC_GATE_INFRA_FAILED, note);
            myc_result_add_evidence(res, MYC_GATE_METAMORPHIC,
                                    MYC_EVIDENCE_SKIP, note);
            myc_proc_result_free(&pres);
            free(argv_b);
            argv_b = NULL;
            goto out;
        }
        myc_proc_result_free(&pres);
        free(argv_b);
        argv_b = NULL;
    }

    /* 4. Windows: salin runtime DLL ASan ke samping exe. */
#ifdef _WIN32
    {
        dll_src = asan_dll_path(clang_path);
        if (dll_src) {
            dll_dst = join_path(tmp_dir, ASAN_DLL_NAME);
            if (dll_dst && !copy_file(dll_src, dll_dst))
                add_diag_run(res, "metamorphic: gagal menyalin ASan DLL");
        } else {
            add_diag_run(res, "metamorphic: runtime ASan DLL tidak ditemukan");
        }
    }
#endif

    /* 5. Eksekusi -O0 dan -O2 dengan input yang sama. */
    for (step = 0; step < 2; step++) {
        const char *exe = step == 0 ? exe0 : exe2;
        int  *exitp = step == 0 ? &res->meta_o0_exit : &res->meta_o2_exit;
        int  *findp = step == 0 ? &res->meta_o0_finding : &res->meta_o2_finding;
        const char *marker;

        argv_r = (const char **)malloc(sizeof(char *) * 2);
        if (!argv_r) {
            res->err = MYC_ERR_INTERNAL;
            goto out;
        }
        argv_r[0] = exe;
        argv_r[1] = NULL;

        memset(&preq, 0, sizeof(preq));
        preq.argv = argv_r;
        preq.cwd = tmp_dir;
        preq.stdin_data = req->run_stdin;
        preq.stdin_len = req->run_stdin_len;
        preq.timeout_ms = req->timeout_ms;
        preq.max_output_bytes = max_out;
        /* Env dengan log_path unik per build (-O0/-O2); buffer di scope
         * fungsi (meta_env_*) agar tetap hidup selama myc_proc_run. */
        snprintf(meta_env_asan[step], sizeof(meta_env_asan[step]),
                 "ASAN_OPTIONS=log_path=myc_meta%d_asan_rpt:"
                 "abort_on_error=1:halt_on_error=1", step);
        snprintf(meta_env_ubsan[step], sizeof(meta_env_ubsan[step]),
                 "UBSAN_OPTIONS=log_path=myc_meta%d_ubsan_rpt:"
                 "halt_on_error=1:print_stacktrace=1", step);
        meta_env[step][0] = meta_env_asan[step];
        meta_env[step][1] = meta_env_ubsan[step];
        meta_env[step][2] = "LC_ALL=C";
        meta_env[step][3] = NULL;
        preq.env = meta_env[step];
        if (!myc_proc_run(&preq, &pres)) {
            myc_proc_result_free(&pres);
            free(argv_r);
            argv_r = NULL;
            res->err = MYC_ERR_EXECUTE_FAILED;
            myc_gate_set_status(res, MYC_GATE_METAMORPHIC, MYC_GATE_INFRA_FAILED,
                                "exec gagal");
            myc_result_add_evidence(res, MYC_GATE_METAMORPHIC, MYC_EVIDENCE_ERROR,
                                    "metamorphic exec gagal");
            goto out;
        }
        res->duration_ms += pres.duration_ms;
        *exitp = pres.exit_code;
        if (pres.timed_out)
            res->meta_timed_out = 1;
        marker = marker_found(pres.stdout_data, pres.stderr_data);
        {
            char base_asan[64], base_ubsan[64];
            char *rpt;
            snprintf(base_asan, sizeof(base_asan), "myc_meta%d_asan_rpt", step);
            snprintf(base_ubsan, sizeof(base_ubsan), "myc_meta%d_ubsan_rpt", step);
            rpt = myc_read_sanitizer_report(tmp_dir, base_asan);
            if (!rpt)
                rpt = myc_read_sanitizer_report(tmp_dir, base_ubsan);
            *findp = (rpt != NULL || (marker && pres.exit_code != 0)) ? 1 : 0;
            if (rpt) {
                const char *rm = report_marker_of(rpt);
                char note[192];
                snprintf(note, sizeof(note),
                         "metamorphic (%s): sanitizer report %s",
                         step == 0 ? "-O0" : "-O2",
                         rm ? rm : "(laporan sanitizer)");
                add_diag_run(res, note);
            } else if (marker) {
                char note[192];
                snprintf(note, sizeof(note), "metamorphic (%s): sanitizer %s",
                         step == 0 ? "-O0" : "-O2", marker);
                add_diag_run(res, note);
            }
            free(rpt);
            myc_remove_sanitizer_reports(tmp_dir, base_asan);
            myc_remove_sanitizer_reports(tmp_dir, base_ubsan);
        }
        myc_proc_result_free(&pres);
        free(argv_r);
        argv_r = NULL;
    }
    res->ran_metamorphic = 1;

    if (res->meta_timed_out) {
        res->verdict = MC_TIMEOUT;
        res->err = MYC_ERR_TIMEOUT;
        myc_gate_set_status(res, MYC_GATE_METAMORPHIC, MYC_GATE_INCONCLUSIVE,
                            "metamorphic run timeout");
        myc_result_add_evidence(res, MYC_GATE_METAMORPHIC, MYC_EVIDENCE_ERROR,
                                "metamorphic run timeout");
        goto out;
    }

    /* 6. Semantic canary (9.9): hasil bersih hanya dipercaya bila backend
     * ASan sehat. */
    canary = myc_runtime_canary(clang_path, tmp_dir,
                                req->checked_header_dir, req->checked,
                                req->timeout_ms, max_out, req->cwd);
    if (canary != 1) {
        char note[192];
        snprintf(note, sizeof(note),
                 "backend health: canary ASan %s -> hasil metamorphic TIDAK dipercaya",
                 canary == 0 ? "clean (tak terdeteksi)" : "gagal dibangun");
        add_diag_run(res, note);
        myc_gate_set_status(res, MYC_GATE_METAMORPHIC, MYC_GATE_INCONCLUSIVE,
                            note);
        myc_result_add_evidence(res, MYC_GATE_METAMORPHIC, MYC_EVIDENCE_ERROR,
                                note);
        res->verdict = MC_INCONCLUSIVE;
        goto out;
    }
    myc_result_add_evidence(res, MYC_GATE_METAMORPHIC, MYC_EVIDENCE_GATE_END,
                            "semantic canary terdeteksi: backend ASan sehat");

    /* 7. Bandingkan hasil -O0 vs -O2. */
    if (res->meta_o0_finding || res->meta_o2_finding) {
        if (res->meta_o0_finding != res->meta_o2_finding) {
            /* Satu build menemukan, yang lain tidak -> metamorfik konflik. */
            char note[256];
            snprintf(note, sizeof(note),
                     "metamorphic inconsistency: -O0 %s vs -O2 %s "
                     "(kemungkinan UB / toolchain-sensitive bug)",
                     res->meta_o0_finding ? "finding" : "clean",
                     res->meta_o2_finding ? "finding" : "clean");
            add_diag_run(res, note);
            res->metamorphic_inconsistent = 1;
            myc_gate_set_status(res, MYC_GATE_METAMORPHIC,
                                MYC_GATE_COMPLETED_FINDINGS, note);
            myc_result_add_evidence(res, MYC_GATE_METAMORPHIC,
                                    MYC_EVIDENCE_FINDING, note);
        } else {
            char note[192];
            snprintf(note, sizeof(note),
                     "metamorphic: kedua build menemukan sanitizer "
                     "(-O0 dan -O2)");
            add_diag_run(res, note);
            myc_gate_set_status(res, MYC_GATE_METAMORPHIC,
                                MYC_GATE_COMPLETED_FINDINGS, note);
            myc_result_add_evidence(res, MYC_GATE_METAMORPHIC,
                                    MYC_EVIDENCE_FINDING, note);
        }
        res->verdict = MC_RUNTIME_VIOLATION;
        res->err = MYC_ERR_RUNTIME_VIOLATION;
        goto out;
    }

    /* Tanpa sanitizer: exit code berbeda hanya informasional (bukan
     * finding) -- program bisa berbeda hasilnya karena UB, tapi kami
     * tidak mengklaim bug tanpa bukti sanitizer. */
    if (res->meta_o0_exit != res->meta_o2_exit) {
        char note[192];
        snprintf(note, sizeof(note),
                 "metamorphic: exit berbeda tanpa sanitizer (-O0=%d vs -O2=%d) "
                 "[informasional]",
                 res->meta_o0_exit, res->meta_o2_exit);
        add_diag_run(res, note);
        myc_result_add_evidence(res, MYC_GATE_METAMORPHIC,
                                MYC_EVIDENCE_DIAGNOSTIC, note);
    }

    ret = 1;
    myc_gate_set_status(res, MYC_GATE_METAMORPHIC, MYC_GATE_COMPLETED_CLEAN,
                        "metamorphic clean (-O0 == -O2)");
    myc_result_add_evidence(res, MYC_GATE_METAMORPHIC, MYC_EVIDENCE_GATE_END,
                            "metamorphic: -O0 dan -O2 setuju clean");
    goto out;

out:
    if (injected) free(injected);
    if (dll_dst) free(dll_dst);
    if (dll_src) free(dll_src);
    if (exe0) {
        remove(exe0);
        free(exe0);
    }
    if (exe2) {
        remove(exe2);
        free(exe2);
    }
    if (tmp_dir) {
        static const char *const artifacts[] = {
            ASAN_DLL_NAME, "meta_o0.pdb", "meta_o2.pdb",
            "myc_canary.exe", "myc_canary.pdb", NULL
        };
        int ai;
        for (ai = 0; artifacts[ai]; ai++) {
            char *p = join_path(tmp_dir, artifacts[ai]);
            if (p) {
                remove(p);
                free(p);
            }
        }
        myc_rmdir(tmp_dir);
        free(tmp_dir);
    }
    free(clang_path);
    return ret;
}
