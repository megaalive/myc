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
    out = _strdup(pres.stdout_data);
    myc_proc_result_free(&pres);
    return out;
}

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
    if (!myc_proc_run(&preq, &pres)) {
        myc_proc_result_free(&pres);
        free(rargv);
        free(can_exe);
        return -1;
    }
    {
        const char *m = marker_found(pres.stdout_data, pres.stderr_data);
        int ec = pres.exit_code;
        ret = (m || ec != 0) ? 1 : 0;
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

    /* 6. Deteksi laporan sanitizer. */
    {
        const char *marker = marker_found(res->run_stdout_text, res->run_stderr_text);
        if (marker) {
            char note[512];
            snprintf(note, sizeof(note), "sanitizer runtime: %s", marker);
            add_diag_run(res, note);
            res->verdict = MC_RUNTIME_VIOLATION;
            res->err = MYC_ERR_RUNTIME_VIOLATION;
            myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_COMPLETED_FINDINGS,
                                note);
            myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_FINDING,
                                    note);
            goto out;
        }
        if (res->exit_code != 0) {
            /* keluar non-zero tanpa laporan sanitizer: bukan bukti bug
             * memori, tapi run tidak bersih -> verification incomplete. */
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
