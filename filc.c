/*
 * filc.c -- Gate Fil-C (D4.1, P8): --filc -> L5 FULL (opsional backend).
 *
 * Fil-C = memory-safe C/C++ (pizlonator/Fil-C; driver filc-clang, clang 20).
 * Semua error memori ditangkap sebagai "Fil-C panics" (marker: "filc safety
 * error" dll, terkonfirmasi dari issue tracker). Fil-C hanya Linux/X86_64,
 * jadi di Windows integrasi lewat WSL (pola prove.c); native filc-clang di
 * PATH juga didukung (mis. bila myc dijalankan di Linux).
 *
 * Alur:
 *   1. Cari filc-clang di PATH (native). Ada -> build+run langsung.
 *   2. Tidak ada -> cari wsl.exe; deteksi filc-clang di dalam WSL
 *      (`command -v filc-clang || ls /opt/fil/bin/filc-clang`).
 *   3. Tidak tersedia -> SKIP, assurance statis + diagnostic (non-blocking).
 *   4. Verification build (source via stdin) + eksekusi terkendali.
 *   5. Parse marker panic pada output: ada -> MC_FILC_VIOLATION; bersih
 *      (exit 0, tanpa marker) -> caller naikkan ke L5 FULL.
 *
 * Catatan jujur: bila build/run gagal tanpa marker panic (mis. tanpa main,
 * runtime Fil-C tidak ter-setup), gate di-skip -- bukan bukti bug.
 */
#include "filc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#include <process.h>   /* _getpid */
#define myc_mkdir(path) _mkdir(path)
#define myc_rmdir(path) _rmdir(path)
#define myc_getpid() _getpid()
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define myc_mkdir(path) mkdir(path, 0700)
#define myc_rmdir(path) rmdir(path)
#define myc_getpid() getpid()
#endif

#include "proc.h"

/* Nama driver Fil-C. */
#define FILC_DRIVER "filc-clang"

/* Marker panic Fil-C (strstr pada stdout+stderr). */
static const char *const FILC_PANIC_MARKERS[] = {
    "filc safety error",
    "Fatal runtime error",
    "panicked",
    "Fil-C panic",
    "double free",
    NULL
};

/* Template tetap yang dijalankan di dalam WSL. Source mengalir via stdin
 * (cat > $t); deteksi driver: command -v filc-clang, fallback ke
 * /opt/fil/bin/filc-clang (distribusi glibc resmi). */
#define WSL_FILC_DETECT_CMD \
    "command -v " FILC_DRIVER " 2>/dev/null || ls /opt/fil/bin/" FILC_DRIVER " 2>/dev/null"

#define WSL_FILC_CMD \
    "t=/tmp/myc_filc_$$.c; cat > $t; " \
    "FILC=$(command -v " FILC_DRIVER " 2>/dev/null || echo /opt/fil/bin/" FILC_DRIVER "); " \
    "\"$FILC\" -O0 -g -o /tmp/myc_filc_$$ $t 2>/tmp/myc_filc_$$.builderr; rc=$?; " \
    "if [ $rc -eq 0 ]; then /tmp/myc_filc_$$; rc=$?; fi; " \
    "cat /tmp/myc_filc_$$.builderr 2>/dev/null; " \
    "rm -f $t /tmp/myc_filc_$$ /tmp/myc_filc_$$.builderr; exit $rc"

/* Tambah diagnostic ringan (string disalin ke pool statis bergilir). */
static void add_diag_filc(myc_result *res, const char *msg)
{
    if (res->diag_count >= MYC_MAX_DIAGNOSTICS)
        return;
    {
        static char pool[MYC_MAX_DIAGNOSTICS][512];
        static int  idx = 0;
        char       *slot = pool[idx];
        size_t      n;
        idx = (idx + 1) % MYC_MAX_DIAGNOSTICS;
        n = strlen(msg);
        if (n > 511)
            n = 511;
        memcpy(slot, msg, n);
        slot[n] = '\0';
        res->diags[res->diag_count].line = 0;
        res->diags[res->diag_count].col = 0;
        res->diags[res->diag_count].message = slot;
        res->diag_count++;
    }
}

/* Jalankan proses via proc.c; 1 sukses, 0 gagal. Jika gagal karena timeout,
 * verdict MC_TIMEOUT di-set. */
static int run_proc(const myc_request *req, const char *const *argv,
                    const void *stdin_data, size_t stdin_len,
                    size_t max_out, const char *cwd, myc_proc_result *pr)
{
    myc_proc_request preq;
    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.cwd = cwd ? cwd : req->cwd;
    preq.stdin_data = stdin_data;
    preq.stdin_len = stdin_len;
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = max_out;
    return myc_proc_run(&preq, pr);
}

/* Hitung marker panic Fil-C pada output. */
static int count_panics(const char *out, const char *err)
{
    int i, count = 0;
    for (i = 0; FILC_PANIC_MARKERS[i]; i++) {
        const char *p = out ? out : "";
        while ((p = strstr(p, FILC_PANIC_MARKERS[i])) != NULL) {
            count++;
            p += strlen(FILC_PANIC_MARKERS[i]);
        }
        p = err ? err : "";
        while ((p = strstr(p, FILC_PANIC_MARKERS[i])) != NULL) {
            count++;
            p += strlen(FILC_PANIC_MARKERS[i]);
        }
    }
    return count;
}

/* Adopsi output proses ke res (ran_filc). */
static void adopt_filc_output(myc_result *res, myc_proc_result *pr,
                              int exit_code)
{
    free(res->filc_stdout_text);
    free(res->filc_stderr_text);
    res->filc_stdout_text = pr->stdout_data; pr->stdout_data = NULL;
    res->filc_stderr_text = pr->stderr_data; pr->stderr_data = NULL;
    res->exit_code = exit_code;
    myc_proc_result_free(pr);
}

/* Jalankan binary Fil-C yang sudah dibangun; kembalikan 1 = bersih,
 * 0 = skip/violation. res->ran_filc di-set di sini. */
static int run_filc_exe(const myc_request *req, const char *exe,
                        size_t max_out, myc_result *res)
{
    const char *run_argv[2];
    myc_proc_result pres;
    int   exit_code;
    int   panics;

    run_argv[0] = exe;
    run_argv[1] = NULL;
    memset(&pres, 0, sizeof(pres));
    if (!run_proc(req, run_argv, req->run_stdin, req->run_stdin_len,
                  max_out, NULL, &pres)) {
        if (pres.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->err = MYC_ERR_TIMEOUT;
            res->duration_ms += pres.duration_ms;
            myc_proc_result_free(&pres);
            return 0;
        }
        add_diag_filc(res, "gate Fil-C di-skip: gagal menjalankan binary "
                           "verification (runtime Fil-C tidak ter-setup?)");
        myc_proc_result_free(&pres);
        return 0;
    }
    res->duration_ms += pres.duration_ms;
    if (pres.timed_out) {
        res->verdict = MC_TIMEOUT;
        res->err = MYC_ERR_TIMEOUT;
        myc_proc_result_free(&pres);
        return 0;
    }
    exit_code = pres.exit_code;
    adopt_filc_output(res, &pres, exit_code);
    res->ran_filc = 1;

    panics = count_panics(res->filc_stdout_text, res->filc_stderr_text);
    res->filc_panics = panics;
    if (panics > 0) {
        char note[192];
        snprintf(note, sizeof(note),
                 "filc: %d panic (marker Fil-C) -> bug memori terbukti",
                 panics);
        add_diag_filc(res, note);
        res->verdict = MC_FILC_VIOLATION;
        res->err = MYC_ERR_FILC_VIOLATION;
        return 0;
    }
    if (exit_code != 0) {
        /* keluar non-zero tanpa marker panic: bukan bukti bug memori,
         * tapi run tidak bersih -> jangan naikkan ke L5. */
        char note[160];
        snprintf(note, sizeof(note),
                 "filc: exit=%d tanpa marker panic (bukan bukti bug; "
                 "L5 tidak diklaim)", exit_code);
        add_diag_filc(res, note);
        return 0;
    }
    add_diag_filc(res, "filc: run bersih - memory-safe (L5 FULL)");
    return 1;
}

/* Path direktori temp unik: <base>/myc_filc_<pid>_<n>. */
static char *make_temp_dir(void)
{
    const char *base = getenv("TEMP");
    char       *dir;
    int         n = 0;
    size_t      bl;

#ifdef _WIN32
    if (!base || !*base)
        base = getenv("TMP");
#endif
    if (!base || !*base)
        base = ".";
    bl = strlen(base);

    while (n < 100) {
        char   buf[32];
        size_t need = bl + 1 + strlen("myc_filc_") + strlen(buf) + 1;
        dir = (char *)malloc(need);
        if (!dir)
            return NULL;
        snprintf(buf, sizeof(buf), "myc_filc_%lu_%d",
                 (unsigned long)myc_getpid(), n);
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

int myc_filc_gate(const myc_request *req, const char *source, size_t source_len,
                  myc_result *res)
{
    char *filc_path = NULL;
    char *wsl_path = NULL;
    char *tmp_dir = NULL;
    char *exe_path = NULL;
    size_t max_out = req->max_output_bytes > 0
                         ? (size_t)req->max_output_bytes
                         : MYC_MAX_OUTPUT_BYTES;
    myc_proc_result pres;
    int   ret = 0;

    /* 1. Cari filc-clang native di PATH (Linux / setup lokal). */
    filc_path = myc_find_executable(FILC_DRIVER);
    if (filc_path) {
        /* filc-clang -O0 -g -o <exe> -x c -  (8 entry + NULL) */
        const char *build_argv[9];
        int   n = 0;

        tmp_dir = make_temp_dir();
        if (!tmp_dir) {
            res->err = MYC_ERR_INTERNAL;
            free(filc_path);
            return 0;
        }
#ifdef _WIN32
        exe_path = join_path(tmp_dir, "myc_filc.exe");
#else
        exe_path = join_path(tmp_dir, "myc_filc");
#endif
        if (!exe_path) {
            res->err = MYC_ERR_INTERNAL;
            goto out;
        }

        build_argv[n++] = filc_path;
        build_argv[n++] = "-O0";
        build_argv[n++] = "-g";
        build_argv[n++] = "-o";
        build_argv[n++] = exe_path;
        build_argv[n++] = "-x";
        build_argv[n++] = "c";
        build_argv[n++] = "-";   /* source via stdin */
        build_argv[n] = NULL;    /* 8 entry + NULL; array ukuran 9 */

        memset(&pres, 0, sizeof(pres));
        if (!run_proc(req, build_argv, source, source_len, max_out,
                      NULL, &pres)) {
            if (pres.timed_out) {
                res->verdict = MC_TIMEOUT;
                res->err = MYC_ERR_TIMEOUT;
                res->duration_ms += pres.duration_ms;
                myc_proc_result_free(&pres);
                goto out;
            }
            add_diag_filc(res, "gate Fil-C di-skip: gagal menjalankan "
                               "filc-clang");
            myc_proc_result_free(&pres);
            goto out;
        }
        res->duration_ms += pres.duration_ms;
        if (pres.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->err = MYC_ERR_TIMEOUT;
            myc_proc_result_free(&pres);
            goto out;
        }
        if (pres.exit_code != 0) {
            /* build verification gagal (mis. tanpa main / Fil-C tidak
             * mendukung sesuatu): bukan pelanggaran -> skip. */
            char note[512];
            const char *fe = pres.stderr_data && pres.stderr_data[0]
                                 ? pres.stderr_data
                                 : "build Fil-C gagal (lihat output)";
            if (strlen(fe) > 400)
                snprintf(note, sizeof(note), "gate Fil-C di-skip: %.*s...", 400, fe);
            else
                snprintf(note, sizeof(note), "gate Fil-C di-skip: %s", fe);
            add_diag_filc(res, note);
            myc_proc_result_free(&pres);
            goto out;
        }
        myc_proc_result_free(&pres);

        ret = run_filc_exe(req, exe_path, max_out, res);
        goto out;
    }

    /* 2. Cari wsl.exe (Windows; Fil-C hanya Linux). Tidak ada -> skip. */
    wsl_path = myc_find_executable("wsl.exe");
    if (!wsl_path) {
        add_diag_filc(res, "gate Fil-C di-skip: filc-clang tidak ditemukan "
                           "di PATH, dan wsl.exe tidak ada "
                           "(Fil-C hanya Linux/X86_64)");
        return 0;
    }

    /* 3. Deteksi filc-clang di dalam WSL. */
    memset(&pres, 0, sizeof(pres));
    {
        const char *argv_wsl[6];
        int   n = 0;
        myc_proc_request preq;

        argv_wsl[n++] = wsl_path;
        argv_wsl[n++] = "-e";
        argv_wsl[n++] = "bash";
        argv_wsl[n++] = "-lc";
        argv_wsl[n++] = WSL_FILC_DETECT_CMD;
        argv_wsl[n] = NULL;

        memset(&preq, 0, sizeof(preq));
        preq.argv = argv_wsl;
        preq.cwd = req->cwd;
        preq.timeout_ms = req->timeout_ms;
        preq.max_output_bytes = 65536;
        if (!myc_proc_run(&preq, &pres)) {
            if (pres.timed_out) {
                res->verdict = MC_TIMEOUT;
                res->err = MYC_ERR_TIMEOUT;
                res->duration_ms += pres.duration_ms;
                myc_proc_result_free(&pres);
                free(wsl_path);
                return 0;
            }
            add_diag_filc(res, "gate Fil-C di-skip: gagal memeriksa "
                               "filc-clang di WSL");
            myc_proc_result_free(&pres);
            free(wsl_path);
            return 0;
        }
        res->duration_ms += pres.duration_ms;
        if (pres.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->err = MYC_ERR_TIMEOUT;
            myc_proc_result_free(&pres);
            free(wsl_path);
            return 0;
        }
        if (pres.exit_code != 0 ||
            !(pres.stdout_data && (strstr(pres.stdout_data, "filc-clang") ||
                                   strstr(pres.stdout_data, "/filc")))) {
            add_diag_filc(res, "gate Fil-C di-skip: filc-clang tidak "
                               "ditemukan di WSL (instal Fil-C, atau letakkan "
                               "di /opt/fil/bin)");
            myc_proc_result_free(&pres);
            free(wsl_path);
            return 0;
        }
        myc_proc_result_free(&pres);
    }

    /* 4. Build + run di dalam WSL (source via stdin ke template tetap). */
    memset(&pres, 0, sizeof(pres));
    {
        const char *argv_wsl[6];
        int   n = 0;
        myc_proc_request preq;

        argv_wsl[n++] = wsl_path;
        argv_wsl[n++] = "-e";
        argv_wsl[n++] = "bash";
        argv_wsl[n++] = "-lc";
        argv_wsl[n++] = WSL_FILC_CMD;
        argv_wsl[n] = NULL;

        memset(&preq, 0, sizeof(preq));
        preq.argv = argv_wsl;
        preq.cwd = req->cwd;
        preq.stdin_data = source;
        preq.stdin_len = source_len;
        preq.timeout_ms = req->timeout_ms;
        preq.max_output_bytes = max_out;
        if (!myc_proc_run(&preq, &pres)) {
            if (pres.timed_out) {
                res->verdict = MC_TIMEOUT;
                res->err = MYC_ERR_TIMEOUT;
                res->duration_ms += pres.duration_ms;
                myc_proc_result_free(&pres);
                free(wsl_path);
                return 0;
            }
            add_diag_filc(res, "gate Fil-C di-skip: gagal menjalankan "
                               "template WSL Fil-C");
            myc_proc_result_free(&pres);
            free(wsl_path);
            return 0;
        }
        res->duration_ms += pres.duration_ms;
        if (pres.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->err = MYC_ERR_TIMEOUT;
            myc_proc_result_free(&pres);
            free(wsl_path);
            return 0;
        }
    }

    /* WSL template menulis builderr ke stdout; gabungkan penilaian:
     * run bersih bila exit 0 & tanpa marker. Build gagal (exit != 0 tanpa
     * marker) -> skip (bukan bukti bug). */
    {
        int   exit_code = pres.exit_code;
        int   panics;
        adopt_filc_output(res, &pres, exit_code);
        res->ran_filc = 1;
        panics = count_panics(res->filc_stdout_text, res->filc_stderr_text);
        res->filc_panics = panics;
        if (panics > 0) {
            char note[192];
            snprintf(note, sizeof(note),
                     "filc: %d panic (marker Fil-C) -> bug memori terbukti",
                     panics);
            add_diag_filc(res, note);
            res->verdict = MC_FILC_VIOLATION;
            res->err = MYC_ERR_FILC_VIOLATION;
            ret = 0;
            goto out_wsl;
        }
        if (exit_code != 0) {
            /* build gagal / run non-zero tanpa marker: skip, assurance
             * statis dipertahankan. */
            char note[512];
            const char *fe = res->filc_stdout_text && res->filc_stdout_text[0]
                                 ? res->filc_stdout_text
                                 : "run Fil-C non-zero tanpa marker panic";
            if (strlen(fe) > 400)
                snprintf(note, sizeof(note), "gate Fil-C di-skip: %.*s...", 400, fe);
            else
                snprintf(note, sizeof(note), "gate Fil-C di-skip: %s", fe);
            add_diag_filc(res, note);
            ret = 0;
            goto out_wsl;
        }
        add_diag_filc(res, "filc: run bersih - memory-safe (L5 FULL)");
        ret = 1;
        goto out_wsl;
    }

out_wsl:
    free(wsl_path);
    return ret;

out:
    if (exe_path) {
        remove(exe_path);
        free(exe_path);
    }
    if (tmp_dir) {
        myc_rmdir(tmp_dir);
        free(tmp_dir);
    }
    free(filc_path);
    return ret;
}
