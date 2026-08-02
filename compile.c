/*
 * compile.c -- Pipeline myc.
 *
 * Urutan (pivot memory-safety 2026-08-01: policy NON-BLOCKING):
 *   1. scan include mentah (lapis 1)  -> warning (non-blocking)
 *   2. lint memory-safety (P5, D1.3+D1.4) -> LINT_VIOLATION stop (gate hard)
 *   3. gcc -E (argv eksak, source via stdin) -> output preprocessed
 *   4. scan markers (lapis 2)         -> warning (non-blocking)
 *   5. scan calls (lapis 3)           -> warning (non-blocking)
 *   6. gcc -c -O2 (gate, tier dasar memori) -> COMPILE_ERROR
 *   7. (opsional) gcc -c -fanalyzer -o NUL
 *   8. verdict MC_OK + assurance
 *
 * Tidak pernah menyusun shell string; source tidak pernah jadi argumen.
 * Catatan ownership: req->source dimiliki caller (myc.c); file loading
 * dilakukan di myc.c, bukan di sini.
 */
#include "compile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "contract.h"
#include "driver.h"
#include "filc.h"
#include "gate.h"
#include "lint.h"
#include "policy.h"
#include "proc.h"
#include "prove.h"
#include "run.h"
#include "scanner.h"
#include "sha256.h"

/* ------------------------------------------------------------------ */
/* Tabel flags gcc terpusat (P4.3).                                    */
/* ------------------------------------------------------------------ */

/* Tier dasar -- default, nol false-positive pd kode sah, semua -Werror. */
static const char *const MEMORY_WARNINGS[] = {
    "-Warray-bounds",
    "-Wstringop-overflow",
    "-Wuse-after-free",
    "-Wfree-nonheap-object",
    "-Wformat-overflow",
    "-Wformat-truncation",
    NULL
};

/* Tier ketat -- opsional (--strict), BISING, bukan default (keputusan 1). */
static const char *const STRICT_WARNINGS[] = {
    "-Wconversion",
    "-Wsign-conversion",
    "-Wint-conversion",
    NULL
};

/* Flags syntax-only yang selalu dipakai (sanity dasar). */
static const char *const SYNTAX_BASE[] = {
    "-std=c11", "-Wall", "-Wextra", "-Werror",
    "-pedantic", "-Werror=implicit-function-declaration", NULL
};

/* Gate memori: perlu -c + -O2 agar -Warray-bounds/-Wstringop-overflow aktif
 * (gcc menjalankan analisis GIMPLE hanya saat kompilasi dengan optimisasi). */
static const char *const MEMORY_GATE[] = {
    "-c", "-O2", "-o", "NUL", NULL
};

/* Flags analyzer: MEMORY_GATE + -fanalyzer. */
static const char *const ANALYZER_EXTRA[] = {
    "-c", "-O2", "-fanalyzer", "-o", "NUL", NULL
};

/* Susun satu array argv gabungan (semua pointer statis, tak perlu bebas).
 * count = jumlah argumen setelah gcc_path. */
static const char **merge_args(const char *const *lists[], size_t nlists,
                               size_t *count)
{
    size_t total = 0;
    size_t li, ai, idx = 0;
    const char **out;
    for (li = 0; li < nlists; li++)
        for (ai = 0; lists[li][ai]; ai++)
            total++;
    out = (const char **)malloc(sizeof(char *) * (total + 1));
    if (!out)
        return NULL;
    for (li = 0; li < nlists; li++)
        for (ai = 0; lists[li][ai]; ai++)
            out[idx++] = lists[li][ai];
    out[idx] = NULL;
    *count = idx;
    return out;
}

/* helper agar add_diag bisa menerima pesan dinamis dari stderr gcc.
 * Pesan disalin ke slot statis bergilir (cukup untuk laporan). */
static void add_diag_copy(myc_result *res, int line, int col, const char *msg)
{
    if (res->diag_count >= MYC_MAX_DIAGNOSTICS)
        return;
    {
        static char pool[MYC_MAX_DIAGNOSTICS][256];
        static int  idx = 0;
        char       *slot = pool[idx];
        size_t      n;
        idx = (idx + 1) % MYC_MAX_DIAGNOSTICS;
        n = strlen(msg);
        if (n > 255)
            n = 255;
        memcpy(slot, msg, n);
        slot[n] = '\0';
        res->diags[res->diag_count].line = line;
        res->diags[res->diag_count].col = col;
        res->diags[res->diag_count].message = slot;
        res->diag_count++;
    }
}

/* Tambah diagnostic dari stderr gcc (parsing baris sederhana).
 * Hanya baris yang memuat "<stdin>:<line>:<col>:" yang diambil sebagai
 * diagnostic; baris lanjutan gcc ("cc1.exe:...", "  'main': events",
 * "<stdin>: In function") dilewati agar laporan tidak bising. */
static void ingest_gcc_diagnostics(myc_result *res, const char *text)
{
    const char *p = text;
    while (p && *p) {
        const char *nl = strchr(p, '\n');
        size_t      linelen = nl ? (size_t)(nl - p) : strlen(p);
        char       *linebuf = (char *)malloc(linelen + 1);
        int         line = 0, col = 0;
        const char *msg = NULL;

        if (linebuf) {
            memcpy(linebuf, p, linelen);
            linebuf[linelen] = '\0';
            if (strncmp(linebuf, "<stdin>:", 8) == 0) {
                char *rest = linebuf + 8;
                char *endptr;
                line = (int)strtol(rest, &endptr, 10);
                if (endptr && *endptr == ':') {
                    col = (int)strtol(endptr + 1, &endptr, 10);
                    if (endptr && *endptr == ':') {
                        msg = endptr + 1;
                        add_diag_copy(res, line, col, msg);
                    }
                }
            }
            free(linebuf);
        }
        if (!nl)
            break;
        p = nl + 1;
    }
}

/* Jalankan gcc dengan argumen tertentu; return hasil proses. */
static void run_gcc(const myc_request *req,
                    const char *gcc_path,
                    const char *const *extra_args,
                    const char *stdin_data, size_t stdin_len,
                    size_t max_out,
                    myc_proc_result *pr)
{
    int    argc = 0;
    int    total;
    int    n = 0;
    int    i;
    const char **argv;
    myc_proc_request preq;

    while (extra_args[argc])
        argc++;
    total = 1 + argc + 3 + 1;
    argv = (const char **)malloc(sizeof(char *) * (size_t)total);
    if (!argv) {
        memset(pr, 0, sizeof(*pr));
        pr->err = MYC_ERR_INTERNAL;
        return;
    }
    argv[n++] = gcc_path;
    for (i = 0; i < argc; i++)
        argv[n++] = extra_args[i];
    argv[n++] = "-x";
    argv[n++] = "c";
    argv[n++] = "-";
    argv[n] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.cwd = req->cwd;
    preq.stdin_data = stdin_data;
    preq.stdin_len = stdin_len;
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = max_out;

    myc_proc_run(&preq, pr);
    free(argv);
}

/* Pindahkan isi myc_proc_result ke res. */
static void adopt_proc(myc_result *res, myc_proc_result *pr)
{
    free(res->stdout_text);
    free(res->stderr_text);
    res->stdout_text = pr->stdout_data; pr->stdout_data = NULL;
    res->stderr_text = pr->stderr_data; pr->stderr_data = NULL;
    res->total_stdout_bytes = pr->stdout_total;
    res->total_stderr_bytes = pr->stderr_total;
    res->shown_stdout_bytes = pr->stdout_shown;
    res->shown_stderr_bytes = pr->stderr_shown;
    res->truncated = pr->truncated;
    res->exit_code = pr->exit_code;
    res->duration_ms += pr->duration_ms;
}

/* Karakter pembentuk identifier (untuk skimmer D1.2). */
static int ident_char(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/* Deteksi apakah source MEMAKAI makro checked-build (D1.2): identifier
 * "MYC_BUF" di LUAR komentar/string/char-literal, yang diikuti '(' (bentuk
 * deklarasi `MYC_BUF(T) b;`). Skimmer mini ini mencegah over-claim L4 untuk
 * source yang hanya MENYEBUT "MYC_BUF" di komentar. */
static int source_uses_checked_buf(const char *src, size_t len)
{
    size_t i = 0;
    while (i < len) {
        char c = src[i];
        if (c == '/' && i + 1 < len) {
            if (src[i + 1] == '/') {
                while (i < len && src[i] != '\n')
                    i++;
                continue;
            }
            if (src[i + 1] == '*') {
                i += 2;
                while (i + 1 < len && !(src[i] == '*' && src[i + 1] == '/'))
                    i++;
                i += 2;
                continue;
            }
        }
        if (c == '"' || c == '\'') {
            char q = c;
            i++;
            while (i < len && src[i] != q) {
                if (src[i] == '\\')
                    i++;
                i++;
            }
            i++;
            continue;
        }
        if (c == '#') {
            while (i < len && src[i] != '\n')
                i++;
            continue;
        }
        if (c == 'M' && i + 7 <= len && memcmp(src + i, "MYC_BUF", 7) == 0) {
            char before = i > 0 ? src[i - 1] : ' ';
            char after  = i + 7 < len ? src[i + 7] : ' ';
            if (!ident_char((unsigned char)before) &&
                !ident_char((unsigned char)after)) {
                size_t j = i + 7;
                while (j < len && (src[j] == ' ' || src[j] == '\t'))
                    j++;
                if (j < len && src[j] == '(')
                    return 1;
            }
            i += 7;
            continue;
        }
        i++;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Gate checked-build (D1.2, --checked) -> L4 SPATIAL.                  */
/* ------------------------------------------------------------------ */
/*
 * Bangun source dua kali: (1) produksi normal (T* polos, sudah di-gate
 * gcc di atas), (2) -DMYC_CHECKED=1 sehingga MYC_BUF menjadi fat-struct
 * yang memaksa semua akses lewat MYC_AT (akses langsung b[i] = error
 * kompilasi). Bila build checked lolos, transformasi fat-pointer terbukti
 * berlaku -> assurance L4 SPATIAL untuk buffer MYC_BUF.
 *
 * Non-blocking (sesuai arah): source tanpa pola MYC_BUF -> gate di-skip,
 * assurance statis dipertahankan + diagnostic. Bila build checked GAGAL
 * (mis. akses langsung pada fat-struct), itu COMPILE_ERROR -- artinya kode
 * tidak memenuhi disiplin checked build.
 */
static void run_checked_gate(const myc_request *req, const char *gcc_path,
                             const char *src, size_t srclen,
                             size_t max_out, myc_result *res)
{
    static const char *const CHECKED_EXTRA[] = {
        "-c", "-O2", "-o", "NUL",
        "-DMYC_CHECKED=1",
        NULL
    };
    const char *const *lists[4];
    const char **args;
    size_t      nargs;
    myc_proc_request preq;
    myc_proc_result  pr;
    int   n = 0;
    int   argc = 0;
    int   total;
    int   i;
    const char **argv;

    if (!source_uses_checked_buf(src, srclen)) {
        add_diag_copy(res, 0, 0,
                      "checked build di-skip: tidak ada pola MYC_BUF di source");
        /* verdict sukses (gate kompilasi sudah lolos); jangan biarkan
         * nilai awal MC_ERROR terbawa ke guard pipeline. */
        res->verdict = MC_OK;
        res->err = MYC_ERR_NONE;
        return;
    }

    /* susun argv: gcc + CHECKED_EXTRA + syntax base + mem warnings (+strict)
     * + -I<checked_header_dir> agar myc_buf.h ditemukan. */
    lists[0] = CHECKED_EXTRA;
    lists[1] = SYNTAX_BASE;
    lists[2] = MEMORY_WARNINGS;
    lists[3] = req->strict ? STRICT_WARNINGS : NULL;
    args = merge_args(lists, req->strict ? 4 : 3, &nargs);
    if (!args) {
        res->err = MYC_ERR_INTERNAL;
        res->verdict = MC_ERROR;
        return;
    }
    argc = (int)nargs;
    total = 1 + argc + (req->checked_header_dir ? 2 : 0) + 3 + 1;
    /* 1(gcc) + argc + [-I dir] + "-x","c","-" + NULL */
    argv = (const char **)malloc(sizeof(char *) * (size_t)total);
    if (!argv) {
        free((void *)args);
        res->err = MYC_ERR_INTERNAL;
        res->verdict = MC_ERROR;
        return;
    }
    argv[n++] = gcc_path;
    for (i = 0; i < argc; i++)
        argv[n++] = args[i];
    if (req->checked_header_dir) {
        argv[n++] = "-I";
        argv[n++] = req->checked_header_dir;
    }
    argv[n++] = "-x";
    argv[n++] = "c";
    argv[n++] = "-";
    argv[n] = NULL;
    free((void *)args);

    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.cwd = req->cwd;
    preq.stdin_data = src;
    preq.stdin_len = srclen;
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = max_out;
    if (!myc_proc_run(&preq, &pr)) {
        /* launch gagal: jangan salah klaim L4 (pr.exit_code=0 palsu) */
        free((void *)argv);
        if (pr.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->err = MYC_ERR_TIMEOUT;
            res->duration_ms += pr.duration_ms;
            myc_proc_result_free(&pr);
            return;
        }
        res->err = MYC_ERR_EXECUTE_FAILED;
        res->verdict = MC_ERROR;
        myc_proc_result_free(&pr);
        return;
    }
    free((void *)argv);

    res->ran_checked = 1;
    res->checked_uses_buf = 1;
    if (pr.timed_out) {
        res->verdict = MC_TIMEOUT;
        res->err = MYC_ERR_TIMEOUT;
        res->duration_ms += pr.duration_ms;
        myc_proc_result_free(&pr);
        return;
    }
    res->duration_ms += pr.duration_ms;
    if (pr.exit_code != 0) {
        /* kode tidak memenuhi disiplin checked build (mis. akses langsung
         * pada fat-struct, atau tipe tidak cocok dengan MYC_AT) */
        res->verdict = MC_COMPILE_ERROR;
        res->err = MYC_ERR_COMPILE_ERROR;
        res->checked_build_ok = 0;
        adopt_proc(res, &pr);
        if (res->stderr_text)
            ingest_gcc_diagnostics(res, res->stderr_text);
        myc_proc_result_free(&pr);
        return;
    }
    myc_proc_result_free(&pr);
    res->checked_build_ok = 1;
    /* gate ini "memiliki" verdict-nya sendiri (pola sama dengan prove/run):
     * nilai awal MC_ERROR tidak boleh terbawa. */
    res->verdict = MC_OK;
    res->err = MYC_ERR_NONE;
    res->exit_code = 0;
    add_diag_copy(res, 0, 0,
                  "checked build OK: transformasi fat-pointer (MYC_BUF) -> L4 SPATIAL");
}

void myc_pipeline(const myc_request *req, myc_result *res)
{
    char *gcc_path = NULL;
    myc_proc_result pr;
    size_t max_out = req->max_output_bytes > 0
                         ? (size_t)req->max_output_bytes
                         : MYC_MAX_OUTPUT_BYTES;
    const char *src;
    size_t      srclen;
    char        hex[65];

    src = req->source;
    srclen = req->source_len;

    /* Inisialisasi gate status (Fase 3). */
    myc_gate_set_status(res, MYC_GATE_PREPROCESS, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_COMPILE, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_ANALYZER, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_PROVE, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_CHECKED, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_FILC, MYC_GATE_NOT_APPLICABLE, NULL);
    myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_NOT_APPLICABLE, NULL);

    /* hash source */
    sha256_hex(src, srclen, hex);
    res->source_sha256 = _strdup(hex);

    /* cari gcc */
    gcc_path = myc_find_executable(req->gcc_program ? req->gcc_program : "gcc");
    if (!gcc_path) {
        res->err = MYC_ERR_GCC_NOT_FOUND;
        res->verdict = MC_ERROR;
        return;
    }
    res->resolved_gcc = _strdup(gcc_path);

    /* fingerprint kanonik
     * Perbaikan MYC-AUDIT-005: snprintf() mengembalikan panjang yang
     * *seharusnya* ditulis jika terpotong, bukan panjang aktual di buffer.
     * Dulu kode memakai nilai n yang truncated sebagai panjang ke sha256_hex
     * sehingga bisa membaca di luar buf[512]. Sekarang kita hitung dulu
     * dengan snprintf(NULL,0,...), lalu alokasi exact, baru hash. */
    {
        char  policy_hex[65];
        char *fp_buf = NULL;
        int   fp_need;
        size_t fp_len;
        myc_policy_hash(policy_hex);
        fp_need = snprintf(NULL, 0,
                     "v8|gcc:%s|cwd:%s|pol:%s|flags:c11;Wall;Werror;pedantic;mem;%s;%s;%s;%s;%s;%s|src:%s",
                     gcc_path,
                     req->cwd ? req->cwd : "",
                     policy_hex,
                     req->strict ? "strict" : "default",
                     req->run ? "run" : "norun",
                     req->prove ? "prove" : "noprove",
                     req->checked ? "checked" : "nochecked",
                     req->filc ? "filc" : "nofilc",
                     req->driver ? "driver" : "nodriver",
                     res->source_sha256 ? res->source_sha256 : "");
        if (fp_need > 0) {
            fp_len = (size_t)fp_need;
            fp_buf = (char *)malloc(fp_len + 1);
        }
        if (fp_buf) {
            snprintf(fp_buf, fp_len + 1,
                     "v8|gcc:%s|cwd:%s|pol:%s|flags:c11;Wall;Werror;pedantic;mem;%s;%s;%s;%s;%s;%s|src:%s",
                     gcc_path,
                     req->cwd ? req->cwd : "",
                     policy_hex,
                     req->strict ? "strict" : "default",
                     req->run ? "run" : "norun",
                     req->prove ? "prove" : "noprove",
                     req->checked ? "checked" : "nochecked",
                     req->filc ? "filc" : "nofilc",
                     req->driver ? "driver" : "nodriver",
                     res->source_sha256 ? res->source_sha256 : "");
            sha256_hex(fp_buf, fp_len, hex);
            free(fp_buf);
        } else {
            /* alokasi gagal: hash string kosong sebagai fallback */
            sha256_hex("", 0, hex);
        }
        res->fingerprint = _strdup(hex);
    }

    /* --- Lapis 1: include mentah (warning, non-blocking) --- */
    myc_scan_include_raw(src, srclen, res);

    /* --- Scan kontrak //@ requires/ensures (D1.5; info, non-blocking) --- */
    myc_contract_scan(src, srclen, res);

    /* --- Lint memory-safety (P5; default aktif, mati via --no-lint) --- */
    if (req->run_lint) {
        if (!myc_lint_source(src, srclen, res)) {
            res->verdict = MC_VIOLATION;
            res->err = MYC_ERR_LINT_VIOLATION;
            res->exit_code = 1;
            free(gcc_path);
            return;
        }
    }

    /* --- gcc -E --- */
    {
        static const char *const pre_args[] = { "-E", "-std=c11", NULL };
        run_gcc(req, gcc_path, pre_args, src, srclen, max_out, &pr);
    }
    if (pr.timed_out) {
        res->verdict = MC_TIMEOUT;
        res->err = MYC_ERR_TIMEOUT;
        myc_proc_result_free(&pr);
        free(gcc_path);
        myc_gate_set_status(res, MYC_GATE_PREPROCESS, MYC_GATE_INCONCLUSIVE,
                            "preprocess timeout");
        myc_result_add_evidence(res, MYC_GATE_PREPROCESS, MYC_EVIDENCE_ERROR,
                                "gcc -E timeout");
        myc_reduce_verdict(res);
        return;
    }
    res->ran_preprocess = 1;
    adopt_proc(res, &pr);
    myc_proc_result_free(&pr);

    if (res->exit_code != 0) {
        /* preprocess gagal (mis. makro rusak) */
        res->verdict = MC_COMPILE_ERROR;
        res->err = MYC_ERR_PREPROCESS_ERROR;
        myc_gate_set_status(res, MYC_GATE_PREPROCESS, MYC_GATE_COMPLETED_FINDINGS,
                            res->stderr_text ? res->stderr_text : "preprocess error");
        myc_result_add_evidence(res, MYC_GATE_PREPROCESS, MYC_EVIDENCE_FINDING,
                                "preprocess gagal");
        if (res->stderr_text)
            ingest_gcc_diagnostics(res, res->stderr_text);
        free(gcc_path);
        myc_reduce_verdict(res);
        return;
    }
    myc_gate_set_status(res, MYC_GATE_PREPROCESS, MYC_GATE_COMPLETED_CLEAN,
                        "preprocess clean");
    myc_result_add_evidence(res, MYC_GATE_PREPROCESS, MYC_EVIDENCE_GATE_END,
                            "gcc -E clean");

    /* --- Lapis 2 + 3: markers & calls (warning, non-blocking) --- */
    {
        /* pre = buffer yang TERSIMPAN (mungkin terpotong 1MB); panjangnya
         * harus shown_stdout_bytes, BUKAN total (gcc bisa menulis jauh lebih
         * banyak). Memakai total -> out-of-bounds read (bug dogfooding). */
        const char *pre = res->stdout_text ? res->stdout_text : "";
        size_t      prelen = res->stdout_text ? res->shown_stdout_bytes : 0;
        myc_scan_markers(pre, prelen, res);
        myc_scan_calls(pre, prelen, res);
    }

    /* --- Gate: kompilasi + tier dasar memori (perlu -O2 utk memori) --- */
    {
        const char *const *lists[4];
        const char **args;
        size_t      nargs;
        lists[0] = MEMORY_GATE;
        lists[1] = SYNTAX_BASE;
        lists[2] = MEMORY_WARNINGS;
        lists[3] = req->strict ? STRICT_WARNINGS : NULL;
        args = merge_args(lists, req->strict ? 4 : 3, &nargs);
        if (!args) {
            res->verdict = MC_ERROR;
            res->err = MYC_ERR_INTERNAL;
            free(gcc_path);
            return;
        }
        run_gcc(req, gcc_path, args, src, srclen, max_out, &pr);
        free((void *)args);
    }
    if (pr.timed_out) {
        res->verdict = MC_TIMEOUT;
        res->err = MYC_ERR_TIMEOUT;
        myc_proc_result_free(&pr);
        free(gcc_path);
        myc_gate_set_status(res, MYC_GATE_COMPILE, MYC_GATE_INCONCLUSIVE,
                            "compile timeout");
        myc_result_add_evidence(res, MYC_GATE_COMPILE, MYC_EVIDENCE_ERROR,
                                "gcc -c timeout");
        myc_reduce_verdict(res);
        return;
    }
    res->ran_compile = 1;
    adopt_proc(res, &pr);
    myc_proc_result_free(&pr);

    if (res->exit_code != 0) {
        res->verdict = MC_COMPILE_ERROR;
        res->err = MYC_ERR_COMPILE_ERROR;
        myc_gate_set_status(res, MYC_GATE_COMPILE, MYC_GATE_COMPLETED_FINDINGS,
                            res->stderr_text ? res->stderr_text : "compile error");
        myc_result_add_evidence(res, MYC_GATE_COMPILE, MYC_EVIDENCE_FINDING,
                                "compile gagal");
        if (res->stderr_text)
            ingest_gcc_diagnostics(res, res->stderr_text);
        free(gcc_path);
        myc_reduce_verdict(res);
        return;
    }
    myc_gate_set_status(res, MYC_GATE_COMPILE, MYC_GATE_COMPLETED_CLEAN,
                        "compile clean");
    myc_result_add_evidence(res, MYC_GATE_COMPILE, MYC_EVIDENCE_GATE_END,
                            "gcc -c clean");

    /* --- Gate opsional: -fanalyzer --- */
    if (req->run_analyzer) {
        const char *const *lists[4];
        const char **args;
        size_t      nargs;
        lists[0] = ANALYZER_EXTRA;
        lists[1] = SYNTAX_BASE;
        lists[2] = MEMORY_WARNINGS;
        lists[3] = req->strict ? STRICT_WARNINGS : NULL;
        args = merge_args(lists, req->strict ? 4 : 3, &nargs);
        if (!args) {
            res->verdict = MC_ERROR;
            res->err = MYC_ERR_INTERNAL;
            free(gcc_path);
            return;
        }
        run_gcc(req, gcc_path, args, src, srclen, max_out, &pr);
        free((void *)args);
        if (pr.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->err = MYC_ERR_TIMEOUT;
            myc_proc_result_free(&pr);
            free(gcc_path);
            myc_gate_set_status(res, MYC_GATE_ANALYZER, MYC_GATE_INCONCLUSIVE,
                                "analyzer timeout");
            myc_result_add_evidence(res, MYC_GATE_ANALYZER, MYC_EVIDENCE_ERROR,
                                    "gcc -fanalyzer timeout");
            myc_reduce_verdict(res);
            return;
        }
        res->ran_analyzer = 1;
        if (pr.exit_code != 0) {
            res->verdict = MC_COMPILE_ERROR;
            res->err = MYC_ERR_COMPILE_ERROR;
            adopt_proc(res, &pr);
            myc_gate_set_status(res, MYC_GATE_ANALYZER, MYC_GATE_COMPLETED_FINDINGS,
                                res->stderr_text ? res->stderr_text : "analyzer finding");
            myc_result_add_evidence(res, MYC_GATE_ANALYZER, MYC_EVIDENCE_FINDING,
                                    "gcc -fanalyzer finding");
            if (res->stderr_text)
                ingest_gcc_diagnostics(res, res->stderr_text);
            myc_proc_result_free(&pr);
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        myc_gate_set_status(res, MYC_GATE_ANALYZER, MYC_GATE_COMPLETED_CLEAN,
                            "analyzer clean");
        myc_result_add_evidence(res, MYC_GATE_ANALYZER, MYC_EVIDENCE_GATE_END,
                                "gcc -fanalyzer clean");
        myc_proc_result_free(&pr);
    }

    /* --- Gate opsional: checked build (D1.2, --checked) -> L4 SPATIAL ---
     * Bangun source kedua dengan -DMYC_CHECKED=1 (fat-pointer). Lolos =
     * transformasi berlaku. Gagal (COMPILE_ERROR) = kode tidak mematuhi
     * disiplin checked build. Di-skip bila source tidak memakai MYC_BUF.
     * Catatan: bila --prove juga diminta, jangan return dulu -- prove tetap
     * dijalankan (PROVE_VIOLATION tetap harus dilaporkan); L4 > L2 jadi
     * assurance tidak diturunkan. */
    if (req->checked) {
        run_checked_gate(req, gcc_path, src, srclen, max_out, res);
        if (res->verdict == MC_TIMEOUT || res->verdict == MC_COMPILE_ERROR ||
            res->verdict == MC_ERROR) {
            myc_gate_set_status(res, MYC_GATE_CHECKED,
                                res->verdict == MC_COMPILE_ERROR
                                    ? MYC_GATE_COMPLETED_FINDINGS
                                    : MYC_GATE_INCONCLUSIVE,
                                res->stderr_text ? res->stderr_text : "checked build error");
            myc_result_add_evidence(res, MYC_GATE_CHECKED,
                                    res->verdict == MC_COMPILE_ERROR
                                        ? MYC_EVIDENCE_FINDING
                                        : MYC_EVIDENCE_ERROR,
                                    "checked build gagal/timeout");
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (res->checked_build_ok) {
            myc_gate_set_status(res, MYC_GATE_CHECKED, MYC_GATE_COMPLETED_CLEAN,
                                "checked build OK");
            myc_result_add_evidence(res, MYC_GATE_CHECKED, MYC_EVIDENCE_GATE_END,
                                    "checked build lolos");
        } else {
            myc_gate_set_status(res, MYC_GATE_CHECKED, MYC_GATE_NOT_APPLICABLE,
                                "tidak ada pola MYC_BUF");
            myc_result_add_evidence(res, MYC_GATE_CHECKED, MYC_EVIDENCE_SKIP,
                                    "checked build di-skip: tanpa MYC_BUF");
        }
        if (!req->run && !req->prove && !req->filc && !req->driver) {
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
    }

    /* --- Gate opsional: Frama-C Eva (D3.1, --prove) -> L2 PROVEN ---
     * Non-blocking: bila wsl/frama-c hilang atau Eva tidak menganalisis,
     * assurance statis dipertahankan (bukan error). Bila --run/--filc juga
     * diminta, jangan return dulu: lanjut ke gate berikut (L5 > L3 > L2). */
    if (req->prove) {
        int ok = myc_prove_gate(req, src, srclen, res);
        if (res->verdict == MC_TIMEOUT || res->verdict == MC_PROVE_VIOLATION) {
            /* violation = bug terbukti -> assurance turun ke NONE
             * (konsisten dengan fixture bad_run_* -> L0) */
            if (res->verdict == MC_PROVE_VIOLATION) {
                res->assurance = MYC_ASSURANCE_NONE;
                myc_gate_set_status(res, MYC_GATE_PROVE, MYC_GATE_COMPLETED_FINDINGS,
                                    res->prove_stderr_text ? res->prove_stderr_text : "prove violation");
                myc_result_add_evidence(res, MYC_GATE_PROVE, MYC_EVIDENCE_FINDING,
                                        "Frama-C Eva: PROVE_VIOLATION");
            } else {
                myc_gate_set_status(res, MYC_GATE_PROVE, MYC_GATE_INCONCLUSIVE,
                                    "prove timeout");
                myc_result_add_evidence(res, MYC_GATE_PROVE, MYC_EVIDENCE_ERROR,
                                        "Frama-C Eva timeout");
            }
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (ok && res->ran_prove && res->prove_alarms == 0) {
            myc_gate_set_status(res, MYC_GATE_PROVE, MYC_GATE_COMPLETED_CLEAN,
                                "Eva: 0 alarm");
            myc_result_add_evidence(res, MYC_GATE_PROVE, MYC_EVIDENCE_GATE_END,
                                    "Frama-C Eva clean");
        } else {
            myc_gate_set_status(res, MYC_GATE_PROVE, MYC_GATE_NOT_APPLICABLE,
                                "Eva tidak menganalisis / di-skip");
            myc_result_add_evidence(res, MYC_GATE_PROVE, MYC_EVIDENCE_SKIP,
                                    "Frama-C Eva di-skip");
        }
        if (!req->run && !req->filc && !req->driver) {
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
    }

    /* --- Gate opsional: Fil-C (D4.1, --filc) -> L5 FULL ---
     * Non-blocking: bila filc-clang tidak tersedia (PATH/WSL), gate di-skip,
     * assurance statis dipertahankan + diagnostic. Bila tersedia dan run
     * bersih (tanpa marker panic) -> L5. Bila --run juga diminta, jangan
     * return dulu: lanjut ke gate run (L3 > L2; L5 tetap dipertahankan). */
    if (req->filc) {
        int ok = myc_filc_gate(req, src, srclen, res);
        if (res->verdict == MC_TIMEOUT || res->verdict == MC_FILC_VIOLATION) {
            if (res->verdict == MC_FILC_VIOLATION) {
                res->assurance = MYC_ASSURANCE_NONE;
                myc_gate_set_status(res, MYC_GATE_FILC, MYC_GATE_COMPLETED_FINDINGS,
                                    res->filc_stderr_text ? res->filc_stderr_text : "filc violation");
                myc_result_add_evidence(res, MYC_GATE_FILC, MYC_EVIDENCE_FINDING,
                                        "Fil-C: VIOLATION");
            } else {
                myc_gate_set_status(res, MYC_GATE_FILC, MYC_GATE_INCONCLUSIVE,
                                    "filc timeout");
                myc_result_add_evidence(res, MYC_GATE_FILC, MYC_EVIDENCE_ERROR,
                                        "Fil-C timeout");
            }
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (ok && res->ran_filc && res->filc_panics == 0) {
            myc_gate_set_status(res, MYC_GATE_FILC, MYC_GATE_COMPLETED_CLEAN,
                                "filc clean");
            myc_result_add_evidence(res, MYC_GATE_FILC, MYC_EVIDENCE_GATE_END,
                                    "Fil-C clean");
        } else {
            myc_gate_set_status(res, MYC_GATE_FILC, MYC_GATE_NOT_APPLICABLE,
                                "filc di-skip");
            myc_result_add_evidence(res, MYC_GATE_FILC, MYC_EVIDENCE_SKIP,
                                    "Fil-C di-skip");
        }
        if (!req->run && !req->driver) {
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
    }

    /* --- Gate opsional: verification run (P6, --run) -> L3 RUNTIME --- */
    if (req->run) {
        int ok = myc_run_gate(req, src, srclen, res);
        if (res->verdict == MC_TIMEOUT || res->verdict == MC_RUNTIME_VIOLATION ||
            res->err == MYC_ERR_EXECUTE_FAILED || res->err == MYC_ERR_INTERNAL) {
            /* violation = bug terbukti -> assurance turun ke NONE
             * (konsisten dengan fixture bad_run_* -> L0) */
            if (res->verdict == MC_RUNTIME_VIOLATION) {
                res->assurance = MYC_ASSURANCE_NONE;
                myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_COMPLETED_FINDINGS,
                                    res->run_stderr_text ? res->run_stderr_text : "runtime violation");
                myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_FINDING,
                                        "verification run: RUNTIME_VIOLATION");
            } else {
                myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INFRA_FAILED,
                                    "runtime infra failed");
                myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_ERROR,
                                        "verification run: infra failed");
            }
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (ok && res->ran_runtime && !res->run_timed_out) {
            /* clean run: gate status sudah di-set oleh myc_run_gate */
        } else {
            myc_gate_set_status(res, MYC_GATE_RUNTIME, MYC_GATE_INCONCLUSIVE,
                                "runtime di-skip");
            myc_result_add_evidence(res, MYC_GATE_RUNTIME, MYC_EVIDENCE_SKIP,
                                    "verification run di-skip");
        }
        if (!req->driver) {
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
    }

    /* --- Gate opsional: driver-generator (D2.2, --driver) -> L3 RUNTIME ---
     * Non-blocking: bila clang hilang / tidak ada fungsi ber-kontrak / build
     * harness gagal, assurance statis dipertahankan + diagnostic. Bila run
     * bersih dengan >= 1 kasus tereksekusi -> L3 (runtime via sanitizer).
     * Marker sanitizer -> MC_DRIVER_VIOLATION (bug nyata pada kasus tepi). */
    if (req->driver) {
        int ok = myc_driver_gate(req, src, srclen, res);
        if (res->verdict == MC_TIMEOUT || res->verdict == MC_DRIVER_VIOLATION) {
            if (res->verdict == MC_DRIVER_VIOLATION) {
                res->assurance = MYC_ASSURANCE_NONE;
                myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_COMPLETED_FINDINGS,
                                    res->driver_stderr_text ? res->driver_stderr_text : "driver violation");
                myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_FINDING,
                                        "driver: DRIVER_VIOLATION");
            } else {
                myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_INCONCLUSIVE,
                                    "driver timeout");
                myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_ERROR,
                                        "driver timeout");
            }
            free(gcc_path);
            myc_reduce_verdict(res);
            return;
        }
        if (ok && res->ran_driver && res->driver_cases > 0) {
            myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_COMPLETED_CLEAN,
                                "driver clean");
            myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_GATE_END,
                                    "driver: clean");
        } else {
            myc_gate_set_status(res, MYC_GATE_DRIVER, MYC_GATE_NOT_APPLICABLE,
                                "driver di-skip");
            myc_result_add_evidence(res, MYC_GATE_DRIVER, MYC_EVIDENCE_SKIP,
                                    "driver di-skip");
        }
        free(gcc_path);
        myc_reduce_verdict(res);
        return;
    }

    myc_reduce_verdict(res);
    free(gcc_path);
}
