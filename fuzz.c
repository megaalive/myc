/*
 * fuzz.c -- D1 Fuzz Gate fuzz-lite (--fuzz, DS-13).
 *
 * PRNG deterministik + loop terikat pada fungsi ber-kontrak.
 * Parser kontrak dan infra temp/ASan ada di driver.c (driver_internal.h).
 */
#include "driver.h"
#include "driver_internal.h"
#include "regress.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <direct.h>
#include <process.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "proc.h"
#include "gate.h"
#include "sha256.h"

/* ================================================================== */
/* D1: Fuzz Gate fuzz-lite (--fuzz, DS-13)                            */
/* PRNG deterministik (seed tetap) + loop terikat pada fungsi          */
/* ber-kontrak; input DIBATASI kontrak requires (keunggulan atas       */
/* fuzzer buta). Clang ASan/UBSan; crash = bukti (DRIVER_VIOLATION).  */
/* ================================================================== */

#define FUZ_DEF_ITERS  20000
#define FUZ_DEF_SEED   0x5EED0001u

/* Generate harness fuzz untuk SATU fungsi: loop fuzz_iters, nilai PRNG
 * dalam rentang kontrak requires (dari kedua arah), pointer di-calloc.
 * Guard requires: hanya eksekusi input yang VALID (kontrak membatasi). */
static char *gen_fuzz_harness(const char *src, size_t srclen,
                              const drv_func *f, int iters, unsigned seed,
                              size_t *out_len)
{
    drv_buf b;
    long    lo[DRV_MAX_PARAMS], hi[DRV_MAX_PARAMS];
    int     has_lo[DRV_MAX_PARAMS], has_hi[DRV_MAX_PARAMS];
    int     p;
    long    max_hi = 0;
    int     have_hi = 0;
    memset(&b, 0, sizeof(b));
    memset(lo, 0, sizeof(lo));
    memset(hi, 0, sizeof(hi));
    memset(has_lo, 0, sizeof(has_lo));
    memset(has_hi, 0, sizeof(has_hi));
    for (p = 0; p < f->nparams; p++) {
        drv_bounds bd;
        int  ii;
        memset(&bd, 0, sizeof(bd));
        for (ii = 0; ii < f->nreqs; ii++)
            parse_bound(f->reqs[ii], f->pname[p], &bd);
        if (bd.has_lo) {
            lo[p] = bd.lo;
            has_lo[p] = 1;
        }
        if (bd.has_hi) {
            hi[p] = bd.hi;
            has_hi[p] = 1;
            if (bd.hi > max_hi)
                max_hi = bd.hi;
            have_hi = 1;
        }
        /* rentang default bila kontrak tidak menyebut */
        if (!has_lo[p] && has_hi[p])
            lo[p] = 0;
        if (!has_hi[p] && has_lo[p])
            hi[p] = lo[p] + 256;
        if (!has_lo[p] && !has_hi[p]) {
            lo[p] = 0;
            hi[p] = 256;
        }
        if (hi[p] - lo[p] > 0x3FFFFFFF)
            hi[p] = lo[p] + 0x3FFFFFFF;
    }
    if (!have_hi)
        max_hi = 8;
    if (max_hi < 1)
        max_hi = 1;

    drv_buf_puts(&b, "#include <stdio.h>\n#include <stdlib.h>\n"
                     "#include <string.h>\n");
    drv_buf_puts(&b, "#define main myc_fuz_orig_main\n");
    drv_buf_putn(&b, src, srclen);
    drv_buf_puts(&b, "\n#undef main\n\n");
    drv_buf_printf(&b, "static unsigned fuz_s = 0x%08Xu;\n", seed);
    drv_buf_puts(&b, "static unsigned fuz_next(void) {\n"
                     "    unsigned x = fuz_s;\n"
                     "    x ^= x << 13; x ^= x >> 17; x ^= x << 5;\n"
                     "    fuz_s = x;\n"
                     "    return x;\n}\n");
    drv_buf_printf(&b, "int main(void) {\n"
                     "    long long run = 0, skip = 0;\n"
                     "    int i;\n"
                     "    setvbuf(stdout, NULL, _IONBF, 0);\n"
                     "    for (i = 0; i < %d; i++) {\n", iters);
    for (p = 0; p < f->nparams; p++) {
        if (f->is_ptr[p]) {
            drv_buf_printf(&b,
                "        %s %s = (%s)calloc(%ld, 1);\n",
                f->type[p], f->pname[p], f->type[p],
                max_hi * f->elem[p] > 0 ? max_hi * f->elem[p] : 8);
        } else {
            drv_buf_printf(&b,
                "        %s %s = (%s)(fuz_next() %% %ld + %ld);\n",
                f->type[p], f->pname[p], f->type[p],
                hi[p] - lo[p] + 1, lo[p]);
        }
    }
    drv_buf_puts(&b, "        if (");
    {
        int first = 1, r;
        for (p = 0; p < f->nparams; p++) {
            if (f->is_ptr[p]) {
                if (!first)
                    drv_buf_puts(&b, " && ");
                drv_buf_printf(&b, "%s != NULL", f->pname[p]);
                first = 0;
            }
        }
        for (r = 0; r < f->nreqs; r++) {
            if (!first)
                drv_buf_puts(&b, " && ");
            drv_buf_printf(&b, "(%s)", f->reqs[r]);
            first = 0;
        }
        if (first)
            drv_buf_puts(&b, "1");
    }
    drv_buf_printf(&b,
        ") { run++; (void)%s(", f->name);
    for (p = 0; p < f->nparams; p++)
        drv_buf_printf(&b, "%s%s", p ? "," : "", f->pname[p]);
    drv_buf_puts(&b, "); } else skip++;\n");
    for (p = 0; p < f->nparams; p++)
        if (f->is_ptr[p])
            drv_buf_printf(&b, "        free((void*)%s);\n", f->pname[p]);
    drv_buf_puts(&b, "    }\n");
    drv_buf_printf(&b, "    printf(\"FUZ run=%%lld skip=%%lld\\n\", "
                     "(long long)run, (long long)skip);\n");
    drv_buf_puts(&b, "    return 0;\n}\n");
    *out_len = b.len;
    return b.data;
}

/* --- Gate D1: fuzz-lite --- */
int myc_fuzz_gate(const myc_request *req, const char *source,
                  size_t source_len, myc_result *res)
{
    drv_func funcs[DRV_MAX_FUNCS];
    int   nfuncs, fi;
    char *clang_path = NULL;
    char *tmp_dir = NULL;
    char *exe_path = NULL;
    char *dll_src = NULL, *dll_dst = NULL;
    myc_proc_request preq;
    myc_proc_result  pres;
    size_t max_out = req->max_output_bytes > 0
                         ? (size_t)req->max_output_bytes
                         : MYC_MAX_OUTPUT_BYTES;
    static const char *const FUZ_FLAGS[] = {
        "-x", "c", "-", "-std=c11", "-O1", "-g",
        "-fsanitize=address,undefined",
        "-fno-sanitize-recover=all",
        NULL
    };
    static const char *const FUZ_ENV[] = {
        "ASAN_OPTIONS=log_path=myc_fuz_asan_rpt:abort_on_error=1:"
        "halt_on_error=1",
        "UBSAN_OPTIONS=log_path=myc_fuz_ubsan_rpt:halt_on_error=1:"
        "print_stacktrace=1",
        "LC_ALL=C",
        NULL
    };
    int  iters = req->fuzz_iters > 0 ? req->fuzz_iters : FUZ_DEF_ITERS;
    unsigned seed = req->fuzz_seed != 0 ? req->fuzz_seed : FUZ_DEF_SEED;
    const char **argv_b = NULL;
    const char **argv_r = NULL;
    int  n, bfl, total;
    int  ret = 0;
    long cases_total = 0, skipped_total = 0;
    char rep[1024];
    size_t roff = 0;

    myc_gate_set_status(res, MYC_GATE_FUZZ, MYC_GATE_NOT_APPLICABLE, NULL);
    res->fuzz_seed = seed;
    res->fuzz_iters = iters;

    nfuncs = scan_contract_funcs(source, source_len, funcs, DRV_MAX_FUNCS);
    if (nfuncs == 0) {
        add_diag_drv(res, "fuzz di-skip: tanpa fungsi ber-kontrak");
        myc_gate_set_status(res, MYC_GATE_FUZZ, MYC_GATE_NOT_APPLICABLE,
                            "tanpa fungsi ber-kontrak");
        myc_result_add_evidence(res, MYC_GATE_FUZZ, MYC_EVIDENCE_SKIP,
                                "fuzz di-skip: tanpa //@ requires");
        return 0;
    }
    clang_path = myc_find_executable(req->clang_program
                                         ? req->clang_program : "clang");
    if (!clang_path) {
        res->err = MYC_ERR_CLANG_NOT_FOUND;
        add_diag_drv(res, "fuzz di-skip: clang tidak ditemukan");
        myc_gate_set_status(res, MYC_GATE_FUZZ, MYC_GATE_UNAVAILABLE,
                            "clang tidak ditemukan");
        myc_result_add_evidence(res, MYC_GATE_FUZZ, MYC_EVIDENCE_SKIP,
                                "fuzz di-skip: clang hilang");
        return 0;
    }
    tmp_dir = drv_make_temp_dir();
    if (!tmp_dir) {
        res->err = MYC_ERR_INTERNAL;
        myc_free(clang_path);
        return 0;
    }
    exe_path = drv_join_path(tmp_dir, "myc_fuz.exe");
    if (!exe_path) {
        res->err = MYC_ERR_INTERNAL;
        goto out;
    }

    res->ran_fuzz = 1;
    res->fuzz_funcs = 0;
    for (fi = 0; fi < nfuncs; fi++) {
        char *harness = NULL;
        size_t hlen = 0;
        if (funcs[fi].unsupported)
            continue;
        harness = gen_fuzz_harness(source, source_len, &funcs[fi],
                                   iters, seed, &hlen);
        if (!harness)
            continue;
        res->fuzz_funcs++;
        /* build */
        n = 0;
        total = 1;
        for (bfl = 0; FUZ_FLAGS[bfl]; bfl++)
            total++;
        total += 2 + 1;
        argv_b = (const char **)myc_malloc(sizeof(char *) * (size_t)total);
        if (!argv_b) {
            myc_free(harness);
            continue;
        }
        argv_b[n++] = clang_path;
        for (bfl = 0; FUZ_FLAGS[bfl]; bfl++)
            argv_b[n++] = FUZ_FLAGS[bfl];
        argv_b[n++] = "-o";
        argv_b[n++] = exe_path;
        argv_b[n] = NULL;
        memset(&preq, 0, sizeof(preq));
        preq.argv = argv_b;
        preq.cwd = req->cwd;
        preq.stdin_data = harness;
        preq.stdin_len = hlen;
        preq.timeout_ms = req->timeout_ms;
        preq.max_output_bytes = max_out;
        if (!myc_proc_run(&preq, &pres)) {
            myc_proc_result_free(&pres);
            myc_free(argv_b);
            myc_free(harness);
            continue;
        }
        if (pres.exit_code != 0) {
            myc_proc_result_free(&pres);
            myc_free(argv_b);
            myc_free(harness);
            continue;
        }
        myc_proc_result_free(&pres);
        myc_free(argv_b);
#ifdef _WIN32
        dll_src = drv_asan_dll_path(clang_path);
        if (dll_src) {
            dll_dst = drv_join_path(tmp_dir, ASAN_DLL_NAME);
            if (dll_dst)
                drv_copy_file(dll_src, dll_dst);
        }
        myc_free(dll_src);
        myc_free(dll_dst);
        dll_src = dll_dst = NULL;
#endif
        /* run */
        argv_r = (const char **)myc_malloc(sizeof(char *) * 2);
        if (!argv_r) {
            myc_free(harness);
            continue;
        }
        argv_r[0] = exe_path;
        argv_r[1] = NULL;
        memset(&preq, 0, sizeof(preq));
        preq.argv = argv_r;
        preq.cwd = tmp_dir;
        preq.timeout_ms = req->timeout_ms;
        preq.max_output_bytes = max_out;
        preq.env = FUZ_ENV;
        if (!myc_proc_run(&preq, &pres)) {
            myc_proc_result_free(&pres);
            myc_free(argv_r);
            myc_free(harness);
            continue;
        }
        res->duration_ms += pres.duration_ms;
        {
            int crashe = 0;
            char *asan_rpt = myc_read_sanitizer_report(tmp_dir,
                                                       "myc_fuz_asan_rpt");
            char *ubsan_rpt = myc_read_sanitizer_report(tmp_dir,
                                                        "myc_fuz_ubsan_rpt");
            int  omarker = drv_marker_found(pres.stdout_data,
                                            pres.stderr_data);
            myc_free(asan_rpt);
            myc_free(ubsan_rpt);
            myc_remove_sanitizer_reports(tmp_dir, "myc_fuz_asan_rpt");
            myc_remove_sanitizer_reports(tmp_dir, "myc_fuz_ubsan_rpt");
            if (((asan_rpt || ubsan_rpt) && pres.exit_code != 0) ||
                (omarker && pres.exit_code != 0))
                crashe = 1;
            if (crashe) {
                char note[512];
                snprintf(note, sizeof(note),
                         "fuzz: crash di %.63s (seed %u) -- input "
                         "reproduksibel", funcs[fi].name, seed);
                add_diag_drv(res, note);
                /* Fase 6: simpan input crash sebagai seed regression.
                 * MYC-AUDIT-065: skip saat replay (no_regress) — replay
                 * adalah pass verifikasi, corpus tidak boleh bermutasi. */
                if (!req->no_regress)
                    myc_regress_save(res, source, source_len, MYC_REG_FUZZ,
                                     funcs[fi].name, seed);
                res->verdict = MC_DRIVER_VIOLATION;
                res->err = MYC_ERR_DRIVER_VIOLATION;
                myc_gate_set_status(res, MYC_GATE_FUZZ,
                                    MYC_GATE_COMPLETED_FINDINGS, note);
                myc_result_add_evidence(res, MYC_GATE_FUZZ,
                                        MYC_EVIDENCE_FINDING,
                                        "fuzz: crash (bukti, hard)");
                myc_free(res->fuzz_stdout_text);
                myc_free(res->fuzz_stderr_text);
                res->fuzz_stdout_text = pres.stdout_data;
                pres.stdout_data = NULL;
                res->fuzz_stderr_text = pres.stderr_data;
                pres.stderr_data = NULL;
                myc_proc_result_free(&pres);
                myc_free(argv_r);
                myc_free(harness);
                goto out;
            }
            if (pres.stdout_data) {
                const char *p = strstr(pres.stdout_data, "FUZ run=");
                if (p) {
                    long long run = 0, skip = 0;
                    sscanf(p, "FUZ run=%lld skip=%lld", &run, &skip);
                    cases_total += run;
                    skipped_total += skip;
                }
            }
        }
        myc_proc_result_free(&pres);
        myc_free(argv_r);
        myc_free(harness);
        argv_b = argv_r = NULL;
    }
    res->fuzz_cases = cases_total;
    res->fuzz_skipped = skipped_total;
    roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
        "fuzz (D1): %d fungsi, %ld kasus tereksekusi, %ld ditolak guard, "
        "seed %u\n", res->fuzz_funcs, cases_total, skipped_total, seed);
    if (roff >= sizeof(rep))
        roff = sizeof(rep) - 1;
    res->fuzz_report = myc_result_arena_dup(res, rep, 0);
    if (cases_total > 0 && res->verdict != MC_DRIVER_VIOLATION) {
        myc_gate_set_status(res, MYC_GATE_FUZZ, MYC_GATE_COMPLETED_CLEAN,
                            "fuzz bersih");
        myc_result_add_evidence(res, MYC_GATE_FUZZ,
                                MYC_EVIDENCE_GATE_END,
                                "fuzz: bersih (loop terikat)");
        ret = 1;
    } else if (res->verdict != MC_DRIVER_VIOLATION) {
        myc_gate_set_status(res, MYC_GATE_FUZZ, MYC_GATE_NOT_APPLICABLE,
                            "0 kasus tereksekusi");
        myc_result_add_evidence(res, MYC_GATE_FUZZ, MYC_EVIDENCE_SKIP,
                                "fuzz: 0 kasus (guard terlalu ketat)");
    }

out:
    if (dll_dst) myc_free(dll_dst);
    if (dll_src) myc_free(dll_src);
    if (exe_path) {
        remove(exe_path);
        myc_free(exe_path);
    }
    if (tmp_dir) {
        char *p = drv_join_path(tmp_dir, ASAN_DLL_NAME);
        if (p) {
            remove(p);
            myc_free(p);
        }
        myc_rmdir(tmp_dir);
        myc_free(tmp_dir);
    }
    myc_free(clang_path);
    return ret;
}
