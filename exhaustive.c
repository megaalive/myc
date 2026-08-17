/*
 * exhaustive.c -- A3 Small-Domain Exhaustive Proof (--exhaustive, DS-03).
 *
 * Enumerasi penuh domain fungsi ber-kontrak yang terbatas. Parser
 * kontrak dan infra build/run ASan ada di driver.c (driver_internal.h).
 */
#include "driver.h"
#include "driver_internal.h"
#include "regress.h"
#include "persist.h"

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
#include "json.h"

/* ================================================================== */
/* A3: Small-Domain Exhaustive Proof (--exhaustive, DS-03)            */
/* Enumerasi PENUH domain fungsi ber-kontrak yang terbatas = bukti     */
/* riil untuk domain yang dideklarasikan (bukan sampel tepi).          */
/* ================================================================== */

#define EXH_MAX_PER_PARAM 1024      /* lebar maksimum tiap dimensi */
#define EXH_MAX_POINTS    1000000   /* budget produk kartesian (A3) */
#define EXH_PRINT_CASES   20000     /* marker per-case maksimum dicetak */
#define EXH_MAX_ENSURES   8         /* ensures per fungsi */
#define EXH_STATE_FILE    ".myc/exhaustive.json"
#define EXH_MAX_STATE     64

/* Satu domain ter-enumerasi: per-parameter int lo..hi. */
typedef struct {
    int    fi;                          /* index di funcs[] */
    long   lo[DRV_MAX_PARAMS], hi[DRV_MAX_PARAMS];
    int    intp[DRV_MAX_PARAMS];        /* index param integer */
    int    nint;
    long   points;                      /* produk kartesian */
    int    ok;
    char   spec[160];                   /* "lo..hi,lo..hi" */
    char   prev_spec[160];              /* spec run sebelumnya (""=none) */
    int    narrowed;                    /* 1 = domain dipersempit (DS-03) */
} ex_domain;

/* Entry state DS-03 (.myc/exhaustive.json). */
typedef struct {
    char   func[64];
    char   spec[160];
    long   points;
} ex_state_entry;

/* Pilih fungsi ber-kontrak yang domain-nya bisa di-enumerasi penuh.
 * Bila tidak ada yang lolos, skip_note (opsional) diisi alasan pertama
 * (pesan skip yang akurat: tak terbatas vs terlalu lebar). */
static void ex_build_domains(const drv_func *funcs, int nfuncs,
                             ex_domain *doms, int maxdoms, int *ndoms,
                             char *skip_note, size_t skip_cap)
{
    int f, d = 0;
    *ndoms = 0;
    if (skip_note && skip_cap > 0)
        skip_note[0] = '\0';
    for (f = 0; f < nfuncs; f++) {
        const drv_func *fn = &funcs[f];
        ex_domain dom;
        long product = 1;
        int  p;
        if (fn->unsupported || fn->nreqs == 0 || fn->name[0] == '\0')
            continue;
        memset(&dom, 0, sizeof(dom));
        dom.fi = f;
        for (p = 0; p < fn->nparams; p++) {
            drv_bounds bd;
            long width;
            int  ii;
            if (fn->is_ptr[p])
                continue;               /* pointer: bukan dimensi enumerasi */
            memset(&bd, 0, sizeof(bd));
            for (ii = 0; ii < fn->nreqs; ii++)
                parse_bound(fn->reqs[ii], fn->pname[p], &bd);
            if (!bd.has_lo || !bd.has_hi || bd.hi < bd.lo) {
                if (skip_note && skip_note[0] == '\0')
                    snprintf(skip_note, skip_cap,
                             "domain %.32s tak terbatas (perlu requires "
                             "\"%.32s >= LO && %.32s <= HI\")",
                             fn->pname[p], fn->pname[p], fn->pname[p]);
                goto skip_func;         /* tanpa rentang penuh: bukan kecil */
            }
            width = bd.hi - bd.lo + 1;
            if (width <= 0 || width > EXH_MAX_PER_PARAM) {
                if (skip_note && skip_note[0] == '\0')
                    snprintf(skip_note, skip_cap,
                             "domain %.32s terlalu lebar (%ld..%ld, max "
                             "%d titik/dimensi)",
                             fn->pname[p], bd.lo, bd.hi, EXH_MAX_PER_PARAM);
                goto skip_func;         /* dimensi terlalu lebar */
            }
            if (product > EXH_MAX_POINTS / width) {
                if (skip_note && skip_note[0] == '\0')
                    snprintf(skip_note, skip_cap,
                             "produk domain melebihi budget %d titik",
                             EXH_MAX_POINTS);
                goto skip_func;         /* produk melebihi budget 1e6 */
            }
            product *= width;
            dom.lo[dom.nint] = bd.lo;
            dom.hi[dom.nint] = bd.hi;
            dom.intp[dom.nint] = p;
            dom.nint++;
        }
        if (dom.nint == 0) {
            if (skip_note && skip_note[0] == '\0')
                snprintf(skip_note, skip_cap, "%.32s: tanpa parameter integer",
                         fn->name);
            goto skip_func;             /* tak ada parameter integer */
        }
        dom.points = product;
        dom.ok = 1;
        /* spec: "lo..hi" per dimensi (deterministik, urutan parameter) */
        {
            size_t off = 0;
            int q;
            for (q = 0; q < dom.nint; q++) {
                int r = snprintf(dom.spec + off,
                                 sizeof(dom.spec) - off,
                                 "%s%ld..%ld", q ? "," : "",
                                 dom.lo[q], dom.hi[q]);
                if (r > 0)
                    off += (size_t)r;
                if (off >= sizeof(dom.spec))
                    off = sizeof(dom.spec) - 1;
            }
        }
        if (d < maxdoms)
            doms[d++] = dom;
        continue;
skip_func:
        ;
    }
    *ndoms = d;
}

/* Ambil ensures PURE yang terikat ke fungsi (dari res->contract_clauses). */
static int ex_get_ensures(const myc_result *res, const char *func,
                          char out[][512], int maxout)
{
    int i, n = 0;
    if (!res)
        return 0;
    for (i = 0; i < res->contract_clause_count && n < maxout; i++) {
        const myc_contract_clause *cl = &res->contract_clauses[i];
        if (cl->kind != 1 || !cl->func || !cl->expr)
            continue;
        if (strcmp(cl->func, func) != 0)
            continue;
        if (cl->status != MYC_CLAUSE_OK)
            continue;                   /* hanya ekspresi pure */
        snprintf(out[n], 512, "%s", cl->expr);
        n++;
    }
    return n;
}

/* Generate harness enumerasi PENUH (odometer) + assert(ensures). */
static char *gen_exhaustive_harness(const char *src, size_t srclen,
                                    const drv_func *funcs,
                                    const ex_domain *doms, int ndoms,
                                    const myc_result *res,
                                    size_t *out_len, long *total_points)
{
    drv_buf b;
    int     d;
    int     gid = 0;
    memset(&b, 0, sizeof(b));
    *total_points = 0;

    drv_buf_puts(&b, "#include <stdio.h>\n#include <stdlib.h>\n"
                     "#include <string.h>\n#include <assert.h>\n");
    drv_buf_puts(&b, "#define main myc_exh_orig_main\n");
    drv_buf_putn(&b, src, srclen);
    drv_buf_puts(&b, "\n#undef main\n\n");
    drv_buf_puts(&b, "static int exh_run = 0;\n");
    drv_buf_puts(&b, "static int exh_skip = 0;\n");
    drv_buf_puts(&b, "static long exh_printed = 0;\n\n");
    drv_buf_puts(&b, "int main(void) {\n");
    drv_buf_puts(&b, "    setvbuf(stdout, NULL, _IONBF, 0);\n");

    for (d = 0; d < ndoms; d++) {
        const ex_domain *dom = &doms[d];
        const drv_func *fn = &funcs[dom->fi];
        long ix[DRV_MAX_PARAMS];
        long psize[DRV_MAX_PARAMS];
        char ensures[EXH_MAX_ENSURES][512];
        int  nens;
        int  p, q;
        long max_hi = 0;
        int  have_hi = 0;
        int  pp, ii;

        /* ukuran buffer pointer: batas atas terbesar di seluruh param */
        for (pp = 0; pp < fn->nparams; pp++) {
            drv_bounds bd;
            memset(&bd, 0, sizeof(bd));
            for (ii = 0; ii < fn->nreqs; ii++)
                parse_bound(fn->reqs[ii], fn->pname[pp], &bd);
            if (bd.has_hi) {
                if (!have_hi || bd.hi > max_hi)
                    max_hi = bd.hi;
                have_hi = 1;
            }
        }
        if (!have_hi)
            max_hi = 8;
        if (max_hi < 1)
            max_hi = 1;
        for (p = 0; p < fn->nparams; p++) {
            psize[p] = fn->is_ptr[p] ? max_hi * fn->elem[p] : 0;
            if (psize[p] > DRV_BUF_CAP)
                psize[p] = DRV_BUF_CAP;
            if (psize[p] < 1)
                psize[p] = 1;
        }

        nens = ex_get_ensures(res, fn->name, ensures, EXH_MAX_ENSURES);
        memset(ix, 0, sizeof(ix));
        for (;;) {
            gid++;
            drv_buf_puts(&b, "    {\n");
            for (p = 0; p < fn->nparams; p++) {
                if (fn->is_ptr[p]) {
                    drv_buf_printf(&b, "        %s %s = (%s)calloc(%ld, 1);\n",
                                   fn->type[p], fn->pname[p], fn->type[p],
                                   psize[p]);
                } else {
                    long v = dom->lo[0];
                    for (q = 0; q < dom->nint; q++)
                        if (dom->intp[q] == p)
                            v = dom->lo[q] + ix[q];
                    drv_buf_printf(&b, "        %s %s = %ld;\n",
                                   fn->type[p], fn->pname[p], v);
                }
            }
            /* guard: pointer non-NULL && semua requires */
            drv_buf_puts(&b, "        if (");
            {
                int first = 1;
                int r;
                for (p = 0; p < fn->nparams; p++) {
                    if (fn->is_ptr[p]) {
                        if (!first)
                            drv_buf_puts(&b, " && ");
                        drv_buf_printf(&b, "%s != NULL", fn->pname[p]);
                        first = 0;
                    }
                }
                for (r = 0; r < fn->nreqs; r++) {
                    if (!first)
                        drv_buf_puts(&b, " && ");
                    drv_buf_printf(&b, "(%s)", fn->reqs[r]);
                    first = 0;
                }
                if (first)
                    drv_buf_puts(&b, "1");
            }
            drv_buf_printf(&b, ") {\n            exh_run++;\n");
            drv_buf_printf(&b,
                "            if (exh_printed < %d) "
                "{ printf(\"EXH case=%d run\\n\", %d); "
                "exh_printed++; }\n",
                EXH_PRINT_CASES, gid, gid);
            drv_buf_puts(&b, "            (void)");
            drv_buf_puts(&b, fn->name);
            drv_buf_puts(&b, "(");
            for (p = 0; p < fn->nparams; p++) {
                if (p)
                    drv_buf_puts(&b, ", ");
                drv_buf_puts(&b, fn->pname[p]);
            }
            drv_buf_puts(&b, ");\n");
            /* ensures pure diperiksa per titik domain (inti bukti A3).
             * Kegagalan dilaporkan via marker PORTABEL EXH_ASSERT_FAIL,
             * bukan assert() libc: format pesan + exit ABI assert berbeda
             * per platform (glibc SIGABRT vs MSVCRT fail-fast), sehingga
             * deteksi berbasis marker sanitizer tidak konsisten lintas OS. */
            for (q = 0; q < nens; q++) {
                drv_buf_printf(&b,
                    "            if (!(%s)) { fprintf(stderr, "
                    "\"EXH_ASSERT_FAIL: %s\\n\"); return 4; }\n",
                    ensures[q], ensures[q]);
            }
            drv_buf_puts(&b, "        } else {\n            exh_skip++;\n");
            drv_buf_printf(&b,
                "            if (exh_printed < %d) "
                "{ printf(\"EXH case=%d skip\\n\", %d); "
                "exh_printed++; }\n",
                EXH_PRINT_CASES, gid, gid);
            drv_buf_puts(&b, "        }\n");
            for (p = 0; p < fn->nparams; p++) {
                if (fn->is_ptr[p])
                    drv_buf_printf(&b, "        free((void*)%s);\n",
                                   fn->pname[p]);
            }
            drv_buf_puts(&b, "    }\n");
            /* majukan odometer; carry keluar = enumerasi selesai */
            {
                int carry = 1;
                for (q = dom->nint - 1; q >= 0 && carry; q--) {
                    ix[q]++;
                    if (ix[q] > dom->hi[q] - dom->lo[q])
                        ix[q] = 0;
                    else
                        carry = 0;
                }
                if (carry)
                    break;
            }
        }
    }
    drv_buf_printf(&b, "    printf(\"EXH run=%%d skip=%%d\\n\", exh_run, "
                       "exh_skip);\n");
    drv_buf_puts(&b, "    return exh_run == 0 ? 3 : 0;\n");
    drv_buf_puts(&b, "}\n");

    *total_points = (long)gid;
    if (!b.data)
        return NULL;
    *out_len = b.len;
    return b.data;
}

/* --- DS-03 state: .myc/exhaustive.json (per-fungsi spec domain) --- */

static void ex_state_read(ex_state_entry *entries, int cap, int *n)
{
    FILE *f;
    long  sz;
    char *buf;
    json_value *root, *arr;
    int   i, cnt = 0;
    *n = 0;
    f = fopen(EXH_STATE_FILE, "rb");
    if (!f)
        return;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 4 * 1024 * 1024) {
        fclose(f);
        return;
    }
    buf = (char *)myc_malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        myc_free(buf);
        fclose(f);
        return;
    }
    buf[sz] = '\0';
    fclose(f);
    if (!json_parse(buf, (size_t)sz, &root)) {
        myc_free(buf);
        return;
    }
    arr = json_get(root, "entries");
    if (arr && arr->type == JSON_ARR) {
        for (i = 0; i < (int)arr->len && cnt < cap; i++) {
            json_value *e = arr->items[i];
            const char *fn, *sp;
            json_value *pt;
            if (!e || e->type != JSON_OBJ)
                continue;
            fn = json_get_str(e, "func");
            sp = json_get_str(e, "spec");
            pt = json_get(e, "points");
            if (!fn || !sp || !pt || pt->type != JSON_NUM)
                continue;
            snprintf(entries[cnt].func, sizeof(entries[cnt].func), "%s", fn);
            snprintf(entries[cnt].spec, sizeof(entries[cnt].spec), "%s", sp);
            entries[cnt].points = (long)pt->num;
            cnt++;
        }
    }
    json_free(root);
    myc_free(buf);
    *n = cnt;
}

static void ex_state_write(const ex_state_entry *entries, int n)
{
    json_value *root, *arr;
    char *out;
    int   i;
    root = json_new_obj();
    if (!root)
        return;
    arr = json_new_arr();
    if (!arr) {
        json_free(root);
        return;
    }
    for (i = 0; i < n; i++) {
        json_value *e = json_new_obj();
        if (!e)
            break;
        json_obj_set(e, "func", json_new_str(entries[i].func));
        json_obj_set(e, "spec", json_new_str(entries[i].spec));
        json_obj_set(e, "points", json_new_num((int64_t)entries[i].points));
        json_arr_push(arr, e);
    }
    json_obj_set(root, "entries", arr);
    if (json_serialize(root, &out)) {
        /* PR-012 (MYC-AUDIT-044, P3-T03): tulis ATOMIK (temp+flush+
         * fsync+rename). Crash kapan pun -> exhaustive.json OLD valid
         * ATAU NEW valid, tidak pernah setengah. NON-blocking: gagal
         * diabaikan (seperti dulu). */
        (void)myc_persist_atomic_write_str(EXH_STATE_FILE, out);
        myc_free(out);
    }
    json_free(root);
}

/* Parse "lo..hi,lo..hi" ke larik rentang. Return jumlah dimensi. */
static int ex_parse_spec(const char *spec, long *lo, long *hi, int maxdim)
{
    const char *p = spec;
    int n = 0;
    while (p && *p && n < maxdim) {
        long a = 0, b = 0;
        int  m = sscanf(p, "%ld..%ld", &a, &b);
        if (m != 2)
            break;
        lo[n] = a;
        hi[n] = b;
        n++;
        p = strchr(p, ',');
        if (p)
            p++;
    }
    return n;
}

/* DS-03 Domain Firewall: deteksi penyempitan domain vs run sebelumnya
 * (SCOPE_LAUNDERING). Update state file (merge per fungsi). */
static void ex_domain_firewall(ex_domain *doms, int ndoms,
                               const drv_func *funcs, const char *source_sha)
{
    ex_state_entry entries[EXH_MAX_STATE];
    ex_state_entry newstate[EXH_MAX_STATE + DRV_MAX_FUNCS];
    int n = 0, nn = 0;
    int d, i, k;
    (void)source_sha;

    ex_state_read(entries, EXH_MAX_STATE, &n);
    /* salin state lama yang TIDAK ter-update */
    for (i = 0; i < n; i++) {
        int matched = 0;
        for (d = 0; d < ndoms; d++) {
            const drv_func *fn = &funcs[doms[d].fi];
            if (strcmp(entries[i].func, fn->name) == 0)
                matched = 1;
        }
        if (!matched && nn < EXH_MAX_STATE)
            newstate[nn++] = entries[i];
    }
    /* proses tiap domain: deteksi narrowing + simpan spec baru */
    for (d = 0; d < ndoms; d++) {
        ex_domain *dom = &doms[d];
        const drv_func *fn = &funcs[dom->fi];
        const ex_state_entry *prev = NULL;
        for (i = 0; i < n; i++) {
            if (strcmp(entries[i].func, fn->name) == 0) {
                prev = &entries[i];
                break;
            }
        }
        dom->narrowed = 0;
        dom->prev_spec[0] = '\0';
        if (prev && strcmp(prev->spec, dom->spec) != 0) {
            long olo[DRV_MAX_PARAMS], ohi[DRV_MAX_PARAMS];
            long nlo[DRV_MAX_PARAMS], nhi[DRV_MAX_PARAMS];
            int  on = ex_parse_spec(prev->spec, olo, ohi, DRV_MAX_PARAMS);
            int  dn = ex_parse_spec(dom->spec, nlo, nhi, DRV_MAX_PARAMS);
            if (on == dn && dn > 0) {
                int strictly = 0;
                int inside = 1;
                for (k = 0; k < dn; k++) {
                    if (nlo[k] < olo[k] || nhi[k] > ohi[k]) {
                        inside = 0;
                        break;
                    }
                    if (nlo[k] > olo[k] || nhi[k] < ohi[k])
                        strictly = 1;
                }
                if (inside && strictly) {
                    dom->narrowed = 1;
                    snprintf(dom->prev_spec, sizeof(dom->prev_spec), "%s",
                             prev->spec);
                }
            }
        }
        if (nn < EXH_MAX_STATE) {
            snprintf(newstate[nn].func, sizeof(newstate[nn].func), "%.63s",
                     fn->name);
            snprintf(newstate[nn].spec, sizeof(newstate[nn].spec), "%.159s",
                     dom->spec);
            newstate[nn].points = dom->points;
            nn++;
        }
    }
    ex_state_write(newstate, nn);
}

/* --- Gate A3: build + run harness enumerasi penuh (mirror driver) --- */
int myc_exhaustive_gate(const myc_request *req, const char *source,
                        size_t source_len, myc_result *res)
{
    drv_func funcs[DRV_MAX_FUNCS];
    ex_domain doms[DRV_MAX_FUNCS];
    int   nfuncs, ndoms;
    char *clang_path = NULL;
    char *harness = NULL;
    char *tmp_dir = NULL;
    char *exe_path = NULL;
    char *dll_src = NULL;
    char *dll_dst = NULL;
    size_t harness_len = 0;
    const char **build_argv = NULL;
    const char **run_argv = NULL;
    myc_proc_request preq;
    myc_proc_result  pres;
    int   ret = 0;
    int   n = 0, total = 0;
    long  total_points = 0;
    size_t max_out = req->max_output_bytes > 0
                         ? (size_t)req->max_output_bytes
                         : MYC_MAX_OUTPUT_BYTES;
    static const char *const BASE_FLAGS[] = {
        "-x", "c", "-", "-std=c11", "-O0", "-g",
        "-fsanitize=address,undefined",
        "-fno-sanitize-recover=all",
        NULL
    };
    static const char *const EXH_RUN_ENV[] = {
        "ASAN_OPTIONS=log_path=myc_exh_asan_rpt:abort_on_error=1:"
        "halt_on_error=1",
        "UBSAN_OPTIONS=log_path=myc_exh_ubsan_rpt:halt_on_error=1:"
        "print_stacktrace=1",
        "LC_ALL=C",
        NULL
    };

    myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_NOT_APPLICABLE,
                        NULL);

    /* 1. Scan fungsi ber-kontrak. */
    nfuncs = scan_contract_funcs(source, source_len, funcs, DRV_MAX_FUNCS);
    if (nfuncs == 0) {
        add_diag_drv(res, "exhaustive di-skip: tidak ada fungsi ber-kontrak");
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                            MYC_GATE_NOT_APPLICABLE,
                            "tidak ada fungsi ber-kontrak");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_SKIP,
                                "exhaustive di-skip: tanpa //@ requires");
        return 0;
    }

    /* 2. Pilih domain terbatas. */
    {
        char skip_note[256];
        skip_note[0] = '\0';
        ex_build_domains(funcs, nfuncs, doms, DRV_MAX_FUNCS, &ndoms,
                         skip_note, sizeof(skip_note));
        if (ndoms == 0) {
            add_diag_drv(res, skip_note[0]
                             ? skip_note
                             : "exhaustive di-skip: tidak ada fungsi "
                               "ber-domain enumerable");
            myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                MYC_GATE_NOT_APPLICABLE,
                                "domain tak ter-enumerasi");
            myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_EVIDENCE_SKIP,
                                    "exhaustive: domain tak ter-enumerasi");
            return 0;
        }
    }

    /* 3. Generate harness enumerasi penuh. */
    harness = gen_exhaustive_harness(source, source_len, funcs,
                                     doms, ndoms, res, &harness_len,
                                     &total_points);
    if (!harness) {
        add_diag_drv(res, "exhaustive di-skip: gagal generate harness");
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_INFRA_FAILED,
                            "gagal generate harness");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_ERROR,
                                "exhaustive: harness generation failed");
        return 0;
    }
    {
        char hex[65];
        sha256_hex(harness, harness_len, hex);
        res->exhaustive_harness_sha256 = myc_strdup(hex);
        if (!res->exhaustive_harness_sha256) {
            res->err = MYC_ERR_INTERNAL;
            myc_free(harness);
            return 0;
        }
    }

    /* 4. Cari clang. */
    clang_path = myc_find_executable(req->clang_program
                                         ? req->clang_program : "clang");
    if (!clang_path) {
        res->err = MYC_ERR_CLANG_NOT_FOUND;
        add_diag_drv(res, "exhaustive di-skip: clang tidak ditemukan");
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_UNAVAILABLE,
                            "clang tidak ditemukan");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_SKIP,
                                "exhaustive di-skip: clang hilang");
        myc_free(harness);
        return 0;
    }
    if (!res->clang_version)
        res->clang_version = myc_tool_version(clang_path);

    /* 5. Direktori temp + path exe. */
    tmp_dir = drv_make_temp_dir();
    if (!tmp_dir) {
        res->err = MYC_ERR_INTERNAL;
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_INFRA_FAILED,
                            "gagal membuat direktori temp");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_ERROR,
                                "exhaustive: temp dir gagal");
        myc_free(harness);
        myc_free(clang_path);
        return 0;
    }
    exe_path = drv_join_path(tmp_dir, "myc_exh.exe");
    if (!exe_path) {
        res->err = MYC_ERR_INTERNAL;
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_INFRA_FAILED,
                            "gagal membuat path exe");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_ERROR,
                                "exhaustive: exe path gagal");
        myc_free(harness);
        myc_free(clang_path);
        myc_free(tmp_dir);
        return 0;
    }

    /* 6. Build harness (source via stdin). */
    {
        int bfl = 0;
        total = 1;
        while (BASE_FLAGS[bfl++])
            total++;
        total += 2 + 1;
        build_argv = (const char **)myc_malloc(sizeof(char *) * (size_t)total);
        if (!build_argv) {
            res->err = MYC_ERR_INTERNAL;
            goto out;
        }
        build_argv[n++] = clang_path;
        for (bfl = 0; BASE_FLAGS[bfl]; bfl++)
            build_argv[n++] = BASE_FLAGS[bfl];
        build_argv[n++] = "-o";
        build_argv[n++] = exe_path;
        build_argv[n] = NULL;

        memset(&preq, 0, sizeof(preq));
        preq.argv = build_argv;
        preq.cwd = req->cwd;
        preq.stdin_data = harness;
        preq.stdin_len = harness_len;
        preq.timeout_ms = req->timeout_ms;
        preq.max_output_bytes = max_out;
        if (!myc_proc_run(&preq, &pres)) {
            res->err = pres.timed_out ? MYC_ERR_TIMEOUT
                                      : MYC_ERR_EXECUTE_FAILED;
            if (pres.timed_out) {
                res->verdict = MC_TIMEOUT;
                res->duration_ms += pres.duration_ms;
                myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_GATE_INCONCLUSIVE,
                                    "build harness timeout");
                myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                        MYC_EVIDENCE_ERROR,
                                        "exhaustive: build timeout");
            } else {
                myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_GATE_INFRA_FAILED,
                                    "build harness exec failed");
                myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                        MYC_EVIDENCE_ERROR,
                                        "exhaustive: build exec failed");
            }
            myc_proc_result_free(&pres);
            myc_free(build_argv);
            goto out;
        }
        res->duration_ms += pres.duration_ms;
        if (pres.exit_code != 0) {
            char note[512];
            const char *fe = pres.stderr_data && pres.stderr_data[0]
                                 ? pres.stderr_data
                                 : "build harness exhaustive gagal";
            snprintf(note, sizeof(note),
                     "exhaustive di-skip: build harness gagal: %.300s", fe);
            add_diag_drv(res, note);
            myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                MYC_GATE_INFRA_FAILED, note);
            myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_EVIDENCE_SKIP, note);
            myc_proc_result_free(&pres);
            myc_free(build_argv);
            goto out_skip;
        }
        myc_proc_result_free(&pres);
        myc_free(build_argv);
    }

    /* 7. Windows: salin runtime DLL ASan. */
#ifdef _WIN32
    {
        dll_src = drv_asan_dll_path(clang_path);
        if (dll_src) {
            dll_dst = drv_join_path(tmp_dir, ASAN_DLL_NAME);
            if (dll_dst && !drv_copy_file(dll_src, dll_dst))
                add_diag_drv(res, "exhaustive: gagal menyalin ASan DLL");
        } else {
            add_diag_drv(res, "exhaustive: runtime ASan DLL tidak ditemukan");
        }
    }
#endif

    /* 8. Eksekusi terkendali. */
    run_argv = (const char **)myc_malloc(sizeof(char *) * 2);
    if (!run_argv) {
        res->err = MYC_ERR_INTERNAL;
        goto out;
    }
    run_argv[0] = exe_path;
    run_argv[1] = NULL;
    memset(&preq, 0, sizeof(preq));
    preq.argv = run_argv;
    preq.cwd = tmp_dir;
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = max_out;
    preq.env = EXH_RUN_ENV;
    if (!myc_proc_run(&preq, &pres)) {
        res->err = pres.timed_out ? MYC_ERR_TIMEOUT
                                  : MYC_ERR_EXECUTE_FAILED;
        if (pres.timed_out) {
            res->verdict = MC_TIMEOUT;
            res->duration_ms += pres.duration_ms;
            myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                MYC_GATE_INCONCLUSIVE, "run timeout");
            myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_EVIDENCE_ERROR,
                                    "exhaustive: run timeout");
        } else {
            myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                MYC_GATE_INFRA_FAILED, "run exec failed");
            myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_EVIDENCE_ERROR,
                                    "exhaustive: run exec failed");
        }
        myc_proc_result_free(&pres);
        myc_free(run_argv);
        goto out;
    }
    res->duration_ms += pres.duration_ms;
    res->ran_exhaustive = 1;
    res->run_timed_out = pres.timed_out;
    res->exit_code = pres.exit_code;
    myc_free(res->exhaustive_stdout_text);
    myc_free(res->exhaustive_stderr_text);
    res->exhaustive_stdout_text = pres.stdout_data;
    pres.stdout_data = NULL;
    res->exhaustive_stderr_text = pres.stderr_data;
    pres.stderr_data = NULL;
    myc_proc_result_free(&pres);
    myc_free(run_argv);

    /* 9. Parse summary "EXH run=N skip=M". */
    res->exhaustive_funcs = ndoms;
    res->exhaustive_cases = 0;
    res->exhaustive_skipped = 0;
    res->exhaustive_points = total_points;
    if (res->exhaustive_stdout_text) {
        const char *p = strstr(res->exhaustive_stdout_text, "EXH run=");
        if (p) {
            int run = 0, skip = 0;
            sscanf(p, "EXH run=%d skip=%d", &run, &skip);
            res->exhaustive_cases = run;
            res->exhaustive_skipped = skip;
        }
    }

    if (res->run_timed_out) {
        res->verdict = MC_TIMEOUT;
        res->err = MYC_ERR_TIMEOUT;
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                            MYC_GATE_INCONCLUSIVE, "run timeout");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_ERROR,
                                "exhaustive: run timeout");
        goto out;
    }

    /* 10. Finding = bukti report sanitizer / assert (non-spoofable).
     * PR-008 (INV-006): report hanya bukti bila exit != 0 (spoof file
     * report palsu + exit 0 ditolak; konsisten gate run/driver). */
    {
        char *asan_rpt = myc_read_sanitizer_report(tmp_dir,
                                                   "myc_exh_asan_rpt");
        char *ubsan_rpt = myc_read_sanitizer_report(tmp_dir,
                                                    "myc_exh_ubsan_rpt");
        int   report_evidence = ((asan_rpt != NULL) || (ubsan_rpt != NULL)) &&
                                res->exit_code != 0;
        int   omarker = drv_marker_found(res->exhaustive_stdout_text,
                                         res->exhaustive_stderr_text);
        int   ex_assert_fail = res->exhaustive_stderr_text &&
                               strstr(res->exhaustive_stderr_text,
                                      "EXH_ASSERT_FAIL") != NULL;
        myc_free(asan_rpt);
        myc_free(ubsan_rpt);
        myc_remove_sanitizer_reports(tmp_dir, "myc_exh_asan_rpt");
        myc_remove_sanitizer_reports(tmp_dir, "myc_exh_ubsan_rpt");
        if (report_evidence || ex_assert_fail ||
            (omarker && res->exit_code != 0)) {
            add_diag_drv(res, "exhaustive: counterexample ditemukan pada "
                              "domain dideklarasikan");
            /* Fase 6: simpan counterexample sebagai seed regression.
             * MYC-AUDIT-065: skip saat replay (no_regress) — replay
             * adalah pass verifikasi, corpus tidak boleh bermutasi. */
            if (!req->no_regress)
                myc_regress_save(res, source, source_len,
                                 MYC_REG_EXHAUSTIVE, "counterexample", 0);
            res->verdict = MC_DRIVER_VIOLATION;
            res->err = MYC_ERR_DRIVER_VIOLATION;
            myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                                MYC_GATE_COMPLETED_FINDINGS,
                                "counterexample pada domain dideklarasikan");
            myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                    MYC_EVIDENCE_FINDING,
                                    "exhaustive: DRIVER_VIOLATION "
                                    "(counterexample enumeratif)");
            if (!res->witness) {
                res->witness = (myc_witness *)myc_malloc(sizeof(myc_witness));
                if (res->witness) {
                    myc_witness_init(res->witness);
                    res->witness->violation_kind =
                        myc_result_arena_dup(res, "exhaustive-counterexample",
                                             0);
                    res->witness->violation_msg =
                        myc_result_arena_dup(res,
                            "exhaustive: counterexample pada domain "
                            "dideklarasikan (enumerasi penuh)", 0);
                    res->witness->backend =
                        myc_result_arena_dup(res, "exhaustive", 0);
                    res->witness->operation =
                        myc_result_arena_dup(res,
                            "exhaustive: enumerasi penuh domain", 0);
                    res->witness->pre_state =
                        myc_result_arena_dup(res,
                            "exhaustive: domain kontrak dideklarasikan", 0);
                }
            }
            goto out;
        }
        if (omarker) {
            add_diag_drv(res, "exhaustive: teks mirip marker sanitizer "
                              "tetapi exit 0 -- diabaikan");
        }
    }
    if (res->exit_code != 0) {
        add_diag_drv(res, "exhaustive: run keluar non-zero tanpa "
                          "laporan sanitizer");
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_INCONCLUSIVE,
                            "exit non-zero tanpa sanitizer");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_SKIP,
                                "exhaustive: exit non-zero tanpa marker");
        goto out_skip;
    }
    if (res->exhaustive_cases == 0) {
        add_diag_drv(res, "exhaustive: semua titik domain dilewati guard");
        myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE,
                            MYC_GATE_NOT_APPLICABLE,
                            "semua titik dilewati guard requires");
        myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                MYC_EVIDENCE_SKIP,
                                "exhaustive: 0 titik tereksekusi");
        goto out_skip;
    }

    /* 11. Bersih: P1 EXHAUSTIVE untuk domain dinyatakan. DS-03 firewall. */
    {
        char spec_all[512];
        size_t off = 0;
        int d;
        spec_all[0] = '\0';
        for (d = 0; d < ndoms; d++) {
            const drv_func *fn = &funcs[doms[d].fi];
            int r = snprintf(spec_all + off, sizeof(spec_all) - off,
                             "%s%s:%s", d ? ";" : "", fn->name,
                             doms[d].spec);
            if (r > 0)
                off += (size_t)r;
            if (off >= sizeof(spec_all))
                off = sizeof(spec_all) - 1;
        }
        sha256_hex(spec_all, off, res->exhaustive_domain_hash);
        ex_domain_firewall(doms, ndoms, funcs, res->source_sha256);
        {
            int d;
            int launder = 0;
            char rep[1024];
            size_t roff = 0;
            res->exhaustive_laundering = 0;
            roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
                "exhaustive (A3): P1 EXHAUSTIVE untuk domain dideklarasikan\n");
            for (d = 0; d < ndoms; d++) {
                const drv_func *fn = &funcs[doms[d].fi];
                if (doms[d].narrowed) {
                    launder = 1;
                    res->exhaustive_laundering = 1;
                }
                roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
                    "  %s: domain %s (%ld titik)%s\n", fn->name,
                    doms[d].spec, doms[d].points,
                    doms[d].narrowed ? " -- SCOPE_LAUNDERING "
                        "(dipersempit dari " : "");
                if (doms[d].narrowed && roff < sizeof(rep))
                    roff += (size_t)snprintf(rep + roff,
                                             sizeof(rep) - roff,
                                             "%s)", doms[d].prev_spec);
                if (roff >= sizeof(rep))
                    roff = sizeof(rep) - 1;
            }
            roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
                "  domain_hash: %s\n  bukan bukti di luar domain "
                "dideklarasikan\n", res->exhaustive_domain_hash);
            if (roff >= sizeof(rep))
                roff = sizeof(rep) - 1;
            res->exhaustive_report = myc_result_arena_dup(res, rep, 0);
            if (launder) {
                add_diag_drv(res, "exhaustive: SCOPE_LAUNDERING -- domain "
                                  "kontrak dipersempit vs run sebelumnya "
                                  "(proof laundering)");
                myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE,
                                        MYC_EVIDENCE_DIAGNOSTIC,
                                        "exhaustive: SCOPE_LAUNDERING");
            }
        }
    }

    ret = 1;
    myc_gate_set_status(res, MYC_GATE_EXHAUSTIVE, MYC_GATE_COMPLETED_CLEAN,
                        "P1 EXHAUSTIVE (domain dideklarasikan)");
    myc_result_add_evidence(res, MYC_GATE_EXHAUSTIVE, MYC_EVIDENCE_GATE_END,
                            "exhaustive: clean (enumerasi penuh)");
    goto out;

out_skip:
    ret = 0;

out:
    if (harness) myc_free(harness);
    if (dll_dst) myc_free(dll_dst);
    if (dll_src) myc_free(dll_src);
    if (exe_path) {
        remove(exe_path);
        myc_free(exe_path);
    }
    if (tmp_dir) {
        static const char *const artifacts[] = { ASAN_DLL_NAME,
                                                 "myc_exh.pdb", NULL };
        int ai;
        for (ai = 0; artifacts[ai]; ai++) {
            char *p = drv_join_path(tmp_dir, artifacts[ai]);
            if (p) {
                remove(p);
                myc_free(p);
            }
        }
        myc_rmdir(tmp_dir);
        myc_free(tmp_dir);
    }
    myc_free(clang_path);
    return ret;
}

