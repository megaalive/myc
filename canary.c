/* canary.c -- Canary Swarm (Fase 6, Self-Challenge)
 *
 * Menjalankan canary per backend: source minimal dengan bug yang HARUS
 * terdeteksi (canary positif) dan source aman yang HARUS bersih (canary
 * negatif). Kalau canary positif tidak terdeteksi, backend TIDAK bisa
 * dipercaya (klaim bersihnya diragukan) -- ini menutup celah "backend
 * rusak diam-diam memberi verdict OK palsu" (false clean).
 *
 * Semua canary self-contained (ingress MEMORY), tanpa fixture file.
 */
#include "canary.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myc.h"

static const myc_canary CANARIES[] = {
    /* ---- compile: canary negatif + positif ---- */
    { "compile", "compile-clean",
      "source C valid harus compile bersih (MC_OK)",
      "int main(void) { return 0; }\n",
      0, MC_OK, NULL },

    { "compile", "compile-syntax-error",
      "source C rusak harus ditolak (MC_COMPILE_ERROR), bukan dibiarkan",
      "int main(void) { return syntax_broken( }\n",
      0, MC_COMPILE_ERROR, NULL },

    /* ---- analyzer (gcc -fanalyzer): jalur interprocedural ---- */
    { "analyzer", "analyzer-null-deref-interproc",
      "-fanalyzer harus menangkap null-deref LINTAS FUNGSI (poke(q=0))",
      "static void poke(int *p) { *p = 1; }\n"
      "int main(void) { int *q = 0; poke(q); return 0; }\n",
      MYC_CANARYF_ANALYZER, MC_COMPILE_ERROR, "fanalyzer finding" },

    /* ---- run (clang ASan/UBSan): heap OOB runtime ---- */
    { "run", "run-heap-oob-write",
      "ASan runtime harus menangkap heap-buffer-overflow (p[4] pada 16 B)",
      "#include <stdlib.h>\n"
      "#include <string.h>\n"
      "int main(void) {\n"
      "    int *p = (int*)malloc(16);\n"
      "    memset(p, 0, 16);\n"
      "    p[4] = 1;   /* di luar 4 int */\n"
      "    free(p);\n"
      "    return 0;\n"
      "}\n",
      MYC_CANARYF_RUN, MC_RUNTIME_VIOLATION, "AddressSanitizer" },

    /* ---- driver (D2): kasus tepi dari kontrak ---- */
    { "driver", "driver-contract-oob",
      "--driver harus menemukan OOB pada tepi domain kontrak (n == 4)",
      "//@ requires n <= 4;\n"
      "int bad_read(const int *a, int n) { return a[n]; }\n",
      MYC_CANARYF_DRIVER, MC_DRIVER_VIOLATION, NULL },

    /* ---- exhaustive (A3): counterexample + proof ---- */
    { "exhaustive", "exhaustive-counterexample",
      "--exhaustive harus MENEMUKAN counterexample untuk ensures salah",
      "//@ requires n >= 0 && n <= 64;\n"
      "//@ ensures n < 64;\n"
      "int clamp_wrong(int n)\n"
      "{\n"
      "    if (n < 0) return 0;\n"
      "    if (n > 64) return 64;\n"
      "    return n;\n"
      "}\n",
      MYC_CANARYF_EXHAUSTIVE, MC_DRIVER_VIOLATION, "counterexample" },

    { "exhaustive", "exhaustive-clean-proof",
      "--exhaustive harus menyatakan P1 EXHAUSTIVE pada domain benar",
      "//@ requires n >= 0 && n <= 64;\n"
      "//@ ensures n >= 0 && n <= 64;\n"
      "int clamp_u8(int n)\n"
      "{\n"
      "    if (n < 0) return 0;\n"
      "    if (n > 64) return 64;\n"
      "    return n;\n"
      "}\n",
      MYC_CANARYF_EXHAUSTIVE, MC_OK, "P1 EXHAUSTIVE" },

    /* ---- fuzz (D1): crash reproduksibel dalam domain kontrak ---- */
    { "fuzz", "fuzz-div-by-zero",
      "--fuzz harus menemukan crash (div-0) di dalam domain kontrak",
      "//@ requires n >= 0 && n <= 3;\n"
      "int fdiv(int n) { return 10 / (n - 2); }\n",
      MYC_CANARYF_FUZZ, MC_DRIVER_VIOLATION, "crash" },

    /* ---- mutate (B5): mutan harus tertangkap (0 GAP) ---- */
    { "mutate", "mutate-guards-caught",
      "--mutate-audit harus menangkap SEMUA mutan guard (mutation gap 0)",
      "//@ requires idx >= 0 && idx <= 15;\n"
      "//@ ensures idx >= 0;\n"
      "int peek_ok(const int *tbl, int idx)\n"
      "{\n"
      "    if (idx >= 16) return -1;\n"
      "    if (idx < 0) return -1;\n"
      "    return tbl[idx];\n"
      "}\n"
      "int main(void)\n"
      "{\n"
      "    static int t[16];\n"
      "    int i;\n"
      "    int acc = 0;\n"
      "    for (i = -5; i <= 20; i++) acc += peek_ok(t, i);\n"
      "    return acc;\n"
      "}\n",
      MYC_CANARYF_MUTATE, MC_OK, "0 GAP" },

    /* ---- stack (C2): rekursi tak terbatas terlihat ---- */
    { "stack", "stack-recursion-detected",
      "--stack harus MELIHAT cycle rekursi (stack tak terbatas)",
      "int f(int n) { return n <= 0 ? 0 : f(n - 1); }\n"
      "int main(void) { return f(10); }\n",
      MYC_CANARYF_STACK, MC_OK, "cycle di call graph" },

    /* ---- lint: canary negatif (tanpa false-positive) ---- */
    { "lint", "lint-clean-no-false-positive",
      "lint heuristik tidak boleh memunculkan finding pada source aman",
      "int main(void) { return 0; }\n",
      0, MC_OK, NULL },
};

const myc_canary *myc_canary_table(int *count)
{
    if (count)
        *count = (int)(sizeof(CANARIES) / sizeof(CANARIES[0]));
    return CANARIES;
}

const char *const *myc_canary_backends(int *count)
{
    static const char *const BACKENDS[] = {
        "compile", "analyzer", "run", "driver", "exhaustive",
        "fuzz", "mutate", "stack", "lint", NULL
    };
    int n = 0;
    while (BACKENDS[n])
        n++;
    if (count)
        *count = n;
    return BACKENDS;
}

static void canary_set_flags(myc_request *req, int flags)
{
    if (flags & MYC_CANARYF_ANALYZER)
        req->run_analyzer = 1;
    if (flags & MYC_CANARYF_RUN)
        req->run = 1;
    if (flags & MYC_CANARYF_DRIVER)
        req->driver = 1;
    if (flags & MYC_CANARYF_EXHAUSTIVE)
        req->exhaustive = 1;
    if (flags & MYC_CANARYF_FUZZ) {
        req->fuzz = 1;
        req->fuzz_iters = 2000;   /* cukup kecil untuk determinisme cepat */
    }
    if (flags & MYC_CANARYF_MUTATE)
        req->mutate_audit = 1;
    if (flags & MYC_CANARYF_STACK)
        req->stack = 1;
}

/* Cari substring wajib pada evidence ledger ATAU report spesifik gate
 * (arena) -- bukti gate benar-benar melihat hal yang dimaksud, bukan
 * hanya verdict cocok. Field yang di-scan: evidence, exhaustive_report,
 * stack_report, fuzz_report, mutate_report. */
static int canary_text_found(const myc_result *res, const char *needle)
{
    size_t i;
    const char *scan[] = {
        res->exhaustive_report,
        res->stack_report,
        res->fuzz_report,
        res->mutate_report,
        NULL
    };
    if (!needle || !needle[0])
        return 1;
    for (i = 0; i < res->evidence_count; i++) {
        const myc_evidence_event *e = &res->evidence[i];
        if (e->message && strstr(e->message, needle))
            return 1;
    }
    /* CATATAN: jangan hentikan loop di NULL pertama -- field report per
     * gate yang TIDAK dijalankan ber-NULL, tapi field lain masih harus
     * diperiksa. Iterasi 4 elemen eksplisit. */
    for (i = 0; i < 4; i++) {
        if (scan[i] && strstr(scan[i], needle))
            return 1;
    }
    return 0;
}

static const char *canary_verdict_name(int verdict)
{
    switch (verdict) {
    case MC_OK:              return "OK";
    case MC_COMPILE_ERROR:   return "COMPILE_ERROR";
    case MC_RUNTIME_VIOLATION: return "RUNTIME_VIOLATION";
    case MC_DRIVER_VIOLATION: return "DRIVER_VIOLATION";
    case MC_INCONCLUSIVE:    return "INCONCLUSIVE";
    case MC_TIMEOUT:         return "TIMEOUT";
    default:                 return "OTHER";
    }
}

int myc_canary_run(const char *backend, FILE *out)
{
    int ncan = 0;
    const myc_canary *t = myc_canary_table(&ncan);
    int npass = 0, nfail = 0, nrun = 0;
    int i;

    for (i = 0; i < ncan; i++) {
        const myc_canary *c = &t[i];
        myc_request req;
        myc_result res;
        int vok, tok, pass;
        size_t j;

        if (backend && strcmp(backend, c->backend) != 0)
            continue;

        myc_request_init(&req);
        req.input.kind = MYC_SOURCE_MEMORY;
        req.input.data = c->source;
        req.input.len = strlen(c->source);
        req.no_cache = 1;
        req.timeout_ms = 60000;
        canary_set_flags(&req, c->flags);

        myc_result_init(&res);
        myc_run(&req, &res);

        vok = ((int)res.verdict == c->expect_verdict);
        tok = canary_text_found(&res, c->expect_text);
        pass = vok && tok;
        nrun++;

        if (out) {
            fprintf(out, "[%s] %-10s %-28s %s\n",
                    pass ? "OK" : "FAIL", c->backend, c->name,
                    c->desc);
            if (!pass) {
                fprintf(out, "        expected verdict=%s%s%s, got=%s\n",
                        canary_verdict_name(c->expect_verdict),
                        c->expect_text ? " text=\"" : "",
                        c->expect_text ? c->expect_text : "",
                        canary_verdict_name(res.verdict));
                if (vok && !tok)
                    fprintf(out, "        verdict cocok tapi evidence TIDAK memuat teks wajib\n");
                for (j = 0; j < res.evidence_count; j++) {
                    const myc_evidence_event *e = &res.evidence[j];
                    if (e->message && e->message[0]) {
                        fprintf(out, "        evidence: %.120s\n", e->message);
                        if (j >= 6)
                            break;
                    }
                }
            }
        }
        if (pass)
            npass++;
        else
            nfail++;

        myc_result_free(&res);
    }

    if (out && nrun > 0) {
        fprintf(out, "\ncanary swarm: %d/%d PASS", npass, npass + nfail);
        if (nfail > 0)
            fprintf(out, " -- %d canary GAGAL: backend tidak terpercaya!\n",
                    nfail);
        else
            fprintf(out, " -- semua backend terverifikasi hidup\n");
    }
    return nfail;
}
