/*
 * reducer_exhaustive.c -- PR-003: test exhaustif verdict reducer.
 *
 * Memanggil myc_reduce_verdict() (gate.c) LANGSUNG dengan kombinasi typed
 * gate status, lalu membandingkan dengan referensi yang mendokumentasikan
 * semantik reducer. Meng-encode invariant produksi dari
 * docs/production-invariants.md:
 *
 *   INV-001  no evidence -> no clean claim
 *            (requested gate UNAVAILABLE/INFRA_FAILED/INCONCLUSIVE
 *             -> INCONCLUSIVE + debt, TIDAK pernah OK)
 *   INV-002  bug evidence dominates incompleteness
 *            (FINDINGS + UNAVAILABLE -> VIOLATION, bukan INCONCLUSIVE)
 *   INV-003  heuristics cannot create hard verdicts
 *            (COMPLETED_OBSERVATIONS benign -> OK/COMPLETE/CLEAN, tanpa debt)
 *   INV-011  unknown enum/state fails closed
 *            (status di luar enum -> INCONCLUSIVE, TIDAK pernah clean)
 *
 * Semantik referensi SALINAN DARI gate.c myc_reduce_verdict() (bukan
 * duplikasi logika produksi di luar reducer): tujuan test ini adalah
 * (a) memaksa SETIAP kombinasi status dijalankan (crash/UB terdeteksi),
 * (b) mengunci perilaku saat ini secara eksplisit (regresi bila reducer
 * berubah), dan (c) meng-encode invariant INV-001/002/003/011 sebagai
 * assert langsung -- bila reduksi berubah, test gagal di sini, bukan
 * menunggu laporan.
 *
 * Build (sama dengan oom_guards, butuh seluruh pipeline karena myc.c):
 *   gcc -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN \
 *       -o reducer_exhaustive reducer_exhaustive.c $SRCS
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myc.h"
#include "gate.h"

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond, fmt, ...) do {                                    \
        if (cond) {                                                   \
            g_pass++;                                                 \
        } else {                                                      \
            fprintf(stderr, "[FAIL] " fmt "\n", ##__VA_ARGS__);       \
            g_fail++;                                                 \
        }                                                             \
    } while (0)

/* --- referensi: semantik reducer (salinan gate.c L490-620) ------------ */

typedef struct {
    myc_verdict      verdict;
    myc_completeness completeness;
    myc_finding      finding;
} expect_t;

/* `sts` = status gate yang REQUESTED (myc_gate_set_status selalu
 * menandai requested=1); `have_witness` = res->witness diset. */
static expect_t ref_reduce(const myc_gate_status *sts, int n,
                           int have_witness)
{
    int i;
    int has_findings = 0;
    int has_incomplete = 0;
    expect_t e;

    for (i = 0; i < n; i++) {
        switch (sts[i]) {
        case MYC_GATE_COMPLETED_FINDINGS:
            has_findings = 1;
            break;
        case MYC_GATE_COMPLETED_OBSERVATIONS:  /* INV-003: benign */
        case MYC_GATE_COMPLETED_CLEAN:
        case MYC_GATE_NOT_APPLICABLE:
            break;
        case MYC_GATE_UNAVAILABLE:
        case MYC_GATE_INFRA_FAILED:
        case MYC_GATE_INCONCLUSIVE:
            has_incomplete = 1;                /* INV-001 */
            break;
        default:
            has_incomplete = 1;                /* INV-011: unknown fails closed */
            break;
        }
    }

    e.verdict = has_findings ? MC_VIOLATION
              : has_incomplete ? MC_INCONCLUSIVE : MC_OK;
    e.completeness = has_incomplete
                     ? MYC_COMPLETENESS_INCOMPLETE
                     : MYC_COMPLETENESS_COMPLETE;
    e.finding = has_findings ? MYC_FINDING_FINDINGS
              : has_incomplete ? MYC_FINDING_INCONCLUSIVE
              : MYC_FINDING_CLEAN;
    /* downgrade hard finding tanpa witness (gate.c L611-617): verdict
     * tetap violation, finding diturunkan ke INCONCLUSIVE. */
    if (has_findings && !have_witness)
        e.finding = MYC_FINDING_INCONCLUSIVE;
    return e;
}

/* --- helper ------------------------------------------------------------ */

static void set_gates(myc_result *res, const myc_gate_id *ids,
                      const myc_gate_status *sts, int n)
{
    int i;
    for (i = 0; i < n; i++)
        myc_gate_set_status(res, ids[i], sts[i], NULL);
}

static int debt_has(const myc_result *res, myc_debt_type t)
{
    size_t i;
    for (i = 0; i < res->debt_count; i++)
        if (res->debt[i].type == t)
            return 1;
    return 0;
}

/* Jalankan reducer pada satu set gate; bandingkan dengan referensi. */
static void run_case(const myc_gate_id *ids, const myc_gate_status *sts,
                     int n, int have_witness, const char *label)
{
    myc_result res;
    expect_t   e;
    int        i;
    int        want_debt;

    e = ref_reduce(sts, n, have_witness);

    myc_result_init(&res);
    set_gates(&res, ids, sts, n);
    if (have_witness) {
        res.witness = (myc_witness *)calloc(1, sizeof(myc_witness));
        if (!res.witness) {
            fprintf(stderr, "[FAIL] %s: calloc witness gagal\n", label);
            g_fail++;
            myc_result_free(&res);
            return;
        }
    }
    myc_reduce_verdict(&res);

    CHECK(res.verdict == e.verdict,
          "%s: verdict=%s (harap %s)",
          label, myc_verdict_name(res.verdict), myc_verdict_name(e.verdict));
    CHECK(res.completeness == e.completeness,
          "%s: completeness=%d (harap %d)", label,
          (int)res.completeness, (int)e.completeness);
    CHECK(res.finding == e.finding,
          "%s: finding=%d (harap %d)", label,
          (int)res.finding, (int)e.finding);

    /* INV-001/002 debt: ada status no-evidence -> harus ada debt; tidak
     * ada -> harus nol (fixture ini tidak memicu debt scope lain). */
    want_debt = 0;
    for (i = 0; i < n; i++) {
        if (sts[i] == MYC_GATE_UNAVAILABLE ||
            sts[i] == MYC_GATE_INFRA_FAILED ||
            sts[i] == MYC_GATE_INCONCLUSIVE)
            want_debt = 1;
    }
    CHECK((res.debt_count > 0) == want_debt,
          "%s: debt_count=%zu (harap %s)", label, res.debt_count,
          want_debt ? ">0" : "0");

    myc_result_free(&res);
}

/* --- test -------------------------------------------------------------- */

/* Gate kritis: satu per dimensi assurance. */
static const myc_gate_id CRITICAL[] = {
    MYC_GATE_COMPILE,   /* C */
    MYC_GATE_ANALYZER,  /* S */
    MYC_GATE_RUNTIME,   /* R */
    MYC_GATE_PROVE,     /* P */
    MYC_GATE_CHECKED,   /* B */
    MYC_GATE_DRIVER,    /* D */
    MYC_GATE_FILC       /* F */
};
#define N_CRITICAL ((int)(sizeof(CRITICAL) / sizeof(CRITICAL[0])))

/* Semua status yang bisa di-set gate (NOT_REQUESTED tidak pernah diset
 * myc_gate_set_status; dimunculkan terpisah sebagai kasus corner). */
static const myc_gate_status STS[] = {
    MYC_GATE_NOT_APPLICABLE,
    MYC_GATE_UNAVAILABLE,
    MYC_GATE_INFRA_FAILED,
    MYC_GATE_INCONCLUSIVE,
    MYC_GATE_COMPLETED_CLEAN,
    MYC_GATE_COMPLETED_FINDINGS,
    MYC_GATE_COMPLETED_OBSERVATIONS
};
#define N_STS ((int)(sizeof(STS) / sizeof(STS[0])))

/* Status "no evidence" (INV-001). */
static const myc_gate_status NOE[] = {
    MYC_GATE_UNAVAILABLE,
    MYC_GATE_INFRA_FAILED,
    MYC_GATE_INCONCLUSIVE
};
#define N_NOE ((int)(sizeof(NOE) / sizeof(NOE[0])))

int main(void)
{
    char label[160];

    /* ---- T1 (INV-001): tiap gate kritis x tiap status no-evidence
     *      -> INCONCLUSIVE, TIDAK pernah OK, + debt tipe yang benar. */
    {
        int g, s;
        for (g = 0; g < N_CRITICAL; g++) {
            for (s = 0; s < N_NOE; s++) {
                myc_result res;
                myc_gate_status st = NOE[s];
                myc_debt_type  dt = st == MYC_GATE_UNAVAILABLE
                                        ? MYC_DEBT_GATE_UNAVAILABLE
                                    : st == MYC_GATE_INFRA_FAILED
                                        ? MYC_DEBT_GATE_INFRA_FAILED
                                        : MYC_DEBT_GATE_INCONCLUSIVE;
                snprintf(label, sizeof(label),
                         "INV-001 %s %s", myc_gate_id_short(CRITICAL[g]),
                         myc_debt_type_name(dt));
                myc_result_init(&res);
                myc_gate_set_status(&res, CRITICAL[g], st, NULL);
                myc_reduce_verdict(&res);
                CHECK(res.verdict == MC_INCONCLUSIVE,
                      "%s: verdict INCONCLUSIVE (got %s)", label,
                      myc_verdict_name(res.verdict));
                CHECK(res.completeness == MYC_COMPLETENESS_INCOMPLETE,
                      "%s: completeness INCOMPLETE", label);
                CHECK(res.finding == MYC_FINDING_INCONCLUSIVE,
                      "%s: finding INCONCLUSIVE", label);
                CHECK(debt_has(&res, dt),
                      "%s: debt %s ada", label, myc_debt_type_name(dt));
                myc_result_free(&res);
            }
        }
    }

    /* ---- T2 (benign): NOT_APPLICABLE / COMPLETED_CLEAN -> OK,
     *      COMPLETE, CLEAN, tanpa debt. */
    {
        int g, s;
        const myc_gate_status BENIGN[] = { MYC_GATE_NOT_APPLICABLE,
                                           MYC_GATE_COMPLETED_CLEAN };
        for (g = 0; g < N_CRITICAL; g++) {
            for (s = 0; s < (int)(sizeof(BENIGN) / sizeof(BENIGN[0])); s++) {
                myc_result res;
                snprintf(label, sizeof(label), "benign %s st=%d",
                         myc_gate_id_short(CRITICAL[g]), (int)BENIGN[s]);
                myc_result_init(&res);
                myc_gate_set_status(&res, CRITICAL[g], BENIGN[s], NULL);
                myc_reduce_verdict(&res);
                CHECK(res.verdict == MC_OK, "%s: verdict OK (got %s)",
                      label, myc_verdict_name(res.verdict));
                CHECK(res.completeness == MYC_COMPLETENESS_COMPLETE,
                      "%s: completeness COMPLETE", label);
                CHECK(res.finding == MYC_FINDING_CLEAN,
                      "%s: finding CLEAN", label);
                CHECK(res.debt_count == 0, "%s: tanpa debt", label);
                myc_result_free(&res);
            }
        }
    }

    /* ---- T3 (INV-003): observasi heuristik TIDAK pernah hard verdict.
     *      LINT/NEGATIVE COMPLETED_OBSERVATIONS -> OK/COMPLETE/CLEAN,
     *      tanpa debt (prinsip MYC-AUDIT-014). */
    {
        const myc_gate_id OBS_GATES[] = { MYC_GATE_LINT, MYC_GATE_NEGATIVE };
        int i;
        for (i = 0; i < (int)(sizeof(OBS_GATES) / sizeof(OBS_GATES[0])); i++) {
            myc_result res;
            snprintf(label, sizeof(label), "INV-003 %s observations",
                     myc_gate_id_short(OBS_GATES[i]));
            myc_result_init(&res);
            myc_gate_set_status(&res, OBS_GATES[i],
                                MYC_GATE_COMPLETED_OBSERVATIONS, NULL);
            myc_reduce_verdict(&res);
            CHECK(res.verdict == MC_OK, "%s: verdict OK (got %s)", label,
                  myc_verdict_name(res.verdict));
            CHECK(res.completeness == MYC_COMPLETENESS_COMPLETE,
                  "%s: completeness COMPLETE", label);
            CHECK(res.finding == MYC_FINDING_CLEAN,
                  "%s: finding CLEAN", label);
            CHECK(res.debt_count == 0, "%s: tanpa debt", label);
            myc_result_free(&res);
        }
    }

    /* ---- T4 (INV-002): bug evidence mendominasi incompleteness.
     *      RUNTIME FINDINGS (dgn witness) + PROVE UNAVAILABLE
     *      -> VIOLATION (bukan INCONCLUSIVE) + completeness INCOMPLETE
     *      + debt GATE-UNAVAILABLE. */
    {
        myc_result res;
        myc_gate_id ids[2] = { MYC_GATE_RUNTIME, MYC_GATE_PROVE };
        myc_gate_status sts[2] = { MYC_GATE_COMPLETED_FINDINGS,
                                   MYC_GATE_UNAVAILABLE };
        myc_result_init(&res);
        res.witness = (myc_witness *)calloc(1, sizeof(myc_witness));
        if (res.witness) {
            myc_gate_set_status(&res, ids[0], sts[0], NULL);
            myc_gate_set_status(&res, ids[1], sts[1], NULL);
            myc_reduce_verdict(&res);
            CHECK(res.verdict == MC_VIOLATION,
                  "INV-002: BUG+INCOMPLETE -> VIOLATION (got %s)",
                  myc_verdict_name(res.verdict));
            CHECK(res.completeness == MYC_COMPLETENESS_INCOMPLETE,
                  "INV-002: completeness INCOMPLETE (gap terlihat)");
            CHECK(res.finding == MYC_FINDING_FINDINGS,
                  "INV-002: finding FINDINGS");
            CHECK(debt_has(&res, MYC_DEBT_GATE_UNAVAILABLE),
                  "INV-002: debt GATE-UNAVAILABLE ada");
        } else {
            fprintf(stderr, "[FAIL] INV-002: calloc witness gagal\n");
            g_fail++;
        }
        myc_result_free(&res);
    }

    /* ---- T5 (INV-011): status tak dikenal -> fails closed. Nilai 99 di
     *      luar enum TIDAK boleh jadi clean; harus incomplete. */
    {
        myc_result res;
        myc_gate_status st = (myc_gate_status)99;
        myc_result_init(&res);
        myc_gate_set_status(&res, MYC_GATE_RUNTIME, st, NULL);
        myc_reduce_verdict(&res);
        CHECK(res.verdict == MC_INCONCLUSIVE,
              "INV-011: status unknown -> INCONCLUSIVE (got %s)",
              myc_verdict_name(res.verdict));
        CHECK(res.verdict != MC_OK,
              "INV-011: status unknown TIDAK pernah OK");
        CHECK(res.completeness == MYC_COMPLETENESS_INCOMPLETE,
              "INV-011: completeness INCOMPLETE");
        myc_result_free(&res);
    }

    /* ---- T6: enumerasi exhaustif. 2 gate x 7 status = 49, lalu
     *      3 gate x 7 status = 343. Tiap kombinasi: verdict/completeness/
     *      finding harus persis referensi; INV-001 (debt) diverifikasi. */
    {
        const myc_gate_id G2[] = { MYC_GATE_COMPILE, MYC_GATE_RUNTIME };
        const myc_gate_id G3[] = { MYC_GATE_COMPILE, MYC_GATE_RUNTIME,
                                   MYC_GATE_PROVE };
        myc_gate_status st[3];
        int i, j, k;

        for (i = 0; i < N_STS; i++) {
            for (j = 0; j < N_STS; j++) {
                st[0] = STS[i];
                st[1] = STS[j];
                snprintf(label, sizeof(label),
                         "exhaustive 2g %d,%d", i, j);
                run_case(G2, st, 2, 0, label);
            }
        }
        for (i = 0; i < N_STS; i++) {
            for (j = 0; j < N_STS; j++) {
                for (k = 0; k < N_STS; k++) {
                    st[0] = STS[i];
                    st[1] = STS[j];
                    st[2] = STS[k];
                    snprintf(label, sizeof(label),
                             "exhaustive 3g %d,%d,%d", i, j, k);
                    run_case(G3, st, 3, 0, label);
                }
            }
        }
    }

    /* ---- T7: corner -- requested gate dengan status NOT_REQUESTED.
     *      Dokumentasi perilaku reducer saat ini: masuk bucket incomplete
     *      (bukan clean). Dalam pipeline nyata gate diminta selalu punya
     *      status nyata; test ini mengunci bahwa status NOT_REQUESTED
     *      TIDAK pernah direinterpretasi sebagai clean.
     *      BATASAN TERDOKUMENTASI: corner ini verdict fails-closed
     *      (INCONCLUSIVE) tetapi TIDAK menghasilkan typed debt
     *      (myc_build_debt memperlakukan NOT_REQUESTED sebagai benign)
     *      -- gap kecil vs INV-001; sengaja dibiarkan agar perbaikan
     *      konsistensi debt di masa depan terlihat oleh test ini. */
    {
        myc_result res;
        myc_result_init(&res);
        myc_gate_set_status(&res, MYC_GATE_RUNTIME, MYC_GATE_NOT_REQUESTED, NULL);
        myc_reduce_verdict(&res);
        CHECK(res.verdict == MC_INCONCLUSIVE,
              "corner NOT_REQUESTED requested -> INCONCLUSIVE (got %s)",
              myc_verdict_name(res.verdict));
        CHECK(res.debt_count == 0,
              "corner NOT_REQUESTED: tanpa debt (batasan terdokumentasi)");
        myc_result_free(&res);
    }

    /* ---- T8: determinisme receipt (INV-004 terkait): kombinasi sama
     *      -> receipt_sha256 sama + 64 hex. */
    {
        char r1[65], r2[65];
        myc_result res;
        myc_gate_status sts[2] = { MYC_GATE_COMPLETED_CLEAN,
                                   MYC_GATE_UNAVAILABLE };
        int i;
        for (i = 0; i < 2; i++) {
            myc_result_init(&res);
            myc_gate_set_status(&res, MYC_GATE_RUNTIME, sts[0], NULL);
            myc_gate_set_status(&res, MYC_GATE_PROVE, sts[1], NULL);
            myc_reduce_verdict(&res);
            if (i == 0)
                memcpy(r1, res.receipt_sha256, 65);
            else
                memcpy(r2, res.receipt_sha256, 65);
            myc_result_free(&res);
        }
        CHECK(strlen(r1) == 64, "T8: receipt 64-hex");
        CHECK(memcmp(r1, r2, 64) == 0,
              "T8: receipt deterministik untuk kombinasi sama");
    }

    /* ---- T9: empty result (tanpa gate). Perilaku reducer saat ini:
     *      MC_OK (tidak ada incomplete). Dalam pipeline nyata gate compile
     *      selalu dijalankan; test ini mendokumentasikan perilaku reducer
     *      murni agar perubahan semantik terdeteksi. */
    {
        myc_result res;
        myc_result_init(&res);
        myc_reduce_verdict(&res);
        CHECK(res.verdict == MC_OK,
              "T9: tanpa gate -> OK (perilaku reducer terdokumentasi)");
        CHECK(res.completeness == MYC_COMPLETENESS_COMPLETE,
              "T9: tanpa gate -> completeness COMPLETE");
        myc_result_free(&res);
    }

    if (g_fail) {
        printf("reducer_exhaustive: FAIL (%d fail, %d pass)\n", g_fail, g_pass);
        return 1;
    }
    printf("reducer_exhaustive: OK (%d checks: INV-001/002/003/011 + exhaustive)\n",
           g_pass);
    return 0;
}
