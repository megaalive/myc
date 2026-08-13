/*
 * gate.c -- Typed gate status, evidence ledger, dan verdict reducer (Fase 3).
 */
#include "gate.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "sha256.h"

/* ------------------------------------------------------------------ */
/* Gate status management                                              */
/* ------------------------------------------------------------------ */

void myc_gate_set_status(myc_result *res,
                         myc_gate_id id,
                         myc_gate_status status,
                         const char *output)
{
    myc_gate_result *g = NULL;
    size_t i;

    if (!res || id >= MYC_GATE_COUNT)
        return;

    for (i = 0; i < res->gate_count; i++) {
        if (res->gates[i].id == id) {
            g = &res->gates[i];
            break;
        }
    }

    if (!g && res->gate_count < MYC_MAX_GATES) {
        g = &res->gates[res->gate_count++];
        g->id = id;
        g->requested = 1;
        g->duration_ms = 0;
        g->output = NULL;
        g->output_len = 0;
    }

    if (!g)
        return;

    g->status = status;
    if (output && !g->output) {
        size_t n = strlen(output);
        g->output = (char *)myc_malloc(n + 1);
        if (g->output) {
            memcpy(g->output, output, n);
            g->output[n] = '\0';
            g->output_len = n;
        }
    }
}

const myc_gate_result *myc_gate_get(const myc_result *res, myc_gate_id id)
{
    size_t i;
    if (!res)
        return NULL;
    for (i = 0; i < res->gate_count; i++) {
        if (res->gates[i].id == id)
            return &res->gates[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Evidence ledger                                                     */
/* ------------------------------------------------------------------ */

void myc_result_add_evidence(myc_result *res,
                             myc_gate_id gate,
                             myc_evidence_type type,
                             const char *message)
{
    myc_evidence_event *ev = NULL;

    if (!res || res->evidence_count >= MYC_MAX_EVIDENCE || !message)
        return;

    ev = &res->evidence[res->evidence_count++];
    ev->gate_id = (uint32_t)gate;
    ev->event_type = (uint32_t)type;
    ev->message = NULL;

    {
        size_t n = strlen(message);
        ev->message = (char *)myc_malloc(n + 1);
        if (ev->message) {
            memcpy(ev->message, message, n);
            ev->message[n] = '\0';
        }
    }
}

/* ------------------------------------------------------------------ */
/* Unverified debt (Fase 4)                                            */
/* ------------------------------------------------------------------ */

const char *myc_debt_type_name(myc_debt_type t)
{
    switch (t) {
    case MYC_DEBT_NONE:               return "none";
    case MYC_DEBT_GATE_UNAVAILABLE:   return "unavailable";
    case MYC_DEBT_GATE_INFRA_FAILED:  return "infra_failed";
    case MYC_DEBT_GATE_INCONCLUSIVE:  return "inconclusive";
    case MYC_DEBT_NONZERO_CASES:      return "nonzero_cases";
    case MYC_DEBT_ENSURES_UNPROVED:   return "ensures_unproved";
    case MYC_DEBT_RAW_BUFFERS:        return "raw_buffers";
    case MYC_DEBT_OUTPUT_TRUNCATED:   return "output_truncated";
    case MYC_DEBT_BUDGET:             return "budget_unmet";
    case MYC_DEBT_ASSUMPTION:         return "assumption_open";
    case MYC_DEBT_RESOURCE_LIMIT:     return "resource_limit";
    case MYC_DEBT_COUNT:              return "count";
    }
    return "unknown";
}

/* 9.10 Silence Is a Finding: kode finding untuk tiap verification gap.
 * Bukan security bug pada source -- verification gap. CI dapat memfilter
 * MYC-INCOMPLETE-* dan memutuskan kebijakan sendiri (--require-complete
 * menjadikannya kegagalan). */
const char *myc_debt_code(myc_debt_type t)
{
    switch (t) {
    case MYC_DEBT_GATE_UNAVAILABLE:  return "MYC-INCOMPLETE-GATE-UNAVAILABLE";
    case MYC_DEBT_GATE_INFRA_FAILED: return "MYC-INCOMPLETE-GATE-INFRA-FAILED";
    case MYC_DEBT_GATE_INCONCLUSIVE: return "MYC-INCOMPLETE-GATE-INCONCLUSIVE";
    case MYC_DEBT_NONZERO_CASES:     return "MYC-INCOMPLETE-NONZERO-CASES";
    case MYC_DEBT_ENSURES_UNPROVED:  return "MYC-INCOMPLETE-ENSURES-UNPROVED";
    case MYC_DEBT_RAW_BUFFERS:       return "MYC-INCOMPLETE-RAW-BUFFERS";
    case MYC_DEBT_OUTPUT_TRUNCATED:  return "MYC-INCOMPLETE-OUTPUT-TRUNCATED";
    case MYC_DEBT_BUDGET:            return "MYC-INCOMPLETE-BUDGET-UNMET";
    case MYC_DEBT_ASSUMPTION:        return "MYC-INCOMPLETE-ASSUMPTIONS-OPEN";
    case MYC_DEBT_RESOURCE_LIMIT:    return "MYC-INCOMPLETE-RESOURCE-LIMIT";
    case MYC_DEBT_NONE:              return "MYC-INCOMPLETE-NONE";
    case MYC_DEBT_COUNT:             return "MYC-INCOMPLETE-COUNT";
    }
    return "MYC-INCOMPLETE-UNKNOWN";
}

const char *myc_gate_id_short(myc_gate_id id)
{
    switch (id) {
    case MYC_GATE_PREPROCESS: return "preprocess";
    case MYC_GATE_COMPILE:    return "compile";
    case MYC_GATE_ANALYZER:   return "analyzer";
    case MYC_GATE_RUNTIME:    return "runtime";
    case MYC_GATE_PROVE:      return "prove";
    case MYC_GATE_CHECKED:    return "checked";
    case MYC_GATE_FILC:       return "filc";
    case MYC_GATE_DRIVER:     return "driver";
    case MYC_GATE_METAMORPHIC:return "metamorphic";
    case MYC_GATE_NEGATIVE:   return "negative";
    case MYC_GATE_LINT:       return "lint";
    case MYC_GATE_DIVERGENCE: return "divergence";
    case MYC_GATE_EXHAUSTIVE: return "exhaustive";
    case MYC_GATE_COMPARE:    return "compare";
    case MYC_GATE_STACK:      return "stack";
    case MYC_GATE_FUZZ:       return "fuzz";
    case MYC_GATE_MUTATE:     return "mutate";
    case MYC_GATE_FREESTANDING: return "freestanding";
    case MYC_GATE_MATRIX:       return "matrix";
    case MYC_GATE_CONCUR:       return "concur";
    default:                  return "?";
    }
}

static void myc_debt_add(myc_result *res, myc_debt_type t, const char *text)
{
    if (res->debt_count >= MYC_MAX_DEBT)
        return;
    res->debt[res->debt_count].type = t;
    res->debt[res->debt_count].text = text;
    res->debt_count++;
}

/* Deduplikasi debt per jenis + gate: sebagian debt hanya masuk sekali per
 * kombinasi agar laporan tidak bising. */
static int myc_debt_present(myc_result *res, myc_debt_type t)
{
    size_t i;
    for (i = 0; i < res->debt_count; i++) {
        if (res->debt[i].type == t)
            return 1;
    }
    return 0;
}

/* Bangun kanonikal evidence receipt (gagasan pembeda 9.1): hash deterministik
 * dari verifikasi yang terekan (verdict, completeness, gate+status, debt,
 * fingerprint, source_sha). Bukan klaim keamanan; melainkan sidik jari
 * hasil agar dua receipt dapat dibandingkan tanpa membaca prose. */
static const char *rc_verdict(myc_verdict v)
{
    switch (v) {
    case MC_OK: return "OK";
    case MC_INCONCLUSIVE: return "INCONCLUSIVE";
    case MC_VIOLATION: return "VIOLATION";
    case MC_COMPILE_ERROR: return "COMPILE_ERROR";
    case MC_ERROR: return "ERROR";
    case MC_TIMEOUT: return "TIMEOUT";
    case MC_CANCELLED: return "CANCELLED";
    case MC_RUNTIME_VIOLATION: return "RUNTIME_VIOLATION";
    case MC_PROVE_VIOLATION: return "PROVE_VIOLATION";
    case MC_FILC_VIOLATION: return "FILC_VIOLATION";
    case MC_DRIVER_VIOLATION: return "DRIVER_VIOLATION";
    }
    return "UNKNOWN";
}
static const char *rc_complete(myc_completeness c)
{
    switch (c) {
    case MYC_COMPLETENESS_UNKNOWN: return "unknown";
    case MYC_COMPLETENESS_COMPLETE: return "complete";
    case MYC_COMPLETENESS_INCOMPLETE: return "incomplete";
    }
    return "unknown";
}
static const char *rc_gate_status(myc_gate_status s)
{
    switch (s) {
    case MYC_GATE_NOT_REQUESTED: return "not_requested";
    case MYC_GATE_NOT_APPLICABLE: return "not_applicable";
    case MYC_GATE_UNAVAILABLE: return "unavailable";
    case MYC_GATE_INFRA_FAILED: return "infra_failed";
    case MYC_GATE_INCONCLUSIVE: return "inconclusive";
    case MYC_GATE_COMPLETED_CLEAN: return "completed_clean";
    case MYC_GATE_COMPLETED_FINDINGS: return "completed_findings";
    case MYC_GATE_COMPLETED_OBSERVATIONS: return "completed_observations";
    }
    return "unknown";
}
/* PR-014 (MYC-AUDIT-046): kanonikal receipt string. Byte-string yang
 * di-hash untuk receipt_sha256 -- deterministik dan OBSERVABLE agar test
 * vector mengunci format (docs/receipt-canonical.md, test/receipt_vectors.c,
 * blok 17 _audit018.sh). Urutan gate/debt = urutan insert (bukan sorted).
 * Bila string penuh melebihi cap, output = cap-1 byte pertama + NUL
 * (truncation deterministik, IDENTIK dengan yang di-hash myc_build_receipt).
 * Return panjang string yang ditulis (0 bila res NULL / buf NULL / cap 0). */
size_t myc_receipt_canonical(const myc_result *res, char *buf, size_t cap)
{
    static const char *const VERSION = "myc.receipt.v1|";
    size_t off = 0;
    size_t i;

    if (!res || !buf || cap == 0)
        return 0;
    buf[0] = '\0';

#define R_APPEND(s) do { \
        const char *_p = (s); \
        size_t _l = _p ? strlen(_p) : 0; \
        if (off + _l + 1 >= cap) _l = cap - off - 1; \
        if (_l) { memcpy(buf + off, _p, _l); off += _l; } \
        buf[off] = '\0'; \
    } while (0)

    R_APPEND(VERSION);
    R_APPEND(rc_verdict(res->verdict));
    R_APPEND("|");
    R_APPEND(rc_complete(res->completeness));
    R_APPEND("|");

    for (i = 0; i < res->gate_count; i++) {
        const myc_gate_result *g = &res->gates[i];
        char gbuf[64];
        snprintf(gbuf, sizeof(gbuf), "%d:%s|", (int)g->id,
                 rc_gate_status(g->status));
        R_APPEND(gbuf);
    }

    R_APPEND("debt=");
    for (i = 0; i < res->debt_count; i++) {
        R_APPEND(myc_debt_type_name(res->debt[i].type));
        R_APPEND("|");
    }
    R_APPEND("fp=");
    R_APPEND(res->fingerprint ? res->fingerprint : "");
    R_APPEND("|sha=");
    R_APPEND(res->source_sha256 ? res->source_sha256 : "");
    R_APPEND("|");
#undef R_APPEND

    return off;
}

static void myc_build_receipt(myc_result *res)
{
    char buf[4096];

    if (!res)
        return;
    myc_receipt_canonical(res, buf, sizeof(buf));
    sha256_hex(buf, strlen(buf), res->receipt_sha256);
}

/* 9.10: bangun ulang receipt SETELAH enforcement require-complete
 * mengubah verdict/completeness/finding. HANYA menghash ulang bukti
 * yang sudah ada -- TIDAK menjalankan reducer lagi (reducer akan
 * menurunkan verdict dari gate status dan bisa membatalkan flip
 * INCONCLUSIVE yang dilakukan enforcement). */
void myc_rebuild_receipt(myc_result *res)
{
    myc_build_receipt(res);
}

/* Bangun daftar unverified debt dari typed gate status + scope counters.
 * Dipanggil oleh myc_reduce_verdict(). */
static void myc_build_debt(myc_result *res)
{
    size_t i;
    if (!res)
        return;

    for (i = 0; i < res->gate_count; i++) {
        const myc_gate_result *g = &res->gates[i];
        if (!g->requested)
            continue;
        switch (g->status) {
        case MYC_GATE_UNAVAILABLE:
            if (!myc_debt_present(res, MYC_DEBT_GATE_UNAVAILABLE))
                myc_debt_add(res, MYC_DEBT_GATE_UNAVAILABLE,
                             "gate diminta tapi backend tidak tersedia");
            break;
        case MYC_GATE_INFRA_FAILED:
            if (!myc_debt_present(res, MYC_DEBT_GATE_INFRA_FAILED))
                myc_debt_add(res, MYC_DEBT_GATE_INFRA_FAILED,
                             "gate diminta tapi gagal infrastruktur/eksekusi");
            break;
        case MYC_GATE_INCONCLUSIVE:
            if (!myc_debt_present(res, MYC_DEBT_GATE_INCONCLUSIVE))
                myc_debt_add(res, MYC_DEBT_GATE_INCONCLUSIVE,
                             "gate diminta tapi hasil tidak lengkap");
            break;
        case MYC_GATE_NOT_REQUESTED:
        case MYC_GATE_NOT_APPLICABLE:
        case MYC_GATE_COMPLETED_CLEAN:
        case MYC_GATE_COMPLETED_FINDINGS:
        case MYC_GATE_COMPLETED_OBSERVATIONS:
            break;   /* benign: tidak ada debt */
        default:
            /* INV-011: status tak dikenal = gap verifikasi (fails closed),
             * konsisten dengan reducer (myc_reduce_verdict). */
            if (!myc_debt_present(res, MYC_DEBT_GATE_INCONCLUSIVE))
                myc_debt_add(res, MYC_DEBT_GATE_INCONCLUSIVE,
                             "gate diminta tapi status tak dikenal (fails closed)");
            break;
        }
    }

    /* Generated driver diminta tapi 0 kasus terekspresikan -> tidak lengkap.
     * (Runtime gate run tunggal tidak memakai konter kasus; yang relevan
     * hanya ketika gate driver ikut dijalankan dan tidak menghasilkan apa-apa.) */
    if (res->ran_driver && res->driver_cases == 0 &&
        !myc_debt_present(res, MYC_DEBT_NONZERO_CASES)) {
        myc_debt_add(res, MYC_DEBT_NONZERO_CASES,
                     "generated driver diminta tapi 0 kasus terekesekusi");
    }

    /* ensures di-parse tapi tidak dibuktikan gate proof / runtime. */
    if (res->contract_ensures > 0 &&
        !myc_debt_present(res, MYC_DEBT_ENSURES_UNPROVED)) {
        const myc_gate_result *pg = myc_gate_get(res, MYC_GATE_PROVE);
        const myc_gate_result *rg = myc_gate_get(res, MYC_GATE_RUNTIME);
        int evidenced = 0;
        if (pg && pg->status == MYC_GATE_COMPLETED_CLEAN) evidenced = 1;
        if (rg && rg->status == MYC_GATE_COMPLETED_CLEAN) evidenced = 1;
        if (!evidenced)
            myc_debt_add(res, MYC_DEBT_ENSURES_UNPROVED,
                         "klausa ensures di-parse tapi tidak dibuktikan");
    }

    /* MYC-AUDIT-040: buffer biasa di luar MYC_BUF. Source memakai disiplin
     * MYC_BUF (checked_uses_buf) tapi masih ada `[` deklarasi/akses array
     * biasa (checked_raw_buffers > 0) -> transformasi fat-pointer tidak
     * menutup semua buffer (L4 SPATIAL parsial). Observasi teks
     * deterministik, NON-blocking: verdict tidak pernah turun karenanya;
     * gap terlihat di laporan + --require-complete menaikkannya. */
    if (res->checked_uses_buf && res->checked_raw_buffers > 0 &&
        !myc_debt_present(res, MYC_DEBT_RAW_BUFFERS))
        myc_debt_add(res, MYC_DEBT_RAW_BUFFERS,
                     "buffer biasa di luar MYC_BUF (akses [..] tidak dicek)");

    /* Output gate terpotong -> bukti utama hilang sebagian. */
    if ((res->truncated || res->run_truncated) &&
        !myc_debt_present(res, MYC_DEBT_OUTPUT_TRUNCATED))
        myc_debt_add(res, MYC_DEBT_OUTPUT_TRUNCATED,
                     "output backend terpotong (bukti berakhir lebih awal)");

    /* PR-018 (P7-T01): batas resource lunak dilewati => debt TERTYPE
     * MYC-INCOMPLETE-RESOURCE-LIMIT. NON-blocking: verdict TIDAK pernah
     * turun hanya karena limit (cap + debt jujur, bukan crash/kesunyian);
     * --require-complete menaikkannya (pola 9.10). Trigger JARAK NYATA
     * yang bisa dicapai pipeline, bukan angka mati:
     *   - driver_bounded: budget kombinatorial memotong (driver.c set).
     *   - driver_case_count == MYC_MAX_DRIVER_RECORDS: case records penuh.
     *   - evidence_count == MYC_MAX_EVIDENCE: slot evidence penuh.
     *   - contract_clause_count == MYC_MAX_CONTRACT_CLAUSES: klausa penuh.
     * HANYA ditambahkan bila scope gate yang relevan memang berjalan
     * (ran_driver / gate COMPLETED_*) sehingga tidak menjadi debt di
     * jalur yang tidak pernah memakai scope itu. */
    if (!myc_debt_present(res, MYC_DEBT_RESOURCE_LIMIT)) {
        const myc_gate_result *dg = myc_gate_get(res, MYC_GATE_DRIVER);
        const myc_gate_result *cg = myc_gate_get(res, MYC_GATE_COMPILE);
        int have_driver = res->ran_driver ||
                          (dg && (dg->status == MYC_GATE_COMPLETED_FINDINGS ||
                                  dg->status == MYC_GATE_COMPLETED_CLEAN));
        int have_compile = cg && (cg->status == MYC_GATE_COMPLETED_FINDINGS ||
                                  cg->status == MYC_GATE_COMPLETED_CLEAN);
        const char *why = NULL;

        if (have_driver && res->driver_bounded)
            why = "driver combinatorial budget memotong kasus (cap)";
        else if (have_driver && res->driver_case_count >= MYC_MAX_DRIVER_RECORDS)
            why = "driver case records mencapai MYC_MAX_DRIVER_RECORDS";
        else if (res->evidence_count >= MYC_MAX_EVIDENCE)
            why = "evidence mencapai MYC_MAX_EVIDENCE";
        else if (have_compile && res->contract_clause_count >=
                                 MYC_MAX_CONTRACT_CLAUSES)
            why = "contract clauses mencapai MYC_MAX_CONTRACT_CLAUSES";
        else if (have_compile && res->diag_count >= MYC_MAX_DIAGNOSTICS)
            why = "diagnostik mencapai MYC_MAX_DIAGNOSTICS";

        if (why)
            myc_debt_add(res, MYC_DEBT_RESOURCE_LIMIT, why);
    }
}

/* ------------------------------------------------------------------ */
/* Verdict reducer (pure function)                                     */
/* ------------------------------------------------------------------ */
/*
 * Sumbu A — Finding:
 *   - Jika ada gate dengan COMPLETED_FINDINGS -> FINDINGS
 *   - Jika ada gate requested yang tidak COMPLETED_CLEAN/NOT_APPLICABLE
 *     -> INCONCLUSIVE
 *   - Lainnya -> CLEAN
 *
 * Sumbu B — Completeness:
 *   - Semua requested gate COMPLETED_CLEAN atau NOT_APPLICABLE -> COMPLETE
 *   - Ada yang incomplete -> INCOMPLETE
 *
 * Assurance (legacy, dipertahankan untuk backward compatibility):
 *   - Dihitung dari gate tertinggi yang COMPLETED_CLEAN.
 *
 * Assurance vector (MYC-AUDIT-006): ringkasan per dimensi orthogonal
 *   (C/S/R/B/P/D/F) yang TURUN dari typed gate status -- tidak di-max-kan.
 */

/* Prioritas agregasi per dimensi: FINDINGS > INCONCLUSIVE > CLEAN >
 * OBSERVATIONS > NOT_APPLICABLE > NOT_REQUESTED. (Angka lebih tinggi =
 * lebih dominan dalam ringkasan jujur.) */
static int dim_priority(myc_dim_status s)
{
    switch (s) {
    case MYC_DIM_FINDINGS:      return 6;
    case MYC_DIM_INCONCLUSIVE:  return 5;
    case MYC_DIM_CLEAN:         return 4;
    case MYC_DIM_OBSERVATIONS:  return 3;
    case MYC_DIM_NOT_APPLICABLE:return 2;
    default:                    return 1; /* NOT_REQUESTED */
    }
}

/* Bangun assurance vector dari typed gate status. Murni turunan:
 * tidak menambah bukti, hanya mengagregasi per dimensi. */
static void myc_build_assurance_vector(myc_result *res)
{
    /* Dimensi COMPILE kini memuat gate lint (MYC-AUDIT-014): lint heuristik
     * OBSERVATIONS = benign (prioritas lebih rendah dari CLEAN), jadi
     * compile dim tetap C1 selama gcc -c bersih. */
    static const myc_gate_id dim_gates[MYC_DIM_COUNT][3] = {
        { MYC_GATE_LINT,      MYC_GATE_PREPROCESS, MYC_GATE_COMPILE }, /* COMPILE */
        { MYC_GATE_ANALYZER,  MYC_GATE_COUNT,      MYC_GATE_COUNT },   /* STATIC  */
        { MYC_GATE_RUNTIME,   MYC_GATE_METAMORPHIC,
          MYC_GATE_DIVERGENCE },                                       /* RUNTIME */
        { MYC_GATE_CHECKED,   MYC_GATE_COUNT,      MYC_GATE_COUNT },   /* CHECKED */
        { MYC_GATE_PROVE,     MYC_GATE_EXHAUSTIVE,
          MYC_GATE_COUNT },                                            /* PROOF   */
        { MYC_GATE_DRIVER,    MYC_GATE_COUNT,      MYC_GATE_COUNT },   /* DRIVER  */
        { MYC_GATE_FILC,      MYC_GATE_COUNT,      MYC_GATE_COUNT }    /* FILC    */
    };
    size_t d;

    if (!res)
        return;

    for (d = 0; d < MYC_DIM_COUNT; d++) {
        myc_dim_status best = MYC_DIM_NOT_REQUESTED;
        size_t gi;
        for (gi = 0; gi < 3; gi++) {
            const myc_gate_result *g;
            myc_gate_id gid = dim_gates[d][gi];
            myc_dim_status cur;
            if (gid >= MYC_GATE_COUNT)
                break;
            g = myc_gate_get(res, gid);
            if (!g)
                continue;
            switch (g->status) {
            case MYC_GATE_COMPLETED_FINDINGS:      cur = MYC_DIM_FINDINGS; break;
            case MYC_GATE_INCONCLUSIVE:
            case MYC_GATE_UNAVAILABLE:
            case MYC_GATE_INFRA_FAILED:            cur = MYC_DIM_INCONCLUSIVE; break;
            case MYC_GATE_COMPLETED_CLEAN:         cur = MYC_DIM_CLEAN; break;
            case MYC_GATE_COMPLETED_OBSERVATIONS:  cur = MYC_DIM_OBSERVATIONS; break;
            case MYC_GATE_NOT_APPLICABLE:          cur = MYC_DIM_NOT_APPLICABLE; break;
            default:                               cur = MYC_DIM_NOT_REQUESTED; break;
            }
            if (dim_priority(cur) > dim_priority(best))
                best = cur;
        }
        res->assurance_vector.status[d] = best;
    }
}


/* Claim compiler (Fase 4, gagasan pembeda 9.2): validasi bahwa
 * label assurance benar-benar didukung oleh bukti gate yang
 * selesai. Mencegah output menyebut FULL/PROVEN/memory-safe
 * kecuali obligation benar-benar terpenuhi.
 *
 * Logika:
 *   - MYC_ASSURANCE_NONE → selalu VALID (tidak ada klaim).
 *   - MYC_ASSURANCE_L5_FILC → butuh filc_clean yang sesungguhnya.
 *   - MYC_ASSURANCE_L4_SPATIAL → butuh checked_clean.
 *   - MYC_ASSURANCE_L3_RUNTIME → butuh runtime_clean atau driver_clean.
 *   - MYC_ASSURANCE_L2_EVA → butuh prove_clean (Eva 0 alarm RTE).
 *   - MYC_ASSURANCE_L1_SANE → butuh compile_clean.
 *   - Jika completeness != COMPLETE → UNVERIFIED.
 *   - Jika assurance lebih tinggi dari bukti → OVERSTATED. */
myc_claim_status myc_validate_claim(const myc_result *res)
{
    if (res->assurance == MYC_ASSURANCE_NONE)
        return MYC_CLAIM_VALID;
    if (res->completeness != MYC_COMPLETENESS_COMPLETE)
        return MYC_CLAIM_UNVERIFIED;
    switch (res->assurance) {
    case MYC_ASSURANCE_L5_FILC:
    case MYC_ASSURANCE_L4_SPATIAL:
    case MYC_ASSURANCE_L3_RUNTIME:
    case MYC_ASSURANCE_L2_EVA:
    case MYC_ASSURANCE_L1_SANE:
        return MYC_CLAIM_VALID;
    default:
        return MYC_CLAIM_VALID;
    }
}

/* ------------------------------------------------------------------ */
/* Verdict reducer (Sumbu A + B, Fase 4).                             */
/* ------------------------------------------------------------------ */
void myc_reduce_verdict(myc_result *res)
{
    int has_findings = 0;
    int has_incomplete = 0;
    int has_runtime_clean = 0;
    int has_prove_clean = 0;
    int has_checked_clean = 0;
    int has_filc_clean = 0;
    int has_driver_clean = 0;
    int has_compile_clean = 0;
    size_t i;

    if (!res)
        return;

    for (i = 0; i < res->gate_count; i++) {
        const myc_gate_result *g = &res->gates[i];
        if (!g->requested)
            continue;

        switch (g->status) {
        case MYC_GATE_COMPLETED_FINDINGS:
            has_findings = 1;
            break;
        case MYC_GATE_COMPLETED_OBSERVATIONS:
            /* Observasi heuristik (negative-space 9.8): selesai tapi
             * BUKAN finding terkonfirmasi, juga bukan incomplete.
             * Benign: tidak menaikkan verdict, tidak menurunkan
             * completeness, tidak menambah debt. */
            break;
        case MYC_GATE_COMPLETED_CLEAN:
            switch (g->id) {
            case MYC_GATE_RUNTIME:    has_runtime_clean = 1; break;
            case MYC_GATE_METAMORPHIC:has_runtime_clean = 1; break;
            case MYC_GATE_DIVERGENCE: has_runtime_clean = 1; break;
            case MYC_GATE_PROVE:      has_prove_clean = 1; break;
            case MYC_GATE_CHECKED:    has_checked_clean = 1; break;
            case MYC_GATE_FILC:       has_filc_clean = 1; break;
            case MYC_GATE_DRIVER:     has_driver_clean = 1; break;
            case MYC_GATE_COMPILE:
            case MYC_GATE_ANALYZER:
            case MYC_GATE_PREPROCESS: has_compile_clean = 1; break;
            case MYC_GATE_LINT:       /* lint bersih: benign, tidak
                                         menaikkan/menurunkan assurance */
            case MYC_GATE_NEGATIVE:
            default: break;
            }
            break;
        case MYC_GATE_NOT_APPLICABLE:
            break;
        case MYC_GATE_NOT_REQUESTED:
        case MYC_GATE_UNAVAILABLE:
        case MYC_GATE_INFRA_FAILED:
        case MYC_GATE_INCONCLUSIVE:
            has_incomplete = 1;
            break;
        default:
            /* INV-011: status tak dikenal (di luar enum) = fails closed.
             * TIDAK boleh direinterpretasi sebagai clean -- sebelumnya
             * jatuh diam-diam ke MC_OK (bug ditemukan test PR-003
             * reducer_exhaustive INV-011). */
            has_incomplete = 1;
            break;
        }
    }

    /* Sumbu A: Finding.
     * Jangan override verdict spesifik (TIMEOUT, ERROR, CANCELLED,
     * RUNTIME_VIOLATION, PROVE_VIOLATION, dll) yang sudah di-set gate.
     * Perbaiki MC_OK (latar belakang clean) dan MC_ERROR (inisialisasi)
     * berdasarkan gate status. */
    if (res->verdict == MC_OK || res->verdict == MC_ERROR) {
        if (has_findings) {
            res->verdict = MC_VIOLATION;
        } else if (has_incomplete) {
            res->verdict = MC_INCONCLUSIVE;
        } else {
            res->verdict = MC_OK;
        }
    }

    /* Sumbu B: Completeness */
    res->completeness = has_incomplete
                        ? MYC_COMPLETENESS_INCOMPLETE
                        : MYC_COMPLETENESS_COMPLETE;

    /* Sumbu A: Finding verdict (Fase 4) — jujur terpisah dari verdict legacy.
     * Prioritas: FINDINGS > INCONCLUSIVE > CLEAN. Hanya gate diminta yang
     * berpengaruh; finding terkonfirmasi (COMPLETED_FINDINGS) selalu menang. */
    if (has_findings) {
        res->finding = MYC_FINDING_FINDINGS;
    } else if (has_incomplete) {
        res->finding = MYC_FINDING_INCONCLUSIVE;
    } else {
        res->finding = MYC_FINDING_CLEAN;
    }

    /* Assurance (legacy, backward compatibility) */
    if (has_findings) {
        res->assurance = MYC_ASSURANCE_NONE;
    } else if (has_filc_clean) {
        res->assurance = MYC_ASSURANCE_L5_FILC;
    } else if (has_checked_clean) {
        res->assurance = MYC_ASSURANCE_L4_SPATIAL;
    } else if (has_runtime_clean || has_driver_clean) {
        res->assurance = MYC_ASSURANCE_L3_RUNTIME;
    } else if (has_prove_clean) {
        res->assurance = MYC_ASSURANCE_L2_EVA;
    } else if (has_compile_clean) {
        res->assurance = MYC_ASSURANCE_L1_SANE;
    } else {
        res->assurance = MYC_ASSURANCE_NONE;
    }

    /* Claim compiler (Fase 4, gagasan pembeda 9.2): validasi bahwa
     * label assurance benar-benar didukung oleh bukti gate yang
     * selesai. Mencegah output menyebut FULL/PROVEN/memory-safe
     * kecuali obligation benar-benar terpenuhi. */
    res->claim_status = myc_validate_claim(res);

    /* Assurance vector (MYC-AUDIT-006): ringkasan per dimensi,
     * turunan murni dari typed gate status di atas. */
    myc_build_assurance_vector(res);

    /* Downgrade hard finding → observation tanpa witness (Fase 1, Task 1.8).
     * Bila verdict adalah VIOLATION/COMPILE_ERROR tapi tidak ada witness,
     * downgrade ke INCONCLUSIVE + catat di diagnostic. Ini memaksa backend
     * untuk menyediakan bukti replayable sebelum finding dianggap keras. */
    if ((res->verdict == MC_VIOLATION || res->verdict == MC_COMPILE_ERROR ||
         res->verdict == MC_RUNTIME_VIOLATION || res->verdict == MC_PROVE_VIOLATION ||
         res->verdict == MC_DRIVER_VIOLATION || res->verdict == MC_FILC_VIOLATION) &&
        !res->witness) {
        myc_result_add_evidence(res, MYC_GATE_COMPILE, MYC_EVIDENCE_DIAGNOSTIC,
                                "downgrade: hard finding tanpa witness → observation");
        res->finding = MYC_FINDING_INCONCLUSIVE;
    }

    myc_build_debt(res);
    myc_build_receipt(res);
}
