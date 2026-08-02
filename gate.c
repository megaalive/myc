/*
 * gate.c -- Typed gate status, evidence ledger, dan verdict reducer (Fase 3).
 */
#include "gate.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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
        g->output = (char *)malloc(n + 1);
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
        ev->message = (char *)malloc(n + 1);
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
    case MYC_DEBT_COUNT:              return "count";
    }
    return "unknown";
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
        default:
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

    /* Output gate terpotong -> bukti utama hilang sebagian. */
    if ((res->truncated || res->run_truncated) &&
        !myc_debt_present(res, MYC_DEBT_OUTPUT_TRUNCATED))
        myc_debt_add(res, MYC_DEBT_OUTPUT_TRUNCATED,
                     "output backend terpotong (bukti berakhir lebih awal)");
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
 */
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
        case MYC_GATE_COMPLETED_CLEAN:
            switch (g->id) {
            case MYC_GATE_RUNTIME:    has_runtime_clean = 1; break;
            case MYC_GATE_PROVE:      has_prove_clean = 1; break;
            case MYC_GATE_CHECKED:    has_checked_clean = 1; break;
            case MYC_GATE_FILC:       has_filc_clean = 1; break;
            case MYC_GATE_DRIVER:     has_driver_clean = 1; break;
            case MYC_GATE_COMPILE:
            case MYC_GATE_ANALYZER:
            case MYC_GATE_PREPROCESS: has_compile_clean = 1; break;
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

    /* Assurance (legacy, backward compatibility) */
    if (has_findings) {
        res->assurance = MYC_ASSURANCE_NONE;
    } else if (has_filc_clean) {
        res->assurance = MYC_ASSURANCE_L5_FULL;
    } else if (has_checked_clean) {
        res->assurance = MYC_ASSURANCE_L4_SPATIAL;
    } else if (has_runtime_clean || has_driver_clean) {
        res->assurance = MYC_ASSURANCE_L3_RUNTIME;
    } else if (has_prove_clean) {
        res->assurance = MYC_ASSURANCE_L2_PROVEN;
    } else if (has_compile_clean) {
        res->assurance = MYC_ASSURANCE_L1_SANE;
    } else {
        res->assurance = MYC_ASSURANCE_NONE;
    }

    myc_build_debt(res);
}
