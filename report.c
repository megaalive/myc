/*
 * report.c -- Output verdict: teks (default) dan JSON (--json).
 */
#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "myc.h"
#include "gate.h"
#include "agent.h"
#include "assume.h"
#include "taxonomy.h"

const char *myc_verdict_name(myc_verdict v)
{
    switch (v) {
    case MC_OK:                return "OK";
    case MC_INCONCLUSIVE:      return "INCONCLUSIVE";
    case MC_VIOLATION:         return "VIOLATION";
    case MC_COMPILE_ERROR:     return "COMPILE_ERROR";
    case MC_ERROR:             return "ERROR";
    case MC_TIMEOUT:           return "TIMEOUT";
    case MC_CANCELLED:         return "CANCELLED";
    case MC_RUNTIME_VIOLATION: return "RUNTIME_VIOLATION";
    case MC_PROVE_VIOLATION:   return "PROVE_VIOLATION";
    case MC_FILC_VIOLATION:    return "FILC_VIOLATION";
    case MC_DRIVER_VIOLATION:  return "DRIVER_VIOLATION";
    }
    return "UNKNOWN";
}

const char *myc_error_name(myc_error_code c)
{
    switch (c) {
    case MYC_ERR_NONE:                        return "none";
    case MYC_ERR_INVALID_REQUEST:             return "invalid_request";
    case MYC_ERR_NUL_IN_INPUT:                return "nul_in_input";
    case MYC_ERR_INPUT_TOO_LARGE:             return "input_too_large";
    case MYC_ERR_INVALID_PATH:                return "invalid_path";
    case MYC_ERR_POLICY_DENIED:               return "policy_denied";
    case MYC_ERR_LINT_VIOLATION:              return "lint_violation";
    case MYC_ERR_COMPILE_ERROR:               return "compile_error";
    case MYC_ERR_PREPROCESS_ERROR:            return "preprocess_error";
    case MYC_ERR_GCC_NOT_FOUND:               return "gcc_not_found";
    case MYC_ERR_EXECUTE_FAILED:              return "execute_failed";
    case MYC_ERR_TIMEOUT:                     return "timeout";
    case MYC_ERR_CANCELLED:                   return "cancelled";
    case MYC_ERR_STDOUT_READ_FAILED:          return "stdout_read_failed";
    case MYC_ERR_STDERR_READ_FAILED:          return "stderr_read_failed";
    case MYC_ERR_PROCESS_TREE_CLEANUP_FAILED: return "process_tree_cleanup_failed";
    case MYC_ERR_RUNTIME_VIOLATION:           return "runtime_violation";
    case MYC_ERR_PROVE_VIOLATION:             return "prove_violation";
    case MYC_ERR_FILC_VIOLATION:              return "filc_violation";
    case MYC_ERR_DRIVER_VIOLATION:            return "driver_violation";
    case MYC_ERR_CLANG_NOT_FOUND:             return "clang_not_found";
    case MYC_ERR_INVALID_TIMEOUT:              return "invalid_timeout";
    case MYC_ERR_INVALID_OUTPUT_CAP:           return "invalid_output_cap";
    case MYC_ERR_INVALID_CWD:                  return "invalid_cwd";
    case MYC_ERR_STDIN_TOO_LARGE:              return "stdin_too_large";
    case MYC_ERR_INTERNAL:                    return "internal";
    }
    return "unknown";
}

const char *myc_assurance_name(myc_assurance a)
{
    switch (a) {
    case MYC_ASSURANCE_NONE:      return "L0 (NONE)";
    case MYC_ASSURANCE_L0_RAW:    return "L0 (RAW)";
    case MYC_ASSURANCE_L1_SANE:   return "L1 (SANE)";
    case MYC_ASSURANCE_L2_EVA:    return "L2 (EVA)";
    case MYC_ASSURANCE_L3_RUNTIME:return "L3 (RUNTIME)";
    case MYC_ASSURANCE_L4_SPATIAL:return "L4 (SPATIAL)";
    case MYC_ASSURANCE_L5_FILC:   return "L5 (FILC)";
    }
    return "L? (UNKNOWN)";
}

const char *myc_gate_status_name(myc_gate_status s)
{
    switch (s) {
    case MYC_GATE_NOT_REQUESTED:   return "not_requested";
    case MYC_GATE_NOT_APPLICABLE:  return "not_applicable";
    case MYC_GATE_UNAVAILABLE:     return "unavailable";
    case MYC_GATE_INFRA_FAILED:    return "infra_failed";
    case MYC_GATE_INCONCLUSIVE:    return "inconclusive";
    case MYC_GATE_COMPLETED_CLEAN: return "completed_clean";
    case MYC_GATE_COMPLETED_FINDINGS: return "completed_findings";
    case MYC_GATE_COMPLETED_OBSERVATIONS: return "completed_observations";
    }
    return "unknown";
}

const char *myc_completeness_name(myc_completeness c)
{
    switch (c) {
    case MYC_COMPLETENESS_UNKNOWN:   return "unknown";
    case MYC_COMPLETENESS_COMPLETE:  return "complete";
    case MYC_COMPLETENESS_INCOMPLETE: return "incomplete";
    }
    return "unknown";
}

const char *myc_finding_name(myc_finding f)
{
    switch (f) {
    case MYC_FINDING_UNKNOWN:     return "unknown";
    case MYC_FINDING_CLEAN:       return "clean";
    case MYC_FINDING_FINDINGS:    return "findings";
    case MYC_FINDING_INCONCLUSIVE:return "inconclusive";
    }
    return "unknown";
}

const char *myc_claim_status_name(myc_claim_status c)
{
    switch (c) {
    case MYC_CLAIM_UNKNOWN:    return "unknown";
    case MYC_CLAIM_VALID:      return "valid";
    case MYC_CLAIM_OVERSTATED: return "overstated";
    case MYC_CLAIM_UNVERIFIED: return "unverified";
    }
    return "unknown";
}

const char *myc_quorum_status_name(myc_quorum_status s)
{
    switch (s) {
    case MYC_QUORUM_NOT_REQUESTED: return "not_requested";
    case MYC_QUORUM_CLEAN:         return "clean";
    case MYC_QUORUM_CONFLICT:      return "conflict";
    case MYC_QUORUM_INCONCLUSIVE:  return "inconclusive";
    }
    return "unknown";
}

const char *myc_dim_status_name(myc_dim_status s)
{
    switch (s) {
    case MYC_DIM_NOT_REQUESTED:   return "not_requested";
    case MYC_DIM_NOT_APPLICABLE:  return "not_applicable";
    case MYC_DIM_CLEAN:           return "clean";
    case MYC_DIM_FINDINGS:        return "findings";
    case MYC_DIM_INCONCLUSIVE:    return "inconclusive";
    case MYC_DIM_OBSERVATIONS:    return "observations";
    default:                      return "unknown";
    }
}

/* Nama confidence diagnostic (MYC-AUDIT-014): label heuristik teks vs
 * bukti semantik. Dipakai laporan teks + JSON. */
const char *myc_confidence_name(myc_confidence c)
{
    switch (c) {
    case MYC_CONF_OBSERVATION: return "observation";
    case MYC_CONF_SUSPICIOUS:  return "suspicious";
    case MYC_CONF_LIKELY:      return "likely";
    case MYC_CONF_CONFIRMED:   return "confirmed";
    }
    return "unknown";
}

/* Digit kompak per dimensi untuk ringkasan assurance vector:
 * 0=n/a 1=clean 2=findings 3=inconclusive 4=observations */
static char dim_digit(myc_dim_status s)
{
    switch (s) {
    case MYC_DIM_CLEAN:        return '1';
    case MYC_DIM_FINDINGS:     return '2';
    case MYC_DIM_INCONCLUSIVE: return '3';
    case MYC_DIM_OBSERVATIONS: return '4';
    default:                   return '0';
    }
}

static void print_assurance_vector(const myc_assurance_vector *v)
{
    static const char dim_chars[MYC_DIM_COUNT] = {
        'C', 'S', 'R', 'B', 'P', 'D', 'F'
    };
    size_t d;
    printf("assurance_vector: ");
    for (d = 0; d < MYC_DIM_COUNT; d++) {
        if (d)
            printf(" ");
        printf("%c%c", dim_chars[d], dim_digit(v->status[d]));
    }
    printf("\n");
    printf("  (dimensi: C=compile S=static R=runtime B=checked "
           "P=proof D=driver F=filc; 0=n/a 1=clean 2=findings "
           "3=inconclusive 4=observations)\n");
}

/* Escape string JSON ke json_sb (tanpa batas 4096; dipakai laporan & MCP). */
static int json_sb_escape(json_sb *b, const char *s)
{
    if (!s)
        return json_sb_puts(b, "null");
    if (!json_sb_putc(b, '\"'))
        return 0;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
        case '\"':  if (!json_sb_puts(b, "\\\"")) return 0; break;
        case '\\': if (!json_sb_puts(b, "\\\\")) return 0; break;
        case '\n': if (!json_sb_puts(b, "\\n")) return 0; break;
        case '\r': if (!json_sb_puts(b, "\\r")) return 0; break;
        case '\t': if (!json_sb_puts(b, "\\t")) return 0; break;
        default:
            if (c < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                if (!json_sb_puts(b, buf)) return 0;
            } else {
                if (!json_sb_putc(b, (char)c)) return 0;
            }
            break;
        }
    }
    return json_sb_putc(b, '\"');
}

void myc_report_text(const myc_result *res)
{
    int i;
    size_t gi;
    printf("verdict:   %s\n", myc_verdict_name(res->verdict));
    printf("assurance: %s [legacy: gunakan assurance_vector + evidence matrix + finding/completeness]\n", myc_assurance_name(res->assurance));
    print_assurance_vector(&res->assurance_vector);
    printf("finding:   %s\n", myc_finding_name(res->finding));
    printf("completeness: %s\n", myc_completeness_name(res->completeness));
    printf("claim:     %s\n", myc_claim_status_name(res->claim_status));
    printf("error:     %s\n", myc_error_name(res->err));
    printf("exit_code: %d\n", res->exit_code);
    printf("duration:  %llu ms\n", res->duration_ms);
    if (res->receipt_sha256[0])
        printf("receipt_sha256: %s\n", res->receipt_sha256);
    if (res->cache_hit)
        printf("cache:     hit (replay dari .myc/evidence_cache.json)\n");
    else if (res->cache_delta_report)
        printf("cache:     %s\n", res->cache_delta_report);
    if (res->resolved_gcc)
        printf("gcc:       %s\n", res->resolved_gcc);
    /* MYC-AUDIT-022 (roadmap 7.1): exact tool identity. */
    if (res->gcc_version)
        printf("gcc_version: %s\n", res->gcc_version);
    if (res->clang_version)
        printf("clang_version: %s\n", res->clang_version);
    if (res->fingerprint)
        printf("fingerprint: %s\n", res->fingerprint);
    if (res->source_sha256)
        printf("source_sha256: %s\n", res->source_sha256);
    if (res->contract_requires > 0 || res->contract_ensures > 0)
        printf("contracts: requires=%d ensures=%d\n",
               res->contract_requires, res->contract_ensures);
    /* MYC-AUDIT-025 (roadmap 7.4): explicit clause status + stable
     * function binding + purity per klausa. */
    if (res->contract_clause_count > 0) {
        printf("contract clauses:\n");
        for (i = 0; i < res->contract_clause_count; i++) {
            const myc_contract_clause *cl = &res->contract_clauses[i];
            printf("  [%d] %-8s (%-8s) %s [%s]\n",
                   i + 1,
                   cl->kind == 0 ? "requires" : "ensures",
                   cl->func && cl->func[0] ? cl->func : "unbound",
                   cl->expr ? cl->expr : "(tak terbaca)",
                   myc_clause_status_name(cl->status));
        }
    }
    /* Fase 5 (Relational contracts): klasifikasi klausa kontrak
     * relasional (observasi, NON-blocking). */
    if (res->rel_analyzed > 0) {
        printf("relational (Fase 5): %d klausa dianalisis, %d unary, "
               "%d relational (>=2 variabel), %d unbound "
               "(observasi, NON-blocking)\n",
               res->rel_analyzed, res->rel_unary, res->rel_relations,
               res->rel_unbound);
        if (res->rel_report)
            printf("%s", res->rel_report);
    }
    /* Fase 5 (SOL-13): ghost state machine dari //@ sm (observasi). */
    if (res->sm_states > 0 || res->sm_findings > 0) {
        printf("state machine (SOL-13): %d state, %d event, %d transisi, "
               "%d finding (observasi, NON-blocking)\n",
               res->sm_states, res->sm_events, res->sm_transitions,
               res->sm_findings);
        if (res->sm_report)
            printf("%s", res->sm_report);
    }
    /* Fase 5 (SOL-14): ABI/FFI Surface Certificate (observasi). */
    if (res->abi_ran) {
        printf("abi certificate (SOL-14): %d struct, %d enum, %d symbol",
               res->abi_n_structs, res->abi_n_enums, res->abi_n_symbols);
        if (res->abi_target)
            printf(" [target=%s]", res->abi_target);
        if (res->abi_changed)
            printf(" -- ABI BERUBAH (%d delta)", res->abi_n_delta);
        printf(" (observasi, NON-blocking)\n");
        if (res->abi_changed && res->abi_delta)
            printf("%s", res->abi_delta);
    }
    /* Fase 5 (SOL-12): Resource Linearity Ledger (observasi). */
    if (res->rsrc_pairs > 0 || res->rsrc_leaks > 0 ||
        res->rsrc_double_releases > 0 || res->rsrc_release_unknown > 0) {
        printf("resource ledger (SOL-12): %d pasang profil, %d acquire, "
               "%d release, %d transfer, %d leak, %d double, %d unknown "
               "(observasi, NON-blocking)\n",
               res->rsrc_pairs, res->rsrc_acquires, res->rsrc_releases,
               res->rsrc_transferred, res->rsrc_leaks,
               res->rsrc_double_releases, res->rsrc_release_unknown);
        if (res->rsrc_report)
            printf("%s", res->rsrc_report);
    }
    /* Fase 5 B4 (DS-08): kandidat kontrak dari komentar biasa (observasi). */
    if (res->harvest_candidates > 0) {
        printf("harvest (B4): %d kandidat komentar-biasa, %d validated, "
               "%d unbound (observasi, NON-blocking)\n",
               res->harvest_candidates, res->harvest_validated,
               res->harvest_unbound);
        if (res->harvest_report)
            printf("%s", res->harvest_report);
    }
    /* Fase 5 B3 (DS-07): coaching transcript untuk model (observasi). */
    if (res->coaching_count > 0) {
        printf("coaching (B3): %d item taksonomi kognitif "
               "(observasi, NON-blocking)\n", res->coaching_count);
        if (res->coaching_report)
            printf("%s", res->coaching_report);
    }
    /* Fase 4 A1: ledger asumsi portabilitas (observasi NON-blocking;
     * verdict tidak turun karenanya kecuali --require-assumptions-closed). */
    if (res->assumption_count > 0) {
        printf("assumptions (A1 ledger): %d terdeteksi, %d terbuka "
               "(status: observed/contradicted)\n",
               res->assumption_detected, res->assumption_unclosed);
        for (i = 0; i < res->assumption_count; i++) {
            const myc_assumption *a = &res->assumptions[i];
            printf("  [%d] %s line %d %s (conf %d) status=%s\n",
                   i + 1, a->id ? a->id : "(null)", a->line,
                   a->kind ? a->kind : "(null)", a->confidence,
                   myc_assumption_status_name(
                       (myc_assumption_status)a->status));
            printf("      host: %s | risiko: %s\n",
                   a->host_fact ? a->host_fact : "(null)",
                   a->risk ? a->risk : "(null)");
            printf("      next: %s\n",
                   a->next_action ? a->next_action : "(null)");
        }
        if (res->assumption_ack_applied > 0)
            printf("ack: %d asumsi ditutup run ini (--assumption-ack)\n",
                   res->assumption_ack_applied);
    }
    if (res->ran_negative)
        printf("negative (9.8): callsites=%d deviations=%d\n",
               res->negative_callsites, res->negative_deviations);
    /* MYC-AUDIT-014: lint heuristik NON-blocking -- jumlah observasi. */
    if (res->lint_observations > 0)
        printf("lint (14): %d observasi (heuristik teks, NON-blocking; "
               "hard hanya dari bukti semantik)\n",
               res->lint_observations);
    if (res->lint_embedded_hits > 0)
        printf("bare-metal (C3/DS-11): %d observasi MMIO/volatile/alignment/"
               "ISR (mode freestanding, NON-blocking)\n",
               res->lint_embedded_hits);
    /* C5/DS-12: scenario pack terpakai (resep gate per domain). */
    if (res->scenario_applied)
        printf("scenario (C5): %s%s\n  %s\n", res->scenario_name,
               res->scenario_auto ? " (auto/D3)" : "",
               res->scenario_report ? res->scenario_report : "");
    /* C4: target matrix bare metal (portability matrix). */
    if (res->ran_matrix)
        printf("matrix (C4): %d target, %d delta asumsi vs host "
               "(portability, NON-blocking)\n  %s\n",
               res->matrix_available, res->matrix_deltas,
               res->matrix_report ? res->matrix_report : "");

    /* Scope Certificate (Fase 4, 9.11): daftar persis apa yang diperiksa.
     * Hanya memuat metrik yang BENAR-BENAR diukur; kolom yang tidak diukur
     * tidak dimunculkan (tidak mengarang angka). */
    if (res->contract_requires > 0 || res->contract_ensures > 0 ||
        res->driver_funcs > 0) {
        printf("scope:\n");
        if (res->contract_requires > 0 || res->contract_ensures > 0)
            printf("  contracts: requires=%d ensures=%d (total=%d)\n",
                   res->contract_requires, res->contract_ensures,
                   res->contract_requires + res->contract_ensures);
        if (res->driver_funcs > 0)
            printf("  driver: functions=%d cases=%d\n",
                   res->driver_funcs, res->driver_cases);
        if (res->ran_negative)
            printf("  negative: callsites=%d deviations=%d\n",
                   res->negative_callsites, res->negative_deviations);
    }

    for (i = 0; i < res->diag_count; i++) {
        const myc_diagnostic *d = &res->diags[i];
        /* Confidence ditampilkan hanya untuk heuristik teks; bukti
         * semantik (gcc/sanitizer/proof) = confirmed, label dihilangkan
         * agar output tetap ringkas (MYC-AUDIT-014). */
        if (d->confidence == MYC_CONF_CONFIRMED)
            printf("  [%d:%d] %s\n", d->line, d->col,
                   d->message ? d->message : "");
        else
            printf("  [%d:%d] [%s] %s\n", d->line, d->col,
                   myc_confidence_name(d->confidence),
                   d->message ? d->message : "");
    }

    if (res->stderr_text && res->stderr_text[0])
        printf("stderr:\n%s\n", res->stderr_text);

    if (res->ran_runtime) {
        printf("run:\n");
        printf("  timed_out: %s\n", res->run_timed_out ? "yes" : "no");
        printf("  run_exit_code: %d\n", res->exit_code);
        if (res->run_stdout_text && res->run_stdout_text[0])
            printf("  run_stdout:\n%s\n", res->run_stdout_text);
        if (res->run_stderr_text && res->run_stderr_text[0])
            printf("  run_stderr:\n%s\n", res->run_stderr_text);
        if (res->perturb_report)
            printf("  perturb: %s\n", res->perturb_report);
    }
    if (res->run_sanitizer_detected)
        printf("sanitizer: %s\n", res->run_sanitizer_marker);
    if (res->concur_report)
        printf("concur (Fase 6):\n%s\n", res->concur_report);

    if (res->ran_prove) {
        printf("prove:\n");
        printf("  mode: %s\n", res->prove_mode ? res->prove_mode
                                               : "eva (abstract interpretation)");
        if (res->prove_version)
            printf("  version: %s\n", res->prove_version);
        printf("  entry: main (default)\n");
        printf("  alarms: %d\n", res->prove_alarms);
        printf("  proof_obligations: %d\n", res->prove_proof_obligations);
        printf("  note: 0 alarm = tidak ada alarm RTE di bawah model Eva; "
               "bukan proof obligation WP\n");
        if (res->prove_stdout_text && res->prove_stdout_text[0])
            printf("  prove_stdout:\n%s\n", res->prove_stdout_text);
        if (res->prove_stderr_text && res->prove_stderr_text[0])
            printf("  prove_stderr:\n%s\n", res->prove_stderr_text);
    }

    if (res->ran_checked) {
        printf("checked:\n");
        printf("  uses_myc_buf: %s\n", res->checked_uses_buf ? "yes" : "no");
        /* MYC-AUDIT-026 (roadmap 7.3): coverage count — cakupan transformasi. */
        if (res->checked_uses_buf) {
            printf("  build_ok:     %s\n", res->checked_build_ok ? "yes" : "no");
            printf("  coverage:     buffers=%d allocations=%d accesses=%d frees=%d\n",
                   res->checked_buffers, res->checked_allocations,
                   res->checked_accesses, res->checked_frees);
        }
    }

    if (res->ran_filc) {
        printf("filc:\n");
        /* MYC-AUDIT-024 (roadmap 7.7): version identity + per-case scope. */
        if (res->filc_version)
            printf("  version: %s\n", res->filc_version);
        printf("  panics: %d\n", res->filc_panics);
        for (i = 0; i < res->filc_case_count; i++) {
            const myc_filc_case *c = &res->filc_cases[i];
            printf("  case #%d: %s\n", i + 1,
                   c->message ? c->message : "(detail tidak tersedia)");
            if (c->file && c->function)
                printf("      origin: %s @ %s:%d:%d\n",
                       c->function, c->file, c->line, c->col);
        }
        if (res->filc_stdout_text && res->filc_stdout_text[0])
            printf("  filc_stdout:\n%s\n", res->filc_stdout_text);
        if (res->filc_stderr_text && res->filc_stderr_text[0])
            printf("  filc_stderr:\n%s\n", res->filc_stderr_text);
    }

    if (res->ran_driver) {
        printf("driver:\n");
        printf("  funcs: %d\n", res->driver_funcs);
        printf("  cases: %d\n", res->driver_cases);
        printf("  skipped: %d\n", res->driver_skipped);
        /* Roadmap 7.5 (combinatorial budget + boundary portfolio):
         * strategi kombinasi dilaporkan; tiap nilai kandidat dari setiap
         * parameter dijamin muncul minimal sekali walau budget memotong. */
        printf("  combinatorial: max_product=%ld budget=%d strategy=%s\n",
               res->driver_max_product, MYC_MAX_DRIVER_CASES,
               res->driver_bounded ? "coverage-first" : "full");
        printf("  harness_sha256: %s\n",
               res->driver_harness_sha256 ? res->driver_harness_sha256
                                          : "(n/a)");
        if (res->driver_case_count > 0) {
            printf("  case records (input + status):\n");
            for (i = 0; i < res->driver_case_count; i++) {
                const myc_driver_case *c = &res->driver_case_records[i];
                printf("    #%-3d %s(%s) alloc=%ldB -> %s\n", c->case_id,
                       c->func ? c->func : "?",
                       c->params ? c->params : "",
                       c->alloc_bytes, c->executed ? "run" : "skip");
            }
        }
        if (res->driver_stdout_text && res->driver_stdout_text[0])
            printf("  driver_stdout:\n%s\n", res->driver_stdout_text);
        if (res->driver_stderr_text && res->driver_stderr_text[0])
            printf("  driver_stderr:\n%s\n", res->driver_stderr_text);
    }

    if (res->ran_exhaustive) {
        printf("exhaustive (A3):\n");
        printf("  funcs: %d  points: %ld  cases: %d  skipped: %d\n",
               res->exhaustive_funcs, res->exhaustive_points,
               res->exhaustive_cases, res->exhaustive_skipped);
        if (res->exhaustive_domain_hash[0])
            printf("  domain_hash: %s\n", res->exhaustive_domain_hash);
        if (res->exhaustive_laundering)
            printf("  SCOPE_LAUNDERING: domain kontrak dipersempit vs run "
                   "sebelumnya (proof laundering)\n");
        if (res->exhaustive_report)
            printf("%s", res->exhaustive_report);
        printf("  harness_sha256: %s\n",
               res->exhaustive_harness_sha256
                   ? res->exhaustive_harness_sha256 : "(n/a)");
        if (res->exhaustive_stdout_text && res->exhaustive_stdout_text[0])
            printf("  exhaustive_stdout:\n%s\n", res->exhaustive_stdout_text);
        if (res->exhaustive_stderr_text && res->exhaustive_stderr_text[0])
            printf("  exhaustive_stderr:\n%s\n", res->exhaustive_stderr_text);
    }

    if (res->ran_compare) {
        printf("compare (A4):\n");
        printf("  funcs: %d  cases: %ld  identical: %ld  divergent: %ld\n",
               res->compare_funcs, res->compare_cases,
               res->compare_identical, res->compare_divergent);
        printf("  preserved: %s  abi_same: %s  domain_same: %s\n",
               res->compare_preserved ? "yes" : "no",
               res->compare_abi_same ? "yes" : "no",
               res->compare_domain_same ? "yes" : "no");
        printf("  digest_ref: %s\n  digest_new: %s\n",
               res->compare_ref_digest, res->compare_new_digest);
        if (res->compare_report)
            printf("%s", res->compare_report);
        if (res->compare_delta)
            printf("  kasus divergen:\n%s\n", res->compare_delta);
    }

    if (res->ran_stack) {
        printf("stack (C2):\n");
        printf("  worst_bytes: %ld  budget: %d  recursion: %s  alloca: %s"
               "  vla: %s  unknown_calls: %d\n",
               res->stack_worst_bytes, res->stack_budget,
               res->stack_recursion ? "yes" : "no",
               res->stack_alloca ? "yes" : "no",
               res->stack_vla ? "yes" : "no",
               res->stack_unknown);
        if (res->stack_worst_path)
            printf("  worst_path: %s\n", res->stack_worst_path);
        if (res->stack_report)
            printf("%s", res->stack_report);
    }

    if (res->ran_fuzz) {
        printf("fuzz (D1):\n");
        printf("  funcs: %d  cases: %ld  skipped: %ld  seed: %u\n",
               res->fuzz_funcs, res->fuzz_cases, res->fuzz_skipped,
               res->fuzz_seed);
        if (res->fuzz_report)
            printf("%s", res->fuzz_report);
        if (res->fuzz_stdout_text && res->fuzz_stdout_text[0])
            printf("  fuzz_stdout:\n%s\n", res->fuzz_stdout_text);
        if (res->fuzz_stderr_text && res->fuzz_stderr_text[0])
            printf("  fuzz_stderr:\n%s\n", res->fuzz_stderr_text);
    }

    if (res->ran_mutate) {
        printf("mutate-audit (B5):\n");
        printf("  total: %d  caught: %d  gap: %d\n",
               res->mutate_total, res->mutate_caught, res->mutate_gap);
        if (res->mutate_report)
            printf("%s", res->mutate_report);
    }

    if (res->ran_freestanding) {
        printf("freestanding (C1):\n");
        printf("  api_hits: %d\n", res->freestanding_api_hits);
        if (res->freestanding_report)
            printf("%s", res->freestanding_report);
    }

    if (res->ran_metamorphic) {
        printf("metamorphic (9.7):\n");
        printf("  o0_exit: %d  o2_exit: %d\n",
               res->meta_o0_exit, res->meta_o2_exit);
        printf("  o0_finding: %s  o2_finding: %s\n",
               res->meta_o0_finding ? "yes" : "no",
               res->meta_o2_finding ? "yes" : "no");
        if (res->metamorphic_inconsistent)
            printf("  inconsistent: ya (hasil -O0 vs -O2 tidak setuju)\n");
    }

    if (res->ran_divergence) {
        printf("divergence (A2/DS-02):\n");
        printf("  cells ran: %d/%d  planned: %d\n",
               res->divergence_ran, res->divergence_ncells,
               res->divergence_planned);
        if (res->divergence_sanitizer_div)
            printf("  klasifikasi: sanitizer_divergence (HARD — bug "
                   "toolchain-sensitive)\n");
        else if (res->divergence_all_findings)
            printf("  klasifikasi: all_findings (HARD — bug konsisten)\n");
        else if (res->divergence_semantic_div)
            printf("  klasifikasi: semantic_divergence (observasi)\n");
        else
            printf("  klasifikasi: konsisten antar toolchain\n");
        if (res->divergence_diag_div)
            printf("  diagnostic_divergence: set warning build beda "
                   "(observasi)\n");
        if (res->divergence_report) {
            const char *p = res->divergence_report;
            printf("  matrix:\n");
            while (*p) {
                printf("    ");
                while (*p && *p != '\n') {
                    putchar(*p);
                    p++;
                }
                putchar('\n');
                if (*p)
                    p++;
            }
        }
    }

    /* Evidence matrix (Fase 4): ringkasan status per scope, bukan hanya
     * label assurance. Memenuhi prinsip "setiap klaim menyertakan scope". */
    printf("evidence:\n");
    for (gi = 0; gi < res->gate_count; gi++) {
        const myc_gate_result *g = &res->gates[gi];
        printf("  %-12s %s\n",
               g->id < MYC_GATE_COUNT ? myc_gate_id_short(g->id) : "?",
               myc_gate_status_name(g->status));
    }

    printf("gates:\n");
    for (gi = 0; gi < res->gate_count; gi++) {
        const myc_gate_result *g = &res->gates[gi];
        printf("  %s: %s",
               g->id < MYC_GATE_COUNT ? myc_gate_id_short(g->id) : "?",
               myc_gate_status_name(g->status));
        if (g->output && g->output[0])
            printf(" (%s)\n", g->output);
        else
            printf("\n");
    }

if (res->debt_count > 0) {
         printf("unverified_debt (verification gap - MYC-INCOMPLETE):\n");
         for (gi = 0; gi < res->debt_count; gi++) {
             const myc_debt_item *d = &res->debt[gi];
             printf("  [%s] %s\n", myc_debt_code(d->type),
                    d->text ? d->text : "");
         }
         if (res->require_complete)
             printf("require_complete: enforced - verification gap "
                    "menjadikan hasil GAGAL (INCONCLUSIVE)\n");
     }

     /* Fase 3, SOL-30: Assurance Budget Contract. */
     if (res->budget_active) {
         printf("budget:      %s\n",
                res->budget_met ? "target TERCAPAI" : "target TIDAK tercapai");
         if (res->budget_report)
             printf("%s", res->budget_report);
     }

      /* Differential Backend Quorum (#3). */
      if (res->quorum_status != MYC_QUORUM_NOT_REQUESTED) {
          printf("quorum: %s\n",
                 myc_quorum_status_name(res->quorum_status));
          if (res->quorum_report)
              printf("%s", res->quorum_report);
      }

      /* Temporal Ledger (Fase 2): delta vs run sebelumnya. */
      if (res->ledger_parent_found) {
          printf("ledger:\n");
          printf("  receipt_parent: %s\n",
                 res->receipt_parent ? res->receipt_parent : "(none)");
          printf("  delta: %s\n",
                 res->delta_kind ? res->delta_kind : "persistent");
          printf("  delta_changed: %s\n",
                 res->delta_changed ? "yes" : "no");
      }

     /* Counterexample Replay Capsule (#2). */
     if (res->capsule) {
         const myc_replay_capsule *cap = res->capsule;
         printf("capsule:\n");
         printf("  source_sha256: %s\n",
                cap->source_sha256 ? cap->source_sha256 : "");
         if (cap->stdin_sha256)
             printf("  stdin_sha256: %s (len=%zu)\n",
                    cap->stdin_sha256, cap->stdin_len);
         printf("  clang: %s\n", cap->clang_path ? cap->clang_path : "");
         printf("  gcc: %s\n", cap->gcc_path ? cap->gcc_path : "");
         printf("  cwd: %s\n", cap->cwd ? cap->cwd : "");
         printf("  timeout_ms: %d\n", cap->timeout_ms);
         printf("  max_output_bytes: %d\n", cap->max_output_bytes);
         printf("  strict: %s\n", cap->strict ? "yes" : "no");
         printf("  run_analyzer: %s\n", cap->run_analyzer ? "yes" : "no");
         printf("  run: %s\n", cap->run ? "yes" : "no");
         printf("  prove: %s\n", cap->prove ? "yes" : "no");
         printf("  checked: %s\n", cap->checked ? "yes" : "no");
         printf("  filc: %s\n", cap->filc ? "yes" : "no");
         printf("  driver: %s\n", cap->driver ? "yes" : "no");
         printf("  metamorphic: %s\n", cap->metamorphic ? "yes" : "no");
         printf("  divergence: %s\n", cap->divergence_ran ? "yes" : "no");
         printf("  negative: %s\n", cap->negative ? "yes" : "no");
         if (cap->negative)
             printf("  negative_callsites: %d  negative_deviations: %d\n",
                    cap->negative_callsites, cap->negative_deviations);
         /* MYC-AUDIT-026: coverage count checked-build di capsule. */
         if (cap->checked)
             printf("  checked_coverage: buffers=%d allocations=%d accesses=%d frees=%d\n",
                    cap->checked_buffers, cap->checked_allocations,
                    cap->checked_accesses, cap->checked_frees);
         /* Roadmap 7.5: driver case records + harness sha (replay). */
         if (cap->driver) {
             int dci;
             printf("  driver_funcs: %d  driver_cases: %d  driver_skipped: %d\n",
                    cap->driver_funcs, cap->driver_cases, cap->driver_skipped);
             printf("  driver_combinatorial: max_product=%ld budget=%d strategy=%s\n",
                    cap->driver_max_product, MYC_MAX_DRIVER_CASES,
                    cap->driver_bounded ? "coverage-first" : "full");
             printf("  driver_harness_sha256: %s\n",
                    cap->driver_harness_sha256 ? cap->driver_harness_sha256 : "");
             for (dci = 0; dci < cap->driver_case_count; dci++) {
                 const myc_driver_case *c = &cap->driver_case_records[dci];
                 printf("    case #%-3d %s(%s) alloc=%ldB -> %s\n",
                        c->case_id, c->func ? c->func : "?",
                        c->params ? c->params : "", c->alloc_bytes,
                        c->executed ? "run" : "skip");
             }
         }
         printf("  require_complete: %s\n",
                cap->require_complete ? "yes" : "no");
         if (cap->budget_active)
             printf("  budget: %s\n",
                    cap->budget_met ? "target tercapai" : "target tidak tercapai");
         if (cap->metamorphic) {
             printf("  meta_o0_exit: %d  meta_o2_exit: %d\n",
                    cap->meta_o0_exit, cap->meta_o2_exit);
             printf("  meta_o0_finding: %s  meta_o2_finding: %s  inconsistent: %s\n",
                    cap->meta_o0_finding ? "yes" : "no",
                    cap->meta_o2_finding ? "yes" : "no",
                    cap->metamorphic_inconsistent ? "yes" : "no");
         }
         if (cap->divergence_ran) {
             printf("  divergence: cells_ran=%d  san_div=%s  all_find=%s  "
                    "semantic=%s  diag=%s\n",
                    cap->divergence_ran,
                    cap->divergence_sanitizer_div ? "yes" : "no",
                    cap->divergence_all_findings ? "yes" : "no",
                    cap->divergence_semantic_div ? "yes" : "no",
                    cap->divergence_diag_div ? "yes" : "no");
         }
         printf("  verdict: %s\n", myc_verdict_name(cap->verdict));
         printf("  exit_code: %d\n", cap->exit_code);
         printf("  timed_out: %s\n", cap->timed_out ? "yes" : "no");
         printf("  sanitizer_detected: %s\n",
                cap->sanitizer_detected ? "yes" : "no");
         if (cap->sanitizer_detected)
             printf("  sanitizer_marker: %s\n", cap->sanitizer_marker);
         printf("  gate_status:\n");
         for (gi = 0; gi < MYC_GATE_COUNT; gi++) {
             if (cap->gate_status[gi] != MYC_GATE_NOT_REQUESTED)
                 printf("    %s: %s\n",
                        myc_gate_id_short((myc_gate_id)gi),
                        myc_gate_status_name(cap->gate_status[gi]));
         }
         printf("  finding: %s\n", myc_finding_name(cap->finding));
         printf("  completeness: %s\n",
                myc_completeness_name(cap->completeness));
         printf("  claim: %s\n",
                myc_claim_status_name(cap->claim_status));
         printf("  quorum: %s\n",
                myc_quorum_status_name(cap->quorum_status));
     }
 }

char *myc_result_to_json(const myc_result *res)
{
    json_sb b;
    int     i;
    int     gi;
    if (!json_sb_init(&b))
        return NULL;
    json_sb_puts(&b, "{");
    json_sb_printf(&b, "\"verdict\":\"%s\",", myc_verdict_name(res->verdict));
    json_sb_printf(&b, "\"assurance\":\"%s\",", myc_assurance_name(res->assurance));
    json_sb_printf(&b, "\"assurance_legacy\":true,");
    /* Assurance vector (MYC-AUDIT-006): ringkasan per dimensi orthogonal,
     * turunan dari typed gate status. */
    json_sb_puts(&b, "\"assurance_vector\":{");
    {
        static const char dim_chars[MYC_DIM_COUNT] = {
            'C', 'S', 'R', 'B', 'P', 'D', 'F'
        };
        int dim_i;
        for (dim_i = 0; dim_i < MYC_DIM_COUNT; dim_i++) {
            if (dim_i)
                json_sb_puts(&b, ",");
            json_sb_printf(&b, "\"%c\":{\"status\":\"%s\"}",
                           dim_chars[dim_i],
                           myc_dim_status_name(
                               res->assurance_vector.status[dim_i]));
        }
    }
    json_sb_puts(&b, "},");
    json_sb_printf(&b, "\"finding\":\"%s\",", myc_finding_name(res->finding));
    json_sb_printf(&b, "\"completeness\":\"%s\",", myc_completeness_name(res->completeness));
    json_sb_printf(&b, "\"claim\":\"%s\",", myc_claim_status_name(res->claim_status));
    json_sb_printf(&b, "\"error\":\"%s\",", myc_error_name(res->err));
    json_sb_printf(&b, "\"exit_code\":%d,", res->exit_code);
    json_sb_printf(&b, "\"duration_ms\":%llu,", (unsigned long long)res->duration_ms);
        json_sb_printf(&b, "\"receipt_sha256\":");
    json_sb_escape(&b, res->receipt_sha256);
    json_sb_puts(&b, ",");
    json_sb_printf(&b, "\"require_complete\":%s,",
                   res->require_complete ? "true" : "false");
    json_sb_printf(&b, "\"cache_hit\":%s,",
                   res->cache_hit ? "true" : "false");
    if (res->cache_delta_report) {
        json_sb_printf(&b, "\"cache_delta\":");
        json_sb_escape(&b, res->cache_delta_report);
        json_sb_puts(&b, ",");
    }
    /* Fase 4 A1: ledger asumsi portabilitas. */
    json_sb_printf(&b, "\"assumptions\":{\"detected\":%d,\"count\":%d,"
                       "\"unclosed\":%d,\"ok\":%s,\"ack_applied\":%d,"
                       "\"items\":[",
                   res->assumption_detected, res->assumption_count,
                   res->assumption_unclosed,
                   res->assumption_ok ? "true" : "false",
                   res->assumption_ack_applied);
    for (i = 0; i < res->assumption_count; i++) {
        const myc_assumption *a = &res->assumptions[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b, "{\"id\":");
        json_sb_escape(&b, a->id);
        json_sb_printf(&b, ",\"kind\":");
        json_sb_escape(&b, a->kind);
        json_sb_printf(&b,
                       ",\"line\":%d,\"status\":\"%s\","
                       "\"confidence\":%d,\"anchor\":",
                       a->line,
                       myc_assumption_status_name(
                           (myc_assumption_status)a->status),
                       a->confidence);
        json_sb_escape(&b, a->anchor);
        json_sb_printf(&b, ",\"host_fact\":");
        json_sb_escape(&b, a->host_fact);
        json_sb_printf(&b, ",\"risk\":");
        json_sb_escape(&b, a->risk);
        json_sb_printf(&b, ",\"next_action\":");
        json_sb_escape(&b, a->next_action);
        json_sb_puts(&b, "}");
    }
    json_sb_puts(&b, "]},");
    json_sb_printf(&b, "\"resolved_gcc\":");
    json_sb_escape(&b, res->resolved_gcc);
    json_sb_puts(&b, ",");
    /* MYC-AUDIT-022 (roadmap 7.1): exact tool identity (NULL -> null). */
    json_sb_printf(&b, "\"gcc_version\":");
    json_sb_escape(&b, res->gcc_version);
    json_sb_puts(&b, ",");
    json_sb_printf(&b, "\"clang_version\":");
    json_sb_escape(&b, res->clang_version);
    json_sb_puts(&b, ",");
    json_sb_printf(&b, "\"fingerprint\":");
    json_sb_escape(&b, res->fingerprint);
    json_sb_puts(&b, ",");
    json_sb_printf(&b, "\"source_sha256\":");
    json_sb_escape(&b, res->source_sha256);
    json_sb_puts(&b, ",");
    json_sb_printf(&b, "\"contract_requires\":%d,", res->contract_requires);
    json_sb_printf(&b, "\"contract_ensures\":%d,", res->contract_ensures);
    /* MYC-AUDIT-025 (roadmap 7.4): per-klausa (status + binding + purity). */
    json_sb_printf(&b, "\"contract_clauses\":[");
    for (i = 0; i < res->contract_clause_count; i++) {
        const myc_contract_clause *cl = &res->contract_clauses[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b, "{\"kind\":\"%s\",\"function\":",
                       cl->kind == 0 ? "requires" : "ensures");
        json_sb_escape(&b, cl->func);
        json_sb_printf(&b, ",\"expr\":");
        json_sb_escape(&b, cl->expr);
        json_sb_printf(&b, ",\"status\":\"%s\",\"line\":%d,\"col\":%d}",
                       myc_clause_status_name(cl->status), cl->line, cl->col);
    }
    json_sb_puts(&b, "],");
    /* Fase 5 (Relational contracts): klasifikasi klausa kontrak
     * relasional (>=2 variabel) vs unary + binding check (observasi). */
    json_sb_printf(&b, "\"relational\":{\"analyzed\":%d,\"unary\":%d,"
                       "\"relations\":%d,\"unbound\":%d,\"clauses\":[",
                   res->rel_analyzed, res->rel_unary, res->rel_relations,
                   res->rel_unbound);
    for (i = 0; i < res->rel_clause_count; i++) {
        const myc_rel_clause *rc = &res->rel_clauses[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b, "{\"kind\":\"%s\",\"function\":",
                       rc->kind == 0 ? "requires" : "ensures");
        json_sb_escape(&b, rc->func);
        json_sb_printf(&b, ",\"expr\":");
        json_sb_escape(&b, rc->expr);
        json_sb_printf(&b, ",\"vars\":%d,\"relational\":%s,"
                           "\"unbound\":%s,\"order\":%s,"
                           "\"equality\":%s,\"arithmetic\":%s,"
                           "\"logic\":%s,\"line\":%d,\"col\":%d}",
                       rc->nvars, rc->relational ? "true" : "false",
                       rc->unbound ? "true" : "false",
                       rc->has_order ? "true" : "false",
                       rc->has_equality ? "true" : "false",
                       rc->has_arith ? "true" : "false",
                       rc->has_logic ? "true" : "false",
                       rc->line, rc->col);
    }
    json_sb_puts(&b, "],\"report\":");
    json_sb_escape(&b, res->rel_report);
    json_sb_puts(&b, "},");
    /* Fase 5 (SOL-13): ghost state machine (observasi NON-blocking). */
    json_sb_printf(&b, "\"state_machine\":{\"states\":%d,\"events\":%d,"
                       "\"transitions\":%d,\"findings\":%d,"
                       "\"finding_list\":[",
                   res->sm_states, res->sm_events, res->sm_transitions,
                   res->sm_findings);
    for (i = 0; i < res->sm_findings && i < MYC_SM_MAX_FINDINGS; i++) {
        const myc_sm_finding *f = &res->sm_finding_list[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b, "{\"kind\":\"%s\",\"text\":",
                       myc_sm_finding_name(f->kind));
        json_sb_escape(&b, f->text);
        json_sb_printf(&b, ",\"witness\":");
        json_sb_escape(&b, f->witness);
        json_sb_printf(&b, ",\"line\":%d}", f->line);
    }
    json_sb_puts(&b, "],\"report\":");
    json_sb_escape(&b, res->sm_report);
    json_sb_puts(&b, "},");
    /* Fase 5 (SOL-14): ABI certificate (observasi NON-blocking). */
    json_sb_printf(&b, "\"abi\":{\"ran\":%s,\"structs\":%d,\"enums\":%d,"
                       "\"symbols\":%d,\"changed\":%s,\"delta\":%d,"
                       "\"target\":",
                   res->abi_ran ? "true" : "false", res->abi_n_structs,
                   res->abi_n_enums, res->abi_n_symbols,
                   res->abi_changed ? "true" : "false", res->abi_n_delta);
    json_sb_escape(&b, res->abi_target ? res->abi_target : "");
    json_sb_puts(&b, ",\"header_sha\":");
    json_sb_escape(&b, res->abi_header_sha ? res->abi_header_sha : "");
    json_sb_puts(&b, ",\"snapshot\":");
    json_sb_escape(&b, res->abi_snapshot ? res->abi_snapshot : "");
    json_sb_puts(&b, ",\"delta_text\":");
    json_sb_escape(&b, res->abi_delta ? res->abi_delta : "");
    json_sb_puts(&b, "},");
    /* Fase 5 (SOL-12): Resource Linearity Ledger (observasi NON-blocking). */
    json_sb_printf(&b, "\"resource\":{\"ran\":%s,\"pairs\":%d,"
                       "\"acquires\":%d,\"releases\":%d,\"transferred\":%d,"
                       "\"leaks\":%d,\"double_releases\":%d,"
                       "\"release_unknown\":%d,\"findings\":[",
                   res->rsrc_ran ? "true" : "false", res->rsrc_pairs,
                   res->rsrc_acquires, res->rsrc_releases,
                   res->rsrc_transferred, res->rsrc_leaks,
                   res->rsrc_double_releases, res->rsrc_release_unknown);
    for (i = 0; i < MYC_RSRC_MAX_FINDINGS; i++) {
        const myc_rsrc_finding *f = &res->rsrc_finding_list[i];
        if (f->text == NULL && f->witness == NULL)
            break;
        if (i > 0)
            json_sb_puts(&b, ",");
        json_sb_printf(&b, "{\"kind\":\"%s\",\"line\":%d,\"text\":",
                       myc_rsrc_finding_name(f->kind), f->line);
        json_sb_escape(&b, f->text);
        json_sb_printf(&b, ",\"witness\":");
        json_sb_escape(&b, f->witness);
        json_sb_puts(&b, "}");
    }
    json_sb_puts(&b, "],\"report\":");
    json_sb_escape(&b, res->rsrc_report ? res->rsrc_report : "");
    json_sb_puts(&b, "},");
    /* Fase 5 B4 (DS-08): harvest kandidat kontrak dari komentar biasa. */
    json_sb_printf(&b, "\"harvest\":{\"candidates\":%d,\"validated\":%d,"
                       "\"unbound\":%d,\"report\":",
                   res->harvest_candidates, res->harvest_validated,
                   res->harvest_unbound);
    json_sb_escape(&b, res->harvest_report);
    json_sb_puts(&b, "},");
    /* Fase 5 B3 (DS-07): coaching transcript (taksonomi kognitif). */
    json_sb_printf(&b, "\"coaching\":{\"count\":%d,\"items\":[",
                   res->coaching_count);
    for (i = 0; i < res->coaching_count; i++) {
        const myc_coaching_item *c = &res->coaching[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b, "{\"class\":\"%s\",\"line\":%d,\"where\":",
                       myc_taxonomy_name(c->cls), c->line);
        json_sb_escape(&b, c->where);
        json_sb_puts(&b, "}");
    }
    json_sb_puts(&b, "],\"report\":");
    json_sb_escape(&b, res->coaching_report);
    json_sb_puts(&b, "},");
    json_sb_printf(&b, "\"ran_negative\":%s,", res->ran_negative ? "true" : "false");
    if (res->ran_negative) {
        json_sb_printf(&b, "\"negative_callsites\":%d,", res->negative_callsites);
        json_sb_printf(&b, "\"negative_deviations\":%d,", res->negative_deviations);
    }
    /* MYC-AUDIT-014: jumlah observasi lint heuristik (non-blocking). */
    json_sb_printf(&b, "\"lint_observations\":%d,", res->lint_observations);
    json_sb_printf(&b, "\"lint_embedded_hits\":%d,", res->lint_embedded_hits);
    if (res->scenario_applied) {
        json_sb_printf(&b, "\"scenario\":{\"applied\":true,\"auto\":%s,"
                           "\"name\":",
                       res->scenario_auto ? "true" : "false");
        json_sb_escape(&b, res->scenario_name);
        json_sb_printf(&b, ",\"report\":");
        json_sb_escape(&b, res->scenario_report);
        json_sb_puts(&b, "},");
    }
    if (res->ran_matrix) {
        json_sb_printf(&b, "\"matrix\":{\"targets\":%d,\"available\":%d,"
                           "\"deltas\":%d,\"report\":",
                       res->matrix_targets, res->matrix_available,
                       res->matrix_deltas);
        json_sb_escape(&b, res->matrix_report);
        json_sb_puts(&b, "},");
    }
    json_sb_printf(&b, "\"truncated\":%s,", res->truncated ? "true" : "false");
    json_sb_printf(&b, "\"sanitizer_detected\":%s,", res->run_sanitizer_detected ? "true" : "false");
    if (res->run_sanitizer_detected)
        json_sb_printf(&b, "\"sanitizer_marker\":\"%s\",", res->run_sanitizer_marker);
    json_sb_printf(&b, "\"stdout_bytes\":%llu,",
                   (unsigned long long)res->total_stdout_bytes);
    json_sb_printf(&b, "\"stderr_bytes\":%llu,",
                   (unsigned long long)res->total_stderr_bytes);
    json_sb_printf(&b, "\"ran_runtime\":%s,", res->ran_runtime ? "true" : "false");
    if (res->ran_runtime) {
        json_sb_printf(&b, "\"run_timed_out\":%s,", res->run_timed_out ? "true" : "false");
        json_sb_printf(&b, "\"run_exit_code\":%d,", res->exit_code);
        json_sb_printf(&b, "\"run_stdout\":");
        json_sb_escape(&b, res->run_stdout_text);
        json_sb_puts(&b, ",");
        json_sb_printf(&b, "\"run_stderr\":");
        json_sb_escape(&b, res->run_stderr_text);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"ran_checked\":%s,", res->ran_checked ? "true" : "false");
    json_sb_printf(&b, "\"checked_uses_buf\":%s,",
                   res->checked_uses_buf ? "true" : "false");
    json_sb_printf(&b, "\"checked_build_ok\":%s,",
                   res->checked_build_ok ? "true" : "false");
    /* MYC-AUDIT-026: coverage count per makro (hanya bila memakai MYC_BUF). */
    if (res->checked_uses_buf) {
        json_sb_printf(&b, "\"checked_buffers\":%d,", res->checked_buffers);
        json_sb_printf(&b, "\"checked_allocations\":%d,", res->checked_allocations);
        json_sb_printf(&b, "\"checked_accesses\":%d,", res->checked_accesses);
        json_sb_printf(&b, "\"checked_frees\":%d,", res->checked_frees);
    }
    json_sb_printf(&b, "\"ran_filc\":%s,", res->ran_filc ? "true" : "false");
    json_sb_printf(&b, "\"filc_panics\":%d,", res->filc_panics);
    /* MYC-AUDIT-024 (roadmap 7.7): version identity + per-case scope. */
    json_sb_printf(&b, "\"filc_version\":");
    json_sb_escape(&b, res->filc_version);
    json_sb_puts(&b, ",");
    json_sb_printf(&b, "\"filc_cases\":[");
    for (i = 0; i < res->filc_case_count; i++) {
        const myc_filc_case *c = &res->filc_cases[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b, "{\"message\":");
        json_sb_escape(&b, c->message);
        json_sb_printf(&b, ",\"file\":");
        json_sb_escape(&b, c->file);
        json_sb_printf(&b, ",\"line\":%d,\"col\":%d,\"function\":",
                       c->line, c->col);
        json_sb_escape(&b, c->function);
        json_sb_puts(&b, "}");
    }
    json_sb_puts(&b, "],");
    if (res->ran_filc) {
        json_sb_printf(&b, "\"filc_stdout\":");
        json_sb_escape(&b, res->filc_stdout_text);
        json_sb_puts(&b, ",");
        json_sb_printf(&b, "\"filc_stderr\":");
        json_sb_escape(&b, res->filc_stderr_text);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"ran_driver\":%s,", res->ran_driver ? "true" : "false");
    json_sb_printf(&b, "\"driver_funcs\":%d,", res->driver_funcs);
    json_sb_printf(&b, "\"driver_cases\":%d,", res->driver_cases);
    json_sb_printf(&b, "\"driver_skipped\":%d,", res->driver_skipped);
    if (res->ran_driver) {
        /* Roadmap 7.5: combinatorial budget + case record (replay). */
        json_sb_printf(&b, "\"driver_max_product\":%ld,", res->driver_max_product);
        json_sb_printf(&b, "\"driver_bounded\":%s,",
                       res->driver_bounded ? "true" : "false");
        json_sb_printf(&b, "\"driver_harness_sha256\":");
        json_sb_escape(&b, res->driver_harness_sha256);
        json_sb_puts(&b, ",");
        json_sb_printf(&b, "\"driver_case_records\":[");
        for (i = 0; i < res->driver_case_count; i++) {
            const myc_driver_case *c = &res->driver_case_records[i];
            if (i)
                json_sb_puts(&b, ",");
            json_sb_puts(&b, "{");
            json_sb_printf(&b, "\"case_id\":%d,", c->case_id);
            json_sb_printf(&b, "\"func\":");
            json_sb_escape(&b, c->func);
            json_sb_puts(&b, ",");
            json_sb_printf(&b, "\"params\":");
            json_sb_escape(&b, c->params);
            json_sb_printf(&b, ",\"alloc_bytes\":%ld,", c->alloc_bytes);
            json_sb_printf(&b, "\"executed\":%s",
                           c->executed ? "true" : "false");
            json_sb_puts(&b, "}");
        }
        json_sb_puts(&b, "],");
    }
    json_sb_printf(&b, "\"ran_metamorphic\":%s,",
                   res->ran_metamorphic ? "true" : "false");
    if (res->ran_metamorphic) {
        json_sb_printf(&b, "\"meta_o0_exit\":%d,", res->meta_o0_exit);
        json_sb_printf(&b, "\"meta_o2_exit\":%d,", res->meta_o2_exit);
        json_sb_printf(&b, "\"meta_o0_finding\":%s,",
                       res->meta_o0_finding ? "true" : "false");
        json_sb_printf(&b, "\"meta_o2_finding\":%s,",
                       res->meta_o2_finding ? "true" : "false");
        json_sb_printf(&b, "\"metamorphic_inconsistent\":%s,",
                       res->metamorphic_inconsistent ? "true" : "false");
    }
    json_sb_printf(&b, "\"ran_exhaustive\":%s,",
                   res->ran_exhaustive ? "true" : "false");
    if (res->ran_exhaustive) {
        json_sb_printf(&b, "\"exhaustive_funcs\":%d,", res->exhaustive_funcs);
        json_sb_printf(&b, "\"exhaustive_cases\":%d,", res->exhaustive_cases);
        json_sb_printf(&b, "\"exhaustive_skipped\":%d,",
                       res->exhaustive_skipped);
        json_sb_printf(&b, "\"exhaustive_points\":%ld,",
                       res->exhaustive_points);
        json_sb_printf(&b, "\"exhaustive_laundering\":%s,",
                       res->exhaustive_laundering ? "true" : "false");
        json_sb_printf(&b, "\"exhaustive_domain_hash\":\"%s\",",
                       res->exhaustive_domain_hash);
        json_sb_puts(&b, "\"exhaustive_report\":");
        json_sb_escape(&b, res->exhaustive_report);
        json_sb_puts(&b, ",");
        json_sb_printf(&b, "\"exhaustive_harness_sha256\":");
        json_sb_escape(&b, res->exhaustive_harness_sha256);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"ran_compare\":%s,",
                   res->ran_compare ? "true" : "false");
    if (res->ran_compare) {
        json_sb_printf(&b, "\"compare_funcs\":%d,", res->compare_funcs);
        json_sb_printf(&b, "\"compare_cases\":%ld,", res->compare_cases);
        json_sb_printf(&b, "\"compare_identical\":%ld,",
                       res->compare_identical);
        json_sb_printf(&b, "\"compare_divergent\":%ld,",
                       res->compare_divergent);
        json_sb_printf(&b, "\"compare_preserved\":%s,",
                       res->compare_preserved ? "true" : "false");
        json_sb_printf(&b, "\"compare_abi_same\":%s,",
                       res->compare_abi_same ? "true" : "false");
        json_sb_printf(&b, "\"compare_domain_same\":%s,",
                       res->compare_domain_same ? "true" : "false");
        json_sb_printf(&b, "\"compare_ref_digest\":\"%s\",",
                       res->compare_ref_digest);
        json_sb_printf(&b, "\"compare_new_digest\":\"%s\",",
                       res->compare_new_digest);
        json_sb_puts(&b, "\"compare_report\":");
        json_sb_escape(&b, res->compare_report);
        json_sb_puts(&b, ",");
        json_sb_puts(&b, "\"compare_delta\":");
        json_sb_escape(&b, res->compare_delta);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"ran_stack\":%s,", res->ran_stack ? "true" : "false");
    if (res->ran_stack) {
        json_sb_printf(&b, "\"stack_worst_bytes\":%ld,",
                       res->stack_worst_bytes);
        json_sb_printf(&b, "\"stack_budget\":%d,", res->stack_budget);
        json_sb_printf(&b, "\"stack_recursion\":%s,",
                       res->stack_recursion ? "true" : "false");
        json_sb_printf(&b, "\"stack_alloca\":%s,",
                       res->stack_alloca ? "true" : "false");
        json_sb_printf(&b, "\"stack_vla\":%s,", res->stack_vla ? "true" : "false");
        json_sb_printf(&b, "\"stack_unknown\":%d,", res->stack_unknown);
        json_sb_puts(&b, "\"stack_report\":");
        json_sb_escape(&b, res->stack_report);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"ran_fuzz\":%s,", res->ran_fuzz ? "true" : "false");
    if (res->ran_fuzz) {
        json_sb_printf(&b, "\"fuzz_funcs\":%d,", res->fuzz_funcs);
        json_sb_printf(&b, "\"fuzz_cases\":%ld,", res->fuzz_cases);
        json_sb_printf(&b, "\"fuzz_skipped\":%ld,", res->fuzz_skipped);
        json_sb_printf(&b, "\"fuzz_seed\":%u,", res->fuzz_seed);
        json_sb_puts(&b, "\"fuzz_report\":");
        json_sb_escape(&b, res->fuzz_report);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"ran_mutate\":%s,", res->ran_mutate ? "true" : "false");
    if (res->ran_mutate) {
        json_sb_printf(&b, "\"mutate_total\":%d,", res->mutate_total);
        json_sb_printf(&b, "\"mutate_caught\":%d,", res->mutate_caught);
        json_sb_printf(&b, "\"mutate_gap\":%d,", res->mutate_gap);
        json_sb_puts(&b, "\"mutate_report\":");
        json_sb_escape(&b, res->mutate_report);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"ran_freestanding\":%s,",
                   res->ran_freestanding ? "true" : "false");
    if (res->ran_freestanding) {
        json_sb_printf(&b, "\"freestanding_api_hits\":%d,",
                       res->freestanding_api_hits);
        json_sb_puts(&b, "\"freestanding_report\":");
        json_sb_escape(&b, res->freestanding_report);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"ran_divergence\":%s,",
                   res->ran_divergence ? "true" : "false");
    if (res->ran_divergence) {
        int di;
        json_sb_printf(&b, "\"divergence_ran\":%d,", res->divergence_ran);
        json_sb_printf(&b, "\"divergence_planned\":%d,",
                       res->divergence_planned);
        json_sb_printf(&b, "\"divergence_sanitizer_div\":%s,",
                       res->divergence_sanitizer_div ? "true" : "false");
        json_sb_printf(&b, "\"divergence_all_findings\":%s,",
                       res->divergence_all_findings ? "true" : "false");
        json_sb_printf(&b, "\"divergence_semantic_div\":%s,",
                       res->divergence_semantic_div ? "true" : "false");
        json_sb_printf(&b, "\"divergence_diag_div\":%s,",
                       res->divergence_diag_div ? "true" : "false");
        json_sb_puts(&b, "\"divergence_cells\":[");
        for (di = 0; di < res->divergence_ncells; di++) {
            const myc_divergence_cell *c = &res->divergence_cells[di];
            if (di > 0)
                json_sb_puts(&b, ",");
            json_sb_puts(&b, "{\"tool\":");
            json_sb_escape(&b, c->tool);
            json_sb_printf(&b, ",\"opt\":\"%s\",\"available\":%s,"
                               "\"built\":%s,\"ran\":%s,\"timed_out\":%s,"
                               "\"finding\":%s,\"exit\":%d,\"marker\":",
                           c->opt_level == 0 ? "-O0" : "-O2",
                           c->available ? "true" : "false",
                           c->built ? "true" : "false",
                           c->ran ? "true" : "false",
                           c->timed_out ? "true" : "false",
                           c->finding ? "true" : "false",
                           c->exit_code);
            json_sb_escape(&b, c->marker);
            json_sb_puts(&b, ",\"stdout_sha256\":");
            json_sb_escape(&b, c->stdout_sha256);
            json_sb_puts(&b, "}");
        }
        json_sb_puts(&b, "],");
        json_sb_puts(&b, "\"divergence_report\":");
        json_sb_escape(&b, res->divergence_report ? res->divergence_report
                                                  : "");
        json_sb_puts(&b, ",");
    }
    json_sb_puts(&b, "\"scope\":{");
    json_sb_printf(&b, "\"contract_requires\":%d,", res->contract_requires);
    json_sb_printf(&b, "\"contract_ensures\":%d,", res->contract_ensures);
    json_sb_printf(&b, "\"contract_total\":%d,",
                   res->contract_requires + res->contract_ensures);
    json_sb_printf(&b, "\"driver_funcs\":%d,", res->driver_funcs);
    json_sb_printf(&b, "\"driver_cases\":%d", res->driver_cases);
    if (res->ran_negative)
        json_sb_printf(&b, ",\"negative_callsites\":%d,\"negative_deviations\":%d",
                       res->negative_callsites, res->negative_deviations);
    json_sb_puts(&b, "},");
    if (res->ran_driver) {
        json_sb_printf(&b, "\"driver_stdout\":");
        json_sb_escape(&b, res->driver_stdout_text);
        json_sb_puts(&b, ",");
        json_sb_printf(&b, "\"driver_stderr\":");
        json_sb_escape(&b, res->driver_stderr_text);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"ran_prove\":%s,", res->ran_prove ? "true" : "false");
    json_sb_printf(&b, "\"prove_alarms\":%d,", res->prove_alarms);
    json_sb_printf(&b, "\"prove_proof_obligations\":%d,",
                   res->prove_proof_obligations);
    json_sb_printf(&b, "\"prove_mode\":\"%s\",",
                   res->prove_mode ? res->prove_mode
                                   : "eva (abstract interpretation)");
    json_sb_printf(&b, "\"prove_version\":");
    json_sb_escape(&b, res->prove_version);
    json_sb_puts(&b, ",");
    if (res->ran_prove) {
        json_sb_printf(&b, "\"prove_stdout\":");
        json_sb_escape(&b, res->prove_stdout_text);
        json_sb_puts(&b, ",");
        json_sb_printf(&b, "\"prove_stderr\":");
        json_sb_escape(&b, res->prove_stderr_text);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"diagnostics\":[");
    for (i = 0; i < res->diag_count; i++) {
        const myc_diagnostic *d = &res->diags[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b,
                       "{\"line\":%d,\"col\":%d,\"confidence\":\"%s\","
                       "\"message\":",
                       d->line, d->col, myc_confidence_name(d->confidence));
        json_sb_escape(&b, d->message);
        json_sb_puts(&b, "}");
    }
    json_sb_puts(&b, "],");
    json_sb_printf(&b, "\"gates\":[");
    for (i = 0; i < (int)res->gate_count; i++) {
        const myc_gate_result *g = &res->gates[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b, "{\"id\":%d,\"status\":\"%s\",\"requested\":%s,\"output\":",
                       (int)g->id, myc_gate_status_name(g->status),
                       g->requested ? "true" : "false");
        json_sb_escape(&b, g->output ? g->output : "");
        json_sb_puts(&b, "}");
    }
    json_sb_puts(&b, "],");
    json_sb_printf(&b, "\"gate_matrix\":[");
    for (i = 0; i < (int)res->gate_count; i++) {
        const myc_gate_result *g = &res->gates[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b, "{\"id\":\"%s\",\"status\":\"%s\"}",
                       (int)g->id < MYC_GATE_COUNT ?
                           myc_gate_id_short(g->id) : "?",
                       myc_gate_status_name(g->status));
    }
    json_sb_puts(&b, "],");
    json_sb_printf(&b, "\"evidence\":[");
    for (i = 0; i < (int)res->evidence_count; i++) {
        const myc_evidence_event *ev = &res->evidence[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b, "{\"gate\":%d,\"type\":%d,\"message\":",
                       (int)ev->gate_id, (int)ev->event_type);
        json_sb_escape(&b, ev->message ? ev->message : "");
        json_sb_puts(&b, "}");
    }
    json_sb_puts(&b, "],");
    json_sb_puts(&b, "\"witness\":");
    if (res->witness) {
        const myc_witness *w = res->witness;
        json_sb_puts(&b, "{");
        json_sb_printf(&b, "\"violation_line\":%d,", w->violation_line);
        json_sb_printf(&b, "\"violation_col\":%d,", w->violation_col);
        json_sb_printf(&b, "\"backend\":\"%s\",", w->backend);
        json_sb_printf(&b, "\"kind\":\"%s\",", w->violation_kind);
        json_sb_printf(&b, "\"message\":");
        json_sb_escape(&b, w->violation_msg);
        json_sb_puts(&b, ",");
        json_sb_printf(&b, "\"pre_state\":");
        json_sb_escape(&b, w->pre_state);
        json_sb_puts(&b, ",");
        json_sb_printf(&b, "\"operation\":");
        json_sb_escape(&b, w->operation);
        json_sb_puts(&b, ",");
        json_sb_printf(&b, "\"source_file\":");
        json_sb_escape(&b, w->slice_file);
        json_sb_puts(&b, ",");
        json_sb_printf(&b, "\"slice_line_start\":%d,", w->slice_line_start);
        json_sb_printf(&b, "\"slice_line_end\":%d,", w->slice_line_end);
        json_sb_printf(&b, "\"stdin_bytes\":%d,", (int)w->stdin_len);
        json_sb_printf(&b, "\"argv\":[");
        for (i = 0; i < w->argc; i++) {
            if (i)
                json_sb_puts(&b, ",");
            json_sb_escape(&b, w->argv[i]);
        }
        json_sb_puts(&b, "]");
        json_sb_puts(&b, "}");
    } else {
        json_sb_puts(&b, "null");
    }
    json_sb_puts(&b, ",");
    json_sb_printf(&b, "\"unverified_debt\":[");
     for (i = 0; i < (int)res->debt_count; i++) {
         const myc_debt_item *d = &res->debt[i];
         if (i)
             json_sb_puts(&b, ",");
         json_sb_printf(&b, "{\"type\":\"%s\",\"code\":\"%s\",\"text\":",
                        myc_debt_type_name(d->type), myc_debt_code(d->type));
         json_sb_escape(&b, d->text);
         json_sb_puts(&b, "}");
     }
     json_sb_puts(&b, "],");

     /* Fase 3, SOL-30: Assurance Budget Contract. */
     json_sb_printf(&b, "\"budget_active\":%s,",
                    res->budget_active ? "true" : "false");
     json_sb_printf(&b, "\"budget_met\":%s,",
                    res->budget_met ? "true" : "false");
     json_sb_printf(&b, "\"budget_report\":");
     json_sb_escape(&b, res->budget_report);
     json_sb_puts(&b, ",");

     /* Differential Backend Quorum (#3). */
      json_sb_printf(&b, "\"quorum_status\":\"%s\",",
                     myc_quorum_status_name(res->quorum_status));
      json_sb_printf(&b, "\"quorum_report\":");
      json_sb_escape(&b, res->quorum_report);
      json_sb_puts(&b, ",");
      json_sb_printf(&b, "\"receipt_parent\":");
      json_sb_escape(&b, res->receipt_parent);
      json_sb_puts(&b, ",");
      json_sb_printf(&b, "\"ledger_parent_found\":%s,",
                     res->ledger_parent_found ? "true" : "false");
      json_sb_printf(&b, "\"delta_kind\":\"%s\",",
                     res->delta_kind ? res->delta_kind : "");
      json_sb_printf(&b, "\"delta_changed\":%s,",
                     res->delta_changed ? "true" : "false");

     /* Counterexample Replay Capsule (#2). */
     json_sb_printf(&b, "\"capsule\":");
     if (res->capsule) {
         const myc_replay_capsule *cap = res->capsule;
         json_sb_puts(&b, "{");
         json_sb_printf(&b, "\"source_sha256\":");
         json_sb_escape(&b, cap->source_sha256);
         json_sb_puts(&b, ",");
         json_sb_printf(&b, "\"stdin_sha256\":");
         json_sb_escape(&b, cap->stdin_sha256);
         json_sb_printf(&b, ",\"stdin_len\":%zu,", cap->stdin_len);
         json_sb_printf(&b, "\"clang\":");
         json_sb_escape(&b, cap->clang_path);
         json_sb_puts(&b, ",");
         json_sb_printf(&b, "\"gcc\":");
         json_sb_escape(&b, cap->gcc_path);
         json_sb_puts(&b, ",");
         json_sb_printf(&b, "\"cwd\":");
         json_sb_escape(&b, cap->cwd);
         json_sb_puts(&b, ",");
         json_sb_printf(&b, "\"timeout_ms\":%d,", cap->timeout_ms);
         json_sb_printf(&b, "\"max_output_bytes\":%d,",
                        cap->max_output_bytes);
         json_sb_printf(&b, "\"strict\":%s,", cap->strict ? "true" : "false");
         json_sb_printf(&b, "\"run_analyzer\":%s,",
                        cap->run_analyzer ? "true" : "false");
         json_sb_printf(&b, "\"run\":%s,", cap->run ? "true" : "false");
         json_sb_printf(&b, "\"prove\":%s,", cap->prove ? "true" : "false");
         json_sb_printf(&b, "\"checked\":%s,",
                        cap->checked ? "true" : "false");
         json_sb_printf(&b, "\"filc\":%s,", cap->filc ? "true" : "false");
         json_sb_printf(&b, "\"driver\":%s,",
                        cap->driver ? "true" : "false");
         json_sb_printf(&b, "\"metamorphic\":%s,",
                        cap->metamorphic ? "true" : "false");
         json_sb_printf(&b, "\"negative\":%s,",
                        cap->negative ? "true" : "false");
         if (cap->negative) {
             json_sb_printf(&b, "\"negative_callsites\":%d,",
                            cap->negative_callsites);
             json_sb_printf(&b, "\"negative_deviations\":%d,",
                            cap->negative_deviations);
         }
         /* MYC-AUDIT-026: coverage count checked-build di capsule. */
         if (cap->checked) {
             json_sb_printf(&b, "\"checked_buffers\":%d,",
                            cap->checked_buffers);
             json_sb_printf(&b, "\"checked_allocations\":%d,",
                            cap->checked_allocations);
             json_sb_printf(&b, "\"checked_accesses\":%d,",
                            cap->checked_accesses);
             json_sb_printf(&b, "\"checked_frees\":%d,",
                            cap->checked_frees);
         }
         /* Roadmap 7.5: driver case records + harness sha (replay). */
         if (cap->driver) {
             int dci;
             json_sb_printf(&b, "\"driver_funcs\":%d,",
                            cap->driver_funcs);
             json_sb_printf(&b, "\"driver_cases\":%d,",
                            cap->driver_cases);
             json_sb_printf(&b, "\"driver_skipped\":%d,",
                            cap->driver_skipped);
             json_sb_printf(&b, "\"driver_max_product\":%ld,",
                            cap->driver_max_product);
             json_sb_printf(&b, "\"driver_bounded\":%s,",
                            cap->driver_bounded ? "true" : "false");
             json_sb_printf(&b, "\"driver_harness_sha256\":");
             json_sb_escape(&b, cap->driver_harness_sha256);
             json_sb_puts(&b, ",");
             json_sb_printf(&b, "\"driver_case_records\":[");
             for (dci = 0; dci < cap->driver_case_count; dci++) {
                 const myc_driver_case *c = &cap->driver_case_records[dci];
                 if (dci)
                     json_sb_puts(&b, ",");
                 json_sb_puts(&b, "{");
                 json_sb_printf(&b, "\"case_id\":%d,", c->case_id);
                 json_sb_printf(&b, "\"func\":");
                 json_sb_escape(&b, c->func);
                 json_sb_puts(&b, ",");
                 json_sb_printf(&b, "\"params\":");
                 json_sb_escape(&b, c->params);
                 json_sb_printf(&b, ",\"alloc_bytes\":%ld,",
                                c->alloc_bytes);
                 json_sb_printf(&b, "\"executed\":%s",
                                c->executed ? "true" : "false");
                 json_sb_puts(&b, "}");
             }
             json_sb_puts(&b, "],");
         }
         json_sb_printf(&b, "\"require_complete\":%s,",
                        cap->require_complete ? "true" : "false");
         if (cap->budget_active)
             json_sb_printf(&b, "\"budget_met\":%s,",
                            cap->budget_met ? "true" : "false");
         if (cap->metamorphic) {
             json_sb_printf(&b, "\"meta_o0_exit\":%d,", cap->meta_o0_exit);
             json_sb_printf(&b, "\"meta_o2_exit\":%d,", cap->meta_o2_exit);
             json_sb_printf(&b, "\"meta_o0_finding\":%s,",
                            cap->meta_o0_finding ? "true" : "false");
             json_sb_printf(&b, "\"meta_o2_finding\":%s,",
                            cap->meta_o2_finding ? "true" : "false");
             json_sb_printf(&b, "\"metamorphic_inconsistent\":%s,",
                            cap->metamorphic_inconsistent ? "true" : "false");
         }
         if (cap->divergence_ran) {
             json_sb_printf(&b, "\"divergence_ran\":%d,",
                            cap->divergence_ran);
             json_sb_printf(&b, "\"divergence_sanitizer_div\":%s,",
                            cap->divergence_sanitizer_div ? "true" : "false");
             json_sb_printf(&b, "\"divergence_all_findings\":%s,",
                            cap->divergence_all_findings ? "true" : "false");
             json_sb_printf(&b, "\"divergence_semantic_div\":%s,",
                            cap->divergence_semantic_div ? "true" : "false");
             json_sb_printf(&b, "\"divergence_diag_div\":%s,",
                            cap->divergence_diag_div ? "true" : "false");
         }
         json_sb_printf(&b, "\"verdict\":\"%s\",",
                        myc_verdict_name(cap->verdict));
         json_sb_printf(&b, "\"exit_code\":%d,", cap->exit_code);
         json_sb_printf(&b, "\"timed_out\":%s,",
                        cap->timed_out ? "true" : "false");
         json_sb_printf(&b, "\"sanitizer_detected\":%s,",
                        cap->sanitizer_detected ? "true" : "false");
         if (cap->sanitizer_detected) {
             json_sb_printf(&b, "\"sanitizer_marker\":\"%s\",",
                            cap->sanitizer_marker);
         }
         json_sb_puts(&b, "\"gate_status\":{");
         {
             int first = 1;
             for (gi = 0; gi < MYC_GATE_COUNT; gi++) {
                 if (cap->gate_status[gi] != MYC_GATE_NOT_REQUESTED) {
                     if (!first)
                         json_sb_puts(&b, ",");
                     json_sb_printf(&b, "\"%s\":\"%s\"",
                                    myc_gate_id_short((myc_gate_id)gi),
                                    myc_gate_status_name(
                                        cap->gate_status[gi]));
                     first = 0;
                 }
             }
         }
         json_sb_puts(&b, "},");
         json_sb_printf(&b, "\"finding\":\"%s\",",
                        myc_finding_name(cap->finding));
         json_sb_printf(&b, "\"completeness\":\"%s\",",
                        myc_completeness_name(cap->completeness));
         json_sb_printf(&b, "\"claim\":\"%s\",",
                        myc_claim_status_name(cap->claim_status));
         json_sb_printf(&b, "\"quorum\":\"%s\"",
                        myc_quorum_status_name(cap->quorum_status));
         json_sb_puts(&b, "}");
     } else {
         json_sb_puts(&b, "null");
     }

     /* Tutup objek level teratas. (Bug lama: `}` ini hilang sejak
      * fitur capsule #2; MCP interop lolos karena isi `text` hanya
      * diperiksa substring, bukan diparse ketat.) */
     json_sb_puts(&b, "}");
     json_sb_putc(&b, '\0');
     return b.buf;
 }

void myc_report_json_summary(const myc_result *res)
{
    json_sb b;
    int     i;
    if (!json_sb_init(&b))
        return;
    json_sb_puts(&b, "{");
    json_sb_printf(&b, "\"verdict\":\"%s\",", myc_verdict_name(res->verdict));
    json_sb_puts(&b, "\"assurance_vector\":{");
    {
        static const char dim_chars[MYC_DIM_COUNT] = {
            'C', 'S', 'R', 'B', 'P', 'D', 'F'
        };
        int dim_i;
        for (dim_i = 0; dim_i < MYC_DIM_COUNT; dim_i++) {
            if (dim_i)
                json_sb_puts(&b, ",");
            json_sb_printf(&b, "\"%c\":\"%s\"",
                           dim_chars[dim_i],
                           myc_dim_status_name(
                               res->assurance_vector.status[dim_i]));
        }
    }
    json_sb_puts(&b, "},");
    json_sb_printf(&b, "\"receipt_sha256\":");
    json_sb_escape(&b, res->receipt_sha256);
    json_sb_puts(&b, ",");
    json_sb_printf(&b, "\"finding\":\"%s\",", myc_finding_name(res->finding));
    json_sb_printf(&b, "\"completeness\":\"%s\",", myc_completeness_name(res->completeness));
    json_sb_printf(&b, "\"error\":\"%s\",", myc_error_name(res->err));
    json_sb_printf(&b, "\"exit_code\":%d,", res->exit_code);
    json_sb_printf(&b, "\"duration_ms\":%llu,", (unsigned long long)res->duration_ms);
    json_sb_printf(&b, "\"lint_observations\":%d,", res->lint_observations);
    json_sb_printf(&b, "\"lint_embedded_hits\":%d,", res->lint_embedded_hits);
    if (res->scenario_applied) {
        json_sb_printf(&b, "\"scenario\":{\"applied\":true,\"auto\":%s,"
                           "\"name\":",
                       res->scenario_auto ? "true" : "false");
        json_sb_escape(&b, res->scenario_name);
        json_sb_puts(&b, "},");
    }
    if (res->ran_matrix) {
        json_sb_printf(&b, "\"matrix\":{\"targets\":%d,\"available\":%d,"
                           "\"deltas\":%d},",
                       res->matrix_targets, res->matrix_available,
                       res->matrix_deltas);
    }
    /* Fase 5 B4 (DS-08): harvest komentar-biasa (observasi). */
    json_sb_printf(&b, "\"harvest\":{\"candidates\":%d,\"validated\":%d,"
                       "\"unbound\":%d},",
                   res->harvest_candidates, res->harvest_validated,
                   res->harvest_unbound);
    /* Fase 5 (Relational contracts): klasifikasi relasional (observasi). */
    json_sb_printf(&b, "\"relational\":{\"analyzed\":%d,\"relations\":%d,"
                       "\"unbound\":%d},",
                   res->rel_analyzed, res->rel_relations, res->rel_unbound);
    /* Fase 5 (SOL-13): ghost state machine (observasi). */
    json_sb_printf(&b, "\"state_machine\":{\"states\":%d,\"events\":%d,"
                       "\"transitions\":%d,\"findings\":%d},",
                   res->sm_states, res->sm_events, res->sm_transitions,
                   res->sm_findings);
    /* Fase 5 (SOL-14): ABI certificate (observasi). */
    json_sb_printf(&b, "\"abi\":{\"ran\":%s,\"structs\":%d,\"enums\":%d,"
                       "\"symbols\":%d,\"changed\":%s,\"delta\":%d},",
                   res->abi_ran ? "true" : "false", res->abi_n_structs,
                   res->abi_n_enums, res->abi_n_symbols,
                   res->abi_changed ? "true" : "false", res->abi_n_delta);
    /* Fase 5 (SOL-12): Resource Linearity Ledger (observasi). */
    json_sb_printf(&b, "\"resource\":{\"ran\":%s,\"pairs\":%d,"
                       "\"acquires\":%d,\"releases\":%d,\"transferred\":%d,"
                       "\"leaks\":%d,\"double_releases\":%d,"
                       "\"release_unknown\":%d},",
                   res->rsrc_ran ? "true" : "false", res->rsrc_pairs,
                   res->rsrc_acquires, res->rsrc_releases,
                   res->rsrc_transferred, res->rsrc_leaks,
                   res->rsrc_double_releases, res->rsrc_release_unknown);
    /* Fase 5 B3 (DS-07): coaching items ringkas. */
    json_sb_printf(&b, "\"coaching\":[");
    for (i = 0; i < res->coaching_count; i++) {
        const myc_coaching_item *c = &res->coaching[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b, "{\"class\":\"%s\",\"line\":%d}",
                       myc_taxonomy_name(c->cls), c->line);
    }
    json_sb_puts(&b, "],");
    json_sb_printf(&b, "\"ran_runtime\":%s,", res->ran_runtime ? "true" : "false");
    json_sb_printf(&b, "\"ran_checked\":%s,", res->ran_checked ? "true" : "false");
    json_sb_printf(&b, "\"ran_prove\":%s,", res->ran_prove ? "true" : "false");
    json_sb_printf(&b, "\"ran_filc\":%s,", res->ran_filc ? "true" : "false");
    json_sb_printf(&b, "\"ran_driver\":%s,", res->ran_driver ? "true" : "false");
    json_sb_printf(&b, "\"ran_negative\":%s,", res->ran_negative ? "true" : "false");
    json_sb_printf(&b, "\"ran_metamorphic\":%s,", res->ran_metamorphic ? "true" : "false");
    json_sb_printf(&b, "\"ran_exhaustive\":%s,", res->ran_exhaustive ? "true" : "false");
    if (res->ran_exhaustive) {
        json_sb_printf(&b, "\"exhaustive_funcs\":%d,", res->exhaustive_funcs);
        json_sb_printf(&b, "\"exhaustive_cases\":%d,", res->exhaustive_cases);
        json_sb_printf(&b, "\"exhaustive_points\":%ld,",
                       res->exhaustive_points);
        json_sb_printf(&b, "\"exhaustive_laundering\":%s,",
                       res->exhaustive_laundering ? "true" : "false");
        json_sb_printf(&b, "\"exhaustive_domain_hash\":\"%s\",",
                       res->exhaustive_domain_hash);
    }
    json_sb_printf(&b, "\"ran_compare\":%s,", res->ran_compare ? "true" : "false");
    if (res->ran_compare) {
        json_sb_printf(&b, "\"compare_funcs\":%d,", res->compare_funcs);
        json_sb_printf(&b, "\"compare_identical\":%ld,",
                       res->compare_identical);
        json_sb_printf(&b, "\"compare_divergent\":%ld,",
                       res->compare_divergent);
        json_sb_printf(&b, "\"compare_preserved\":%s,",
                       res->compare_preserved ? "true" : "false");
    }
    json_sb_printf(&b, "\"ran_stack\":%s,", res->ran_stack ? "true" : "false");
    if (res->ran_stack) {
        json_sb_printf(&b, "\"stack_worst_bytes\":%ld,",
                       res->stack_worst_bytes);
        json_sb_printf(&b, "\"stack_budget\":%d,", res->stack_budget);
        json_sb_printf(&b, "\"stack_recursion\":%s,",
                       res->stack_recursion ? "true" : "false");
        json_sb_printf(&b, "\"stack_alloca\":%s,",
                       res->stack_alloca ? "true" : "false");
        json_sb_printf(&b, "\"stack_vla\":%s,", res->stack_vla ? "true" : "false");
        json_sb_printf(&b, "\"stack_report\":");
        json_sb_escape(&b, res->stack_report);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"ran_fuzz\":%s,", res->ran_fuzz ? "true" : "false");
    if (res->ran_fuzz) {
        json_sb_printf(&b, "\"fuzz_funcs\":%d,", res->fuzz_funcs);
        json_sb_printf(&b, "\"fuzz_cases\":%ld,", res->fuzz_cases);
        json_sb_printf(&b, "\"fuzz_skipped\":%ld,", res->fuzz_skipped);
        json_sb_printf(&b, "\"fuzz_seed\":%u,", res->fuzz_seed);
        json_sb_puts(&b, "\"fuzz_report\":");
        json_sb_escape(&b, res->fuzz_report);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"ran_mutate\":%s,", res->ran_mutate ? "true" : "false");
    if (res->ran_mutate) {
        json_sb_printf(&b, "\"mutate_total\":%d,", res->mutate_total);
        json_sb_printf(&b, "\"mutate_caught\":%d,", res->mutate_caught);
        json_sb_printf(&b, "\"mutate_gap\":%d,", res->mutate_gap);
        json_sb_puts(&b, "\"mutate_report\":");
        json_sb_escape(&b, res->mutate_report);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"ran_freestanding\":%s,",
                   res->ran_freestanding ? "true" : "false");
    if (res->ran_freestanding) {
        json_sb_printf(&b, "\"freestanding_api_hits\":%d,",
                       res->freestanding_api_hits);
        json_sb_puts(&b, "\"freestanding_report\":");
        json_sb_escape(&b, res->freestanding_report);
        json_sb_puts(&b, ",");
    }
    json_sb_printf(&b, "\"ran_divergence\":%s,", res->ran_divergence ? "true" : "false");
    if (res->ran_divergence) {
        json_sb_printf(&b, "\"divergence_ran\":%d,", res->divergence_ran);
        json_sb_printf(&b, "\"divergence_sanitizer_div\":%s,",
                       res->divergence_sanitizer_div ? "true" : "false");
        json_sb_printf(&b, "\"divergence_all_findings\":%s,",
                       res->divergence_all_findings ? "true" : "false");
        json_sb_printf(&b, "\"divergence_semantic_div\":%s,",
                       res->divergence_semantic_div ? "true" : "false");
        json_sb_printf(&b, "\"divergence_diag_div\":%s,",
                       res->divergence_diag_div ? "true" : "false");
    }
    json_sb_printf(&b, "\"diagnostics\":[");
    for (i = 0; i < res->diag_count; i++) {
        const myc_diagnostic *d = &res->diags[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b,
                       "{\"line\":%d,\"col\":%d,\"confidence\":\"%s\","
                       "\"message\":",
                       d->line, d->col, myc_confidence_name(d->confidence));
        json_sb_escape(&b, d->message);
        json_sb_puts(&b, "}");
    }
    json_sb_puts(&b, "],");
    json_sb_printf(&b, "\"gate_matrix\":[");
    for (i = 0; i < (int)res->gate_count; i++) {
        const myc_gate_result *g = &res->gates[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b, "{\"id\":\"%s\",\"status\":\"%s\"}",
                       (int)g->id < MYC_GATE_COUNT ?
                           myc_gate_id_short((myc_gate_id)g->id) : "?",
                       myc_gate_status_name(g->status));
    }
    json_sb_puts(&b, "],");
    json_sb_printf(&b, "\"unverified_debt\":[");
    for (i = 0; i < (int)res->debt_count; i++) {
        const myc_debt_item *d = &res->debt[i];
        if (i)
            json_sb_puts(&b, ",");
        json_sb_printf(&b, "{\"code\":\"%s\",\"text\":",
                       myc_debt_code(d->type));
        json_sb_escape(&b, d->text);
        json_sb_puts(&b, "}");
    }
    json_sb_puts(&b, "],");
    json_sb_printf(&b, "\"budget_met\":%s,",
                   res->budget_met ? "true" : "false");
    json_sb_printf(&b, "\"budget_report\":");
    json_sb_escape(&b, res->budget_report);
    json_sb_puts(&b, ",");
    json_sb_printf(&b, "\"assumptions\":{\"count\":%d,\"unclosed\":%d,"
                       "\"ok\":%s},",
                   res->assumption_count, res->assumption_unclosed,
                   res->assumption_ok ? "true" : "false");
    json_sb_printf(&b, "\"quorum_status\":\"%s\"",
                   myc_quorum_status_name(res->quorum_status));
    json_sb_puts(&b, "}");
    json_sb_putc(&b, '\0');
    printf("%s\n", b.buf);
}

void myc_report_json(const myc_result *res)
{
    char *s = myc_result_to_json(res);
    if (s) {
        printf("%s\n", s);
        free(s);
    }
}

int myc_report_agent(const myc_result *res)
{
    myc_agent_result ar;
    const char *js;

    if (!res) return -1;

    memset(&ar, 0, sizeof(ar));

    if (myc_build_agent_result(res, &ar, NULL, NULL) < 0)
        return -1;

    js = myc_agent_result_json(&ar);
    if (js) {
        printf("%s\n", js);
        free((void *)js);
    }

    myc_agent_result_free(&ar);
    return 0;
}
