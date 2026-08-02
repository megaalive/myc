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
    case MYC_ASSURANCE_L2_PROVEN: return "L2 (PROVEN)";
    case MYC_ASSURANCE_L3_RUNTIME:return "L3 (RUNTIME)";
    case MYC_ASSURANCE_L4_SPATIAL:return "L4 (SPATIAL)";
    case MYC_ASSURANCE_L5_FULL:   return "L5 (FULL)";
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
    printf("assurance: %s [legacy: gunakan evidence matrix + finding/completeness]\n", myc_assurance_name(res->assurance));
    printf("finding:   %s\n", myc_finding_name(res->finding));
    printf("completeness: %s\n", myc_completeness_name(res->completeness));
    printf("claim:     %s\n", myc_claim_status_name(res->claim_status));
    printf("error:     %s\n", myc_error_name(res->err));
    printf("exit_code: %d\n", res->exit_code);
    printf("duration:  %llu ms\n", res->duration_ms);
    if (res->receipt_sha256[0])
        printf("receipt_sha256: %s\n", res->receipt_sha256);
    if (res->resolved_gcc)
        printf("gcc:       %s\n", res->resolved_gcc);
    if (res->fingerprint)
        printf("fingerprint: %s\n", res->fingerprint);
    if (res->source_sha256)
        printf("source_sha256: %s\n", res->source_sha256);
    if (res->contract_requires > 0 || res->contract_ensures > 0)
        printf("contracts: requires=%d ensures=%d\n",
               res->contract_requires, res->contract_ensures);
    if (res->ran_negative)
        printf("negative (9.8): callsites=%d deviations=%d\n",
               res->negative_callsites, res->negative_deviations);

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
        printf("  [%d:%d] %s\n", d->line, d->col,
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
    }
    if (res->run_sanitizer_detected)
        printf("sanitizer: %s\n", res->run_sanitizer_marker);

    if (res->ran_prove) {
        printf("prove:\n");
        printf("  alarms: %d\n", res->prove_alarms);
        if (res->prove_stdout_text && res->prove_stdout_text[0])
            printf("  prove_stdout:\n%s\n", res->prove_stdout_text);
        if (res->prove_stderr_text && res->prove_stderr_text[0])
            printf("  prove_stderr:\n%s\n", res->prove_stderr_text);
    }

    if (res->ran_checked) {
        printf("checked:\n");
        printf("  uses_myc_buf: %s\n", res->checked_uses_buf ? "yes" : "no");
        if (res->checked_uses_buf)
            printf("  build_ok:     %s\n", res->checked_build_ok ? "yes" : "no");
    }

    if (res->ran_filc) {
        printf("filc:\n");
        printf("  panics: %d\n", res->filc_panics);
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
        if (res->driver_stdout_text && res->driver_stdout_text[0])
            printf("  driver_stdout:\n%s\n", res->driver_stdout_text);
        if (res->driver_stderr_text && res->driver_stderr_text[0])
            printf("  driver_stderr:\n%s\n", res->driver_stderr_text);
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

     /* Differential Backend Quorum (#3). */
     if (res->quorum_status != MYC_QUORUM_NOT_REQUESTED) {
         printf("quorum: %s\n",
                myc_quorum_status_name(res->quorum_status));
         if (res->quorum_report)
             printf("%s", res->quorum_report);
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
         printf("  negative: %s\n", cap->negative ? "yes" : "no");
         if (cap->negative)
             printf("  negative_callsites: %d  negative_deviations: %d\n",
                    cap->negative_callsites, cap->negative_deviations);
         printf("  require_complete: %s\n",
                cap->require_complete ? "yes" : "no");
         if (cap->metamorphic) {
             printf("  meta_o0_exit: %d  meta_o2_exit: %d\n",
                    cap->meta_o0_exit, cap->meta_o2_exit);
             printf("  meta_o0_finding: %s  meta_o2_finding: %s  inconsistent: %s\n",
                    cap->meta_o0_finding ? "yes" : "no",
                    cap->meta_o2_finding ? "yes" : "no",
                    cap->metamorphic_inconsistent ? "yes" : "no");
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
    json_sb_printf(&b, "\"resolved_gcc\":");
    json_sb_escape(&b, res->resolved_gcc);
    json_sb_puts(&b, ",");
    json_sb_printf(&b, "\"fingerprint\":");
    json_sb_escape(&b, res->fingerprint);
    json_sb_puts(&b, ",");
    json_sb_printf(&b, "\"source_sha256\":");
    json_sb_escape(&b, res->source_sha256);
    json_sb_puts(&b, ",");
    json_sb_printf(&b, "\"contract_requires\":%d,", res->contract_requires);
    json_sb_printf(&b, "\"contract_ensures\":%d,", res->contract_ensures);
    json_sb_printf(&b, "\"ran_negative\":%s,", res->ran_negative ? "true" : "false");
    if (res->ran_negative) {
        json_sb_printf(&b, "\"negative_callsites\":%d,", res->negative_callsites);
        json_sb_printf(&b, "\"negative_deviations\":%d,", res->negative_deviations);
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
    json_sb_printf(&b, "\"ran_filc\":%s,", res->ran_filc ? "true" : "false");
    json_sb_printf(&b, "\"filc_panics\":%d,", res->filc_panics);
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
        json_sb_printf(&b, "{\"line\":%d,\"col\":%d,\"message\":",
                       d->line, d->col);
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
    json_sb_puts(&b, "],");     json_sb_printf(&b, "\"unverified_debt\":[");
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

     /* Differential Backend Quorum (#3). */
     json_sb_printf(&b, "\"quorum_status\":\"%s\",",
                    myc_quorum_status_name(res->quorum_status));
     json_sb_printf(&b, "\"quorum_report\":");
     json_sb_escape(&b, res->quorum_report);
     json_sb_puts(&b, ",");

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
         json_sb_printf(&b, "\"require_complete\":%s,",
                        cap->require_complete ? "true" : "false");
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

void myc_report_json(const myc_result *res)
{
    char *s = myc_result_to_json(res);
    if (s) {
        printf("%s\n", s);
        free(s);
    }
}
