/*
 * report.c -- Output verdict: teks (default) dan JSON (--json).
 */
#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "myc.h"

const char *myc_verdict_name(myc_verdict v)
{
    switch (v) {
    case MC_OK:            return "OK";
    case MC_VIOLATION:     return "VIOLATION";
    case MC_COMPILE_ERROR: return "COMPILE_ERROR";
    case MC_ERROR:         return "ERROR";
    case MC_TIMEOUT:       return "TIMEOUT";
    case MC_CANCELLED:     return "CANCELLED";
    case MC_RUNTIME_VIOLATION: return "RUNTIME_VIOLATION";
    case MC_PROVE_VIOLATION:    return "PROVE_VIOLATION";
    case MC_FILC_VIOLATION:     return "FILC_VIOLATION";
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
    printf("verdict:   %s\n", myc_verdict_name(res->verdict));
    printf("assurance: %s\n", myc_assurance_name(res->assurance));
    printf("error:     %s\n", myc_error_name(res->err));
    printf("exit_code: %d\n", res->exit_code);
    printf("duration:  %llu ms\n", res->duration_ms);
    if (res->resolved_gcc)
        printf("gcc:       %s\n", res->resolved_gcc);
    if (res->fingerprint)
        printf("fingerprint: %s\n", res->fingerprint);
    if (res->source_sha256)
        printf("source_sha256: %s\n", res->source_sha256);
    if (res->contract_requires > 0 || res->contract_ensures > 0)
        printf("contracts: requires=%d ensures=%d\n",
               res->contract_requires, res->contract_ensures);

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
}

char *myc_result_to_json(const myc_result *res)
{
    json_sb b;
    int     i;
    if (!json_sb_init(&b))
        return NULL;
    json_sb_puts(&b, "{");
    json_sb_printf(&b, "\"verdict\":\"%s\",", myc_verdict_name(res->verdict));
    json_sb_printf(&b, "\"assurance\":\"%s\",", myc_assurance_name(res->assurance));
    json_sb_printf(&b, "\"error\":\"%s\",", myc_error_name(res->err));
    json_sb_printf(&b, "\"exit_code\":%d,", res->exit_code);
    json_sb_printf(&b, "\"duration_ms\":%llu,", (unsigned long long)res->duration_ms);
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
    json_sb_printf(&b, "\"truncated\":%s,", res->truncated ? "true" : "false");
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
    json_sb_puts(&b, "]}");
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
