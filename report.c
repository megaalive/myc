/*
 * report.c -- Output verdict: teks (default) dan JSON (--json).
 */
#include "report.h"

#include <stdio.h>
#include <string.h>

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

/* Escape string JSON ke buffer statis (cukup untuk laporan). */
static const char *json_escape(const char *s)
{
    static char buf[4096];
    size_t      o = 0;
    if (!s)
        return "null";
    for (const char *p = s; *p && o < sizeof(buf) - 2; p++) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
        case '"':  buf[o++] = '\\'; buf[o++] = '"';  break;
        case '\\': buf[o++] = '\\'; buf[o++] = '\\'; break;
        case '\n': buf[o++] = '\\'; buf[o++] = 'n';  break;
        case '\r': buf[o++] = '\\'; buf[o++] = 'r';  break;
        case '\t': buf[o++] = '\\'; buf[o++] = 't';  break;
        default:
            if (c < 0x20) {
                buf[o++] = '\\';
                buf[o++] = 'u';
                buf[o++] = '0';
                buf[o++] = '0';
                buf[o++] = "0123456789abcdef"[c >> 4];
                buf[o++] = "0123456789abcdef"[c & 0x0f];
            } else {
                buf[o++] = (char)c;
            }
            break;
        }
    }
    buf[o] = '\0';
    return buf;
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
}

void myc_report_json(const myc_result *res)
{
    int i;
    printf("{\n");
    printf("  \"verdict\": \"%s\",\n", myc_verdict_name(res->verdict));
    printf("  \"assurance\": \"%s\",\n", myc_assurance_name(res->assurance));
    printf("  \"error\": \"%s\",\n", myc_error_name(res->err));
    printf("  \"exit_code\": %d,\n", res->exit_code);
    printf("  \"duration_ms\": %llu,\n", res->duration_ms);
    printf("  \"resolved_gcc\": \"%s\",\n",
           json_escape(res->resolved_gcc));
    printf("  \"fingerprint\": \"%s\",\n",
           json_escape(res->fingerprint));
    printf("  \"source_sha256\": \"%s\",\n",
           json_escape(res->source_sha256));
    printf("  \"truncated\": %s,\n", res->truncated ? "true" : "false");
    printf("  \"stdout_bytes\": %llu,\n",
           (unsigned long long)res->total_stdout_bytes);
    printf("  \"stderr_bytes\": %llu,\n",
           (unsigned long long)res->total_stderr_bytes);
    printf("  \"ran_runtime\": %s,\n", res->ran_runtime ? "true" : "false");
    if (res->ran_runtime) {
        printf("  \"run_timed_out\": %s,\n", res->run_timed_out ? "true" : "false");
        printf("  \"run_exit_code\": %d,\n", res->exit_code);
        printf("  \"run_stdout\": \"%s\",\n",
               json_escape(res->run_stdout_text));
        printf("  \"run_stderr\": \"%s\",\n",
               json_escape(res->run_stderr_text));
    }
    printf("  \"diagnostics\": [");
    for (i = 0; i < res->diag_count; i++) {
        const myc_diagnostic *d = &res->diags[i];
        if (i)
            printf(",");
        printf("\n    {\"line\": %d, \"col\": %d, \"message\": \"%s\"}",
               d->line, d->col, json_escape(d->message));
    }
    if (res->diag_count)
        printf("\n  ");
    printf("]\n");
    printf("}\n");
}
