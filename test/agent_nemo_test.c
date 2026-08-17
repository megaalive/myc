/*
 * agent_nemo_test.c -- NEMO-1..4: next_check, edits, delta, diagnostic_class.
 *
 * Fixture myc_result (tanpa gcc/clang). Deterministik.
 *
 * Jalankan: gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I.
 *           -DMYC_NO_MAIN -o test/agent_nemo_test.exe test/agent_nemo_test.c
 *           <SRCS>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myc.h"
#include "agent.h"
#include "gate.h"

static int PASS = 0;
static int FAIL = 0;

#define CHECK(cond, msg)                                              \
    do {                                                              \
        if (cond) {                                                   \
            PASS++;                                                   \
        } else {                                                      \
            FAIL++;                                                   \
            fprintf(stderr, "[FAIL] %s (%s:%d)\n", msg, __FILE__,     \
                    __LINE__);                                        \
        }                                                             \
    } while (0)

static void res_init(myc_result *res)
{
    memset(res, 0, sizeof(*res));
    myc_result_init(res);
}

static void test_next_check(void)
{
    myc_result res;
    char *cmd;

    /* T1: RUNTIME_VIOLATION tanpa sanloc -> GIVE_UP + context */
    res_init(&res);
    res.verdict = MC_RUNTIME_VIOLATION;
    cmd = myc_agent_build_next_check(&res, NULL);
    CHECK(cmd && strstr(cmd, "myc context") && strstr(cmd, "--budget 4K"),
          "T1: RUNTIME tanpa template -> myc context --budget 4K");
    CHECK(cmd && !strstr(cmd, "--prove"), "T1: tanpa --prove");
    myc_free(cmd);
    myc_result_free(&res);

    /* T2: COMPILE_ERROR tanpa template -> context, bukan re-check */
    res_init(&res);
    res.verdict = MC_COMPILE_ERROR;
    cmd = myc_agent_build_next_check(&res, "x.c");
    CHECK(cmd && strstr(cmd, "myc context x.c --budget 4K"),
          "T2: COMPILE_ERROR tanpa template -> myc context x.c --budget 4K");
    myc_free(cmd);
    myc_result_free(&res);

    /* T3: OK + runtime untested -> --run */
    res_init(&res);
    res.verdict = MC_OK;
    myc_gate_set_status(&res, MYC_GATE_RUNTIME, MYC_GATE_NOT_REQUESTED,
                        NULL);
    cmd = myc_agent_build_next_check(&res, NULL);
    CHECK(cmd && strstr(cmd, "--run"), "T3: OK untested runtime -> --run");
    myc_free(cmd);
    myc_result_free(&res);

    /* T4: OK + runtime clean -> tanpa --run */
    res_init(&res);
    res.verdict = MC_OK;
    myc_gate_set_status(&res, MYC_GATE_RUNTIME, MYC_GATE_COMPLETED_CLEAN,
                        NULL);
    cmd = myc_agent_build_next_check(&res, NULL);
    CHECK(cmd && strstr(cmd, "STOP_COMPILE_CLEAN"),
          "T4: OK + runtime clean -> STOP_COMPILE_CLEAN");
    CHECK(cmd && !strstr(cmd, "--run"),
          "T4: OK + runtime clean -> tanpa --run");
    myc_free(cmd);
    myc_result_free(&res);

    /* T5: DRIVER_VIOLATION */
    res_init(&res);
    res.verdict = MC_DRIVER_VIOLATION;
    cmd = myc_agent_build_next_check(&res, NULL);
    CHECK(cmd && strstr(cmd, "--driver"), "T5: DRIVER -> --driver");
    myc_free(cmd);
    myc_result_free(&res);
}

static void test_diagnostic_class_and_edits(void)
{
    myc_agent_result ar;
    myc_result res;
    const char *src =
        "int f(void){char b[4]; return b[0];}\n"
        "int main(void){system(\"x\"); return f();}\n";

    res_init(&res);
    res.verdict = MC_RUNTIME_VIOLATION;
    res.finding = MYC_FINDING_FINDINGS;
    res.sanloc_have = 1;
    res.sanloc_line = 1;
    res.sanloc_kind = "stack-buffer-overflow";
    res.sanloc_function = "f";
    res.sanloc_snippet = "return b[0];";
    res.diags[0].line = 1;
    res.diags[0].col = 1;
    res.diags[0].message = "sanitizer runtime: stack-buffer-overflow";
    res.diags[0].confidence = MYC_CONF_CONFIRMED;
    res.diag_count = 1;
    res.diags[1].line = 2;
    res.diags[1].col = 1;
    res.diags[1].message =
        "warning: fungsi dilarang: system (non-blocking)";
    res.diags[1].confidence = MYC_CONF_OBSERVATION;
    res.diag_count = 2;

    CHECK(myc_build_agent_result(&res, &ar, NULL, NULL, NULL,
                                 src, strlen(src)) == 0,
          "T6: build agent result OK");
    CHECK(ar.has_primary, "T6: has primary");
    CHECK(ar.primary_finding.diagnostic_class &&
              strcmp(ar.primary_finding.diagnostic_class, "runtime") == 0,
          "T6: diagnostic_class=runtime");
    CHECK(ar.has_next_check && ar.next_check.command &&
              (strstr(ar.next_check.command, "FIX_ONE") ||
               strstr(ar.next_check.command, "myc context")),
          "T6: next_check FIX_ONE atau context (bukan re-check buta)");
    CHECK(ar.has_action, "T6: action terisi");
    CHECK(ar.allowed_edit_count >= 1, "T6: allowed_edits non-empty");
    CHECK(ar.preserve_count >= 1, "T6: preserve non-empty");
    CHECK(ar.forbidden_count >= 1 && ar.forbidden[0].region &&
              strstr(ar.forbidden[0].region, "system"),
          "T6: forbidden system()");
    CHECK(ar.delta_receipt_sha == NULL,
          "T6: no delta on first/fixture without parent");

    myc_agent_result_free(&ar);
    myc_result_free(&res);

    /* T7: delta_receipt_sha dari receipt_parent */
    res_init(&res);
    res.verdict = MC_OK;
    memcpy(res.receipt_sha256,
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
           64);
    res.receipt_sha256[64] = '\0';
    res.receipt_parent =
        myc_strdup(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    CHECK(myc_build_agent_result(&res, &ar, NULL, NULL, NULL, NULL, 0) == 0,
          "T7: build OK");
    CHECK(ar.delta_receipt_sha &&
              strcmp(ar.delta_receipt_sha, res.receipt_parent) == 0,
          "T7: delta_receipt_sha = receipt_parent");
    myc_agent_result_free(&ar);
    myc_result_free(&res);
}

static void test_feedback_and_payload_drop(void)
{
    myc_agent_result ar;
    myc_result res;
    const char *src =
        "int main(void){return 0;}\n";

    /* T9: feedback terisi bila source ada */
    res_init(&res);
    res.verdict = MC_OK;
    CHECK(myc_build_agent_result(&res, &ar, NULL, NULL, NULL,
                                 src, strlen(src)) == 0,
          "T9: build with source");
    CHECK(ar.feedback && ar.feedback[0] != '\0',
          "T9: feedback non-empty from myc_prompt_build");
    CHECK(ar.payload_dropped_count == 0,
          "T9: no drops under default cap");
    myc_agent_result_free(&ar);
    myc_result_free(&res);

    /* T10: cap di bawah payload penuh memaksa drop enrichment.
     * Ukur dulu ukuran default, lalu rebuild dengan cap sedikit lebih kecil. */
    res_init(&res);
    res.verdict = MC_OK;
    {
        int i;
        for (i = 0; i < 8 && i < MYC_MAX_DIAGNOSTICS; i++) {
            res.diags[i].line = i + 1;
            res.diags[i].col = 1;
            res.diags[i].message =
                "observation: lint pattern for payload pressure xxxxxxxx";
            res.diags[i].confidence = MYC_CONF_OBSERVATION;
        }
        res.diag_count = 8;
        res.finding = MYC_FINDING_FINDINGS;
    }
    CHECK(myc_build_agent_result(&res, &ar, NULL, NULL, NULL,
                                 src, strlen(src)) == 0,
          "T10a: build full payload");
    {
        size_t full = ar.payload_size;
        int cap;
        myc_agent_result_free(&ar);
        cap = (int)full - 400;
        if (cap < 1024)
            cap = 1024;
        if ((size_t)cap >= full)
            cap = 1024;
        res.agent_payload_cap = cap;
        CHECK(myc_build_agent_result(&res, &ar, NULL, NULL, NULL,
                                     src, strlen(src)) == 0,
              "T10b: build under reduced cap");
        CHECK(ar.payload_dropped_count > 0,
              "T10: at least one enrichment dropped");
        {
            int i, ok_names = 1;
            for (i = 0; i < ar.payload_dropped_count; i++) {
                const char *n = ar.payload_dropped[i];
                if (!n ||
                    (strcmp(n, "experiments") != 0 &&
                     strcmp(n, "causal") != 0 &&
                     strcmp(n, "next_best") != 0 &&
                     strcmp(n, "feedback") != 0 &&
                     strcmp(n, "pack") != 0))
                    ok_names = 0;
            }
            CHECK(ok_names, "T10: payload_dropped names known");
        }
        CHECK(ar.has_next_check && ar.next_check.command,
              "T10: next_check tetap setelah drop");
    }
    myc_agent_result_free(&ar);
    myc_result_free(&res);
}

static void test_compile_class(void)
{
    myc_agent_result ar;
    myc_result res;

    res_init(&res);
    res.verdict = MC_COMPILE_ERROR;
    res.finding = MYC_FINDING_FINDINGS;
    res.diags[0].line = 10;
    res.diags[0].col = 1;
    res.diags[0].message = "error: array subscript is above array bounds";
    res.diags[0].confidence = MYC_CONF_CONFIRMED;
    res.diag_count = 1;

    CHECK(myc_build_agent_result(&res, &ar, NULL, NULL, NULL, NULL, 0) == 0,
          "T8: build compile");
    CHECK(ar.has_primary && ar.primary_finding.diagnostic_class &&
              strcmp(ar.primary_finding.diagnostic_class, "compile") == 0,
          "T8: diagnostic_class=compile");
    CHECK(ar.next_check.command &&
              strstr(ar.next_check.command, "FIX_ONE") &&
              !strstr(ar.next_check.command, "--run"),
          "T8: next_check FIX_ONE tanpa --run");
    CHECK(ar.has_action && ar.action == MYC_LITE_FIX_ONE,
          "T8: action=FIX_ONE");
    CHECK(ar.has_primary && ar.primary_finding.source_anchor &&
              strstr(ar.primary_finding.source_anchor, "f-"),
          "T8: source_anchor additive");
    myc_agent_result_free(&ar);
    myc_result_free(&res);
}

int main(void)
{
    test_next_check();
    test_diagnostic_class_and_edits();
    test_compile_class();
    test_feedback_and_payload_drop();
    printf("agent_nemo_test: PASS=%d FAIL=%d\n", PASS, FAIL);
    return FAIL ? 1 : 0;
}
