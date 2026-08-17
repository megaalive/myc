/*
 * lite_agent_test.c -- myc.lite.v1: 10 kasus agen-bodoh (hanya baca action).
 *
 * Skrip "agen bodoh": hormati action + allowed_span; jangan kirim flag soup.
 *
 * Jalankan: gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I.
 *           -DMYC_NO_MAIN -o test/lite_agent_test.exe test/lite_agent_test.c
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

/* Agen bodoh: boleh sunting iff action==FIX_ONE && allowed_span terisi. */
static int dumb_would_edit(const myc_lite_result *lr)
{
    return lr->action == MYC_LITE_FIX_ONE &&
           lr->allowed_span && lr->allowed_span[0] != '\0';
}

static int dumb_would_pass_filc(const myc_lite_result *lr)
{
    return lr->next_command && strstr(lr->next_command, "--filc") != NULL;
}

static void test_ten_cases(void)
{
    myc_result res;
    myc_lite_result lr;
    const char *lib =
        "int add(int a, int b){return a+b;}\n";
    const char *cli =
        "int main(void){return 0;}\n";

    /* 1. OK tanpa main -> STOP (bukan eskalasi runtime) */
    res_init(&res);
    res.verdict = MC_OK;
    myc_gate_set_status(&res, MYC_GATE_RUNTIME, MYC_GATE_NOT_REQUESTED, NULL);
    CHECK(myc_build_lite_result(&res, &lr, lib, strlen(lib)) == 0, "C1 build");
    CHECK(lr.action == MYC_LITE_STOP_COMPILE_CLEAN, "C1 STOP tanpa main");
    CHECK(!dumb_would_edit(&lr), "C1 agen bodoh tidak menyunting");
    CHECK(!dumb_would_pass_filc(&lr), "C1 tidak --filc");
    myc_lite_result_free(&lr);
    myc_result_free(&res);

    /* 2. OK + main, runtime belum jalan -> ESCALATE_RUNTIME */
    res_init(&res);
    res.verdict = MC_OK;
    myc_gate_set_status(&res, MYC_GATE_RUNTIME, MYC_GATE_NOT_REQUESTED, NULL);
    CHECK(myc_build_lite_result(&res, &lr, cli, strlen(cli)) == 0, "C2 build");
    CHECK(lr.action == MYC_LITE_ESCALATE_RUNTIME, "C2 ESCALATE_RUNTIME");
    CHECK(lr.next_command && strstr(lr.next_command, "--run"),
          "C2 next --run");
    CHECK(!dumb_would_edit(&lr), "C2 tidak sunting (eskalasi)");
    myc_lite_result_free(&lr);
    myc_result_free(&res);

    /* 3. COMPILE_ERROR + template array-bounds -> FIX_ONE + span */
    res_init(&res);
    res.verdict = MC_COMPILE_ERROR;
    res.finding = MYC_FINDING_FINDINGS;
    res.diags[0].line = 4;
    res.diags[0].col = 1;
    res.diags[0].message = "error: array subscript is above array bounds";
    res.diags[0].confidence = MYC_CONF_CONFIRMED;
    res.diag_count = 1;
    CHECK(myc_build_lite_result(&res, &lr, NULL, 0) == 0, "C3 build");
    CHECK(lr.action == MYC_LITE_FIX_ONE, "C3 FIX_ONE");
    CHECK(dumb_would_edit(&lr), "C3 agen bodoh menyunting span");
    CHECK(lr.allowed_span && strstr(lr.allowed_span, "4"),
          "C3 allowed_span line 4");
    CHECK(lr.fix_or_null && lr.fix_or_null[0], "C3 fix template ada");
    myc_lite_result_free(&lr);
    myc_result_free(&res);

    /* 4. COMPILE_ERROR tanpa template -> GIVE_UP, tidak sunting */
    res_init(&res);
    res.verdict = MC_COMPILE_ERROR;
    res.diags[0].line = 2;
    res.diags[0].message = "error: unknown type name 'blargh'";
    res.diag_count = 1;
    CHECK(myc_build_lite_result(&res, &lr, NULL, 0) == 0, "C4 build");
    CHECK(lr.action == MYC_LITE_GIVE_UP_NO_TEMPLATE, "C4 GIVE_UP");
    CHECK(!dumb_would_edit(&lr), "C4 agen bodoh tidak menebak");
    CHECK(lr.next_command && strstr(lr.next_command, "myc context"),
          "C4 next = context");
    myc_lite_result_free(&lr);
    myc_result_free(&res);

    /* 5. RUNTIME + sanloc tanpa source -> FIX_ONE (optimistis) */
    res_init(&res);
    res.verdict = MC_RUNTIME_VIOLATION;
    res.sanloc_have = 1;
    res.sanloc_line = 7;
    res.sanloc_function = "f";
    res.sanloc_kind = "stack-buffer-overflow";
    CHECK(myc_build_lite_result(&res, &lr, NULL, 0) == 0, "C5 build");
    CHECK(lr.action == MYC_LITE_FIX_ONE, "C5 FIX_ONE");
    CHECK(lr.line == 7, "C5 line 7");
    CHECK(lr.source_anchor && strstr(lr.source_anchor, "f-"),
          "C5 source_anchor");
    myc_lite_result_free(&lr);
    myc_result_free(&res);

    /* 6. RUNTIME tanpa sanloc -> GIVE_UP */
    res_init(&res);
    res.verdict = MC_RUNTIME_VIOLATION;
    CHECK(myc_build_lite_result(&res, &lr, NULL, 0) == 0, "C6 build");
    CHECK(lr.action == MYC_LITE_GIVE_UP_NO_TEMPLATE, "C6 GIVE_UP");
    CHECK(!dumb_would_edit(&lr), "C6 tidak sunting");
    myc_lite_result_free(&lr);
    myc_result_free(&res);

    /* 7. DRIVER -> ESCALATE_CONTRACT */
    res_init(&res);
    res.verdict = MC_DRIVER_VIOLATION;
    CHECK(myc_build_lite_result(&res, &lr, NULL, 0) == 0, "C7 build");
    CHECK(lr.action == MYC_LITE_ESCALATE_CONTRACT, "C7 ESCALATE_CONTRACT");
    CHECK(lr.next_command && strstr(lr.next_command, "--driver"),
          "C7 --driver");
    CHECK(!dumb_would_pass_filc(&lr), "C7 tidak --filc");
    myc_lite_result_free(&lr);
    myc_result_free(&res);

    /* 8. OK + runtime clean -> STOP */
    res_init(&res);
    res.verdict = MC_OK;
    myc_gate_set_status(&res, MYC_GATE_RUNTIME, MYC_GATE_COMPLETED_CLEAN,
                        NULL);
    CHECK(myc_build_lite_result(&res, &lr, cli, strlen(cli)) == 0, "C8 build");
    CHECK(lr.action == MYC_LITE_STOP_COMPILE_CLEAN, "C8 STOP");
    CHECK(lr.claim && strstr(lr.claim, "runtime_clean"),
          "C8 claim runtime_clean");
    myc_lite_result_free(&lr);
    myc_result_free(&res);

    /* 9. JSON lite memuat field wajib + schema */
    res_init(&res);
    res.verdict = MC_OK;
    CHECK(myc_build_lite_result(&res, &lr, lib, strlen(lib)) == 0, "C9 build");
    {
        char *js = myc_lite_result_json(&lr);
        CHECK(js && strstr(js, "\"schema\":\"myc.lite.v1\""), "C9 schema");
        CHECK(js && strstr(js, "\"action\""), "C9 action key");
        CHECK(js && strstr(js, "\"allowed_span\""), "C9 allowed_span");
        CHECK(js && strlen(js) < 2048, "C9 payload < 2KiB target");
        myc_free(js);
    }
    myc_lite_result_free(&lr);
    myc_result_free(&res);

    /* 10. claim tidak pernah "safe" */
    res_init(&res);
    res.verdict = MC_OK;
    CHECK(myc_build_lite_result(&res, &lr, lib, strlen(lib)) == 0, "C10 build");
    CHECK(lr.claim && !strstr(lr.claim, "safe"),
          "C10 claim bukan 'safe'");
    CHECK(strcmp(myc_lite_action_name(lr.action), "STOP_COMPILE_CLEAN") == 0,
          "C10 nama action panjang");
    myc_lite_result_free(&lr);
    myc_result_free(&res);
}

int main(void)
{
    test_ten_cases();
    printf("lite_agent_test: PASS=%d FAIL=%d\n", PASS, FAIL);
    return FAIL ? 1 : 0;
}
