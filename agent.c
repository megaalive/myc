#include "agent.h"
#include "report.h"
#include "gate.h"
#include "json.h"
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

static char *agent_strdup(const char *s)
{
    size_t len;
    char *out;
    if (!s) return NULL;
    len = strlen(s);
    out = malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, s, len + 1);
    return out;
}

static char *agent_printf(const char *fmt, ...)
{
    va_list ap;
    va_list ap2;
    int len;
    char *out;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (len < 0) { va_end(ap2); return NULL; }
    out = malloc((size_t)len + 1);
    if (!out) { va_end(ap2); return NULL; }
    vsnprintf(out, (size_t)len + 1, fmt, ap2);
    va_end(ap2);
    return out;
}

void myc_agent_result_init(myc_agent_result *ar)
{
    memset(ar, 0, sizeof(*ar));
    ar->schema = MYC_AGENT_SCHEMA;
}

void myc_agent_result_free(myc_agent_result *ar)
{
    size_t i;
    free(ar->intent_hash);
    free(ar->scenario_hash);
    free(ar->source_sha256);
    free(ar->receipt_sha256);
    free(ar->primary_finding.finding_id);
    free(ar->primary_finding.anchor);
    free(ar->primary_finding.diagnostic_class);
    free(ar->primary_finding.message);
    free(ar->primary_finding.repro);
    free(ar->primary_finding.witness_hash);
    free(ar->witness_text);
    free(ar->witness_repro);
    free(ar->witness_slice);
    for (i = 0; i < (size_t)ar->allowed_edit_count; i++) {
        free(ar->allowed_edits[i].region);
        free(ar->allowed_edits[i].description);
    }
    for (i = 0; i < (size_t)ar->preserve_count; i++) {
        free(ar->preserve[i].symbol);
        free(ar->preserve[i].reason);
    }
    for (i = 0; i < (size_t)ar->forbidden_count; i++) {
        free(ar->forbidden[i].region);
        free(ar->forbidden[i].reason);
    }
    free(ar->next_check.finding_id);
    free(ar->next_check.command);
    for (i = 0; i < (size_t)ar->frontier_count; i++) {
        free(ar->frontier[i]);
    }
    free(ar->delta_receipt_sha);
}

static void agent_add_str(json_value *obj, const char *key, const char *val)
{
    if (val) json_obj_set(obj, key, json_new_str(val));
}

static void agent_add_int(json_value *obj, const char *key, int val)
{
    json_obj_set(obj, key, json_new_num((int64_t)val));
}

const char *myc_agent_result_json(const myc_agent_result *ar)
{
    json_value *root;
    json_value *pf;
    json_value *arr;
    json_value *obj;
    json_value *av;
    size_t i;
    char *out;
    int ok;

    root = json_new_obj();
    if (!root) return NULL;

    json_obj_set(root, "schema", json_new_str(MYC_AGENT_SCHEMA));
    agent_add_str(root, "intent_hash", ar->intent_hash);
    agent_add_str(root, "scenario_hash", ar->scenario_hash);
    agent_add_str(root, "source_sha256", ar->source_sha256);
    agent_add_str(root, "receipt_sha256", ar->receipt_sha256);

    agent_add_int(root, "finding", (int)ar->finding);
    agent_add_int(root, "verdict", (int)ar->verdict);

    av = json_new_obj();
    if (av) {
        const char *dim_names = "CSRBPDF";
        for (i = 0; i < MYC_DIM_COUNT; i++) {
            char key[2];
            key[0] = dim_names[i];
            key[1] = '\0';
            json_obj_set(av, key,
                json_new_num((int64_t)ar->assurance.status[i]));
        }
        json_obj_set(root, "assurance_vector", av);
    }

    if (ar->has_primary) {
        pf = json_new_obj();
        if (pf) {
            agent_add_str(pf, "finding_id",
                ar->primary_finding.finding_id);
            agent_add_str(pf, "anchor",
                ar->primary_finding.anchor);
            agent_add_str(pf, "diagnostic_class",
                ar->primary_finding.diagnostic_class);
            agent_add_str(pf, "message",
                ar->primary_finding.message);
            agent_add_int(pf, "confidence",
                (int)ar->primary_finding.confidence);
            agent_add_str(pf, "repro",
                ar->primary_finding.repro);
            agent_add_str(pf, "witness_hash",
                ar->primary_finding.witness_hash);
            json_obj_set(root, "primary_finding", pf);
        }
    }

    agent_add_str(root, "witness_text", ar->witness_text);
    agent_add_str(root, "witness_repro", ar->witness_repro);
    agent_add_str(root, "witness_slice", ar->witness_slice);

    arr = json_new_arr();
    if (arr) {
        for (i = 0; i < (size_t)ar->allowed_edit_count; i++) {
            obj = json_new_obj();
            if (obj) {
                agent_add_str(obj, "region",
                    ar->allowed_edits[i].region);
                agent_add_str(obj, "description",
                    ar->allowed_edits[i].description);
                json_arr_push(arr, obj);
            }
        }
        json_obj_set(root, "allowed_edits", arr);
    }

    arr = json_new_arr();
    if (arr) {
        for (i = 0; i < (size_t)ar->preserve_count; i++) {
            obj = json_new_obj();
            if (obj) {
                agent_add_str(obj, "symbol",
                    ar->preserve[i].symbol);
                agent_add_str(obj, "reason",
                    ar->preserve[i].reason);
                json_arr_push(arr, obj);
            }
        }
        json_obj_set(root, "preserve", arr);
    }

    arr = json_new_arr();
    if (arr) {
        for (i = 0; i < (size_t)ar->forbidden_count; i++) {
            obj = json_new_obj();
            if (obj) {
                agent_add_str(obj, "region",
                    ar->forbidden[i].region);
                agent_add_str(obj, "reason",
                    ar->forbidden[i].reason);
                json_arr_push(arr, obj);
            }
        }
        json_obj_set(root, "forbidden_changes", arr);
    }

    if (ar->has_next_check) {
        obj = json_new_obj();
        if (obj) {
            agent_add_str(obj, "finding_id",
                ar->next_check.finding_id);
            agent_add_str(obj, "command",
                ar->next_check.command);
            json_obj_set(root, "next_check", obj);
        }
    }

    arr = json_new_arr();
    if (arr) {
        for (i = 0; i < (size_t)ar->frontier_count; i++) {
            json_arr_push(arr, json_new_str(ar->frontier[i]));
        }
        json_obj_set(root, "frontier", arr);
    }

    agent_add_str(root, "delta_receipt_sha", ar->delta_receipt_sha);

    ok = json_serialize(root, &out);
    json_free(root);
    if (!ok) return NULL;
    return out;
}

const myc_agent_finding *myc_agent_select_primary(const myc_result *res)
{
    static myc_agent_finding primary;
    const char *msg = "no finding";
    myc_confidence conf = MYC_CONF_OBSERVATION;

    if (!res) return NULL;

    memset(&primary, 0, sizeof(primary));

    if (res->finding == MYC_FINDING_FINDINGS && res->diag_count > 0) {
        msg = res->diags[0].message ? res->diags[0].message : "unknown";
        conf = res->diags[0].confidence;
    }

    primary.diagnostic_class = agent_strdup("memory-safety");
    primary.message = agent_strdup(msg);
    primary.confidence = conf;
    primary.repro = NULL;
    primary.witness_hash = NULL;

    return &primary;
}

char *myc_agent_build_witness(const myc_result *res)
{
    if (!res || !res->capsule) return NULL;
    return agent_strdup(res->capsule->source_sha256);
}

char *myc_agent_build_next_check(const myc_result *res)
{
    (void)res;
    return agent_strdup("myc check <file> --agent");
}

int myc_build_agent_result(const myc_result *res,
                                  myc_agent_result *ar,
                                  const char *intent_hash,
                                  const char *scenario_hash)
{
    size_t i;

    if (!res || !ar) return -1;

    myc_agent_result_init(ar);

    ar->finding = res->finding;
    ar->verdict = res->verdict;
    ar->assurance = res->assurance_vector;

    if (intent_hash) {
        ar->intent_hash = agent_strdup(intent_hash);
    }
    if (scenario_hash) {
        ar->scenario_hash = agent_strdup(scenario_hash);
    }
    if (res->source_sha256) {
        ar->source_sha256 = agent_strdup(res->source_sha256);
    }
    if (res->receipt_sha256[0] != '\0') {
        ar->receipt_sha256 = agent_strdup(res->receipt_sha256);
    }

    /* Primary finding: pick the first CONFIRMED diagnostic. */
    if (res->finding == MYC_FINDING_FINDINGS && res->diag_count > 0) {
        for (i = 0; i < (size_t)res->diag_count; i++) {
            if (res->diags[i].confidence >= MYC_CONF_CONFIRMED) {
                myc_agent_finding *pf = &ar->primary_finding;
                pf->finding_id = agent_printf("f-%08x",
                    (unsigned)res->diags[i].line);
                pf->anchor = agent_strdup(res->diags[i].message);
                pf->diagnostic_class = agent_strdup(
                    myc_gate_id_short(MYC_GATE_COMPILE));
                pf->message = agent_strdup(res->diags[i].message);
                pf->confidence = res->diags[i].confidence;
                pf->repro = NULL;
                pf->witness_hash = NULL;
                ar->has_primary = 1;
                break;
            }
        }
    }

    /* Witness from capsule */
    if (res->capsule) {
        ar->witness_text = agent_strdup(
            res->capsule->source_sha256);
        if (res->capsule->stdin_sha256) {
            ar->witness_repro = agent_strdup(
                res->capsule->stdin_sha256);
        }
    }

    /* Next check */
    ar->next_check.command = agent_strdup(
        "myc check <file> --agent");
    ar->has_next_check = 1;

    /* Check payload size */
    {
        const char *js = myc_agent_result_json(ar);
        ar->payload_size = js ? strlen(js) : 0;
        free((void *)js);
    }

    if (ar->payload_size > MYC_AGENT_PAYLOAD_CAP) {
        myc_agent_result_free(ar);
        return -1;
    }

    return 0;
}