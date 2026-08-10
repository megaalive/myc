#include "agent.h"
#include "report.h"
#include "gate.h"
#include "json.h"
#include "frontier.h"
#include "observation.h"
#include "causal.h"
#include "nextbest.h"
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
    free(ar->experiments_json);
    free(ar->causal_json);
    free(ar->next_best_json);
    free(ar->delta_receipt_sha);
    free(ar->pack_json);
}

static void agent_add_str(json_value *obj, const char *key, const char *val)
{
    if (val) json_obj_set(obj, key, json_new_str(val));
}

static void agent_add_int(json_value *obj, const char *key, int val)
{
    json_obj_set(obj, key, json_new_num((int64_t)val));
}

/* Fase 7 (DS-15 wiring): bangun objek JSON pack proyek lokal dari
 * info (hasil myc_pack_load). NULL bila info kosong / OOM. Field
 * prompt_sha256/prompt_text hanya ada bila prompt.md present;
 * spec_sha256/name/domain/rules/allow_headers/deny_functions hanya
 * bila spec.json present -- klaim selalu punya sumber (jujur). */
static char *agent_pack_build_json(const myc_pack_info *info)
{
    json_value *root;
    json_value *arr;
    char *out = NULL;
    int  i;

    if (!info || (!info->prompt_present && !info->spec_present))
        return NULL;

    root = json_new_obj();
    if (!root) return NULL;

    json_obj_set(root, "prompt_present",
                 json_new_num(info->prompt_present ? 1 : 0));
    json_obj_set(root, "spec_present",
                 json_new_num(info->spec_present ? 1 : 0));

    if (info->prompt_present) {
        agent_add_str(root, "prompt_sha256",
            info->prompt_sha256[0] ? info->prompt_sha256 : NULL);
        agent_add_str(root, "prompt_text", info->prompt_text);
    }
    if (info->spec_present) {
        agent_add_str(root, "spec_sha256",
            info->spec_sha256[0] ? info->spec_sha256 : NULL);
        agent_add_str(root, "name",
            info->spec_name[0] ? info->spec_name : NULL);
        agent_add_str(root, "domain",
            info->spec_domain[0] ? info->spec_domain : NULL);

        arr = json_new_arr();
        if (arr) {
            for (i = 0; i < info->spec_n_rules && i < MYC_PACK_MAX_RULES; i++)
                json_arr_push(arr, json_new_str(info->spec_rules[i]));
            json_obj_set(root, "rules", arr);
        }
        arr = json_new_arr();
        if (arr) {
            for (i = 0; i < info->spec_n_allow && i < MYC_PACK_MAX_HEADS; i++)
                json_arr_push(arr, json_new_str(info->spec_allow[i]));
            json_obj_set(root, "allow_headers", arr);
        }
        arr = json_new_arr();
        if (arr) {
            for (i = 0; i < info->spec_n_deny && i < MYC_PACK_MAX_DENIES; i++)
                json_arr_push(arr, json_new_str(info->spec_deny[i]));
            json_obj_set(root, "deny_functions", arr);
        }
    }

    if (!json_serialize(root, &out))
        out = NULL;   /* OOM: gagal jujur, bukan pointer sampah */
    json_free(root);
    return out;
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

    /* Fase 7 (privacy/size controls): cap payload yang dipakai run ini
     * (0 = default 16384). Ukuran aktual (payload_size) TIDAK
     * diserialisasi di sini agar enforcement size di build tidak
     * circular (ukuran JSON yang dihitung = ukuran yang dihasilkan). */
    agent_add_int(root, "payload_cap", (int)ar->payload_cap);

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

    agent_add_str(root, "experiments", ar->experiments_json);
    agent_add_str(root, "causal", ar->causal_json);
    agent_add_str(root, "next_best", ar->next_best_json);
    agent_add_str(root, "delta_receipt_sha", ar->delta_receipt_sha);

    /* Fase 7 (DS-15 wiring): pack proyek lokal diserialisasi sebagai
     * objek (bukan string) bila ada. pack_json dibangun dari isi pack
     * dengan json API, jadi parse ulang di sini aman & deterministik. */
    if (ar->pack_json) {
        json_value *pv = NULL;
        if (json_parse_cstr(ar->pack_json, &pv) && pv) {
            json_obj_set(root, "pack", pv);
        }
    }

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
                                  const char *scenario_hash,
                                  const myc_pack_info *pack)
{
    size_t i;
    const char *js = NULL;

    if (!res || !ar) return -1;

    myc_agent_result_init(ar);

    /* Fase 7 (DS-15 wiring): pack proyek lokal -> enrichment terakhir
     * (dibuang paling akhir saat enforcement cap di bawah). Hanya
     * disertakan bila ada isi (prompt.md ATAU spec.json). */
    ar->pack_json = agent_pack_build_json(pack);

    /* Fase 7 (privacy/size controls): cap dari res (di-wire myc_run
     * dari --agent-payload-cap); 0 = default MYC_AGENT_PAYLOAD_CAP.
     * Enforcement di bawah memakai cap ini, bukan konstanta hardcoded. */
    ar->payload_cap = res->agent_payload_cap > 0
                          ? (size_t)res->agent_payload_cap
                          : (size_t)MYC_AGENT_PAYLOAD_CAP;

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

    /* Primary finding: ROOT CAUSE dari causal graph dulu (SOL-09) --
     * bukan sekadar diag CONFIRMED pertama. Setelah root hilang,
     * dependent findings diverifikasi ulang (lihat ar->causal_json). */
    if (res->diag_count > 1 ||
        (res->finding == MYC_FINDING_FINDINGS && res->diag_count > 0)) {
        myc_causal_graph cg;
        int ridx = -1;

        /* Graph dibangun SEKALI, dipakai untuk primary selection DAN
         * serialisasi causal_json (hindari kerja duplikat). */
        myc_causal_build(res, &cg);

        if (res->finding == MYC_FINDING_FINDINGS && res->diag_count > 0) {
            ridx = myc_causal_first_confirmed_root(&cg);
            if (ridx < 0 && cg.repair_count > 0)
                ridx = cg.repair_order[0];
            if (ridx >= 0) {
                const myc_diagnostic *d = &res->diags[ridx];
                myc_agent_finding *pf = &ar->primary_finding;
                pf->finding_id = agent_printf("f-%08x",
                    (unsigned)d->line);
                pf->anchor = agent_strdup(d->message);
                pf->diagnostic_class = agent_strdup(
                    myc_gate_id_short(MYC_GATE_COMPILE));
                pf->message = agent_strdup(d->message);
                pf->confidence = d->confidence;
                pf->repro = NULL;
                pf->witness_hash = NULL;
                ar->has_primary = 1;
            }
        }

        /* Causal Finding Graph (Fase 3, SOL-09): serialize cluster finding
         * agar model tahu root cause dulu + dependent findings yang ditahan. */
        if (res->diag_count > 1)
            ar->causal_json = myc_causal_json(&cg);

        myc_causal_free(&cg);
    }

    /* Witness from myc_witness (Fase 1) */
    if (res->witness) {
        /* witness_text = ringkasan violation */
        if (res->witness->violation_kind) {
            ar->witness_text = agent_strdup(res->witness->violation_kind);
        } else if (res->witness->violation_msg) {
            ar->witness_text = agent_strdup(res->witness->violation_msg);
        }
        /* witness_repro = backend info */
        if (res->witness->backend) {
            ar->witness_repro = agent_strdup(res->witness->backend);
        }
    } else if (res->capsule) {
        /* Fallback ke capsule bila tidak ada witness */
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

    /* Frontier + Experiments (Fase 3, SOL-02/SOL-17): isi peta frontier
     * dan set eksperimen dari observasi agar LLM bekerja di batas
     * pengetahuan, bukan mengulang pemeriksaan yang sudah selesai. */
    {
        myc_frontier_set fs;
        myc_experiment_set exps;
        myc_frontier_build(res, &fs);
        myc_observation_to_experiment(res, &exps);

        for (i = 0; i < (size_t)fs.count &&
                    ar->frontier_count < MYC_AGENT_MAX_FRONTIER; i++) {
            const myc_frontier_item *it = &fs.items[i];
            char buf[256];
            snprintf(buf, sizeof(buf), "%s: %s (%s) -- %s",
                     it->hazard, it->status, it->backend,
                     it->reason ? it->reason : "");
            ar->frontier[ar->frontier_count++] = agent_strdup(buf);
        }

        if (exps.count > 0) {
            ar->experiments_json = myc_experiment_json(&exps);
        }

        /* Next-Best Experiment (Fase 3, SOL-03): pilih eksperimen
         * termurah/menjanjikan untuk maju dari frontier status. */
        {
            myc_nextbest_set nb;
            myc_nextbest_plan(&fs, &exps, &nb);
            if (nb.count > 0)
                ar->next_best_json = myc_nextbest_json(&nb);
            myc_nextbest_free(&nb);
        }

        myc_experiment_free(&exps);
        myc_frontier_free(&fs);
    }

    /* Check payload size: bila melebihi cap (dari res->agent_payload_cap,
     * default MYC_AGENT_PAYLOAD_CAP), buang field ENRICHMENT bertahap
     * (experiments_json dulu, lalu causal_json) dan cek ulang -- protokol
     * inti (verdict/finding/primary/witness) harus selalu utuh. Hanya bila
     * protokol inti pun melebihi cap baru gagal total (-1). */
    js = myc_agent_result_json(ar);
    ar->payload_size = js ? strlen(js) : 0;
    free((void *)js);
    if (ar->payload_size > ar->payload_cap && ar->experiments_json) {
        free(ar->experiments_json);
        ar->experiments_json = NULL;
        js = myc_agent_result_json(ar);
        ar->payload_size = js ? strlen(js) : 0;
        free((void *)js);
    }
    if (ar->payload_size > ar->payload_cap && ar->causal_json) {
        free(ar->causal_json);
        ar->causal_json = NULL;
        js = myc_agent_result_json(ar);
        ar->payload_size = js ? strlen(js) : 0;
        free((void *)js);
    }
    if (ar->payload_size > ar->payload_cap && ar->next_best_json) {
        free(ar->next_best_json);
        ar->next_best_json = NULL;
        js = myc_agent_result_json(ar);
        ar->payload_size = js ? strlen(js) : 0;
        free((void *)js);
    }
    /* Pack = enrichment TERAKHIR yang dibuang: konten proyek yang user
     * sengaja sediakan (version-controllable), lebih berharga daripada
     * eksperimen otomatis; hanya dikorbankan bila benar-benar perlu. */
    if (ar->payload_size > ar->payload_cap && ar->pack_json) {
        free(ar->pack_json);
        ar->pack_json = NULL;
        js = myc_agent_result_json(ar);
        ar->payload_size = js ? strlen(js) : 0;
        free((void *)js);
    }

    if (ar->payload_size > ar->payload_cap) {
        myc_agent_result_free(ar);
        return -1;
    }

    return 0;
}