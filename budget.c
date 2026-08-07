/*
 * budget.c -- Assurance Budget Contract (Fase 3, SOL-30).
 *
 * Implementasi:
 *   - myc_budget_parse: parse JSON kontrak ketat (reuse json.c).
 *     Format:
 *       { "required": { "<gate>": "clean"|"optional", ... },
 *         "max_time_ms": N, "max_output_bytes": N }
 *     Nama gate memakai nama pendek myc_gate_id_short() (mis. "compile",
 *     "runtime", "prove", "driver", "checked", "filc", "analyzer",
 *     "metamorphic", "negative", "lint", "preprocess").
 *   - myc_budget_enforce: panggil setelah pipeline + quorum. Untuk tiap
 *     gate ber-level CLEAN: bila status != completed_clean -> target
 *     TIDAK tercapai. Detail per gate dirangkum ke res->budget_report
 *     (arena) + debt MYC_DEBT_BUDGET (kode MYC-INCOMPLETE-BUDGET-*).
 *     Bila verdict masih MC_OK dan ada gate clean yang gagal tercapai,
 *     verdict -> INCONCLUSIVE + completeness/finding diselaraskan +
 *     receipt dibangun ulang (pola enforce_require_complete 9.10).
 *     Verdict findings (bug nyata) TIDAK diturunkan.
 *
 * Non-blocking secara desain: tanpa req.budget.active, fungsi ini no-op
 * dan TIDAK mengubah verdict/receipt (receipt deterministik lintas run
 * tanpa kontrak tetap terjaga).
 */
#include "budget.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gate.h"
#include "json.h"
#include "sha256.h"

/* ------------------------------------------------------------------ */
/* Nama level (statis)                                                 */
/* ------------------------------------------------------------------ */

const char *myc_budget_level_name(myc_budget_level l)
{
    switch (l) {
    case MYC_BUDGET_CLEAN:   return "clean";
    case MYC_BUDGET_OPTIONAL:return "optional";
    default:                 return "unset";
    }
}

void myc_budget_free(myc_budget_contract *bc)
{
    if (!bc)
        return;
    free(bc->raw);
    bc->raw = NULL;
    bc->active = 0;
}

/* Cek apakah debt BUDGET sudah ada di res->debt (hindari duplikat saat
 * enforce dipanggil pada hasil yang sudah membawa debt, mis. replay). */
static int budget_debt_present(const myc_result *res)
{
    size_t i;
    for (i = 0; i < res->debt_count; i++) {
        if (res->debt[i].type == MYC_DEBT_BUDGET)
            return 1;
    }
    return 0;
}

/* Map nama gate pendek -> gate id; -1 bila tidak dikenal. */
static int budget_gate_id(const char *name)
{
    int i;
    for (i = 0; i < MYC_GATE_COUNT; i++) {
        if (strcmp(myc_gate_id_short((myc_gate_id)i), name) == 0)
            return i;
    }
    return -1;
}

/* Parse objek "required" -> level per gate. Mengembalikan 0 sukses,
 * -1 bila ada key tidak dikenal / nilai tidak valid. */
static int budget_parse_required(json_value *req_obj, myc_budget_contract *bc)
{
    size_t i;
    if (!req_obj || req_obj->type != JSON_OBJ)
        return -1;
    for (i = 0; i < req_obj->mlen; i++) {
        const char *k = req_obj->members[i].key;
        json_value *v = req_obj->members[i].val;
        int gid, lvl;

        if (!k || !v || v->type != JSON_STR)
            return -1;
        gid = budget_gate_id(k);
        if (gid < 0)
            return -1;
        if (strcmp(v->str, "clean") == 0)
            lvl = MYC_BUDGET_CLEAN;
        else if (strcmp(v->str, "optional") == 0)
            lvl = MYC_BUDGET_OPTIONAL;
        else
            return -1;
        bc->level[gid] = (myc_budget_level)lvl;
    }
    return 0;
}

int myc_budget_parse(const char *json_text, size_t len,
                     myc_budget_contract *bc)
{
    json_value *root = NULL;
    json_value *required = NULL;
    json_value *v;
    int ret = -1;

    if (!bc || !json_text || len == 0)
        return -1;
    memset(bc, 0, sizeof(*bc));

    if (!json_parse(json_text, len, &root) || !root)
        return -1;

    required = json_get(root, "required");
    if (required && budget_parse_required(required, bc) != 0)
        goto out;

    v = json_get(root, "max_time_ms");
    if (v && v->type == JSON_NUM) {
        if (v->num < 0 || v->num > 600000)
            goto out;               /* batas konsisten --timeout */
        bc->max_time_ms = (int)v->num;
    } else if (v) {
        goto out;
    }

    v = json_get(root, "max_output_bytes");
    if (v && v->type == JSON_NUM) {
        if (v->num < 0 || v->num > MYC_MAX_OUTPUT_CAP_BYTES)
            goto out;
        bc->max_output_bytes = (int)v->num;
    } else if (v) {
        goto out;
    }

    /* Setidaknya satu dimensi target harus diminta (bukan kontrak kosong
     * yang diam-diam "clean segalanya tanpa budget"). */
    if (bc->max_time_ms <= 0 && bc->max_output_bytes <= 0) {
        int any = 0, i;
        for (i = 0; i < MYC_GATE_COUNT; i++)
            if (bc->level[i] == MYC_BUDGET_CLEAN)
                any = 1;
        if (!any)
            goto out;
    }

    bc->raw = (char *)malloc(len + 1);
    if (!bc->raw)
        goto out;
    memcpy(bc->raw, json_text, len);
    bc->raw[len] = '\0';
    bc->active = 1;
    ret = 0;

out:
    json_free(root);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Enforcement                                                         */
/* ------------------------------------------------------------------ */

/* Apakah user meminta gate ini dijalankan (flag request)? Gate yang
 * tidak pernah diminta = recipe lebih lemah dari kontrak -> TIDAK
 * tercapai, scheduler wajib menjelaskan (SOL-30). */
static int budget_gate_requested(const myc_request *req, myc_gate_id id)
{
    switch (id) {
    case MYC_GATE_PREPROCESS:
    case MYC_GATE_COMPILE:
    case MYC_GATE_LINT:      return 1;   /* selalu dijalankan */
    case MYC_GATE_ANALYZER:  return req->run_analyzer;
    case MYC_GATE_RUNTIME:   return req->run;
    case MYC_GATE_PROVE:     return req->prove;
    case MYC_GATE_CHECKED:   return req->checked;
    case MYC_GATE_FILC:      return req->filc;
    case MYC_GATE_DRIVER:    return req->driver;
    case MYC_GATE_METAMORPHIC: return req->metamorphic;
    case MYC_GATE_NEGATIVE:  return req->negative;
    default:                 return 0;
    }
}

/* Status gate yang "mencapai target clean":
 *   - gate WAJIB diminta user (flag) — bila tidak, recipe lebih lemah;
 *   - status COMPLETED_CLEAN = tercapai;
 *   - status NOT_APPLICABLE SETELAH diminta = benar-benar tak berlaku
 *     utk source ini (mis. checked tanpa MYC_BUF) — dihitung tercapai;
 *   - UNAVAILABLE/INFRA_FAILED/INCONCLUSIVE/FINDINGS = tidak tercapai. */
static int budget_gate_met(const myc_request *req, const myc_result *res,
                           myc_gate_id id)
{
    const myc_gate_result *g = myc_gate_get(res, id);
    if (!g)
        return 0;   /* tidak pernah dijalankan */
    if (!budget_gate_requested(req, id))
        return 0;   /* recipe lebih lemah dari kontrak */
    return g->status == MYC_GATE_COMPLETED_CLEAN ||
           g->status == MYC_GATE_NOT_APPLICABLE;
}

void myc_budget_enforce(const myc_request *req, myc_result *res)
{
    char   report[1024];
    size_t off = 0;
    int    target_met = 1;
    int    has_budget_debt = 0;
    int    i;

    if (!req || !res || !req->budget.active)
        return;

#define B_APPEND(...) do { \
        int _n = snprintf(report + off, sizeof(report) - off, __VA_ARGS__); \
        if (_n > 0) off += (size_t)_n; \
        if (off >= sizeof(report)) off = sizeof(report) - 1; \
    } while (0)

    res->budget_active = 1;
    B_APPEND("budget contract: target ");
    {
        int first = 1;
        for (i = 0; i < MYC_GATE_COUNT; i++) {
            if (req->budget.level[i] == MYC_BUDGET_CLEAN) {
                B_APPEND("%s%s=clean", first ? "" : " ", 
                         myc_gate_id_short((myc_gate_id)i));
                first = 0;
            }
        }
        if (req->budget.max_time_ms > 0)
            B_APPEND("%smax_time_ms=%d", first ? "" : " ",
                     req->budget.max_time_ms);
        if (req->budget.max_output_bytes > 0)
            B_APPEND("%smax_output_bytes=%d", first ? "" : " ",
                     req->budget.max_output_bytes);
    }
    B_APPEND("\n");

    for (i = 0; i < MYC_GATE_COUNT; i++) {
        if (req->budget.level[i] != MYC_BUDGET_CLEAN)
            continue;
        if (budget_gate_met(req, res, (myc_gate_id)i)) {
            B_APPEND("  %s: tercapai (clean)\n",
                     myc_gate_id_short((myc_gate_id)i));
        } else {
            const myc_gate_result *g = myc_gate_get(res, (myc_gate_id)i);
            const char *st = "not_run";
            if (g)
                switch (g->status) {
                case MYC_GATE_UNAVAILABLE:    st = "unavailable"; break;
                case MYC_GATE_INFRA_FAILED:   st = "infra_failed"; break;
                case MYC_GATE_INCONCLUSIVE:   st = "inconclusive"; break;
                case MYC_GATE_COMPLETED_FINDINGS: st = "findings"; break;
                default:                      st = "not_run"; break;
                }
            if (!g && !budget_gate_requested(req, (myc_gate_id)i))
                st = "not_requested";
            B_APPEND("  %s: TIDAK tercapai (%s) -- dimensi dikorbankan\n",
                     myc_gate_id_short((myc_gate_id)i), st);
            target_met = 0;
            if (!has_budget_debt && !budget_debt_present(res) &&
                res->debt_count < MYC_MAX_DEBT) {
                res->debt[res->debt_count].type = MYC_DEBT_BUDGET;
                res->debt[res->debt_count].text =
                    "target assurance tidak tercapai dalam budget "
                    "(lihat budget_report)";
                res->debt_count++;
                has_budget_debt = 1;
            }
        }
    }

    if (req->budget.max_time_ms > 0 &&
        res->duration_ms > (unsigned long long)req->budget.max_time_ms) {
        B_APPEND("  max_time_ms: TIDAK tercapai (durasi %llu ms > %d ms) "
                 "-- dimensi dikorbankan: waktu\n",
                 res->duration_ms, req->budget.max_time_ms);
        target_met = 0;
        if (!has_budget_debt && !budget_debt_present(res) &&
            res->debt_count < MYC_MAX_DEBT) {
            res->debt[res->debt_count].type = MYC_DEBT_BUDGET;
            res->debt[res->debt_count].text =
                "target waktu tidak tercapai dalam budget";
            res->debt_count++;
            has_budget_debt = 1;
        }
    }
    if (req->budget.max_output_bytes > 0 &&
        (res->total_stdout_bytes + res->total_stderr_bytes +
         res->run_total_stdout_bytes + res->run_total_stderr_bytes +
         (res->prove_stdout_text ? strlen(res->prove_stdout_text) : 0) +
         (res->prove_stderr_text ? strlen(res->prove_stderr_text) : 0) +
         (res->filc_stdout_text ? strlen(res->filc_stdout_text) : 0) +
         (res->filc_stderr_text ? strlen(res->filc_stderr_text) : 0) +
         (res->driver_stdout_text ? strlen(res->driver_stdout_text) : 0) +
         (res->driver_stderr_text ? strlen(res->driver_stderr_text) : 0)) >
            (size_t)req->budget.max_output_bytes) {
        B_APPEND("  max_output_bytes: TIDAK tercapai (output total melebihi "
                 "%d bytes) -- dimensi dikorbankan: detail output\n",
                 req->budget.max_output_bytes);
        target_met = 0;
        if (!has_budget_debt && !budget_debt_present(res) &&
            res->debt_count < MYC_MAX_DEBT) {
            res->debt[res->debt_count].type = MYC_DEBT_BUDGET;
            res->debt[res->debt_count].text =
                "target output tidak tercapai dalam budget";
            res->debt_count++;
            has_budget_debt = 1;
        }
    }

    B_APPEND("target tercapai: %s\n", target_met ? "YA" : "TIDAK");
    res->budget_report = myc_result_arena_dup(res, report, strlen(report));
    res->budget_met = target_met;
#undef B_APPEND

    /* Enforcement verdict: target tidak tercapai tapi belum ada bug nyata
     * (verdict masih OK) -> INCONCLUSIVE. Verdict findings/COMPILE_ERROR
     * TIDAK diturunkan (bug nyata tetap findings; kontrak dilaporkan
     * tidak tercapai di budget_report). */
    if (!target_met && res->verdict == MC_OK) {
        res->verdict = MC_INCONCLUSIVE;
        if (res->finding == MYC_FINDING_CLEAN)
            res->finding = MYC_FINDING_INCONCLUSIVE;
        if (res->completeness == MYC_COMPLETENESS_COMPLETE)
            res->completeness = MYC_COMPLETENESS_INCOMPLETE;
        myc_rebuild_receipt(res);
    }
}
