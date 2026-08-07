/*
 * cache.c -- Incremental Evidence Cache (Fase 3, SOL-18).
 */
#include "cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "ledger.h"
#include "policy.h"
#include "proc.h"
#include "sha256.h"

/* mkdir portabel (pola sama dengan driver.c/filc.c). */
#if defined(_WIN32)
#include <direct.h>
#define cache_mkdir(p) _mkdir(p)
#else
#include <sys/stat.h>
#define cache_mkdir(p) mkdir(p, 0700)
#endif

/* ------------------------------------------------------------------ */
/* Key + tool identity                                                 */
/* ------------------------------------------------------------------ */

/* Tool identity: versi gcc + clang (untuk memastikan cache tidak dipakai
 * bila toolchain berubah). Menjalankan `<exe> --version` via myc_tool_version;
 * non-blocking: gagal = string kosong (key tetap deterministik untuk input
 * yang sama, hanya kurang tool-version granularity). */
static void cache_tool_key(const myc_request *req, char *out, size_t cap)
{
    char *gcc = NULL;
    char *gcc_ver = NULL;
    char *clang = NULL;
    char *clang_ver = NULL;

    if (cap == 0)
        return;
    out[0] = '\0';

    gcc = myc_find_executable(req->gcc_program ? req->gcc_program : "gcc");
    if (gcc)
        gcc_ver = myc_tool_version(gcc);

    /* clang hanya dipakai bila gate runtime/driver/metamorphic diminta. */
    if (req->run || req->driver || req->metamorphic) {
        clang = myc_find_executable(
            req->clang_program ? req->clang_program : "clang");
        if (clang)
            clang_ver = myc_tool_version(clang);
    }

    snprintf(out, cap, "gcc:%s|clang:%s",
             gcc_ver ? gcc_ver : (gcc ? gcc : "?"),
             clang_ver ? clang_ver : (clang ? clang : "?"));

    free(gcc);
    free(gcc_ver);
    free(clang);
    free(clang_ver);
}

/* Key kanonik: sha256(source + scenario + tool + cwd). */
static void cache_build_key(const myc_request *req,
                            const char *src, size_t srclen,
                            const char *tool_key, char out[65])
{
    char source_hex[65];
    char scenario[17];
    char *scen_full;
    char buf[8192];
    int  n;

    sha256_hex(src, srclen, source_hex);

    scen_full = myc_ledger_build_scenario_hash(req, NULL);
    if (scen_full) {
        snprintf(scenario, sizeof(scenario), "%s", scen_full);
        free(scen_full);
    } else {
        snprintf(scenario, sizeof(scenario), "?");
    }

    n = snprintf(buf, sizeof(buf), "v1|src:%s|scen:%s|tool:%s|cwd:%s|",
                 source_hex, scenario, tool_key ? tool_key : "",
                 req->cwd ? req->cwd : "");
    if (n < 0)
        n = 0;
    if ((size_t)n >= sizeof(buf))
        n = (int)sizeof(buf) - 1;
    sha256_hex(buf, (size_t)n, out);
}

/* ------------------------------------------------------------------ */
/* Persistence: .myc/evidence_cache.json                              */
/* ------------------------------------------------------------------ */

static int cache_read_all(myc_cache_entry *out, int cap)
{
    FILE *f;
    long  sz;
    char *buf;
    json_value *root, *arr;
    int i, n = 0;

    if (cap <= 0)
        return 0;
    f = fopen(MYC_CACHE_FILE, "rb");
    if (!f)
        return 0;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 32 * 1024 * 1024) {
        fclose(f);
        return 0;
    }
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return 0;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return 0;
    }
    buf[sz] = '\0';
    fclose(f);

    if (!json_parse(buf, (size_t)sz, &root) || !root ||
        root->type != JSON_OBJ) {
        if (root)
            json_free(root);
        free(buf);
        return 0;
    }
    arr = json_get(root, "entries");
    if (arr && arr->type == JSON_ARR) {
        for (i = 0; i < (int)arr->len && n < cap; i++) {
            json_value *e = arr->items[i];
            json_value *v;
            myc_cache_entry *ce = &out[n];
            int k;

            if (!e || e->type != JSON_OBJ)
                continue;
            memset(ce, 0, sizeof(*ce));

            v = json_get(e, "key");   if (v && v->type == JSON_STR) snprintf(ce->key_sha256, sizeof(ce->key_sha256), "%s", v->str);
            v = json_get(e, "source"); if (v && v->type == JSON_STR) snprintf(ce->source_sha256, sizeof(ce->source_sha256), "%s", v->str);
            v = json_get(e, "scenario"); if (v && v->type == JSON_STR) snprintf(ce->scenario_hash, sizeof(ce->scenario_hash), "%s", v->str);
            v = json_get(e, "tool");  if (v && v->type == JSON_STR) snprintf(ce->tool_key, sizeof(ce->tool_key), "%s", v->str);
            v = json_get(e, "cwd");   if (v && v->type == JSON_STR) snprintf(ce->cwd, sizeof(ce->cwd), "%s", v->str);
            v = json_get(e, "path");  if (v && v->type == JSON_STR) snprintf(ce->path, sizeof(ce->path), "%s", v->str);
            v = json_get(e, "receipt"); if (v && v->type == JSON_STR) snprintf(ce->receipt_sha256, sizeof(ce->receipt_sha256), "%s", v->str);
            v = json_get(e, "fingerprint"); if (v && v->type == JSON_STR) snprintf(ce->fingerprint, sizeof(ce->fingerprint), "%s", v->str);

            /* Enum di-clamp ke range valid (file cache = input eksternal;
             * nilai di luar range -> UNKNOWN/0, bukan UB di name-function). */
            /* MC_INCONCLUSIVE (10) adalah nilai TERAKHIR dari myc_verdict;
             * clamp salah memakai MC_DRIVER_VIOLATION (9) akan MENOLAK
             * verdict INCONCLUSIVE -> replay mengubahnya jadi OK (false-
             * clean). Kunci: batas atas harus nilai enum terakhir. */
            v = json_get(e, "verdict"); if (v && v->type == JSON_NUM && v->num >= 0 && v->num <= MC_INCONCLUSIVE) ce->verdict = (myc_verdict)v->num;
            v = json_get(e, "err");    if (v && v->type == JSON_NUM && v->num >= 0 && v->num < (int64_t)MYC_ERR_INTERNAL) ce->err = (myc_error_code)v->num;
            v = json_get(e, "assurance"); if (v && v->type == JSON_NUM && v->num >= 0 && v->num <= MYC_ASSURANCE_L5_FILC) ce->assurance = (myc_assurance)v->num;
            v = json_get(e, "finding"); if (v && v->type == JSON_NUM && v->num >= 0 && v->num <= MYC_FINDING_INCONCLUSIVE) ce->finding = (myc_finding)v->num;
            v = json_get(e, "completeness"); if (v && v->type == JSON_NUM && v->num >= 0 && v->num <= MYC_COMPLETENESS_INCOMPLETE) ce->completeness = (myc_completeness)v->num;
            v = json_get(e, "claim");  if (v && v->type == JSON_NUM && v->num >= 0 && v->num <= MYC_CLAIM_UNVERIFIED) ce->claim = (myc_claim_status)v->num;
            v = json_get(e, "duration_ms"); if (v && v->type == JSON_NUM) ce->duration_ms = (unsigned long long)v->num;

            v = json_get(e, "lint_obs"); if (v && v->type == JSON_NUM) ce->lint_observations = (int)v->num;
            v = json_get(e, "neg_calls"); if (v && v->type == JSON_NUM) ce->negative_callsites = (int)v->num;
            v = json_get(e, "neg_dev"); if (v && v->type == JSON_NUM) ce->negative_deviations = (int)v->num;
            v = json_get(e, "chk_b"); if (v && v->type == JSON_NUM) ce->checked_buffers = (int)v->num;
            v = json_get(e, "chk_a"); if (v && v->type == JSON_NUM) ce->checked_allocations = (int)v->num;
            v = json_get(e, "chk_at"); if (v && v->type == JSON_NUM) ce->checked_accesses = (int)v->num;
            v = json_get(e, "chk_f"); if (v && v->type == JSON_NUM) ce->checked_frees = (int)v->num;
            v = json_get(e, "budget_active"); if (v && v->type == JSON_NUM) ce->budget_active = (int)v->num;
            v = json_get(e, "budget_met"); if (v && v->type == JSON_NUM) ce->budget_met = (int)v->num;
            v = json_get(e, "budget_report"); if (v && v->type == JSON_STR) snprintf(ce->budget_report, sizeof(ce->budget_report), "%s", v->str);
            /* Fase 4 A1: host facts toolchain (replay tanpa exec gcc). */
            v = json_get(e, "asm_f_ok"); if (v && v->type == JSON_NUM) ce->host_facts_ok = (int)v->num;
            v = json_get(e, "asm_cu"); if (v && v->type == JSON_NUM) ce->host_char_unsigned = (int)v->num;
            v = json_get(e, "asm_ib"); if (v && v->type == JSON_NUM) ce->host_int_bits = (int)v->num;
            v = json_get(e, "asm_pb"); if (v && v->type == JSON_NUM) ce->host_ptr_bits = (int)v->num;
            v = json_get(e, "asm_le"); if (v && v->type == JSON_NUM) ce->host_little_endian = (int)v->num;
            v = json_get(e, "asm_stdc"); if (v && v->type == JSON_NUM) ce->host_stdc_version = (long)v->num;
            v = json_get(e, "asm_cb"); if (v && v->type == JSON_NUM) ce->host_char_bit = (int)v->num;
            v = json_get(e, "drv_funcs"); if (v && v->type == JSON_NUM) ce->driver_funcs = (int)v->num;
            v = json_get(e, "drv_cases"); if (v && v->type == JSON_NUM) ce->driver_cases = (int)v->num;
            v = json_get(e, "drv_skip"); if (v && v->type == JSON_NUM) ce->driver_skipped = (int)v->num;
            v = json_get(e, "ran_neg"); if (v && v->type == JSON_NUM) ce->ran_negative = (int)v->num;
            v = json_get(e, "ran_chk"); if (v && v->type == JSON_NUM) ce->ran_checked = (int)v->num;
            v = json_get(e, "ran_drv"); if (v && v->type == JSON_NUM) ce->ran_driver = (int)v->num;

            /* snapshot lengkap field hasil (SOL-18 replay identik). */
            v = json_get(e, "exit_code"); if (v && v->type == JSON_NUM) ce->exit_code = (int)v->num;
            v = json_get(e, "req_complete"); if (v && v->type == JSON_NUM) ce->require_complete = (int)v->num;
            v = json_get(e, "truncated"); if (v && v->type == JSON_NUM) ce->truncated = (int)v->num;
            v = json_get(e, "run_timed_out"); if (v && v->type == JSON_NUM) ce->run_timed_out = (int)v->num;
            v = json_get(e, "san_detected"); if (v && v->type == JSON_NUM) ce->run_sanitizer_detected = (int)v->num;
            v = json_get(e, "ran_rt"); if (v && v->type == JSON_NUM) ce->ran_runtime = (int)v->num;
            v = json_get(e, "ran_prove"); if (v && v->type == JSON_NUM) ce->ran_prove = (int)v->num;
            v = json_get(e, "ran_filc"); if (v && v->type == JSON_NUM) ce->ran_filc = (int)v->num;
            v = json_get(e, "ran_meta"); if (v && v->type == JSON_NUM) ce->ran_metamorphic = (int)v->num;
            v = json_get(e, "ran_pre"); if (v && v->type == JSON_NUM) ce->ran_preprocess = (int)v->num;
            v = json_get(e, "ran_comp"); if (v && v->type == JSON_NUM) ce->ran_compile = (int)v->num;
            v = json_get(e, "ran_anl"); if (v && v->type == JSON_NUM) ce->ran_analyzer = (int)v->num;
            v = json_get(e, "chk_uses"); if (v && v->type == JSON_NUM) ce->checked_uses_buf = (int)v->num;
            v = json_get(e, "chk_ok"); if (v && v->type == JSON_NUM) ce->checked_build_ok = (int)v->num;
            v = json_get(e, "prov_alarms"); if (v && v->type == JSON_NUM) ce->prove_alarms = (int)v->num;
            v = json_get(e, "prov_po"); if (v && v->type == JSON_NUM) ce->prove_proof_obligations = (int)v->num;
            v = json_get(e, "filc_panics"); if (v && v->type == JSON_NUM) ce->filc_panics = (int)v->num;
            v = json_get(e, "m0_exit"); if (v && v->type == JSON_NUM) ce->meta_o0_exit = (int)v->num;
            v = json_get(e, "m2_exit"); if (v && v->type == JSON_NUM) ce->meta_o2_exit = (int)v->num;
            v = json_get(e, "m0_fnd"); if (v && v->type == JSON_NUM) ce->meta_o0_finding = (int)v->num;
            v = json_get(e, "m2_fnd"); if (v && v->type == JSON_NUM) ce->meta_o2_finding = (int)v->num;
            v = json_get(e, "m_inc"); if (v && v->type == JSON_NUM) ce->metamorphic_inconsistent = (int)v->num;
            v = json_get(e, "drv_max"); if (v && v->type == JSON_NUM) ce->driver_max_product = (long)v->num;
            v = json_get(e, "drv_bnd"); if (v && v->type == JSON_NUM) ce->driver_bounded = (int)v->num;
            v = json_get(e, "out_bytes"); if (v && v->type == JSON_NUM) ce->total_stdout_bytes = (unsigned long long)v->num;
            v = json_get(e, "err_bytes"); if (v && v->type == JSON_NUM) ce->total_stderr_bytes = (unsigned long long)v->num;
            v = json_get(e, "ct_req"); if (v && v->type == JSON_NUM) ce->contract_requires = (int)v->num;
            v = json_get(e, "ct_ens"); if (v && v->type == JSON_NUM) ce->contract_ensures = (int)v->num;
            v = json_get(e, "san_marker"); if (v && v->type == JSON_STR) snprintf(ce->sanitizer_marker, sizeof(ce->sanitizer_marker), "%s", v->str);
            v = json_get(e, "prov_mode"); if (v && v->type == JSON_STR) snprintf(ce->prove_mode, sizeof(ce->prove_mode), "%s", v->str);
            v = json_get(e, "prov_ver"); if (v && v->type == JSON_STR) snprintf(ce->prove_version, sizeof(ce->prove_version), "%s", v->str);
            v = json_get(e, "filc_ver"); if (v && v->type == JSON_STR) snprintf(ce->filc_version, sizeof(ce->filc_version), "%s", v->str);
            v = json_get(e, "drv_hsha"); if (v && v->type == JSON_STR) snprintf(ce->driver_harness_sha256, sizeof(ce->driver_harness_sha256), "%s", v->str);
            v = json_get(e, "stderr_text"); if (v && v->type == JSON_STR) snprintf(ce->stderr_text, sizeof(ce->stderr_text), "%s", v->str);
            v = json_get(e, "run_stdout"); if (v && v->type == JSON_STR) snprintf(ce->run_stdout_text, sizeof(ce->run_stdout_text), "%s", v->str);
            v = json_get(e, "run_stderr"); if (v && v->type == JSON_STR) snprintf(ce->run_stderr_text, sizeof(ce->run_stderr_text), "%s", v->str);
            v = json_get(e, "prov_stdout"); if (v && v->type == JSON_STR) snprintf(ce->prove_stdout_text, sizeof(ce->prove_stdout_text), "%s", v->str);
            v = json_get(e, "prov_stderr"); if (v && v->type == JSON_STR) snprintf(ce->prove_stderr_text, sizeof(ce->prove_stderr_text), "%s", v->str);
            v = json_get(e, "filc_stdout"); if (v && v->type == JSON_STR) snprintf(ce->filc_stdout_text, sizeof(ce->filc_stdout_text), "%s", v->str);
            v = json_get(e, "filc_stderr"); if (v && v->type == JSON_STR) snprintf(ce->filc_stderr_text, sizeof(ce->filc_stderr_text), "%s", v->str);
            v = json_get(e, "drv_stdout"); if (v && v->type == JSON_STR) snprintf(ce->driver_stdout_text, sizeof(ce->driver_stdout_text), "%s", v->str);
            v = json_get(e, "drv_stderr"); if (v && v->type == JSON_STR) snprintf(ce->driver_stderr_text, sizeof(ce->driver_stderr_text), "%s", v->str);
            v = json_get(e, "resolved_gcc"); if (v && v->type == JSON_STR) snprintf(ce->resolved_gcc, sizeof(ce->resolved_gcc), "%s", v->str);
            v = json_get(e, "gcc_version"); if (v && v->type == JSON_STR) snprintf(ce->gcc_version, sizeof(ce->gcc_version), "%s", v->str);
            v = json_get(e, "clang_version"); if (v && v->type == JSON_STR) snprintf(ce->clang_version, sizeof(ce->clang_version), "%s", v->str);

            /* driver case records */
            {
                json_value *dc = json_get(e, "drv_records");
                if (dc && dc->type == JSON_ARR) {
                    for (k = 0; k < (int)dc->len && k < 64; k++) {
                        json_value *ro = dc->items[k];
                        json_value *rv;
                        if (!ro || ro->type != JSON_OBJ)
                            continue;
                        rv = json_get(ro, "id"); if (rv && rv->type == JSON_NUM) ce->driver_records[k].case_id = (int)rv->num;
                        rv = json_get(ro, "alloc"); if (rv && rv->type == JSON_NUM) ce->driver_records[k].alloc_bytes = (long)rv->num;
                        rv = json_get(ro, "exec"); if (rv && rv->type == JSON_NUM) ce->driver_records[k].executed = (int)rv->num;
                        rv = json_get(ro, "func"); if (rv && rv->type == JSON_STR) snprintf(ce->driver_records[k].func, sizeof(ce->driver_records[k].func), "%s", rv->str);
                        rv = json_get(ro, "params"); if (rv && rv->type == JSON_STR) snprintf(ce->driver_records[k].params, sizeof(ce->driver_records[k].params), "%s", rv->str);
                        ce->driver_case_count++;
                    }
                }
            }

            /* filc cases */
            {
                json_value *fc = json_get(e, "filc_cases");
                if (fc && fc->type == JSON_ARR) {
                    for (k = 0; k < (int)fc->len && k < 16; k++) {
                        json_value *fo = fc->items[k];
                        json_value *fv;
                        if (!fo || fo->type != JSON_OBJ)
                            continue;
                        fv = json_get(fo, "line"); if (fv && fv->type == JSON_NUM) ce->filc_cases[k].line = (int)fv->num;
                        fv = json_get(fo, "col"); if (fv && fv->type == JSON_NUM) ce->filc_cases[k].col = (int)fv->num;
                        fv = json_get(fo, "msg"); if (fv && fv->type == JSON_STR) snprintf(ce->filc_cases[k].message, sizeof(ce->filc_cases[k].message), "%s", fv->str);
                        fv = json_get(fo, "file"); if (fv && fv->type == JSON_STR) snprintf(ce->filc_cases[k].file, sizeof(ce->filc_cases[k].file), "%s", fv->str);
                        fv = json_get(fo, "func"); if (fv && fv->type == JSON_STR) snprintf(ce->filc_cases[k].function, sizeof(ce->filc_cases[k].function), "%s", fv->str);
                        ce->filc_case_count++;
                    }
                }
            }

            /* contract clauses */
            {
                json_value *cc = json_get(e, "clauses");
                if (cc && cc->type == JSON_ARR) {
                    for (k = 0; k < (int)cc->len && k < 16; k++) {
                        json_value *co = cc->items[k];
                        json_value *cv;
                        if (!co || co->type != JSON_OBJ)
                            continue;
                        cv = json_get(co, "kind"); if (cv && cv->type == JSON_NUM) ce->contract_clauses[k].kind = (int)cv->num;
                        cv = json_get(co, "line"); if (cv && cv->type == JSON_NUM) ce->contract_clauses[k].line = (int)cv->num;
                        cv = json_get(co, "col"); if (cv && cv->type == JSON_NUM) ce->contract_clauses[k].col = (int)cv->num;
                        cv = json_get(co, "status"); if (cv && cv->type == JSON_NUM) ce->contract_clauses[k].status = (int)cv->num;
                        cv = json_get(co, "func"); if (cv && cv->type == JSON_STR) snprintf(ce->contract_clauses[k].func, sizeof(ce->contract_clauses[k].func), "%s", cv->str);
                        cv = json_get(co, "expr"); if (cv && cv->type == JSON_STR) snprintf(ce->contract_clauses[k].expr, sizeof(ce->contract_clauses[k].expr), "%s", cv->str);
                        ce->contract_clause_count++;
                    }
                }
            }

            /* evidence events */
            {
                json_value *ev = json_get(e, "evidence");
                if (ev && ev->type == JSON_ARR) {
                    for (k = 0; k < (int)ev->len && k < 32; k++) {
                        json_value *eo = ev->items[k];
                        json_value *e2;
                        if (!eo || eo->type != JSON_OBJ)
                            continue;
                        e2 = json_get(eo, "gate"); if (e2 && e2->type == JSON_NUM) ce->evidence[k].gate_id = (int)e2->num;
                        e2 = json_get(eo, "type"); if (e2 && e2->type == JSON_NUM) ce->evidence[k].event_type = (int)e2->num;
                        e2 = json_get(eo, "msg"); if (e2 && e2->type == JSON_STR) snprintf(ce->evidence[k].message, sizeof(ce->evidence[k].message), "%s", e2->str);
                        ce->evidence_count++;
                    }
                }
            }

            /* assurance vector (array 7) */
            {
                json_value *av = json_get(e, "av");
                if (av && av->type == JSON_ARR) {
                    for (k = 0; k < MYC_DIM_COUNT && k < (int)av->len; k++) {
                        if (av->items[k] && av->items[k]->type == JSON_NUM)
                            ce->av.status[k] = (myc_dim_status)av->items[k]->num;
                    }
                }
            }

            /* gates (status/id di-clamp ke range valid; requested = bool) */
            {
                json_value *g = json_get(e, "gates");
                if (g && g->type == JSON_ARR) {
                    for (k = 0; k < (int)g->len && k < MYC_MAX_GATES; k++) {
                        json_value *go = g->items[k];
                        json_value *gv;
                        if (!go || go->type != JSON_OBJ)
                            continue;
                        gv = json_get(go, "id");        if (gv && gv->type == JSON_NUM && gv->num >= 0 && gv->num < MYC_GATE_COUNT) ce->gate_id[k] = (int)gv->num;
                        gv = json_get(go, "requested"); if (gv && gv->type == JSON_NUM) ce->gate_requested[k] = (int)(gv->num != 0);
                        gv = json_get(go, "status");    if (gv && gv->type == JSON_NUM && gv->num >= 0 && gv->num <= MYC_GATE_COMPLETED_OBSERVATIONS) ce->gate_status[k] = (myc_gate_status)gv->num;
                        gv = json_get(go, "findings");  if (gv && gv->type == JSON_NUM) ce->gate_findings[k] = (int)gv->num;
                        ce->gate_count++;
                    }
                }
            }

            /* debt (type di-clamp ke range valid — myc_debt_type_name/
             * myc_debt_code harus selalu punya default untuk nilai valid). */
            {
                json_value *d = json_get(e, "debt");
                if (d && d->type == JSON_ARR) {
                    for (k = 0; k < (int)d->len && k < MYC_MAX_DEBT; k++) {
                        if (d->items[k] && d->items[k]->type == JSON_NUM &&
                            d->items[k]->num >= 0 &&
                            d->items[k]->num < (int64_t)MYC_DEBT_COUNT)
                            ce->debt[ce->debt_count++].type =
                                (myc_debt_type)d->items[k]->num;
                    }
                }
            }

            /* diagnostics */
            {
                json_value *d = json_get(e, "diags");
                if (d && d->type == JSON_ARR) {
                    for (k = 0; k < (int)d->len && k < MYC_MAX_DIAGNOSTICS; k++) {
                        json_value *do_ = d->items[k];
                        json_value *dv;
                        if (!do_ || do_->type != JSON_OBJ)
                            continue;
                        dv = json_get(do_, "line"); if (dv && dv->type == JSON_NUM) ce->diag_line[k] = (int)dv->num;
                        dv = json_get(do_, "col");  if (dv && dv->type == JSON_NUM) ce->diag_col[k] = (int)dv->num;
                        dv = json_get(do_, "conf"); if (dv && dv->type == JSON_NUM) ce->diag_conf[k] = (myc_confidence)dv->num;
                        dv = json_get(do_, "msg");  if (dv && dv->type == JSON_STR) snprintf(ce->diag_msg[k], sizeof(ce->diag_msg[k]), "%s", dv->str);
                        ce->diag_count++;
                    }
                }
            }

            /* functions */
            {
                json_value *fn = json_get(e, "funcs");
                if (fn && fn->type == JSON_ARR) {
                    for (k = 0; k < (int)fn->len && k < MYC_CACHE_MAX_FUNCS; k++) {
                        json_value *fo = fn->items[k];
                        json_value *fv;
                        if (!fo || fo->type != JSON_OBJ)
                            continue;
                        fv = json_get(fo, "name"); if (fv && fv->type == JSON_STR) snprintf(ce->funcs[k].name, sizeof(ce->funcs[k].name), "%s", fv->str);
                        fv = json_get(fo, "line"); if (fv && fv->type == JSON_NUM) ce->funcs[k].line = (int)fv->num;
                        fv = json_get(fo, "hash"); if (fv && fv->type == JSON_STR) snprintf(ce->funcs[k].hash, sizeof(ce->funcs[k].hash), "%s", fv->str);
                        ce->func_count++;
                    }
                }
            }

            n++;
        }
    }
    json_free(root);
    free(buf);
    return n;
}

/* Tulis ulang cache file (ukuran kecil, rewrite penuh seperti ledger). */
static void cache_write_all(const myc_cache_entry *entries, int count)
{
    FILE *f;
    json_value *root, *arr;
    char *out;
    int ok, i, k;

    cache_mkdir(".myc");

    root = json_new_obj();
    if (!root)
        return;
    arr = json_new_arr();
    if (!arr) { json_free(root); return; }

    for (i = 0; i < count; i++) {
        const myc_cache_entry *ce = &entries[i];
        json_value *e = json_new_obj();
        json_value *tmp;
        if (!e)
            continue;
        json_obj_set(e, "key", json_new_str(ce->key_sha256));
        json_obj_set(e, "source", json_new_str(ce->source_sha256));
        json_obj_set(e, "scenario", json_new_str(ce->scenario_hash));
        json_obj_set(e, "tool", json_new_str(ce->tool_key));
        json_obj_set(e, "cwd", json_new_str(ce->cwd));
        json_obj_set(e, "path", json_new_str(ce->path));
        json_obj_set(e, "receipt", json_new_str(ce->receipt_sha256));
        json_obj_set(e, "fingerprint", json_new_str(ce->fingerprint));
        json_obj_set(e, "verdict", json_new_num((int64_t)ce->verdict));
        json_obj_set(e, "err", json_new_num((int64_t)ce->err));
        json_obj_set(e, "assurance", json_new_num((int64_t)ce->assurance));
        json_obj_set(e, "finding", json_new_num((int64_t)ce->finding));
        json_obj_set(e, "completeness", json_new_num((int64_t)ce->completeness));
        json_obj_set(e, "claim", json_new_num((int64_t)ce->claim));
        json_obj_set(e, "duration_ms", json_new_num((int64_t)ce->duration_ms));
        json_obj_set(e, "lint_obs", json_new_num((int64_t)ce->lint_observations));
        json_obj_set(e, "neg_calls", json_new_num((int64_t)ce->negative_callsites));
        json_obj_set(e, "neg_dev", json_new_num((int64_t)ce->negative_deviations));
        json_obj_set(e, "chk_b", json_new_num((int64_t)ce->checked_buffers));
        json_obj_set(e, "chk_a", json_new_num((int64_t)ce->checked_allocations));
        json_obj_set(e, "chk_at", json_new_num((int64_t)ce->checked_accesses));
        json_obj_set(e, "chk_f", json_new_num((int64_t)ce->checked_frees));
        json_obj_set(e, "budget_active", json_new_num((int64_t)ce->budget_active));
        json_obj_set(e, "budget_met", json_new_num((int64_t)ce->budget_met));
        json_obj_set(e, "budget_report", json_new_str(ce->budget_report));
        /* Fase 4 A1: host facts toolchain. */
        json_obj_set(e, "asm_f_ok", json_new_num((int64_t)ce->host_facts_ok));
        json_obj_set(e, "asm_cu", json_new_num((int64_t)ce->host_char_unsigned));
        json_obj_set(e, "asm_ib", json_new_num((int64_t)ce->host_int_bits));
        json_obj_set(e, "asm_pb", json_new_num((int64_t)ce->host_ptr_bits));
        json_obj_set(e, "asm_le", json_new_num((int64_t)ce->host_little_endian));
        json_obj_set(e, "asm_stdc", json_new_num((int64_t)ce->host_stdc_version));
        json_obj_set(e, "asm_cb", json_new_num((int64_t)ce->host_char_bit));
        json_obj_set(e, "drv_funcs", json_new_num((int64_t)ce->driver_funcs));
        json_obj_set(e, "drv_cases", json_new_num((int64_t)ce->driver_cases));
        json_obj_set(e, "drv_skip", json_new_num((int64_t)ce->driver_skipped));
        json_obj_set(e, "ran_neg", json_new_num((int64_t)ce->ran_negative));
        json_obj_set(e, "ran_chk", json_new_num((int64_t)ce->ran_checked));
        json_obj_set(e, "ran_drv", json_new_num((int64_t)ce->ran_driver));

        /* snapshot lengkap field hasil (SOL-18 replay identik). */
        json_obj_set(e, "exit_code", json_new_num((int64_t)ce->exit_code));
        json_obj_set(e, "req_complete", json_new_num((int64_t)ce->require_complete));
        json_obj_set(e, "truncated", json_new_num((int64_t)ce->truncated));
        json_obj_set(e, "run_timed_out", json_new_num((int64_t)ce->run_timed_out));
        json_obj_set(e, "san_detected", json_new_num((int64_t)ce->run_sanitizer_detected));
        json_obj_set(e, "ran_rt", json_new_num((int64_t)ce->ran_runtime));
        json_obj_set(e, "ran_prove", json_new_num((int64_t)ce->ran_prove));
        json_obj_set(e, "ran_filc", json_new_num((int64_t)ce->ran_filc));
        json_obj_set(e, "ran_meta", json_new_num((int64_t)ce->ran_metamorphic));
        json_obj_set(e, "ran_pre", json_new_num((int64_t)ce->ran_preprocess));
        json_obj_set(e, "ran_comp", json_new_num((int64_t)ce->ran_compile));
        json_obj_set(e, "ran_anl", json_new_num((int64_t)ce->ran_analyzer));
        json_obj_set(e, "chk_uses", json_new_num((int64_t)ce->checked_uses_buf));
        json_obj_set(e, "chk_ok", json_new_num((int64_t)ce->checked_build_ok));
        json_obj_set(e, "prov_alarms", json_new_num((int64_t)ce->prove_alarms));
        json_obj_set(e, "prov_po", json_new_num((int64_t)ce->prove_proof_obligations));
        json_obj_set(e, "filc_panics", json_new_num((int64_t)ce->filc_panics));
        json_obj_set(e, "m0_exit", json_new_num((int64_t)ce->meta_o0_exit));
        json_obj_set(e, "m2_exit", json_new_num((int64_t)ce->meta_o2_exit));
        json_obj_set(e, "m0_fnd", json_new_num((int64_t)ce->meta_o0_finding));
        json_obj_set(e, "m2_fnd", json_new_num((int64_t)ce->meta_o2_finding));
        json_obj_set(e, "m_inc", json_new_num((int64_t)ce->metamorphic_inconsistent));
        json_obj_set(e, "drv_max", json_new_num((int64_t)ce->driver_max_product));
        json_obj_set(e, "drv_bnd", json_new_num((int64_t)ce->driver_bounded));
        json_obj_set(e, "out_bytes", json_new_num((int64_t)ce->total_stdout_bytes));
        json_obj_set(e, "err_bytes", json_new_num((int64_t)ce->total_stderr_bytes));
        json_obj_set(e, "ct_req", json_new_num((int64_t)ce->contract_requires));
        json_obj_set(e, "ct_ens", json_new_num((int64_t)ce->contract_ensures));
        json_obj_set(e, "san_marker", json_new_str(ce->sanitizer_marker));
        json_obj_set(e, "prov_mode", json_new_str(ce->prove_mode));
        json_obj_set(e, "prov_ver", json_new_str(ce->prove_version));
        json_obj_set(e, "filc_ver", json_new_str(ce->filc_version));
        json_obj_set(e, "drv_hsha", json_new_str(ce->driver_harness_sha256));
        json_obj_set(e, "stderr_text", json_new_str(ce->stderr_text));
        json_obj_set(e, "run_stdout", json_new_str(ce->run_stdout_text));
        json_obj_set(e, "run_stderr", json_new_str(ce->run_stderr_text));
        json_obj_set(e, "prov_stdout", json_new_str(ce->prove_stdout_text));
        json_obj_set(e, "prov_stderr", json_new_str(ce->prove_stderr_text));
        json_obj_set(e, "filc_stdout", json_new_str(ce->filc_stdout_text));
        json_obj_set(e, "filc_stderr", json_new_str(ce->filc_stderr_text));
        json_obj_set(e, "drv_stdout", json_new_str(ce->driver_stdout_text));
        json_obj_set(e, "drv_stderr", json_new_str(ce->driver_stderr_text));
        json_obj_set(e, "resolved_gcc", json_new_str(ce->resolved_gcc));
        json_obj_set(e, "gcc_version", json_new_str(ce->gcc_version));
        json_obj_set(e, "clang_version", json_new_str(ce->clang_version));

        /* driver case records */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->driver_case_count && k < 64; k++) {
                json_value *ro = json_new_obj();
                if (!ro)
                    continue;
                json_obj_set(ro, "id", json_new_num((int64_t)ce->driver_records[k].case_id));
                json_obj_set(ro, "alloc", json_new_num((int64_t)ce->driver_records[k].alloc_bytes));
                json_obj_set(ro, "exec", json_new_num((int64_t)ce->driver_records[k].executed));
                json_obj_set(ro, "func", json_new_str(ce->driver_records[k].func));
                json_obj_set(ro, "params", json_new_str(ce->driver_records[k].params));
                json_arr_push(tmp, ro);
            }
            json_obj_set(e, "drv_records", tmp);
        }

        /* filc cases */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->filc_case_count && k < 16; k++) {
                json_value *fo = json_new_obj();
                if (!fo)
                    continue;
                json_obj_set(fo, "line", json_new_num((int64_t)ce->filc_cases[k].line));
                json_obj_set(fo, "col", json_new_num((int64_t)ce->filc_cases[k].col));
                json_obj_set(fo, "msg", json_new_str(ce->filc_cases[k].message));
                json_obj_set(fo, "file", json_new_str(ce->filc_cases[k].file));
                json_obj_set(fo, "func", json_new_str(ce->filc_cases[k].function));
                json_arr_push(tmp, fo);
            }
            json_obj_set(e, "filc_cases", tmp);
        }

        /* contract clauses */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->contract_clause_count && k < 16; k++) {
                json_value *co = json_new_obj();
                if (!co)
                    continue;
                json_obj_set(co, "kind", json_new_num((int64_t)ce->contract_clauses[k].kind));
                json_obj_set(co, "line", json_new_num((int64_t)ce->contract_clauses[k].line));
                json_obj_set(co, "col", json_new_num((int64_t)ce->contract_clauses[k].col));
                json_obj_set(co, "status", json_new_num((int64_t)ce->contract_clauses[k].status));
                json_obj_set(co, "func", json_new_str(ce->contract_clauses[k].func));
                json_obj_set(co, "expr", json_new_str(ce->contract_clauses[k].expr));
                json_arr_push(tmp, co);
            }
            json_obj_set(e, "clauses", tmp);
        }

        /* evidence events */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->evidence_count && k < 32; k++) {
                json_value *eo = json_new_obj();
                if (!eo)
                    continue;
                json_obj_set(eo, "gate", json_new_num((int64_t)ce->evidence[k].gate_id));
                json_obj_set(eo, "type", json_new_num((int64_t)ce->evidence[k].event_type));
                json_obj_set(eo, "msg", json_new_str(ce->evidence[k].message));
                json_arr_push(tmp, eo);
            }
            json_obj_set(e, "evidence", tmp);
        }

        /* assurance vector */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < MYC_DIM_COUNT; k++)
                json_arr_push(tmp, json_new_num((int64_t)ce->av.status[k]));
            json_obj_set(e, "av", tmp);
        }

        /* gates */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->gate_count; k++) {
                json_value *go = json_new_obj();
                if (!go)
                    continue;
                json_obj_set(go, "id", json_new_num((int64_t)ce->gate_id[k]));
                json_obj_set(go, "requested",
                             json_new_num((int64_t)ce->gate_requested[k]));
                json_obj_set(go, "status", json_new_num((int64_t)ce->gate_status[k]));
                json_obj_set(go, "findings", json_new_num((int64_t)ce->gate_findings[k]));
                json_arr_push(tmp, go);
            }
            json_obj_set(e, "gates", tmp);
        }

        /* debt */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->debt_count; k++)
                json_arr_push(tmp, json_new_num((int64_t)ce->debt[k].type));
            json_obj_set(e, "debt", tmp);
        }

        /* diagnostics */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->diag_count; k++) {
                json_value *do_ = json_new_obj();
                if (!do_)
                    continue;
                json_obj_set(do_, "line", json_new_num((int64_t)ce->diag_line[k]));
                json_obj_set(do_, "col", json_new_num((int64_t)ce->diag_col[k]));
                json_obj_set(do_, "conf", json_new_num((int64_t)ce->diag_conf[k]));
                json_obj_set(do_, "msg", json_new_str(ce->diag_msg[k]));
                json_arr_push(tmp, do_);
            }
            json_obj_set(e, "diags", tmp);
        }

        /* functions */
        tmp = json_new_arr();
        if (tmp) {
            for (k = 0; k < ce->func_count; k++) {
                json_value *fo = json_new_obj();
                if (!fo)
                    continue;
                json_obj_set(fo, "name", json_new_str(ce->funcs[k].name));
                json_obj_set(fo, "line", json_new_num((int64_t)ce->funcs[k].line));
                json_obj_set(fo, "hash", json_new_str(ce->funcs[k].hash));
                json_arr_push(tmp, fo);
            }
            json_obj_set(e, "funcs", tmp);
        }

        json_arr_push(arr, e);
    }
    json_obj_set(root, "entries", arr);

    ok = json_serialize(root, &out);
    json_free(root);
    if (!ok || !out)
        return;

    f = fopen(MYC_CACHE_FILE, "wb");
    if (f) {
        fwrite(out, 1, strlen(out), f);
        fclose(f);
    }
    free(out);
}

/* ------------------------------------------------------------------ */
/* Function extraction                                                 */
/* ------------------------------------------------------------------ */

/* Ekstrak fungsi dari source (skimmer leksikal sederhana): cari pola
 * `<name>(...){ ... }` di brace level 0. Hash = sha256 isi fungsi. */
static int is_ident_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

static int is_keyword(const char *s, size_t n)
{
    static const char *const K[] = {
        "if", "for", "while", "switch", "do", "return", "sizeof",
        "case", "goto", "else", "typedef", "struct", "union", "enum",
        "static", "extern", "const", "volatile", "int", "char", "void",
        "unsigned", "signed", "long", "short", "double", "float", "ifdef",
        NULL
    };
    int i;
    for (i = 0; K[i]; i++) {
        size_t l = strlen(K[i]);
        if (l == n && strncmp(s, K[i], l) == 0)
            return 1;
    }
    return 0;
}

/* Skip whitespace (termasuk newline — dukung gaya Allman: ')' di satu
 * baris, '{' di baris berikutnya, gaya yang dipakai seluruh source myc)
 * + komentar. Mengembalikan posisi pertama non-whitespace/non-komentar. */
static size_t skip_ws_comments(const char *src, size_t srclen, size_t j)
{
    for (;;) {
        while (j < srclen &&
               (src[j] == ' ' || src[j] == '\t' || src[j] == '\n' ||
                src[j] == '\r'))
            j++;
        if (j + 1 < srclen && src[j] == '/' && src[j + 1] == '/') {
            while (j < srclen && src[j] != '\n')
                j++;
            continue;
        }
        if (j + 1 < srclen && src[j] == '/' && src[j + 1] == '*') {
            j += 2;
            while (j + 1 < srclen &&
                   !(src[j] == '*' && src[j + 1] == '/'))
                j++;
            j += 2;
            continue;
        }
        break;
    }
    return j;
}

int myc_cache_extract_functions(const char *src, size_t srclen,
                                myc_cache_function *out, int cap)
{
    size_t i = 0;
    int    depth = 0;
    int    line = 1;
    int    n = 0;

    if (!src || !out || cap <= 0)
        return -1;

    while (i < srclen) {
        char c = src[i];

        if (c == '\n')
            line++;

        /* skip komentar */
        if (c == '/' && i + 1 < srclen) {
            if (src[i + 1] == '/') {
                while (i < srclen && src[i] != '\n')
                    i++;
                continue;
            }
            if (src[i + 1] == '*') {
                i += 2;
                while (i + 1 < srclen &&
                       !(src[i] == '*' && src[i + 1] == '/'))
                    i++;
                i += 2;
                continue;
            }
        }
        /* skip string/char literal */
        if (c == '"' || c == '\'') {
            char q = c;
            i++;
            while (i < srclen && src[i] != q) {
                if (src[i] == '\\')
                    i++;
                i++;
            }
            i++;
            continue;
        }

        if (c == '{') {
            depth++;
            i++;
            continue;
        }
        if (c == '}') {
            if (depth > 0)
                depth--;
            i++;
            continue;
        }
        if (c == '#') {
            while (i < srclen && src[i] != '\n')
                i++;
            continue;
        }

        /* cari nama fungsi di level 0: ident( lalu ... ) lalu { */
        if (depth == 0 && (is_ident_char(c) &&
                           !(c >= '0' && c <= '9'))) {
            size_t start = i;
            size_t name_end;
            size_t j;

            while (i < srclen && is_ident_char(src[i]))
                i++;
            name_end = i;

            /* bukan keyword */
            if (is_keyword(src + start, name_end - start))
                continue;

            /* skip whitespace + komentar lalu cek '(' */
            j = skip_ws_comments(src, srclen, i);
            if (j >= srclen || src[j] != '(')
                continue;

            /* skip sampai ')' (matching paren) */
            {
                int paren = 1;
                j++;
                while (j < srclen && paren > 0) {
                    if (src[j] == '(') paren++;
                    else if (src[j] == ')') paren--;
                    j++;
                }
            }
            /* skip whitespace + komentar lalu cek '{' (dukung gaya
             * Allman: brace di baris berikutnya). */
            j = skip_ws_comments(src, srclen, j);
            if (j >= srclen || src[j] != '{')
                continue;

            /* ini fungsi: cari '}' penutup (brace depth mulai 1) */
            {
                size_t body_start = j;   /* posisi '{' */
                int    bd = 1;
                size_t k = j + 1;
                while (k < srclen && bd > 0) {
                    if (src[k] == '{') bd++;
                    else if (src[k] == '}') bd--;
                    k++;
                }
                if (bd == 0) {
                    /* nama + line + hash isi fungsi */
                    myc_cache_function *fn = &out[n];
                    char hashbuf[65];
                    size_t len;
                    if (name_end - start >= sizeof(fn->name))
                        name_end = start + sizeof(fn->name) - 1;
                    memcpy(fn->name, src + start, name_end - start);
                    fn->name[name_end - start] = '\0';
                    fn->line = line;
                    len = k - body_start;   /* "{ ... }" */
                    sha256_hex(src + body_start, len, hashbuf);
                    memcpy(fn->hash, hashbuf, 65);
                    n++;
                    if (n >= cap)
                        return n;
                }
            }
            /* lanjut scan dari akhir body */
            continue;
        }

        i++;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Replay                                                              */
/* ------------------------------------------------------------------ */

/* Isi res dari entry cache. Replay harus mengisi SEMUA komponen receipt
 * (verdict/completeness/gates/debt/fingerprint/source) agar receipt_sha256
 * konsisten dengan hasil yang pernah dihitung. */
static void cache_replay_into(const myc_cache_entry *e, myc_result *res)
{
    int i;

    res->verdict = e->verdict;
    res->err = e->err;
    res->assurance = e->assurance;
    res->assurance_vector = e->av;
    res->finding = e->finding;
    res->completeness = e->completeness;
    res->claim_status = e->claim;

    /* gates (id + requested ASLI dari cache, bukan index) */
    res->gate_count = 0;
    for (i = 0; i < e->gate_count && i < MYC_MAX_GATES; i++) {
        myc_gate_result *g = &res->gates[res->gate_count];
        g->id = (myc_gate_id)e->gate_id[i];
        g->status = e->gate_status[i];
        g->requested = e->gate_requested[i];
        g->findings = e->gate_findings[i];
        g->output = NULL;
        res->gate_count++;
    }

    /* debt (string statis dari myc_debt_type_name) */
    res->debt_count = 0;
    for (i = 0; i < e->debt_count && i < MYC_MAX_DEBT; i++) {
        res->debt[res->debt_count].type = e->debt[i].type;
        res->debt[res->debt_count].text = myc_debt_type_name(e->debt[i].type);
        res->debt_count++;
    }

    /* diagnostics (ke arena milik hasil) */
    for (i = 0; i < e->diag_count && i < MYC_MAX_DIAGNOSTICS; i++) {
        res->diags[i].line = e->diag_line[i];
        res->diags[i].col = e->diag_col[i];
        res->diags[i].confidence = e->diag_conf[i];
        res->diags[i].message = myc_result_arena_dup(res, e->diag_msg[i], 0);
        res->diag_count = i + 1;
    }

    /* counts */
    res->lint_observations = e->lint_observations;
    res->negative_callsites = e->negative_callsites;
    res->negative_deviations = e->negative_deviations;
    res->checked_buffers = e->checked_buffers;
    res->checked_allocations = e->checked_allocations;
    res->checked_accesses = e->checked_accesses;
    res->checked_frees = e->checked_frees;
    res->driver_funcs = e->driver_funcs;
    res->driver_cases = e->driver_cases;
    res->driver_skipped = e->driver_skipped;
    res->ran_negative = e->ran_negative;
    res->ran_checked = e->ran_checked;
    res->ran_driver = e->ran_driver;

    /* snapshot lengkap field hasil (SOL-18 replay identik). */
    res->exit_code = e->exit_code;
    res->require_complete = e->require_complete;
    res->truncated = e->truncated;
    res->run_timed_out = e->run_timed_out;
    res->run_sanitizer_detected = e->run_sanitizer_detected;
    res->ran_runtime = e->ran_runtime;
    res->ran_prove = e->ran_prove;
    res->ran_filc = e->ran_filc;
    res->ran_metamorphic = e->ran_metamorphic;
    res->ran_preprocess = e->ran_preprocess;
    res->ran_compile = e->ran_compile;
    res->ran_analyzer = e->ran_analyzer;
    res->checked_uses_buf = e->checked_uses_buf;
    res->checked_build_ok = e->checked_build_ok;
    res->prove_alarms = e->prove_alarms;
    res->prove_proof_obligations = e->prove_proof_obligations;
    res->filc_panics = e->filc_panics;
    res->meta_o0_exit = e->meta_o0_exit;
    res->meta_o2_exit = e->meta_o2_exit;
    res->meta_o0_finding = e->meta_o0_finding;
    res->meta_o2_finding = e->meta_o2_finding;
    res->metamorphic_inconsistent = e->metamorphic_inconsistent;
    res->driver_max_product = e->driver_max_product;
    res->driver_bounded = e->driver_bounded;
    res->total_stdout_bytes = e->total_stdout_bytes;
    res->total_stderr_bytes = e->total_stderr_bytes;
    res->contract_requires = e->contract_requires;
    res->contract_ensures = e->contract_ensures;
    /* SOL-30: hasil enforcement budget contract di-replay utuh (verdict/
     * debt/report sudah mencerminkan run asli; kontrak ada di cache key,
     * jadi re-enforce di jalur cache-hit TIDAK dilakukan). */
    res->budget_active = e->budget_active;
    res->budget_met = e->budget_met;
    if (e->budget_report[0]) {
        res->budget_report = myc_result_arena_dup(res, e->budget_report, 0);
        if (!res->budget_report)
            res->budget_report = NULL;
    }
    /* Fase 4 A1: replay host facts — deteksi asumsi tetap di-scan ulang
     * di jalur cache-hit (myc.c) memakai facts ini (tanpa exec gcc). */
    res->assumption_facts_ok = e->host_facts_ok;
    res->host_facts.ok = e->host_facts_ok;
    res->host_facts.char_unsigned = e->host_char_unsigned;
    res->host_facts.int_bits = e->host_int_bits;
    res->host_facts.ptr_bits = e->host_ptr_bits;
    res->host_facts.little_endian = e->host_little_endian;
    res->host_facts.stdc_version = e->host_stdc_version;
    res->host_facts.char_bit = e->host_char_bit;

    snprintf(res->run_sanitizer_marker,
             sizeof(res->run_sanitizer_marker), "%s", e->sanitizer_marker);
    /* PENTING (SOL-18): myc_result_free memanggil free() INDIVIDUAL pada
     * field-field ini (lihat myc_result_free). Karena itu replay WAJIB
     * memakai myc_strdup (malloc), BUKAN myc_result_arena_dup — arena
     * dibebaskan utuh oleh myc_result_free, free() individual pada
     * pointer arena = invalid free (heap corruption c0000374, pola sama
     * dengan bug witness Fase 3). */
    /* prove_mode/prove_version TIDAK di-free individual oleh
     * myc_result_free (arena-based) -> tetap arena dup. */
    res->prove_mode = myc_result_arena_dup(res, e->prove_mode, 0);
    res->prove_version = myc_result_arena_dup(res, e->prove_version, 0);
    res->filc_version = myc_strdup(e->filc_version);
    res->driver_harness_sha256 = myc_strdup(e->driver_harness_sha256);
    res->stderr_text = myc_strdup(e->stderr_text);
    res->run_stdout_text = myc_strdup(e->run_stdout_text);
    res->run_stderr_text = myc_strdup(e->run_stderr_text);
    res->prove_stdout_text = myc_strdup(e->prove_stdout_text);
    res->prove_stderr_text = myc_strdup(e->prove_stderr_text);
    res->filc_stdout_text = myc_strdup(e->filc_stdout_text);
    res->filc_stderr_text = myc_strdup(e->filc_stderr_text);
    res->driver_stdout_text = myc_strdup(e->driver_stdout_text);
    res->driver_stderr_text = myc_strdup(e->driver_stderr_text);

    /* resolved_gcc/gcc_version/clang_version: malloc di pipeline (di-free
     * individual oleh myc_result_free) -> strdup. */
    res->resolved_gcc = myc_strdup(e->resolved_gcc);
    res->gcc_version = myc_strdup(e->gcc_version);
    res->clang_version = myc_strdup(e->clang_version);

    /* driver case records: func/params arena-based di pipeline. */
    res->driver_case_count = 0;
    for (i = 0; i < e->driver_case_count && i < 64; i++) {
        myc_driver_case *r = &res->driver_case_records[res->driver_case_count];
        r->case_id = e->driver_records[i].case_id;
        r->alloc_bytes = e->driver_records[i].alloc_bytes;
        r->executed = e->driver_records[i].executed;
        r->func = myc_result_arena_dup(res, e->driver_records[i].func, 0);
        r->params = e->driver_records[i].params[0]
                        ? myc_result_arena_dup(res, e->driver_records[i].params, 0)
                        : NULL;
        res->driver_case_count++;
    }

    /* filc cases (arena-based). */
    res->filc_case_count = 0;
    for (i = 0; i < e->filc_case_count && i < 16; i++) {
        myc_filc_case *c = &res->filc_cases[res->filc_case_count];
        memset(c, 0, sizeof(*c));
        c->line = e->filc_cases[i].line;
        c->col = e->filc_cases[i].col;
        c->message = myc_result_arena_dup(res, e->filc_cases[i].message, 0);
        c->file = myc_result_arena_dup(res, e->filc_cases[i].file, 0);
        c->function = myc_result_arena_dup(res, e->filc_cases[i].function, 0);
        res->filc_case_count++;
    }

    /* contract clauses (arena-based). */
    res->contract_clause_count = 0;
    for (i = 0; i < e->contract_clause_count && i < 16; i++) {
        myc_contract_clause *cl =
            &res->contract_clauses[res->contract_clause_count];
        memset(cl, 0, sizeof(*cl));
        cl->kind = e->contract_clauses[i].kind;
        cl->line = e->contract_clauses[i].line;
        cl->col = e->contract_clauses[i].col;
        cl->status = (myc_clause_status)e->contract_clauses[i].status;
        cl->func = myc_result_arena_dup(res, e->contract_clauses[i].func, 0);
        cl->expr = myc_result_arena_dup(res, e->contract_clauses[i].expr, 0);
        res->contract_clause_count++;
    }

    /* evidence events: message malloc di pipeline (di-free individual) ->
     * strdup. */
    res->evidence_count = 0;
    for (i = 0; i < e->evidence_count && i < 32; i++) {
        myc_evidence_event *ev = &res->evidence[res->evidence_count++];
        ev->gate_id = (uint32_t)e->evidence[i].gate_id;
        ev->event_type = (uint32_t)e->evidence[i].event_type;
        ev->message = myc_strdup(e->evidence[i].message);
    }

    /* identity + receipt (agar deterministik) */
    res->source_sha256 = myc_strdup(e->source_sha256);
    res->fingerprint = myc_strdup(e->fingerprint);
    memcpy(res->receipt_sha256, e->receipt_sha256, 65);

    res->cache_hit = 1;
}

/* Cari entry dengan scenario+tool+cwd SAMA tapi source BERBEDA
 * (untuk delta report saat source berubah). Saat kedua sisi punya path
 * file, path harus cocok juga supaya tidak membandingkan file BERBEDA.
 * Return index atau -1. */
static int cache_find_stale(const myc_cache_entry *entries, int n,
                            const char *source_sha256,
                            const char *scenario_hash,
                            const char *tool_key,
                            const char *cwd,
                            const char *path)
{
    int i;
    for (i = 0; i < n; i++) {
        if (strcmp(entries[i].scenario_hash, scenario_hash) != 0 ||
            strcmp(entries[i].tool_key, tool_key) != 0 ||
            strcmp(entries[i].cwd, cwd) != 0 ||
            strcmp(entries[i].source_sha256, source_sha256) == 0)
            continue;
        /* bila path tersedia di kedua sisi, harus cocok (file yang sama). */
        if (path && path[0] && entries[i].path[0] &&
            strcmp(entries[i].path, path) != 0)
            continue;
        return i;
    }
    return -1;
}

int myc_cache_try_replay(const myc_request *req, myc_result *res,
                         const char *src, size_t srclen)
{
    /* Entry cache besar (~100KB): array harus di HEAP, bukan stack
     * (64 entries di stack = stack overflow, crash c00000fd). */
    myc_cache_entry *entries;
    char tool[129];
    char key[65];
    char source_hex[65];
    char scenario[17];
    char *scen_full;
    int  n, i, ret = 0;

    if (!req || !res || !src)
        return 0;
    if (req->no_cache)
        return 0;
    if (srclen == 0)
        return 0;
    /* Fase 4 A1 (review fix): run yang MENGUBAH/menggantung pada state
     * eksternal .myc/assumptions.json (--assumption-ack menulis state;
     * --require-assumptions-closed menegakkan atas state) TIDAK boleh
     * di-replay: entry lama bisa memuat verdict/debt/receipt dari state
     * yang sudah berubah (mis. ack menutup asumsi setelah entry dibuat)
     * -> hasil stale yang kontradiktif. Run ini selalu lewat pipeline
     * (filosofi sama dgn fix SOL-30: enforcement stateful tak di-replay). */
    if (req->require_assumptions_closed || req->assumption_acks)
        return 0;

    entries = (myc_cache_entry *)calloc(MYC_CACHE_MAX_ENTRIES,
                                        sizeof(*entries));
    if (!entries)
        return 0;

    sha256_hex(src, srclen, source_hex);
    cache_tool_key(req, tool, sizeof(tool));
    cache_build_key(req, src, srclen, tool, key);

    scen_full = myc_ledger_build_scenario_hash(req, NULL);
    if (scen_full) {
        snprintf(scenario, sizeof(scenario), "%s", scen_full);
        free(scen_full);
    } else {
        snprintf(scenario, sizeof(scenario), "?");
    }

    n = cache_read_all(entries, MYC_CACHE_MAX_ENTRIES);
    for (i = 0; i < n; i++) {
        if (strcmp(entries[i].key_sha256, key) == 0) {
            cache_replay_into(&entries[i], res);
            ret = 1;
            goto done;
        }
    }

    /* Miss tapi source BERUBAH dengan scenario sama: hitung delta
     * (fungsi berubah + dependents) agar edit satu fungsi terlihat
     * scope-nya tanpa harus membandingkan seluruh output. */
    {
        int stale = cache_find_stale(entries, n, source_hex, scenario, tool,
                                     req->cwd ? req->cwd : "",
                                     req->input.file_path ?
                                         req->input.file_path : "");
        if (stale >= 0) {
            res->cache_delta_report =
                myc_cache_delta_report(src, srclen, &entries[stale]);
        }
    }

done:
    free(entries);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Store                                                               */
/* ------------------------------------------------------------------ */

void myc_cache_store(const myc_request *req, const myc_result *res,
                     const char *src, size_t srclen)
{
    /* Fase 4 A1 (review fix): konsisten dgn try_replay — run stateful
     * (--assumption-ack / --require-assumptions-closed) tidak disimpan
     * ke cache (state eksternal .myc/assumptions.json bisa berubah;
     * replay entry lama = hasil stale). */
    if (req && (req->require_assumptions_closed || req->assumption_acks))
        return;
    /* Entry cache besar (~100KB): SEMUA di HEAP, bukan stack
     * (64 entries di stack = stack overflow c00000fd). */
    myc_cache_entry *entries;
    myc_cache_entry *ne;
    char tool[129];
    char key[65];
    int  n, i;

    if (!req || !res || !src)
        return;
    if (req->no_cache)
        return;
    if (srclen == 0)
        return;

    /* jangan cache hasil error/timeout (bukan bukti valid untuk replay) */
    if (res->verdict == MC_ERROR || res->err == MYC_ERR_TIMEOUT ||
        res->err == MYC_ERR_INTERNAL)
        return;

    entries = (myc_cache_entry *)calloc(MYC_CACHE_MAX_ENTRIES,
                                        sizeof(*entries));
    ne = (myc_cache_entry *)calloc(1, sizeof(*ne));
    if (!entries || !ne) {
        free(entries);
        free(ne);
        return;
    }
    cache_tool_key(req, tool, sizeof(tool));
    cache_build_key(req, src, srclen, tool, key);
    memcpy(ne->key_sha256, key, 65);
    sha256_hex(src, srclen, ne->source_sha256);
    {
        char *scen = myc_ledger_build_scenario_hash(req, NULL);
        snprintf(ne->scenario_hash, sizeof(ne->scenario_hash), "%s",
                 scen ? scen : "?");
        free(scen);
    }
    snprintf(ne->tool_key, sizeof(ne->tool_key), "%s", tool);
    snprintf(ne->cwd, sizeof(ne->cwd), "%s", req->cwd ? req->cwd : "");
    snprintf(ne->path, sizeof(ne->path), "%s",
             req->input.file_path ? req->input.file_path : "");
    memcpy(ne->receipt_sha256, res->receipt_sha256, 65);
    snprintf(ne->fingerprint, sizeof(ne->fingerprint), "%s",
             res->fingerprint ? res->fingerprint : "");

    ne->verdict = res->verdict;
    ne->err = res->err;
    ne->assurance = res->assurance;
    ne->av = res->assurance_vector;
    ne->finding = res->finding;
    ne->completeness = res->completeness;
    ne->claim = res->claim_status;
    ne->duration_ms = res->duration_ms;

    ne->lint_observations = res->lint_observations;
    ne->negative_callsites = res->negative_callsites;
    ne->negative_deviations = res->negative_deviations;
    ne->checked_buffers = res->checked_buffers;
    ne->checked_allocations = res->checked_allocations;
    ne->checked_accesses = res->checked_accesses;
    ne->checked_frees = res->checked_frees;
    ne->budget_active = res->budget_active;
    ne->budget_met = res->budget_met;
    if (res->budget_report)
        snprintf(ne->budget_report, sizeof(ne->budget_report), "%s",
                 res->budget_report);
    /* Fase 4 A1: host facts toolchain (replay tanpa exec gcc). */
    ne->host_facts_ok = res->assumption_facts_ok;
    ne->host_char_unsigned = res->host_facts.char_unsigned;
    ne->host_int_bits = res->host_facts.int_bits;
    ne->host_ptr_bits = res->host_facts.ptr_bits;
    ne->host_little_endian = res->host_facts.little_endian;
    ne->host_stdc_version = res->host_facts.stdc_version;
    ne->host_char_bit = res->host_facts.char_bit;
    ne->driver_funcs = res->driver_funcs;
    ne->driver_cases = res->driver_cases;
    ne->driver_skipped = res->driver_skipped;
    ne->ran_negative = res->ran_negative;
    ne->ran_checked = res->ran_checked;
    ne->ran_driver = res->ran_driver;

    /* snapshot lengkap field hasil (SOL-18 replay identik). */
    ne->exit_code = res->exit_code;
    ne->require_complete = res->require_complete;
    ne->truncated = res->truncated;
    ne->run_timed_out = res->run_timed_out;
    ne->run_sanitizer_detected = res->run_sanitizer_detected;
    ne->ran_runtime = res->ran_runtime;
    ne->ran_prove = res->ran_prove;
    ne->ran_filc = res->ran_filc;
    ne->ran_metamorphic = res->ran_metamorphic;
    ne->ran_preprocess = res->ran_preprocess;
    ne->ran_compile = res->ran_compile;
    ne->ran_analyzer = res->ran_analyzer;
    ne->checked_uses_buf = res->checked_uses_buf;
    ne->checked_build_ok = res->checked_build_ok;
    ne->prove_alarms = res->prove_alarms;
    ne->prove_proof_obligations = res->prove_proof_obligations;
    ne->filc_panics = res->filc_panics;
    ne->meta_o0_exit = res->meta_o0_exit;
    ne->meta_o2_exit = res->meta_o2_exit;
    ne->meta_o0_finding = res->meta_o0_finding;
    ne->meta_o2_finding = res->meta_o2_finding;
    ne->metamorphic_inconsistent = res->metamorphic_inconsistent;
    ne->driver_max_product = res->driver_max_product;
    ne->driver_bounded = res->driver_bounded;
    ne->total_stdout_bytes = res->total_stdout_bytes;
    ne->total_stderr_bytes = res->total_stderr_bytes;
    ne->contract_requires = res->contract_requires;
    ne->contract_ensures = res->contract_ensures;

    snprintf(ne->sanitizer_marker, sizeof(ne->sanitizer_marker), "%s",
             res->run_sanitizer_marker);
    snprintf(ne->prove_mode, sizeof(ne->prove_mode), "%s",
             res->prove_mode ? res->prove_mode : "");
    snprintf(ne->prove_version, sizeof(ne->prove_version), "%s",
             res->prove_version ? res->prove_version : "");
    snprintf(ne->filc_version, sizeof(ne->filc_version), "%s",
             res->filc_version ? res->filc_version : "");
    snprintf(ne->driver_harness_sha256, sizeof(ne->driver_harness_sha256),
             "%s", res->driver_harness_sha256 ? res->driver_harness_sha256 : "");
    snprintf(ne->stderr_text, sizeof(ne->stderr_text), "%s",
             res->stderr_text ? res->stderr_text : "");
    snprintf(ne->run_stdout_text, sizeof(ne->run_stdout_text), "%s",
             res->run_stdout_text ? res->run_stdout_text : "");
    snprintf(ne->run_stderr_text, sizeof(ne->run_stderr_text), "%s",
             res->run_stderr_text ? res->run_stderr_text : "");
    snprintf(ne->prove_stdout_text, sizeof(ne->prove_stdout_text), "%s",
             res->prove_stdout_text ? res->prove_stdout_text : "");
    snprintf(ne->prove_stderr_text, sizeof(ne->prove_stderr_text), "%s",
             res->prove_stderr_text ? res->prove_stderr_text : "");
    snprintf(ne->filc_stdout_text, sizeof(ne->filc_stdout_text), "%s",
             res->filc_stdout_text ? res->filc_stdout_text : "");
    snprintf(ne->filc_stderr_text, sizeof(ne->filc_stderr_text), "%s",
             res->filc_stderr_text ? res->filc_stderr_text : "");
    snprintf(ne->driver_stdout_text, sizeof(ne->driver_stdout_text), "%s",
             res->driver_stdout_text ? res->driver_stdout_text : "");
    snprintf(ne->driver_stderr_text, sizeof(ne->driver_stderr_text), "%s",
             res->driver_stderr_text ? res->driver_stderr_text : "");
    snprintf(ne->resolved_gcc, sizeof(ne->resolved_gcc), "%s",
             res->resolved_gcc ? res->resolved_gcc : "");
    snprintf(ne->gcc_version, sizeof(ne->gcc_version), "%s",
             res->gcc_version ? res->gcc_version : "");
    snprintf(ne->clang_version, sizeof(ne->clang_version), "%s",
             res->clang_version ? res->clang_version : "");

    /* driver case records */
    ne->driver_case_count = 0;
    for (i = 0; i < (int)res->driver_case_count && i < 64; i++) {
        const myc_driver_case *r = &res->driver_case_records[i];
        ne->driver_records[ne->driver_case_count].case_id = r->case_id;
        ne->driver_records[ne->driver_case_count].alloc_bytes = r->alloc_bytes;
        ne->driver_records[ne->driver_case_count].executed = r->executed;
        snprintf(ne->driver_records[ne->driver_case_count].func,
                 sizeof(ne->driver_records[ne->driver_case_count].func),
                 "%s", r->func ? r->func : "");
        snprintf(ne->driver_records[ne->driver_case_count].params,
                 sizeof(ne->driver_records[ne->driver_case_count].params),
                 "%s", r->params ? r->params : "");
        ne->driver_case_count++;
    }

    /* filc cases */
    ne->filc_case_count = 0;
    for (i = 0; i < (int)res->filc_case_count && i < 16; i++) {
        const myc_filc_case *c = &res->filc_cases[i];
        ne->filc_cases[ne->filc_case_count].line = c->line;
        ne->filc_cases[ne->filc_case_count].col = c->col;
        snprintf(ne->filc_cases[ne->filc_case_count].message,
                 sizeof(ne->filc_cases[ne->filc_case_count].message),
                 "%s", c->message ? c->message : "");
        snprintf(ne->filc_cases[ne->filc_case_count].file,
                 sizeof(ne->filc_cases[ne->filc_case_count].file),
                 "%s", c->file ? c->file : "");
        snprintf(ne->filc_cases[ne->filc_case_count].function,
                 sizeof(ne->filc_cases[ne->filc_case_count].function),
                 "%s", c->function ? c->function : "");
        ne->filc_case_count++;
    }

    /* contract clauses */
    ne->contract_clause_count = 0;
    for (i = 0; i < (int)res->contract_clause_count && i < 16; i++) {
        const myc_contract_clause *cl = &res->contract_clauses[i];
        ne->contract_clauses[ne->contract_clause_count].kind = cl->kind;
        ne->contract_clauses[ne->contract_clause_count].line = cl->line;
        ne->contract_clauses[ne->contract_clause_count].col = cl->col;
        ne->contract_clauses[ne->contract_clause_count].status = cl->status;
        snprintf(ne->contract_clauses[ne->contract_clause_count].func,
                 sizeof(ne->contract_clauses[ne->contract_clause_count].func),
                 "%s", cl->func ? cl->func : "");
        snprintf(ne->contract_clauses[ne->contract_clause_count].expr,
                 sizeof(ne->contract_clauses[ne->contract_clause_count].expr),
                 "%s", cl->expr ? cl->expr : "");
        ne->contract_clause_count++;
    }

    /* evidence events */
    ne->evidence_count = 0;
    for (i = 0; i < (int)res->evidence_count && i < 32; i++) {
        const myc_evidence_event *ev = &res->evidence[i];
        ne->evidence[ne->evidence_count].gate_id = (int)ev->gate_id;
        ne->evidence[ne->evidence_count].event_type = (int)ev->event_type;
        snprintf(ne->evidence[ne->evidence_count].message,
                 sizeof(ne->evidence[ne->evidence_count].message),
                 "%s", ev->message ? ev->message : "");
        ne->evidence_count++;
    }

    for (i = 0; i < (int)res->gate_count && i < MYC_MAX_GATES; i++) {
        ne->gate_status[i] = res->gates[i].status;
        ne->gate_requested[i] = res->gates[i].requested;
        ne->gate_id[i] = (int)res->gates[i].id;
        ne->gate_findings[i] = res->gates[i].findings;
        ne->gate_count++;
    }
    for (i = 0; i < (int)res->debt_count && i < MYC_MAX_DEBT; i++) {
        ne->debt[ne->debt_count++].type = res->debt[i].type;
    }
    for (i = 0; i < (int)res->diag_count && i < MYC_MAX_DIAGNOSTICS; i++) {
        ne->diag_line[i] = res->diags[i].line;
        ne->diag_col[i] = res->diags[i].col;
        ne->diag_conf[i] = res->diags[i].confidence;
        snprintf(ne->diag_msg[i], sizeof(ne->diag_msg[i]), "%s",
                 res->diags[i].message ? res->diags[i].message : "");
        ne->diag_count++;
    }
    ne->func_count = myc_cache_extract_functions(src, srclen, ne->funcs,
                                                 MYC_CACHE_MAX_FUNCS);
    if (ne->func_count < 0)
        ne->func_count = 0;

    /* merge: replace bila key sama, append bila baru, cap entries */
    n = cache_read_all(entries, MYC_CACHE_MAX_ENTRIES);
    {
        int found = -1;
        for (i = 0; i < n; i++) {
            if (strcmp(entries[i].key_sha256, key) == 0) {
                found = i;
                break;
            }
        }
        if (found >= 0) {
            entries[found] = *ne;
        } else if (n < MYC_CACHE_MAX_ENTRIES) {
            entries[n] = *ne;
            n++;
        } else {
            /* buang entry tertua (index 0) */
            memmove(&entries[0], &entries[1],
                    sizeof(entries[0]) * (size_t)(n - 1));
            entries[n - 1] = *ne;
        }
    }
    cache_write_all(entries, n);
    free(ne);
    free(entries);
}

void myc_cache_entry_free(myc_cache_entry *e)
{
    /* Semua field flat (tidak ada heap string di luar struct) — memset
     * cukup. Dijaga untuk kompatibilitas masa depan. */
    if (e)
        memset(e, 0, sizeof(*e));
}

/* ------------------------------------------------------------------ */
/* Delta report                                                        */
/* ------------------------------------------------------------------ */

/* Cari fungsi bernama `name` di daftar; return index atau -1. */
static int find_func(const myc_cache_function *f, int n, const char *name)
{
    int i;
    for (i = 0; i < n; i++) {
        if (strcmp(f[i].name, name) == 0)
            return i;
    }
    return -1;
}

/* Cari nama di daftar nama (char[][64]); return 1 bila ada. */
static int find_name(char (*names)[64], int n, const char *name)
{
    int i;
    for (i = 0; i < n; i++) {
        if (strcmp(names[i], name) == 0)
            return 1;
    }
    return 0;
}

/* Rentang fungsi (untuk deteksi dependents yang benar). */
typedef struct {
    char   name[64];
    int    line;
    size_t start;   /* posisi '{' */
    size_t end;     /* posisi SETELAH '}' penutup */
    char   hash[65];
} range_func;

/* Cari nama di daftar range_func; return index atau -1. */
static int find_range_func(const range_func *f, int n, const char *name)
{
    int i;
    for (i = 0; i < n; i++) {
        if (strcmp(f[i].name, name) == 0)
            return i;
    }
    return -1;
}

/* Ekstrak fungsi + rentang body (varian lokal myc_cache_extract_functions). */
static int extract_ranges(const char *src, size_t srclen,
                          range_func *out, int cap)
{
    size_t i = 0;
    int    depth = 0;
    int    line = 1;
    int    n = 0;

    while (i < srclen) {
        char c = src[i];
        if (c == '\n')
            line++;
        if (c == '/' && i + 1 < srclen) {
            if (src[i + 1] == '/') {
                while (i < srclen && src[i] != '\n') i++;
                continue;
            }
            if (src[i + 1] == '*') {
                i += 2;
                while (i + 1 < srclen && !(src[i] == '*' && src[i+1] == '/')) i++;
                i += 2;
                continue;
            }
        }
        if (c == '"' || c == '\'') {
            char q = c;
            i++;
            while (i < srclen && src[i] != q) {
                if (src[i] == '\\') i++;
                i++;
            }
            i++;
            continue;
        }
        if (c == '{') { depth++; i++; continue; }
        if (c == '}') { if (depth > 0) depth--; i++; continue; }
        if (c == '#') { while (i < srclen && src[i] != '\n') i++; continue; }

        if (depth == 0 && is_ident_char(c) && !(c >= '0' && c <= '9')) {
            size_t start = i, name_end, j;
            while (i < srclen && is_ident_char(src[i])) i++;
            name_end = i;
            if (is_keyword(src + start, name_end - start))
                continue;
            j = skip_ws_comments(src, srclen, i);
            if (j >= srclen || src[j] != '(')
                continue;
            { int paren = 1; j++; while (j < srclen && paren > 0) {
                if (src[j] == '(') paren++;
                else if (src[j] == ')') paren--;
                j++; } }
            j = skip_ws_comments(src, srclen, j);
            if (j >= srclen || src[j] != '{')
                continue;
            {
                size_t body_start = j;
                int bd = 1;
                size_t k = j + 1;
                while (k < srclen && bd > 0) {
                    if (src[k] == '{') bd++;
                    else if (src[k] == '}') bd--;
                    k++;
                }
                if (bd == 0 && n < cap) {
                    range_func *fn = &out[n];
                    size_t len = name_end - start;
                    if (len >= sizeof(fn->name)) len = sizeof(fn->name) - 1;
                    memcpy(fn->name, src + start, len);
                    fn->name[len] = '\0';
                    fn->line = line;
                    fn->start = body_start;
                    fn->end = k;
                    sha256_hex(src + body_start, k - body_start, fn->hash);
                    n++;
                }
            }
            continue;
        }
        i++;
    }
    return n;
}

/* Apakah token `needle` muncul di rentang [start,end) sebagai identifier
 * utuh (bukan substring, mis. foo vs foo_bar)? */
static int token_in_range(const char *src, size_t start, size_t end,
                          const char *needle)
{
    size_t nl = strlen(needle);
    size_t p = start;
    if (nl == 0 || end <= start)
        return 0;
    while (p + nl <= end) {
        const char *hit = memchr(src + p, needle[0], end - p);
        if (!hit)
            return 0;
        p = (size_t)(hit - src);
        if (p + nl <= end &&
            strncmp(src + p, needle, nl) == 0 &&
            (p == start || !is_ident_char(src[p - 1])) &&
            (p + nl >= end || !is_ident_char(src[p + nl]))) {
            return 1;
        }
        p += 1;
    }
    return 0;
}

char *myc_cache_delta_report(const char *src, size_t srclen,
                             const myc_cache_entry *old_entry)
{
    range_func cur[MYC_CACHE_MAX_FUNCS];
    char changed[1024];
    char identical[1024];
    char added[1024];
    char removed[1024];
    char dependents[1024];
    char changed_names[MYC_CACHE_MAX_FUNCS][64];
    int  cur_n, changed_n = 0, i, j;
    int  n_changed = 0, n_identical = 0, n_added = 0, n_removed = 0, n_dep = 0;
    size_t co = 0, io = 0, ao = 0, ro = 0, dp = 0;

    if (!src || !old_entry)
        return NULL;

    cur_n = extract_ranges(src, srclen, cur, MYC_CACHE_MAX_FUNCS);
    if (cur_n < 0)
        return NULL;

    changed[0] = identical[0] = added[0] = removed[0] = dependents[0] = '\0';

    /* fungsi berubah / identik / BARU (bandingkan vs cache), dan
     * kumpulkan nama fungsi berubah. */
    for (i = 0; i < cur_n; i++) {
        int oi = find_func(old_entry->funcs, old_entry->func_count,
                           cur[i].name);
        if (oi >= 0 && strcmp(cur[i].hash, old_entry->funcs[oi].hash) == 0) {
            n_identical++;
            if (io < sizeof(identical) - 64) {
                int r = snprintf(identical + io, sizeof(identical) - io,
                                 "%s%s", io ? "," : "", cur[i].name);
                if (r > 0) io += (size_t)r;
            }
        } else if (oi >= 0) {
            n_changed++;
            if (co < sizeof(changed) - 64) {
                int r = snprintf(changed + co, sizeof(changed) - co,
                                 "%s%s", co ? "," : "", cur[i].name);
                if (r > 0) co += (size_t)r;
            }
            if (changed_n < MYC_CACHE_MAX_FUNCS) {
                size_t nl = strlen(cur[i].name);
                if (nl >= 64)
                    nl = 63;
                memcpy(changed_names[changed_n], cur[i].name, nl);
                changed_names[changed_n][nl] = '\0';
                changed_n++;
            }
        } else {
            n_added++;
            if (ao < sizeof(added) - 64) {
                int r = snprintf(added + ao, sizeof(added) - ao,
                                 "%s%s", ao ? "," : "", cur[i].name);
                if (r > 0) ao += (size_t)r;
            }
            /* fungsi baru juga perlu dependents (memanggil fungsi lain). */
            if (changed_n < MYC_CACHE_MAX_FUNCS) {
                size_t nl = strlen(cur[i].name);
                if (nl >= 64)
                    nl = 63;
                memcpy(changed_names[changed_n], cur[i].name, nl);
                changed_names[changed_n][nl] = '\0';
                changed_n++;
            }
        }
    }

    /* fungsi yang HILANG dari cache (sudah dihapus/rename di source). */
    for (i = 0; i < old_entry->func_count; i++) {
        if (find_range_func(cur, cur_n, old_entry->funcs[i].name) < 0) {
            n_removed++;
            if (ro < sizeof(removed) - 64) {
                int r = snprintf(removed + ro, sizeof(removed) - ro,
                                 "%s%s", ro ? "," : "",
                                 old_entry->funcs[i].name);
                if (r > 0) ro += (size_t)r;
            }
        }
    }

    /* dependents: fungsi (yang TIDAK berubah) yang body-nya memanggil
     * salah satu fungsi berubah/baru -> perlu diverifikasi ulang. */
    for (i = 0; i < cur_n; i++) {
        int self_changed = 0;
        if (find_name(changed_names, changed_n, cur[i].name))
            self_changed = 1;
        if (self_changed)
            continue;
        for (j = 0; j < changed_n; j++) {
            if (token_in_range(src, cur[i].start, cur[i].end,
                               changed_names[j])) {
                n_dep++;
                if (dp < sizeof(dependents) - 64) {
                    int r = snprintf(dependents + dp, sizeof(dependents) - dp,
                                     "%s%s", dp ? "," : "", cur[i].name);
                    if (r > 0) dp += (size_t)r;
                }
                break;
            }
        }
    }

    {
        char *out = (char *)malloc(3072);
        if (!out)
            return NULL;
        snprintf(out, 3072,
                 "%d berubah (%s); %d identik (%s); %d baru (%s); "
                 "%d hilang (%s)%s%s",
                 n_changed, n_changed ? changed : "-",
                 n_identical, n_identical ? identical : "-",
                 n_added, n_added ? added : "-",
                 n_removed, n_removed ? removed : "-",
                 n_dep ? "; dependents: " : "",
                 n_dep ? dependents : "");
        return out;
    }
}
