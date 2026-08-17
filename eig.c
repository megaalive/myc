/*
 * eig.c -- Expected-Information-Gain Scheduler (Fase 7, #2029 / DS-14).
 */
#include "eig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "json.h"
#include "calibrate.h"
#include "profile.h"
#include "experiment_cost.h"

/* ---------- tabel deterministik: hazard -> kandidat + scope ---------- */

/* Kandidat eksperimen per hazard class (urut prioritas), nama hazard harus
 * sama persis dengan frontier.c FRONTIER_ROWS[] (dan nextbest.c). scope =
 * bobot hazard (1..5); gate_prefix = nama pendek gate (myc_gate_id_short,
 * dipakai memetakan kelas profil SOL-20 ke hazard). */
typedef struct {
    const char *hazard;
    myc_experiment_type candidates[3];
    int  scope;
    const char *gate_prefix;
} eig_rule;

static const eig_rule EIG_RULES[] = {
    { "integer/bounds (static)",
      { MYC_EXPERIMENT_BOUNDARY_INPUT, MYC_EXPERIMENT_CROSS_TARGET,
        MYC_EXPERIMENT_DRIVER_GEN }, 4, "compile" },
    { "temporal/null-deref (analyzer)",
      { MYC_EXPERIMENT_POLLING_HARNESS, MYC_EXPERIMENT_REALLOC_PATH,
        MYC_EXPERIMENT_ASSERTION_HARNESS }, 5, "analyzer" },
    { "runtime memory (ASan/UBSan)",
      { MYC_EXPERIMENT_ALLOC_FAIL, MYC_EXPERIMENT_LEAK_CHECK,
        MYC_EXPERIMENT_SHORT_IO }, 5, "runtime" },
    { "spatial (checked buffers)",
      { MYC_EXPERIMENT_BOUNDARY_INPUT, MYC_EXPERIMENT_DRIVER_GEN,
        MYC_EXPERIMENT_ALLOC_FAIL }, 5, "checked" },
    { "proof obligation (RTE)",
      { MYC_EXPERIMENT_DRIVER_GEN, MYC_EXPERIMENT_ASSERTION_HARNESS,
        MYC_EXPERIMENT_BOUNDARY_INPUT }, 3, "prove" },
    { "boundary input (contract)",
      { MYC_EXPERIMENT_DRIVER_GEN, MYC_EXPERIMENT_BOUNDARY_INPUT,
        MYC_EXPERIMENT_SHORT_IO }, 2, "driver" },
    { "capability safety",
      { MYC_EXPERIMENT_ASSERTION_HARNESS, MYC_EXPERIMENT_POLLING_HARNESS,
        MYC_EXPERIMENT_ALLOC_FAIL }, 4, "filc" }
};

/* Default cost/severity per eksperimen (dipakai bila tidak ada observasi
 * aktual). Sama dengan angka di nextbest.c/observation.c. */
static int exp_cost(myc_experiment_type t)
{
    return myc_experiment_cost_ms(t);
}

static int exp_severity(myc_experiment_type t)
{
    return myc_experiment_severity(t);
}

/* Proksi biaya token (dimensi independen di DS-14). Tabel deterministik. */
static int exp_token(myc_experiment_type t)
{
    switch (t) {
    case MYC_EXPERIMENT_ALLOC_FAIL:       return 500;
    case MYC_EXPERIMENT_BOUNDARY_INPUT:   return 300;
    case MYC_EXPERIMENT_SHORT_IO:         return 200;
    case MYC_EXPERIMENT_CROSS_TARGET:     return 400;
    case MYC_EXPERIMENT_POLLING_HARNESS:  return 300;
    case MYC_EXPERIMENT_REALLOC_PATH:     return 300;
    case MYC_EXPERIMENT_LEAK_CHECK:       return 500;
    case MYC_EXPERIMENT_DRIVER_GEN:       return 600;
    case MYC_EXPERIMENT_ASSERTION_HARNESS:return 400;
    default:                              return 400;
    }
}

/* Prior P(new_evidence) per-mille (tabel deterministik, "seeded"). */
static int exp_prior(myc_experiment_type t)
{
    switch (t) {
    case MYC_EXPERIMENT_ALLOC_FAIL:       return 600;
    case MYC_EXPERIMENT_BOUNDARY_INPUT:   return 700;
    case MYC_EXPERIMENT_SHORT_IO:         return 450;
    case MYC_EXPERIMENT_CROSS_TARGET:     return 400;
    case MYC_EXPERIMENT_POLLING_HARNESS:  return 500;
    case MYC_EXPERIMENT_REALLOC_PATH:     return 550;
    case MYC_EXPERIMENT_LEAK_CHECK:       return 450;
    case MYC_EXPERIMENT_DRIVER_GEN:       return 650;
    case MYC_EXPERIMENT_ASSERTION_HARNESS:return 350;
    default:                              return 500;
    }
}

/* Ekspor tabel biaya default (DS-14) untuk modul lain. */
int myc_eig_gate_cost_ms(myc_experiment_type t)
{
    return exp_cost(t);
}

int myc_eig_hazard_cost_ms(const char *hazard)
{
    size_t i;
    for (i = 0; i < sizeof(EIG_RULES) / sizeof(EIG_RULES[0]); i++)
        if (strcmp(EIG_RULES[i].hazard, hazard) == 0)
            return exp_cost(EIG_RULES[i].candidates[0]);
    return 0;
}

/* Slug deterministik hazard -> rule id kalibrasi: "eig-" + hazard dengan
 * karakter non-alnum -> '-', huruf kecil, '-' beruntun dipadatkan.
 * Contoh: "runtime memory (ASan/UBSan)" -> "eig-runtime-memory-asan-ubsan".
 * Selalu dalam charset [A-Za-z0-9._-] (myc_calib_id_valid). */
static void eig_rule_id(const char *hazard, char *out, size_t cap)
{
    const char *p;
    size_t o = 0;
    int last_dash = 0;

    if (!out || cap < 8)
        return;
    memcpy(out, "eig-", 4);
    o = 4;
    last_dash = 1;
    for (p = hazard; *p && o + 1 < cap; p++) {
        unsigned char c = (unsigned char)*p;
        if (isalnum(c)) {
            out[o++] = (char)tolower(c);
            last_dash = 0;
        } else if (!last_dash) {
            out[o++] = '-';
            last_dash = 1;
        }
    }
    while (o > 3 && out[o - 1] == '-')
        o--;
    out[o] = '\0';
}

/* ---------- kalibrasi dari ledger SOL-21 ---------- */

/* Prior tabel dikalibrasi dari Trust Calibration Ledger (rule `eig-<slug>`).
 * accepted/confirmed_later = bukti eksperimen jenis ini menemukan bug nyata
 * (prior naik); rejected/harmful_fix = false positive (prior turun). missed
 * sengaja NETRAL (ketiadaan bukti). Langkah 60 per-mille, clamp [100..950].
 * *calibrated = 1 bila rule punya >= 1 feedback. Deterministik. */
static int eig_calibrate_prior(const char *hazard, int base, int *calibrated)
{
    char rule[MYC_CALIB_ID_MAX + 1];
    long long counts[MYC_CALIB_OUTCOME_COUNT];
    long long total = 0, net;
    int found = 0;
    int i;

    if (calibrated)
        *calibrated = 0;
    eig_rule_id(hazard, rule, sizeof(rule));
    if (myc_calib_read_counts(rule, counts, &found) != 0 || !found)
        return base;
    for (i = 0; i < MYC_CALIB_OUTCOME_COUNT; i++)
        total += counts[i];
    if (total <= 0)
        return base;
    net = counts[MYC_CALIB_ACCEPTED] + counts[MYC_CALIB_CONFIRMED_LATER]
        - counts[MYC_CALIB_REJECTED] - counts[MYC_CALIB_HARMFUL_FIX];
    if (calibrated)
        *calibrated = 1;
    if (net != 0) {
        long long p = (long long)base + net * 60;
        if (p < 100) p = 100;
        if (p > 950) p = 950;
        return (int)p;
    }
    return base;
}

/* ---------- profil SOL-20 (opt-in) ---------- */

typedef struct {
    int  ok;                  /* 1 = profil terbaca */
    long long checks;
    int  nclasses;
    char names[32][48];
    long long counts[32];
} eig_profile;

/* Baca .myc/profiles/<id>.json (schema myc.profile.v1, field `checks` +
 * `classes[].name/count`). NON-blocking: gagal baca = ok=0. */
static void eig_profile_load(const char *id, eig_profile *pf)
{
    char path[160];
    FILE *f;
    long fsize;
    char *buf;
    json_value *root, *v;
    int i;

    memset(pf, 0, sizeof(*pf));
    if (!id || !*id)
        return;
    snprintf(path, sizeof(path), ".myc/profiles/%s.json", id);
    f = fopen(path, "rb");
    if (!f)
        return;
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > (long)(4u << 20)) {
        fclose(f);
        return;
    }
    buf = (char *)myc_malloc((size_t)fsize + 1);
    if (!buf) {
        fclose(f);
        return;
    }
    if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        myc_free(buf);
        fclose(f);
        return;
    }
    buf[fsize] = '\0';
    fclose(f);

    if (!json_parse_cstr(buf, &root) || !root) {
        myc_free(buf);
        return;
    }
    v = json_get(root, "checks");
    if (v && v->type == JSON_NUM)
        pf->checks = v->num;
    v = json_get(root, "classes");
    if (v && v->type == JSON_ARR) {
        for (i = 0; i < (int)v->len && pf->nclasses < 32; i++) {
            json_value *e = v->items[i];
            json_value *cn, *cc;
            if (!e || e->type != JSON_OBJ)
                continue;
            cn = json_get(e, "name");
            cc = json_get(e, "count");
            if (!cn || cn->type != JSON_STR || !cc || cc->type != JSON_NUM)
                continue;
            snprintf(pf->names[pf->nclasses],
                     sizeof(pf->names[0]), "%s", cn->str);
            pf->counts[pf->nclasses] = cc->num;
            pf->nclasses++;
        }
    }
    json_free(root);
    myc_free(buf);
    pf->ok = 1;
}

/* Prior disesuaikan profil: kelas "<gate>/findings|observations" ada dengan
 * count > 0 -> prior naik (+80); profil punya checks tapi gate itu tidak
 * pernah menghasilkan finding -> prior turun (-30). Clamp [100..950]. */
static int eig_profile_adjust(const eig_rule *rule, int prior,
                              const eig_profile *pf)
{
    int i;
    int found = 0;
    char prefix[64];

    if (!pf || !pf->ok)
        return prior;
    snprintf(prefix, sizeof(prefix), "%s/", rule->gate_prefix);
    for (i = 0; i < pf->nclasses; i++) {
        if (strncmp(pf->names[i], prefix, strlen(prefix)) == 0) {
            if (pf->counts[i] > 0)
                found = 1;
        }
    }
    if (found) {
        prior += 80;
    } else if (pf->checks > 0) {
        prior -= 30;
    }
    if (prior < 100) prior = 100;
    if (prior > 950) prior = 950;
    return prior;
}

/* ---------- observasi aktual ---------- */

static const myc_experiment *find_observation(const myc_experiment_set *exps,
                                              myc_experiment_type t)
{
    int i;
    if (!exps)
        return NULL;
    for (i = 0; i < exps->count; i++) {
        if (exps->experiments[i].type == t)
            return &exps->experiments[i];
    }
    return NULL;
}

/* ---------- skor + urutan ---------- */

/* expected_value = P(new_evidence) x severity x scope x 1e6 / (cost x token).
 * P per-mille (0..1000), aritmetika int64 deterministik (skala 1e6). */
static long long compute_ev(const myc_eig_item *it)
{
    long long num = (long long)it->p_new_evidence
                    * it->severity * it->scope * 1000000LL;
    long long den = (long long)it->cost_estimate_ms
                    * (it->token_cost > 0 ? it->token_cost : 1);
    return den > 0 ? num / den : 0;
}

/* Selection sort: expected_value desc; tie-break cost asc, type asc,
 * hazard asc (deterministik penuh). */
static void sort_by_ev(myc_eig_set *eig)
{
    int i;
    for (i = 0; i < eig->count - 1; i++) {
        int best = i;
        int j;
        for (j = i + 1; j < eig->count; j++) {
            const myc_eig_item *a = &eig->items[j];
            const myc_eig_item *b = &eig->items[best];
            int better = 0;
            if (a->expected_value != b->expected_value)
                better = a->expected_value > b->expected_value;
            else if (a->cost_estimate_ms != b->cost_estimate_ms)
                better = a->cost_estimate_ms < b->cost_estimate_ms;
            else if (a->type != b->type)
                better = a->type < b->type;
            else
                better = strcmp(a->hazard ? a->hazard : "",
                                b->hazard ? b->hazard : "") < 0;
            if (better)
                best = j;
        }
        if (best != i) {
            myc_eig_item tmp = eig->items[i];
            eig->items[i] = eig->items[best];
            eig->items[best] = tmp;
        }
    }
    for (i = 0; i < eig->count; i++)
        eig->items[i].rank = i;
}

/* ---------- laporan teks ---------- */

/* Clamp off setelah tiap append: snprintf berikutnya selalu menerima
 * size >= 1 sehingga tidak pernah menulis OOB (guard overflow latif). */
#define RP_ADD(...) do { \
        off += snprintf(buf + off, sizeof(buf) - (size_t)off, __VA_ARGS__); \
        if (off >= (int)sizeof(buf)) off = (int)sizeof(buf) - 1; \
    } while (0)

static void eig_build_report(myc_eig_set *eig)
{
    char buf[8192];
    int off = 0;
    int i;

    RP_ADD("eig scheduler (Fase 7, DS-14): expected-information-gain\n");
    RP_ADD("  frontier: %d item, %d eligible (untested/unknown/observed), "
           "%d blocked_by_violation\n",
           eig->frontier_items, eig->count, eig->blocked_by_violation);
    RP_ADD("  source_changed: %d budget_time_ms: %d profile: %s "
           "calibrated_rules: %d\n",
           eig->source_changed, eig->budget_time_ms,
           eig->profile_used ? eig->profile_id : "-",
           eig->calibrated_rules);
    RP_ADD("  rekomendasi: %d\n", eig->count);
    for (i = 0; i < eig->count; i++) {
        const myc_eig_item *it = &eig->items[i];
        RP_ADD("  rank %d: %s -> hazard \"%s\" (status=%s)\n",
               it->rank, myc_experiment_name(it->type),
               it->hazard ? it->hazard : "?",
               it->frontier_status ? it->frontier_status : "?");
        RP_ADD("    P(new-evidence)=%d/1000 calibrated=%d "
               "severity=%d scope=%d cost=%dms token=%d\n",
               it->p_new_evidence, it->calibrated, it->severity,
               it->scope, it->cost_estimate_ms, it->token_cost);
        RP_ADD("    expected-value=%lld within_budget=%d\n",
               it->expected_value, it->within_budget);
        RP_ADD("    command: %s\n", it->command ? it->command : "");
        RP_ADD("    rationale: %s\n", it->rationale ? it->rationale : "");
    }
    RP_ADD("  within_budget: %d/%d\n", eig->within_budget_count, eig->count);
    eig->report = myc_strdup(buf);
}

/* ---------- plan ---------- */

void myc_eig_plan(const myc_frontier_set *fs,
                  const myc_experiment_set *exps,
                  const myc_eig_input *in,
                  myc_eig_set *eig)
{
    int i;
    int rule_count;
    eig_profile prof;
    int profile_used = 0;

    if (!fs || !eig)
        return;
    memset(eig, 0, sizeof(*eig));

    eig->source_changed = (in && in->source_changed == 0) ? 0 : 1;
    eig->budget_time_ms = in ? in->budget_time_ms : 0;
    if (eig->budget_time_ms < 0)
        eig->budget_time_ms = 0;

    if (in && in->profile_id && myc_profile_id_valid(in->profile_id)) {
        eig_profile_load(in->profile_id, &prof);
        if (prof.ok) {
            profile_used = 1;
            snprintf(eig->profile_id, sizeof(eig->profile_id), "%s",
                     in->profile_id);
        }
    }

    rule_count = (int)(sizeof(EIG_RULES) / sizeof(EIG_RULES[0]));

    for (i = 0; i < fs->count; i++) {
        const myc_frontier_item *it = &fs->items[i];
        int eligible = 0;
        int r;

        if (strcmp(it->status, "untested") == 0 ||
            strcmp(it->status, "unknown") == 0 ||
            strcmp(it->status, "observed") == 0)
            eligible = 1;
        else if (strcmp(it->status, "violation") == 0)
            eig->blocked_by_violation = 1;

        if (!eligible)
            continue;

        for (r = 0; r < rule_count; r++) {
            const eig_rule *rule = &EIG_RULES[r];
            myc_experiment_type t;
            const myc_experiment *obs = NULL;
            myc_eig_item *item;
            int k;
            int base, calibrated;

            if (strcmp(rule->hazard, it->hazard) != 0)
                continue;

            /* 1) Observasi AKTUAL menang (eksperimen dari observation-to-
             * experiment yang type-nya kandidat hazard ini; didukung
             * observasi konkret di source). 2) Fallback: kandidat pertama
             * rule table (default cost/severity). Satu eksperimen per
             * hazard (bukan dedup global) agar tiap hazard punya skor
             * EIG sendiri. */
            for (k = 0; k < 3; k++) {
                const myc_experiment *cand =
                    find_observation(exps, rule->candidates[k]);
                if (cand) {
                    obs = cand;
                    t = cand->type;
                    break;
                }
            }
            if (!obs)
                t = rule->candidates[0];

            if (eig->count >= MYC_MAX_EIG)
                break;

            item = &eig->items[eig->count];
            item->type = t;
            item->hazard = it->hazard;
            item->frontier_status = it->status;
            item->scope = rule->scope;

            if (obs) {
                item->cost_estimate_ms = obs->cost_estimate_ms;
                item->severity = obs->severity;
                item->source_anchor = obs->source_anchor
                    ? myc_strdup(obs->source_anchor) : NULL;
            } else {
                item->cost_estimate_ms = exp_cost(t);
                item->severity = exp_severity(t);
                item->source_anchor = NULL;
            }
            item->token_cost = exp_token(t);

            base = exp_prior(t);
            if (profile_used)
                base = eig_profile_adjust(rule, base, &prof);
            item->p_new_evidence =
                eig_calibrate_prior(it->hazard, base, &calibrated);
            item->calibrated = calibrated;
            if (calibrated)
                eig->calibrated_rules++;
            if (eig->source_changed == 0)
                item->p_new_evidence /= 2;

            item->within_budget = (eig->budget_time_ms <= 0) ||
                                  (item->cost_estimate_ms <=
                                   eig->budget_time_ms);
            if (item->within_budget)
                eig->within_budget_count++;
            item->expected_value = compute_ev(item);

            item->command = myc_experiment_command(
                &(myc_experiment){ .type = t }, NULL);

            {
                char rb[256];
                snprintf(rb, sizeof(rb),
                         "frontier %s (%s): expected-value %lld = "
                         "P(new-evidence) %d/1000 x severity %d x scope %d / "
                         "(cost %dms x token %d)%s%s",
                         it->hazard, it->status, item->expected_value,
                         item->p_new_evidence, item->severity, item->scope,
                         item->cost_estimate_ms, item->token_cost,
                         item->calibrated ? " [dikalibrasi ledger SOL-21]" : "",
                         profile_used ? " [profil SOL-20]" : "");
                item->rationale = myc_strdup(rb);
            }
            eig->count++;
            break;
        }
    }

    eig->profile_used = profile_used;
    sort_by_ev(eig);
    eig->frontier_items = fs->count;
    eig_build_report(eig);
}

/* ---------- JSON ---------- */

char *myc_eig_json(const myc_eig_set *eig)
{
    json_value *root;
    json_value *arr;
    char *out;
    int i, ok;

    if (!eig)
        return NULL;

    root = json_new_obj();
    if (!root)
        return NULL;

    arr = json_new_arr();
    if (!arr) {
        json_free(root);
        return NULL;
    }

    for (i = 0; i < eig->count; i++) {
        const myc_eig_item *it = &eig->items[i];
        json_value *obj = json_new_obj();
        if (!obj)
            continue;
        json_obj_set(obj, "rank", json_new_num((int64_t)it->rank));
        json_obj_set(obj, "type", json_new_str(myc_experiment_name(it->type)));
        json_obj_set(obj, "hazard", json_new_str(it->hazard));
        json_obj_set(obj, "frontier_status",
                     json_new_str(it->frontier_status));
        json_obj_set(obj, "command",
                     json_new_str(it->command ? it->command : ""));
        if (it->source_anchor)
            json_obj_set(obj, "source_anchor",
                         json_new_str(it->source_anchor));
        json_obj_set(obj, "cost_estimate_ms",
                     json_new_num((int64_t)it->cost_estimate_ms));
        json_obj_set(obj, "severity", json_new_num((int64_t)it->severity));
        json_obj_set(obj, "scope", json_new_num((int64_t)it->scope));
        json_obj_set(obj, "p_new_evidence",
                     json_new_num((int64_t)it->p_new_evidence));
        json_obj_set(obj, "token_cost",
                     json_new_num((int64_t)it->token_cost));
        json_obj_set(obj, "expected_value",
                     json_new_num(it->expected_value));
        json_obj_set(obj, "within_budget",
                     json_new_bool(it->within_budget ? 1 : 0));
        json_obj_set(obj, "calibrated",
                     json_new_bool(it->calibrated ? 1 : 0));
        json_obj_set(obj, "rationale",
                     json_new_str(it->rationale ? it->rationale : ""));
        json_arr_push(arr, obj);
    }
    json_obj_set(root, "recommendations", arr);
    json_obj_set(root, "count", json_new_num((int64_t)eig->count));
    json_obj_set(root, "frontier_items",
                 json_new_num((int64_t)eig->frontier_items));
    json_obj_set(root, "blocked_by_violation",
                 json_new_bool(eig->blocked_by_violation ? 1 : 0));
    json_obj_set(root, "source_changed",
                 json_new_bool(eig->source_changed ? 1 : 0));
    json_obj_set(root, "budget_time_ms",
                 json_new_num((int64_t)eig->budget_time_ms));
    json_obj_set(root, "profile_used",
                 json_new_bool(eig->profile_used ? 1 : 0));
    if (eig->profile_used)
        json_obj_set(root, "profile_id", json_new_str(eig->profile_id));
    json_obj_set(root, "calibrated_rules",
                 json_new_num((int64_t)eig->calibrated_rules));
    json_obj_set(root, "within_budget_count",
                 json_new_num((int64_t)eig->within_budget_count));

    ok = json_serialize(root, &out);
    json_free(root);
    if (!ok)
        out = NULL;
    return out;
}

void myc_eig_free(myc_eig_set *eig)
{
    int i;
    if (!eig)
        return;
    for (i = 0; i < eig->count; i++) {
        myc_free(eig->items[i].source_anchor);
        myc_free(eig->items[i].rationale);
        myc_free(eig->items[i].command);
    }
    myc_free(eig->report);
    memset(eig, 0, sizeof(*eig));
}

static int eig_try_set_flags(myc_request *req, myc_experiment_type t)
{
    switch (t) {
    case MYC_EXPERIMENT_ALLOC_FAIL:
    case MYC_EXPERIMENT_BOUNDARY_INPUT:
    case MYC_EXPERIMENT_SHORT_IO:
    case MYC_EXPERIMENT_DRIVER_GEN:
        if (req->driver)
            return 0;
        req->driver = 1;
        return 1;
    case MYC_EXPERIMENT_CROSS_TARGET:
        if (req->strict)
            return 0;
        req->strict = 1;
        return 1;
    case MYC_EXPERIMENT_POLLING_HARNESS:
        if (req->metamorphic)
            return 0;
        req->metamorphic = 1;
        return 1;
    case MYC_EXPERIMENT_REALLOC_PATH:
        if (req->checked && req->driver)
            return 0;
        req->checked = 1;
        req->driver = 1;
        return 1;
    case MYC_EXPERIMENT_LEAK_CHECK:
    case MYC_EXPERIMENT_ASSERTION_HARNESS:
        if (req->run)
            return 0;
        req->run = 1;
        return 1;
    default:
        return 0;
    }
}

int myc_eig_apply_one(myc_request *req, const myc_result *res)
{
    myc_frontier_set fs;
    myc_experiment_set exps;
    myc_eig_set eig;
    myc_eig_input in;
    int i, applied = 0;

    if (!req || !res || res->verdict != MC_OK)
        return 0;

    memset(&fs, 0, sizeof(fs));
    memset(&exps, 0, sizeof(exps));
    memset(&eig, 0, sizeof(eig));
    memset(&in, 0, sizeof(in));
    myc_frontier_build(res, &fs);
    myc_observation_to_experiment(res, &exps);
    in.source_changed = 1;
    in.budget_time_ms = req->eig_budget_ms > 0 ? req->eig_budget_ms : 5000;
    myc_eig_plan(&fs, &exps, &in, &eig);
    for (i = 0; i < eig.count; i++) {
        if (!eig.items[i].within_budget)
            continue;
        if (eig_try_set_flags(req, eig.items[i].type)) {
            applied = 1;
            break;
        }
    }
    myc_eig_free(&eig);
    myc_experiment_free(&exps);
    myc_frontier_free(&fs);
    return applied;
}
