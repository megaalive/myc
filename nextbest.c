/*
 * nextbest.c -- Next-Best Experiment Rule Table (Fase 3, SOL-03).
 */
#include "nextbest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

/* ---------- rule table: hazard -> eksperimen cocok ---------- */

/* Kandidat eksperimen per hazard class, urut prioritas (paling efektif
 * dulu). Nama hazard harus sama persis dengan frontier.c FRONTIER_ROWS[]. */
typedef struct {
    const char *hazard;
    myc_experiment_type candidates[3];
} nextbest_rule;

static const nextbest_rule NEXTBEST_RULES[] = {
    { "integer/bounds (static)",
      { MYC_EXPERIMENT_BOUNDARY_INPUT, MYC_EXPERIMENT_CROSS_TARGET,
        MYC_EXPERIMENT_DRIVER_GEN } },
    { "temporal/null-deref (analyzer)",
      { MYC_EXPERIMENT_POLLING_HARNESS, MYC_EXPERIMENT_REALLOC_PATH,
        MYC_EXPERIMENT_ASSERTION_HARNESS } },
    { "runtime memory (ASan/UBSan)",
      { MYC_EXPERIMENT_ALLOC_FAIL, MYC_EXPERIMENT_LEAK_CHECK,
        MYC_EXPERIMENT_SHORT_IO } },
    { "spatial (checked buffers)",
      { MYC_EXPERIMENT_BOUNDARY_INPUT, MYC_EXPERIMENT_DRIVER_GEN,
        MYC_EXPERIMENT_ALLOC_FAIL } },
    { "proof obligation (RTE)",
      { MYC_EXPERIMENT_DRIVER_GEN, MYC_EXPERIMENT_ASSERTION_HARNESS,
        MYC_EXPERIMENT_BOUNDARY_INPUT } },
    { "boundary input (contract)",
      { MYC_EXPERIMENT_DRIVER_GEN, MYC_EXPERIMENT_BOUNDARY_INPUT,
        MYC_EXPERIMENT_SHORT_IO } },
    { "capability safety",
      { MYC_EXPERIMENT_ASSERTION_HARNESS, MYC_EXPERIMENT_POLLING_HARNESS,
        MYC_EXPERIMENT_ALLOC_FAIL } }
};

/* Default cost/severity per eksperimen (dipakai bila tidak ada observasi
 * aktual). Sama dengan angka di observation.c. */
static int exp_cost(myc_experiment_type t)
{
    switch (t) {
    case MYC_EXPERIMENT_ALLOC_FAIL:       return 5000;
    case MYC_EXPERIMENT_BOUNDARY_INPUT:   return 2500;
    case MYC_EXPERIMENT_SHORT_IO:         return 2000;
    case MYC_EXPERIMENT_CROSS_TARGET:     return 2000;
    case MYC_EXPERIMENT_POLLING_HARNESS:  return 1500;
    case MYC_EXPERIMENT_REALLOC_PATH:     return 1500;
    case MYC_EXPERIMENT_LEAK_CHECK:       return 4000;
    case MYC_EXPERIMENT_DRIVER_GEN:       return 4000;
    case MYC_EXPERIMENT_ASSERTION_HARNESS:return 3000;
    default:                              return 3000;
    }
}

static int exp_severity(myc_experiment_type t)
{
    switch (t) {
    case MYC_EXPERIMENT_ALLOC_FAIL:       return 3;
    case MYC_EXPERIMENT_BOUNDARY_INPUT:   return 3;
    case MYC_EXPERIMENT_SHORT_IO:         return 2;
    case MYC_EXPERIMENT_CROSS_TARGET:     return 2;
    case MYC_EXPERIMENT_POLLING_HARNESS:  return 2;
    case MYC_EXPERIMENT_REALLOC_PATH:     return 3;
    case MYC_EXPERIMENT_LEAK_CHECK:       return 2;
    case MYC_EXPERIMENT_DRIVER_GEN:       return 2;
    case MYC_EXPERIMENT_ASSERTION_HARNESS:return 1;
    default:                              return 1;
    }
}

/* Skor: severity*1000 - cost_ms. Makin tinggi makin direkomendasikan. */
static int exp_score(int severity, int cost_ms)
{
    return severity * 1000 - cost_ms;
}

/* ---------- pencocokan observasi aktual ---------- */

/* Cari eksperimen di set (dari observation-to-experiment) dengan type sama.
 * Return pointer, atau NULL. */
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

/* ---------- build + sort ---------- */

/* Selection sort: skor desc, tie-break cost asc, lalu type asc (stabil). */
static void sort_by_score(myc_nextbest_set *nb)
{
    int i, j;
    for (i = 0; i < nb->count - 1; i++) {
        int best = i;
        int best_score = exp_score(nb->items[i].severity,
                                   nb->items[i].cost_estimate_ms);
        int best_cost = nb->items[i].cost_estimate_ms;
        for (j = i + 1; j < nb->count; j++) {
            int sc = exp_score(nb->items[j].severity,
                               nb->items[j].cost_estimate_ms);
            int cost = nb->items[j].cost_estimate_ms;
            if (sc > best_score ||
                (sc == best_score && cost < best_cost) ||
                (sc == best_score && cost == best_cost &&
                 nb->items[j].type < nb->items[best].type)) {
                best = j;
                best_score = sc;
                best_cost = cost;
            }
        }
        if (best != i) {
            myc_nextbest_item tmp = nb->items[i];
            nb->items[i] = nb->items[best];
            nb->items[best] = tmp;
        }
    }
    for (i = 0; i < nb->count; i++)
        nb->items[i].rank = i;
}

void myc_nextbest_plan(const myc_frontier_set *fs,
                       const myc_experiment_set *exps,
                       myc_nextbest_set *nb)
{
    int i;
    int rule_count;

    if (!fs || !nb)
        return;
    memset(nb, 0, sizeof(*nb));

    rule_count = (int)(sizeof(NEXTBEST_RULES) / sizeof(NEXTBEST_RULES[0]));

    for (i = 0; i < fs->count; i++) {
        const myc_frontier_item *it = &fs->items[i];
        int eligible = 0;
        int r, k;

        /* Status yang memicu rekomendasi eksperimen. */
        if (strcmp(it->status, "untested") == 0 ||
            strcmp(it->status, "unknown") == 0 ||
            strcmp(it->status, "observed") == 0)
            eligible = 1;
        else if (strcmp(it->status, "violation") == 0)
            nb->blocked_by_violation = 1;

        if (!eligible)
            continue;

        for (r = 0; r < rule_count; r++) {
            const nextbest_rule *rule = &NEXTBEST_RULES[r];
            myc_experiment_type t;
            const myc_experiment *obs = NULL;
            myc_nextbest_item *item;
            int j;

            if (strcmp(rule->hazard, it->hazard) != 0)
                continue;

            /* 1) Observasi AKTUAL menang: eksperimen dari
             * observation-to-experiment yang type-nya termasuk kandidat
             * hazard ini lebih menjanjikan daripada default rule table
             * (didukung observasi konkret di source). SKIP type yang
             * sudah terpakai; bila semua observasi terpakai, fallback. */
            for (k = 0; k < 3; k++) {
                const myc_experiment *cand =
                    find_observation(exps, rule->candidates[k]);
                int dup = 0;
                if (!cand)
                    continue;
                for (j = 0; j < nb->count; j++) {
                    if (nb->items[j].type == cand->type) {
                        dup = 1;
                        break;
                    }
                }
                if (!dup) {
                    obs = cand;
                    t = cand->type;
                    break;
                }
            }

            /* 2) Fallback: kandidat rule table pertama yang belum
             * terpakai (default cost/severity). */
            if (!obs) {
                for (k = 0; k < 3; k++) {
                    int dup = 0;
                    for (j = 0; j < nb->count; j++) {
                        if (nb->items[j].type == rule->candidates[k]) {
                            dup = 1;
                            break;
                        }
                    }
                    if (!dup) {
                        t = rule->candidates[k];
                        break;
                    }
                }
                if (k >= 3)
                    break;   /* semua kandidat sudah terpakai */
            }

            if (nb->count >= MYC_MAX_NEXTBEST)
                break;

            item = &nb->items[nb->count];
            item->type = t;
            item->hazard = it->hazard;
            item->frontier_status = it->status;
            item->command = myc_experiment_command(
                &(myc_experiment){ .type = t }, NULL);

            if (obs) {
                /* Observasi aktual: pakai data nyata. */
                item->cost_estimate_ms = obs->cost_estimate_ms;
                item->severity = obs->severity;
                item->source_anchor =
                    obs->source_anchor ? myc_strdup(obs->source_anchor)
                                       : NULL;
            } else {
                item->cost_estimate_ms = exp_cost(t);
                item->severity = exp_severity(t);
                item->source_anchor = NULL;
            }

            {
                char buf[256];
                snprintf(buf, sizeof(buf),
                         "frontier %s (%s): %s%seksperimen %s (cost ~%dms, "
                         "severity %d) untuk membuktikan hazard ini",
                         it->hazard, it->status,
                         obs ? "didukung observasi nyata; " : "",
                         obs ? "konfirmasi " : "",
                         myc_experiment_name(t),
                         item->cost_estimate_ms, item->severity);
                item->rationale = myc_strdup(buf);
            }
            nb->count++;
            break;   /* satu eksperimen terbaik per hazard */
        }
    }

    sort_by_score(nb);
}

char *myc_nextbest_json(const myc_nextbest_set *nb)
{
    json_value *root;
    json_value *arr;
    char *out;
    int i, ok;

    if (!nb)
        return NULL;

    root = json_new_obj();
    if (!root)
        return NULL;

    arr = json_new_arr();
    if (!arr) { json_free(root); return NULL; }

    for (i = 0; i < nb->count; i++) {
        const myc_nextbest_item *it = &nb->items[i];
        json_value *obj = json_new_obj();
        if (!obj) continue;
        json_obj_set(obj, "rank", json_new_num((int64_t)it->rank));
        json_obj_set(obj, "type", json_new_str(myc_experiment_name(it->type)));
        json_obj_set(obj, "hazard", json_new_str(it->hazard));
        json_obj_set(obj, "frontier_status", json_new_str(it->frontier_status));
        json_obj_set(obj, "command", json_new_str(it->command ? it->command : ""));
        if (it->source_anchor)
            json_obj_set(obj, "source_anchor", json_new_str(it->source_anchor));
        json_obj_set(obj, "cost_estimate_ms",
                     json_new_num((int64_t)it->cost_estimate_ms));
        json_obj_set(obj, "severity", json_new_num((int64_t)it->severity));
        json_obj_set(obj, "rationale",
                     json_new_str(it->rationale ? it->rationale : ""));
        json_arr_push(arr, obj);
    }
    json_obj_set(root, "recommendations", arr);
    json_obj_set(root, "count", json_new_num((int64_t)nb->count));
    json_obj_set(root, "blocked_by_violation",
                 json_new_bool(nb->blocked_by_violation ? 1 : 0));

    ok = json_serialize(root, &out);
    json_free(root);
    if (!ok) out = NULL;
    return out;
}

void myc_nextbest_free(myc_nextbest_set *nb)
{
    int i;
    if (!nb)
        return;
    for (i = 0; i < nb->count; i++) {
        myc_free(nb->items[i].source_anchor);
        myc_free(nb->items[i].rationale);
        myc_free(nb->items[i].command);
    }
    memset(nb, 0, sizeof(*nb));
}
