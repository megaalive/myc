/*
 * observation.c -- Observation-to-Experiment Compiler (Fase 3, roadmap 7.9).
 */
#include "observation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

static const char *EXPERIMENT_NAMES[] = {
    "alloc_fail",
    "boundary_input",
    "short_io",
    "cross_target",
    "polling_harness",
    "realloc_path",
    "leak_check",
    "driver_gen",
    "assertion_harness",
    "unknown"
};

const char *myc_experiment_name(myc_experiment_type t)
{
    if (t >= 0 && t < MYC_EXPERIMENT_MAX)
        return EXPERIMENT_NAMES[t];
    return "unknown";
}

/* Deskripsi panjang per eksperimen. */
static const char *EXPERIMENT_DESCRIPTIONS[] = {
    "Unlikely code paths di allocator failure belum diuji. Inject failure "
    "pada N-th malloc/calloc/realloc untuk memaksa error path.",

    "Buffer/size arithmetic diduga rentan overflow. Synthesize input pada "
    "boundary value +1, -1, size-1, size.",

    "Read/write sistem pemakai short I/O. Compare behavior dengan input "
    "partial vs full.",

    "Signedness char dapat menyebabkan warning yang berbeda antar target. "
    "Compile dengan -fsigned-char vs -funsigned-char.",

    "Volatile/polling pattern sering break di antara -O0/-O2. Compare "
    "execution untuk deteksi UB toolchain-sensitive.",

    "realloc disimpan ke variabel lain (use-after-free potensial). "
    "Test realloc failure path: pastikan free(old) tidak dipanggil.",

    "Possible memory/resource leak. Loop N kali, ukur "
    "alloc/free balance + handle count.",

    "Kontrak requires/ensures dideklarasikan tapi tidak diuji. "
    "Generate driver cases dari kontrak.",

    "Diagnostic lint (mis. cast pointer, unchecked return) dapat jadi "
    "issue runtime. Generate assertion harness."
};

/* Bangun experiment set dari observasi yang ada di myc_result. */
void myc_observation_to_experiment(const myc_result *res,
                                   myc_experiment_set *exps)
{
    int i;
    if (!res || !exps)
        return;
    memset(exps, 0, sizeof(*exps));

    for (i = 0; i < res->diag_count && exps->count < MYC_MAX_EXPERIMENTS; i++) {
        const myc_diagnostic *d = &res->diags[i];
        const char *msg = d->message ? d->message : "";
        const char *fname = "source";
        char anchor[128];
        myc_experiment *exp;

        /* Hanya proses observasi heuristik (bukan confirmed). */
        if (d->confidence == MYC_CONF_CONFIRMED)
            continue;

        /* Nama file asli bila witness tahu (slice_file), fallback "source". */
        if (res->witness && res->witness->slice_file)
            fname = res->witness->slice_file;

        snprintf(anchor, sizeof(anchor), "%s:%d", fname, d->line);

        /* Cek pola observasi dan konversi ke eksperimen. */
        if (strstr(msg, "pointer") && strstr(msg, "integer")) {
            exp = &exps->experiments[exps->count++];
            exp->type = MYC_EXPERIMENT_CROSS_TARGET;
            exp->name = EXPERIMENT_NAMES[MYC_EXPERIMENT_CROSS_TARGET];
            exp->description = EXPERIMENT_DESCRIPTIONS[MYC_EXPERIMENT_CROSS_TARGET];
            exp->source_anchor = myc_strdup(anchor);
            exp->confidence = d->confidence;
            exp->cost_estimate_ms = 2000;
            exp->severity = 2;
            exp->command = myc_experiment_command(exp, NULL);
        }
        else if (strstr(msg, "realloc") || strstr(msg, "overflow")) {
            exp = &exps->experiments[exps->count++];
            exp->type = MYC_EXPERIMENT_REALLOC_PATH;
            exp->name = EXPERIMENT_NAMES[MYC_EXPERIMENT_REALLOC_PATH];
            exp->description = EXPERIMENT_DESCRIPTIONS[MYC_EXPERIMENT_REALLOC_PATH];
            exp->source_anchor = myc_strdup(anchor);
            exp->confidence = d->confidence;
            exp->cost_estimate_ms = 1500;
            exp->severity = 3;
            exp->command = myc_experiment_command(exp, NULL);
        }
        else if (strstr(msg, "akses") && strstr(msg, "langsung")) {
            exp = &exps->experiments[exps->count++];
            exp->type = MYC_EXPERIMENT_ASSERTION_HARNESS;
            exp->name = EXPERIMENT_NAMES[MYC_EXPERIMENT_ASSERTION_HARNESS];
            exp->description = EXPERIMENT_DESCRIPTIONS[MYC_EXPERIMENT_ASSERTION_HARNESS];
            exp->source_anchor = myc_strdup(anchor);
            exp->confidence = d->confidence;
            exp->cost_estimate_ms = 3000;
            exp->severity = 2;
            exp->command = myc_experiment_command(exp, NULL);
        }
        else if (strstr(msg, "allocation") || strstr(msg, "alloc")) {
            exp = &exps->experiments[exps->count++];
            exp->type = MYC_EXPERIMENT_ALLOC_FAIL;
            exp->name = EXPERIMENT_NAMES[MYC_EXPERIMENT_ALLOC_FAIL];
            exp->description = EXPERIMENT_DESCRIPTIONS[MYC_EXPERIMENT_ALLOC_FAIL];
            exp->source_anchor = myc_strdup(anchor);
            exp->confidence = d->confidence;
            exp->cost_estimate_ms = 5000;
            exp->severity = 3;
            exp->command = myc_experiment_command(exp, NULL);
        }
        else if (strstr(msg, "boundary") || strstr(msg, "size")) {
            exp = &exps->experiments[exps->count++];
            exp->type = MYC_EXPERIMENT_BOUNDARY_INPUT;
            exp->name = EXPERIMENT_NAMES[MYC_EXPERIMENT_BOUNDARY_INPUT];
            exp->description = EXPERIMENT_DESCRIPTIONS[MYC_EXPERIMENT_BOUNDARY_INPUT];
            exp->source_anchor = myc_strdup(anchor);
            exp->confidence = d->confidence;
            exp->cost_estimate_ms = 2500;
            exp->severity = 3;
            exp->command = myc_experiment_command(exp, NULL);
        }
        else {
            /* Default: assertion harness untuk observasi tak dikategorikan. */
            exp = &exps->experiments[exps->count++];
            exp->type = MYC_EXPERIMENT_ASSERTION_HARNESS;
            exp->name = EXPERIMENT_NAMES[MYC_EXPERIMENT_ASSERTION_HARNESS];
            exp->description = EXPERIMENT_DESCRIPTIONS[MYC_EXPERIMENT_ASSERTION_HARNESS];
            exp->source_anchor = myc_strdup(anchor);
            exp->confidence = d->confidence;
            exp->cost_estimate_ms = 3000;
            exp->severity = 1;
            exp->command = myc_experiment_command(exp, NULL);
        }
    }

    /* Negative-space observations → driver_gen / leak_check */
    if (res->negative_callsites > 0 &&
        res->negative_deviations > 0 &&
        exps->count < MYC_MAX_EXPERIMENTS) {
        myc_experiment *exp = &exps->experiments[exps->count++];
        exp->type = MYC_EXPERIMENT_DRIVER_GEN;
        exp->name = EXPERIMENT_NAMES[MYC_EXPERIMENT_DRIVER_GEN];
        exp->description = EXPERIMENT_DESCRIPTIONS[MYC_EXPERIMENT_DRIVER_GEN];
        exp->source_anchor = myc_strdup("negative-space");
        exp->confidence = MYC_CONF_LIKELY;
        exp->cost_estimate_ms = 4000;
        exp->severity = 2;
        exp->command = myc_experiment_command(exp, NULL);
    }
}

char *myc_experiment_command(const myc_experiment *exp,
                             const char *source_file)
{
    if (!exp)
        return NULL;
    (void)source_file;
    switch (exp->type) {
    case MYC_EXPERIMENT_ALLOC_FAIL:
        return myc_strdup("myc check <file> --driver --require-complete "
                          "(allocator failure injection via driver cases)");
    case MYC_EXPERIMENT_BOUNDARY_INPUT:
        return myc_strdup("myc check <file> --driver --run-stdin <boundary_input>");
    case MYC_EXPERIMENT_SHORT_IO:
        return myc_strdup("myc check <file> --driver --run-stdin <short_io>");
    case MYC_EXPERIMENT_CROSS_TARGET:
        return myc_strdup("myc check <file> --strict (compare char signedness)");
    case MYC_EXPERIMENT_POLLING_HARNESS:
        return myc_strdup("myc check <file> --metamorphic (O0 vs O2)");
    case MYC_EXPERIMENT_REALLOC_PATH:
        return myc_strdup("myc check <file> --checked --driver");
    case MYC_EXPERIMENT_LEAK_CHECK:
        return myc_strdup("myc check <file> --run (loop + resource balance)");
    case MYC_EXPERIMENT_DRIVER_GEN:
        return myc_strdup("myc check <file> --driver");
    case MYC_EXPERIMENT_ASSERTION_HARNESS:
        return myc_strdup("myc check <file> --run --strict");
    default:
        return myc_strdup("myc check <file>");
    }
}

char *myc_experiment_json(const myc_experiment_set *exps)
{
    json_value *root;
    json_value *arr;
    char *out;
    int i, ok;

    if (!exps)
        return NULL;

    root = json_new_obj();
    if (!root)
        return NULL;

    arr = json_new_arr();
    if (!arr) { json_free(root); return NULL; }

    for (i = 0; i < exps->count; i++) {
        const myc_experiment *e = &exps->experiments[i];
        json_value *obj = json_new_obj();
        if (!obj) continue;
        json_obj_set(obj, "type", json_new_str(e->name));
        json_obj_set(obj, "description", json_new_str(e->description ? e->description : ""));
        json_obj_set(obj, "command", json_new_str(e->command ? e->command : ""));
        json_obj_set(obj, "source_anchor", json_new_str(e->source_anchor ? e->source_anchor : ""));
        json_obj_set(obj, "confidence", json_new_num((int64_t)e->confidence));
        json_obj_set(obj, "cost_estimate_ms", json_new_num((int64_t)e->cost_estimate_ms));
        json_obj_set(obj, "severity", json_new_num((int64_t)e->severity));
        json_arr_push(arr, obj);
    }
    json_obj_set(root, "experiments", arr);
    json_obj_set(root, "count", json_new_num((int64_t)exps->count));

    ok = json_serialize(root, &out);
    json_free(root);
    if (!ok) { out = NULL; }
    return out;
}

void myc_experiment_free(myc_experiment_set *exps)
{
    int i;
    if (!exps)
        return;
    for (i = 0; i < exps->count; i++) {
        myc_experiment *e = &exps->experiments[i];
        free(e->source_anchor);
        free(e->command);
    }
    memset(exps, 0, sizeof(*exps));
}
