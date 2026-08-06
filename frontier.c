/*
 * frontier.c -- Verification Frontier Map (Fase 3, SOL-02).
 */
#include "frontier.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "gate.h"

/* Satu baris konfigurasi: hazard class yang bisa dibuktikan oleh satu
 * dimensi assurance + gate sumber + backend + flag untuk next action. */
typedef struct {
    myc_assurance_dim dim;
    myc_gate_id       gate;
    const char       *hazard;
    const char       *backend;
    const char       *next_flag;
} frontier_row;

static const frontier_row FRONTIER_ROWS[] = {
    { MYC_DIM_COMPILE, MYC_GATE_COMPILE,
      "integer/bounds (static)", "gcc", "" },
    { MYC_DIM_STATIC,  MYC_GATE_ANALYZER,
      "temporal/null-deref (analyzer)", "gcc -fanalyzer", "--analyze" },
    { MYC_DIM_RUNTIME, MYC_GATE_RUNTIME,
      "runtime memory (ASan/UBSan)", "clang-asan", "--run" },
    { MYC_DIM_CHECKED, MYC_GATE_CHECKED,
      "spatial (checked buffers)", "myc_buf.h", "--checked" },
    { MYC_DIM_PROOF,   MYC_GATE_PROVE,
      "proof obligation (RTE)", "frama-c eva", "--prove" },
    { MYC_DIM_DRIVER,  MYC_GATE_DRIVER,
      "boundary input (contract)", "clang harness", "--driver" },
    { MYC_DIM_FILC,    MYC_GATE_FILC,
      "capability safety", "fil-c", "--filc" }
};

/* Status frontier dari gate status. Murni derivasi, tidak mengubah verdict. */
static const char *frontier_status(myc_gate_status st)
{
    switch (st) {
    case MYC_GATE_COMPLETED_CLEAN:        return "tested";
    case MYC_GATE_COMPLETED_FINDINGS:     return "violation";
    case MYC_GATE_COMPLETED_OBSERVATIONS: return "observed";
    case MYC_GATE_INCONCLUSIVE:           return "unknown";
    case MYC_GATE_UNAVAILABLE:            return "unknown";
    case MYC_GATE_INFRA_FAILED:           return "unknown";
    case MYC_GATE_NOT_APPLICABLE:         return "untested";
    case MYC_GATE_NOT_REQUESTED:          return "untested";
    default:                              return "unknown";
    }
}

/* Alasan frontier berhenti — apa yang belum dibuktikan. Statis per status. */
static const char *frontier_reason(myc_gate_status st)
{
    switch (st) {
    case MYC_GATE_COMPLETED_CLEAN:        return "clean: tidak ada finding di scope ini";
    case MYC_GATE_COMPLETED_FINDINGS:     return "violation terkonfirmasi (lihat witness)";
    case MYC_GATE_COMPLETED_OBSERVATIONS: return "hanya observasi heuristik, belum bukti semantik";
    case MYC_GATE_INCONCLUSIVE:           return "gate selesai tapi hasil tidak lengkap";
    case MYC_GATE_UNAVAILABLE:            return "backend tidak tersedia di mesin ini";
    case MYC_GATE_INFRA_FAILED:           return "backend gagal infra/exec";
    case MYC_GATE_NOT_APPLICABLE:         return "tidak berlaku untuk source ini";
    case MYC_GATE_NOT_REQUESTED:          return "gate belum diminta";
    default:                              return "status tidak diketahui";
    }
}

/* Next action: eksperimen termurah untuk maju dari posisi ini. */
static void frontier_next_action(const frontier_row *row,
                                 myc_gate_status st,
                                 char **out)
{
    char buf[256];
    const char *flag = row->next_flag;

    switch (st) {
    case MYC_GATE_COMPLETED_CLEAN:
        if (flag[0])
            snprintf(buf, sizeof(buf),
                     "pertahankan (jalankan ulang %s)", flag);
        else
            snprintf(buf, sizeof(buf), "pertahankan (jalankan ulang check)");
        break;
    case MYC_GATE_COMPLETED_FINDINGS:
        if (flag[0])
            snprintf(buf, sizeof(buf),
                     "replay witness + perbaiki; verifikasi ulang %s", flag);
        else
            snprintf(buf, sizeof(buf),
                     "replay witness + perbaiki; verifikasi ulang check");
        break;
    case MYC_GATE_COMPLETED_OBSERVATIONS:
        snprintf(buf, sizeof(buf),
                 "konfirmasi observasi via myc check <file>%s%s",
                 flag[0] ? " " : "", flag);
        break;
    case MYC_GATE_UNAVAILABLE:
    case MYC_GATE_INFRA_FAILED:
        snprintf(buf, sizeof(buf),
                 "instal/siapkan backend %s lalu jalankan %s",
                 row->backend, flag[0] ? flag : "check");
        break;
    case MYC_GATE_INCONCLUSIVE:
        snprintf(buf, sizeof(buf),
                 "periksa kelengkapan backend %s; jalankan ulang %s",
                 row->backend, flag[0] ? flag : "check");
        break;
    case MYC_GATE_NOT_APPLICABLE:
    case MYC_GATE_NOT_REQUESTED:
        if (flag[0]) {
            snprintf(buf, sizeof(buf),
                     "jalankan myc check <file> %s untuk membuktikan hazard %s",
                     flag, row->hazard);
        } else {
            snprintf(buf, sizeof(buf),
                     "jalankan myc check <file> (compile gate selalu aktif)");
        }
        break;
    default:
        snprintf(buf, sizeof(buf), "periksa ulang %s", flag[0] ? flag : "check");
        break;
    }
    *out = myc_strdup(buf);
}

void myc_frontier_build(const myc_result *res, myc_frontier_set *fs)
{
    size_t i;

    if (!res || !fs)
        return;
    memset(fs, 0, sizeof(*fs));

    for (i = 0;
         i < sizeof(FRONTIER_ROWS) / sizeof(FRONTIER_ROWS[0]) &&
         fs->count < MYC_MAX_FRONTIER_ITEMS;
         i++) {
        const frontier_row *row = &FRONTIER_ROWS[i];
        const myc_gate_result *g = myc_gate_get(res, row->gate);
        myc_gate_status st = g ? g->status : MYC_GATE_NOT_REQUESTED;
        myc_frontier_item *it = &fs->items[fs->count];

        it->hazard = row->hazard;
        it->backend = row->backend;
        it->status = frontier_status(st);
        it->reason = myc_strdup(frontier_reason(st));
        it->next_action = NULL;
        if (it->reason)
            frontier_next_action(row, st, &it->next_action);
        fs->count++;
    }
}

char *myc_frontier_json(const myc_frontier_set *fs)
{
    json_value *root;
    json_value *arr;
    char *out;
    int i, ok;

    if (!fs)
        return NULL;

    root = json_new_obj();
    if (!root)
        return NULL;

    arr = json_new_arr();
    if (!arr) { json_free(root); return NULL; }

    for (i = 0; i < fs->count; i++) {
        const myc_frontier_item *it = &fs->items[i];
        json_value *obj = json_new_obj();
        if (!obj) continue;
        json_obj_set(obj, "hazard", json_new_str(it->hazard));
        json_obj_set(obj, "status", json_new_str(it->status));
        json_obj_set(obj, "backend", json_new_str(it->backend));
        json_obj_set(obj, "reason", json_new_str(it->reason ? it->reason : ""));
        json_obj_set(obj, "next_action",
                     json_new_str(it->next_action ? it->next_action : ""));
        json_arr_push(arr, obj);
    }
    json_obj_set(root, "items", arr);
    json_obj_set(root, "count", json_new_num((int64_t)fs->count));

    ok = json_serialize(root, &out);
    json_free(root);
    if (!ok) out = NULL;
    return out;
}

void myc_frontier_free(myc_frontier_set *fs)
{
    int i;
    if (!fs)
        return;
    for (i = 0; i < fs->count; i++) {
        free(fs->items[i].reason);
        free(fs->items[i].next_action);
    }
    memset(fs, 0, sizeof(*fs));
}
