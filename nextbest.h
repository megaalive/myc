/*
 * nextbest.h -- Next-Best Experiment Rule Table (Fase 3, SOL-03, roadmap 7.10).
 *
 * Frontier memberi STATUS per hazard class; observation-to-experiment memberi
 * eksperimen dari observasi AKTUAL. Rule table menjawab: dari posisi frontier
 * saat ini, eksperimen APA yang paling murah/menjanjikan untuk maju?
 *
 * Deterministik (bukan "berpikir seperti LLM"):
 *   - untuk tiap hazard class berstatus untested/unknown/observed, cari
 *     kandidat eksperimen dari rule table (hazard -> eksperimen cocok);
 *   - bila observasi aktual (dari myc_experiment_set) sudah mengusulkan
 *     eksperimen yang sama, pakai cost/severity/anchor NYATA-nya (lebih
 *     menjanjikan, karena observasi konkret mendukung);
 *   - skor = severity*1000 - cost_ms; pilih skor tertinggi;
 *   - status violation TIDAK diusulkan eksperimen: fix root cause dulu
 *     (lihat causal graph), ditandai blocked_by_violation.
 *
 * NON-blocking: rekomendasi murni DERIVASI dari frontier + experiments;
 * tidak mengubah verdict, tidak menambah gate, tidak menambah debt.
 */
#ifndef MYC_NEXTBEST_H
#define MYC_NEXTBEST_H

#include "myc.h"
#include "frontier.h"
#include "observation.h"

#define MYC_MAX_NEXTBEST 8

typedef struct {
    myc_experiment_type type;       /* eksperimen yang direkomendasikan */
    const char *hazard;             /* hazard class target (statis) */
    const char *frontier_status;    /* status frontier saat ini (statis) */
    char *command;                  /* perintah myc (malloc'd) */
    char *source_anchor;            /* anchor observasi bila ada (malloc'd) */
    char *rationale;                /* alasan pilihan (malloc'd) */
    int  cost_estimate_ms;
    int  severity;
    int  rank;                      /* 0 = paling direkomendasikan */
} myc_nextbest_item;

typedef struct {
    myc_nextbest_item items[MYC_MAX_NEXTBEST];
    int count;
    int blocked_by_violation;       /* 1 bila ada hazard status violation */
} myc_nextbest_set;

/* Bangun rekomendasi next-best experiment dari frontier + experiments.
 * Murni derivasi; urutan deterministik (skor severity*1000 - cost). */
void myc_nextbest_plan(const myc_frontier_set *fs,
                       const myc_experiment_set *exps,
                       myc_nextbest_set *nb);

/* Serialisasi rekomendasi ke JSON (untuk agent output / debug).
 * Mengembalikan string malloc'd yang harus free() oleh caller. */
char *myc_nextbest_json(const myc_nextbest_set *nb);

/* Bebaskan next-best set (source_anchor/rationale). */
void myc_nextbest_free(myc_nextbest_set *nb);

#endif /* MYC_NEXTBEST_H */
