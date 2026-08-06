/*
 * frontier.h -- Verification Frontier Map (Fase 3, SOL-02, roadmap 7.8).
 *
 * unverified_debt menyebut gap, tetapi belum menunjukkan BATAS antara
 * wilayah yang diketahui dan tidak diketahui. Frontier membangun peta
 * per hazard class / dimensi bukti:
 *
 *   - status: proven / tested / observed / violation / unknown / untested
 *   - hazard class yang tercakup (spatial, temporal, integer, runtime,
 *     proof obligation, boundary input, capability safety)
 *   - backend yang memberikan bukti
 *   - alasan frontier berhenti (apa yang belum dibuktikan)
 *   - eksperimen termurah untuk maju (next action)
 *
 * Nilai: LLM dapat bekerja di batas pengetahuan, bukan mengulang
 * pemeriksaan yang sudah selesai. NON-blocking: frontier adalah DERIVASI
 * murni dari myc_result (gate status + debt), tidak menambah gate baru,
 * tidak mengubah verdict, tidak menambah debt.
 */
#ifndef MYC_FRONTIER_H
#define MYC_FRONTIER_H

#include "myc.h"

#define MYC_MAX_FRONTIER_ITEMS 16

typedef struct {
    const char *hazard;     /* "spatial", "temporal", "integer", dll (statis) */
    const char *status;     /* proven/tested/observed/violation/unknown/untested */
    const char *backend;    /* "gcc", "clang-asan", "checked", "eva", "driver", "fil-c" */
    char *reason;           /* alasan frontier berhenti (malloc'd) */
    char *next_action;      /* eksperimen termurah untuk maju (malloc'd) */
} myc_frontier_item;

typedef struct {
    myc_frontier_item items[MYC_MAX_FRONTIER_ITEMS];
    int count;
} myc_frontier_set;

/* Bangun peta frontier dari myc_result. Setiap item = satu hazard class
 * yang bisa dibuktikan oleh satu dimensi assurance (gate). Status murni
 * derivasi dari gate status + debt; TIDAK mengubah verdict. */
void myc_frontier_build(const myc_result *res, myc_frontier_set *fs);

/* Serialisasi frontier ke JSON (untuk agent output / debug).
 * Mengembalikan string malloc'd yang harus free() oleh caller. */
char *myc_frontier_json(const myc_frontier_set *fs);

/* Bebaskan frontier set (reason/next_action). */
void myc_frontier_free(myc_frontier_set *fs);

#endif /* MYC_FRONTIER_H */
