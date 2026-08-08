/* testaudit.h -- Test-Quality Audit (Fase 6, Self-Challenge)
 *
 * Menjawab pertanyaan: "apakah corpus test benar-benar menutupi hazard
 * class yang menjadi tanggung jawab myc?" -- bukan hanya apakah pipeline
 * lolos. `myc audit-tests` memindai test/ dan tests/, mengklasifikasi
 * fixture (bad/ok, ber-kontrak, ber-main), lalu memetakan cakupan per
 * hazard class (spatial/temporal/integer/runtime/proof/boundary/
 * capability) dan per backend. Hazard class TANPA fixture = gap yang
 * terlihat (bukan kesunyian). NON-blocking observasi.
 *
 * Exit criteria Fase 6: "Mutation score dan gap dilaporkan" (mutate
 * gate) + audit kualitas test corpus di sini.
 */
#ifndef MYC_TESTAUDIT_H
#define MYC_TESTAUDIT_H

#include <stdio.h>

#define MYC_TA_MAX_HAZARDS 8
#define MYC_TA_MAX_BACKENDS 12

typedef struct {
    const char *name;          /* hazard class: spatial|temporal|integer|... */
    int         fixtures;      /* jumlah fixture bad yang menargetkan */
    int         covered;       /* 1 = ada >= 1 fixture */
    const char *example;       /* nama fixture pertama (contoh) */
} myc_ta_hazard;

typedef struct {
    const char *name;          /* backend: run|driver|exhaustive|fuzz|... */
    int         fixtures;      /* jumlah fixture yang relevan */
    int         covered;
    const char *example;
} myc_ta_backend;

/* Audit corpus test (test/ + tests/). Hasil statistik per hazard class
 * dan backend diisi di struktur; return 0 bila semua hazard class punya
 * fixture (no gap), -1 bila ada gap (masih NON-blocking -- ini laporan,
 * bukan verdict). */
int myc_testaudit_run(myc_ta_hazard *hazards, int *nhaz,
                      myc_ta_backend *backends, int *nback);

/* Cetak laporan audit ke out. Return sama dengan myc_testaudit_run. */
int myc_testaudit_report(FILE *out);

#endif /* MYC_TESTAUDIT_H */
