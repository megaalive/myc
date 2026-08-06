/*
 * observation.h -- Observation-to-Experiment Compiler (Fase 3, roadmap 7.9).
 *
 * Mengubah observasi heuristik (lint, negative-space, cast pointer, dll)
 * menjadi eksperimen verifikasi konkret yang dapat dieksekusi:
 *
 *   - unchecked allocation → inject allocator failure (fail on N-th malloc)
 *   - suspected bounds → synthesize boundary input
 *   - ignored short I/O → force short read/write
 *   - signedness assumption → cross-target compile
 *   - missing volatile → compare O0/O2 polling harness
 *   - unchecked realloc → test realloc failure path
 *   - possible leak → loop operation N kali, ukur resource balance
 *
 * Setiap eksperimen memiliki:
 *   - type: eksperimen apa yang dilakukan
 *   - description: penjelasan singkat
 *   - command: perintah myc untuk menjalankan eksperimen
 *   - source_anchor: di mana observasi terjadi (file:line)
 *   - confidence: LIKELY / OBSERVATION (bukan CONFIRMED)
 *   - cost_estimate_ms: perkiraan biaya eksekusi
 *
 * Non-blocking: observasi tidak mengubah verdict; eksperimen opsional. */
#ifndef MYC_OBSERVATION_H
#define MYC_OBSERVATION_H

#include "myc.h"

#define MYC_MAX_EXPERIMENTS 16

typedef enum {
    MYC_EXPERIMENT_ALLOC_FAIL = 0,  /* inject allocator failure on N-th alloc */
    MYC_EXPERIMENT_BOUNDARY_INPUT,  /* synthesize input pada boundary value */
    MYC_EXPERIMENT_SHORT_IO,        /* force short read/write */
    MYC_EXPERIMENT_CROSS_TARGET,    /* compile untuk target dengan char berbeda */
    MYC_EXPERIMENT_POLLING_HARNESS, /* compare O0/O2 untuk volatile/polling */
    MYC_EXPERIMENT_REALLOC_PATH,    /* test realloc failure path */
    MYC_EXPERIMENT_LEAK_CHECK,      /* loop N kali, ukur resource balance */
    MYC_EXPERIMENT_DRIVER_GEN,      /* generate driver cases untuk kontrak */
    MYC_EXPERIMENT_ASSERTION_HARNESS, /* generate assertion harness */
    MYC_EXPERIMENT_MAX
} myc_experiment_type;

typedef struct {
    myc_experiment_type type;
    const char *name;
    const char *description;
    char *command;
    char *source_anchor;    /* "file.c:line" */
    myc_confidence confidence;
    int cost_estimate_ms;    /* perkiraan biaya */
    int severity;           /* 1-5 (5 = kritis) */
} myc_experiment;

typedef struct {
    myc_experiment experiments[MYC_MAX_EXPERIMENTS];
    int count;
} myc_experiment_set;

/* Bangun eksperimen dari observasi lint/negative-space yang ada di res.
 * Scan diagnostic list dan konversi setiap observasi ber-confidence tinggi
 * menjadi eksperimen yang dapat dieksekusi. */
void myc_observation_to_experiment(const myc_result *res,
                                   myc_experiment_set *exps);

/* Bangun perintah myc untuk menjalankan satu eksperimen.
 * Mengembalikan string malloc'd. */
char *myc_experiment_command(const myc_experiment *exp,
                             const char *source_file);

/* Nama string untuk experiment type. */
const char *myc_experiment_name(myc_experiment_type t);

/* Serialisasi eksperimen ke JSON (untuk agent output).
 * Mengembalikan string malloc'd. */
char *myc_experiment_json(const myc_experiment_set *exps);

/* Bebaskan experiment set. */
void myc_experiment_free(myc_experiment_set *exps);

#endif /* MYC_OBSERVATION_H */
