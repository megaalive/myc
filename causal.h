/*
 * causal.h -- Causal Finding Graph (Fase 3, SOL-09).
 *
 * Satu kesalahan ukuran dapat menghasilkan puluhan warning sekunder.
 * Graph menghubungkan finding yang BERKAITAN agar model memperbaiki
 * ROOT CAUSE dulu; dependent findings ditahan dan diverifikasi ulang
 * setelah root hilang.
 *
 * Implementasi awal = rule deterministik (TANPA solver):
 *   - symbol sama (identifier dalam kutip gcc: 'buf', 'p', ...);
 *   - lokasi sama (line sama);
 *   - witness overlap (keduanya pada violation_line witness).
 *
 * Output: cluster (union-find), root per cluster (confidence tertinggi,
 * tie-break line terkecil; note tidak pernah root), dan urutan perbaikan
 * (root clusters dulu, dependents ditahan).
 *
 * NON-blocking: graph adalah DERIVASI murni dari myc_result.diags[] --
 * tidak mengubah verdict, tidak menambah debt, tidak menambah gate.
 */
#ifndef MYC_CAUSAL_H
#define MYC_CAUSAL_H

#include "myc.h"

#define MYC_MAX_CAUSAL_NODES MYC_MAX_DIAGNOSTICS

/* Satu node = satu diagnostic yang di-cluster. */
typedef struct {
    int  diag_index;       /* index ke res->diags[] */
    int  line, col;
    myc_confidence confidence;
    int  is_note;          /* 1 bila message diawali "note:" (pre-state) */
    int  cluster_id;       /* hasil union-find (0..count-1) */
    int  is_root;          /* 1 bila root cluster-nya */
    char *symbols;         /* daftar simbol dipisah koma (malloc'd) */
} myc_causal_node;

typedef struct {
    myc_causal_node nodes[MYC_MAX_CAUSAL_NODES];
    int count;
    /* Urutan perbaikan: diag_index, root cause dulu. */
    int repair_order[MYC_MAX_CAUSAL_NODES];
    int repair_count;
} myc_causal_graph;

/* Bangun causal graph dari diagnostics. Node dengan confidence OBSERVATION
 * tetap diproses (bisa jadi dependent); note di-flag bukan root. */
void myc_causal_build(const myc_result *res, myc_causal_graph *g);

/* Serialisasi graph ke JSON (untuk agent output / debug):
 *   { "clusters": [ { "root": {diag...}, "dependents": [...] } ],
 *     "repair_order": [ diag_index... ] }
 * Mengembalikan string malloc'd yang harus free() oleh caller. */
char *myc_causal_json(const myc_causal_graph *g);

/* Cari ROOT pertama yang ber-confidence CONFIRMED (untuk primary_finding).
 * Mengembalikan index diag di res->diags[] atau -1 bila tidak ada. */
int myc_causal_first_confirmed_root(const myc_causal_graph *g);

/* Bebaskan graph (symbols). */
void myc_causal_free(myc_causal_graph *g);

#endif /* MYC_CAUSAL_H */
