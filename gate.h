/*
 * gate.h -- API untuk typed gate status, evidence ledger, dan verdict reducer (Fase 3).
 *
 * Prinsip:
 *   - Setiap gate memiliki typed status (bukan boolean).
 *   - Evidence ledger append-only mencatat setiap event gate.
 *   - Verdict reducer adalah pure function dari gate results + evidence.
 *
 * Tipe (myc_gate_status, myc_gate_id, myc_gate_result, myc_evidence_event,
 * myc_evidence_type, myc_completeness) didefinisikan di myc.h.
 */
#ifndef MYC_GATE_H
#define MYC_GATE_H

#include "myc.h"

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

/* Set status gate; alokasikan/memperbarui gate result di res. */
void myc_gate_set_status(myc_result *res,
                         myc_gate_id id,
                         myc_gate_status status,
                         const char *output);

/* Dapatkan gate result berdasarkan id (NULL bila tidak ada). */
const myc_gate_result *myc_gate_get(const myc_result *res, myc_gate_id id);

/* Reducer murni: hitung verdict + completeness dari gate results.
 * Dipanggil di akhir myc_pipeline(), setelah semua gate mengisi status. */
void myc_reduce_verdict(myc_result *res);

/* Tambah event ke evidence ledger (append-only). */
void myc_result_add_evidence(myc_result *res,
                             myc_gate_id gate,
                             myc_evidence_type type,
                             const char *message);

/* Nama pendek gate (untuk laporan). */
const char *myc_gate_id_short(myc_gate_id id);
const char *myc_debt_type_name(myc_debt_type t);

#endif /* MYC_GATE_H */
