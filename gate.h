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

/* Tambah durasi wall-clock ke gate (P0). Tidak masuk receipt.
 * No-op bila gate belum ada. */
void myc_gate_add_ms(myc_result *res, myc_gate_id id,
                     unsigned long long ms);

/* Dapatkan gate result berdasarkan id (NULL bila tidak ada). */
const myc_gate_result *myc_gate_get(const myc_result *res, myc_gate_id id);

/* Reducer murni: hitung verdict + completeness dari gate results.
 * Dipanggil di akhir myc_pipeline(), setelah semua gate mengisi status. */
void myc_reduce_verdict(myc_result *res);
myc_claim_status myc_validate_claim(const myc_result *res);

/* PR-014 (MYC-AUDIT-046): kanonikal receipt STRING -- byte-string yang
 * di-hash untuk receipt_sha256 (myc_build_receipt di gate.c), dibuat
 * OBSERVABLE agar format dibekukan oleh test vector
 * (docs/receipt-canonical.md, test/receipt_vectors.c, blok 17).
 * Deterministik: urutan gate/debt = urutan insert (bukan sorted).
 * Bila string penuh melebihi cap, output = cap-1 byte pertama + NUL
 * (truncation deterministik, IDENTIK dengan yang di-hash).
 * Return panjang string yang ditulis (0 bila res NULL / buf NULL /
 * cap == 0). */
size_t myc_receipt_canonical(const myc_result *res, char *buf, size_t cap);

/* Tambah event ke evidence ledger (append-only). */
void myc_result_add_evidence(myc_result *res,
                             myc_gate_id gate,
                             myc_evidence_type type,
                             const char *message);

/* Nama pendek gate (untuk laporan). */
const char *myc_gate_id_short(myc_gate_id id);
const char *myc_debt_type_name(myc_debt_type t);

#endif /* MYC_GATE_H */
