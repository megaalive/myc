/*
 * budget.h -- Assurance Budget Contract (Fase 3, SOL-30).
 *
 * User/harness dapat meminta TARGET assurance eksplisit sebagai kontrak,
 * bukan sekadar memilih flag:
 *
 *   {
 *     "required": {
 *       "compile": "clean",
 *       "runtime": "clean",
 *       "driver": "clean",
 *       "proof":  "optional"
 *     },
 *     "max_time_ms": 10000,
 *     "max_output_bytes": 16384
 *   }
 *
 * Scheduler (myc_budget_enforce) WAJIB menjelaskan bila target tidak
 * dapat dicapai dalam budget dan menyebut dimensi yang dikorbankan.
 * TIDAK BOLEH diam-diam memilih recipe lebih lemah: gate yang diminta
 * "clean" tapi tidak dijalankan / tidak tersedia / menemukan finding ->
 * target TIDAK tercapai (verdict INCONCLUSIVE bila masih OK, debt
 * MYC-...-BUDGET-* , report rinci). NON-blocking secara default: kontrak
 * hanya aktif bila user menyediakannya (req.budget.active = 1).
 */
#ifndef MYC_BUDGET_H
#define MYC_BUDGET_H

#include "myc.h"

/* Tipe (myc_budget_level, myc_budget_contract) didefinisikan di myc.h
 * (myc_request memuat kontrak by-value; budget.h hanya berisi API agar
 * tidak ada include circular).
 *
 * Format kontrak JSON:
 *   { "required": { "compile": "clean", "runtime": "clean",
 *                   "driver": "clean", "proof": "optional" },
 *     "max_time_ms": 10000, "max_output_bytes": 16384 }
 */

/* Parse kontrak JSON ketat (reuse json.c). Mengisi `bc`; `raw`
 * di-strdup dari teks masukan. Mengembalikan 0 sukses, -1 gagal
 * (JSON invalid / key tidak dikenal / level tidak valid). Bila gagal,
 * `bc->active` tetap 0 dan `bc->raw` NULL. */
int myc_budget_parse(const char *json_text, size_t len,
                     myc_budget_contract *bc);

/* Bebaskan field yang dialokasikan parse (raw). */
void myc_budget_free(myc_budget_contract *bc);

/* Enforcement: panggil SETELAH pipeline + quorum (di myc_run). Bila
 * kontrak tidak aktif -> no-op. Mengisi res->budget_met, res->budget_report
 * (arena), menaikkan debt BUDGET_*, dan bila target tidak tercapai sementara
 * verdict masih MC_OK -> INCONCLUSIVE + completeness/finding diselaraskan +
 * receipt dibangun ulang (pola enforce_require_complete). TIDAK menurunkan
 * verdict findings (bug nyata tetap findings). */
void myc_budget_enforce(const myc_request *req, myc_result *res);

/* Nama level (statis): "unset"/"clean"/"optional". */
const char *myc_budget_level_name(myc_budget_level l);

#endif /* MYC_BUDGET_H */
