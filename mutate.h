/*
 * mutate.h -- Gate Mutation-Audited Verification (B5, --mutate-audit,
 * DS-09).
 *
 * Verifier yang mengaudit dirinya sendiri: myc mem-mutasi kode model
 * dengan pola error LLM (off-by-one, guard lemah, komparasi dibalik,
 * dst), lalu MENJALANKAN ULANG portfolio gate yang diminta terhadap tiap
 * mutan. Mutan yang tetap "clean" pada semua gate => coverage gap:
 * "kelas bug X tidak terlihat oleh konfigurasi verifikasi Anda".
 *
 * Semantik (jujur):
 *   - NON-blocking observasi: coverage gap TIDAK menurunkan verdict
 *     program (trust rules #1). Ini adalah metrik kualitas *verifikasi*,
 *     bukan finding di kode.
 *   - Mutan yang "ekuivalen" (mutasi tak mengubah source, mis. kena
 *     komentar) di-skip. Budget `--mutate-max N` (default 8) membatasi
 *     total build (biaya = N x pipeline).
 */
#ifndef MYC_MUTATE_H
#define MYC_MUTATE_H

#include "myc.h"

/* Jalankan mutation audit. Untuk tiap mutan menjalankan pipeline penuh
 * (compile + run ASan) via myc_pipeline; verdict mutan mencatat
 * tertangkap/lolos. Mengisi res->ran_mutate, mutate_total/gap/caught,
 * mutate_report. Kode kembalian: 1 = selesai, 0 = di-skip. */
int myc_mutate_gate(const myc_request *req, const char *source,
                    size_t source_len, myc_result *res);

#endif /* MYC_MUTATE_H */
