/*
 * negative.h -- Negative-Space Analysis (gagasan pembeda 9.8, --negative).
 *
 * Structural mining "pola yang hilang" tanpa AI: keluarga pola pertama =
 * konvensi pemeriksaan hasil fungsi alokasi (malloc/calloc/realloc/strdup/
 * fopen, dst). Bila mayoritas callsite suatu fungsi memeriksa hasilnya
 * tetapi ada yang tidak -> "project convention deviation" dengan confidence.
 *
 * Sifat: HANYA observasi (diagnostic + confidence), TIDAK pernah hard
 * verdict -- konsisten dengan prinsip MYC-AUDIT-014 (heuristik teks tidak
 * boleh jadi verdict kecuali dikonfirmasi bukti semantik). Non-blocking:
 * tanpa callsite yang cocok -> 0 laporan, tidak ada klaim apa pun.
 */
#ifndef MYC_NEGATIVE_H
#define MYC_NEGATIVE_H

#include "myc.h"

/* Scan source mentah; isi res->negative_callsites / negative_deviations
 * dan tambahkan diagnostic untuk callsite yang tidak memeriksa hasil.
 * Thread-safe (reentrant): tidak memakai global state. */
void myc_negative_space(const char *source, size_t len, myc_result *res);

#endif /* MYC_NEGATIVE_H */
