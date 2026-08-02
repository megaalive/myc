/*
 * prove.h -- Gate Frama-C Eva (D3.1, P7): --prove -> L2 EVA.
 *
 * Menjalankan Frama-C Eva (`-eva`) pada source melalui WSL (jalur resmi
 * Frama-C di Windows) dan mem-parsing summary analisis. Prinsip:
 *   - Non-blocking: bila wsl.exe / frama-c tidak tersedia, gate di-skip,
 *     assurance statis dipertahankan + diagnostic (pola sama dengan clang P6).
 *   - Eva sound untuk kelas RTE: alarm Eva = bug pasti (kelas RTE), sesuai
 *     rencana D3.1 -> verdict MC_PROVE_VIOLATION.
 *   - 0 alarm + analisis sungguhan (ANALYSIS SUMMARY) -> L2 EVA.
 *     MYC-AUDIT-013: L2 EVA = tidak ada alarm RTE di bawah model Eva
 *     (abstract interpretation, entry main default); BUKAN proof
 *     obligation WP, BUKAN "kontrak terbukti". Laporan menyertakan
 *     tool + versi + mode agar klaim punya konteks.
 * Source dikirim via stdin (tidak pernah menjadi argumen); perintah WSL
 * adalah template tetap (tanpa data source).
 */
#ifndef MYC_PROVE_H
#define MYC_PROVE_H

#include "myc.h"

/*
 * Jalankan gate prove. Mengisi res->ran_prove, res->prove_alarms, dan output.
 * Kode kembalian: 0 = di-skip / violation / error, 1 = analisis bersih
 * (caller menaikkan assurance ke L2). Saat violation, res->verdict diset
 * MC_PROVE_VIOLATION oleh gate ini.
 */
int myc_prove_gate(const myc_request *req, const char *source, size_t source_len,
                   myc_result *res);

#endif /* MYC_PROVE_H */
