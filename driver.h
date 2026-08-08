/*
 * driver.h -- Gate driver-generator (D2.2, --driver).
 *
 * Dari source yang memuat fungsi ber-kontrak (//@ requires), gate ini:
 *   1. Parse signature fungsi ber-kontrak (nama + daftar parameter).
 *   2. Bangkitkan harness main() yang memanggil setiap fungsi dengan kasus
 *      uji tepi: 0, 1, 2, 3, batas dari requires (mis. "n <= 4" -> n=4 dan
 *      3), dan -1/SIZE_MAX -- pada buffer yang dialokasikan per kasus.
 *      Kasus yang melanggar requires dilewati (guard ekspresi requires),
 *      sehingga yang diuji hanya masukan di dalam domain kontrak.
 *   3. Build harness + source asli (main asli diganti nama via #define)
 *      dengan clang ASan+UBSan (-O0), lalu eksekusi terkendali.
 *
 * Semantik (jujur, heuristik):
 *   - Non-blocking: bila clang hilang, tidak ada fungsi ber-kontrak yang
 *     bisa di-generate, atau build harness gagal -> gate di-skip, assurance
 *     statis dipertahankan + diagnostic (pola sama dengan gate prove/run).
 *   - Laporan ASan/UBSan saat eksekusi = bug memori nyata pada kasus tepi
 *     di dalam domain kontrak -> verdict MC_DRIVER_VIOLATION.
 *   - Run bersih dengan >= 1 kasus tereksekusi -> caller menaikkan ke
 *     L3 RUNTIME (verifikasi runtime via sanitizer, sama dengan --run).
 *   - NULL tidak pernah diuji (pointer selalu dialokasikan) agar tidak
 *     menghasilkan false positive null-deref pada kode yang berasumsi
 *     caller menghormati kontrak non-NULL.
 */
#ifndef MYC_DRIVER_H
#define MYC_DRIVER_H

#include "myc.h"

/*
 * Jalankan gate driver-generator. Mengisi res->ran_driver, res->driver_funcs,
 * res->driver_cases, res->driver_skipped, dan output harness.
 * Kode kembalian: 0 = di-skip / violation / error, 1 = run bersih dengan
 * >= 1 kasus (caller menaikkan assurance ke L3). Saat violation,
 * res->verdict diset MC_DRIVER_VIOLATION oleh gate ini.
 */
int myc_driver_gate(const myc_request *req, const char *source, size_t source_len,
                    myc_result *res);

/* A3 (Small-Domain Exhaustive Proof, --exhaustive, DS-03): enumerasi PENUH
 * domain fungsi ber-kontrak yang terbatas (requires dengan rentang integer
 * lengkap, produk <= 1e6) = bukti riil untuk domain yang dideklarasikan.
 * Reuse mesin driver (scan_contract_funcs, parse_bound, build/run ASan).
 * Return 1 = clean dengan >= 1 titik tereksekusi (P1 EXHAUSTIVE untuk
 * domain dinyatakan); violation -> verdict MC_DRIVER_VIOLATION. */
int myc_exhaustive_gate(const myc_request *req, const char *source,
                        size_t source_len, myc_result *res);

#endif /* MYC_DRIVER_H */
