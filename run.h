/*
 * run.h -- Gate verification run (P6): build + eksekusi terkendali.
 *
 * Menghasilkan assurance L3 (RUNTIME) bila verification build (clang dengan
 * ASan+UBSan, -O0) sukses dan eksekusi tidak memunculkan laporan sanitizer.
 * Prinsip tetap: source hanya via stdin, tidak ada shell string.
 */
#ifndef MYC_RUN_H
#define MYC_RUN_H

#include "myc.h"

/*
 * Jalankan gate verification run pada source. Dipanggil setelah gate statis
 * (compile + analyzer) lolos. Mengisi res->ran_runtime dan, bila ditemukan
 * masalah runtime, verdict MC_RUNTIME_VIOLATION + err MYC_ERR_RUNTIME_VIOLATION.
 *
 * Kode kembalian: 0 = gate tidak tersedia/di-skip (bukan error), 1 = selesai.
 * Ketika gate di-skip (mis. clang tidak ditemukan), ditulis diagnostic warning
 * dan assurance tidak dinaikkan (tetap level statis).
 */
int myc_run_gate(const myc_request *req, const char *source, size_t source_len,
                 myc_result *res);

/*
 * Gate Metamorphic Verification (9.7, --metamorphic): bangun source sama
 * dengan clang ASan+UBSan di -O0 dan -O2, jalankan keduanya, bandingkan.
 * Bila hanya satu build yang melaporkan sanitizer -> inconsistent
 * (kemungkinan UB / toolchain-sensitive) -> RUNTIME_VIOLATION. Keduanya
 * bersih -> COMPLETED_CLEAN (L3). Non-blocking: clang hilang / build gagal
 * -> di-skip, assurance statis dipertahankan.
 *
 * Kode kembalian: 0 = gate tidak tersedia/di-skip, 1 = selesai.
 */
int myc_metamorphic_gate(const myc_request *req, const char *source,
                         size_t source_len, myc_result *res);

#endif /* MYC_RUN_H */
