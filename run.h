/*
 * run.h -- Gate verification run (P6): build + eksekusi terkendali.
 *
 * Menghasilkan assurance L3 (RUNTIME) bila verification build (clang dengan
 * ASan+UBSan, -O0) sukses dan eksekusi tidak memunculkan laporan sanitizer.
 * Prinsip tetap: source hanya via stdin, tidak ada shell string.
 */
#ifndef MYC_RUN_H
#define MYC_RUN_H

#include <stddef.h>

/* --- sel matriks cross-toolchain divergence (Fase 4, A2/DS-02) ---
 * Satu kombinasi {toolchain} x {-O0,-O2}. `available=0` bila compiler
 * tidak ditemukan (sel di-skip). `built=1` + `ran=1` = sel benar-benar
 * dieksekusi. `finding` = bukti sanitizer (report log_path non-spoofable
 * ATAU marker + exit!=0). stdout_sha256 = hash trace stdout penuh untuk
 * deteksi semantic divergence (deterministik; env LC_ALL=C).
 * Tipe di sini (bukan myc.h) karena hanya run/report/cache. */
#define MYC_DIVERGENCE_MAX_CELLS 8   /* 2 toolchains x 2 opt = 4; cadangan */

typedef struct {
    char         tool[16];        /* "gcc" / "clang" / "tcc" */
    char         tool_path[260];  /* path absolut hasil myc_find_executable
                                     (fixed array agar aman di-copy untuk
                                     cache replay) */
    int          opt_level;       /* 0 = -O0, 1 = -O2 */
    int          available;       /* 0 = compiler tidak ditemukan */
    int          san;             /* 1 = build+run DENGAN sanitizer
                                     (finding bisa jadi bukti); 0 = tanpa
                                     sanitizer (fallback: toolchain tak
                                     punya ASan, mis. gcc MinGW) */
    int          built;           /* 1 = build sukses */
    int          ran;             /* 1 = exe dijalankan */
    int          timed_out;       /* 1 = run timeout */
    int          exit_code;       /* exit code run */
    int          finding;         /* 1 = bukti sanitizer pada sel ini */
    char         marker[80];      /* marker sanitizer atau "" */
    char         stdout_sha256[65]; /* sha256 hex trace stdout ("" bila
                                       tak tersedia) */
    int          diag_warn;       /* 1 = build menghasilkan warning */
} myc_divergence_cell;

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

/*
 * Gate Cross-Toolchain Divergence (Fase 4, A2/DS-02, --divergence):
 * bangun + jalankan source SAMA dengan matriks {gcc, clang, [tcc]} x
 * {-O0,-O2}; tiap sel mencatat exit code, finding sanitizer (report
 * log_path non-spoofable / marker+exit!=0), sha256 trace stdout, dan
 * ada-tidaknya warning build. Klasifikasi DS-02:
 *   - sanitizer_divergence (>=1 sel finding, >=1 sel clean yang ran)
 *     -> HARD RUNTIME_VIOLATION (bug toolchain-sensitive);
 *   - all_findings (SEMUA sel yang ran menemukan) -> bug konsisten,
 *     HARD;
 *   - semantic_divergence (tanpa finding, stdout/exit beda antar sel)
 *     dan diagnostic_divergence (set warning beda) -> OBSERVASI,
 *     NON-blocking (tidak menurunkan verdict).
 * Non-blocking: toolchain hilang / build gagal / exec gagal = sel
 * di-skip, assurance statis dipertahankan.
 *
 * Kode kembalian: 0 = gate tidak tersedia/di-skip, 1 = selesai.
 */
int myc_divergence_gate(const myc_request *req, const char *source,
                        size_t source_len, myc_result *res);

#endif /* MYC_RUN_H */
