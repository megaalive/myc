/*
 * matrix.h -- C4: Toolchain Matrix bare metal (portability matrix).
 *
 * Perluasan A2 (divergence) ke MATRIKS TARGET: saat cross-compiler
 * (arm-none-eabi-gcc, riscv32/64-unknown-elf-gcc) tersedia, source yang
 * sama di-cross-compile dan dibandingkan dengan host:
 *   (a) macro target (__CHAR_UNSIGNED__, __SIZEOF_POINTER__, endianness)
 *       via `-dM -E` (reuse myc_assume_fetch_facts);
 *   (b) warning set compile -c;
 *   (c) delta asumsi portabilitas vs host -> "kode ini bertaruh X di
 *       x86, dan taruhan itu berubah di ARM".
 *
 * NON-blocking penuh (kejujuran P5): cross-compiler absen = sel di-skip +
 * catatan "target lain tidak diuji (host-only)". Verdict TIDAK pernah
 * turun karena matrix (hanya observasi portability).
 */
#ifndef MYC_MATRIX_H
#define MYC_MATRIX_H

#include <stddef.h>

/* Satu sel matriks target (Fase 5, C4): satu cross-compiler + fakta
 * target + hasil compile. String target/cc disalin by-value (fixed array)
 * agar aman disalin ke cache replay. `deltas` = jumlah fakta yang
 * berubah vs host (char signedness / ptr bits / endianness). */
#define MYC_MATRIX_MAX_CELLS 4

typedef struct {
    char  target[64];        /* "arm-none-eabi" (nama compiler) */
    char  cc[260];           /* path absolut compiler */
    int   available;         /* cross-compiler ditemukan */
    int   facts_ok;          /* macro dump -dM -E terbaca */
    int   built;             /* compile -c sukses */
    int   warnings;          /* jumlah warning compile */
    int   char_unsigned;     /* __CHAR_UNSIGNED__ di target */
    int   ptr_bits;          /* 8 * sizeof(void*) di target */
    int   little_endian;     /* endianness target */
    int   deltas;            /* fakta yang berubah vs host */
} myc_matrix_cell;

#include "myc.h"

/* Gate target matrix (dipanggil pipeline bila req->matrix). */
int myc_matrix_gate(const myc_request *req, const char *source,
                    size_t source_len, myc_result *res);

#endif /* MYC_MATRIX_H */
