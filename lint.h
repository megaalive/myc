/*
 * lint.h -- Lint memory-safety myc (heuristik, tingkat token).
 *
 * Catatan jujur (dari rencana, Bagian D / P5): tanpa AST/CFG, lint ini
 * HEURISTIK, bukan sound. Tujuannya early warning untuk pola berisiko
 * yang biasanya lolos gcc, bukan verdict penalti penuh.
 */
#ifndef MYC_LINT_H
#define MYC_LINT_H

#include <stddef.h>

#include "myc.h"

/*
 * Pindai source C mentah untuk pola memory-safety berisiko:
 *   - pointer diubah via intptr_t/uintptr_t (provenance tidak diverifikasi)
 *   - realloc hasil disimpan ke variabel berbeda yang masih memakai pointer lama
 *   - memcpy/memmove/memset dengan ukuran bukan dari sizeof (bounds tak terbukti)
 *   - ukuran alokasi yang bisa overflow integer (malloc(a*b) tanpa sizeof)
 *
 * Mengembalikan 1 bila aman, 0 bila ditemukan pelanggaran lint (res diisi
 * diagnostic). Catatan: ini lint heuristik -- lihat komentar header.
 */
int myc_lint_source(const char *source, size_t len, myc_result *res);

#endif /* MYC_LINT_H */
