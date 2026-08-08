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
 * Pindai source C mentah untuk pola memory-safety berisiko (heuristik):
 *   - pointer diubah via intptr_t/uintptr_t (provenance tidak diverifikasi)
 *   - realloc hasil disimpan ke variabel berbeda yang masih memakai pointer lama
 *   - memcpy/memmove/memset dengan ukuran bukan dari sizeof (bounds tak terbukti)
 *   - ukuran alokasi yang bisa overflow integer (malloc(a*b) tanpa sizeof)
 *   - akses langsung b[i] pada variabel MYC_BUF (checked gate = hard)
 *
 * Bila `embedded` != 0 (mode freestanding, Fase 5 C3/DS-11), ditambah
 * keluarga heuristik bare-metal (NON-blocking, confidence-scored):
 *   - MMIO deref alamat absolut tanpa volatile (hang setelah optimisasi)
 *   - polling loop `while (...);` tanpa volatile
 *   - struct __attribute__((packed)) dengan field multi-byte (alignment ARM)
 *   - cast uint8_t* -> tipe multi-byte (misaligned access)
 *   - variabel bersama ISR tanpa volatile/atomic (data race)
 *
 * MYC-AUDIT-014: TIDAK pernah hard verdict -- hasil HANYA observasi
 * (diagnostic ber-confidence) dan NON-blocking. Mengembalikan jumlah
 * observasi (0 = bersih). Hard violation ditangani gate SEMANTIK:
 * gcc -Wuse-after-free / -fanalyzer, sanitizer runtime, checked build,
 * Frama-C Eva, Fil-C. Lihat komentar header.
 */
int myc_lint_source(const char *source, size_t len, int embedded,
                    myc_result *res);

/* WHY+FIX (Item 4): alasan dan saran perbaikan untuk observasi lint.
 * Mengembalikan string malloc'd atau NULL jika tidak dikenali. Caller free(). */
const char *myc_lint_why(const char *message);
const char *myc_lint_fix(const char *message);

#endif /* MYC_LINT_H */
