/*
 * filc.h -- Gate Fil-C (D4.1, P8): --filc -> L5 FULL (opsional backend).
 *
 * Fil-C (pizlonator/Fil-C) adalah implementasi memory-safe C/C++ berbasis
 * clang 20 (driver: filc-clang) yang menangkap SEMUA error memori sebagai
 * "Fil-C panics" (marker: "filc safety error" dll). Hanya Linux/X86_64.
 *
 * Prinsip (pola sama dengan prove/run):
 *   - Opsional & non-blocking: bila filc-clang tidak tersedia (PATH atau
 *     WSL), gate di-skip, assurance statis dipertahankan + diagnostic.
 *   - Bila tersedia: verification build (filc-clang) + eksekusi terkendali.
 *     Run bersih (exit 0, tanpa panic) -> caller naikkan ke L5 FILC.
 *   - Panic terkonfirmasi (parser struktural MYC-AUDIT-024: baris kanonik
 *     "[pid] filc panic:" + detail per-case) -> MC_FILC_VIOLATION.
 * Source hanya via stdin (tidak pernah jadi argumen).
 */
#ifndef MYC_FILC_H
#define MYC_FILC_H

#include <stddef.h>

/* Satu panic Fil-C terkonfirmasi (MYC-AUDIT-024, roadmap 7.7 per-case
 * scope). Lokasi berasal dari frame "semantic origin" report Fil-C:
 *   (module) /path/file.c:LINE:COL: func
 * String (message/file/function) disimpan di arena milik hasil. */
#define MYC_MAX_FILC_CASES 8

typedef struct {
    char *message;      /* pesan panic (mis. "cannot write pointer ...") */
    char *file;         /* file origin pertama (NULL bila tak terparse) */
    int   line, col;    /* lokasi origin (0 bila tak terparse) */
    char *function;     /* fungsi origin pertama (NULL bila tak terparse) */
} myc_filc_case;

#include "myc.h"

/*
 * Jalankan gate Fil-C. Mengisi res->ran_filc, res->filc_panics, dan output.
 * Kode kembalian: 0 = di-skip / violation / error, 1 = run bersih (caller
 * menaikkan assurance ke L5 FULL). Saat violation, res->verdict diset
 * MC_FILC_VIOLATION oleh gate ini.
 */
int myc_filc_gate(const myc_request *req, const char *source, size_t source_len,
                  myc_result *res);

#endif /* MYC_FILC_H */
