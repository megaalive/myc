/*
 * scanner.h -- Scanner kebijakan myc.
 *
 * Tiga lapis:
 *   1. scan_include_raw   -- #include pada source mentah (sebelum gcc -E)
 *   2. scan_markers       -- penanda "# 1 <path>" pada output gcc -E
 *   3. scan_calls         -- tokenize output -E, deteksi panggilan deny list
 *
 * Setelah pivot memory-safety (2026-08-01), ketiga lapis bersifat
 * NON-BLOCKING: menambah diagnostic warning tetapi selalu mengembalikan 1.
 * Satu-satunya gate hard = lint memory-safety (lint.h) + gate gcc.
 */
#ifndef MYC_SCANNER_H
#define MYC_SCANNER_H

#include <stddef.h>

#include "myc.h"

/*
 * Lapis 1: scan source mentah untuk #include.
 * source: bytes C; len: panjang. Menambah diagnostic warning bila ada
 * include di luar whitelist. SELALU mengembalikan 1 (non-blocking).
 */
int myc_scan_include_raw(const char *source, size_t len, myc_result *res);

/*
 * Lapis 2: periksa output gcc -E. Setiap baris "# 1 \"<path>\"" yang
 * menunjuk ke header sistem harus dalam whitelist. Bila ada header sistem
 * non-whitelist, tambah warning. SELALU mengembalikan 1 (non-blocking).
 */
int myc_scan_markers(const char *preprocessed, size_t len, myc_result *res);

/*
 * Lapis 3: tokenize output gcc -E (komentar sudah dibuang gcc -E) dan
 * deteksi pemanggilan fungsi yang ada di denylist. Menambah warning.
 * SELALU mengembalikan 1 (non-blocking).
 */
int myc_scan_calls(const char *preprocessed, size_t len, myc_result *res);

#endif /* MYC_SCANNER_H */
