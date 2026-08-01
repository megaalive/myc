/*
 * scanner.h -- Scanner kebijakan myc.
 *
 * Tiga lapis:
 *   1. scan_include_raw   -- #include pada source mentah (sebelum gcc -E)
 *   2. scan_markers       -- penanda "# 1 <path>" pada output gcc -E
 *   3. scan_calls         -- tokenize output -E, deteksi panggilan deny list
 */
#ifndef MYC_SCANNER_H
#define MYC_SCANNER_H

#include <stddef.h>

#include "myc.h"

/*
 * Lapis 1: scan source mentah untuk #include.
 * source: bytes C; len: panjang. Diisi ke res sebagai VIOLATION bila ada
 * include di luar whitelist. Mengembalikan 1 bila aman, 0 bila violation.
 */
int myc_scan_include_raw(const char *source, size_t len, myc_result *res);

/*
 * Lapis 2: periksa output gcc -E. Setiap baris "# 1 \"<path>\"" yang
 * menunjuk ke header sistem harus dalam whitelist. Bila ada header sistem
 * non-whitelist, dianggap VIOLATION (menangkap makro-smuggle).
 */
int myc_scan_markers(const char *preprocessed, size_t len, myc_result *res);

/*
 * Lapis 3: tokenize output gcc -E (komentar sudah dibuang gcc -E) dan
 * deteksi pemanggilan fungsi yang ada di denylist. Mengembalikan 1 bila
 * aman, 0 bila violation (res diisi diagnostic).
 */
int myc_scan_calls(const char *preprocessed, size_t len, myc_result *res);

#endif /* MYC_SCANNER_H */
