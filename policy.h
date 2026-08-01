/*
 * policy.h -- Whitelist header + denylist fungsi untuk myc.
 *
 * Kebijakan di-embed dalam biner; tanpa file eksternal (prinsip anti-bloat).
 */
#ifndef MYC_POLICY_H
#define MYC_POLICY_H

#include <stddef.h>

/* Apakah nama header sistem (tanpa <>) diizinkan oleh whitelist. */
int myc_policy_allow_include(const char *name);

/* Apakah nama fungsi berada dalam denylist berbahaya. */
int myc_policy_deny_function(const char *name);

/* Nama header diizinkan (untuk laporan / debug). */
const char *const *myc_policy_allowed_headers(size_t *count);

/* Fingerprint kebijakan: hash dari semua aturan (untuk fingerprint kanonik). */
void myc_policy_hash(char out_hex[65]);

#endif /* MYC_POLICY_H */
