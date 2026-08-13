/*
 * persist.h -- Atomic .myc state writes (Batch PR-012, P3-T03).
 *
 * Common atomic persistence helper untuk SEMUA state `.myc` (*.json):
 *   tulis temp file (direktori yang sama, suffix pid) -> flush ->
 *   fsync/FlushFileBuffers -> rename/replace atomik (POSIX rename(),
 *   Windows MoveFileExA MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)
 *   -> optional parent-dir sync pada POSIX.
 *
 * Jaminan crash-consistency (P3-T03 "Required result"): pada crash di
 * langkah mana pun, file target selalu OLD VALID atau NEW VALID — tidak
 * pernah setengah tertulis yang tampak valid.
 *
 * NON-blocking penuh (pola state .myc lainnya): return 1 sukses, 0 gagal;
 * caller bebas mengabaikan (tidak pernah menurunkan verdict).
 */
#ifndef MYC_PERSIST_H
#define MYC_PERSIST_H

#include <stddef.h>

/* Tulis `len` byte dari `data` ke `path` secara atomik.
 * Return 1 sukses, 0 gagal (NON-blocking). */
int myc_persist_atomic_write(const char *path, const char *data, size_t len);

/* Varian string (len = strlen). */
int myc_persist_atomic_write_str(const char *path, const char *str);

#endif /* MYC_PERSIST_H */
