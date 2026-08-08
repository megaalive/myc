/* concur.h -- Concurrency Schedule / Lock-Order Probe (Fase 6)
 *
 * Dua lapis, keduanya NON-blocking observasi:
 *   1. Lock-order probe STATIS: deteksi pasangan mutex yang di-lock dalam
 *      urutan berbeda antar fungsi (A->B vs B->A) = potensi deadlock /
 *      lock-order inversion.
 *   2. TSan runtime probe (best-effort): bila source memakai thread dan
 *      clang mendukung -fsanitize=thread, build+run -> deteksi data race.
 *      Platform tanpa TSan (Windows) = catatan "tidak tersedia", bukan
 *      kesunyian.
 */
#ifndef MYC_CONCUR_H
#define MYC_CONCUR_H

#include "myc.h"

#define MYC_CONCUR_MAX_LOCKS  32   /* mutex berbeda yang dilacak */
#define MYC_CONCUR_MAX_PAIRS  32   /* pasangan lock berurutan */

/* Jalankan probe pada source (ingress MEMORY). Semua hasil ditulis ke
 * res->concur_* (ran, race_detected, report arena) + evidence.
 * Return 0 (observasi non-blocking; verdict tidak pernah berubah). */
int myc_concur_gate(const myc_request *req, myc_result *res,
                    const char *source, size_t source_len);

#endif /* MYC_CONCUR_H */
