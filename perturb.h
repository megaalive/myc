/* perturb.h -- Environment Perturbation (Fase 6, Self-Challenge)
 *
 * Determinisme lintas lingkungan: program yang perilakunya BERUBAH ketika
 * env diubah (TZ, locale, PATH, HOME/TERM) adalah observasi penting --
 * hasil verifikasi bisa berbeda di CI vs mesin developer. `--perturb`
 * menjalankan ulang program verification dengan beberapa env yang diubah
 * dan membandingkan (stdout hash + exit code + sanitizer) dengan run
 * baseline. NON-blocking observasi: verdict tidak pernah berubah.
 */
#ifndef MYC_PERTURB_H
#define MYC_PERTURB_H

#include "myc.h"

/* Jalankan perturb runs (setelah run utama selesai). exe_path = binary
 * verification (masih ada di tmp); cwd = tmp dir; base_env = env run
 * utama (RUN_ENV); stdin_data/len = input run utama. Hasil dicatat di
 * res->perturb_* (ran, changed, report arena) + evidence RUNTIME.
 * Return 0 (selalu; observasi non-blocking). */
int myc_perturb_gate(const myc_request *req, myc_result *res,
                     const char *exe_path, const char *cwd,
                     const char *const *base_env,
                     const void *stdin_data, size_t stdin_len);

#endif /* MYC_PERTURB_H */
