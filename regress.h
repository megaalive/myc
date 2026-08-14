/* regress.h -- Counterexample Seeds -> Regression (Fase 6, Self-Challenge)
 *
 * Setiap counterexample yang DITEMUKAN (fuzz crash, exhaustive
 * counterexample, driver violation) disimpan otomatis ke
 * `.myc/regression/<kind>_<sha8>.c` + index `.myc/regression/index.txt`
 * = corpus memory. `myc regression run` menjalankan ulang semua seed:
 * masih violation = bug BELUM diperbaiki; OK = RESOLVED (fix tidak
 * regress). NON-blocking: penyimpanan tidak pernah mengubah verdict.
 */
#ifndef MYC_REGRESS_H
#define MYC_REGRESS_H

#include <stdio.h>

#include "myc.h"

#define MYC_REG_FUZZ       0
#define MYC_REG_EXHAUSTIVE 1
#define MYC_REG_DRIVER     2

const char *myc_regress_kind_name(int kind);

/* Simpan source sebagai seed regression (idempoten per sha8). detail =
 * label pendek tanpa spasi (mis. nama fungsi); seed = seed PRNG fuzz
 * (0 bila tidak relevan). NON-blocking: gagal menulis = diabaikan
 * senyap (bukan kegagalan verifikasi). */
void myc_regress_save(myc_result *res, const char *source, size_t len,
                      int kind, const char *detail, unsigned seed);

/* `myc regression list`: cetak isi corpus. return 0. */
int myc_regress_list(FILE *out);

/* Replay seluruh corpus terhadap source IN-MEMORY (pasca-repair, IDE-4):
 * tiap seed (kind + seed PRNG) dijalankan pada source yang diberikan.
 * Mengisi *total, *resolved (OK), *failing; return jumlah seed yang
 * masih gagal (bug lama hidup kembali). NON-blocking: tidak mengubah
 * verdict run yang sedang berlangsung. */
int myc_regress_replay_mem(const char *source, size_t len,
                           int *total, int *resolved, int *failing);

/* `myc regression run [file.c]`:
 * - tanpa file: replay setiap seed (source snapshot buggy) -> status
 *   deteksi (STILL_FAILING bila toolchain masih menangkapnya).
 * - dengan file.c: jalankan setiap seed-INPUT (fuzz seed PRNG
 *   deterministik, exhaustive/driver full gate) pada source SAAT INI:
 *   masih violation = bug belum diperbaiki; OK = RESOLVED (fix tidak
 *   regress). return jumlah seed yang masih gagal. */
int myc_regress_run(FILE *out, const char *target_file);

#endif /* MYC_REGRESS_H */
