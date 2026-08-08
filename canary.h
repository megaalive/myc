/* canary.h -- Canary Swarm (Fase 6, Self-Challenge)
 *
 * Setiap backend (gate) yang bisa memberi klaim memory-safety harus
 * DIBUKTIKAN hidup lewat canary: source minimal ber-bug (canary positif,
 * harus TERDETEKSI) dan source aman (canary negatif, harus bersih).
 * `myc canary run [backend]` menjalankan seluruh canary; canary yang
 * gagal berarti backend tidak bisa dipercaya -- klaim backend tsb harus
 * dibaca dengan curiga (UNRELIABLE), bukan kesunyian.
 *
 * Exit criteria Fase 6: "Setiap klaim backend mempunyai canary relevan."
 */
#ifndef MYC_CANARY_H
#define MYC_CANARY_H

#include <stdio.h>

/* Flag gate yang diaktifkan untuk satu canary (bitmask). Compile gate
 * selalu berjalan (dasar semua backend). */
#define MYC_CANARYF_ANALYZER   (1 << 0)   /* --analyze (gcc -fanalyzer)    */
#define MYC_CANARYF_RUN        (1 << 1)   /* --run (clang ASan/UBSan)      */
#define MYC_CANARYF_DRIVER     (1 << 2)   /* --driver (harness kasus tepi) */
#define MYC_CANARYF_EXHAUSTIVE (1 << 3)   /* --exhaustive (A3, P1 EXH)     */
#define MYC_CANARYF_FUZZ       (1 << 4)   /* --fuzz (D1, fuzz-lite)        */
#define MYC_CANARYF_MUTATE     (1 << 5)   /* --mutate-audit (B5)           */
#define MYC_CANARYF_STACK      (1 << 6)   /* --stack (C2)                  */

/* Satu canary. source = C source SELF-CONTAINED (tanpa file eksternal),
 * dikirim via ingress MEMORY. expect_verdict = verdict yang HARUS
 * dihasilkan agar canary PASS; expect_text (opsional) = substring wajib
 * pada evidence (bukti gate benar-benar melihat hal yang dimaksud). */
typedef struct {
    const char *backend;        /* nama backend: compile|analyzer|run|driver|
                                   exhaustive|fuzz|mutate|stack|lint */
    const char *name;           /* nama canary unik */
    const char *desc;           /* klaim yang diverifikasi */
    const char *source;         /* C source self-contained */
    int         flags;          /* bitmask MYC_CANARYF_* */
    int         expect_verdict; /* MC_OK / MC_COMPILE_ERROR / ... */
    const char *expect_text;    /* substring evidence wajib; NULL = tak ada */
} myc_canary;

/* Tabel canary (static). return pointer; *count diisi jumlah entri. */
const myc_canary *myc_canary_table(int *count);

/* Nama backend yang punya canary (untuk `myc canary list`). */
const char *const *myc_canary_backends(int *count);

/* Jalankan semua canary backend [backend] (NULL = semua).
 * Laporan teks ditulis ke out. Return JUMLAH canary GAGAL (0 = semua
 * backend terverifikasi hidup). */
int myc_canary_run(const char *backend, FILE *out);

#endif /* MYC_CANARY_H */
