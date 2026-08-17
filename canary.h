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

/* ------------------------------------------------------------------ */
/* Backend qualification registry (PR-017 / P5-T01 + P5-T02)           */
/* ------------------------------------------------------------------ */

/* Tier kebijakan backend (docs/backends.md, PR-017):
 *   A = release-blocking, diuji CI (Windows + Linux)
 *   B = supported, non-blocking (kehadiran/kerusakan = debt, bukan FAIL)
 *   C = best-effort / eksperimental (observasi saja)                  */
#define MYC_BACKEND_TIER_A "A"
#define MYC_BACKEND_TIER_B "B"
#define MYC_BACKEND_TIER_C "C"

/* Satu baris kebijakan backend: siapa backend-nya, executable utama yang
 * dicari (NULL = internal, tanpa binary eksternal), tier dukungan, versi
 * minimum yang didukung (NULL = tidak ada pernyataan minimum), dan apa
 * evidence yang diekstrak (dokumentasi P5-T01). */
typedef struct {
    const char *backend;     /* nama backend: compile|analyzer|run|driver|
                                exhaustive|fuzz|mutate|stack|lint|prove|
                                filc|matrix|checked */
    const char *exe;         /* executable utama (gcc / clang / filc-clang /
                                frama-c / arm-none-eabi-gcc ...); NULL =
                                internal (tanpa binary eksternal) */
    const char *tier;        /* MYC_BACKEND_TIER_A / _B / _C */
    const char *min_version; /* versi minimum; NULL = n/a */
    const char *evidence;    /* evidence yang diekstrak (satu kalimat) */
} myc_backend_policy;

/* Tabel kebijakan backend (static). *count = jumlah entri. */
const myc_backend_policy *myc_backend_policy_table(int *count);

/* Identitas backend yang di-resolve saat ini: path executable + versi
 * (baris pertama `<exe> --version`). Dua string malloc'd; pemanggil
 * membebaskan dengan myc_backend_probe_free(). `found` = executable
 * ditemukan; `path`/`version` NULL bila tidak. */
typedef struct {
    const myc_backend_policy *policy;  /* entry kebijakan (milik tabel) */
    int    found;                      /* executable ditemukan di PATH */
    char  *path;                       /* path absolut resolv (malloc'd) */
    char  *version;                    /* versi exact (malloc'd) */
} myc_backend_probe;

/* Probe identitas backend [backend] (NULL = semua). Mengisi array
 * `out` (calloc'd, *count entri) — SETIAP entri milik pemanggil dan
 * di-free via myc_backend_probe_free(). Return 1 sukses, 0 gagal. */
int myc_backend_probe_run(const char *backend, myc_backend_probe **out,
                          int *count);

/* Bebaskan array hasil myc_backend_probe. */
void myc_backend_probe_free(myc_backend_probe *p, int count);

/* Cetak registry backend ke out: tier, path, versi, dan status canary
 * per backend. `run_canary` = 1 menjalankan canary backend tsb (mahal);
 * 0 hanya mencantumkan jumlah canary yang tersedia. Return jumlah
 * backend yang canary-nya GAGAL (0 = semua terverifikasi hidup). */
int myc_backends_report(FILE *out, int run_canary);

/* P5-T03 / P12: major version dari string `--version` atau "gcc 9+".
 * Tupel N.N terakhir ("15.2.0" → 15); bila tidak ada titik, integer
 * terakhir ("gcc 9+" → 9). Return -1 bila tidak ada angka. */
int myc_tool_version_major(const char *s);

struct myc_request;
struct myc_result;
void myc_production_enforce(const struct myc_request *req,
                            struct myc_result *res);

#endif /* MYC_CANARY_H */
