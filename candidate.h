/*
 * candidate.h -- Candidate Tournament dengan Pareto Frontier (Fase 7, SOL-10).
 *
 * Dari spec SOL-10: model sering menghasilkan 2-4 patch alternatif; memilih
 * yang "compile" terlalu lemah. Modul ini menilai tiap kandidat pada
 * DIMENSI yang terukur secara deterministik, lalu memilih kandidat pada
 * Pareto frontier (bukan satu skor ajaib).
 *
 * Dimensi (v1):
 *   - hard_gate          pipeline myc (compile tier) lolos        [higher better]
 *   - findings           observasi lint + negative-space          [lower better]
 *   - obligations_lost   requires/ensures hilang vs baseline      [lower better]
 *   - churn_lines        baris ditambah+dihapus vs baseline       [lower better]
 *   - verification_cost  biaya verifikasi frontier terbuka (tabel [lower better]
 *                        deterministik DS-14, diekspos eig.c)
 *   - runtime_proxy      jumlah loop for/while/do (teks, proksi)  [lower better]
 *   - portability        rasio include whitelist policy           [higher better]
 *   - readability        1 - rasio baris > 100 kolom              [higher better]
 *   - stack_impact       UNMEASURED di v1 (butuh gcc -fstack-usage
 *                        per kandidat; gap TERLIHAT, bukan kesunyian)
 *
 * Algoritma: Pareto dominance murni (tanpa bobot). A mendominasi B bila
 * A >= B pada SEMUA dimensi terukur (arah higher-better) dan ketat pada
 * >= 1 dimensi. Kandidat yang tidak didominasi = Pareto frontier.
 *
 * Anti-overclaim (spec SOL-10): myc TIDAK menyatakan kandidat "terbaik
 * secara umum"; ia menyatakan "tidak didominasi pada dimensi yang terukur".
 * Harness atau user tetap memilih final. Baseline ikut dalam perbandingan
 * (mempertahankan original selalu merupakan opsi).
 *
 * NON-blocking (trust rules): observasi murni; TIDAK mengubah verdict/exit.
 * Deterministik: input + toolchain sama -> hasil sama.
 */
#ifndef MYC_CANDIDATE_H
#define MYC_CANDIDATE_H

#include "myc.h"

#define MYC_MAX_CANDIDATES 8   /* total file: baseline + hingga 7 kandidat */

typedef struct {
    const char *path;           /* statis, milik caller argv */
    int  measured_ok;           /* 1 = pipeline + semua dimensi terukur */
    int  hard_gate;             /* 1 = verdict OK (compile tier)  [higher] */
    int  findings;              /* lint + negative observations   [lower] */
    int  obligations_lost;      /* requires/ensures hilang vs baseline [lower] */
    int  churn_lines;           /* baris ditambah+dihapus vs baseline [lower] */
    int  verification_cost;     /* biaya verifikasi frontier terbuka [lower] */
    int  runtime_proxy;         /* jumlah loop for/while/do       [lower] */
    int  portability;           /* 0..1000 rasio include whitelist [higher] */
    int  readability;           /* 0..1000 1-long_line_ratio      [higher] */
    int  frontier;              /* 1 = tidak didominasi (Pareto)  */
    int  dominated_by;          /* index pemenang, -1 = none      */
} myc_candidate_item;

typedef struct {
    myc_candidate_item items[MYC_MAX_CANDIDATES]; /* [0] = baseline */
    int   count;                 /* baseline + kandidat */
    int   ncandidates;
    int   measured_dims;         /* 8 */
    int   frontier_count;
    char *report;                /* malloc'd, dibebaskan myc_candidate_free */
} myc_candidate_set;

/* Jalankan tournament: ukur baseline + tiap kandidat, hitung churn/
 * obligations vs baseline, hitung Pareto frontier, bangun laporan teks.
 * checked_header_dir: dir dari argv0 (dipakai pipeline utk header MYC_BUF,
 * boleh NULL). Kembali 0 sukses; 1 = fatal (baseline tidak terbaca) --
 * laporan (error) tetap terisi. */
int myc_candidate_tournament(const char *baseline_path,
                             const char *const *cand_paths, int ncands,
                             const char *checked_header_dir,
                             myc_candidate_set *out);

/* Serialisasi tournament ke JSON (schema myc.candidate.v1). String
 * malloc'd yang harus free() oleh caller; NULL bila OOM. */
char *myc_candidate_json(const myc_candidate_set *cs);

/* Bebaskan set (report). */
void myc_candidate_free(myc_candidate_set *cs);

#endif /* MYC_CANDIDATE_H */
