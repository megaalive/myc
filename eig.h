/*
 * eig.h -- Expected-Information-Gain Scheduler (Fase 7, #2029 / DS-14).
 *
 * Scheduler memilih eksperimen verifikasi berdasarkan *expected information
 * gain*, bukan sekadar rule `parser -> fuzz` (DS-14). Skor konseptual:
 *
 *   expected_value = P(new_evidence) x severity x scope
 *                    --------------------------------
 *                        time_cost x token_cost
 *
 * Data lokal yang dipakai (versi pertama = tabel deterministik yang
 * dikalibrasi dari ledger, sesuai DS-14):
 *   - frontier yang masih terbuka (untested/unknown/observed)  [frontier.c];
 *   - observasi AKTUAL (observation-to-experiment)             [observation.c];
 *   - prior P(new_evidence) tabel deterministik per eksperimen, dikalibrasi
 *     dari Trust Calibration Ledger (SOL-21, rule id `eig-<slug-hazard>`):
 *     accepted/confirmed_later menaikkan prior, rejected/harmful_fix
 *     menurunkannya (langkah deterministik, clamp [100..950]/1000);
 *   - profil model/harness opt-in (SOL-20, `--profile <id>`): kelas gate
 *     yang historis menemukan finding menaikkan prior hazard terkait;
 *   - budget waktu user (`budget_time_ms`) -> flag within_budget per item;
 *   - `source_changed` = 0 (source sama sejak run terakhir) -> prior dibagi
 *     dua (bukti sudah dikumpulkan, informasi baru kecil kemungkinannya).
 *
 * Deterministik: input + data lokal + scenario sama -> urutan sama
 * (sort expected_value desc, tie-break cost asc, type asc, hazard asc).
 *
 * NON-blocking (trust rule 1-3): EIG adalah DERIVASI murni dari frontier +
 * experiments + ledger + profil. Ia TIDAK mengubah verdict, TIDAK menambah
 * gate, TIDAK menambah debt. Ledger/profil gagal baca = prior tabel murni.
 *
 * Batas jujur (v1): lapisan PERENCANAAN rekomendasi (`myc eig <file>`),
 * belum memilih/menjalankan gate otomatis di dalam `myc check`. Pemakaian
 * rekomendasi ini oleh assurance budget (D3/SOL-30) = follow-up.
 */
#ifndef MYC_EIG_H
#define MYC_EIG_H

#include "myc.h"
#include "frontier.h"
#include "observation.h"

#define MYC_MAX_EIG 8

/* Input scheduler. Semua opsional; NULL/0 = default deterministik. */
typedef struct {
    const char *profile_id;   /* profil SOL-20 (opsional, `.myc/profiles/<id>.json`) */
    int         source_changed; /* 1 = source berubah sejak run terakhir (default),
                                   0 = tidak berubah (prior dibagi dua) */
    int         budget_time_ms; /* 0 = tanpa budget; >0 = flag within_budget */
} myc_eig_input;

typedef struct {
    myc_experiment_type type;      /* eksperimen yang direkomendasikan */
    const char *hazard;            /* hazard class target (statis) */
    const char *frontier_status;   /* status frontier saat ini (statis) */
    char *command;                 /* perintah myc (malloc'd) */
    char *source_anchor;           /* anchor observasi bila ada (malloc'd) */
    char *rationale;               /* alasan pilihan (malloc'd) */
    int   cost_estimate_ms;        /* time_cost */
    int   severity;                /* 1..5 */
    int   scope;                   /* bobot hazard (1..5) */
    int   p_new_evidence;          /* P(new_evidence) per-mille 0..1000 */
    int   token_cost;              /* proksi biaya token (tabel deterministik) */
    long long expected_value;      /* skor EIG (int64, skala 1e6) */
    int   within_budget;           /* 1 bila cost <= budget_time_ms (bila budget > 0) */
    int   calibrated;              /* 1 bila prior dikalibrasi dari ledger SOL-21 */
    int   rank;                    /* 0 = paling direkomendasikan */
} myc_eig_item;

typedef struct {
    myc_eig_item items[MYC_MAX_EIG];
    int   count;
    int   frontier_items;          /* jumlah item frontier yang dilihat */
    int   blocked_by_violation;    /* 1 bila ada hazard status violation */
    int   source_changed;          /* nilai efektif (default 1) */
    int   budget_time_ms;          /* nilai efektif (default 0) */
    int   profile_used;            /* 1 bila profil SOL-20 dibaca */
    int   calibrated_rules;        /* jumlah item dengan prior terkalibrasi */
    int   within_budget_count;     /* jumlah item within_budget */
    char  profile_id[64];          /* id profil efektif (bila dipakai) */
    char *report;                  /* laporan teks (malloc'd) */
} myc_eig_set;

/* Bangun rekomendasi EiG dari frontier + experiments + input.
 * Murni derivasi; urutan deterministik (expected_value desc). */
void myc_eig_plan(const myc_frontier_set *fs,
                  const myc_experiment_set *exps,
                  const myc_eig_input *in,
                  myc_eig_set *eig);

/* Serialisasi rekomendasi ke JSON (untuk agent output / debug).
 * Mengembalikan string malloc'd yang harus free() oleh caller. */
char *myc_eig_json(const myc_eig_set *eig);

/* Bebaskan eig set (command/source_anchor/rationale/report). */
void myc_eig_free(myc_eig_set *eig);

/* Tabel biaya default per eksperimen (DS-14) — diekspos agar modul lain
 * memakai tabel yang sama, bukan salinan (Candidate Tournament SOL-10
 * memakai dimensi verification_cost). */
int myc_eig_gate_cost_ms(myc_experiment_type t);

/* Biaya default utk hazard class dari rule table DS-14; 0 bila hazard
 * tidak dikenal. Dipakai verification_cost di candidate.c. */
int myc_eig_hazard_cost_ms(const char *hazard);

#endif /* MYC_EIG_H */
