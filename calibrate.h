/*
 * calibrate.h -- Trust Calibration Ledger (Fase 7, SOL-21).
 *
 * Opt-in ledger untuk mencatat feedback user/harness terhadap rule heuristik
 * (lint/negative-space) agar kepercayaan terhadap myc terukur, bukan diasumsikan.
 *
 * PRIVACY (exit criteria Fase 7):
 *   - opt-in: hanya aktif bila user menjalankan `myc calibrate` atau
 *             `--calibrate` pada check; TIDAK pernah auto-record.
 *   - lokal:  `.myc/calibration.json`, tanpa telemetry.
 *   - TIDAK menyimpan source, hanya counter + derived state per rule.
 *
 * NON-blocking (trust rule 1-3): ledger adalah observasi. Ia TIDAK pernah
 * menaikkan/menurunkan verdict. Gagal tulis = dilewati diam-diam (pola
 * .myc/assumptions.json). Kalibrasi rendah = label + anotasi report saja,
 * verdict TIDAK berubah. Gate hard (gcc/analyzer/sanitizer/EVA/Fil-C/L4)
 * TIDAK pernah dibawa ke kalibrasi.
 *
 * Batas jujur: kalibrasi = observasi lokal per repo; `disabled` ≠ dihapus
 * dan ≠ gate di-skip; rule-id mapping ke diagnostic via `match` substring.
 * File hanya ditulis/umum oleh subcommand `myc calibrate` dan (opsional)
 * saat `myc check --calibrate`. Tata letak: .myc/calibration.json
 */
#ifndef MYC_CALIBRATE_H
#define MYC_CALIBRATE_H

#include "myc.h"
#include <stddef.h>

#define MYC_CALIB_SCHEMA       "myc.calibration.v1"
#define MYC_CALIB_DIR          ".myc"
#define MYC_CALIB_FILE         ".myc/calibration.json"
#define MYC_CALIB_ID_MAX       63
#define MYC_CALIB_MAX_ENTRIES  256
#define MYC_CALIB_MIN_FEEDBACK 3

/* Outcome kategori feedback (plan 1484-1490) */
typedef enum {
    MYC_CALIB_ACCEPTED        = 0,  /* finding benar */
    MYC_CALIB_REJECTED        = 1,  /* false positive */
    MYC_CALIB_CONFIRMED_LATER = 2,  /* sempat diragukan, ternyata bug */
    MYC_CALIB_MISSED          = 3,  /* false negative = bug terlewat */
    MYC_CALIB_USEFUL_FIX      = 4,  /* saran fix membantu */
    MYC_CALIB_HARMFUL_FIX     = 5,  /* saran fix merusak */
    MYC_CALIB_OUTCOME_COUNT   = 6
} myc_calib_outcome;

/* State terderivasi (deterministik dari counter) */
typedef enum {
    MYC_CALIB_STATE_UNKNOWN   = 0,  /* feedback < MYC_CALIB_MIN_FEEDBACK */
    MYC_CALIB_STATE_OK        = 1,  /* score > 0  -> rule terpercaya */
    MYC_CALIB_STATE_LOW       = 2,  /* score <= -2 -> CALIBRATED LOW */
    MYC_CALIB_STATE_DISABLED  = 3   /* score <  -4 -> DISABLED (label report) */
} myc_calib_state;

/* Entry ledger per rule */
typedef struct {
    char rule[MYC_CALIB_ID_MAX + 1];
    long long counts[MYC_CALIB_OUTCOME_COUNT];
    char match[128];   /* opsional: fragmen message untuk mapping diag->rule */
} myc_calib_entry;

/* Validasi identifier: charset [A-Za-z0-9._-], panjang 1..63.
 * 1 = valid, 0 = invalid. */
int myc_calib_id_valid(const char *id);

/* Parse outcome name -> enum. 0 ok, -1 unknown. */
int myc_calib_outcome_parse(const char *s, myc_calib_outcome *out);

/* Record satu outcome untuk rule (load-or-init, increment, save).
 * Bila match != NULL, simpan sebagai fragmen message untuk mapping.
 * NON-blocking: gagal tulis = dilewati (return 0 tetap).
 * Return: 0 ok, -1 invalid id, -2 unknown outcome. */
int myc_calib_mark(const char *rule, const char *outcome, const char *match);

/* Laporan teks rule ke buf. Return: 0 ok / -1 not found / -2 invalid id. */
int myc_calib_show(const char *rule, char *buf, size_t cap);

/* Daftar semua rule + aggregate ke buf. 0 ok, -2 dir tak ada. */
int myc_calib_list(char *buf, size_t cap);

/* Hapus satu rule (atau NULL = hapus seluruh ledger).
 * Return: 0 ok / -1 tak ada / -2 invalid id. */
int myc_calib_reset(const char *rule);

/* Derive state dari counter (deterministik). */
myc_calib_state myc_calib_derive_state(const long long *counts);

/* Apply calibration ke result (dipanggil bila --calibrate aktif).
 * Baca ledger, untuk tiap diag yang message-nya mengandung match
 * rule dengan state LOW/DISABLED -> catat anotasi (return count). */
int myc_calib_apply(const myc_result *res, char *buf, size_t cap);

#endif /* MYC_CALIBRATE_H */