/*
 * ledger.h -- Temporal Ledger (Fase 2, roadmap 7.2).
 *
 * Persistent append-only ledger di .myc/ledger.json yang mencatat:
 *   - source_sha256 (identity file)
 *   - source_anchor (semantic anchor: function + normalized token window)
 *   - receipt_sha256 (hash bukti run ini)
 *   - receipt_parent (hash run sebelumnya untuk source yang sama)
 *   - scenario_hash (intent + flags + tool identity)
 *   - delta_kinds (fixed/new/persistent/churn per gate)
 *   - timestamp
 *
 * Receipt chain: receipt_n = H(receipt_{n-1}, source_sha, evidence, scenario)
 * memungkinkan CI/harness mendeteksi cherry-pick (receipt chain putus).
 *
 * NON-blocking: bila .myc/ tidak dapat ditulis, ledger dilewati dengan
 * diagnostic (bukan error). Ledger opsional.
 */
#ifndef MYC_LEDGER_H
#define MYC_LEDGER_H

#include "myc.h"

#define MYC_LEDGER_DIR ".myc"
#define MYC_LEDGER_FILE ".myc/ledger.json"
#define MYC_LEDGER_MAX_ENTRIES 256

typedef enum {
    MYC_DELTA_FIXED = 0,    /* finding hilang (gate turun → clean/findings) */
    MYC_DELTA_NEW,          /* finding muncul (gate naik → findings) */
    MYC_DELTA_PERSISTENT,   /* finding tetap sama */
    MYC_DELTA_CHURN         /* finding berubah (line/message berubah) */
} myc_delta_kind;

typedef struct {
    char    *source_sha256;   /* identity source */
    char    *anchor;          /* semantic anchor (function + token hash) */
    char    *receipt_sha256;  /* bukti run ini */
    char    *receipt_parent;  /* parent receipt (chain) */
    char    *scenario_hash;   /* intent + flags + tool identity */
    char    *timestamp;       /* ISO 8601 */
    char    *source_anchor_line; /* anchor line content */
    myc_delta_kind delta;     /* vs run sebelumnya */
    char    *gate_id;         /* gate yang berubah */
    char    *gate_status;     /* status gate ini */
    char    *verdict;         /* verdict string */
    char    *finding;         /* finding string */
} myc_ledger_entry;

typedef struct {
    myc_ledger_entry entries[MYC_LEDGER_MAX_ENTRIES];
    int count;
    int parent_found;   /* apakah parent receipt ditemukan di ledger */
} myc_ledger;

/* Baca ledger dari .myc/ledger.json.
 * Mengembalikan 1 jika file ditemukan dan parsed, 0 bila tidak ada/tidak bisa. */
int myc_ledger_read(myc_ledger *ledger);

/* Tulis ledger ke .myc/ledger.json (append entry baru).
 * Jika entry sudah ada (source_sha sama), update receipt_parent + delta.
 * Non-blocking: return 0 bila gagal, 1 sukses. */
int myc_ledger_write(const myc_ledger_entry *entry);

/* Cari entry terakhir untuk source_sha yang diberikan.
 * Mengembalikan pointer ke entry statis, atau NULL bila tidak ada. */
const myc_ledger_entry *myc_ledger_find(const myc_ledger *ledger,
                                        const char *source_sha256);

/* Hitung delta antara dua receipt (gate status strings).
 * Mengembalikan MYC_DELTA_* berdasarkan perbandingan gate status. */
myc_delta_kind myc_ledger_compute_delta(const char *prev_status,
                                        const char *curr_status);

/* Bangun semantic anchor: "<function>:<normalized_token_hash>:<line_window>"
 * Mengembalikan string malloc'd. */
char *myc_ledger_build_anchor(const char *source, size_t source_len,
                              int line, int col, size_t window_chars);

/* Bangun scenario hash: H(flags, tool versions, intent_hash).
 * Mengembalikan string hex 16 karakter (8 byte), malloc'd. */
char *myc_ledger_build_scenario_hash(const myc_request *req,
                                     const char *intent_hash);

/* Bebaskan ledger (entry strings dialokasikan oleh parser JSON). */
void myc_ledger_free(myc_ledger *ledger);

/* Helper: dapatkan timestamp ISO 8601. */
char *myc_ledger_timestamp(void);

#endif /* MYC_LEDGER_H */
