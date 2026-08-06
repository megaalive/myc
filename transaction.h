/*
 * transaction.h -- Repair Transaction + Preservation Obligations (Fase 2).
 *
 * State machine: BEGIN → PROPOSED → APPLIED_IN_SANDBOX → VERIFIED
 *                  → ACCEPTED | REJECTED | ROLLED_BACK
 *
 * Preservation obligations otomatis:
 *   - source di luar edit region tidak berubah
 *   - public ABI sama (signature fungsi exported)
 *   - kontrak tidak melemah (requires tighter, ensures same/stronger)
 *   - domain tidak menyempit (precondition scope)
 *   - assurance dimensions tidak turun
 *   - scenario dan flags sama
 *   - test yang sebelumnya lulus tetap lulus
 *   - behavior reference tetap sama (kecuali target witness)
 *
 * Scope-laundering detector: mendeteksi perubahan yang mengurangi kemampuan
 * verifikasi (hapus test, hapus assert, nonaktifkan sanitizer, tambah cast
 * untuk mematikan warning, persempit requires, dll).
 *
 * Evidence-sabotage detector: mendeteksi perubahan yang menurunkan kualitas
 * bukti (menonaktifkan -Werror, -Werror=use-after-free, menghapus -fsanitize,
 * menambah #pragma diagnostic ignored, mengubah scenario).
 *
 * Non-blocking: semua pengecekan optional, hanya menghasilkan evidence.
 */
#ifndef MYC_TRANSACTION_H
#define MYC_TRANSACTION_H

#include "myc.h"

/* Result kode untuk tx verify */
typedef enum {
    MYC_TX_RESULT_ACCEPTED = 0,     /* patch diterima: finding hilang, tidak ada regression */
    MYC_TX_RESULT_REJECTED_FINDING, /* patch tidak menghilangkan finding */
    MYC_TX_RESULT_REJECTED_SABOTAGE, /* patch sabotase evidence/scope */
    MYC_TX_RESULT_REJECTED_PRESERVATION, /* preservation obligation terlanggar */
    MYC_TX_RESULT_REJECTED_LAUNDERING, /* scope-laundering terdeteksi */
    MYC_TX_RESULT_REJECTED_TIMEOUT, /* verify timeout */
    MYC_TX_RESULT_INVALID_PATCH    /* patch tidak bisa di-parse/compile */
} myc_tx_result;

/* Perubahan sumber yang dicari (untuk scope/sabotage detector) */
typedef enum {
    MYC_SABOTAGE_NONE = 0,
    MYC_SABOTAGE_DISABLE_SANITIZER,
    MYC_SABOTAGE_DISABLE_WARNING,
    MYC_SABOTAGE_DISABLE_ASSERT,
    MYC_SABOTAGE_ADD_VOID_CAST,
    MYC_SABOTAGE_ADD_PRAGMA,
    MYC_SABOTAGE_INCREASE_NDEBUG,
    MYC_SABOTAGE_REMOVE_TEST,
    MYC_SABOTAGE_NARROW_REQUIRED,
    MYC_SABOTAGE_ADD_EARLY_RETURN,
    MYC_SABOTAGE_CHANGE_SCENARIO,
    MYC_SABOTAGE_WEAKEN_POSTCONDITION,
    MYC_SABOTAGE_INCREASE_BUFFER,
    MYC_SABOTAGE_DISABLE_FRAMA_C,
    MYC_SABOTAGE_DISABLE_FIL_C
} myc_sabotage_kind;

typedef struct {
    myc_sabotage_kind kind;
    char *line;
    char *description;
} myc_sabotage_finding;

typedef struct {
    myc_sabotage_finding findings[32];
    int count;
} myc_sabotage_report;

typedef struct {
    char *tx_id;
    char *initial_receipt_sha;
    char *initial_source_sha;
    char *finding_id;
    char *edit_region;
    myc_sabotage_report sabotage;
    char *preserve_region;
    char *verdict_before;
    char *verdict_after;
    char *assurance_before;
    char *assurance_after;
    int finding_resolved;
    int preservation_violations;
    myc_tx_result result;
} myc_transaction;

/* Inisialisasi transaksi baru.
 * tx_id: identifier unik (bisa NULL untuk auto-generate).
 * initial_receipt: receipt dari run sebelumnya (untuk chain). */
void myc_transaction_init(myc_transaction *tx,
                          const char *tx_id,
                          const char *initial_receipt,
                          const char *initial_source_sha,
                          const char *finding_id,
                          const char *edit_region);

/* Bebaskan transaksi. */
void myc_transaction_free(myc_transaction *tx);

/* Scan source diff untuk sabotage patterns.
 * old_src/new_src: source asli dan sudah di-patch.
 * Non-blocking: mengisi tx->sabotage, tidak menggagalkan build. */
void myc_sabotage_scan(myc_transaction *tx,
                       const char *old_src,
                       const char *new_src);

/* Verifikasi patch: run myc pipeline pada source baru, bandingkan hasil.
 * - finding harus hilang
 * - tidak boleh ada preservation violation
 * - tidak boleh ada sabotage
 * - assurance tidak boleh turun
 * Mengembalikan myc_tx_result. */
myc_tx_result myc_transaction_verify(myc_transaction *tx,
                                     const myc_request *req,
                                     const char *new_source, size_t new_len,
                                     const myc_result *new_result);

/* Generate transaction ID unik (malloc'd, caller free). */
char *myc_transaction_new_id(void);

/* Serialisasi transaksi ke JSON (malloc'd string, caller free).
 * HANYA untuk laporan/debug. */
char *myc_transaction_json(const myc_transaction *tx);

/* Nama string untuk sabotage kind. */
const char *myc_sabotage_name(myc_sabotage_kind k);

/* Nama string untuk tx result. */
const char *myc_tx_result_name(myc_tx_result r);

#endif /* MYC_TRANSACTION_H */
