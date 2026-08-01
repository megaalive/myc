/*
 * myc.h -- Kontrak inti myc: request/result, verdict, error codes.
 *
 * Prinsip (dari rencana fpagnt):
 *   - structured di model boundary
 *   - canonical di dalam harness
 *   - program + argv[] langsung di boundary proses (tanpa shell)
 *   - policy sebelum launch
 *   - stdin di-hash, tidak pernah di-log mentah
 *
 * Semua komentar ditulis dalam Bahasa Indonesia; identifier berbahasa Inggris.
 */
#ifndef MYC_H
#define MYC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#define MYC_MAX_CODE_BYTES  (1u << 20)        /* 1 MiB */
#define MYC_MAX_OUTPUT_BYTES (1u << 20)       /* 1 MiB per channel */
#define MYC_MAX_DIAGNOSTICS 128
#define MYC_DEFAULT_TIMEOUT_MS 30000

typedef enum {
    MC_OK = 0,
    MC_VIOLATION,
    MC_COMPILE_ERROR,
    MC_ERROR,
    MC_TIMEOUT,
    MC_CANCELLED
} myc_verdict;

/* Assurance ladder (lihat docs/rencana-memory-safety.md, Bagian C). */
typedef enum {
    MYC_ASSURANCE_NONE = 0,
    MYC_ASSURANCE_L0_RAW,
    MYC_ASSURANCE_L1_SANE,
    MYC_ASSURANCE_L2_PROVEN,
    MYC_ASSURANCE_L3_RUNTIME,
    MYC_ASSURANCE_L4_SPATIAL,
    MYC_ASSURANCE_L5_FULL
} myc_assurance;

/* Error codes terstruktur (diadaptasi dari Appendix B rencana fpagnt). */
typedef enum {
    MYC_ERR_NONE = 0,
    MYC_ERR_INVALID_REQUEST,
    MYC_ERR_NUL_IN_INPUT,
    MYC_ERR_INPUT_TOO_LARGE,
    MYC_ERR_INVALID_PATH,
    MYC_ERR_POLICY_DENIED,
    MYC_ERR_LINT_VIOLATION,
    MYC_ERR_COMPILE_ERROR,
    MYC_ERR_PREPROCESS_ERROR,
    MYC_ERR_GCC_NOT_FOUND,
    MYC_ERR_EXECUTE_FAILED,
    MYC_ERR_TIMEOUT,
    MYC_ERR_CANCELLED,
    MYC_ERR_STDOUT_READ_FAILED,
    MYC_ERR_STDERR_READ_FAILED,
    MYC_ERR_PROCESS_TREE_CLEANUP_FAILED,
    MYC_ERR_INTERNAL
} myc_error_code;

/* Satu pelanggaran / diagnostic yang ditemukan scanner atau gcc. */
typedef struct {
    int         line;       /* 1-based; 0 bila tidak tersedia */
    int         col;        /* 1-based; 0 bila tidak tersedia */
    const char *message;    /* string statis, tidak dimiliki struct ini */
} myc_diagnostic;

typedef struct {
    const char *source;         /* bytes C (atau NULL bila pakai file_path) */
    size_t      source_len;     /* panjang source dalam byte */
    const char *file_path;      /* alternatif input: path file C */
    int         timeout_ms;     /* 0 = default */
    int         max_output_bytes;
    const char *cwd;            /* workspace root; NULL = cwd proses */
    int         run_analyzer;   /* jalankan gate -fanalyzer */
    int         run_lint;       /* jalankan lint memory-safety (default 1) */
    int         strict;         /* tier ketat: -Wconversion dll */
    int         as_json;        /* output JSON ke stdout */
    const char *gcc_program;    /* NULL = cari "gcc" via PATH */
} myc_request;

typedef struct {
    myc_verdict verdict;
    myc_assurance assurance;    /* level jaminan yang DIBUKTIKAN */
    int         exit_code;              /* exit code dari gate terakhir */
    myc_error_code err;                 /* kode error utama (NONE bila ok) */

    char       *stdout_text;            /* output -E (debug) / stdout gate */
    char       *stderr_text;            /* diagnostik gcc */
    size_t      total_stdout_bytes;
    size_t      total_stderr_bytes;
    size_t      shown_stdout_bytes;
    size_t      shown_stderr_bytes;
    int         truncated;

    unsigned long long duration_ms;

    char       *resolved_gcc;           /* canonical executable identity */
    char       *fingerprint;            /* canonical process fingerprint */
    char       *source_sha256;          /* stdin content hash */

    myc_diagnostic diags[MYC_MAX_DIAGNOSTICS];
    int         diag_count;

    /* internal: gate mana yang dijalankan terakhir */
    int         ran_preprocess;
    int         ran_compile;
    int         ran_analyzer;
} myc_result;

/* --- API --- */

/* Siapkan request dengan nilai default. */
void myc_request_init(myc_request *req);

/* Validasi request; mengembalikan error code atau NONE. */
myc_error_code myc_request_validate(const myc_request *req);

/* Siapkan result dengan alokasi internal. Harus dibebaskan myc_result_free. */
void myc_result_init(myc_result *res);
void myc_result_free(myc_result *res);

/* Jalankan pipeline penuh pada request. Mengisi res. */
void myc_run(const myc_request *req, myc_result *res);

/* Output teks / JSON hasil ke stdout. */
void myc_report_text(const myc_result *res);
void myc_report_json(const myc_result *res);

/* Nama error code (statis). */
const char *myc_error_name(myc_error_code c);
const char *myc_verdict_name(myc_verdict v);
const char *myc_assurance_name(myc_assurance a);

#ifdef __cplusplus
}
#endif

#endif /* MYC_H */
