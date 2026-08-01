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
    MC_CANCELLED,
    MC_RUNTIME_VIOLATION,
    MC_PROVE_VIOLATION,
    MC_FILC_VIOLATION,
    MC_DRIVER_VIOLATION
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
    MYC_ERR_RUNTIME_VIOLATION,
    MYC_ERR_PROVE_VIOLATION,
    MYC_ERR_FILC_VIOLATION,
    MYC_ERR_DRIVER_VIOLATION,
    MYC_ERR_CLANG_NOT_FOUND,
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
    int         run;            /* verification build + eksekusi (L3 RUNTIME) */
    const char *run_stdin;      /* stdin untuk program verification (NULL = kosong) */
    size_t      run_stdin_len;
    int         prove;          /* gate Frama-C Eva (D3.1, L2 PROVEN, via WSL) */
    int         checked;        /* checked-build makro (D1.2, L4 SPATIAL):
                                   bangun 2x (produksi T* + -DMYC_CHECKED fat) */
    const char *checked_header_dir; /* direktori berisi myc_buf.h (biasanya
                                       dir myc.exe); NULL = cari via -I cwd */
    int         filc;           /* gate Fil-C (D4.1, L5 FULL, opsional):
                                   verification build filc-clang + eksekusi */
    int         driver;         /* gate driver-generator (D2.2, opsional):
                                   harness kasus tepi dari fungsi ber-kontrak,
                                   build+run clang ASan (L3 bila bersih) */
    const char *clang_program;  /* NULL = cari "clang" via PATH */
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

    /* --- hasil verification run (P6, --run) --- */
    int         ran_runtime;            /* 1 bila gate run dijalankan */
    char       *run_stdout_text;        /* stdout program verification */
    char       *run_stderr_text;        /* stderr program verification */
    size_t      run_total_stdout_bytes;
    size_t      run_total_stderr_bytes;
    size_t      run_shown_stdout_bytes;
    size_t      run_shown_stderr_bytes;
    int         run_truncated;
    int         run_timed_out;

    /* --- hasil gate prove (D3.1, --prove) --- */
    int         ran_prove;              /* 1 bila gate prove dijalankan */
    int         prove_alarms;           /* jumlah alarm Eva (RTE) */
    char       *prove_stdout_text;      /* output frama-c -eva */
    char       *prove_stderr_text;

    char       *resolved_gcc;           /* canonical executable identity */
    char       *fingerprint;            /* canonical process fingerprint */
    char       *source_sha256;          /* stdin content hash */

    myc_diagnostic diags[MYC_MAX_DIAGNOSTICS];
    int         diag_count;

    /* --- hasil contract-lite (D1.5, P7) --- */
    int         contract_requires;      /* jumlah //@ requires terbaca */
    int         contract_ensures;       /* jumlah //@ ensures terbaca */

    /* --- hasil checked build (D1.2, P8, --checked) --- */
    int         ran_checked;            /* 1 bila gate checked-build dijalankan */
    int         checked_uses_buf;       /* 1 bila source memakai makro MYC_BUF */
    int         checked_build_ok;       /* 1 bila build -DMYC_CHECKED lolos */

    /* --- hasil gate Fil-C (D4.1, P8, --filc) --- */
    int         ran_filc;               /* 1 bila gate Fil-C dijalankan */
    int         filc_panics;            /* jumlah marker panic Fil-C */
    char       *filc_stdout_text;       /* output program Fil-C */
    char       *filc_stderr_text;

    /* --- hasil gate driver-generator (D2.2, --driver) --- */
    int         ran_driver;             /* 1 bila gate driver dijalankan */
    int         driver_funcs;           /* jumlah fungsi ber-kontrak dipanggil */
    int         driver_cases;           /* jumlah kasus tepi tereksekusi */
    int         driver_skipped;         /* jumlah kasus dilewati guard */
    char       *driver_stdout_text;     /* output harness (DRIVER run=...) */
    char       *driver_stderr_text;

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

/* Direktori yang memuat executable (tempat myc_buf.h diharapkan ada).
 * Mengembalikan string malloc'd atau NULL. Dipakai gate checked-build (D1.2)
 * untuk -I dan oleh MCP server (P9, mcp.exe). */
char *myc_exe_dirname(const char *argv0);

#ifdef __cplusplus
}
#endif

#endif /* MYC_H */
