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
#include <stdint.h>

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
    MC_DRIVER_VIOLATION,
    MC_INCONCLUSIVE
} myc_verdict;

/* Assurance ladder (lihat docs/rencana-memory-safety.md, Bagian C).
 * Catatan: ladder ini dipertahankan untuk backward compatibility,
 * tetapi verdict sebenarnya diturunkan dari typed gate status
 * melalui myc_reduce_verdict() (Fase 3). */
typedef enum {
    MYC_ASSURANCE_NONE = 0,
    MYC_ASSURANCE_L0_RAW,
    MYC_ASSURANCE_L1_SANE,
    MYC_ASSURANCE_L2_PROVEN,
    MYC_ASSURANCE_L3_RUNTIME,
    MYC_ASSURANCE_L4_SPATIAL,
    MYC_ASSURANCE_L5_FULL
} myc_assurance;

/* ------------------------------------------------------------------ */
/* Gate status (Fase 3)                                                */
/* ------------------------------------------------------------------ */

typedef enum {
    MYC_GATE_NOT_REQUESTED = 0,
    MYC_GATE_NOT_APPLICABLE,
    MYC_GATE_UNAVAILABLE,
    MYC_GATE_INFRA_FAILED,
    MYC_GATE_INCONCLUSIVE,
    MYC_GATE_COMPLETED_CLEAN,
    MYC_GATE_COMPLETED_FINDINGS,
    /* Gate selesai tapi hasilnya HANYA observasi (heuristik teks, mis.
     * negative-space 9.8): bukan finding terkonfirmasi, juga bukan
     * incomplete. Benign terhadap verdict/assurance; muncul di evidence
     * matrix agar laporan jujur ("scan selesai, ada catatan"). */
    MYC_GATE_COMPLETED_OBSERVATIONS
} myc_gate_status;

typedef enum {
    MYC_GATE_PREPROCESS = 0,
    MYC_GATE_COMPILE,
    MYC_GATE_ANALYZER,
    MYC_GATE_RUNTIME,
    MYC_GATE_PROVE,
    MYC_GATE_CHECKED,
    MYC_GATE_FILC,
    MYC_GATE_DRIVER,
    MYC_GATE_METAMORPHIC,    /* (9.7) build ganda -O0/-O2, bandingkan hasil */
    MYC_GATE_NEGATIVE,       /* (9.8) negative-space: observasi konvensi
                                callsite (bukan finding, bukan verdict) */
    MYC_GATE_COUNT
} myc_gate_id;

typedef struct {
    myc_gate_id    id;
    myc_gate_status status;
    int            requested;
    int            findings;
    unsigned long long duration_ms;
    char          *output;
    size_t         output_len;
} myc_gate_result;

typedef enum {
    MYC_EVIDENCE_GATE_START = 0,
    MYC_EVIDENCE_GATE_END,
    MYC_EVIDENCE_DIAGNOSTIC,
    MYC_EVIDENCE_FINDING,
    MYC_EVIDENCE_SKIP,
    MYC_EVIDENCE_ERROR
} myc_evidence_type;

typedef struct {
    uint32_t gate_id;
    uint32_t event_type;
    char    *message;
} myc_evidence_event;

typedef enum {
    MYC_COMPLETENESS_UNKNOWN = 0,
    MYC_COMPLETENESS_COMPLETE,
    MYC_COMPLETENESS_INCOMPLETE
} myc_completeness;

/* Sumbu A — Finding (Fase 4): status hasil dilihat dari ada-tidaknya
 * finding terkonfirmasi pada scope yang selesai. Sumbu yang berbeda
 * dan setara dengan completeness (Sumbu B). */
typedef enum {
    MYC_FINDING_UNKNOWN = 0,
    MYC_FINDING_CLEAN,       /* tak ada finding terkonfirmasi di scope selesai */
    MYC_FINDING_FINDINGS,    /* ≥1 finding terkonfirmasi di scope yang selesai */
    MYC_FINDING_INCONCLUSIVE /* ada gate diminta yang belum selesai */
} myc_finding;

/* --- Claim compiler (Fase 4, gagasan pembeda 9.2) ---
 * Validasi bahwa label assurance yang dipakai benar-benar didukung
 * oleh bukti. Mencegah output menyebut FULL/PROVEN/memory-safe
 * kecuali obligation benar-benar terpenuhi. */
typedef enum {
    MYC_CLAIM_UNKNOWN = 0,
    MYC_CLAIM_VALID,       /* assurance label didukung oleh bukti */
    MYC_CLAIM_OVERSTATED,  /* assurance label lebih tinggi dari bukti */
    MYC_CLAIM_UNVERIFIED   /* bukti tidak cukup untuk menyatakan klaim */
} myc_claim_status;

/* Unverified debt (Fase 4, gagasan pembeda 9.3): daftar scope yang DIMINTA
 * tetapi tidak benar-benar diselesaikan / diverifikasi. Ini menjadikan
 * "keheningan tidak disalahartikan sebagai keamanan". Setiap kernel debt
 * dijumlahkan dari typed gate status + counter scope yang tersedia. */
typedef enum {
    MYC_DEBT_NONE = 0,
    MYC_DEBT_GATE_UNAVAILABLE,    /* backend diminta tapi tidak tersedia */
    MYC_DEBT_GATE_INFRA_FAILED,   /* backend diminta tapi gagal infra/exec */
    MYC_DEBT_GATE_INCONCLUSIVE,   /* backend diminta tapi hasil tidak lengkap */
    MYC_DEBT_NONZERO_CASES,       /* gate run/driver diminta tapi 0 kasus */
    MYC_DEBT_ENSURES_UNPROVED,    /* ensures di-parse tapi tidak dibuktikan */
    MYC_DEBT_RAW_BUFFERS,         /* terdapat buffer biasa di luar MYC_BUF */
    MYC_DEBT_OUTPUT_TRUNCATED,    /* output backend terpotong (moral hilang) */
    MYC_DEBT_COUNT
} myc_debt_type;

typedef struct {
    myc_debt_type type;
    const char   *text;   /* string statis penjelasan debt */
} myc_debt_item;

#define MYC_MAX_GATES      16
#define MYC_MAX_EVIDENCE   256
#define MYC_MAX_DEBT       32

#define MYC_ARENA_BLOCK    65536        /* ukuran blok arena per request */

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
    int         quorum;         /* gate Differential Backend Quorum (#3):
                                    jalankan semua backend tersedia,
                                    bandingkan hasil, laporkan konflik */
    int         metamorphic;    /* gate Metamorphic Verification (9.7):
                                    bangun 2x (clang ASan -O0 dan -O2),
                                    jalankan, bandingkan hasil; beda =
                                    kemungkinan UB / toolchain-sensitive */
    int         negative;       /* gate Negative-Space Analysis (9.8):
                                    observasi pola yang hilang (konvensi
                                    pemeriksaan hasil alokasi); NON-blocking,
                                    HANYA diagnostic + confidence */
} myc_request;

/* --- Differential Backend Quorum (#3) --- */
typedef enum {
    MYC_QUORUM_NOT_REQUESTED = 0,
    MYC_QUORUM_CLEAN,
    MYC_QUORUM_CONFLICT,
    MYC_QUORUM_INCONCLUSIVE
} myc_quorum_status;

/* --- Counterexample Replay Capsule (#2) ---
 * Captures all information needed to replay a specific verification
 * run: source identity, stdin identity, backend, flags, and result.
 * Stored in myc_result; freed by myc_result_free(). */
typedef struct {
    /* Source identity */
    char *source_sha256;
    /* Stdin identity (hash of data fed to program under test;
     * NULL if no --run-stdin was provided). */
    char *stdin_sha256;
    size_t stdin_len;
    /* Backend identity */
    char *clang_path;
    char *gcc_path;
    char *cwd;
    /* Request parameters */
    int timeout_ms;
    int max_output_bytes;
    int strict;
    int run_analyzer;
    int run;
    int prove;
    int checked;    int     filc;
    int     driver;
    int     metamorphic;    /* (9.7) flag gate metamorphic */
    int     negative;       /* (9.8) flag gate negative-space */
    /* Execution result */
    myc_verdict verdict;
    int exit_code;
    int timed_out;
    int sanitizer_detected;
    char sanitizer_marker[64];
    /* Metamorphic (9.7): hasil per-build */
    int metamorphic_inconsistent; /* hasil -O0 vs -O2 tidak setuju (sanitizer) */
    int meta_o0_exit;
    int meta_o2_exit;
    int meta_o0_finding;   /* 1 = marker sanitizer pada build -O0 */
    int meta_o2_finding;   /* 1 = marker sanitizer pada build -O2 */
    /* Negative-space (9.8): hasil observasi */
    int negative_callsites;   /* total callsite alokasi terdeteksi */
    int negative_deviations;  /* jumlah yang tidak memeriksa hasil */
    /* Gate summary (one status per gate) */
    myc_gate_status gate_status[MYC_GATE_COUNT];
    /* Finding / completeness / claim */
    myc_finding finding;
    myc_completeness completeness;
    myc_claim_status claim_status;
    /* Differential Backend Quorum (#3) */
    myc_quorum_status quorum_status;
} myc_replay_capsule;

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
    /* Streaming evidence: sanitizer terdeteksi pada output
     * streaming (dari proc.c drain thread). */
    int         run_sanitizer_detected;
    char        run_sanitizer_marker[64];

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

    /* --- hasil gate metamorphic (9.7, --metamorphic) --- */
    int         ran_metamorphic;      /* 1 bila gate metamorphic dijalankan */
    int         metamorphic_inconsistent; /* hasil -O0 vs -O2 tidak setuju */
    int         meta_o0_exit;         /* exit code build -O0 */
    int         meta_o2_exit;         /* exit code build -O2 */
    int         meta_o0_finding;      /* 1 = marker sanitizer pada -O0 */
    int         meta_o2_finding;      /* 1 = marker sanitizer pada -O2 */
    int         meta_timed_out;       /* salah satu run timeout */

    /* --- hasil gate negative-space (9.8, --negative) --- */
    int         ran_negative;         /* 1 bila gate negative dijalankan */
    int         negative_callsites;   /* total callsite alokasi terdeteksi */
    int         negative_deviations;  /* jumlah yang tidak memeriksa hasil */

    /* internal: gate mana yang dijalankan terakhir */
    int         ran_preprocess;
    int         ran_compile;
    int         ran_analyzer;

    /* --- typed gate status (Fase 3) --- */
    myc_gate_result gates[MYC_MAX_GATES];
    size_t          gate_count;

    /* --- evidence ledger (Fase 3) --- */
    myc_evidence_event evidence[MYC_MAX_EVIDENCE];
    size_t             evidence_count;

    /* --- verification completeness (Sumbu B) --- */
    myc_completeness completeness;

    /* --- finding verdict (Sumbu A, Fase 4) --- */
    /* Status hasil dari sisi finding: CLEAN / FINDINGS / INCONCLUSIVE.
     * Dipisah dari verdict legacy agar konsumen tidak perlu menebak makna
     * MC_OK/MC_VIOLATION; output dua sumbu (finding + completeness). */
    myc_finding finding;

    /* --- Claim compiler (Fase 4, 9.2) ---
     * Validasi bahwa assurance label benar-benar didukung oleh bukti.
     * Mencegah output menyebut FULL/PROVEN/memory-safe kecuali
     * obligation benar-benar terpenuhi. */
    myc_claim_status claim_status;

    /* --- unverified debt (Fase 4) --- */
    myc_debt_item debt[MYC_MAX_DEBT];
    size_t        debt_count;

/* --- evidence receipt (gagasan pembeda 9.1) --- */
    /* Hash deterministik atas bukti terkumpul (verdict, completeness, setiap
     * gate por padanya status, debt, fingerprint, source_sha). Bukan klaim
     * keamanan — melainkan sidik jari hasil agar CI/auditor dapat membandingkan
     * dua receipt tanpa membaca prose. Kosong bila request gagal sebelum reduce. */
    char receipt_sha256[65];

/* --- arena bump milik hasil (Fase 5, MYC-AUDIT-008) --- */
    /* Penyimpanan teks yang dimiliki hasil: diagnostic message, dst. Seluruhnya
      * dibebaskan oleh myc_result_free. Menghapus static message ring
      * (penyebab data race + hasil basi). NULL bila arena belum dialokasikan.
      * Jangan disentuh langsung oleh caller. */
    struct myc_arena *arena;

    /* --- Counterexample Replay Capsule (#2) --- */
    /* Informasi lengkap untuk mereplay satu verifikasi run.
     * NULL bila capsule belum dibangun (request gagal sebelum pipeline).
     * Dibebaskan oleh myc_result_free(). */
    myc_replay_capsule *capsule;

    /* --- Differential Backend Quorum (#3) --- */
    /* Hasil quorum: apakah semua backend yang tersedia setuju.
     * QUORUM_CLEAN: SEMUA backend SETUJU -- bisa bersepakat clean ATAU
     *   bersepakat findings (periksa quorum_report untuk arahnya; nama
     *   "clean" = konsensus, bukan "kode bersih").
     * QUORUM_CONFLICT: backend bertentangan (ada yang findings, ada yang clean).
     * QUORUM_INCONCLUSIVE: salah satu backend inconclusive/unavailable, atau
     *   tidak ada hasil backend sama sekali.
     * QUORUM_NOT_REQUESTED: quorum tidak diminta. */
    myc_quorum_status quorum_status;
    char *quorum_report;    /* teks laporan konflik, freed oleh arena */
} myc_result;

/* Nama debt type (statis). */
const char *myc_debt_type_name(myc_debt_type t);

/* --- API --- */

/* Siapkan request dengan nilai default. */
void myc_request_init(myc_request *req);

/* Validasi request; mengembalikan error code atau NONE. */
myc_error_code myc_request_validate(const myc_request *req);

/* Siapkan result dengan alokasi internal. Harus dibebaskan myc_result_free. */
void myc_result_init(myc_result *res);
void myc_result_free(myc_result *res);

/* Arena milik hasil (Fase 5, MYC-AUDIT-008): alokasikan buffer di arena yang
 * dimiliki res; dibebaskan bersamaan dengan myc_result_free. Mengembalikan
 * NULL_out bila OOM. string_len = 0 menyalin sampai NUL (seperti strdup).
 * Dipakai modul internal supaya tidak menyimpan diagnostic ke static ring. */
char *myc_result_arena_dup(myc_result *res, const char *s, size_t string_len);

/* Jalankan pipeline penuh pada request. Mengisi res. */
void myc_run(const myc_request *req, myc_result *res);

/* Output teks / JSON hasil ke stdout. */
void myc_report_text(const myc_result *res);
void myc_report_json(const myc_result *res);

/* Nama error code (statis). */
const char *myc_error_name(myc_error_code c);
const char *myc_verdict_name(myc_verdict v);
const char *myc_assurance_name(myc_assurance a);
const char *myc_finding_name(myc_finding f);
const char *myc_claim_status_name(myc_claim_status c);

/* Gate status API (Fase 3). */
void myc_gate_set_status(myc_result *res,
                         myc_gate_id id,
                         myc_gate_status status,
                         const char *output);
const myc_gate_result *myc_gate_get(const myc_result *res, myc_gate_id id);
void myc_reduce_verdict(myc_result *res);
void myc_result_add_evidence(myc_result *res,
                             myc_gate_id gate,
                             myc_evidence_type type,
                             const char *message);

/* Direktori yang memuat executable (tempat myc_buf.h diharapkan ada).
 * Mengembalikan string malloc'd atau NULL. Dipakai gate checked-build (D1.2)
 * untuk -I dan oleh MCP server (P9, mcp.exe). */
char *myc_exe_dirname(const char *argv0);

#ifdef __cplusplus
}
#endif

#endif /* MYC_H */
