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
#define MYC_MAX_STDIN_BYTES  (8u << 20)       /* 8 MiB: run_stdin (Fase 2) */
#define MYC_MAX_DIAGNOSTICS 128
#define MYC_DEFAULT_TIMEOUT_MS 30000
#define MYC_MAX_TIMEOUT_MS   600000           /* 10 menit */
#define MYC_MAX_OUTPUT_CAP_BYTES (100u << 20)  /* 100 MiB */

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

/* Assurance ladder (see AGENTS.md).
 * Catatan: ladder ini dipertahankan untuk backward compatibility,
 * tetapi verdict sebenarnya diturunkan dari typed gate status
 * melalui myc_reduce_verdict() (Fase 3). */
typedef enum {
    MYC_ASSURANCE_NONE = 0,
    MYC_ASSURANCE_L0_RAW,
    MYC_ASSURANCE_L1_SANE,
    /* MYC-AUDIT-013: label lama "PROVEN" terlalu kuat. Eva adalah abstract
     * interpretation: L2 EVA = TIDAK ada alarm RTE di bawah model/default
     * entry (bukan proof obligation WP, bukan "kontrak terbukti"). Detail
     * tool/versi/model/entry ada di blok prove laporan. */
    MYC_ASSURANCE_L2_EVA,
    MYC_ASSURANCE_L3_RUNTIME,
    MYC_ASSURANCE_L4_SPATIAL,
    /* MYC-AUDIT-013: label lama "FULL" melebihi bukti. Fil-C clean run
     * membuktikan eksekusi terkendali tertentu bersih, bukan "full". */
    MYC_ASSURANCE_L5_FILC
} myc_assurance;

/* ------------------------------------------------------------------ */
/* Assurance vector / evidence lattice (MYC-AUDIT-006, roadmap 5.7)    */
/* ------------------------------------------------------------------ */
/* Scalar L1-L5 legacy menggabungkan bukti yang ORTHOGONAL (compile,
 * static, runtime, checked, proof, driver, fil-c) menjadi urutan total
 * max(level) -- menghilangkan informasi. Vector ini memecah assurance
 * per dimensi, TURUNAN MURNI dari typed gate status (bukan klaim baru).
 * Dihitung di myc_reduce_verdict(); dipakai laporan teks + JSON. */
typedef enum {
    MYC_DIM_NOT_REQUESTED = 0, /* tidak ada gate dim yang diminta/dijalankan */
    MYC_DIM_NOT_APPLICABLE,    /* gate dim diminta tapi NOT_APPLICABLE
                                  (mis. checked tanpa MYC_BUF, prove tanpa clang) */
    MYC_DIM_CLEAN,             /* semua gate dim COMPLETED_CLEAN */
    MYC_DIM_FINDINGS,          /* ada gate dim COMPLETED_FINDINGS */
    MYC_DIM_INCONCLUSIVE,      /* ada gate dim INCONCLUSIVE/UNAVAILABLE/INFRA_FAILED */
    MYC_DIM_OBSERVATIONS       /* gate dim COMPLETED_OBSERVATIONS (benign) */
} myc_dim_status;

typedef enum {
    MYC_DIM_COMPILE = 0,  /* C: compile diagnostics (preprocess + gcc -c + lint) */
    MYC_DIM_STATIC,       /* S: static analysis (gcc -fanalyzer) */
    MYC_DIM_RUNTIME,      /* R: runtime observation (clang ASan+UBSan, metamorphic) */
    MYC_DIM_CHECKED,      /* B: checked-buffer coverage (MYC_BUF fat-pointer) */
    MYC_DIM_PROOF,        /* P: proof obligations (Frama-C Eva, abstract interp.) */
    MYC_DIM_DRIVER,       /* D: generated-driver coverage (D2.2) */
    MYC_DIM_FILC,         /* F: Fil-C execution evidence (D4.1) */
    MYC_DIM_COUNT
} myc_assurance_dim;

typedef struct {
    myc_dim_status status[MYC_DIM_COUNT];
} myc_assurance_vector;

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
    MYC_GATE_LINT,           /* (14) lint memory-safety heuristik: HANYA
                                observasi + confidence (MYC-AUDIT-014),
                                non-blocking -- bukan finding terkonfirmasi */
    MYC_GATE_DIVERGENCE,     /* (Fase 4, A2/DS-02) cross-toolchain divergence:
                                matriks {gcc, clang, [tcc]} x {-O0,-O2};
                                klasifikasi semantic/diagnostic/sanitizer
                                divergence (hanya bukti sanitizer / witness
                                stabil = hard; sisanya observasi) */
    MYC_GATE_EXHAUSTIVE,     /* (Fase 5, A3/DS-03) small-domain exhaustive
                                proof: enumerasi PENUH domain fungsi
                                ber-kontrak yang terbatas (requires dengan
                                rentang integer lengkap, produk <= 1e6) =
                                bukti riil untuk domain dideklarasikan
                                (P1 EXHAUSTIVE). DS-03 domain firewall:
                                penyempitan domain vs run sebelumnya =
                                SCOPE_LAUNDERING (diagnostic). */
    MYC_GATE_COMPARE,        /* (Fase 5, A4/DS-04) differential oracle pair:
                                myc compare ref.c new.c [func...] --
                                baterai input bersama dijalankan pada KEDUA
                                versi, perilaku (return + errno + digest +
                                exit) dibandingkan per kasus. Semua identik
                                = behavior-preserving (P1 DIFF); ada
                                divergen = unexpected_change (finding).
                                DS-04 semantic delta escrow: ABI signature
                                + domain hash ikut dibandingkan. */
    MYC_GATE_STACK,          /* (Fase 5, C2/DS-10) stack budget analyzer:
                                gcc -fstack-usage (frame/fungsi) + call
                                graph dari source -> worst-case stack depth
                                per root vs --stack-budget; deteksi
                                rekursi (cycle) / alloca / VLA. Static
                                worst-case != dynamic; NON-blocking. */
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

/* --- sel matriks cross-toolchain divergence (Fase 4, A2/DS-02) ---
 * Satu kombinasi {toolchain} x {-O0,-O2}. `available=0` bila compiler
 * tidak ditemukan (sel di-skip). `built=1` + `ran=1` = sel benar-benar
 * dieksekusi. `finding` = bukti sanitizer (report log_path non-spoofable
 * ATAU marker + exit!=0). stdout_sha256 = hash trace stdout penuh untuk
 * deteksi semantic divergence (deterministik; env LC_ALL=C). */
typedef struct {
    char         tool[16];        /* "gcc" / "clang" / "tcc" */
    char         tool_path[260];  /* path absolut hasil myc_find_executable
                                     (fixed array agar aman di-copy untuk
                                     cache replay) */
    int          opt_level;       /* 0 = -O0, 1 = -O2 */
    int          available;       /* 0 = compiler tidak ditemukan */
    int          san;             /* 1 = build+run DENGAN sanitizer
                                     (finding bisa jadi bukti); 0 = tanpa
                                     sanitizer (fallback: toolchain tak
                                     punya ASan, mis. gcc MinGW) */
    int          built;           /* 1 = build sukses */
    int          ran;             /* 1 = exe dijalankan */
    int          timed_out;       /* 1 = run timeout */
    int          exit_code;       /* exit code run */
    int          finding;         /* 1 = bukti sanitizer pada sel ini */
    char         marker[80];      /* marker sanitizer atau "" */
    char         stdout_sha256[65]; /* sha256 hex trace stdout ("" bila
                                       tak tersedia) */
    int          diag_warn;       /* 1 = build menghasilkan warning */
} myc_divergence_cell;

#define MYC_DIVERGENCE_MAX_CELLS 8   /* 2 toolchains x 2 opt = 4; cadangan */

typedef enum {
    MYC_EVIDENCE_GATE_START = 0,
    MYC_EVIDENCE_GATE_END,
    MYC_EVIDENCE_DIAGNOSTIC,
    MYC_EVIDENCE_FINDING,
    MYC_EVIDENCE_SKIP,
    MYC_EVIDENCE_ERROR,
    MYC_EVIDENCE_CLEAN
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
    /* Fase 3, SOL-30: Assurance Budget Contract -- target assurance yang
     * diminta user/harness tidak tercapai dalam budget (gate wajib clean
     * tidak dijalankan / tidak tersedia / menemukan finding, atau budget
     * waktu/output dilampaui). Kode: MYC-INCOMPLETE-BUDGET-*. */
    MYC_DEBT_BUDGET,
    /* Fase 4, A1/DS-01: Assumption Closure -- ada asumsi portabilitas yang
     * BELUM ditutup (status observed/contradicted) padahal
     * --require-assumptions-closed diminta. Kode:
     * MYC-INCOMPLETE-ASSUMPTIONS-OPEN. */
    MYC_DEBT_ASSUMPTION,
    MYC_DEBT_COUNT
} myc_debt_type;

typedef struct {
    myc_debt_type type;
    const char   *text;   /* string statis penjelasan debt */
} myc_debt_item;

#define MYC_MAX_GATES      16
#define MYC_MAX_EVIDENCE   256
#define MYC_MAX_DEBT       32
#define MYC_MAX_FILC_CASES 8        /* rincian per-panic Fil-C (7.7) */
#define MYC_MAX_CONTRACT_CLAUSES 64 /* rincian per-klausa kontrak (7.4) */
#define MYC_MAX_DRIVER_CASES   32  /* budget kombinatorial per fungsi (7.5) */
#define MYC_MAX_DRIVER_RECORDS 256 /* total case records tersimpan (hasil) */

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
    MYC_ERR_INVALID_TIMEOUT,
    MYC_ERR_INVALID_OUTPUT_CAP,
    MYC_ERR_INVALID_CWD,
    MYC_ERR_STDIN_TOO_LARGE,
    MYC_ERR_PROCESS_TREE_CLEANUP_FAILED,
    MYC_ERR_RUNTIME_VIOLATION,
    MYC_ERR_PROVE_VIOLATION,
    MYC_ERR_FILC_VIOLATION,
    MYC_ERR_DRIVER_VIOLATION,
    MYC_ERR_CLANG_NOT_FOUND,
    MYC_ERR_INTERNAL
} myc_error_code;

/* Satu panic Fil-C terkonfirmasi (MYC-AUDIT-024, roadmap 7.7 per-case
 * scope). Lokasi berasal dari frame "semantic origin" report Fil-C:
 *   (module) /path/file.c:LINE:COL: func
 * String (message/file/function) disimpan di arena milik hasil. */
typedef struct {
    char *message;      /* pesan panic (mis. "cannot write pointer ...") */
    char *file;         /* file origin pertama (NULL bila tak terparse) */
    int   line, col;    /* lokasi origin (0 bila tak terparse) */
    char *function;     /* fungsi origin pertama (NULL bila tak terparse) */
} myc_filc_case;

/* Confidence diagnostic heuristik teks (MYC-AUDIT-014, roadmap 5.15):
 * scanner/lint berbasis token/text TIDAK boleh menghasilkan hard verdict
 * kecuali dikonfirmasi bukti SEMANTIK. Skala keyakinan:
 *   OBSERVATION < SUSPICIOUS < LIKELY < CONFIRMED
 * Hard failure hanya dari bukti semantik (compiler AST/dataflow, sanitizer,
 * proof counterexample, checked runtime) atau rule syntactic yang benar-benar
 * unambiguous. Diagnostic dari gcc = CONFIRMED; lint/negative = observasi. */
typedef enum {
    MYC_CONF_OBSERVATION = 0, /* pola terlihat, belum tentu masalah */
    MYC_CONF_SUSPICIOUS,      /* indikasi nyata, butuh konfirmasi semantik */
    MYC_CONF_LIKELY,          /* hampir pasti, belum bukti */
    MYC_CONF_CONFIRMED        /* bukti semantik / syntactic pasti */
} myc_confidence;

/* ------------------------------------------------------------------ */
/* B3: LLM Error Taxonomy (DS-07)                                      */
/* ------------------------------------------------------------------ */
/* Sumbu kedua klasifikasi finding: kelas KOGNITIF -- cara model biasanya
 * salah -- bukan hanya semantik C. Urutan enum = prioritas coaching
 * (kecil = diprioritaskan; lihat coach_priority di taxonomy.c).
 * Classifier rule-based, NON-blocking observasi. */
typedef enum {
    MYC_TAX_UNCLASSIFIED = 0,
    MYC_TAX_HALLUCINATED_API,   /* API dianggap lebih aman dari sebenarnya */
    MYC_TAX_MISSING_GUARD,      /* null-deref / unchecked alloc / uninit */
    MYC_TAX_OFF_BY_ONE,         /* batas loop/index salah satu */
    MYC_TAX_UB_ASSUMPTION,      /* implementation-defined / UB */
    MYC_TAX_TYPE_CONFUSION,     /* cast / signedness / lebar tipe */
    MYC_TAX_IGNORED_RETURN,     /* return value dibuang */
    MYC_TAX_WRONG_CONSTANT,     /* konstanta/batas salah */
    MYC_TAX_CHURN,              /* mengubah kode yang tidak terkait */
    MYC_TAX_COUNT
} myc_taxonomy_class;

/* Satu item coaching (tersimpan di res->coaching[]). String where di
 * arena milik hasil. */
typedef struct {
    myc_taxonomy_class cls;
    int   line;                  /* 0 bila tak tersedia */
    char *where;                 /* arena: ringkasan lokasi + pesan */
} myc_coaching_item;

#define MYC_MAX_COACHING 10

/* Status klausa kontrak (MYC-AUDIT-025, roadmap 7.4): hasil validasi
 * ekspresi kontrak-lite. Purity adalah SYARAT inject: klausa ber-efek
 * samping TIDAK pernah di-inject sebagai assert (safety). */
typedef enum {
    MYC_CLAUSE_OK = 0,      /* ekspresi valid + pure (layak inject) */
    MYC_CLAUSE_EMPTY,       /* ekspresi kosong (ditolak) */
    MYC_CLAUSE_TOO_LONG,    /* melebihi buffer (ditolak, no silent truncate) */
    MYC_CLAUSE_IMPURE,      /* efek samping: assignment / ++ / -- / comma */
    MYC_CLAUSE_CALL         /* pemanggilan fungsi: purity tak terbukti */
} myc_clause_status;

/* Satu klausa kontrak //@ requires/ensures ter-parse (MYC-AUDIT-025).
 * String (expr/func) disimpan di arena milik hasil. */
typedef struct {
    char *expr;             /* ekspresi kontrak */
    char *func;             /* nama fungsi terikat (stable binding);
                               "" bila tidak terikat ke fungsi */
    myc_clause_status status;
    int   line, col;        /* lokasi klausa di source */
    int   kind;             /* 0 = requires, 1 = ensures */
} myc_contract_clause;

/* Satu kasus uji driver ter-record (roadmap 7.5 "case record").
 * Merekam INPUT yang benar-benar diuji — parameter values + allocation
 * sizes — plus status eksekusi (guard requires lolos / dilewati).
 * String (func/params) disimpan di arena milik hasil; bila disalin ke
 * capsule, di-strdup. `case_id` = nomor global 1-based lintas fungsi. */
typedef struct {
    char *func;        /* nama fungsi ber-kontrak yang diuji */
    char *params;      /* ringkasan argumen deterministik, mis. "n=4, a=16B" */
    long  alloc_bytes; /* total bytes dialokasikan utk parameter pointer */
    int   case_id;     /* 1-based (global lintas fungsi) */
    int   executed;    /* 1 = dieksekusi, 0 = dilewati guard requires */
} myc_driver_case;

/* Satu pelanggaran / diagnostic yang ditemukan scanner atau gcc. */
typedef struct {
    int            line;       /* 1-based; 0 bila tidak tersedia */
    int            col;        /* 1-based; 0 bila tidak tersedia */
    const char    *message;    /* string statis, tidak dimiliki struct ini */
    myc_confidence confidence; /* tingkat keyakinan (heuristik vs semantik) */
} myc_diagnostic;

/* Canonical ingress (Fase 2, MYC-AUDIT-029): satu cara formal untuk
 * menyatakan input program. Setelah ingress, pipeline HANYA menerima
 * source in-memory (MYC_SOURCE_MEMORY). File/STDIN di-load terpusat oleh
 * myc_source_load() dengan cap + policy NUL + error typed. */
typedef enum {
    MYC_SOURCE_MEMORY = 0, /* data/len diisi (bytes C, boleh ber-NUL) */
    MYC_SOURCE_FILE,       /* file_path diisi */
    MYC_SOURCE_STDIN       /* baca stdin saat load */
} myc_source_kind;

typedef struct {
    myc_source_kind kind;
    const char     *data;      /* MEMORY: bytes; FILE/STDIN: NULL */
    size_t          len;       /* MEMORY: panjang byte; FILE/STDIN: 0 */
    const char     *file_path; /* FILE: path; MEMORY/STDIN: NULL */
} myc_source_input;

/* --- Assurance Budget Contract (Fase 3, SOL-30) ---
 * Level target per gate dalam kontrak --budget-contract. Definisi tipe
 * ada di myc.h (bukan budget.h) karena myc_request memuatnya by-value
 * dan budget.h hanya berisi fungsi API (menghindari include circular). */
typedef enum {
    MYC_BUDGET_UNSET = 0,   /* gate tidak disebut dalam kontrak */
    MYC_BUDGET_CLEAN,       /* gate WAJIB completed_clean (target) */
    MYC_BUDGET_OPTIONAL     /* gate boleh dijalankan bila tersedia */
} myc_budget_level;

/* Satu kontrak budget. `active=1` artinya user meminta target ini;
 * `max_time_ms`/`max_output_bytes` 0 = tidak dibatasi. Disimpan
 * per-value di myc_request (bukan pointer) supaya request tetap
 * stack-friendly; `raw` (representasi teks kontrak, malloc'd) di-free
 * oleh caller yang mengalokasikannya (myc.c main / MCP). */
typedef struct myc_budget_contract {
    int  active;
    myc_budget_level level[MYC_GATE_COUNT]; /* per gate id */
    int  max_time_ms;
    int  max_output_bytes;
    char *raw;   /* representasi asli kontrak (untuk laporan), malloc'd */
} myc_budget_contract;

/* --- Assumption Closure (Fase 4, A1 + DS-01) ---
 * Ledger asumsi: fakta implementation-defined yang DI-PERTARUHKAN source
 * (signedness char, lebar int, endianness bit-field, alignment cast,
 * sizeof), disandingkan dengan kebenaran toolchain host (macro dump
 * `gcc -dM -E`). Observasi NON-blocking: verdict TIDAK pernah turun
 * karena asumsi, kecuali --require-assumptions-closed diminta (DS-01:
 * asumsi terbuka = gap verifikasi -> INCONCLUSIVE + debt).
 * Lifecycle per asumsi (DS-01): observed -> declared / tested /
 * contradicted / eliminated / accepted-risk. Status dipersisten di
 * .myc/assumptions.json agar run kedua bisa menunjukkan asumsi mana
 * yang sudah ditutup; `--assumption-ack id:status` menutup tanpa
 * menghilangkan asumsi dari receipt. */
#define MYC_MAX_ASSUMPTIONS 32

typedef enum {
    MYC_ASM_OBSERVED = 0,      /* terdeteksi, belum ditindaklanjuti */
    MYC_ASM_DECLARED,          /* ketergantungan disengaja (di-ack) */
    MYC_ASM_TESTED,            /* sudah diuji pada target relevan */
    MYC_ASM_CONTRADICTED,      /* target lain mengubah perilaku (masih terbuka) */
    MYC_ASM_ELIMINATED,        /* kode diubah, tak lagi bergantung */
    MYC_ASM_ACCEPTED_RISK      /* pengguna menerima keterikatan target */
} myc_assumption_status;

/* Satu asumsi terdeteksi. String (id/kind/anchor/host_fact/risk/
 * next_action) disimpan di arena milik hasil (myc_result_arena_dup). */
typedef struct {
    char *id;           /* asm-<kind>-<8 hex sha256(anchor)> */
    char *kind;         /* char-signedness | int-width | bitfield-endian |
                           alignment-cast | sizeof-assumption */
    int   line;         /* 1-based */
    char *anchor;       /* <fungsi>:<line>:<hash window> (stabil) */
    char *host_fact;    /* fakta toolchain INI, mis. "char=signed" */
    char *risk;         /* risiko di target lain */
    char *next_action;  /* saran perbaikan untuk LLM */
    int   status;       /* myc_assumption_status (persisten lintas run) */
    int   confidence;   /* 0..100 (observasi) */
} myc_assumption;

/* Fakta target toolchain host hasil `gcc -dM -E` (predefined macros).
 * Disimpan per-value di myc_result (dan di cache entry SOL-18) agar
 * cache-hit TIDAK perlu mengeksekusi gcc ulang. `ok=1` bila macro dump
 * berhasil dibaca (gcc tersedia). */
typedef struct {
    int  ok;             /* facts berhasil dibaca */
    int  char_unsigned;  /* __CHAR_UNSIGNED__ terdefinisi */
    int  int_bits;       /* 8 * __SIZEOF_INT__ (0 = tak diketahui) */
    int  ptr_bits;       /* 8 * __SIZEOF_POINTER__ (0 = tak diketahui) */
    int  little_endian;  /* __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ */
    long stdc_version;   /* __STDC_VERSION__ (0 = tak diketahui) */
    int  char_bit;       /* CHAR_BIT (default 8) */
} myc_host_facts;

typedef struct {
    myc_source_input input;     /* sumber program: MEMORY/FILE/STDIN */
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
    int         prove;          /* gate Frama-C Eva (D3.1, L2 EVA, via WSL):
                                   abstract interpretation RTE, bukan WP proof */
    int         checked;        /* checked-build makro (D1.2, L4 SPATIAL):
                                   bangun 2x (produksi T* + -DMYC_CHECKED fat) */
    const char *checked_header_dir; /* direktori berisi myc_buf.h (biasanya
                                       dir myc.exe); NULL = cari via -I cwd */
    int         filc;           /* gate Fil-C (D4.1, L5 FILC, opsional):
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
    int         divergence;     /* gate Cross-Toolchain Divergence (Fase 4,
                                    A2/DS-02): bangun+jalankan source sama
                                    dengan {gcc, clang, [tcc]} x {-O0,-O2},
                                    bandingkan sanitizer + trace stdout penuh
                                    + set warning; divergensi diklasifikasi
                                    (semantic/diagnostic/sanitizer). Non-
                                    blocking: kompiler kedua absen = skip. */
    int         require_complete; /* 9.10 Silence Is a Finding: bila set,
                                     verification gap (unverified_debt) membuat
                                     hasil gagal (verdict INCONCLUSIVE, exit 1)
                                     -- bukan kesunyian */
    int         json_summary;     /* --json-summary: output JSON ringkas
                                     (tanpa stdout/stderr/fingerprint) untuk
                                     agent LLM */
     int         no_cache;        /* --no-cache: matikan incremental evidence
                                     cache (SOL-18); default 0 = cache ON */
     int         agent;            /* --agent: output protokol agent
                                      (myc.agent.v2) untuk konsumsi LLM */
     int         write_repro;     /* --write-repro: tulis .myc-witness/ repro dir */
     int         tx_verify;       /* --tx-verify: verifikasi patch dalam transaksi */
     char       *tx_finding_id;   /* --finding-id ID: finding target */
     char       *tx_edit_region;  /* --edit-region R: region yang diizinkan diedit */
     /* --- Assurance Budget Contract (Fase 3, SOL-30) ---
      * Target assurance eksplisit yang diminta user/harness. `active=1`
      * bila kontrak diparse dari --budget-contract; enforcement di
      * myc_budget_enforce() (budget.c) di akhir myc_run: target tidak
      * tercapai -> verdict INCONCLUSIVE (bila masih OK) + debt
      * MYC_DEBT_BUDGET + budget_report rinci dimensi yang dikorbankan.
      * `raw` (malloc'd) dibebaskan caller (myc.c main). */
     myc_budget_contract budget; /* by-value; definisi di atas */

     /* --- Assumption Closure (Fase 4, A1 + DS-01) ---
      * require_assumptions_closed: --require-assumptions-closed — asumsi
      * terbuka (observed/contradicted) = gap verifikasi -> INCONCLUSIVE
      * + debt MYC-INCOMPLETE-ASSUMPTIONS-OPEN (pola 9.10).
      * assumption_acks: --assumption-ack "id:status,..." (malloc'd,
      * di-free caller myc.c main) — tutup asumsi terdeteksi tanpa
      * menghilangkannya dari receipt. no_assumptions: --no-assumptions
      * — matikan deteksi (default 0 = aktif, seperti --no-lint). */    int         require_assumptions_closed;
    char *assumption_acks;
    int  no_assumptions;
    /* Fase 5, A3 (--exhaustive): gate Small-Domain Exhaustive Proof. */
    int         exhaustive;
    /* Fase 5, A4: subcommand `myc compare ref.c new.c [func...]`. */
    char       *compare_ref_path;
    char       *compare_new_path;
    char      **compare_funcs;
    int         compare_nfuncs;
    /* Fase 5, C2 (--stack): stack budget analyzer. stack_budget = budget
     * target (bytes); default 4096 bila 0. */
    int         stack;
    int         stack_budget;
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
    int     require_complete; /* (9.10) flag require-complete */
    /* Fase 3, SOL-30: hasil enforcement budget contract */
    int     budget_active;
    int     budget_met;
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
    /* Divergence (Fase 4 A2/DS-02): ringkasan klasifikasi */
    int divergence_ran;         /* sel yang benar-benar dieksekusi */
    int divergence_sanitizer_div; /* HARD: satu sel finding, lain clean */
    int divergence_all_findings;  /* HARD: semua sel menemukan */
    int divergence_semantic_div;  /* observasi: stdout/exit beda */
    int divergence_diag_div;      /* observasi: set warning beda */
    /* Negative-space (9.8): hasil observasi */
    int negative_callsites;   /* total callsite alokasi terdeteksi */
    int negative_deviations;  /* jumlah yang tidak memeriksa hasil */
    /* Checked coverage (MYC-AUDIT-026): cakupan transformasi fat-pointer */
    int checked_buffers;      /* deklarasi MYC_BUF */
    int checked_allocations;  /* invokasi MYC_NEW */
    int checked_accesses;     /* invokasi MYC_AT */
    int checked_frees;        /* invokasi MYC_FREE */
    /* Driver (roadmap 7.5): ringkasan + per-case record untuk replay.
     * String di-strdup (capsule dibebaskan myc_result_free). */
    int driver_funcs;
    int driver_cases;
    int driver_skipped;
    int driver_case_count;
    char *driver_harness_sha256;   /* hash source harness yang dibangun */
    long  driver_max_product;
    int   driver_bounded;
    myc_driver_case driver_case_records[MYC_MAX_DRIVER_RECORDS];
    /* Gate summary (one status per gate) */
    myc_gate_status gate_status[MYC_GATE_COUNT];
    /* Finding / completeness / claim */
    myc_finding finding;
    myc_completeness completeness;
    myc_claim_status claim_status;
    /* Differential Backend Quorum (#3) */
    myc_quorum_status quorum_status;
} myc_replay_capsule;

/* --- Witness Pipeline (Fase 1) --- */
/* Setiap hard finding harus disertai witness yang dapat direplay.
 * Witness berisi reproducer, causal slice, dan violation info. */
#define MYC_MAX_WITNESS_ARGV 8

typedef struct {
    /* Reproducer */
    char *source;           /* source penuh atau slice */
    size_t source_len;
    char *stdin_data;       /* stdin input (NULL bila tidak ada) */
    size_t stdin_len;
    char *argv[MYC_MAX_WITNESS_ARGV]; /* argv tambahan */
    int   argc;

    /* Causal slice */
    char *slice_file;       /* nama file asli */
    int   slice_line_start; /* baris awal slice */
    int   slice_line_end;   /* baris akhir slice */

    /* Violation info */
    char *violation_kind;   /* "use-after-free", "OOB", "null-deref", dst */
    char *violation_msg;    /* pesan lengkap dari backend */
    int   violation_line;   /* baris pelanggaran */
    int   violation_col;    /* kolom pelanggaran */

    /* Backend provenance */
    char *backend;          /* "gcc", "clang-asan", "eva", "fil-c", "driver" */
    char *backend_version;  /* "gcc 13.2", "frama-c 33.0", dst */

    /* Kronologi pelanggaran (Fase 1, pre-state → operation → violation).
     * pre_state : keadaan sebelum pelanggaran (mis. "p freed at line 7")
     * operation : operasi yang melanggar (mis. "access p[10] out of bounds")
     * Agar LLM memahami urutan kronologis, bukan hanya titik pelanggaran. */
    char *pre_state;        /* deskripsi keadaan awal, NULL bila tidak diketahui */
    char *operation;        /* deskripsi operasi pelanggaran, NULL bila tidak diketahui */
} myc_witness;

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
    int         prove_proof_obligations; /* jumlah "proof obligation" (Task 11) */
    char       *prove_stdout_text;      /* output frama-c -eva */
    char       *prove_stderr_text;
    char       *prove_version;          /* versi Frama-C dari banner (arena) */
    const char *prove_mode;             /* adapter: "eva" (abstract interpretation) */

    char       *resolved_gcc;           /* canonical executable identity */
    /* Exact tool identity (MYC-AUDIT-022, roadmap 7.1): baris pertama
     * `<exe> --version` untuk backend yang benar-benar dipakai. NULL
     * bila tool tidak tersedia / versi tidak terbaca. */
    char       *gcc_version;
    char       *clang_version;
    char       *fingerprint;            /* canonical process fingerprint */
    char       *source_sha256;          /* stdin content hash */

    myc_diagnostic diags[MYC_MAX_DIAGNOSTICS];
    int         diag_count;

    /* --- hasil contract-lite (D1.5, P7) --- */
    int         contract_requires;      /* jumlah //@ requires terbaca */
    int         contract_ensures;       /* jumlah //@ ensures terbaca */
    /* MYC-AUDIT-025 (roadmap 7.4): explicit clause status + stable
     * function binding + purity per klausa. String di arena milik hasil;
     * clause_count dibatasi MYC_MAX_CONTRACT_CLAUSES (hitungan total
     * tetap di contract_requires/ensures). */
    myc_contract_clause contract_clauses[MYC_MAX_CONTRACT_CLAUSES];
    int         contract_clause_count;

    /* --- Fase 5, B4 (Comments-as-Contracts, DS-08) ---
     * Panen kandidat kontrak dari komentar BIASA (bukan //@):
     *   candidate  = pola bahasa terdeteksi (deterministik, bukan NLP);
     *   validated  = ekspresi C murni (contract_expr_purity) + terikat
     *                fungsi berikutnya (find_func_binding);
     *   unbound    = ekspresi murni tapi tak terikat ke fungsi;
     *   harvest_report (arena) = rincian per kandidat (line, func,
     *                ekspresi, status). NON-blocking: observasi murni,
     *                verdict tidak pernah turun karenanya. */
    int         harvest_candidates;   /* pola terdeteksi */
    int         harvest_validated;    /* pure + terikat fungsi */
    int         harvest_unbound;      /* pure tapi tak terikat */
    char       *harvest_report;       /* arena */

    /* --- Fase 5, B3 (LLM Error Taxonomy + coaching transcript, DS-07) ---
     * Klasifikasi kognitif tiap finding + transcript untuk dibaca model.
     * coaching[] (arena where), coaching_class_count[] per kelas,
     * coaching_report = transcript teks (arena). NON-blocking observasi.
     * Dibangun oleh myc_coach_build() (taxonomy.c) di akhir myc_run. */
    myc_coaching_item coaching[MYC_MAX_COACHING];
    int               coaching_count;
    int               coaching_class_count[MYC_TAX_COUNT];
    char             *coaching_report;   /* arena */

    /* --- hasil checked build (D1.2, P8, --checked) --- */
    int         ran_checked;            /* 1 bila gate checked-build dijalankan */
    int         checked_uses_buf;       /* 1 bila source memakai makro MYC_BUF */
    int         checked_build_ok;       /* 1 bila build -DMYC_CHECKED lolos */
    /* MYC-AUDIT-026 (roadmap 7.3): coverage count transformasi fat-pointer.
     * Jumlah deklarasi/invokasi makro checked-build yang terdeteksi di source
     * (di luar komentar/string) — bukti CAKUPAN gate L4: berapa buffer dan
     * berapa titik akses yang tercakup disiplin MYC_AT. */
    int         checked_buffers;        /* deklarasi MYC_BUF(T) b; */
    int         checked_allocations;    /* invokasi MYC_NEW */
    int         checked_accesses;       /* invokasi MYC_AT (akses yang dicek) */
    int         checked_frees;          /* invokasi MYC_FREE */

    /* --- hasil gate Fil-C (D4.1, P8, --filc) --- */
    int         ran_filc;               /* 1 bila gate Fil-C dijalankan */
    int         filc_panics;            /* jumlah panic terkonfirmasi
                                           (MYC-AUDIT-024: baris kanonik
                                           "[pid] filc panic:", fallback blok
                                           "filc safety error:") */
    /* MYC-AUDIT-024 (roadmap 7.7 version identity): baris pertama
     * `filc-clang --version` (mis. "clang version 20.1.8 (Fil-C 0.681 ...)").
     * NULL bila tidak tersedia / tidak terbaca. Malloc'd, di-free
     * myc_result_free (pola gcc_version/clang_version). */
    char       *filc_version;
    /* Per-case scope (roadmap 7.7): rincian tiap panic terkonfirmasi,
     * hasil parsing STRUKTURAL report Fil-C (bukan hitung marker).
     * String di arena milik hasil; hanya N case pertama disimpan. */
    myc_filc_case filc_cases[MYC_MAX_FILC_CASES];
    int         filc_case_count;        /* banyak case tersimpan (<= MAX) */
    char       *filc_stdout_text;       /* output program Fil-C */
    char       *filc_stderr_text;

    /* --- hasil gate driver-generator (D2.2, --driver) --- */
    int         ran_driver;             /* 1 bila gate driver dijalankan */
    int         driver_funcs;           /* jumlah fungsi ber-kontrak dipanggil */
    int         driver_cases;           /* jumlah kasus tepi tereksekusi */
    int         driver_skipped;         /* jumlah kasus dilewati guard */
    char       *driver_stdout_text;     /* output harness (DRIVER run=...) */
    char       *driver_stderr_text;
    /* Roadmap 7.5 (case record): rincian tiap kasus yang diuji.
     * String di arena milik hasil; case_count dibatasi
     * MYC_MAX_DRIVER_RECORDS (hitungan exact tetap di driver_cases). */
    myc_driver_case driver_case_records[MYC_MAX_DRIVER_RECORDS];
    int             driver_case_count;
    char           *driver_harness_sha256; /* hash source harness (replay) */
    /* Roadmap 7.5 (combinatorial budget): produk kartesian terbesar di
     * seluruh fungsi (sebelum budget) + apakah budget memotong (bila
     * memotong, tiap nilai kandidat tetap muncul minimal sekali). */
    long            driver_max_product;
    int             driver_bounded;

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

    /* --- hasil gate cross-toolchain divergence (Fase 4, A2/DS-02) ---
     * divergence_ran = sel yang benar-benar dieksekusi (build+run sukses),
     * divergence_planned = sel non-unavailable. Klasifikasi DS-02:
     * sanitizer_div=1 (satu sel finding, lainnya clean -> HARD),
     * all_findings=1 (semua sel menemukan — bug konsisten, hard),
     * semantic_div=1 (stdout/exit beda tanpa sanitizer -> observasi),
     * diag_div=1 (set warning build beda -> observasi). divergence_report
     * = tabel matriks (arena). */
    int            ran_divergence;
    int            divergence_ran;
    int            divergence_planned;
    int            divergence_sanitizer_div;
    int            divergence_all_findings;
    int            divergence_semantic_div;
    int            divergence_diag_div;
    char          *divergence_report;   /* arena */
    myc_divergence_cell divergence_cells[MYC_DIVERGENCE_MAX_CELLS];
    int            divergence_ncells;   /* sel terisi (valid) */

    /* --- hasil lint memory-safety heuristik (P5; MYC-AUDIT-014) --- */
    /* Jumlah observasi heuristik (bukan finding terkonfirmasi).
     * Non-blocking: lint TIDAK pernah menurunkan verdict; hard evidence
     * hanya dari gate semantik (gcc AST/dataflow, sanitizer, dll). */
    int         lint_observations;

    /* --- 9.10 Silence Is a Finding (--require-complete) --- */
    /* Apakah require-complete diminta (untuk laporan). Enforcement
     * dilakukan di myc_run(): gap verifikasi (debt) -> INCONCLUSIVE. */
    int         require_complete;

    /* --- Incremental Evidence Cache (Fase 3, SOL-18) ---
     * cache_hit=1 bila hasil di-replay dari .myc/evidence_cache.json
     * (bukan dihitung ulang); cache_delta_report = string "N fungsi
     * berubah, M identik, dependents" untuk source yang BERUBAH
     * (malloc'd, di-free myc_result_free). */
    int         cache_hit;
    char       *cache_delta_report;

    /* --- Assurance Budget Contract (Fase 3, SOL-30) ---
     * Hasil enforcement: budget_active=1 bila kontrak dipakai;
     * budget_met=1 bila SEMUA target tercapai; budget_report = teks
     * rinci per-gate ("tercapai (clean)" / "TIDAK tercapai (...)" +
     * dimensi dikorbankan) di arena milik hasil. */
    int         budget_active;
    int         budget_met;
    char       *budget_report;

    /* --- Assumption Closure (Fase 4, A1 + DS-01) ---
     * Hasil ledger asumsi (arena-based strings): host_facts (fakta
     * toolchain), assumptions[] (deteksi, status persisten), unclosed
     * (jumlah status observed/contradicted), ok (1 = tak ada yang
     * terbuka), ack_applied (jumlah ack diterapkan run ini),
     * assumption_report = teks ledger untuk laporan. */
    int            assumption_facts_ok;
    myc_host_facts host_facts;
    int            assumption_detected;  /* total terdeteksi (bisa > tersimpan) */
    int            assumption_count;     /* jumlah tersimpan (<= MAX) */
    myc_assumption assumptions[MYC_MAX_ASSUMPTIONS];
    int            assumption_unclosed;  /* status observed/contradicted */
    int            assumption_ok;        /* 1 = tidak ada asumsi terbuka */
    int            assumption_ack_applied;
    char          *assumption_report;    /* arena */

    /* --- Fase 5, A3 (Small-Domain Exhaustive Proof, --exhaustive) ---
     * Hasil gate: ran_exhaustive=1 bila dijalankan; exhaustive_funcs =
     * jumlah fungsi domain kecil; exhaustive_cases/skipped = titik domain
     * tereksekusi/dilewati guard; exhaustive_points = total titik domain
     * (produk kartesian); exhaustive_domain_hash = sha256 spec domain;
     * exhaustive_laundering = 1 bila domain dipersempit vs run sebelumnya
     * (DS-03 SCOPE_LAUNDERING); report/harness_sha/stdout/stderr. */
    int            ran_exhaustive;
    int            exhaustive_funcs;
    int            exhaustive_cases;
    int            exhaustive_skipped;
    long           exhaustive_points;
    int            exhaustive_laundering;
    char           exhaustive_domain_hash[65];
    char          *exhaustive_report;        /* arena */
    char          *exhaustive_harness_sha256;/* malloc'd, freed result_free */
    char          *exhaustive_stdout_text;   /* malloc'd, freed result_free */
    char          *exhaustive_stderr_text;   /* malloc'd, freed result_free */
    /* --- Fase 5, A4 (differential oracle pair, DS-04) ---
     * ran_compare=1 setelah myc_compare_gate dijalankan (subcommand
     * `myc compare`). compare_funcs/cases = fungsi & kasus yang
     * dibandingkan; identical = kasus dengan perilaku sama (ret + errno +
     * output digest + exit); divergent = unexpected_change. preserved=1
     * bila semua identik (behavior-preserving, P1 DIFF). delta = daftar
     * kasus divergen (teks, arena). abi_same = ABI signature identik;
     * domain_same = domain hash identik. unobserved = fungsi yang tak
     * bisa dibandingkan (pointer return / void? / tak ada di kedua file).
     * compare_report = laporan ringkas (arena). */
    int            ran_compare;
    int            compare_funcs;
    long           compare_cases;
    long           compare_identical;
    long           compare_divergent;
    int            compare_preserved;
    int            compare_abi_same;
    int            compare_domain_same;
    int            compare_unobserved;
    char          *compare_report;           /* arena */
    char          *compare_delta;            /* arena */
    char           compare_ref_digest[65];   /* sha256 stdout ref */
    char           compare_new_digest[65];   /* sha256 stdout new */
    /* --- Fase 5, C2 (--stack, DS-10) ---
     * ran_stack=1 setelah analisis; stack_worst_bytes = worst-case
     * static depth dari root; stack_worst_path (arena); recursion =
     * cycle di call graph (stack tak terbatas); alloca/VLA = komponen
     * dinamis tak terhitung; unknown = panggilan ke fungsi tanpa frame
     * .su; stack_report (arena). NON-blocking observasi. */
    int            ran_stack;
    long           stack_worst_bytes;
    int            stack_budget;
    int            stack_recursion;
    int            stack_alloca;
    int            stack_vla;
    int            stack_unknown;
    char          *stack_worst_path;   /* arena */
    char          *stack_report;       /* arena */

    /* internal: gate mana yang dijalankan terakhir */
    int         ran_preprocess;
    int         ran_compile;
    int         ran_analyzer;

    /* --- typed gate status (Fase 3) --- */
    myc_gate_result gates[MYC_MAX_GATES];
    size_t          gate_count;

    /* --- assurance vector (MYC-AUDIT-006) ---
     * Status per dimensi evidence, turunan dari gates[] (dihitung di
     * myc_reduce_verdict). Menggantikan scalar L1-L5 sebagai ringkasan
     * jujur: tiap dimensi orthogonal, tidak di-max-kan. */
    myc_assurance_vector assurance_vector;

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

    /* --- Witness Pipeline (Fase 1) --- */
    /* Witness untuk hard finding: reproducible reproduction info.
     * NULL bila tidak ada hard finding atau witness belum dibangun. */
    myc_witness *witness;

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

    /* --- Temporal Ledger (Fase 2, roadmap 7.2) --- */
    /* Receipt chain: hash run sebelumnya untuk source yang sama.
     * NULL bila run pertama kali. Dibebaskan oleh myc_result_free. */
    char *receipt_parent;   /* parent receipt_sha256 (chain) */
    /* Delta vs run sebelumnya: fixed/new/persistent/churn */
    int  ledger_parent_found; /* 1 = ditemukan parent di .myc/ledger.json */
    char *delta_kind;       /* "fixed" / "new" / "persistent" / "churn" */
    char *delta_gate;       /* gate yang berubah */
    int  delta_changed;     /* 1 jika ada perubahan dari run sebelumnya */
} myc_result;

/* Nama debt type (statis). */
const char *myc_debt_type_name(myc_debt_type t);

/* Kode finding gap verifikasi (9.10): "MYC-INCOMPLETE-XXX" per debt type.
 * Dipakai laporan teks/JSON agar CI/auditor dapat memfilter gap. */
const char *myc_debt_code(myc_debt_type t);

/* Bangun ulang receipt (9.10) setelah perubahan verdict pasca-reduce
 * (mis. enforcement require-complete). Hash ulang saja, bukan reducer. */
void myc_rebuild_receipt(myc_result *res);

/* --- API --- */

/* Siapkan request dengan nilai default. */
void myc_request_init(myc_request *req);

/* Validasi request; mengembalikan error code atau NONE. */
myc_error_code myc_request_validate(const myc_request *req);

/* MYC-AUDIT-029 (Fase 2): muat input canonical ke memory. Untuk
 * MYC_SOURCE_MEMORY mengembalikan (data,len) asli tanpa alokasi (return 0);
 * untuk FILE/STDIN mengalokasikan buffer (caller free) + cap + NUL policy.
 * Return myc_error_code: NONE / INVALID_REQUEST / INVALID_PATH /
 * INPUT_TOO_LARGE / NUL_IN_INPUT / INTERNAL. Untuk MEMORY, *out mengarah ke
 * req->input.data (bukan milik caller); untuk FILE/STDIN caller harus free. */
myc_error_code myc_source_load(const myc_source_input *in,
                               const char **out, size_t *out_len,
                               int *needs_free);

/* Siapkan result dengan alokasi internal. Harus dibebaskan myc_result_free. */
void myc_result_init(myc_result *res);
void myc_result_free(myc_result *res);

/* Witness Pipeline (Fase 1): inisialisasi dan bebaskan witness.
 * CATATAN OWNERSHIP: seluruh string di dalam myc_witness dialokasikan
 * dari ARENA milik hasil (myc_result_arena_dup) dan dibebaskan utuh oleh
 * myc_result_free -- myc_witness_free HANYA zero-kan struct (struct itu
 * sendiri di-malloc terpisah dan di-free oleh myc_result_free). Jangan
 * pernah mengisi field witness dengan malloc/strdup langsung. */
void myc_witness_init(myc_witness *w);
void myc_witness_free(myc_witness *w);

/* Arena milik hasil (Fase 5, MYC-AUDIT-008): alokasikan buffer di arena yang
 * dimiliki res; dibebaskan bersamaan dengan myc_result_free. Mengembalikan
 * NULL_out bila OOM. string_len = 0 menyalin sampai NUL (seperti strdup).
 * Dipakai modul internal supaya tidak menyimpan diagnostic ke static ring. */
char *myc_result_arena_dup(myc_result *res, const char *s, size_t string_len);

/* Portability: _strdup adalah MSVC/MinGW-only; POSIX memakai strdup (yang
 * butuh _DEFAULT_SOURCE/gnu11). Helper ini menggantikan seluruh pemakaian
 * _strdup agar myc ikut ter-build di POSIX (diperlukan test MYC-AUDIT-011
 * verify_descendants yang POSIX-only). Implementasi di myc.c; memeriksa
 * hasil malloc (idiom aman, lolos lint). Mengembalikan malloc'd copy atau
 * NULL bila OOM / s NULL. */
char *myc_strdup(const char *s);

/* Exact tool identity (MYC-AUDIT-022, roadmap 7.1): jalankan <exe>
 * --version, kembalikan baris pertama stdout sebagai string malloc'd,
 * atau NULL bila exec gagal / exit != 0 / tidak ada output. Implementasi
 * di proc.c (selalu di-link). Dipakai pipeline (gcc/clang) + `myc version`. */
char *myc_tool_version(const char *exe);

/* Jalankan pipeline penuh pada request. Mengisi res. */
void myc_run(const myc_request *req, myc_result *res);

/* Output teks / JSON hasil ke stdout. */
void myc_report_text(const myc_result *res);
void myc_report_json(const myc_result *res);
void myc_report_json_summary(const myc_result *res);

/* Nama error code (statis). */
const char *myc_error_name(myc_error_code c);
const char *myc_verdict_name(myc_verdict v);
const char *myc_assurance_name(myc_assurance a);
const char *myc_finding_name(myc_finding f);
const char *myc_claim_status_name(myc_claim_status c);
const char *myc_dim_status_name(myc_dim_status s);
/* Status klausa kontrak (MYC-AUDIT-025): "ok"/"empty"/"too_long"
 * /"impure"/"call" (statis). */
const char *myc_clause_status_name(myc_clause_status s);

/* Nama confidence diagnostic (MYC-AUDIT-014): "observation"/"suspicious"
 * /"likely"/"confirmed" (statis). */
const char *myc_confidence_name(myc_confidence c);

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
