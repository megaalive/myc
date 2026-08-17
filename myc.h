/*
 * myc.h -- Kontrak inti myc: request/result, verdict, gate_id, error.
 *
 * Struct gate/agent yang hanya dipakai 2-3 modul ada di header modul
 * (run.h, filc.h, driver.h, state.h, ...). myc.h include header itu
 * setelah enum verdict/gate_id agar myc_result tetap by-value.
 * myc_replay_capsule: forward-declare; definisi di report.h.
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

#include "alloc.h"

#define MYC_MAX_CODE_BYTES  (1u << 20)        /* 1 MiB */
#define MYC_MAX_OUTPUT_BYTES (1u << 20)       /* 1 MiB per channel */
#define MYC_MAX_STDIN_BYTES  (8u << 20)       /* 8 MiB: run_stdin (Fase 2) */
#define MYC_MAX_DIAGNOSTICS 128
#define MYC_DEFAULT_TIMEOUT_MS 30000
#define MYC_MAX_TIMEOUT_MS   600000           /* 10 menit */
#define MYC_MAX_OUTPUT_CAP_BYTES (100u << 20)  /* 100 MiB */
/* Fase 7 (privacy/size): batas atas --agent-payload-cap (1 MiB); 0 =
 * default MYC_AGENT_PAYLOAD_CAP (16384). Rentang sah: 0 | 1024..MAX. */
#define MYC_MIN_AGENT_PAYLOAD_CAP_BYTES 1024
#define MYC_MAX_AGENT_PAYLOAD_CAP_BYTES (1u << 20)

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
    MYC_GATE_FUZZ,            /* (Fase 5, D1/DS-13) fuzz gate fuzz-lite:
                                PRNG deterministik (seed tetap) + loop
                                terikat pada fungsi ber-kontrak, input
                                DIBATASI kontrak requires (keunggulan atas
                                fuzzer buta), dijalankan clang ASan/UBSan.
                                Crash = bukti (DRIVER_VIOLATION). */
    MYC_GATE_MUTATE,          /* (Fase 5, B5/DS-09) mutation-audited
                                verification: mem-mutasi kode dengan pola
                                error LLM lalu menjalankan ulang portfolio
                                gate; mutan yang tetap clean = coverage
                                gap (kelas bug tak terlihat). NON-blocking
                                observasi (mengukur verifier, bukan
                                verdict program). */
    MYC_GATE_FREESTANDING,    /* (Fase 5, C1) freestanding mode: compile
                                -ffreestanding -fno-builtin + hosted-API
                                trap (printf/malloc/fopen/exit dilarang di
                                firmware). Observasi NON-blocking. */
    MYC_GATE_MATRIX,          /* (Fase 5, C4) target matrix bare metal:
                                cross-compile (arm-none-eabi-gcc, riscv*-elf)
                                + macro dump per target, bandingkan dgn host:
                                signedness char, lebar pointer, endianness,
                                set warning -> portability matrix (asumsi
                                yang BERUBAH antar target). Observasi
                                NON-blocking; cross-compiler absen = sel
                                di-skip (host-only). */
    MYC_GATE_CONCUR,          /* (Fase 6) concurrency probe (--thread-probe):
                                lock-order statis (inversi urutan mutex =
                                potensi deadlock) + TSan runtime best-effort
                                (data race). NON-blocking observasi. */
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
    /* PR-018, P7-T01: batas resource lunak dilewati (cap + debt TERTYPE,
     * bukan crash / kesunyian). Terpicu saat counter scope mencapai
     * batasnya: evidence/finding/driver-cases/contract-clauses/diag,
     * atau output terpotong oleh cap. Kode: MYC-INCOMPLETE-RESOURCE-LIMIT.
     * NON-blocking: verdict TIDAK pernah turun hanya karena limit lunak;
     * --require-complete menaikkannya (pola 9.10). */
    MYC_DEBT_RESOURCE_LIMIT,
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
    MYC_ERR_INVALID_TIMEOUT,
    MYC_ERR_INVALID_OUTPUT_CAP,
    /* Fase 7 (privacy/size): agent_payload_cap di luar rentang valid
     * (0 atau 1024..1048576) dari jalur API/MCP -- CLI fail-fast di
     * main, API divalidasi di ingress (pola MYC-AUDIT-020). */
    MYC_ERR_INVALID_AGENT_CAP,
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

typedef struct myc_request myc_request;
typedef struct myc_result myc_result;

/* Tipe gate/agent yang hanya dipakai 2-3 modul: header modul.
 * myc.h include mereka SETELAH kontrak inti (verdict/gate_id/debt)
 * supaya myc_result tetap by-value tanpa circular include. */
#include "taxonomy.h"
#include "contract.h"
#include "state.h"
#include "resource.h"
#include "units.h"
#include "run.h"
#include "filc.h"
#include "driver.h"
#include "assume.h"
#include "matrix.h"
#include "witness.h"
#define MYC_TYPES_ONLY
#include "cache.h"
#undef MYC_TYPES_ONLY

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

struct myc_request {
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
    /* IDE-6 (--watch-diff / --delta): fast inner loop per-fungsi. Output-
     * only (TIDAK masuk scenario hash, seperti --json-summary): menambah
     * delta assurance terstruktur per-fungsi ke hasil (fungsi berubah /
     * identik / baru / hilang / dependents vs baseline cache) + timing.
     * NON-blocking penuh: verdict/hasil TIDAK berubah. */
    int         watch_diff;
     int         no_cache;        /* --no-cache: matikan incremental evidence
                                     cache (SOL-18); default 0 = cache ON */
     int         agent;            /* --agent: output protokol agent
                                      (myc.agent.v2) untuk konsumsi LLM */
     int         lite;             /* --lite: output myc.lite.v1 (agen lemah) */
     /* G4: --eig-apply [--budget-ms N]: setelah L1, jalankan paling
      * banyak satu eksperimen within_budget. Default OFF. Budget 0 =
      * 5000 ms. Masuk cache key g2 (hasil bisa berbeda). */
     int         eig_apply;
     int         eig_budget_ms;
     /* P4: --parallel-gates — setelah compile clean, spawn --run
      * berbarengan dengan --analyze. Default OFF. Join, lalu tulis
      * status RUNTIME dalam urutan kanonik (setelah analyzer /
      * checked / prove / filc). Masuk cache key g2. Timeout anak
      * tetap timeout_ms. */
     int         parallel_gates;
     /* P12 / INV-015: --production — jangan senyap melemahan assurance.
      * Mengaktifkan require_complete + floor versi backend (P5-T03).
      * Toolchain di bawah min_version = UNAVAILABLE + debt, bukan clean.
      * Masuk cache key g2. Default OFF. */
     int         production;
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
    /* Fase 7 (Privacy/size controls, DS-14 #3):
     * agent_payload_cap: --agent-payload-cap BYTES -- override
     * MYC_AGENT_PAYLOAD_CAP (default 16384) untuk output --agent.
     * 0 = default; rentang valid 1024..1048576 (1 KiB - 1 MiB),
     * invalid = fail-fast exit 2 (pola MYC-AUDIT-019/020).
     * no_persist: --no-persist -- mode privasi: JANGAN menulis state
     * apa pun ke disk (ledger .myc/ledger.json, cache SOL-18, ledger
     * asumsi .myc/assumptions.json, profil SOL-20, kalibrasi).
     * Verdict/hasil run TIDAK berubah (NON-blocking penuh); hanya
     * tidak meninggalkan jejak. Kontradiksi dgn --profile = fail-fast
     * (pola A1: --no-assumptions + --require-assumptions-closed). */
    int         agent_payload_cap;
    int         no_persist;
    /* IDE-4 (MYC-AUDIT-065): no_regress — replay regression (pasca-
     * repair, myc_regress_replay_mem / myc_regress_run) adalah pass
     * VERIFIKASI, bukan discovery: saat source yang di-replay masih
     * buggy, gate TIDAK menyimpan seed baru ke corpus (corpus tidak
     * bermutasi di tengah replay). Dipakai internal oleh regress.c;
     * default 0 = discovery run normal (fuzz/exhaustive/driver check
     * tetap menyimpan counterexample). NON-blocking: verdict/status
     * gate TIDAK berubah, hanya efek samping penyimpanan yang mati. */
    int         no_regress;
    /* Fase 7 (DS-15 pack wiring, MYC-AUDIT-038): pack proyek lokal
     * (myc.prompt.md + myc.spec.json, SOL-15) untuk output --agent dan
     * paket context SOL-22. pack_dir: --pack-dir DIR (NULL = cwd);
     * no_pack: --no-pack (nonaktifkan; perilaku = pack absen). pack_dir
     * malloc'd, di-free caller (myc.c main). NON-blocking: pack hanya
     * memperkaya output, verdict TIDAK pernah berubah. */
    char       *pack_dir;
    int         no_pack;
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
    /* Fase 5, D1 (--fuzz): fuzz-lite gate. fuzz_iters = loop terikat per
     * fungsi (default 20000); fuzz_seed = seed PRNG (default 0x5EED). */
    int         fuzz;
    int         fuzz_iters;
    unsigned    fuzz_seed;
    /* Fase 5, B5 (--mutate-audit): mutation-audited verification. */
    int         mutate_audit;
    int         mutate_max;         /* budget total mutan (default 8) */
    /* Fase 5, C1 (--freestanding): mode C tanpa OS (firmware). Compile
     * dengan -ffreestanding -fno-builtin; hosted-API trap (printf,
     * malloc, fopen, exit, ...) dilaporkan sebagai observasi NON-blocking
     * (bukan warning senyap). */
    int         freestanding;
    /* Fase 5, SOL-14 (--abi): ABI/FFI Surface Certificate. Snapshot
     * exported symbols + struct size/align/offset + enum + target triple
     * + header digest via helper program compiler-generated. NON-blocking
     * observasi; delta tak diminta = hard transaction failure. */
    int         abi;
    /* Fase 5, C5 (--scenario <name>): scenario pack (profil JSON) yang
     * mengaktifkan resep gate per domain sekaligus. "auto" = D3: tebak
     * dari struktur source. scenario_file = path profil user (opsional;
     * default scenarios.json di cwd). Malloc'd, di-free caller main. */
    char       *scenario;
    char       *scenario_file;
    /* Fase 5, C4 (--matrix): target matrix bare metal -- cross-compile
     * source dengan cross-compiler (arm-none-eabi-gcc, riscv*-elf) bila
     * tersedia, dump macro target, bandingkan dgn host -> portability
     * matrix (asumsi yang berubah antar target). NON-blocking. */
    int         matrix;
    /* Fase 6 (Self-Challenge): --perturb -- environment perturbation --
     * jalankan ulang program verification dengan env diubah (TZ, locale,
     * PATH, HOME/TERM), bandingkan stdout/exit/sanitizer vs baseline.
     * NON-blocking observasi: hasil berubah = env-sensitive. */
    int         perturb;
    /* Fase 6 (Self-Challenge): --thread-probe -- concurrency probe:
     * lock-order statis (inversi urutan mutex) + TSan runtime bila
     * tersedia. NON-blocking observasi. */
    int         thread_probe;
};

/* --- Differential Backend Quorum (#3) --- */
typedef enum {
    MYC_QUORUM_NOT_REQUESTED = 0,
    MYC_QUORUM_CLEAN,
    MYC_QUORUM_CONFLICT,
    MYC_QUORUM_INCONCLUSIVE
} myc_quorum_status;

/* Capsule lengkap di report.h (hanya myc.c + report.c). */
typedef struct myc_replay_capsule myc_replay_capsule;

struct myc_result {
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

    /* --- hasil Sanitizer Location Extractor (IDE-1, qwen-review) ---
     * Lokasi pelanggaran runtime yang diekstrak dari report sanitizer
     * (log_path, non-spoofable) — untuk repair loop agent. sanloc_have=1
     * bila lokasi berhasil dipastikan milik source target. String di
     * arena milik hasil (myc_result_arena_dup). Additive terhadap
     * verdict/gate semantics: lokasi TIDAK pernah mengubah verdict. */
    int         sanloc_have;      /* 1 = lokasi pelanggaran diekstrak */
    char       *sanloc_kind;      /* arena: "stack-buffer-overflow", dst */
    int         sanloc_line;      /* baris pelanggaran (source asli) */
    int         sanloc_col;       /* kolom (UBSan), 0 bila tak ada */
    char       *sanloc_function;  /* arena: fungsi pelanggaran */
    char       *sanloc_file;      /* arena: file pelanggaran */
    int         sanloc_alloc_line;/* baris alokasi/free (0 bila tak ada) */
    char       *sanloc_alloc_function; /* arena: fungsi alokasi/free */
    char       *sanloc_snippet;   /* arena: baris source di lokasi */

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

    /* --- Fase 5 (Relational contracts): klasifikasi klausa kontrak
     * relasional (>=2 variabel) vs unary, operator (order/equality/
     * aritmetika/logika), dan binding check (identifier di luar
     * parameter fungsi + alias return = unbound). NON-blocking
     * observasi murni (analisis teks deterministik). */
    int         rel_analyzed;    /* klausa valid yang dianalisis */
    int         rel_relations;   /* klausa relasional (>=2 variabel) */
    int         rel_unary;       /* klausa unary (1 variabel) */
    int         rel_unbound;     /* klausa dgn identifier tak terikat */
    char       *rel_report;      /* arena */
    myc_rel_clause rel_clauses[MYC_MAX_REL_CLAUSES];
    int         rel_clause_count;

    /* --- Fase 5 (SOL-13): ghost state machine (observasi NON-blocking) ---
     * sm_states/events/transitions = deklarasi valid; sm_findings =
     * jumlah temuan ghost machine (sink/unreachable/no-recovery/...);
     * sm_report = laporan teks (arena). Daftar state/event/transisi/
     * finding tersimpan di sm_*_list (string arena). */
    int            sm_states;
    int            sm_events;
    int            sm_transitions;
    int            sm_findings;
    char          *sm_report;                 /* arena */
    myc_sm_state   sm_state_list[MYC_SM_MAX_STATES];
    myc_sm_event   sm_event_list[MYC_SM_MAX_EVENTS];
    myc_sm_trans   sm_trans_list[MYC_SM_MAX_TRANS];
    myc_sm_finding sm_finding_list[MYC_SM_MAX_FINDINGS];

    /* --- Fase 5, SOL-14 (--abi): ABI/FFI Surface Certificate ---
     * abi_ran=1 setelah myc_abi_snapshot (observasi NON-blocking, butuh
     * compiler gcc untuk helper sizeof/offsetof/_Alignof).
     * abi_n_structs/enums/symbols = deklarasi yang di-scan;
     * abi_snapshot (arena) = teks deterministik "# myc abi v1"
     * (baris TARGET/HEADER/SYMBOL/STRUCT/MEMBER/ENUM);
     * abi_changed/n_delta/abi_delta (arena) = hasil banding vs referensi
     * (baris HEADER diabaikan). abi_target = target triple; abi_header_sha
     * = sha256 source. ABI delta tak diminta = hard transaction failure. */
    int            abi_ran;
    int            abi_n_structs;
    int            abi_n_enums;
    int            abi_n_symbols;
    int            abi_changed;
    int            abi_n_delta;
    char          *abi_snapshot;               /* arena */
    char          *abi_delta;                  /* arena */
    char          *abi_target;                 /* arena */

    /* --- Fase 5, SOL-12: Resource Linearity Ledger ---
     * rsrc_ran=1 setelah myc_resource_scan (observasi NON-blocking teks).
     * rsrc_pairs/acquires/releases/transferred = hitungan snapshot;
     * rsrc_lk/dbl/unk = jumlah temuan (leak / double-release /
     * release-unknown). rsrc_report (arena) = laporan teks per fungsi
     * dengan jalur `acq@L -> release@R | leaked@E | transferred@T`;
     * temuan rinci di rsrc_finding_list (arena). Deterministik. */
    int            rsrc_ran;
    int            rsrc_pairs;
    int            rsrc_acquires;
    int            rsrc_releases;
    int            rsrc_transferred;
    int            rsrc_leaks;
    int            rsrc_double_releases;
    int            rsrc_release_unknown;
char          *rsrc_report;                /* arena */
    myc_rsrc_finding rsrc_finding_list[MYC_RSRC_MAX_FINDINGS];
    char          *abi_header_sha;             /* arena */

    /* --- Fase 5, SOL-11: Units / Shape / Provenance Contracts ---
     * units_ran=1 setelah myc_units_scan (observasi NON-blocking teks).
     * units_annotations = ttl annotation //@ unit|shape|provenance|endian;
     * units_unbound/mismatches/shape_dims/duplicates = hitungan temuan.
     * units_report (arena) = ringkasan per fungsi + per annotation;
     * temuan rinci di units_finding_list (arena). Deterministik. */
    int            units_ran;
    int            units_annotations;
    int            units_unbound;
    int            units_mismatches;
    int            units_shape_dims;
    int            units_duplicates;
    char          *units_report;               /* arena */
    myc_units_finding units_finding_list[MYC_UNITS_MAX_FINDINGS];

    /* --- Fase 7, #2029 (DS-14): Expected-Information-Gain scheduler ---
     * eig_ran=1 setelah myc_eig_plan (observasi NON-blocking murni: skor
     * rekomendasi expected_value = P(new_evidence) x severity x scope /
     * (time_cost x token_cost); prior tabel deterministik yang dikalibrasi
     * dari ledger SOL-21 (rule `eig-<slug>`) + profil SOL-20). v1 =
     * lapisan PERENCANAAN rekomendasi via `myc eig <file>`; pemilihan gate
     * otomatis di dalam check = follow-up. eig_report (arena) = laporan
     * teks; counts ringkas utk replay masa depan. Deterministik. */
    int            eig_ran;
    int            eig_recommendations;
    int            eig_calibrated_rules;
    int            eig_within_budget;
    int            eig_profile_used;
    long long      eig_top_expected_value;
    char          *eig_report;                 /* arena */

    /* --- Fase 7 (SOL-10): Candidate Tournament dengan Pareto Frontier ---
     * cand_ran=1 setelah myc_candidate_tournament (`myc compare-candidates`
     * <baseline.c> <c1.c> [c2.c ...]): menilai kandidat patch pada dimensi
     * terukur deterministik (hard_gate/findings/obligations_lost/churn/
     * verification_cost/runtime_proxy/portability/readability;
     * stack_impact = UNMEASURED v1, gap terlihat). Pareto frontier =
     * TIDAK didominasi pada dimensi yang terukur (anti-overclaim SOL-10:
     * BUKAN klaim "terbaik umum"; harness/user memilih final). Observasi
     * NON-blocking murni; cand_report (arena) = laporan teks; counts
     * ringkas utk replay masa depan. */
    int            cand_ran;
    int            cand_candidates;
    int            cand_frontier;
    char          *cand_report;                /* arena */

    /* Fase 7 (Privacy/size controls): cap payload agent yang DIPAKAI
     * run ini (0 = default MYC_AGENT_PAYLOAD_CAP). Di-wire dari
     * req->agent_payload_cap di awal myc_run SEBELUM branch cache agar
     * jalur cache-hit pun memakainya (agent output dibangun ulang dari
     * res, bukan di-replay dari cache). Dipakai myc_build_agent_result
     * untuk enforcement size; agent JSON memuat payload_cap. */
    int            agent_payload_cap;

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
    /* MYC-AUDIT-040: buffer biasa di luar MYC_BUF (jumlah `[` non-makro
     * checked di luar komentar/string). Debt RAW-BUFFERS bila
     * checked_uses_buf && checked_raw_buffers > 0. */
    int         checked_raw_buffers;

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
    /* C3 (DS-11): jumlah observasi bare-metal (MMIO/volatile/alignment/
     * ISR) saat mode freestanding. NON-blocking, subset dari lint_observations. */
    int         lint_embedded_hits;

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

    /* --- IDE-6 (--watch-diff): delta assurance terstruktur per-fungsi ---
     * watch_diff_present=1 bila delta dihitung (ada baseline cache,
     * scenario sama, source berubah); watch_diff[] = satu entry per
     * fungsi source saat ini (IDENTICAL/CHANGED/NEW/DEPENDENT); counts
     * per status (REMOVED tidak masuk array); watch_diff_baseline =
     * source_sha256 entry baseline; watch_diff_ms = durasi hitung delta
     * (murni teks, tanpa backend). NON-blocking: verdict TIDAK berubah. */
    /* watch_diff_requested = 1 bila --watch-diff diminta (untuk laporan
     * jujur saat baseline belum ada: "belum ada baseline — delta kosong"). */
    int             watch_diff_requested;
    int             watch_diff_present;
    int             watch_diff_count;
    myc_delta_func  watch_diff_funcs[MYC_CACHE_MAX_FUNCS];
    int             watch_diff_n_changed;
    int             watch_diff_n_identical;
    int             watch_diff_n_new;
    int             watch_diff_n_removed;
    int             watch_diff_n_dep;
    char            watch_diff_baseline[65];
    unsigned long long watch_diff_ms;

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
    /* --- Fase 5, D1 (--fuzz, DS-13) ---
     * ran_fuzz=1 setelah gate; fuzz_funcs = fungsi yang di-fuzz;
     * fuzz_iters = loop per fungsi; fuzz_cases = eksekusi penuh
     * (guard requires lolos); fuzz_skipped = ditolak guard; fuzz_seed =
     * seed PRNG (reproduksibel, masuk receipt); fuzz_report (arena).
     * Crash sanitizer = DRIVER_VIOLATION (bukti, hard). */
    int            ran_fuzz;
    int            fuzz_funcs;
    int            fuzz_iters;
    long           fuzz_cases;
    long           fuzz_skipped;
    unsigned       fuzz_seed;
    char          *fuzz_report;        /* arena */
    char          *fuzz_stdout_text;   /* malloc'd, freed result_free */
    char          *fuzz_stderr_text;   /* malloc'd, freed result_free */
    /* --- Fase 5, B5 (--mutate-audit, DS-09) ---
     * ran_mutate=1 setelah audit; mutate_total = mutan dieksekusi;
     * mutate_caught = tertangkap gate; mutate_gap = lolos semua gate
     * (coverage gap); mutate_report (arena). NON-blocking observasi. */
    int            ran_mutate;
    int            mutate_total;
    int            mutate_caught;
    int            mutate_gap;
    char          *mutate_report;      /* arena */
    /* --- Fase 5, C1 (--freestanding) ---
     * ran_freestanding=1 bila compile memakai -ffreestanding;
     * freestanding_api_hits = jumlah panggilan API hosted yang dilarang
     * di mode ini; freestanding_report (arena). NON-blocking. */
    int            ran_freestanding;
    int            freestanding_api_hits;
    char          *freestanding_report; /* arena */
    /* --- Fase 5, C5 (--scenario) / D3 (auto) / DS-12 (env contract) ---
     * scenario_applied=1 bila scenario diterapkan sebelum pipeline;
     * scenario_auto=1 bila D3 menebak resep dari struktur source;
     * scenario_name (arena) = profil terpakai; scenario_report (arena)
     * = desc + flags aktif + env contract (DS-12: stack_budget, no_heap,
     * no_recursion, ...). Verdict tidak pernah berubah karena scenario. */
    int            scenario_applied;
    int            scenario_auto;
    char          *scenario_name;       /* arena */
    char          *scenario_report;     /* arena */
    /* --- Fase 5, C4 (--matrix, target matrix bare metal) ---
     * ran_matrix=1 setelah gate; matrix_targets = target dievaluasi
     * (termasuk yang tak terpasang); matrix_available = cross-compiler
     * ditemukan; matrix_built = compile -c sukses; matrix_deltas =
     * fakta (char/ptr/endianness) yang berubah vs host; matrix_report
     * (arena) = portability matrix. NON-blocking observasi. */
    /* --- Fase 6 (--perturb, environment perturbation) ---
     * perturb_ran=1 setelah gate; perturb_changed = jumlah env variant
     * yang mengubah perilaku (stdout/exit/sanitizer vs baseline);
     * perturb_report (arena). NON-blocking observasi. */
    int            perturb_ran;
    int            perturb_changed;
    char          *perturb_report;      /* arena */
    /* --- Fase 6 (--thread-probe, concurrency probe) ---
     * concur_ran=1 setelah probe; concur_race_detected=1 bila TSan
     * menemukan data race; concur_report (arena). NON-blocking. */
    int            concur_ran;
    int            concur_race_detected;
    char          *concur_report;       /* arena */

    int            ran_matrix;
    int            matrix_targets;
    int            matrix_available;
    int            matrix_built;
    int            matrix_deltas;
    myc_matrix_cell matrix_cells[MYC_MATRIX_MAX_CELLS];
    int            matrix_ncells;
    char          *matrix_report;       /* arena */

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
};

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

/* Wall clock monotonic dalam milidetik (IDE-6, --watch-diff: timing
 * delta assurance). Implementasi di alloc.c (selalu di-link). Caller
 * hanya boleh memakai SELISIH dua panggilan; 0 bila clock tidak ada. */
unsigned long long myc_wall_ms(void);

/* Jalankan pipeline penuh pada request. Mengisi res. */
void myc_run(const myc_request *req, myc_result *res);

/* Output teks / JSON hasil ke stdout. */
void myc_report_text(const myc_result *res);
void myc_report_json(const myc_result *res);
void myc_report_json_summary(const myc_result *res);
int myc_report_lite(const myc_result *res, const char *source,
                    size_t source_len);

/* Nama error code (statis). */
const char *myc_error_name(myc_error_code c);
const char *myc_verdict_name(myc_verdict v);
const char *myc_assurance_name(myc_assurance a);
const char *myc_finding_name(myc_finding f);
const char *myc_claim_status_name(myc_claim_status c);
const char *myc_dim_status_name(myc_dim_status s);

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
