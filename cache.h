/*
 * cache.h -- Incremental Evidence Cache (Fase 3, SOL-18).
 *
 * Menjalankan seluruh gate setelah edit satu fungsi itu boros. Cache
 * menyimpan evidence receipt per (source_sha + scenario + tool identity)
 * agar run dengan input tak berubah bisa di-REPLAY tanpa menjalankan
 * backend, dan edit satu fungsi menghasilkan DELTA REPORT (fungsi mana
 * yang berubah + dependents yang perlu diverifikasi ulang).
 *
 * Design (jujur, deterministic):
 *   - Key  = sha256(source_sha256 + scenario_hash + tool_key + cwd).
 *     Cache TIDAK dipakai bila flags/tool/scenario berubah (SOL-18).
 *   - Hit  = replay penuh hasil: verdict/assurance/finding/completeness/
 *     claim/receipt/gates/diags/debt — receipt_sha256 IKUT di-replay
 *     (deterministik: receipt adalah hash dari status yang sama).
 *   - Miss = pipeline normal; delta report menghitung fungsi berubah
 *     vs identik + dependents (fungsi yang memanggil fungsi berubah)
 *     dari function fingerprints yang disimpan.
 *   - Persist: .myc/evidence_cache.json (sama seperti ledger).
 *   - NON-blocking: bila .myc/ tak dapat ditulis, cache dilewati
 *     dengan aman; replay TIDAK pernah menurunkan/menaikkan verdict
 *     (hanya mengembalikan hasil yang sudah pernah dihitung valid).
 */
#ifndef MYC_CACHE_H
#define MYC_CACHE_H

#include "myc.h"

#define MYC_CACHE_FILE       ".myc/evidence_cache.json"
#define MYC_CACHE_MAX_ENTRIES 64
#define MYC_CACHE_MAX_FUNCS   256

/* Satu fungsi yang ter-ekstrak dari source (untuk delta report). */
typedef struct {
    char name[64];
    int  line;
    char hash[65];   /* sha256 dari isi fungsi (rentang body) */
} myc_cache_function;

/* Satu entry cache = snapshot hasil gate untuk satu key. */
typedef struct {
    char key_sha256[65];
    char source_sha256[65];
    char scenario_hash[33];
    char tool_key[129];   /* gcc+clang version identity */
    char cwd[512];
    char path[512];       /* path file asli (FILE), kosong utk MEMORY/STDIN */

    char receipt_sha256[65];
    char fingerprint[129];

    myc_verdict       verdict;
    myc_error_code    err;
    myc_assurance     assurance;
    myc_assurance_vector av;
    myc_finding       finding;
    myc_completeness  completeness;
    myc_claim_status  claim;

    /* gate statuses snapshot (untuk replay + quorum + frontier) */
    myc_gate_status   gate_status[MYC_MAX_GATES];
    int               gate_requested[MYC_MAX_GATES];
    int               gate_id[MYC_MAX_GATES];   /* id gate ASLI (bukan index) */
    int               gate_findings[MYC_MAX_GATES];
    int               gate_count;

    /* debt snapshot (untuk replay + require-complete enforcement) */
    myc_debt_item     debt[MYC_MAX_DEBT];
    int               debt_count;

    /* diagnostics snapshot (untuk replay agent/causal/observation) */
    int               diag_line[MYC_MAX_DIAGNOSTICS];
    int               diag_col[MYC_MAX_DIAGNOSTICS];
    myc_confidence    diag_conf[MYC_MAX_DIAGNOSTICS];
    char              diag_msg[MYC_MAX_DIAGNOSTICS][512];
    int               diag_count;

    /* counts snapshot */
    int lint_observations;
    int negative_callsites;
    int negative_deviations;
    int checked_buffers, checked_allocations, checked_accesses, checked_frees;
    int driver_funcs, driver_cases, driver_skipped;
    int ran_negative, ran_checked, ran_driver;

    /* snapshot lengkap field hasil yang di-output report.c (SOL-18:
     * replay harus identik dgn run asli). */
    int   exit_code;
    int   require_complete;
    int   truncated;
    int   run_timed_out;
    int   run_sanitizer_detected;
    int   ran_runtime, ran_prove, ran_filc, ran_metamorphic;
    int   ran_preprocess, ran_compile, ran_analyzer;
    int   checked_uses_buf, checked_build_ok;
    int   prove_alarms, prove_proof_obligations;
    int   filc_panics;
    int   meta_o0_exit, meta_o2_exit;
    int   meta_o0_finding, meta_o2_finding, metamorphic_inconsistent;
    long  driver_max_product;
    int   driver_bounded;
    unsigned long long total_stdout_bytes, total_stderr_bytes;
    int   contract_requires, contract_ensures;
    /* Fase 5 B4 (DS-08): hasil harvest komentar-biasa (observasi). */
    int   harvest_candidates, harvest_validated, harvest_unbound;
    /* Fase 5 (Relational contracts): klasifikasi klausa kontrak
     * relasional (observasi; report arena + per-klausa TIDAK di-cache
     * -- sama seperti harvest_report -- sehingga replay hanya punya
     * counts, `clauses`/`report` kosong di output penuh). */
    int   rel_analyzed, rel_relations, rel_unary, rel_unbound;
    /* Fase 5 A3 (--exhaustive): hasil enumerasi penuh domain. */
    int   ex_ran, ex_funcs, ex_cases, ex_skip, ex_laund;
    long  ex_points;
    char  ex_dhash[65];

    /* SOL-30: hasil enforcement budget contract (replay identik). */
    int   budget_active;
    int   budget_met;
    char  budget_report[1024];

    /* Fase 4 A2/DS-02: hasil gate cross-toolchain divergence (replay
     * identik: flags + cell matriks + report). Deteksi ulang? Tidak —
     * divergence = eksekusi penuh toolchain; pada cache-hit hasil
     * di-replay apa adanya (scenario hash sudah memuat flag --divergence). */
    int   divergence_ran;
    int   divergence_planned;
    int   divergence_ncells;
    int   divergence_sanitizer_div;
    int   divergence_all_findings;
    int   divergence_semantic_div;
    int   divergence_diag_div;
    char  divergence_report[2048];
    struct {
        char tool[16];
        char opt_level;       /* 0 = -O0, 1 = -O2 */
        char available;       /* 0/1 */
        char san;             /* 1 = dgn sanitizer (finding bisa jadi bukti) */
        char built;
        char ran;
        char timed_out;
        char finding;
        char diag_warn;
        int  exit_code;
        char marker[80];
        char stdout_sha256[65];
    } divergence_cells[MYC_DIVERGENCE_MAX_CELLS];

    /* Fase 4 A1: host facts toolchain (macro dump gcc -dM) disimpan agar
     * cache-hit TIDAK mengeksekusi gcc ulang; deteksi asumsi tetap
     * di-scan ulang (murni teks, non-blocking). */
    int   host_facts_ok;
    int   host_char_unsigned;
    int   host_int_bits;
    int   host_ptr_bits;
    int   host_little_endian;
    long  host_stdc_version;
    int   host_char_bit;

    char  sanitizer_marker[64];
    char  prove_mode[64];
    char  prove_version[64];
    char  filc_version[64];
    char  driver_harness_sha256[65];

    /* teks backend (cap 2048, truncation aman — cukup untuk marker/
     * pesan pendek; output besar tetap identik verdict/gates). */
    char  stderr_text[2048];
    char  run_stdout_text[2048];
    char  run_stderr_text[2048];
    char  prove_stdout_text[2048];
    char  prove_stderr_text[2048];
    char  filc_stdout_text[2048];
    char  filc_stderr_text[2048];
    char  driver_stdout_text[2048];
    char  driver_stderr_text[2048];

    /* identitas tool + versi (report MYC-AUDIT-022, di-free individual
     * oleh myc_result_free -> strdup saat replay). */
    char  resolved_gcc[128];
    char  gcc_version[128];
    char  clang_version[128];

    /* driver case records (replay identik; cap penyimpanan 64 — cukup
     * untuk budget nyata; func/params arena-based di myc_result). */
    int   driver_case_count;
    struct {
        int   case_id;
        long  alloc_bytes;
        int   executed;
        char  func[64];
        char  params[128];
    } driver_records[64];

    /* filc cases (arena-based di myc_result). */
    int   filc_case_count;
    struct {
        int   line, col;
        char  message[256];
        char  file[128];
        char  function[128];
    } filc_cases[16];

    /* contract clauses (arena-based di myc_result). */
    int   contract_clause_count;
    struct {
        int   kind;
        int   line, col;
        int   status;
        char  func[64];
        char  expr[256];
    } contract_clauses[16];

    /* evidence events (message di-free individual -> strdup saat replay). */
    int   evidence_count;
    struct {
        int   gate_id;
        int   event_type;
        char  message[256];
    } evidence[32];

    /* function fingerprints untuk delta report */
    myc_cache_function funcs[MYC_CACHE_MAX_FUNCS];
    int func_count;

    unsigned long long duration_ms;
} myc_cache_entry;

/* Coba replay dari cache. Mengembalikan 1 bila hit (res diisi hasil),
 * 0 bila miss. NON-blocking: file cache tak terbaca = miss. */
int myc_cache_try_replay(const myc_request *req, myc_result *res,
                         const char *src, size_t srclen);

/* Simpan snapshot hasil ke cache (NON-blocking, gagal = diam). */
void myc_cache_store(const myc_request *req, const myc_result *res,
                     const char *src, size_t srclen);

/* Ekstrak fungsi dari source: nama + line + sha256 isi fungsi.
 * Mengembalikan jumlah fungsi atau -1 bila source tidak bisa diparse. */
int myc_cache_extract_functions(const char *src, size_t srclen,
                                myc_cache_function *out, int cap);

/* Bangun delta report: bandingkan fungsi baru vs yang tersimpan di cache
 * (untuk source yang BERUBAH, scenario sama). Mengembalikan string
 * malloc'd "N berubah (a,b), M identik, dependents: x,y" atau NULL. */
char *myc_cache_delta_report(const char *src, size_t srclen,
                             const myc_cache_entry *old_entry);

/* Bebaskan entry (saat ini semua field flat — hanya untuk masa depan). */
void myc_cache_entry_free(myc_cache_entry *e);

#endif /* MYC_CACHE_H */
