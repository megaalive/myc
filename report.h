/*
 * report.h -- Output verdict myc.
 */
#ifndef MYC_REPORT_H
#define MYC_REPORT_H

#include "myc.h"
#include "prompt.h"
#include "driver.h"

/* --- Counterexample Replay Capsule (#2) ---
 * Captures all information needed to replay a specific verification
 * run: source identity, stdin identity, backend, flags, and result.
 * Stored in myc_result; freed by myc_result_free(). Definisi lengkap
 * di sini (bukan myc.h) karena hanya myc.c + report.c yang membaca
 * field; myc.h hanya forward-declare. */
struct myc_replay_capsule {
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
    /* MYC-AUDIT-040: raw buffers di luar MYC_BUF — jumlah `[` di luar
     * komentar/string/preprocessor (deklarasi/akses array biasa). Debt
     * MYC-INCOMPLETE-RAW-BUFFERS bila source memakai MYC_BUF (checked)
     * tapi masih ada buffer biasa: transformasi fat-pointer tidak menutup
     * semua buffer. Observasi teks deterministik, NON-blocking. */
    int checked_raw_buffers;
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
};

/* Serialisasi hasil ke string JSON (malloc'd; caller membebaskan).
  * Dipakai MCP server (P9) untuk konten tool. NULL bila gagal. */
char *myc_result_to_json(const myc_result *res);

/* Nama status gate (untuk laporan). */
const char *myc_gate_status_name(myc_gate_status s);

/* Nama status quorum (untuk laporan differential backend). */
const char *myc_quorum_status_name(myc_quorum_status s);

/* Cetak protokol agent JSON ke stdout.
 * source/source_len opsional (NEMO-2); NULL/0 = tanpa repair runtime.
 * Return 0 bila sukses, -1 bila gagal. */
int myc_report_agent(const myc_result *res, const myc_pack_info *pack,
                     const char *source, size_t source_len);
int myc_report_lite(const myc_result *res, const char *source,
                    size_t source_len);

#endif /* MYC_REPORT_H */
