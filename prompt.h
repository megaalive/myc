/*
 * prompt.h -- D4 (System-Prompt Contract Generator, DS-15).
 *
 * Render kebijakan efektif proyek menjadi snippet system-prompt (<= 12
 * baris) yang bisa ditempel harness LLM SEBELUM model menulis kode
 * (pencegahan, bukan koreksi). Sumber 100% deterministik -- TIDAK ada
 * AI-generated: fakta target (macro dump gcc host), denylist fungsi
 * (policy.c), konvensi pemeriksaan alokasi (negative-space 9.8), idiom
 * checked-buffer (MYC_BUF), dan aturan anti-churn.
 *
 * Kejujuran: setiap klaim menyertakan sumbernya ("dari gcc host",
 * "non-blocking", "konvensi N/M callsite"). Tidak pernah mengarang.
 *
 * Fase 7 (item plan terakhir): Project-local prompt/spec pack.
 * `myc prompt <file.c> [--pack-dir DIR] [--no-pack]` memperkaya snippet
 * dengan pack proyek lokal: `myc.prompt.md` (teks bebas, hingga 8 KiB)
 * dan `myc.spec.json` (spec terstruktur: name/domain/rules/
 * allow_headers/deny_functions) di direktori proyek. Keduanya OPTIONAL
 * dan NON-blocking (verdict TIDAK pernah berubah); spec.json yang ada
 * tapi invalid = fail-fast (pola scenario). Setiap klaim pack diberi
 * sumber + sha256 isi file -- deterministik, harness bisa verifikasi.
 */
#ifndef MYC_PROMPT_H
#define MYC_PROMPT_H

#include <stddef.h>

/* Bangun snippet prompt (malloc'd; caller membebaskan) dari source.
 * NULL bila OOM. Non-blocking: gcc absen = fakta target dilewati dengan
 * catatan; denylist/konvensi tetap dilaporkan. TANPA pack proyek. */
char *myc_prompt_build(const char *source, size_t len);

/* --- Project-local prompt/spec pack (Fase 7, item terakhir) --- */

#define MYC_PACK_PROMPT_FILE "myc.prompt.md"
#define MYC_PACK_SPEC_FILE   "myc.spec.json"

#define MYC_PACK_PROMPT_CAP  8192   /* cap teks prompt.md (byte) */
#define MYC_PACK_MAX_RULES   8
#define MYC_PACK_RULE_LEN    192
#define MYC_PACK_MAX_HEADS   8
#define MYC_PACK_HEAD_LEN    96
#define MYC_PACK_MAX_DENIES  8
#define MYC_PACK_DENY_LEN    96

/* Hasil muat pack proyek lokal. prompt_present/spec_present = 1 bila
 * file terbaca & valid; sha256 hex isi file (65 byte) diisi walau absen
 * (nol). spec invalid TIDAK sampai ke sini (myc_pack_load return -1). */
typedef struct myc_pack_info {
    int  prompt_present;
    char *prompt_text;         /* isi prompt.md (malloc'd, CAP diterapkan;
                                  caller bebas setelah pakai) */
    size_t prompt_text_len;    /* panjang prompt_text */
    size_t prompt_total_len;   /* panjang asli prompt.md (utk penanda
                                  potong jujur bila > MYC_PACK_PROMPT_CAP) */
    char prompt_sha256[65];    /* sha256 dari prompt_text (isi ter-cap) */
    int  spec_present;
    char spec_sha256[65];      /* sha256 dari isi spec.json (utuh) */
    char spec_name[64];
    char spec_domain[64];
    int  spec_n_rules;
    char spec_rules[MYC_PACK_MAX_RULES][MYC_PACK_RULE_LEN];
    int  spec_n_allow;
    char spec_allow[MYC_PACK_MAX_HEADS][MYC_PACK_HEAD_LEN];
    int  spec_n_deny;
    char spec_deny[MYC_PACK_MAX_DENIES][MYC_PACK_DENY_LEN];
} myc_pack_info;

/* Muat pack proyek lokal dari `pack_dir` (NULL = cwd). Mencari
 * <pack_dir>/myc.prompt.md + <pack_dir>/myc.spec.json (pola scenario:
 * user file di cwd, version-controllable -- BUKAN .myc/ yang gitignored).
 * `no_pack` = 1 => info di-nol-kan, file tidak dibaca (perilaku sama dgn
 * pack absen). Mengisi *info (zero-kan dulu di dalam).
 * Return: 0 = OK; -1 = spec.json ADA tapi invalid (fail-fast, pola
 *         scenario -2); -2 = OOM/IO error fatal. */
int myc_pack_load(const char *pack_dir, int no_pack, myc_pack_info *info);

/* Bangun snippet prompt inti (myc_prompt_build) + blok pack dari info
 * (hasil myc_pack_load). NULL bila OOM. Blok pack memuat isi prompt.md
 * verbatim + daftar spec, SEMUA dengan sumber & sha256. info boleh NULL
 * (sama dgn pack kosong). */
char *myc_prompt_build_packed(const char *source, size_t len,
                              const myc_pack_info *info);

/* Cuplikan protokol lite untuk harness (cursor|claude|codex).
 * malloc'd; caller myc_free. NULL bila kind tidak dikenal atau OOM. */
char *myc_prompt_harness(const char *kind, const char *source, size_t len);

#endif /* MYC_PROMPT_H */
