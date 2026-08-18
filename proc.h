/*
 * proc.h -- Peluncur proses argv eksak untuk myc.
 *
 * Prinsip fpagnt: program + argv[] langsung di boundary proses.
 * Tidak ada shell string. Source (data tidak tepercaya) hanya lewat stdin.
 */
#ifndef MYC_PROC_H
#define MYC_PROC_H

#include <stddef.h>

#include "myc.h"

typedef struct {
    const char *const *argv;    /* argv[0] = executable; diakhiri NULL */
    const char *cwd;            /* NULL = warisi cwd proses */
    const void *stdin_data;     /* bytes yang dikirim ke stdin; NULL = tanpa stdin */
    size_t      stdin_len;
    int         timeout_ms;     /* 0 = tanpa batas */
    size_t      max_output_bytes;
    /* Override env "KEY=VALUE" (MYC-AUDIT-017): NULL = warisi seluruh env
     * induk. Bila diisi, entri yang dipakai MENGGANTI nilai induk dengan
     * key yang sama; sisanya diwarisi. Dipakai gate run/driver untuk
     * mengarahkan ASAN_OPTIONS/UBSAN_OPTIONS ke log_path unik (saluran
     * laporan sanitizer non-spoofable) dan menstabilkan locale (LC_ALL=C). */
    const char *const *env;
} myc_proc_request;

typedef struct {
    int    ok;                  /* berhasil men-drain sampai selesai */
    int    exit_code;
    int    timed_out;
    int    cancelled;
    char  *stdout_data;         /* dialokasikan myc; diakhiri NUL */
    size_t stdout_total;        /* total byte sebelum truncation */
    size_t stdout_shown;        /* byte yang benar-benar disimpan */
    char  *stderr_data;
    size_t stderr_total;
    size_t stderr_shown;
    int    truncated;
    /* Streaming evidence: sanitizer terdeteksi pada output streaming. */
    int    sanitizer_detected;
    char   sanitizer_marker[64];
    unsigned long long duration_ms;
    myc_error_code err;         /* error terakhir, NONE bila lancar */
} myc_proc_result;

/* Jalankan proses dengan argv eksak. Mengisi res (harus myc_proc_result_free). */
int myc_proc_run(const myc_proc_request *req, myc_proc_result *res);
void myc_proc_result_free(myc_proc_result *res);

/* Cari executable "gcc" via PATH + extension .exe di Windows.
 * Mengembalikan string yang dialokasikan, atau NULL bila tidak ditemukan. */
char *myc_find_executable(const char *program);

/* gcc untuk pipeline myc: override (--gcc / path), lalu env MYC_GCC,
 * lalu PATH — skip major < 9 (FPC 2.95, DJGPP) bila ada gcc 9+ belakangan.
 * Override tidak di-skip. Caller membebaskan. */
char *myc_find_gcc(const char *override);

/* Major dari string `--version` atau "gcc 9+". Tupel N.N terakhir
 * ("15.2.0" → 15). Return -1 bila tidak ada angka. */
int myc_tool_version_major(const char *s);

/* --- Saluran laporan sanitizer (MYC-AUDIT-017) ---
 * ASan/UBSan dengan ASAN_OPTIONS/UBSAN_OPTIONS log_path=<base> menulis
 * report ke file "<base>.<pid>" di direktori kerja child. Helper berikut
 * membaca/membersihkan file tersebut di <dir> (pola "<dir>/<base>.*").
 * Ini saluran bukti yang TIDAK bisa dipalsukan program secara tidak
 * sengaja (report ditulis oleh runtime sanitizer sendiri, bukan stdout/
 * stderr program). */

/* Baca isi file report sanitizer pertama yang cocok <dir>/<base>.* dan
 * non-kosong; NULL bila tidak ada. Hasil malloc'd (caller membebaskan). */
char *myc_read_sanitizer_report(const char *dir, const char *base);

/* Hapus semua file <dir>/<base>.* (cleanup artefak report). */
void myc_remove_sanitizer_reports(const char *dir, const char *base);

#endif /* MYC_PROC_H */
