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

/* Cari executable "gcc" via PATH + extension .exe di Windows. */
/* Mengembalikan string yang dialokasikan, atau NULL bila tidak ditemukan. */
char *myc_find_executable(const char *program);

#endif /* MYC_PROC_H */
