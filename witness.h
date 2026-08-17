/*
 * witness.h -- Witness Pipeline (Fase 1).
 */
#ifndef MYC_WITNESS_H
#define MYC_WITNESS_H

#include <stddef.h>

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

#include "myc.h"

/* Buat direktori repro dari witness + source.
 * Struktur: .myc-witness/<violation_kind>/
 *   source.c, stdin.bin, witness.json, replay.sh, replay.bat
 * Mengembalikan path direktori (malloc'd) atau NULL bila gagal. */
char *myc_witness_write_repro(const myc_witness *w,
                              const char *source, size_t source_len,
                              const char *base_dir);

/* Bangun slice dari source berdasarkan baris pelanggaran.
 * Mengembalikan string malloc'd (context_lines baris sebelum/sesudah).
 * Caller harus free(). out_start/out_end = baris awal/akhir slice. */
char *myc_witness_build_slice(const char *source, size_t source_len,
                              int violation_line, int context_lines,
                              int *out_start, int *out_end);

/* Minimasi input: coba hapus baris satu per satu dari data
 * selama finding masih muncul. Mengembalikan data minimal (malloc'd)
 * atau NULL bila gagal. out_len = panjang data minimal. */
char *myc_witness_minimize_input(const char *data, size_t data_len,
                                 size_t *out_len);

/* Ekstrak fungsi yang mengandung baris pelanggaran dari source.
 * Mengembalikan string malloc'd berisi fungsi tersebut atau NULL.
 * Caller harus free(). */
char *myc_witness_extract_function(const char *source, size_t source_len,
                                   int violation_line);

#endif /* MYC_WITNESS_H */
