/*
 * witness.h -- Witness Pipeline (Fase 1).
 */
#ifndef MYC_WITNESS_H
#define MYC_WITNESS_H

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
