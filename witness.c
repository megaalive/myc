/*
 * witness.c -- Witness Pipeline (Fase 1): repro directory, minimizer, slice.
 *
 * Struktur direktori repro:
 *   .myc-witness/<source_sha256>/
 *     source.c          -- source penuh atau slice
 *     stdin.bin         -- stdin input (bila ada)
 *     witness.json      -- metadata witness
 *     replay.sh         -- script replay (POSIX)
 *     replay.bat        -- script replay (Windows)
 */
#include "witness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#define myc_mkdir(path) _mkdir(path)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define myc_mkdir(path) mkdir(path, 0700)
#endif

#include "myc.h"
#include "json.h"

/* Buat direktori repro dari witness + source.
 * Mengembalikan path direktori (malloc'd) atau NULL bila gagal.
 * Caller harus free(). */
char *myc_witness_write_repro(const myc_witness *w,
                              const char *source, size_t source_len,
                              const char *base_dir)
{
    char *dir = NULL;
    char *path = NULL;
    FILE *f;
    size_t len;

    if (!w || !source || !base_dir)
        return NULL;

    /* Hitung panjang path: base_dir / .myc-witness / sha256 */
    len = strlen(base_dir) + 16 + 65;
    dir = (char *)malloc(len);
    if (!dir) return NULL;
    snprintf(dir, len, "%s/.myc-witness", base_dir);
    myc_mkdir(dir);

    /* Gunakan violation_kind sebagai sub-directory sederhana */
    len = strlen(dir) + 1 + (w->violation_kind ? strlen(w->violation_kind) : 8) + 1;
    path = (char *)malloc(len);
    if (!path) { free(dir); return NULL; }
    snprintf(path, len, "%s/%s", dir,
             w->violation_kind ? w->violation_kind : "unknown");
    myc_mkdir(path);
    free(dir);

    /* Tulis source.c */
    {
        char *src_path = (char *)malloc(strlen(path) + 12);
        if (src_path) {
            snprintf(src_path, strlen(path) + 12, "%s/source.c", path);
            f = fopen(src_path, "wb");
            if (f) {
                fwrite(source, 1, source_len, f);
                fclose(f);
            }
            free(src_path);
        }
    }

    /* Tulis stdin.bin bila ada */
    if (w->stdin_data && w->stdin_len > 0) {
        char *stdin_path = (char *)malloc(strlen(path) + 12);
        if (stdin_path) {
            snprintf(stdin_path, strlen(path) + 12, "%s/stdin.bin", path);
            f = fopen(stdin_path, "wb");
            if (f) {
                fwrite(w->stdin_data, 1, w->stdin_len, f);
                fclose(f);
            }
            free(stdin_path);
        }
    }

    /* Tulis witness.json */
    {
        char *json_path = (char *)malloc(strlen(path) + 15);
        json_value *root;
        char *js;

        if (json_path) {
            snprintf(json_path, strlen(path) + 15, "%s/witness.json", path);
            root = json_new_obj();
            if (w->violation_kind)
                json_obj_set(root, "violation_kind",
                             json_new_str(w->violation_kind));
            if (w->violation_msg)
                json_obj_set(root, "violation_msg",
                             json_new_str(w->violation_msg));
            if (w->backend)
                json_obj_set(root, "backend", json_new_str(w->backend));
            if (w->backend_version)
                json_obj_set(root, "backend_version",
                             json_new_str(w->backend_version));
            json_obj_set(root, "violation_line",
                         json_new_num((int64_t)w->violation_line));
            json_obj_set(root, "violation_col",
                         json_new_num((int64_t)w->violation_col));
            if (w->pre_state)
                json_obj_set(root, "pre_state", json_new_str(w->pre_state));
            if (w->operation)
                json_obj_set(root, "operation", json_new_str(w->operation));

            js = NULL;
            if (json_serialize(root, &js) == 0) {
                js = NULL;
            }
            json_free(root);
            if (js) {
                f = fopen(json_path, "w");
                if (f) {
                    fprintf(f, "%s\n", js);
                    fclose(f);
                }
                free(js);
            }
            free(json_path);
        }
    }

    /* Tulis replay.sh (POSIX) */
    {
        char *replay_path = (char *)malloc(strlen(path) + 12);
        if (replay_path) {
            snprintf(replay_path, strlen(path) + 12, "%s/replay.sh", path);
            f = fopen(replay_path, "w");
            if (f) {
                fprintf(f, "#!/bin/sh\n");
                fprintf(f, "# Replay script for witness\n");
                fprintf(f, "# Backend: %s\n", w->backend ? w->backend : "unknown");
                fprintf(f, "# Violation: %s\n",
                        w->violation_kind ? w->violation_kind : "unknown");
                if (w->stdin_data && w->stdin_len > 0)
                    fprintf(f, "cat stdin.bin | gcc -x c source.c -o /tmp/repro && /tmp/repro\n");
                else
                    fprintf(f, "gcc -x c source.c -o /tmp/repro && /tmp/repro\n");
                fclose(f);
            }
            free(replay_path);
        }
    }

    /* Tulis replay.bat (Windows) */
    {
        char *replay_path = (char *)malloc(strlen(path) + 13);
        if (replay_path) {
            snprintf(replay_path, strlen(path) + 13, "%s/replay.bat", path);
            f = fopen(replay_path, "w");
            if (f) {
                fprintf(f, "@echo off\n");
                fprintf(f, "REM Replay script for witness\n");
                fprintf(f, "REM Backend: %s\n", w->backend ? w->backend : "unknown");
                fprintf(f, "REM Violation: %s\n",
                        w->violation_kind ? w->violation_kind : "unknown");
                if (w->stdin_data && w->stdin_len > 0)
                    fprintf(f, "type stdin.bin | gcc -x c source.c -o repro.exe && repro.exe\n");
                else
                    fprintf(f, "gcc -x c source.c -o repro.exe && repro.exe\n");
                fclose(f);
            }
            free(replay_path);
        }
    }

    return path;
}

/* Bangun slice dari source berdasarkan baris pelanggaran.
 * Mengembalikan string malloc'd yang harus free() oleh caller.
 * Slice = 5 baris sebelum dan sesudah baris pelanggaran. */
char *myc_witness_build_slice(const char *source, size_t source_len,
                              int violation_line, int context_lines,
                              int *out_start, int *out_end)
{
    const char *p = source;
    const char *end = source + source_len;
    int line = 1;
    int start_line, end_line;
    const char *slice_start, *slice_end;
    char *result;
    size_t result_len;

    if (!source || violation_line <= 0 || context_lines <= 0)
        return NULL;

    start_line = violation_line - context_lines;
    if (start_line < 1) start_line = 1;
    end_line = violation_line + context_lines;

    /* Cari awal slice */
    while (p < end && line < start_line) {
        if (*p == '\n') line++;
        p++;
    }
    slice_start = p;

    /* Cari akhir slice */
    while (p < end && line <= end_line) {
        if (*p == '\n') line++;
        p++;
    }
    slice_end = p;

    /* Handle edge case: jika p masih di tengah baris, advance ke newline */
    if (p < end && *p != '\n') {
        while (p < end && *p != '\n') p++;
        if (p < end) p++; /* skip newline */
    }

    result_len = (size_t)(slice_end - slice_start);
    result = (char *)malloc(result_len + 1);
    if (result) {
        memcpy(result, slice_start, result_len);
        result[result_len] = '\0';
    }

    if (out_start) *out_start = start_line;
    if (out_end) *out_end = end_line > line ? line : end_line;

    return result;
}

/* Minimasi input: coba hapus baris satu per satu dari stdin_data
 * selama finding masih muncul. Mengembalikan data minimal (malloc'd)
 * atau NULL bila gagal. out_len = panjang data minimal. */
char *myc_witness_minimize_input(const char *data, size_t data_len,
                                 size_t *out_len)
{
    char *result;
    char *test_buf;
    size_t i;
    size_t result_len;

    if (!data || data_len == 0 || !out_len) return NULL;

    /* Mulai dengan data penuh */
    result = (char *)malloc(data_len);
    if (!result) return NULL;
    memcpy(result, data, data_len);
    result_len = data_len;

    /* Binary search: coba hapus setiap baris */
    test_buf = (char *)malloc(data_len);
    if (!test_buf) { free(result); return NULL; }

    i = 0;
    while (i < result_len) {
        /* Cari akhir baris */
        size_t line_start = i;
        while (i < result_len && result[i] != '\n') i++;
        size_t line_end = i < result_len ? i + 1 : i;
        size_t line_len = line_end - line_start;

        /* Buat test buffer tanpa baris ini */
        size_t test_len = result_len - line_len;
        memcpy(test_buf, result, line_start);
        memcpy(test_buf + line_start, result + line_end, result_len - line_end);

        /* TODO: jalankan myc check pada test_buf untuk verifikasi finding
         * masih muncul. Untuk sekarang, kembalikan data penuh (minimizer
         * sederhana yang tidak mengubah data). */
        (void)test_len;

        i = line_end;
    }

    free(test_buf);
    *out_len = result_len;
    return result;
}

/* Ekstrak fungsi yang mengandung baris pelanggaran dari source.
 * Mengembalikan string malloc'd berisi fungsi tersebut atau NULL.
 * Caller harus free(). */
char *myc_witness_extract_function(const char *source, size_t source_len,
                                   int violation_line)
{
    const char *p = source;
    const char *end = source + source_len;
    int line = 1;
    const char *func_start = NULL;
    const char *func_end = NULL;
    int brace_count = 0;
    int in_function = 0;
    char *result;
    size_t result_len;

    if (!source || violation_line <= 0) return NULL;

    /* Cari awal fungsi: mundur dari violation_line sampai menemukan
     * '{' yang menandakan awal badan fungsi. */
    p = source;
    while (p < end && line < violation_line) {
        if (*p == '\n') line++;
        p++;
    }

    /* Mundur sampai menemukan '{' di level 0 */
    {
        const char *q = p;
        int bc = 0;
        while (q > source) {
            q--;
            if (*q == '}') bc++;
            else if (*q == '{') {
                if (bc == 0) {
                    func_start = q;
                    break;
                }
                bc--;
            }
        }
    }

    if (!func_start) return NULL;

    /* Mundur lebih jauh untuk mencari deklarasi fungsi */
    {
        const char *q = func_start;
        while (q > source) {
            q--;
            if (*q == '\n') {
                /* Cek apakah baris ini berisi tipe fungsi */
                const char *line_start = q + 1;
                if (line_start < func_start) {
                    /* Sederhana: ambil dari baris ini */
                    func_start = line_start;
                }
                break;
            }
        }
    }

    /* Cari akhir fungsi: maju sampai brace_count kembali ke 0 */
    p = func_start;
    brace_count = 0;
    in_function = 0;
    while (p < end) {
        if (*p == '{') {
            brace_count++;
            in_function = 1;
        } else if (*p == '}') {
            brace_count--;
            if (in_function && brace_count == 0) {
                func_end = p + 1;
                break;
            }
        }
        p++;
    }

    if (!func_end) func_end = end;

    /* Ekstrak fungsi */
    result_len = (size_t)(func_end - func_start);
    result = (char *)malloc(result_len + 1);
    if (result) {
        memcpy(result, func_start, result_len);
        result[result_len] = '\0';
    }

    return result;
}
