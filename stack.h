/*
 * stack.h -- Gate Stack Budget Analyzer (C2, --stack, DS-10).
 *
 * Dari `gcc -fstack-usage` (frame per fungsi) + call graph yang di-parse
 * dari source, hitung **worst-case stack depth statis** per root
 * (main/_start), bandingkan dengan budget, dan deteksi komponen yang
 * tak terbatas: rekursi (cycle di call graph), alloca, VLA (warning
 * `-Wvla`).
 *
 * Semantik (jujur, claim compiler):
 *   - Static worst-case != dynamic worst-case: laporan selalu menyatakan
 *     ini (DS-10 membedakan static call-path estimate vs interrupt /
 *     unbounded/unknown component).
 *   - NON-blocking observasi (trust rules #1): rekursi/over-budget/
 *     alloca/VLA = diagnostic + evidence, TIDAK menurunkan verdict.
 *   - `--stack-budget N` (default 4096 B) dari profil target.
 */
#ifndef MYC_STACK_H
#define MYC_STACK_H

#include "myc.h"

/* Jalankan gate stack budget analyzer. Mengisi res->ran_stack,
 * res->stack_worst_bytes, res->stack_worst_path, res->stack_recursion,
 * res->stack_alloca, res->stack_vla, res->stack_unknown, dan
 * res->stack_report. Kode kembalian: 1 = analisis selesai (observasi
 * tetap NON-blocking), 0 = di-skip (gcc absen / gagal compile). */
int myc_stack_gate(const myc_request *req, const char *source,
                   size_t source_len, myc_result *res);

#endif /* MYC_STACK_H */
