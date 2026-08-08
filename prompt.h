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
 */
#ifndef MYC_PROMPT_H
#define MYC_PROMPT_H

#include <stddef.h>

/* Bangun snippet prompt (malloc'd; caller membebaskan) dari source.
 * NULL bila OOM. Non-blocking: gcc absen = fakta target dilewati dengan
 * catatan; denylist/konvensi tetap dilaporkan. */
char *myc_prompt_build(const char *source, size_t len);

#endif /* MYC_PROMPT_H */
