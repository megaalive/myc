/*
 * taxonomy.h -- B3 (LLM Error Taxonomy + coaching transcript, DS-07).
 *
 * Sumbu kedua klasifikasi finding: bukan hanya semantik C (use-after-free,
 * array-bounds), tapi kelas KOGNITIF -- cara model biasanya salah
 * (myc_taxonomy_class didefinisikan di myc.h).
 *
 * Prinsip (jujur):
 *   - Classifier RULE-BASED kecil (substring deterministik), klasifikasi
 *     = observasi; tidak pernah mengubah verdict.
 *   - Coaching transcript ditulis UNTUK DIBACA MODEL (5-10 baris): satu
 *     prioritas per kelas + strategi perbaikan + instruksi "jangan
 *     sentuh" (anti-churn).
 *   - Deterministik: input + scenario sama -> transcript sama.
 */
#ifndef MYC_TAXONOMY_H
#define MYC_TAXONOMY_H

#include "myc.h"

/* Nama kelas (statis, lowercase: "hallucinated_api", ...). */
const char *myc_taxonomy_name(myc_taxonomy_class c);

/* Strategi perbaikan per kelas (statis, Bahasa Indonesia). */
const char *myc_taxonomy_strategy(myc_taxonomy_class c);

/* Classify satu pesan finding ke kelas kognitif (rule-based). */
myc_taxonomy_class myc_taxonomy_classify(const char *message);

/* Bangun coaching transcript dari res (diagnostics + witness + delta).
 * Mengisi res->coaching[] / coaching_count / coaching_class_count /
 * coaching_report (arena). Deterministik; NON-blocking. */
void myc_coach_build(myc_result *res);

#endif /* MYC_TAXONOMY_H */
