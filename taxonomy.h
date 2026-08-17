/*
 * taxonomy.h -- B3 (LLM Error Taxonomy + coaching transcript, DS-07).
 *
 * Sumbu kedua klasifikasi finding: bukan hanya semantik C (use-after-free,
 * array-bounds), tapi kelas KOGNITIF -- cara model biasanya salah
 * (myc_taxonomy_class di header ini; myc.h include taxonomy.h).
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

#include <stddef.h>

/* Sumbu kedua klasifikasi finding: kelas KOGNITIF -- cara model biasanya
 * salah -- bukan hanya semantik C. Urutan enum = prioritas coaching
 * (kecil = diprioritaskan; lihat coach_priority di taxonomy.c).
 * Classifier rule-based, NON-blocking observasi. */
typedef enum {
    MYC_TAX_UNCLASSIFIED = 0,
    MYC_TAX_HALLUCINATED_API,   /* API dianggap lebih aman dari sebenarnya */
    MYC_TAX_MISSING_GUARD,      /* null-deref / unchecked alloc / uninit */
    MYC_TAX_OFF_BY_ONE,         /* batas loop/index salah satu */
    MYC_TAX_UB_ASSUMPTION,      /* implementation-defined / UB */
    MYC_TAX_TYPE_CONFUSION,     /* cast / signedness / lebar tipe */
    MYC_TAX_IGNORED_RETURN,     /* return value dibuang */
    MYC_TAX_WRONG_CONSTANT,     /* konstanta/batas salah */
    MYC_TAX_CHURN,              /* mengubah kode yang tidak terkait */
    MYC_TAX_COUNT
} myc_taxonomy_class;

/* Satu item coaching (tersimpan di res->coaching[]). String where di
 * arena milik hasil. */
typedef struct {
    myc_taxonomy_class cls;
    int   line;                  /* 0 bila tak tersedia */
    char *where;                 /* arena: ringkasan lokasi + pesan */
} myc_coaching_item;

#define MYC_MAX_COACHING 10

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
