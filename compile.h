/*
 * compile.h -- Pipeline myc: -E -> scan -> -c -O2 -> (opsional -analyze).
 * Policy scan = warning non-blocking; lint memory-safety = gate hard.
 */
#ifndef MYC_COMPILE_H
#define MYC_COMPILE_H

#include "myc.h"

typedef struct {
    const char *finding_code;
    const char *patch_template;
    int         confidence;
} repair_template_t;

/* Jalankan pipeline penuh. Mengisi res. */
void myc_pipeline(const myc_request *req, myc_result *res);

/* Differential Backend Quorum (#3): analisis hasil semua
 * backend setelah pipeline selesai. */
void myc_quorum_analysis(const myc_request *req, myc_result *res);

/* Repair: dapatkan patch minimal untuk finding compile tertentu. */
char *myc_repair_get_patch(const char *finding_code);
char *myc_repair_from_diagnostic(const char *message);
const char *repair_find_code(const char *message);
extern const repair_template_t REPAIR_TEMPLATES[];
extern const size_t REPAIR_TEMPLATES_COUNT;

/* --- IDE-2 (qwen-review): repair template untuk RUNTIME_VIOLATION ---
 * Berbasis sanitizer_location (IDE-1, sanloc_* di myc_result). Template
 * deterministik (bukan AI): mengganti baris pelanggaran dengan versi aman
 * (snprintf ber-batas / clamp n / NULL-kan setelah free). patched_source
 * = source lengkap setelah patch (malloc'd) ATAU NULL + why (jujur) bila
 * template tidak yakin. Caller bebas via myc_runtime_repair_free(). */
typedef struct {
    char *patched_source;  /* source utuh setelah patch; NULL bila tidak yakin */
    char *patch_text;      /* deskripsi patch utk output agent (malloc'd) */
    char *why;             /* alasan bila patched_source == NULL (malloc'd) */
    int   confidence;      /* 0..100 */
} myc_runtime_repair;

myc_runtime_repair *myc_repair_runtime_patch(const myc_result *res,
                                             const char *source,
                                             size_t source_len);
void myc_runtime_repair_free(myc_runtime_repair *r);

#endif /* MYC_COMPILE_H */
