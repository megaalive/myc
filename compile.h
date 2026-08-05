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

#endif /* MYC_COMPILE_H */
