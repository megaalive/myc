/*
 * compile.h -- Pipeline myc: -E -> scan -> -c -O2 -> (opsional -analyze).
 * Policy scan = warning non-blocking; lint memory-safety = gate hard.
 */
#ifndef MYC_COMPILE_H
#define MYC_COMPILE_H

#include "myc.h"

/* Jalankan pipeline penuh. Mengisi res. */
void myc_pipeline(const myc_request *req, myc_result *res);

#endif /* MYC_COMPILE_H */
