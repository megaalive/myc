/*
 * compile.h -- Pipeline myc: -E -> scan -> -fsyntax-only -> (opsional -analyze)
 */
#ifndef MYC_COMPILE_H
#define MYC_COMPILE_H

#include "myc.h"

/* Jalankan pipeline penuh. Mengisi res. */
void myc_pipeline(const myc_request *req, myc_result *res);

#endif /* MYC_COMPILE_H */
