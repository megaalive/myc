/*
 * report.h -- Output verdict myc.
 */
#ifndef MYC_REPORT_H
#define MYC_REPORT_H

#include "myc.h"

/* Serialisasi hasil ke string JSON (malloc'd; caller membebaskan).
 * Dipakai MCP server (P9) untuk konten tool. NULL bila gagal. */
char *myc_result_to_json(const myc_result *res);

#endif /* MYC_REPORT_H */
