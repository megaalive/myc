/*
 * report.h -- Output verdict myc.
 */
#ifndef MYC_REPORT_H
#define MYC_REPORT_H

#include "myc.h"
#include "prompt.h"

/* Serialisasi hasil ke string JSON (malloc'd; caller membebaskan).
  * Dipakai MCP server (P9) untuk konten tool. NULL bila gagal. */
char *myc_result_to_json(const myc_result *res);

/* Nama status gate (untuk laporan). */
const char *myc_gate_status_name(myc_gate_status s);

/* Nama status quorum (untuk laporan differential backend). */
const char *myc_quorum_status_name(myc_quorum_status s);

/* Cetak protokol agent JSON ke stdout.
 * Return 0 bila sukses, -1 bila gagal. */
int myc_report_agent(const myc_result *res, const myc_pack_info *pack);

#endif /* MYC_REPORT_H */
