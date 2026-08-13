/* limit.c -- Resource ceilings (PR-018, P7-T01)
 *
 * Satu tabel kebenaran resource limit + laporan `myc limits` (teks/JSON).
 * Setiap entri menghubungkan ID kanonik dengan makro sumber di myc.h
 * (nilai DEFAULT yang diberlakukan), kelas enforcement (hard = ingress
 * fail-fast MYC_ERR_*; soft = cap + debt MYC_DEBT_RESOURCE_LIMIT) dan
 * deskripsi satu kalimat untuk dokumentasi production-readiness.
 *
 * NON-blocking penuh: modul ini tidak memanggil pipeline verifikasi dan
 * tidak mengubah perilaku gate; `myc limits` adalah laporan observasi
 * (aturan trust rule 1). 'Hard'/'soft' hanyalah DOKUMENTASI kelas
 * enforcement yang sudah ada di pipeline (ingress validate vs cap+debt).
 */
#include <stdio.h>
#include <stddef.h>

#include "myc.h"
#include "limit.h"

/* Tabel kebenaran (single source of truth). Nilai diambil VERBATIM dari
 * makro di myc.h -- bila makro berubah, tabel ini WAJIB disinkronkan.
 * Freeze di-dokumentasikan di docs/capabilities.md + audit-history
 * MYC-AUDIT-050
 * (pola golden: menambah/mengurangi baris wajib update cek CI blok 21). */
static const myc_limit_entry LIMITS[] = {
    { "max_source_bytes",    "angka maksimum byte source C (ingress)",
      "MYC_MAX_CODE_BYTES",        MYC_MAX_CODE_BYTES,   MYC_LIMIT_HARD },
    { "max_stdin_bytes",     "angka maksimum byte run_stdin (ingress)",
      "MYC_MAX_STDIN_BYTES",       MYC_MAX_STDIN_BYTES,  MYC_LIMIT_HARD },
    { "max_backend_output_bytes",
      "angka maximum byte per channel output compile/run (cap+debt)",
      "MYC_MAX_OUTPUT_BYTES",      MYC_MAX_OUTPUT_BYTES, MYC_LIMIT_SOFT },
    { "max_output_cap_bytes",
      "batas atas --output-cap (rentang valid request)",
      "MYC_MAX_OUTPUT_CAP_BYTES",  MYC_MAX_OUTPUT_CAP_BYTES, MYC_LIMIT_HARD },
    { "default_timeout_ms",
      "timeout default proses backend",
      "MYC_DEFAULT_TIMEOUT_MS",    MYC_DEFAULT_TIMEOUT_MS,   MYC_LIMIT_SOFT },
    { "max_timeout_ms",
      "timeout maksimum yang diterima (ingress)",
      "MYC_MAX_TIMEOUT_MS",        MYC_MAX_TIMEOUT_MS,   MYC_LIMIT_HARD },
    { "max_diagnostics",
      "angka maksimum pesan diagnostik yang disimpan per result",
      "MYC_MAX_DIAGNOSTICS",       MYC_MAX_DIAGNOSTICS, MYC_LIMIT_SOFT },
    { "max_gates",           "slot gate hasil (per request)",
      "MYC_MAX_GATES",             MYC_MAX_GATES,        MYC_LIMIT_SOFT },
    { "max_evidence",        "slot evidence event (per request)",
      "MYC_MAX_EVIDENCE",          MYC_MAX_EVIDENCE,     MYC_LIMIT_SOFT },
    { "max_debt",            "slot item debt (per request)",
      "MYC_MAX_DEBT",              MYC_MAX_DEBT,         MYC_LIMIT_SOFT },
    { "max_contract_clauses",
      "klausa kontrak yang disimpan per result",
      "MYC_MAX_CONTRACT_CLAUSES",  MYC_MAX_CONTRACT_CLAUSES, MYC_LIMIT_SOFT },
    { "max_rel_clauses",
      "klausa relasional yang disimpan (Fase 5)",
      "MYC_MAX_REL_CLAUSES",       MYC_MAX_REL_CLAUSES,  MYC_LIMIT_SOFT },
    { "max_driver_cases",
      "budget kombinatorial kasus tepi per fungsi (--driver)",
      "MYC_MAX_DRIVER_CASES",      MYC_MAX_DRIVER_CASES, MYC_LIMIT_SOFT },
    { "max_driver_records",
      "total case records driver yang tersimpan",
      "MYC_MAX_DRIVER_RECORDS",    MYC_MAX_DRIVER_RECORDS, MYC_LIMIT_SOFT },
    { "max_filc_panic_cases",
      "rincian per-panic Fil-C yang disimpan",
      "MYC_MAX_FILC_CASES",        MYC_MAX_FILC_CASES,   MYC_LIMIT_SOFT },
    { "max_assumptions",
      "asumsi portabilitas yang dilacak (assumption ledger)",
      "MYC_MAX_ASSUMPTIONS",       MYC_MAX_ASSUMPTIONS,  MYC_LIMIT_SOFT },
    { "max_sm_states",       "state machine ghost: batas state",
      "MYC_SM_MAX_STATES",         MYC_SM_MAX_STATES,    MYC_LIMIT_SOFT },
    { "max_sm_events",       "state machine ghost: batas event",
      "MYC_SM_MAX_EVENTS",         MYC_SM_MAX_EVENTS,    MYC_LIMIT_SOFT },
    { "max_sm_transitions",  "state machine ghost: batas transisi",
      "MYC_SM_MAX_TRANS",          MYC_SM_MAX_TRANS,     MYC_LIMIT_SOFT },
    { "max_sm_findings",     "state machine ghost: batas finding",
      "MYC_SM_MAX_FINDINGS",       MYC_SM_MAX_FINDINGS,  MYC_LIMIT_SOFT },
    { "max_rsrc_pairs",      "resource ledger: pasangan acquire->release",
      "MYC_RSRC_MAX_PAIRS",        MYC_RSRC_MAX_PAIRS,   MYC_LIMIT_SOFT },
    { "max_rsrc_functions",  "resource ledger: fungsi yang dilacak",
      "MYC_RSRC_MAX_FUNCS",        MYC_RSRC_MAX_FUNCS,   MYC_LIMIT_SOFT },
    { "max_rsrc_vars",       "resource ledger: variabel per fungsi",
      "MYC_RSRC_MAX_VARS",         MYC_RSRC_MAX_VARS,    MYC_LIMIT_SOFT },
    { "max_units_annotations","units/shape/provenance: annotation per file",
      "MYC_UNITS_MAX_ANNS",        MYC_UNITS_MAX_ANNS,   MYC_LIMIT_SOFT },
    { "max_coaching",        "pesan coaching yang disimpan",
      "MYC_MAX_COACHING",          MYC_MAX_COACHING,     MYC_LIMIT_SOFT },
    { "max_witness_argv",    "argv tambahan witness pipeline",
      "MYC_MAX_WITNESS_ARGV",      MYC_MAX_WITNESS_ARGV, MYC_LIMIT_SOFT },
    { "divergence_max_cells","cross-toolchain divergence: sel matriks",
      "MYC_DIVERGENCE_MAX_CELLS",  MYC_DIVERGENCE_MAX_CELLS, MYC_LIMIT_SOFT },
    { "matrix_max_cells",    "target matrix: sel per matrix",
      "MYC_MATRIX_MAX_CELLS",      MYC_MATRIX_MAX_CELLS, MYC_LIMIT_SOFT },
    { "arena_block_bytes",   "ukuran blok arena alokasi per request",
      "MYC_ARENA_BLOCK",           MYC_ARENA_BLOCK,      MYC_LIMIT_SOFT },
};

const myc_limit_entry *myc_limits_table(int *count)
{
    if (count)
        *count = (int)(sizeof(LIMITS) / sizeof(LIMITS[0]));
    return LIMITS;
}

int myc_limits_report(FILE *out)
{
    int n = 0, i;
    const myc_limit_entry *t = myc_limits_table(&n);

    if (!out)
        return 0;
    fprintf(out, "resource limits (PR-018/P7-T01):\n");
    for (i = 0; i < n; i++) {
        fprintf(out, "  [%s] %-28s %-10lu %s\n",
                t[i].hard ? "HARD" : "soft",
                t[i].id,
                t[i].value,
                t[i].desc);
    }
    fprintf(out, "%d resource limit terdefinisi; HARD = ingress fail-fast, "
                 "soft = cap + debt MYC-INCOMPLETE-RESOURCE-LIMIT.\n", n);
    return n;
}

int myc_limits_report_json(FILE *out)
{
    int n = 0, i;
    const myc_limit_entry *t = myc_limits_table(&n);

    if (!out)
        return 0;
    fprintf(out, "{\n  \"schema\": \"myc.limits.v1\",\n");
    fprintf(out, "  \"count\": %d,\n  \"limits\": [\n", n);
    for (i = 0; i < n; i++) {
        if (i > 0)
            fprintf(out, ",\n");
        fprintf(out,
                "    { \"id\": \"%s\", \"desc\": \"%s\", \"macro\": \"%s\", "
                "\"value\": %lu, \"hard\": %d }",
                t[i].id, t[i].desc, t[i].macro, t[i].value, t[i].hard);
    }
    fprintf(out, "\n  ]\n}\n");
    return 0;
}