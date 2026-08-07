/*
 * assume.h -- Assumption Closure (Fase 4, A1 + DS-01).
 *
 * Ledger asumsi portabilitas: konstruk yang MEMBETTAR fakta target
 * implementation-defined (signedness char, lebar int, endianness
 * bit-field, alignment cast, sizeof) disandingkan dengan kebenaran
 * toolchain host dari macro dump `gcc -dM -E -` (predefined macros:
 * __CHAR_UNSIGNED__, __SIZEOF_INT__, __BYTE_ORDER__, __STDC_VERSION__,
 * CHAR_BIT). Observasi NON-blocking: verdict tidak pernah turun karena
 * asumsi (confidence-scored), kecuali --require-assumptions-closed
 * (DS-01): asumsi terbuka = gap verifikasi -> INCONCLUSIVE + debt.
 *
 * Lifecycle (DS-01): observed -> declared / tested / contradicted /
 * eliminated / accepted-risk. Status dipersisten di .myc/assumptions.json
 * agar run kedua menunjukkan asumsi mana yang sudah ditutup;
 * `--assumption-ack id:status` menutup asumsi TANPA menghilangkannya
 * dari receipt (masih muncul di laporan dengan status barunya).
 *
 * Cache (SOL-18): host facts disimpan di entry cache dan di-replay tanpa
 * mengeksekusi gcc ulang; DETEKSI selalu di-scan ulang pada cache-hit
 * (murni teks, ~ms, non-blocking) supaya status dari
 * .myc/assumptions.json selalu segar. Karena itu asumsi TIDAK disimpan
 * di cache entry (selalu dihitung ulang), dan flags asumsi masuk
 * scenario hash (ledger.c) untuk pemisahan cache yang konsisten.
 */
#ifndef MYC_ASSUME_H
#define MYC_ASSUME_H

#include "myc.h"

#define MYC_ASSUME_DIR      ".myc"
#define MYC_ASSUME_FILE     ".myc/assumptions.json"
#define MYC_ASSUME_MAX_ACKS 16
#define MYC_ASSUME_MAX_STATE 256

/* Nama status (statis): "observed"/"declared"/"tested"/"contradicted"
 * /"eliminated"/"accepted-risk". */
const char *myc_assumption_status_name(myc_assumption_status s);

/* Ambil fakta toolchain host: `gcc -dM -E -` dengan stdin KOSONG (macro
 * predefined murni — deterministik, tidak bergantung source/syntax).
 * Mengisi *out; return 1 bila berhasil (gcc tersedia). */
int myc_assume_fetch_facts(const char *gcc, myc_host_facts *out);

/* Validasi spec ack "id:status,..." (fail-fast CLI). 0 valid, -1
 * malformed (status tidak dikenal / format salah). */
int myc_assume_ack_validate(const char *spec);

/* Run penuh: deteksi (scan token source) + merge state
 * .myc/assumptions.json + terapkan ack + set res->assumption_* dan
 * res->assumption_report. facts NULL -> ambil sendiri via
 * myc_assume_fetch_facts (exec gcc; dipakai jalur pipeline). facts
 * non-NULL -> pakai facts yang diberikan (jalur cache-hit, tanpa exec).
 * NON-blocking: gagal baca state = dianggap kosong. */
void myc_assume_run(const myc_request *req, myc_result *res,
                    const char *src, size_t srclen,
                    const myc_host_facts *facts);

/* Enforce --require-assumptions-closed (dipanggil setelah
 * enforce_require_complete, sebelum budget yang tetap TERAKHIR):
 * unclosed > 0 -> debt MYC_DEBT_ASSUMPTION + verdict INCONCLUSIVE bila
 * masih MC_OK + receipt dibangun ulang (pola 9.10). Verdict findings
 * (bug nyata) TIDAK diturunkan. */
void myc_assume_enforce(const myc_request *req, myc_result *res);

#endif /* MYC_ASSUME_H */
