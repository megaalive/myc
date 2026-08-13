/* limit.h -- Resource ceilings (PR-018, P7-T01)
 *
 * Sumber untrusted input, sehingga ukuran / kompleksitas patologis adalah
 * permukaan DoS. Modul ini mendefinisikan SATU tabel kebenaran dari semua
 * resource limit yang diberlakukan myc (default value = makro di myc.h dan
 * konstantan modul lain) dan menyediakan laporan `myc limits` yang
 * deterministik (dokumentasi "Source/output/resource limits" di checklist
 * production-readiness).
 *
 * Filosofi P7-T01: semua limit harus menghasilkan KELELAHAN RESOURCE yang
 * TERTYPE, bukan crash. Dua kelas enforcement:
 *
 *   - HARD (fail-fast): limit yang melewatinya menolak REQUEST di ingress
 *     sebelum kerja mahal dijalankan (mis. source > 1 MiB -> MYC_ERR_*
 *     tanpa alokasi buffer raksasa). Ditandai `hard=1`.
 *   - SOFT (non-blocking): limit yang melewatinya memotong/membatasi hasil
 *     dengan jujur dan memunculkan debt TERTYPE MYC_DEBT_RESOURCE_LIMIT
 *     (kode MYC-INCOMPLETE-RESOURCE-LIMIT) sehingga "keheningan tidak
 *     disalahartikan sebagai keamanan". Verdict TIDAK pernah turun hanya
 *     karena limit lunak — kecuali --require-complete menaikkannya
 *     (pola 9.10). Ditandai `hard=0`.
 *
 * Modul ini murni laporan: TIDAK mengubah perilaku gate manapun (NON-
 * blocking penuh), konsisten dengan aturan trust "heuristik teks /
 * observasi tidak pernah menurunkan verdict".
 */
#ifndef MYC_LIMIT_H
#define MYC_LIMIT_H

#include <stdio.h>
#include <stddef.h>

/* Kelas enforcement limit (lihat header). */
#define MYC_LIMIT_HARD  1   /* ingress fail-fast (MYC_ERR_*)   */
#define MYC_LIMIT_SOFT  0   /* cap + debt MYC_DEBT_RESOURCE_LIMIT */

/* Satu entri limit. `value` = default yang diberlakukan saat ini
 * (makro sumber: MYC_MAX_CODE_BYTES, dst). `hard` = kelas enforcement. */
typedef struct {
    const char *id;          /* ID kanonik (contoh: "max_source_bytes") */
    const char *desc;        /* deskripsi satu kalimat                  */
    const char *macro;       /* makro/konstanta sumber (dokumentasi)    */
    unsigned long value;     /* default yang diberlakukan               */
    int         hard;        /* MYC_LIMIT_HARD (ingress) / _SOFT (debt) */
} myc_limit_entry;

/* Tabel resource limit (static). *count = jumlah entri. */
const myc_limit_entry *myc_limits_table(int *count);

/* Cetak laporan resource limit ke out (teks deterministik). Return
 * jumlah entri yang dicetak. */
int myc_limits_report(FILE *out);

/* Cetak laporan dalam JSON (objek myc.limits.v1) ke out. Return 0. */
int myc_limits_report_json(FILE *out);

#endif /* MYC_LIMIT_H */
