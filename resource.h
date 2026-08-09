/*
 * resource.h -- Resource Linearity Ledger (Fase 5, SOL-12).
 *
 * Memory safety bersih tidak menjamin file descriptor, mutex, socket,
 * mapping, atau handle dilepas. Ledger ini menelusuri acquire/release
 * pairs -- baik dari profil default (fopen/fclose, open/close, dll)
 * maupun deklarasi //@ resource -- dan melaporkan nasib tiap resource
 * per fungsi:
 *
 *     resource acquired -> release | leaked | double-released |
 *                         transferred | unknown
 *
 * Temuan (NON-blocking observasi; verdict TIDAK pernah turun):
 *   - LEAKED           : acquired di baris L, tidak pernah direlease atau
 *                        ditransfer sampai akhir body fungsi. witness =
 *                        jalur singkat (acq@L .. end@E).
 *   - DOUBLE_RELEASE   : release kedua pada resource yang sudah release.
 *   - RELEASE_UNKNOWN  : release dipanggil pada variabel yang TIDAK
 *                        di-trace sebagai acquire; bila variabel adalah
 *                        parameter fungsi (kepemilikan dari caller) cek
 *                        ini TIDAK dilaporkan (bukan temuan).
 *
 * Analisis TEKS deterministik (bukan AST), bounded, dan parsial -- jujur:
 * penelusuran tidak interprocedural; resource yang dilewati ke fungsi
 * lain (arg/return/alias) ditandai "transferred" / "unknown", bukan
 * klaim leak. Backend semantic (Eva/Fil-C/ASan) dapat menaikkan bukti.
 *
 * Notasi deklarasi (opsional; tanpa deklarasi = profil default):
 *   //@ resource fopen -> fclose;
 *   //@ resource CreateFileA -> CloseHandle;
 *
 * Hasil di res->rsrc_* (arena). Scalar selalu zero saat tidak dianalisis.
 */
#ifndef MYC_RESOURCE_H
#define MYC_RESOURCE_H

#include "myc.h"

/* Batas analisis (observasi bounded, deterministik) didefinisikan di
 * myc.h (MYC_RSRC_MAX_*); gunakan konstanta itu di resource.c. */

/* Jalankan ledger (NON-blocking) atas source. Selalu diberi hasil:
 * rsrc_ran=1, pasangan profil (default + deklarasi //@ rsrc), temuan di
 * rsrc_finding_list + report teks rsrc_report (arena). Menyandikan
 * temuan; tidak pernah menurunkan verdict. */
void myc_resource_scan(const char *source, size_t len, myc_result *res);

#endif /* MYC_RESOURCE_H */