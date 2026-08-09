/*
 * units.h -- Units, Shape, dan Provenance Contracts (Fase 5, SOL-11).
 *
 * Annotation ringan menambah vocabulary semantik yang type system C tidak
 * miliki:
 *
 *     //@ unit        len bytes              -- satuan kuantitas
 *     //@ shape       buf capacity=cap length=len
 *     //@ provenance  p owned
 *     //@ endian      value little
 *
 * myc melacak subset sederhana secara DETERMINISTIK (analisis teks,
 * bukan AST) melalui assignment, check dimensi shape, dan konsistensi antar
 * annotation pada identifier yang sama. Semua temuan diawasi observasi
 * NON-blocking: verdict TIDAK pernah turun karenanya.
 *
 * Temuan (myc_units_finding_kind):
 *  - UNBOUND          : identifier pada annotation tidak pernah muncul
 *                        di source (salah eja / annotation yatim).
 *  - UNIT_MISMATCH    : di dalam body fungsi, `lhs = rhs` di mana kedua
 *                        sisi ter-unit dan unitnya berbeda.
 *   - SHAPE_DIM        : capacity dan length dari shape yang sama
 *                        ter-unit dengan dimensi berbeda.
 *   - DUP_CONFLICT     : dua annotation bertentangan (unit berubah /
 *                        endian berubah) pada identifier yang sama.
 *
 * Batas jujur: penelusuran assignment hanya intra-fungsi dan hanya utk
 * identifier yang eksplisit ter-annotasi; selain itu = "tak ada bukti",
 * bukan klaim. Backend semantic (contract/Eva/ASan) dapat menaikkan bukti.
 *
 * Hasil di res->units_* (arena). Scalar selalu zero saat tidak dianalisis.
 */
#ifndef MYC_UNITS_H
#define MYC_UNITS_H

#include "myc.h"

/* Batas analisis di myc.h (MYC_UNITS_MAX_*). */
void myc_units_scan(const char *source, size_t len, myc_result *res);

#endif /* MYC_UNITS_H */