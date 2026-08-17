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

#include <stddef.h>

#define MYC_UNITS_MAX_ANNS    64
#define MYC_UNITS_MAX_FINDINGS 32
#define MYC_UNITS_NAME_LEN    64

typedef enum {
    MYC_UNITS_UNBOUND = 0,    /* ident annotation tak terikat di source */
    MYC_UNITS_UNIT_MISMATCH,  /* `lhs = rhs` beda unit di dalam fungsi  */
    MYC_UNITS_SHAPE_DIM,      /* capacity vs length beda dimensi        */
    MYC_UNITS_DUP_CONFLICT    /* dua annotasi bertentangan pada id sama  */
} myc_units_finding_kind;

typedef struct {
    myc_units_finding_kind kind;
    char *text;       /* arena: penjelasan */
    char *witness;    /* arena: konteks (mis. "x = y @12@|L" -> label) */
    int   line;
} myc_units_finding;

#include "myc.h"

const char *myc_units_finding_name(myc_units_finding_kind k);

void myc_units_scan(const char *source, size_t len, myc_result *res);

#endif /* MYC_UNITS_H */