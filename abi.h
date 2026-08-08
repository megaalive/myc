/*
 * abi.h -- ABI/FFI Surface Certificate (Fase 5, SOL-14).
 *
 * Snapshot deterministik permukaan ABI sebuah source C:
 *   - exported symbols (fungsi global non-static + signature);
 *   - struct size/alignment/offset (via helper program compiler-generated
 *     memakai sizeof/offsetof/_Alignof);
 *   - enum values (via helper program, nilai dihitung compiler);
 *   - target triple (`<cc> -dumpmachine`);
 *   - header digest (sha256 source).
 *
 * NON-blocking observasi: kegagalan (compiler tak ada, helper gagal
 * compile) TIDAK pernah menurunkan verdict -- hasil berupa laporan +
 * abi_ran=0. Determinisme: snapshot teks identik untuk input + compiler
 * sama; delta membandingkan baris snapshot (HEADER sha diabaikan).
 *
 * ABI delta tak diminta = hard transaction failure (SOL-14 exit criteria:
 * "ABI regression ditolak dalam transaction"), ditegakkan oleh
 * myc_transaction_verify via myc_abi_texts_changed.
 */
#ifndef MYC_ABI_H
#define MYC_ABI_H

#include "myc.h"

/* Batas snapshot (observasi bounded, deterministik). */
#define MYC_ABI_MAX_STRUCTS  24
#define MYC_ABI_MAX_MEMBERS  48      /* per struct */
#define MYC_ABI_MAX_ENUMS    16
#define MYC_ABI_MAX_ENUMVALS 64      /* per enum */
#define MYC_ABI_MAX_SYMBOLS  64
#define MYC_ABI_NAME_LEN     64
#define MYC_ABI_BODY_LEN     2048    /* deklarasi struct/enum verbatim */

/* Snapshot ABI dari source: scan deklarasi, generate helper program
 * (sizeof/offsetof/_Alignof/enum), compile + run via compiler, kumpulkan
 * teks snapshot deterministik. Hasil di res->abi_* (arena).
 * cc = compiler eksplisit atau NULL (auto-cari "gcc"). */
void myc_abi_snapshot(const char *src, size_t len, const char *cc,
                      myc_result *res);

/* Bandingkan dua teks snapshot (format "# myc abi v1"). Baris HEADER
 * diabaikan. Isi res->abi_changed / abi_n_delta / abi_delta (arena). */
void myc_abi_delta(const char *old_text, const char *new_text,
                   myc_result *res);

/* Versi ringkas untuk transaction: 1 = ada perbedaan ABI, 0 = sama.
 * out/cap opsional untuk menampung baris delta (NULL/0 = hitung saja). */
int myc_abi_texts_changed(const char *old_text, const char *new_text,
                          char *out, size_t cap);

#endif /* MYC_ABI_H */
