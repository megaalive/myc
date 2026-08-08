/*
 * contract.h -- Contract-lite (D1.5): parse //@ requires/ensures.
 *
 * Kontrak satu-baris bergaya ACSL minimum:
 *     //@ requires expr;
 *     //@ ensures  expr;
 *
 * Dua kegunaan (bertahap):
 *   1. Scan & validasi: menghitung requires/ensures, menandai kontrak yang
 *      tidak terbaca (diagnostic). Ini data masukan untuk gate Frama-C Eva
 *      (D3.1, L2 EVA) nanti.
 *   2. Inject runtime: menghasilkan salinan source dengan `assert(expr)`
 *      disisipkan setelah `{` pembuka fungsi yang didahului `//@ requires`.
 *      Dipakai oleh verification build (--run, L3) sebagai defense-in-depth.
 *
 * Catatan jujur (lihat rencana): inject berbasis scanner baris/karakter,
 * HEURISTIK, bukan AST. Pola yang tidak dikenali dengan yakin TIDAK di-inject
 * (dibiarkan sebagai kontrak statis) agar tidak menimbulkan false violation.
 * ensures tidak di-inject di v1 (butuh menangkap nilai return -- diperiksa
 * oleh Frama-C nanti).
 */
#ifndef MYC_CONTRACT_H
#define MYC_CONTRACT_H

#include <stddef.h>

#include "myc.h"

/*
 * Scan source untuk kontrak //@ requires/ensures. Mengisi
 * res->contract_requires / res->contract_ensures dan menambah diagnostic
 * bila ada kontrak yang tidak terbaca (mis. ekspresi kosong). SELALU
 * mengembalikan 1 (non-blocking, info).
 */
int myc_contract_scan(const char *source, size_t len, myc_result *res);

/*
 * Buat salinan source dengan assert(requires) disisipkan (untuk verification
 * build). Mengembalikan string malloc'd; *out_len diisi bila return non-NULL.
 * Mengembalikan NULL bila tidak ada kontrak yang layak inject (caller memakai
 * source asli; *out_len TIDAK disentuh).
 */
char *myc_contract_inject(const char *source, size_t len, size_t *out_len);

/*
 * List semua kontrak //@ requires/ensures sebagai string ekspresi (tanpa
 * kata kunci). Mengisi *reqs dan *ensures dengan array malloc'd berisi
 * string malloc'd; *nreqs dan *nensures = jumlah. Caller membebaskan tiap
 * elemen dan array. Bila tidak ada kontrak, *reqs = NULL dan *nreqs = 0.
 * Selalu mengembalikan 1 (non-blocking). Dipakai tool MCP `contracts` (P9).
 */
int myc_contract_list(const char *source, size_t len,
                      char ***reqs, int *nreqs,
                      char ***ensures, int *nensures);

/*
 * B4 (Comments-as-Contracts, DS-08): panen kandidat kontrak dari KOMENTAR
 * BIASA (bukan //@). Pola bahasa deterministik (bukan NLP):
 *   - "returns X" / "return X"              -> ensures X
 *   - "X must not exceed Y"                  -> X <= Y
 *   - "X must be <=|<|>=|> Y"                -> X op Y
 *   - "assumes X" / "requires X"            -> X (requires)
 *   - "precondition: X" / "pre: X"          -> X (requires)
 *   - "postcondition: X" / "post: X"        -> X (ensures)
 *   - komparasi langsung "X <= Y" dst.       -> X op Y
 *
 * Lifecycle DS-08: candidate (pola terdeteksi) -> validated (ekspresi C
 * murni + terikat fungsi) -> promoted (user menulis //@) -> enforced
 * (gate). Non-blocking: hasil HANYA observasi; verdict tidak pernah turun
 * karenanya. Mengisi res->harvest_candidates / harvest_validated /
 * harvest_unbound / harvest_report (arena). Selalu mengembalikan 1.
 */
int myc_contract_harvest(const char *source, size_t len, myc_result *res);

#endif /* MYC_CONTRACT_H */
