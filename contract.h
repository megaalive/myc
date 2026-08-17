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

#define MYC_MAX_CONTRACT_CLAUSES 64 /* rincian per-klausa kontrak (7.4) */
#define MYC_MAX_REL_CLAUSES 64       /* rincian klausa relasional (Fase 5) */

/* Status klausa kontrak (MYC-AUDIT-025, roadmap 7.4): hasil validasi
 * ekspresi kontrak-lite. Purity adalah SYARAT inject: klausa ber-efek
 * samping TIDAK pernah di-inject sebagai assert (safety). */
typedef enum {
    MYC_CLAUSE_OK = 0,      /* ekspresi valid + pure (layak inject) */
    MYC_CLAUSE_EMPTY,       /* ekspresi kosong (ditolak) */
    MYC_CLAUSE_TOO_LONG,    /* melebihi buffer (ditolak, no silent truncate) */
    MYC_CLAUSE_IMPURE,      /* efek samping: assignment / ++ / -- / comma */
    MYC_CLAUSE_CALL         /* pemanggilan fungsi: purity tak terbukti */
} myc_clause_status;

/* Satu klausa kontrak //@ requires/ensures ter-parse (MYC-AUDIT-025).
 * String (expr/func) disimpan di arena milik hasil. */
typedef struct {
    char *expr;             /* ekspresi kontrak */
    char *func;             /* nama fungsi terikat (stable binding);
                               "" bila tidak terikat ke fungsi */
    myc_clause_status status;
    int   line, col;        /* lokasi klausa di source */
    int   kind;             /* 0 = requires, 1 = ensures */
} myc_contract_clause;

/* Satu klausa kontrak terklasifikasi relasional (Fase 5, Relational
 * contracts). Analisis TEKS deterministik -- observasi NON-blocking,
 * verdict tidak pernah turun karenanya. `relational` = klausa yang
 * mengikat >= 2 variabel DISTINCT (order `a <= b`, kesetaraan
 * aritmetika `r == a + b`, rentang `a < b && b < c`) vs `unary`
 * (satu variabel vs konstanta, mis. `n >= 0`). `unbound` = ada
 * identifier di luar parameter fungsi DAN di luar alias return
 * (r/ret/result/res/\result) -- bisa typo atau global (observasi). */
typedef struct {
    char *expr;          /* arena: ekspresi kontrak */
    char *func;          /* arena: fungsi terikat ("" bila tak terikat) */
    int   kind;          /* 0 = requires, 1 = ensures */
    int   line, col;     /* lokasi klausa */
    int   nvars;         /* jumlah identifier DISTINCT (bukan konstanta/keyword/call) */
    int   relational;    /* 1 = >= 2 variabel */
    int   unbound;       /* 1 = ada identifier di luar params + alias return */
    int   has_order;     /* < <= > >= */
    int   has_equality;  /* == != */
    int   has_arith;     /* + - * / % */
    int   has_logic;     /* && || ! */
} myc_rel_clause;

#include "myc.h"

const char *myc_clause_status_name(myc_clause_status s);

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
 * Fase 5 (Relational contracts): klasifikasi klausa //@ requires/ensures
 * yang sudah di-scan ke res->contract_clauses (panggil SETELAH
 * myc_contract_scan). Per klausa: ekstrak identifier DISTINCT,
 * klasifikasi unary (1 variabel) vs RELATIONAL (>=2 variabel, mis.
 * `a <= b`, `r == a + b`, `a < b && b < c`), deteksi operator
 * (order/equality/arith/logic), dan BINDING CHECK -- identifier di luar
 * parameter fungsi (diekstrak dari signature) dan di luar alias return
 * (r/ret/result/res/\result) ditandai `unbound` (typo / global).
 * Hasil di res->rel_* (arena); NON-blocking observasi murni, verdict
 * tidak pernah turun karenanya. Selalu mengembalikan 1.
 */
int myc_contract_relational(const char *source, size_t len, myc_result *res);

/* ---- Contract/domain delta (Fase 2) ----
 * Bandingkan kontrak //@ requires/ensures dua versi source (before =
 * baseline, after = patch). Mendeteksi:
 *   - NARROWED : requires BERTAMBAH -> domain panggilan menyempit
 *                (repair yang "menghilangkan" bug dengan mempersempit
 *                domain = scope-laundering; Wajib ditolak di tx).
 *   - WEAKENED : ensures BERKURANG / BERUBAH -> kontrak melemah
 *                (menurunkan jaminan = melanggar preservation).
 *   - CHANGED  : perubahan lain (ensures baru / requires hilang).
 *   - CLEAN    : tidak ada perubahan kontrak.
 * isi added/removed lists (malloc'd). caller memanggil
 * myc_contract_delta_free. Selalu mengembalikan 1.
 */
typedef enum {
    MYC_DELTA_CLEAN = 0,   /* kontrak tidak berubah */
    MYC_DELTA_NARROWED,    /* requires bertambah: domain menyempit (laundering) */
    MYC_DELTA_WEAKENED,    /* ensures berkurang: kontrak melemah */
    MYC_DELTA_CHANGED      /* perubahan kontrak lain (ensures baru / requires hilang) */
} myc_contract_delta_kind;

typedef struct {
    myc_contract_delta_kind kind;
    char  **added_requires;   int n_added_requires;
    char  **removed_requires; int n_removed_requires;
    char  **added_ensures;    int n_added_ensures;
    char  **removed_ensures;  int n_removed_ensures;
} myc_contract_delta;

const char *myc_contract_delta_name(myc_contract_delta_kind k);
/* Kembalikan 1 sukses (out terisi; caller membebaskan via
 * myc_contract_delta_free), 0 = GAGAL (OOM) -- out tidak valid dan TIDAK
 * boleh dianggap CLEAN (jangan diam-diam loloskan gate). */
int myc_contract_delta_compare(const char *before, size_t before_len,
                               const char *after, size_t after_len,
                               myc_contract_delta *out);
void myc_contract_delta_free(myc_contract_delta *out);

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
