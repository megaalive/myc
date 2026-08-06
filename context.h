/*
 * context.h -- Agent Context Compiler (Fase 3, SOL-22).
 *
 * `myc context <file.c>` menghasilkan PAKET konteks minimal untuk model:
 * bukan seluruh source/log/docs (boros token), melainkan hanya bagian yang
 * relevan dengan SATU finding:
 *
 *   - finding (satu, root cause dulu — causal order);
 *   - function slice (isi fungsi yang memuat finding);
 *   - callers/callees minimal (fungsi pemanggil / dipanggil);
 *   - contracts (klausa //@ di atas fungsi);
 *   - witness (repro + slice bila ada);
 *   - target facts (identitas toolchain);
 *   - one action (primary action + next-best experiment);
 *   - preservation obligations (anti-churn / anti-weakening);
 *   - exact verification command (perintah untuk mengulang bukti).
 *
 * Budget token dapat dipilih (4K/8K/16K approximation; default 8K).
 * Paket DETERMINISTIK: input + flags sama -> paket sama, dan memiliki
 * hash sha256 (context_sha256 di header; hash mencakup isi paket TANPA
 * baris hash itu sendiri).
 *
 * NON-blocking: context adalah DERIVASI murni dari hasil run (myc_result +
 * source + request). Tidak mengubah verdict, tidak menambah gate, tidak
 * menambah debt.
 */
#ifndef MYC_CONTEXT_H
#define MYC_CONTEXT_H

#include "myc.h"

/* Budget default (token approximation) dan nilai yang diterima CLI. */
#define MYC_CONTEXT_BUDGET_DEFAULT 8192
#define MYC_CONTEXT_BUDGET_MIN     4096
#define MYC_CONTEXT_BUDGET_MAX     16384

/*
 * Bangun paket konteks untuk SATU finding.
 *
 * res      : hasil run (diags, witness, assurance, identity tool).
 * src/len  : source asli (untuk function slice + callers/callees + kontrak).
 * req      : request (untuk scenario hash + exact verification command).
 * finding_id: NULL = pilih primary/root otomatis; "f-%08x" = line hex.
 * budget_tokens: target ukuran (approximation; bagian prioritas rendah
 *             di-truncate dengan penanda eksplisit).
 * hash_out : 65 byte diisi sha256 hex dari isi paket (tanpa baris hash).
 *
 * Mengembalikan string malloc'd (caller free) berisi paket teks, atau NULL
 * bila source/req/res tidak valid. Bila tidak ada finding terkonfirmasi,
 * paket tetap dihasilkan (target facts + verify command) dengan catatan
 * "tidak ada finding terkonfirmasi".
 */
char *myc_context_build(const myc_result *res,
                        const char *src, size_t srclen,
                        const myc_request *req,
                        const char *finding_id,
                        int budget_tokens,
                        char hash_out[65]);

#endif /* MYC_CONTEXT_H */
