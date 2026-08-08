/*
 * state.h -- State-Machine Ghosting (Fase 5, SOL-13).
 *
 * Membangun "ghost state machine" dari deklarasi //@ sm (deterministik,
 * bukan AST):
 *     //@ sm state IDLE initial;
 *     //@ sm state BUSY;
 *     //@ sm state ERROR final;
 *     //@ sm event START;
 *     //@ sm event TIMEOUT;
 *     //@ sm event RESET;
 *     //@ sm trans IDLE --START--> BUSY;
 *     //@ sm trans BUSY --TIMEOUT--> ERROR;
 *     //@ sm trans ERROR --RESET--> IDLE;
 *
 * Analisis (NON-blocking observasi; verdict tidak pernah turun):
 *   - SINK        : state tanpa transisi keluar, bukan final (dead state);
 *                   witness = urutan event terpendek dari initial (BFS).
 *   - UNREACHABLE : state != initial tanpa transisi masuk.
 *   - NO_RECOVERY : state ber-transisi keluar tapi tak ada jalur kembali
 *                   ke initial (perangkap satu arah); witness jalur masuk.
 *   - UNDECLARED  : transisi merujuk state/event yang tidak dideklarasikan
 *                   (typo spec machine); transisi tsb TIDAK masuk graf.
 *   - UNUSED      : state/event dideklarasikan tapi tak dipakai transisi.
 *   - NO_INITIAL / NO_FINAL : mesin tanpa initial/final; initial implisit
 *                   = state pertama yang dideklarasikan (witness tetap
 *                   dihasilkan).
 *   - DUP_DECL    : deklarasi nama ganda (state/event).
 *
 * Cek bersifat PARSIAL (jujur): "illegal transition" = referensi tak
 * terdeklarasi + struktur graf (sink/unreachable/no-recovery). Matriks
 * (state,event) yang HILANG (event dipakai di state lain tapi tidak di
 * state S) sengaja TIDAK dilaporkan demi anti-noise (O(state x event));
 * invariant per state (//@ sm invariant) = future work. Ini observasi,
 * bukan sertifikat kelengkapan machine.
 *
 * Witness berupa urutan event ("IDLE --START--> BUSY ...") jauh lebih
 * mudah dipahami LLM daripada stack trace (SOL-13).
 * Hasil di res->sm_* (arena). Selalu mengembalikan 1.
 */
#ifndef MYC_STATE_H
#define MYC_STATE_H

#include <stddef.h>

#include "myc.h"

int myc_sm_scan(const char *source, size_t len, myc_result *res);

#endif /* MYC_STATE_H */
