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

/* Ghost state machine dari deklarasi //@ sm (state/event/trans).
 * NON-blocking observasi. String (name/from/event/to/text/witness)
 * disimpan di arena milik hasil. */
#define MYC_SM_MAX_STATES   32
#define MYC_SM_MAX_EVENTS   32
#define MYC_SM_MAX_TRANS    64
#define MYC_SM_MAX_FINDINGS 32

typedef enum {
    MYC_SM_SINK = 0,         /* state tanpa transisi keluar, bukan final */
    MYC_SM_UNREACHABLE,      /* tak ada transisi masuk, bukan initial */
    MYC_SM_NO_RECOVERY,      /* tak ada jalur kembali ke initial */
    MYC_SM_UNDECLARED_STATE, /* transisi merujuk state tak terdeklarasi */
    MYC_SM_UNDECLARED_EVENT, /* transisi merujuk event tak terdeklarasi */
    MYC_SM_UNUSED_STATE,     /* state dideklarasikan tapi tak dipakai */
    MYC_SM_UNUSED_EVENT,     /* event dideklarasikan tapi tak dipakai */
    MYC_SM_NO_INITIAL,       /* tidak ada state initial (pakai state pertama) */
    MYC_SM_NO_FINAL,         /* tidak ada state final */
    MYC_SM_DUP_DECL          /* deklarasi nama ganda */
} myc_sm_finding_kind;

typedef struct {
    char *name;       /* arena */
    int   line;
    int   is_initial;
    int   is_final;
} myc_sm_state;

typedef struct {
    char *name;       /* arena */
    int   line;
} myc_sm_event;

typedef struct {
    char *from;       /* arena */
    char *event;      /* arena */
    char *to;         /* arena */
    int   line;
} myc_sm_trans;

typedef struct {
    myc_sm_finding_kind kind;
    char *text;       /* arena: penjelasan */
    char *witness;    /* arena: urutan event terpendek ("" bila tak ada) */
    int   line;
} myc_sm_finding;

#include "myc.h"

const char *myc_sm_finding_name(myc_sm_finding_kind k);

int myc_sm_scan(const char *source, size_t len, myc_result *res);

#endif /* MYC_STATE_H */
