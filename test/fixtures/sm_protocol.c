/* sm_protocol.c -- Fixture State-Machine Ghosting (SOL-13): mesin SEHAT.
 *
 * Mesin protocol minimal dengan recovery lengkap:
 *   IDLE --START--> BUSY --DONE--> IDLE        (siklus normal)
 *   BUSY --TIMEOUT--> ERROR --RESET--> IDLE    (recovery dari error)
 *
 * Harapan analisis (deterministik, observasi NON-blocking):
 *   3 state (IDLE initial, BUSY, ERROR final), 4 event, 4 transisi,
 *   findings = 0 (semua state reachable, tidak ada sink, semua bisa
 *   kembali ke initial).
 */
#include <stddef.h>

//@ sm state IDLE initial;
//@ sm state BUSY;
//@ sm state ERROR final;
//@ sm event START;
//@ sm event TIMEOUT;
//@ sm event DONE;
//@ sm event RESET;
//@ sm trans IDLE --START--> BUSY;
//@ sm trans BUSY --TIMEOUT--> ERROR;
//@ sm trans BUSY --DONE--> IDLE;
//@ sm trans ERROR --RESET--> IDLE;

/* Body nyata: transisi dijalankan dengan switch pada state. */
enum { ST_IDLE, ST_BUSY, ST_ERROR };
static int g_state = ST_IDLE;

int handle_event(int ev)
{
    switch (g_state) {
    case ST_IDLE:
        if (ev == 1) {
            g_state = ST_BUSY;
            return 0;
        }
        break;
    case ST_BUSY:
        if (ev == 2) {
            g_state = ST_ERROR;
            return 0;
        }
        if (ev == 3) {
            g_state = ST_IDLE;
            return 0;
        }
        break;
    case ST_ERROR:
        if (ev == 4) {
            g_state = ST_IDLE;
            return 0;
        }
        break;
    }
    return -1;
}
