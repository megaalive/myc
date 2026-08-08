/* sm_broken.c -- Fixture State-Machine Ghosting (SOL-13): mesin RUSAK.
 *
 * Kesalahan yang disengaja untuk diverifikasi terdeteksi:
 *   - transisi merujuk event tak terdeklarasi (NOPE) -> UNDECLARED_EVENT
 *     (transisi tsb DIBUANG dari graf);
 *   - STUCK menjadi SINK (tak ada transisi keluar, bukan final);
 *   - LOST tidak pernah dicapai (tak ada transisi masuk, bukan initial);
 *   - tidak ada state final -> NO_FINAL.
 *
 * Harapan analisis: 5 finding — undeclared_event (NOPE), no_final,
 * no_recovery (BUSY: satu-satunya keluar mengarah ke STUCK yang tak bisa
 * kembali), sink (STUCK, dgn witness `IDLE --START--> BUSY --START-->
 * STUCK`), unreachable (LOST).
 */
#include <stddef.h>

//@ sm state IDLE initial;
//@ sm state BUSY;
//@ sm state STUCK;
//@ sm state LOST;
//@ sm event START;
//@ sm event RESET;
//@ sm trans IDLE --START--> BUSY;
//@ sm trans BUSY --START--> STUCK;
//@ sm trans STUCK --NOPE--> IDLE;   /* undeclared event: dibuang */
//@ sm trans LOST --RESET--> IDLE;   /* LOST unreachable */

enum { ST_IDLE, ST_BUSY, ST_STUCK, ST_LOST };
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
        g_state = ST_STUCK;   /* bug: tidak pernah kembali */
        return 0;
    }
    return -1;
}
