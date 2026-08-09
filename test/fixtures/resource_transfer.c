/* resource_transfer.c -- Fixture Resource Lineage Ledger (SOL-12):
 * OWNERSHIP DIPINDAHKAN (return var).
 *
 * Resource yang di-return ke caller BUKAN leak. Harapan analisis:
 *   leaks = 0, transferred = 1, acquire = 1, release = 0.
 */
#include <stdio.h>

FILE *open_and_handover(void)
{
    FILE *f = fopen("y.txt", "r");
    if (!f)
        return NULL;
    return f;
}