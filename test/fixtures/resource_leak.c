/* resource_leak.c -- Fixture Resource Linearity Ledger (SOL-12): LEAK.
 *
 * `fopen` di-acquire tanpa pernah di-release (dan tanpa di-return).
 * Harapan analisis (deterministik, observasi NON-blocking):
 *   leaks = 1 (di fungsi open_and_forget), acquire = 1, release = 0.
 */
#include <stdio.h>

int open_and_forget(void)
{
    FILE *f = fopen("x.txt", "w");
    if (!f)
        return -1;
    return 0;
}