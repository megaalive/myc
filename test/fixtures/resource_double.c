/* resource_double.c -- Fixture Resource Linearity Ledger (SOL-12):
 * DOUBLE-RELEASE.
 *
 * `fclose` dipanggil dua kali pada resource yang sama. Harapan analisis:
 *   double_releases = 1 (di fungsi close_twice), acquire = 1,
 *   release = 2.
 */
#include <stdio.h>

int close_twice(void)
{
    FILE *f = fopen("z.txt", "r");
    if (!f)
        return -1;
    fclose(f);
    fclose(f);
    return 0;
}