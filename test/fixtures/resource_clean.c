/* resource_clean.c -- Fixture Resource Linearity Ledger (SOL-12): SEHAT.
 *
 * Semua resource di-acquire lalu di-release tepat sekali. Harapan
 * analisis (deterministik, observasi NON-blocking):
 *   leaks = 0, double_releases = 0, release_unknown = 0,
 *   acquire = 3, release = 3.
 */
#include <stdio.h>

int open_and_close_ok(void)
{
    FILE *f = fopen("a.txt", "r");
    if (!f)
        return -1;
    fclose(f);
    return 0;
}

int nested_immediate_ok(void)
{
    fclose(fopen("b.txt", "r"));
    return 0;
}

int open_close_indirect_ok(void)
{
    int fd = open("c.txt", 0);
    if (fd < 0)
        return -1;
    close(fd);
    return 0;
}