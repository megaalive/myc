/*
 * negative_ok.c -- Fixture Negative-Space Analysis (9.8, --negative).
 * Semua callsite alokasi MEMERIKSA hasil -> gate COMPLETED_CLEAN,
 * verdict tetap OK (observasi non-blocking).
 */
#include <stdlib.h>

int main(void)
{
    char *a = (char *)malloc(8);
    char *b;
    char *c = (char *)calloc(16, 1);

    if (a == NULL)
        return 1;
    if (!c)
        return 1;

    b = (char *)malloc(24);
    if (b == NULL)
        return 1;

    free(a);
    free(b);
    free(c);
    return 0;
}
