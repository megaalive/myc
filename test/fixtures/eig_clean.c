/*
 * eig_clean.c -- fixture Fase 7 (#2029, DS-14): Expected-Information-Gain
 * scheduler.
 *
 * Program BERSIH (compile gate clean; verdict OK). Dengan check default
 * (compile-only), 6 hazard class berstatus `untested` -> `myc eig <file>`
 * menghasilkan 6 rekomendasi terurut dengan prior deterministik (tabel,
 * dikalibrasi dari ledger SOL-21 dan profil SOL-20 bila diberikan).
 * NON-blocking: skor rekomendasi tidak mengubah verdict.
 */
#include <limits.h>

static int sat_add(int a, int b)
{
    long long s = (long long)a + (long long)b;
    if (s > INT_MAX)
        return INT_MAX;
    if (s < INT_MIN)
        return INT_MIN;
    return (int)s;
}

int main(void)
{
    int acc = 0;
    int i;
    for (i = 0; i < 8; i++)
        acc = sat_add(acc, i * i);
    return acc;
}
