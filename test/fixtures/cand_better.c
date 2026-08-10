/* cand_better.c -- kandidat A untuk candidate tournament (SOL-10).
 * Memperbaiki observasi lint baseline (tanpa cast uintptr_t),
 * mempertahankan kontrak requires dan struktur (churn kecil, loop sama).
 * Harus tidak didominasi pada dimensi yang terukur. */
#include <stdint.h>

//@ requires p != 0;
static int low_bits(const int *p)
{
    (void)p;
    return 0;
}

int cand_better_scan(const int *buf, int n)
{
    int sum = 0;
    int i;
    for (i = 0; i < n; i++)
        sum += buf[i];
    while (sum > 1000)
        sum -= 1000;
    return sum + low_bits(buf);
}
