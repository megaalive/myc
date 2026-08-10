/* cand_base.c -- baseline untuk candidate tournament (SOL-10).
 * Memuat 1 observasi lint (pointer via uintptr_t), 1 kontrak requires,
 * dan 2 loop (for + while). Kandidat better/worse membandingkan terhadap
 * file ini. */
#include <stdint.h>

//@ requires p != 0;
static int low_bits(const int *p)
{
    uintptr_t u = (uintptr_t)p;   /* lint: pointer diubah via uintptr_t */
    return (int)(u & 0x7u);
}

int cand_base_scan(const int *buf, int n)
{
    int sum = 0;
    int i;
    for (i = 0; i < n; i++)
        sum += buf[i];
    while (sum > 1000)
        sum -= 1000;
    return sum + low_bits(buf);
}
