/* cand_worse.c -- kandidat B untuk candidate tournament (SOL-10).
 * Regresi: menambah observasi lint (2 cast uintptr_t), menghapus kontrak
 * requires (obligations_lost), menambah loop (4), dan satu baris sangat
 * panjang yang menurunkan readability. Dipakai menguji Pareto dominance:
 * kandidat ini harus DIDOMINASI oleh baseline dan kandidat better.
 * (Tanpa //@ requires -- kontrak baseline dihilangkan.) */
#include <stdint.h>

static int low_bits(const int *p)
{
    uintptr_t u = (uintptr_t)p;
    uintptr_t v = (uintptr_t)p + 1;
    return (int)((u ^ v) & 0x7u);
}

int cand_worse_scan(const int *buf, int n)
{
    int sum = 0;
    int i;
    for (i = 0; i < n; i++)
        sum += buf[i];
    for (i = 0; i < n; i++)
        sum ^= buf[i];
    while (sum > 1000)
        sum -= 1000;
    do {
        sum -= 1;
    } while (sum > 500);
    /* baris panjang: sum ditambah sebanyak buf[i] untuk i pada rentang 0..n-1 yang nilainya genap dan tidak nol, lalu dikurangi satu, demi menguji perhitungan readability pada baris yang melebihi seratus kolom */
    return sum + low_bits(buf);
}
