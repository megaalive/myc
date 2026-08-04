/* semantics_parity.c -- Fixture MYC-AUDIT-026 (roadmap 7.3): SEMANTICS
 * PARITY. Program deterministik yang memakai MYC_BUF (buffer int + buffer
 * struct). Test harness mengkompilasinya DUA KALI dan membandingkan output:
 *   1. produksi:  gcc -O2 ...            (MYC_BUF = T* polos, tanpa cek)
 *   2. checked:   gcc -O2 -DMYC_CHECKED=1 (fat-struct + cek batas runtime)
 * stdout + exit code harus IDENTIK -> membuktikan transformasi fat-pointer
 * TIDAK mengubah perilaku kode yang sah (nol false positive).
 *
 * Coverage yang harus dideteksi `myc check --checked` (per TITIK di source,
 * bukan per eksekusi runtime):
 *   buffers=2 allocations=2 accesses=6 frees=2
 *   (1 isi + 1 baca buffer int; 2 isi + 2 baca buffer point)
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "myc_buf.h"

typedef struct { int x, y; } point;

#define INTCAP 64
#define PTSCAP 16

int main(void)
{
    MYC_BUF(int) a;
    MYC_BUF(point) pts;
    int      i;
    uint32_t d = 0;

    MYC_NEW(a, int, INTCAP);
    MYC_NEW(pts, point, PTSCAP);
    if (MYC_IS_NULL(a) || MYC_IS_NULL(pts))
        return 1;

    /* isi + baca buffer int (akses batas aman 0..INTCAP-1) */
    for (i = 0; i < INTCAP; i++)
        MYC_AT(a, int, i) = (i * 7 + 3) % 251;
    for (i = 0; i < INTCAP; i++)
        d = d * 31u + (uint32_t)MYC_AT(a, int, i);

    /* isi + baca buffer struct point */
    for (i = 0; i < PTSCAP; i++) {
        MYC_AT(pts, point, i).x = i * 11;
        MYC_AT(pts, point, i).y = i * 13 + 1;
    }
    for (i = 0; i < PTSCAP; i++)
        d = d * 31u + (uint32_t)(MYC_AT(pts, point, i).x +
                                 MYC_AT(pts, point, i).y);

    printf("digest=%u\n", (unsigned)d);

    MYC_FREE(a);
    MYC_FREE(pts);
    return 0;
}
