/*
 * divergence_clean.c -- fixture gate Cross-Toolchain Divergence (A2):
 * program deterministik tanpa UB -> matriks {gcc,clang} x {-O0,-O2}
 * harus konsisten (clean di semua sel, klasifikasi konsisten).
 */
#include <stdio.h>

int main(void)
{
    int sum = 0;
    int i;
    for (i = 0; i < 100; i++)
        sum += i;
    printf("divergence_clean:%d\n", sum);
    return 0;
}
