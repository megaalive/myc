/*
 * divergence_oob.c -- fixture gate Cross-Toolchain Divergence (A2):
 * heap-buffer-overflow -> sel clang (dgn sanitizer) menemukan finding;
 * gcc (fallback tanpa sanitizer) tetap dijalankan utk semantic compare.
 * Verdict harus RUNTIME_VIOLATION (HARD), klasifikasi sanitizer_divergence
 * atau all_findings.
 */
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *p = (char *)malloc(8);
    if (!p)
        return 1;
    memcpy(p, "0123456789abcdef", 16);   /* heap-buffer-overflow */
    return p[0];
}
