/* rt_ubsan_ovf.c -- Fixture IDE-2 (repair RUNTIME_VIOLATION): UBSan
 * signed-integer-overflow. Tidak ada template deterministik utk kasus
 * ini -> repair harus jujur (patch null + why). Verdict: RUNTIME_VIOLATION. */
#include <limits.h>
#include <stdio.h>

int main(void)
{
    int x = INT_MAX;
    printf("%d\n", x + 1); /* signed overflow -> UBSan */
    return 0;
}
