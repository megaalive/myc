/*
 * ok_bounds.c -- fixture P4: loop index aman, tier dasar memori tidak boleh
 * bising (nol false positive pada kode sah). Harus OK di myc check.
 */
#include <stdio.h>

int main(void)
{
    int arr[16];
    int i;
    for (i = 0; i < 16; i++)
        arr[i] = i * i;
    printf("last=%d\n", arr[15]);
    return 0;
}
