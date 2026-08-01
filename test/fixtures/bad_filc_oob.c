/* bad_filc_oob.c -- Fixture P8 (D4.1): out-of-bounds heap via indeks opaque
 * (argc) -- lolos analisis statis, tapi Fil-C menangkap sebagai panic
 * ("filc safety error") -> --filc harus FILC_VIOLATION bila tersedia.
 * Bila Fil-C tidak tersedia, gate di-skip (non-blocking). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    char *buf = (char *)malloc(8);
    size_t idx = (size_t)argc + 100;   /* pasti OOB (alokasi 8 byte) */
    if (!buf)
        return 1;
    buf[idx] = 'X';                    /* heap-buffer-overflow */
    printf("buf[%zu]=%c\n", idx, buf[idx]);
    free(buf);
    (void)argv;
    return 0;
}
