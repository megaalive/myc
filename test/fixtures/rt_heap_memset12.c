/* rt_heap_memset12.c -- fixture runtime: heap-buffer-overflow dengan
 * kapasitas malloc 2-digit (malloc(12), memset n=24). Memverifikasi
 * sanloc membaca kapasitas multi-digit dan lokasi heap overflow.
 * Expected sanitizer_location: heap-buffer-overflow @main:13. */
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *p = (char *)malloc(12);
    if (!p)
        return 1;
    memset(p, 0, 24); /* heap-buffer-overflow: 24 > 12 */
    free(p);
    return 0;
}
