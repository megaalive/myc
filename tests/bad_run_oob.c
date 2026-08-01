/* bad_run_oob.c -- Heap-buffer-overflow yang lolos statis, harus terdeteksi
 * ASan saat --run (verdict RUNTIME_VIOLATION, assurance tidak naik ke L3). */
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *b = (char *)malloc(8);
    if (!b)
        return 1;
    memset(b, 'A', 16);  /* overflow 8 byte melewati alokasi */
    free(b);
    return 0;
}
