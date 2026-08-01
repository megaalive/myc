/* ok_filc.c -- Fixture P8 (D4.1): program bersih yang aman di Fil-C.
 * Bila filc-clang tersedia (PATH/WSL) dan run bersih (tanpa marker panic),
 * --filc harus L5 (FULL). Bila Fil-C tidak tersedia, gate di-skip
 * (non-blocking) -> assurance statis (L1) + diagnostic. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *msg = (char *)malloc(6);
    size_t i;
    if (!msg)
        return 1;
    memcpy(msg, "hello", 6);
    for (i = 0; i < 5; i++)
        putchar(msg[i]);
    putchar('\n');
    free(msg);
    return 0;
}
