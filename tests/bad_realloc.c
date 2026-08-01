/*
 * bad_realloc.c -- fixture P5: realloc disimpan ke variabel lain, pointer
 * lama tetap dipakai -> lint harus menolak (VIOLATION lint, use-after-free).
 */
#include <stdlib.h>

int main(void)
{
    char *buf = (char *)malloc(16);
    char *tmp;
    if (!buf)
        return 1;
    tmp = (char *)realloc(buf, 32); /* pointer lama invalid setelah ini */
    buf[0] = 'x';                   /* memakai pointer lama (UAF) */
    free(tmp);
    return 0;
}
