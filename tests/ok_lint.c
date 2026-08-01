/*
 * ok_lint.c -- fixture P5: source bersih (lint harus diam, no warning).
 * Menggunakan malloc + memcpy dengan sizeof secara eksplisit.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char  msg[] = "hello lint";
    char *buf = (char *)malloc(sizeof(char) * 32);
    if (!buf)
        return 1;
    memcpy(buf, msg, sizeof(msg));
    printf("%s\n", buf);
    free(buf);
    return 0;
}
