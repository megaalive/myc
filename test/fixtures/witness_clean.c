/* witness_clean.c -- fixture untuk witness: kode bersih */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    char *p = malloc(10);
    if (p) {
        printf("hello\n");
        free(p);
    }
    return 0;
}
