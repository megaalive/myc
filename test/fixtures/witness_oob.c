/* witness_oob.c -- fixture untuk witness: out-of-bounds */
#include <stdlib.h>

int main(void)
{
    char *p = malloc(10);
    p[10] = 'x';  /* out-of-bounds */
    free(p);
    return 0;
}
