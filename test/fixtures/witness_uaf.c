/* witness_uaf.c -- fixture untuk witness: use-after-free */
#include <stdlib.h>

int main(void)
{
    char *p = malloc(10);
    free(p);
    return *p;  /* use-after-free */
}
