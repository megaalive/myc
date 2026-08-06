/* agent_bad.c -- fixture untuk agent_check: kode dengan finding */
#include <stdlib.h>

int main(void)
{
    char *p = malloc(10);
    /* use-after-free: p sudah di-free */
    free(p);
    return *p;
}
