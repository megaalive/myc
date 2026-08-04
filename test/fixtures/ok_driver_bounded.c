/* bounded_probe.c -- probe combinatorial budget coverage-first (AUDIT-027) */
#include <stdio.h>

//@ requires a <= 3;
//@ requires b <= 3;
//@ requires c <= 3;
int triple(int a, int b, int c)
{
    return a + b + c;
}

int main(void)
{
    printf("%d\n", triple(1, 1, 1));
    return 0;
}
