/* bad_run_intovf.c -- Signed integer overflow, harus terdeteksi UBSan saat
 * --run (verdict RUNTIME_VIOLATION). */
#include <limits.h>
#include <stdio.h>

int main(void)
{
    int x = INT_MAX;
    printf("%d\n", x + 1);  /* overflow signed */
    return 0;
}
