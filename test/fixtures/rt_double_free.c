/* rt_double_free.c -- fixture runtime: double-free.
 * free(g) dua kali via fungsi noinline (drop), sehingga lolos gate
 * statis gcc -Wuse-after-free dan hanya tertangkap ASan saat --run.
 * Expected sanitizer_location: attempting double-free @drop:16. */
#include <stdlib.h>

static char *g;

__attribute__((noinline)) static void make(void)
{
    g = (char *)malloc(8);
}

__attribute__((noinline)) static void drop(void)
{
    free(g);
}

int main(void)
{
    make();
    drop();
    drop(); /* double-free: ASan hanya tertangkap runtime */
    return 0;
}
