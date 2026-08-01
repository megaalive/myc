/* bad_run_uaf.c -- Use-after-free melintasi batas fungsi opaque (noinline),
 * sehingga lolos gate statis gcc (-Wuse-after-free) dan hanya terdeteksi
 * ASan saat --run (verdict RUNTIME_VIOLATION). */
#include <stdlib.h>

static char *g;

__attribute__((noinline)) static void setup(void)
{
    g = (char *)malloc(8);
}

__attribute__((noinline)) static void teardown(void)
{
    free(g);
}

int main(void)
{
    setup();
    teardown();
    return g[0];  /* use-after-free, hanya tertangkap runtime */
}
