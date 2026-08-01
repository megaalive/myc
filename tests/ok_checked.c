/* ok_checked.c -- Fixture P8 (D1.2): kode memakai makro MYC_BUF dengan
 * benar (semua akses via MYC_AT). --checked harus L4 (SPATIAL);
 * --run --checked juga bersih (L4 + runtime). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myc_buf.h"

int main(void)
{
    MYC_BUF(int) b;
    int i;
    int s = 0;

    MYC_NEW(b, int, 8);
    if (MYC_IS_NULL(b))
        return 1;

    for (i = 0; i < 8; i++)
        MYC_AT(b, int, i) = i * 2;
    for (i = 0; i < 8; i++)
        s += MYC_AT(b, int, i);
    printf("sum=%d\n", s);

    MYC_FREE(b);
    return 0;
}
