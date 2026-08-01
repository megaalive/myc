/* bad_checked_oob.c -- Fixture P8 (D1.2): memakai MYC_AT dengan indeks
 * out-of-bounds (via argc, opaque bagi analisis statis). Lolos gate gcc
 * statis, tapi di --run --checked fat-pointer MYC_AT menangkap
 * (marker MYC_CHECKED: -> RUNTIME_VIOLATION). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myc_buf.h"

int main(int argc, char **argv)
{
    MYC_BUF(int) b;
    size_t idx = (size_t)argc + 100;   /* pasti OOB (cap=8) */

    MYC_NEW(b, int, 8);
    if (MYC_IS_NULL(b))
        return 1;

    MYC_AT(b, int, idx) = 42;
    printf("b[%zu]=%d\n", idx, MYC_AT(b, int, idx));

    MYC_FREE(b);
    (void)argv;
    return 0;
}
