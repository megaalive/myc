/* bad_checked.c -- Fixture P8 (D1.2): memakai MYC_BUF TAPI mengakses
 * langsung b[i] (bukan MYC_AT). Di checked build (-DMYC_CHECKED) fat-struct
 * tidak bisa di-index -> COMPILE_ERROR. Inilah mekanisme L4: akses langsung
 * pada buffer MYC_BUF dipaksa gagal, sehingga semua akses ter-cover MYC_AT. */
#include <stdlib.h>
#include <string.h>

#include "myc_buf.h"

int main(void)
{
    MYC_BUF(int) b;
    int i;

    MYC_NEW(b, int, 8);
    if (MYC_IS_NULL(b))
        return 1;

    for (i = 0; i < 8; i++)
        b[i] = i;           /* SALAH: akses langsung, harus MYC_AT(b,int,i) */

    MYC_FREE(b);
    return 0;
}
