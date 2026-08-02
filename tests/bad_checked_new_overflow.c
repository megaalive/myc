/* bad_checked_new_overflow.c -- Fixture MYC-AUDIT-012: MYC_NEW dengan n yang
 * membuat n*sizeof(T) melampaui SIZE_MAX (checked multiplication). Di checked
 * build myc_buf_alloc menolak dengan trap "MYC_CHECKED: MYC_NEW overflow" ->
 * --run --checked = RUNTIME_VIOLATION. (Juga menangkap n NEGATIF yang di-cast
 * ke size_t raksasa.) Di produksi calloc sendiri mengembalikan NULL untuk
 * overflow -> MYC_IS_NULL -> return 1 (bukan bug, hanya gagal alokasi).
 * Catatan: n sengaja opaque (via argc) agar gcc -Werror=alloc-size-larger-than
 * tidak menangkapnya lebih dulu di production build; fixture ini membuktikan
 * cek multiplication DI DALAM myc_buf.h. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "myc_buf.h"

int main(int argc, char **argv)
{
    MYC_BUF(int) b;
    size_t huge = (size_t)argc + SIZE_MAX / sizeof(int);

    MYC_NEW(b, int, huge);     /* n*4 overflow -> trap di checked build */
    if (MYC_IS_NULL(b))
        return 1;              /* produksi: calloc overflow -> NULL */

    MYC_AT(b, int, 0) = 7;
    MYC_FREE(b);
    (void)argv;
    return 0;
}
