/* bad_checked_type.c -- Fixture MYC-AUDIT-012: MYC_AT dipanggil dengan tipe
 * elemen yang BERBEDA UKURANNYA dari deklarasi MYC_BUF (char pada
 * MYC_BUF(int)). Sebelum audit, elem_size tidak disimpan sehingga tipe salah
 * lolos diam-diam (rasa aman palsu). Kini checked build (-DMYC_CHECKED)
 * menolaknya di COMPILE TIME via trik array negatif
 * `sizeof(char[sizeof(T)==sizeof((b).data[0]) ? 1 : -1])` (tipe elemen
 * tersimpan di TYPE member `data`) -> COMPILE_ERROR.
 * (Di produksi, T di MYC_AT diabaikan -> kode tetap lulus L1; hanya
 * disiplin checked build yang menolak.) */
#include <stdlib.h>
#include <string.h>

#include "myc_buf.h"

int main(void)
{
    MYC_BUF(int) b;

    MYC_NEW(b, int, 8);
    if (MYC_IS_NULL(b))
        return 1;

    MYC_AT(b, char, 0) = 1;   /* SALAH: MYC_BUF(int) diakses sebagai char */

    MYC_FREE(b);
    return 0;
}
