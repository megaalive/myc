/* raw_buf_mixed.c -- Fixture MYC-AUDIT-040: DISIPLIN CHECKED CAMPURAN.
 *
 * Program memakai makro MYC_BUF (checked-build, L4 SPATIAL) untuk SATU
 * buffer, tapi masih mendeklarasikan/mengakses array biasa (char raw[..])
 * DI LUAR MYC_BUF. Transformasi fat-pointer (--checked) hanya menutup
 * buffer MYC_BUF, bukan array biasa -> L4 SPATIAL parsial. Debt
 * MYC-INCOMPLETE-RAW-BUFFERS harus muncul di unverified_debt (gap jujur,
 * NON-blocking: verdict TIDAK turun tanpa --require-complete).
 *
 * Harapan `myc check --checked`:
 *   - verdict: OK (checked build lolos; buffer MYC_BUF patuh disiplin)
 *   - checked: uses_myc_buf yes, build_ok yes, raw_buffers >= 1
 *   - unverified_debt: [MYC-INCOMPLETE-RAW-BUFFERS]
 *   - `--checked --require-complete` -> verdict INCONCLUSIVE
 */
#include <stdio.h>
#include "myc_buf.h"

#define N 16

int main(void)
{
    MYC_BUF(int) a;
    int          raw[N];   /* buffer biasa di luar MYC_BUF */
    int          i, sum = 0;

    MYC_NEW(a, int, N);
    if (MYC_IS_NULL(a))
        return 1;

    /* buffer MYC_BUF: akses via MYC_AT (disiplin checked). */
    for (i = 0; i < N; i++)
        MYC_AT(a, int, i) = i * 3;

    /* array biasa: akses langsung — di luar cakupan fat-pointer. */
    for (i = 0; i < N; i++)
        raw[i] = MYC_AT(a, int, i);

    for (i = 0; i < N; i++)
        sum += raw[i];

    printf("sum=%d\n", sum);

    MYC_FREE(a);
    return 0;
}
