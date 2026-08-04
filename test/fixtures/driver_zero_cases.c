/* driver_zero_cases.c -- fixture MYC-AUDIT-027
 *
 * Semua kasus di-skip guard requires (kondisi selalu salah):
 *   - harness men-rename main asli -> driver meng-drive fungsi ini
 *   - guard `g_flag == 1` selalu FALSE (g_flag==0, tak pernah diubah)
 *   - setiap case -> skip, drv_run==0 -> exit 3
 *   - myc: exit non-zero tanpa sanitizer -> INCONCLUSIVE
 *     + debt MYC-INCOMPLETE-NONZERO-CASES (0 kasus tereksekusi)
 *
 * Ini mengunci jalur debt NONZERO_CASES yang jujur (0 kasus BENAR-BENAR
 * tereksekusi), berbeda dari bad_driver_oob yang kini mengeksekusi
 * beberapa kasus sebelum crash (record per-case akurat, bukan debt).
 */

int g_flag = 0;

//@ requires g_flag == 1;
int guarded_func(int n)
{
    return n * 2;
}

int main(void)
{
    return g_flag == 1 ? 0 : 1;
}
