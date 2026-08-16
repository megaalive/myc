/* watchdiff_edit.c -- Fixture IDE-6 (--watch-diff) setelah edit.
 *
 * HANYA isi helper() yang berubah vs watchdiff_base.c (x+1 → x+2).
 * caller() dan main() IDENTIK dengan baseline. Delta yang diharapkan
 * saat dibandingkan dgn watchdiff_base.c:
 *   - helper  = CHANGED
 *   - caller  = DEPENDENT (identik, tapi memanggil helper yang berubah)
 *   - main    = IDENTICAL
 * Verdict tetap OK (perilaku berubah tapi tidak melanggar gate).
 */
int helper(int x)
{
    return x + 2;
}

int caller(int x)
{
    return helper(x) * 2;
}

int main(void)
{
    int a = caller(1);
    return a - 4;
}
