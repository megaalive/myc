/* watchdiff_base.c -- Fixture IDE-6 (--watch-diff) baseline.
 *
 * 3 fungsi: helper (primitif), caller (memanggil helper), main (memanggil
 * caller). Pasangan watchdiff_edit.c mengubah HANYA isi helper → delta
 * yang diharapkan: helper=berubah, caller=dependent (identik tapi
 * memanggil helper), main=identik. Verdict tetap OK (exit code bukan
 * finding; run gate tidak aktif).
 */
int helper(int x)
{
    return x + 1;
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
