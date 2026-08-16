/* watchdiff_edit2.c -- Fixture IDE-6 (--watch-diff) edit kedua.
 *
 * helper() berubah LAGI vs watchdiff_edit.c (x+2 → x+3). Dipakai blok
 * test 6i untuk menghasilkan MISS baru (vs baseline edit) agar JSON
 * summary --delta memuat delta n_changed=1 yang nyata (bukan cache hit).
 * caller()/main() identik dgn watchdiff_edit.c.
 */
int helper(int x)
{
    return x + 3;
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
