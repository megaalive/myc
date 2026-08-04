/* MYC-AUDIT-025 -- fix review (stable binding / purity scan):
 *   1. ';' SELALU membuang pending kontrak (statement ber-parens tanpa
 *      ident pemanggil, mis. `while (y--) ;`, menyisakan pending basi yang
 *      bila tidak dibuang akan ter-inject ke fungsi BERIKUTNYA -> assert
 *      palsu di dummy()).
 *   2. Teks `//@` di DALAM komentar blok BUKAN klausa nyata (klausa hantu
 *      dari contoh kontrak di komentar header harus TIDAK dihitung).
 *   //@ requires ghost > 0     <- klausa hantu: harus diabaikan
 */

int dummy(int y);   /* prototype: ';' memutus ikatan, aman */

int main(void)
{
    int y = 0;
    /* klausa di dalam body (bukan sebelum fungsi) -- ';' harus membuang */
    //@ requires y > 0
    while (y--) ;
    /* dummy dipanggil dengan 0: bila assert(y>0) palsu ter-inject ke
     * dummy (regresi fix ';'), assert gagal -> RUNTIME_VIOLATION. */
    return dummy(0);
}

/* tanpa fix ';': dummy() menerima assert(y > 0) palsu -> dummy(0) gagal */
int dummy(int y)
{
    return y;
}
