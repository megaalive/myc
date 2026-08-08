/* fixture A3 (DS-03): domain kecil terbatas -> enumerasi penuh = P1
 * EXHAUSTIVE (bukan bukti di luar domain dideklarasikan). */

//@ requires n >= 0 && n <= 64;
//@ ensures n >= 0 && n <= 64;
int clamp_u8(int n)
{
    if (n < 0)
        return 0;
    if (n > 64)
        return 64;
    return n;
}
