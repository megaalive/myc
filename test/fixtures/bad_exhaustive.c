/* fixture A3 BAD (DS-03): ensures `n < 64` GAGAL pada titik domain n=64 ->
 * enumerasi penuh menemukan counterexample (bukan proof). */

//@ requires n >= 0 && n <= 64;
//@ ensures n < 64;
int clamp_wrong(int n)
{
    if (n < 0)
        return 0;
    if (n > 64)
        return 64;
    return n;
}
