/* fixture Fase 6 (regression corpus): versi FIXED dari fuzz_div0.c.
 * Seed regression yang tersimpan dari versi buggy harus melaporkan
 * RESOLVED saat di-replay terhadap file ini. */
//@ requires n >= 0 && n <= 3;
int fdiv(int n)
{
    return n == 2 ? 0 : 10 / (n - 2);
}
