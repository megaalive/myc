/*
 * ok_driver.c -- Fixture D2.2 (--driver): fungsi ber-kontrak yang AMAN
 * terhadap kasus tepi di dalam domain kontrak.
 *
 * Kontrak `requires n <= 4` membatasi buffer 4 elemen int. Implementasi
 * memeriksa batas (n < 0 -> 0, n > 4 -> 4) sehingga semua kasus tepi
 * (0, 1, 2, 3, 4) tidak melampaui buffer 16 byte. --driver harus OK + L3.
 */
//@ requires n <= 4;
int ok_sum(const int *a, int n)
{
    int s = 0;
    int i;
    if (n <= 0)
        return 0;
    if (n > 4)
        n = 4;
    for (i = 0; i < n; i++)
        s += a[i];
    return s;
}

//@ requires len >= 0;
//@ requires len <= 4;
int ok_copy(char *dst, const char *src, int len)
{
    int i;
    if (len <= 0)
        return 0;
    if (len > 4)
        len = 4;
    for (i = 0; i < len; i++)
        dst[i] = src[i];
    return len;
}
