/*
 * bad_driver_oob.c -- Fixture D2.2 (--driver): fungsi ber-kontrak dengan
 * bug out-of-bounds yang TERSEBAR di dalam domain kontrak.
 *
 * Kontrak `requires n <= 4` menjanjikan akses maksimal a[3] (buffer 4
 * elemen int). Implementasi membaca `a[n]` -- saat driver menguji n = 4
 * (tepi atas yang SAH menurut kontrak), akses a[4] = byte 16..19 pada
 * buffer 16 byte -> heap-buffer-overflow tertangkap ASan.
 * --driver harus DRIVER_VIOLATION.
 */
//@ requires n <= 4;
int bad_read(const int *a, int n)
{
    return a[n];   /* OOB saat n == 4 */
}
