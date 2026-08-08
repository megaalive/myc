/* fixture DS-03 NARROW: domain DIPERSEMPTI ke 0..63 vs run sebelumnya
 * (0..64 di ok_exhaustive.c). Menjalankan fixture ini SETELAH
 * ok_exhaustive.c harus melaporkan SCOPE_LAUNDERING (proof laundering,
 * DS-03): bukti di domain 0..63 tidak boleh diam-diam menggantikan
 * domain 0..64 yang sudah dibuktikan. */

//@ requires n >= 0 && n <= 63;
//@ ensures n >= 0 && n <= 64;
int clamp_u8(int n)
{
    if (n < 0)
        return 0;
    if (n > 64)
        return 64;
    return n;
}
