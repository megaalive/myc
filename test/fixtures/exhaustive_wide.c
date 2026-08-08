/* fixture DS-03 WIDE: domain lebar 0..65535 (2^16 titik). Gap checker
 * harus menolak enumerasi penuh -> exhaustive di-skip dengan alasan
 * scope laundering / domain terlalu lebar. */

//@ requires n >= 0 && n <= 65535;
//@ ensures n >= 0 && n <= 65535;
int clamp_domain(int n)
{
    if (n < 0)
        return 0;
    if (n > 65535)
        return 65535;
    return n;
}
