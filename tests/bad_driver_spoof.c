/*
 * bad_driver_spoof.c -- Spoof marker sanitizer via driver (MYC-AUDIT-017).
 *
 * Fungsi ber-kontrak yang MENCETAK teks mirip laporan ASan tetapi tidak
 * melakukan apa pun yang salah (tidak mengakses memori di luar batas).
 * Sebelum MYC-AUDIT-017, gate --driver mendeteksi finding murni dari
 * string marker pada output harness: teks ini menghasilkan
 * DRIVER_VIOLATION PALSU.
 *
 * Sejak MYC-AUDIT-017: finding = file report sanitizer (log_path) ATAU
 * marker teks yang terkonfirmasi exit code != 0. Harness ini bersih
 * (exit 0) tanpa report -> BUKAN DRIVER_VIOLATION.
 */
#include <stdio.h>

//@ requires n <= 4;
int f(int *a, int n)
{
    if (a && n <= 4)
        fprintf(stderr, "ERROR: AddressSanitizer: fake spoof (bukan bug)\n");
    return 1;
}
