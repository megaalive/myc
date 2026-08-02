/*
 * spoof_marker_run.c -- Spoof marker sanitizer (MYC-AUDIT-017).
 *
 * Program BERSIH (tidak ada bug memori) yang mencetak teks mirip laporan
 * ASan ke stderr lalu keluar 0. Sebelum MYC-AUDIT-017, gate --run
 * mendeteksi finding murni dari pencarian string pada output program:
 * teks ini menghasilkan RUNTIME_VIOLATION PALSU (false positive).
 *
 * Sejak MYC-AUDIT-017:
 *   - bukti utama finding = FILE report yang ditulis runtime sanitizer
 *     (ASAN_OPTIONS/UBSAN_OPTIONS log_path di tmp dir) — program tidak
 *     bisa memalsukannya secara tidak sengaja;
 *   - marker teks pada stdout/stderr hanya bukti SEKUNDER dan WAJIB
 *     dikonfirmasi exit code != 0. Di sini exit 0 tanpa report -> BUKAN
 *     finding (verdict tetap OK; diagnostic mencatat teks diabaikan).
 */
#include <stdio.h>

int main(void)
{
    fprintf(stderr, "ERROR: AddressSanitizer: fake report (bukan bug)\n");
    fputs("clean program\n", stdout);
    return 0;
}
