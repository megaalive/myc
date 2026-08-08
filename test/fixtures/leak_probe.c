/*
 * leak_probe.c -- Fixture no-source-leak (Fase 8, Definition of Done).
 *
 * Berisi sentinel unik MYC_LEAK_SENTINEL_9137_... yang TIDAK boleh muncul
 * verbatim di output agent/json-summary/report teks. Source hanya boleh
 * direpresentasikan sebagai hash (source_sha256), bukan konten.
 */
#include <stdio.h>

/* MYC_LEAK_SENTINEL_9137_a4b2c6 */
int main(void)
{
    /* MYC_LEAK_SENTINEL_9137_x9y8z7 */
    printf("clean program\n");
    return 0;
}
