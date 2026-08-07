/*
 * assume_char_signed.c -- Fixture Fase 4 A1: source yang MEMBETTAR fakta
 * implementation-defined (sengaja, untuk uji ledger asumsi):
 *   - char c dibandingkan < 0        -> char-signedness
 *   - int n = strlen(s)              -> int-width
 *   - bit-field di struct            -> bitfield-endian
 *   - *(const uint32_t *)s           -> alignment-cast (+ endianness)
 *   - sizeof(int) == 4               -> sizeof-assumption
 * Semua deteksi NON-blocking: verdict tetap OK (observasi).
 */
#include <stdint.h>
#include <string.h>

struct flags {
    unsigned ready : 1;
    unsigned mode : 3;
};

static int probe(const char *s)
{
    char c = s[0];
    int n = strlen(s);
    uint32_t v = *(const uint32_t *)s;
    if (c < 0)
        return -1;
    if (sizeof(int) == 4)
        n += 1;
    return n + (int)v;
}

int main(void)
{
    struct flags f = {1, 2};
    return probe((const char *)&f) >= 0 ? 0 : 1;
}
