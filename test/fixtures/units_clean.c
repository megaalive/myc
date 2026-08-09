/* units_clean.c -- Fixture Units / Shape / Provenance Contracts (SOL-11):
 * SEHAT. Semua annotation konsisten; tidak ada temuan (0 unbound,
 * 0 unit-mismatch, 0 shape-dim, 0 dup). */
#include <stddef.h>

//@ unit cap bytes
//@ unit len bytes
//@ shape buf capacity=cap length=len

static size_t fill(char *buf, size_t cap, size_t len)
{
    len = cap;              /* bytes = bytes: tak ada mismatch */
    (void)buf;
    return len;
}

int main(void)
{
    char    buf[64];
    size_t  cap = 64, len = 0;

    cap = len;
    return (int)fill(buf, cap, len);
}