/* units_broken.c -- Fixture Units / Shape / Provenance Contracts (SOL-11):
 * with sengaja RUSAK: unbound identifier, unit-mismatch pada assignment,
 * shape-dim capacity vs length, dan konflik annotation ganda. Semua
 * temuan = observasi NON-blocking. */
#include <stddef.h>

//@ unit raw_len bytes
//@ unit count elements
//@ unit data_len bytes      // data_len tidak ada di kode -> UNBOUND
//@ shape packet capacity=raw_len length=count
//@ shape probe capacity=raw_len length=count
//@ endian raw_len little
//@ endian raw_len big         // DUP: endian little lalu big
//@ unit count bytes         // DUP: count elements lalu bytes

size_t nematic(const char *data, size_t raw_len)
{
    size_t len, count = 0;

    count = raw_len;        /* native mismatch */
    len = count;
    (void)data;
    return len;
}