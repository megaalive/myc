/*
 * assume_clean.c -- Fixture Fase 4 A1: source TANPA taruhan pada fakta
 * implementation-defined (tidak ada char sign check, int-width, bit-field,
 * alignment cast, atau sizeof assumption) -> 0 asumsi terdeteksi.
 */
#include <stddef.h>

static size_t add(size_t a, size_t b)
{
    return a + b;
}

int main(void)
{
    size_t x = add(1, 2);
    return x == 3 ? 0 : 1;
}
