/*
 * scen_parser.c -- fixture C5/D3: parser dengan kontrak //@.
 * `--scenario auto` harus menebak resep library (driver + exhaustive)
 * karena ada kontrak //@ dan tidak ada pola firmware.
 */
#include <stdint.h>

//@ requires n <= 64;
//@ ensures res >= 0;
static int parse_len(const uint8_t *buf, int n)
{
    int sum = 0;
    int i;
    for (i = 0; i < n; i++)
        sum += buf[i];
    return sum;
}

int main(void)
{
    uint8_t b[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    return parse_len(b, 8);
}
