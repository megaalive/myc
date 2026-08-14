/* scen_input_parser.c -- fixture C5/D3 (IDE-5, qwen-review): parser input
 * stdin. `--scenario auto` harus menebak resep `parser` (fuzz + run)
 * karena ada loop baca stdin (fgets) + parsing string (strtol) + main.
 * Sebelum IDE-5 file ber-`main` seperti ini salah tebak `cli-daily`. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char line[128];
    long total = 0;

    while (fgets(line, sizeof(line), stdin) != NULL) {
        char *end = NULL;
        long v = strtol(line, &end, 10);
        if (end != line)
            total += v;
    }
    return (int)(total & 0xFF);
}
