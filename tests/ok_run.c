/* ok_run.c -- Program sah yang bisa dijalankan (P6, --run harus OK + L3). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *msg = (char *)malloc(6);
    size_t i;
    if (!msg)
        return 1;
    memcpy(msg, "hello", 6);  /* salin termasuk NUL */
    for (i = 0; i < 5; i++)
        putchar(msg[i]);
    putchar('\n');
    free(msg);
    return 0;
}
