/* rt_memcpy_ovf.c -- fixture runtime: stack-buffer-overflow via memcpy
 * (bukan strcpy/strcat). Expected sanitizer_location:
 * stack-buffer-overflow @f:9. */
#include <string.h>

int f(void)
{
    char b[4];
    memcpy(b, "abcdefghij", 10); /* overflow: 10 > sizeof b */
    return b[0];
}

int main(void)
{
    (void)f();
    return 0;
}
