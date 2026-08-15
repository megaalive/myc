/* rt_strcpy_ovf.c -- Fixture IDE-2 (repair RUNTIME_VIOLATION):
 * stack-buffer-overflow via strcpy ke array lokal. Template repair
 * harus mengganti baris strcpy dengan copy ber-batas + null-terminate
 * (compile-clean tanpa <stdio.h>, tanpa -Wformat-truncation) dan
 * re-run membuktikan verdict OK. */
#include <string.h>

int copy_it(void)
{
    char b[6];
    strcpy(b, "abcdefghij"); /* overflow runtime */
    return b[0];
}

int main(void)
{
    (void)copy_it();
    return 0;
}
