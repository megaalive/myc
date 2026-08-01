/*
 * bad_intptr.c -- fixture P5: provenance diubah via cast integer.
 * Lint harus menolak (VIOLATION lint): pointer -> intptr_t -> pointer
 * tidak dapat diverifikasi asalnya.
 */
#include <stdint.h>
#include <stdlib.h>

int main(void)
{
    char  c = 0;
    intptr_t addr = (intptr_t)&c;   /* pointer -> integer */
    char *p = (char *)(uintptr_t)addr; /* integer -> pointer */
    (void)p;
    return 0;
}
