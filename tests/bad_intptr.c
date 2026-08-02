/*
 * bad_intptr.c -- fixture P5: provenance diubah via cast integer.
 * MYC-AUDIT-014: lint heuristik TIDAK lagi hard -- source ini OK dengan
 * 2 observasi lint (suspicious + observation). gcc tidak menangkapnya
 * (cast eksplisit), jadi verdict OK; hard evidence hanya dari gate
 * semantik. Lihat test/_regress_run.bat section AUDIT-014.
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
