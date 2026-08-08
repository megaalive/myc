/* fixture Fase 6 (--perturb): program yang bergantung ZONA WAKTU.
 * localtime() membaca env TZ; mengubah TZ mengubah output -> perturb
 * harus menandai ENV-SENSITIVE (bukan DETERMINISTIK). */
#include <stdio.h>
#include <time.h>

int main(void)
{
    time_t t = 0;
    printf("%ld\n", (long)localtime(&t)->tm_hour);
    return 0;
}
