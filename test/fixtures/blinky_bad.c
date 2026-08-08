/* fixture C1 (freestanding): kode "firmware" yang memanggil API hosted
 * (printf, malloc) — di mode --freestanding ini = observasi trap. */

#include <stdio.h>
#include <stdlib.h>

static void led_on(int pin)
{
    (void)pin;
}

int main(void)
{
    int *buf = (int *)malloc(64);
    led_on(1);
    printf("hello\n");
    free(buf);
    return 0;
}
