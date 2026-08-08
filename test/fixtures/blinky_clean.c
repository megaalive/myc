/* fixture C1 (freestanding): kode "firmware" BERSIH — tanpa API hosted.
 * --freestanding harus lapor hygiene bersih. */

static void led_on(int pin)
{
    (void)pin;
}

static void delay_loop(volatile unsigned long n)
{
    while (n-- > 0)
        ;
}

int main(void)
{
    delay_loop(1000);
    led_on(1);
    return 0;
}
