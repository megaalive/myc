/* fixture D1 (DS-13): fungsi murni aman — fuzz-lite harus bersih. */

//@ requires n >= 0 && n <= 1024;
//@ requires base >= 0 && base <= 255;
//@ ensures n >= 0 && n <= 1024;
int clamp_byte(int n, int base)
{
    int v = n + base;
    if (v < 0)
        return 0;
    if (v > 1024)
        return 1024;
    return v;
}

int main(void)
{
    return 0;
}
