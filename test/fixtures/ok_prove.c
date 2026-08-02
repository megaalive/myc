/* ok_prove.c -- Fixture P7 (D3.1): kode aman + kontrak; --prove harus L2
 * (EVA): Eva 0 alarm RTE di bawah model (label lama PROVEN dihapus
 * MYC-AUDIT-013), preconditions valid. Array diinisialisasi penuh
 * (menghindari alarm uninitialized dari loop partition Eva). */
//@ requires n > 0;
int twice(int n)
{
    return n * 2;
}

int main(void)
{
    int a[4] = {0};
    int s = 0;
    int i;
    for (i = 0; i < 4; i++)
        s += a[i];
    return twice(21) == 42 ? s : 1;
}
