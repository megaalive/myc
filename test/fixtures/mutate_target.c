/* fixture B5 (DS-09): target mutation audit. Guard batas yang benar;
 * mutasi (guard dilemahkan / komparasi dibalik) harus tertangkap ASan
 * bila jalur tereksekusi — main di bawah memanggil rentang LUAS. */

//@ requires idx >= 0 && idx <= 15;
//@ ensures idx >= 0;
int peek_ok(const int *tbl, int idx)
{
    if (idx >= 16)
        return -1;
    if (idx < 0)
        return -1;
    return tbl[idx];
}

int main(void)
{
    static int t[16];
    int        i;
    int        acc = 0;
    for (i = -5; i <= 20; i++)
        acc += peek_ok(t, i);
    return acc;
}
