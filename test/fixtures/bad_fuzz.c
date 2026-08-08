/* fixture D1 (DS-13) BAD: OOB read pada index tertentu — fuzz-lite
 * harus menemukan crash (DRIVER_VIOLATION, bukti). */

static int g_tbl[16];

//@ requires idx >= 0 && idx <= 31;
//@ ensures idx >= 0;
int peek_tbl(int idx)
{
    return g_tbl[idx];   /* OOB bila idx >= 16 */
}

int main(void)
{
    return 0;
}
