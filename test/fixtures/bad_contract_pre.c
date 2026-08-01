// Fixture P7 (D1.5): kontrak requires yang DILANGGAR saat --run.
// Assert hasil inject harus menangkap pelanggaran prekondisi.
//@ requires n > 0;
int twice(int n) {
    return n * 2;
}

int main(void) {
    return twice(-1); /* melanggar requires n > 0 */
}
