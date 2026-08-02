/* bad_no_main.c -- Fixture untuk MYC-AUDIT-004:
 * Source tanpa main() sehingga verification build (--run) gagal.
 * Seharusnya verdict TIDAK OK, melainkan INCONCLUSIVE karena gate runtime
 * diminta tetapi tidak dapat diselesaikan. */
int helper(void) {
    return 42;
}
