/* fixture B4 (DS-08): komentar biasa yang harus dipanen sebagai kandidat
 * kontrak oleh myc_contract_harvest. Non-blocking: observasi murni. */

#include <stddef.h>

/* returns n + 1 */
/* n must not exceed 64 */
/* assumes p != 0 */
int add_bounded(int n, int *p)
{
    if (!p)
        return 0;
    return n + 1;
}

/* len must be <= cap */
/* len must be >= 0 */
size_t clamp_len(size_t len, size_t cap)
{
    return len < cap ? len : cap;
}

/* prose tanpa operator: returns number of words -> bukan C murni,
 * harus dilaporkan "perlu //@ syntax", TIDAK dihitung validated. */
int prose_fn(void)
{
    return 42;
}
