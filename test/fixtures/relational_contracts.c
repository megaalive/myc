/* relational_contracts.c -- Fixture Relational Contracts (Fase 5).
 *
 * Berisi keempat kelas klausa untuk myc_contract_relational:
 *   - UNARY        : satu variabel vs konstanta (n >= 0);
 *   - RELATIONAL   : >= 2 variabel (a <= b, r == a + b, a < b && b < c);
 *   - RETURN alias : r == ... (r dianggap terikat sebagai nilai return);
 *   - UNBOUND      : identifier di luar param fungsi (mystery = typo /
 *                    global tak terdeklarasi) -> observasi NON-blocking.
 *
 * Harapan klasifikasi (deterministik):
 *   analyzed=6  unary=1  relations=5  unbound=1
 * Round-trip: contract-delta file file = CLEAN; dua run berturut-turut
 * memberi receipt + hitungan relasional yang identik.
 */
#include <stddef.h>

/* UNARY: satu variabel vs konstanta. */
//@ requires n >= 0;
//@ ensures  r == n * 2;
int double_it(int n)
{
    return n * 2;
}

/* RELATIONAL order: dua parameter dibandingkan. */
//@ requires a <= b;
int order_ok(int a, int b)
{
    return a < b ? 1 : 0;
}

/* RELATIONAL rentang (order + logic) + aritmetika (return alias). */
//@ requires a >= 0 && b >= 0;
//@ ensures  r == a + b;
int sum2(int a, int b)
{
    return a + b;
}

/* UNBOUND: identifier di luar param (typo / global tak terdeklarasi). */
//@ ensures  r <= mystery;
int with_typo(int n)
{
    return n;
}
