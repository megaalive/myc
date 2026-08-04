/* Fixture MYC-AUDIT-025 (roadmap 7.4): klausa kontrak dengan status
 * eksplisit + pure expression validation + stable function binding.
 *   - twice: requires pure (ok, terikat) + ensures pure -> requires DI-INJECT
 *     (assert n > 0) saat --run; dipanggil dengan nilai sah -> run bersih.
 *   - risky: requires impure `(x = 0) != 0` (assignment) -> TIDAK di-inject;
 *     bila di-inject, assert pasti GAGAL (RUNTIME_VIOLATION) -- jadi run
 *     bersih membuktikan purity gate bekerja.
 *   - uses_call: requires `helper(-5) > 0` (pemanggilan fungsi) -> TIDAK
 *     di-inject (purity tak terbukti); bila di-inject, assert GAGAL.
 *   - unbound: klausa sebelum deklarasi global (bukan fungsi) -> unbound.
 * Verdict: OK (statis) dan OK (--run). */
#include <stdio.h>

static int helper(int x) { return x; }

/* requires pure + ensures pure: keduanya terikat ke fungsi `twice`. */
//@ requires n > 0;
//@ ensures res > 0;
static int twice(int n)
{
    return n * 2;
}

/* requires impure: ekspresi ber-efek samping tidak boleh di-inject. */
//@ requires (x = 0) != 0;
static int risky(int x)
{
    return x + 1;
}

/* requires call: pemanggilan fungsi tidak diverifikasi purity-nya. */
//@ requires helper(-5) > 0;
static int uses_call(int x)
{
    return x + 2;
}

/* unbound: klausa sebelum deklarasi global (bukan definisi fungsi). */
//@ requires helper(7) == 7;
static int g = 7;

int main(void)
{
    printf("twice=%d risky=%d call=%d g=%d h=%d\n",
           twice(2), risky(3), uses_call(4), g, helper(7));
    return 0;
}
