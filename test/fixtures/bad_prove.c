/* bad_prove.c -- Fixture P7 (D3.1): indeks array OOB dari nilai opaque
 * (argc). Lolos gate gcc statis (-Warray-bounds tidak bisa tahu nilai
 * argc), tapi Eva harus menemukan alarm "access out of bounds index"
 * -> verdict PROVE_VIOLATION (kelas RTE = bug pasti, sesuai rencana D3.1). */
int main(int argc, char **argv)
{
    int a[4] = {0};
    (void)argv;
    a[argc] = argc;   /* argc bisa > 3 -> OOB */
    return a[0];
}
