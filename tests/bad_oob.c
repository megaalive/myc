/*
 * bad_oob.c -- fixture P4: indeks array statis melebihi batas. Tier dasar
 * (-Warray-bounds -Wstringop-overflow, semua -Werror) harus menjadikannya
 * COMPILE_ERROR.
 */
int main(void)
{
    int arr[4] = {1, 2, 3, 4};
    return arr[4];   /* out of bounds statis */
}
