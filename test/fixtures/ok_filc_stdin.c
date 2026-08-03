/* ok_filc_stdin.c -- Fixture MYC-AUDIT-021: run_stdin diteruskan ke program
 * Fil-C. Sebelum fix, env MYC_FILC_STDIN (path Windows) tidak sampai ke
 * WSL bash (env Windows -> WSL butuh WSLENV) sehingga stdin program selalu
 * kosong; kini WSLENV=MYC_FILC_STDIN/p diteruskan + path translation
 * otomatis, dan template membaca file stdin. Program ini membaca stdin dan
 * menggema isinya: bila run_stdin sampai, output berisi `got:<isi>`.
 * Dipakai bersama --filc --run-stdin (CLI) / run_stdin (MCP check). */
#include <stdio.h>

int main(void)
{
    char buf[256];

    printf("filc_stdin_ok\n");
    if (fgets(buf, sizeof(buf), stdin))
        printf("got:%s", buf);
    return 0;
}
