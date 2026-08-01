/* ok_run_stdin.c -- Fixture gate --run (P6): program membaca stdin dan
 * menggema baris yang diterima ke stdout. Dipakai menguji argumen
 * `run_stdin` pada tool MCP `check` (--run): input yang dikirim lewat
 * SDK harus sampai ke stdin program verification. */
#include <stdio.h>

int main(void)
{
    char buf[256];

    printf("run_stdin_ok\n");
    if (fgets(buf, sizeof(buf), stdin))
        printf("got:%s", buf);
    return 0;
}
