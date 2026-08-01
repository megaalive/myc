/*
 * argv_probe.c -- Fixture deterministik untuk membuktikan exact argv.
 *
 * Mencetak ke stdout, satu baris per argumen (NDJSON-ish), lalu stdin hash
 * dan cwd. Dipakai oleh `myc probe` dan test. Bukan bagian produksi.
 */
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#define my_getcwd _getcwd
#else
#include <unistd.h>
#define my_getcwd getcwd
#endif

/* hash sederhana (bukan SHA; hanya untuk probe) */
static unsigned long probe_hash(const char *s, int len)
{
    unsigned long h = 5381;
    int i;
    for (i = 0; i < len; i++)
        h = ((h << 5) + h) + (unsigned char)s[i];
    return h;
}

int main(int argc, char **argv)
{
    int i;
    char cwd[4096];
    int ch;
    unsigned long stdin_hash = 0;
    long stdin_len = 0;

    for (i = 0; i < argc; i++) {
        printf("arg[%d] len=%d hash=%08lx |%s|\n",
               i, (int)strlen(argv[i]), probe_hash(argv[i], (int)strlen(argv[i])),
               argv[i]);
    }

    while ((ch = getchar()) != EOF) {
        stdin_hash = ((stdin_hash << 5) + stdin_hash) + (unsigned char)ch;
        stdin_len++;
    }
    printf("stdin len=%ld hash=%08lx\n", stdin_len, stdin_hash);

    if (!my_getcwd(cwd, sizeof(cwd)))
        strcpy(cwd, "?");
    printf("cwd |%s|\n", cwd);
    return 0;
}
