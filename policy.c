/*
 * policy.c -- Data kebijakan myc.
 *
 * Whitelist header (sistem C11 standar yang disetujui user):
 *   stdio.h, stdlib.h, string.h, ctype.h, math.h, limits.h, stdint.h,
 *   stdbool.h, stddef.h, stdarg.h, errno.h, float.h, assert.h,
 *   locale.h, time.h.
 *
 * Denylist fungsi: lapis kedua. Meski header diizinkan, fungsi berbahaya
 * diblokir keras:
 *   - eksekusi proses (system, exec*, spawn*, fork, popen)
 *   - file I/O ke disk (fopen, fread, ...) -- stdio.h diizinkan, tapi
 *     hanya untuk console: printf, puts, getchar, scanf, dll.
 *   - jaringan, memory-map, env.
 *
 * Catatan: deny list ini menegakkan "vokabular aman" supaya model tidak
 * bisa menulis kode yang (jika nanti dieksekusi) membahayakan sistem.
 * myc sendiri hanya melakukan syntax-only compile; deny list menjaga
 * hasil akhir tetap aman untuk fase eksekusi berikutnya.
 */
#include "policy.h"

#include "alloc.h"
#include <string.h>

#include "sha256.h"

/* ------------------------------------------------------------------ */
/* Whitelist header                                                     */
/* ------------------------------------------------------------------ */

static const char *const allowed_headers[] = {
    "assert.h",
    "ctype.h",
    "errno.h",
    "float.h",
    "limits.h",
    "locale.h",
    "math.h",
    "stdarg.h",
    "stdbool.h",
    "stddef.h",
    "stdint.h",
    "stdio.h",
    "stdlib.h",
    "string.h",
    "time.h",
    NULL
};

int myc_policy_allow_include(const char *name)
{
    int i;
    if (!name || !*name)
        return 0;
    for (i = 0; allowed_headers[i]; i++) {
        if (strcmp(allowed_headers[i], name) == 0)
            return 1;
    }
    return 0;
}

const char *const *myc_policy_allowed_headers(size_t *count)
{
    size_t n = 0;
    while (allowed_headers[n])
        n++;
    if (count)
        *count = n;
    return allowed_headers;
}

/* ------------------------------------------------------------------ */
/* Denylist fungsi berbahaya                                            */
/* ------------------------------------------------------------------ */

static const char *const denied_functions[] = {
    /* Eksekusi proses / sistem */
    "system", "popen", "pclose", "execl", "execle", "execlp", "execv",
    "execve", "execvp", "execvpe", "spawnl", "spawnle", "spawnlp",
    "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "fork",
    "vfork", "posix_spawn", "_wsystem",
    /* File I/O ke disk -- diblokir meski stdio.h diizinkan */
    "fopen", "fopen_s", "fclose", "freopen", "remove", "rename",
    "tmpfile", "tmpnam", "fread", "fwrite", "fseek", "ftell",
    "rewind", "fflush", "fgetc", "fgets", "fputc", "fputs",
    "fscanf", "fprintf", "fprintf_s", "feof", "ferror", "fgetpos",
    "fsetpos", "clearerr", "setbuf", "setvbuf", "fileno", "fdopen",
    "perror", "getline", "gets",
    "open", "close", "read", "write", "creat", "unlink", "mkdir",
    "rmdir", "access", "stat", "lstat", "fstat", "chmod", "chown",
    "truncate", "ftruncate", "remove", "_chmod", "_unlink", "_open",
    "_read", "_write", "_close", "_mkdir", "_rmdir", "_stat",
    /* Memory-map / alokasi liar */
    "mmap", "munmap", "mprotect", "brk", "sbrk", "shmat", "shmget",
    "shmdt", "alloca",
    /* Jaringan */
    "socket", "connect", "bind", "listen", "accept", "send", "recv",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "getaddrinfo",
    "gethostbyname", "htons", "ntohs", "inet_addr", "select",
    "poll", "ioctl", "setsockopt", "getsockopt", "close_socket",
    "WSAStartup", "WSACleanup", "closesocket",
    /* Environment / utas (di luar vokabular aman) */
    "getenv", "setenv", "putenv", "_putenv", "pthread_create",
    "pthread_join", "pthread_mutex_lock", "pthread_mutex_unlock",
    NULL
};

int myc_policy_deny_function(const char *name)
{
    int i;
    if (!name || !*name)
        return 0;
    for (i = 0; denied_functions[i]; i++) {
        if (strcmp(denied_functions[i], name) == 0)
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Fingerprint kebijakan                                                */
/* ------------------------------------------------------------------ */

void myc_policy_hash(char out_hex[65])
{
    sha256_ctx ctx;
    uint8_t    digest[32];
    int        i, j;
    static const char hexc[] = "0123456789abcdef";

    sha256_init(&ctx);

    for (i = 0; allowed_headers[i]; i++) {
        const char *h = allowed_headers[i];
        sha256_update(&ctx, "H:", 2);
        sha256_update(&ctx, h, strlen(h));
        sha256_update(&ctx, "\n", 1);
    }
    for (j = 0; denied_functions[j]; j++) {
        const char *f = denied_functions[j];
        sha256_update(&ctx, "D:", 2);
        sha256_update(&ctx, f, strlen(f));
        sha256_update(&ctx, "\n", 1);
    }

    sha256_final(&ctx, digest);
    for (i = 0; i < 32; i++) {
        out_hex[i * 2]     = hexc[digest[i] >> 4];
        out_hex[i * 2 + 1] = hexc[digest[i] & 0x0f];
    }
    out_hex[64] = '\0';
}
