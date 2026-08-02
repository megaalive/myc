/*
 * proc_flood.c -- Regression MYC-AUDIT-018 (test portabel, Windows + POSIX).
 *
 * Unit test langsung myc_proc_run (proc.c), bukan lewat pipeline:
 *   1. DEADLOCK (MYC-AUDIT-002): child menulis 1 MiB stdout SEBELUM membaca
 *      1 MiB stdin, lalu menulis 1 MiB stderr. Tanpa drain thread yang
 *      berjalan lebih dulu (bug lama: tulis stdin penuh dulu), child
 *      memblok di stdout (pipe penuh) -> deadlock. Test menegaskan
 *      selesai tanpa timeout dan total byte persis.
 *   2. SIMULTANEOUS FLOOD: child menulis 100 MiB stdout + 100 MiB stderr
 *      bersamaan; cap 64 KiB per channel. Harus: output dibatasi (prefix +
 *      tail ring), total 100 MiB, flag truncated, memori bounded.
 *   3. ENV OVERRIDE (MYC-AUDIT-017): override "KEY=VALUE" menggantikan key
 *      induk, sisanya diwarisi (termasuk variabel yang di-set parent).
 *
 * Child dijalankan dengan re-invoke diri sendiri: argv[1] = mode.
 *
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -I. -o proc_flood proc_flood.c proc.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "myc.h"
#include "proc.h"

#define MIB         (1024u * 1024u)
#define FLOOD_BYTES (100u * MIB)
#define FLOOD_CHUNK (64u * 1024u)

static int g_fail = 0;

#define CHECK(cond, fmt, ...) do {                                    \
        if (cond) {                                                   \
            printf("[OK]   " fmt "\n", ##__VA_ARGS__);                \
        } else {                                                      \
            fprintf(stderr, "[FAIL] " fmt "\n", ##__VA_ARGS__);       \
            g_fail++;                                                 \
        }                                                             \
    } while (0)

/* Tulis n byte karakter c ke stream, flush (pipe 64 KiB penuh = blocking). */
static void write_flood(FILE *f, char c, size_t n)
{
    char buf[FLOOD_CHUNK];
    memset(buf, c, sizeof(buf));
    while (n > 0) {
        size_t chunk = n > sizeof(buf) ? sizeof(buf) : n;
        if (fwrite(buf, 1, chunk, f) != chunk)
            break;
        n -= chunk;
    }
    fflush(f);
}

/* --- mode child: deadlock --- */
static void child_deadlock(void)
{
    char buf[8192];
    /* 1. tulis 1 MiB stdout dulu (akan memblok bila drain tidak jalan) */
    write_flood(stdout, 'A', MIB);
    /* 2. baca 1 MiB stdin sampai EOF */
    while (fread(buf, 1, sizeof(buf), stdin) > 0)
        ;
    /* 3. tulis 1 MiB stderr */
    write_flood(stderr, 'Z', MIB);
    exit(0);
}

/* --- mode child: flood 100 MiB stdout + 100 MiB stderr bersamaan --- */
static void child_flood(void)
{
    size_t i;
    for (i = 0; i < FLOOD_BYTES / FLOOD_CHUNK; i++) {
        write_flood(stdout, 'A', FLOOD_CHUNK);
        write_flood(stderr, 'Z', FLOOD_CHUNK);
    }
    exit(0);
}

/* --- mode child: cetak env untuk verifikasi override --- */
static void child_env(void)
{
    const char *v;
    v = getenv("MYC_T_OVR");  printf("MYC_T_OVR=%s\n", v ? v : "(null)");
    v = getenv("MYC_T_KEEP"); printf("MYC_T_KEEP=%s\n", v ? v : "(null)");
    v = getenv("LC_ALL");     printf("LC_ALL=%s\n", v ? v : "(null)");
    exit(0);
}

static void set_env_keep(const char *kv)
{
#ifdef _WIN32
    _putenv(kv);
#else
    setenv("MYC_T_KEEP", "keepval", 1);
#endif
}

/* Path executable diri sendiri (untuk re-invoke child mode). */
static const char *self_path(const char *argv0)
{
#ifdef _WIN32
    static char buf[4096];
    DWORD n = GetModuleFileNameA(NULL, buf, sizeof(buf));
    if (n > 0 && n < sizeof(buf))
        return buf;
#endif
    return argv0;
}

static myc_proc_result run_child(const char *self, const char *mode,
                                 const void *stdin_data, size_t stdin_len,
                                 size_t cap, const char *const *env,
                                 int timeout_ms)
{
    myc_proc_request preq;
    myc_proc_result  pres;
    const char *argv[3];

    argv[0] = self;
    argv[1] = mode;
    argv[2] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.stdin_data = stdin_data;
    preq.stdin_len = stdin_len;
    preq.timeout_ms = timeout_ms;
    preq.max_output_bytes = cap;
    preq.env = env;
    memset(&pres, 0, sizeof(pres));
    myc_proc_run(&preq, &pres);
    return pres;
}

int main(int argc, char **argv)
{
    const char *self;

    if (argc > 1) {
        if (strcmp(argv[1], "--child-deadlock") == 0)
            child_deadlock();
        if (strcmp(argv[1], "--child-flood") == 0)
            child_flood();
        if (strcmp(argv[1], "--child-env") == 0)
            child_env();
        return 2;
    }

    self = self_path(argv[0]);

    /* ---- T1: deadlock (1 MiB stdout sebelum baca stdin, 1 MiB stderr) ---- */
    {
        char *stdin_data = (char *)malloc(MIB);
        myc_proc_result pres;
        if (stdin_data) {
            memset(stdin_data, 'x', MIB);
            pres = run_child(self, "--child-deadlock", stdin_data, MIB,
                             2u * MIB, NULL, 60000);
            CHECK(!pres.timed_out,
                  "T1 deadlock: selesai tanpa timeout (dur=%llums)",
                  (unsigned long long)pres.duration_ms);
            CHECK(pres.exit_code == 0, "T1 deadlock: exit=0 (got %d)",
                  pres.exit_code);
            CHECK(pres.stdout_total == MIB, "T1 deadlock: stdout_total=1MiB (got %zu)",
                  pres.stdout_total);
            CHECK(pres.stderr_total == MIB, "T1 deadlock: stderr_total=1MiB (got %zu)",
                  pres.stderr_total);
            CHECK(pres.stdout_shown == MIB && pres.stdout_data &&
                  pres.stdout_data[0] == 'A',
                  "T1 deadlock: stdout prefix 'A' utuh");
            myc_proc_result_free(&pres);
            free(stdin_data);
        } else {
            fprintf(stderr, "[FAIL] T1: alokasi stdin 1MiB gagal\n");
            g_fail++;
        }
    }

    /* ---- T2: flood 100 MiB stdout + 100 MiB stderr, cap 64 KiB ---- */
    {
        myc_proc_result pres;
        pres = run_child(self, "--child-flood", NULL, 0, 64u * 1024u, NULL,
                         120000);
        CHECK(!pres.timed_out, "T2 flood: selesai tanpa timeout (dur=%llums)",
              (unsigned long long)pres.duration_ms);
        CHECK(pres.exit_code == 0, "T2 flood: exit=0 (got %d)", pres.exit_code);
        CHECK(pres.stdout_total == FLOOD_BYTES,
              "T2 flood: stdout_total=100MiB (got %zu)", pres.stdout_total);
        CHECK(pres.stderr_total == FLOOD_BYTES,
              "T2 flood: stderr_total=100MiB (got %zu)", pres.stderr_total);
        CHECK(pres.truncated, "T2 flood: truncated=1 (cap 64KiB)");
        CHECK(pres.stdout_shown <= 64u * 1024u && pres.stdout_shown > 0,
              "T2 flood: stdout shown bounded (got %zu)", pres.stdout_shown);
        CHECK(pres.stderr_shown <= 64u * 1024u && pres.stderr_shown > 0,
              "T2 flood: stderr shown bounded (got %zu)", pres.stderr_shown);
        CHECK(pres.stdout_data && pres.stdout_shown > 0 &&
              pres.stdout_data[0] == 'A' &&
              pres.stdout_data[pres.stdout_shown - 1] == 'A',
              "T2 flood: stdout prefix+tail 'A' dipertahankan");
        CHECK(pres.stderr_data && pres.stderr_shown > 0 &&
              pres.stderr_data[0] == 'Z' &&
              pres.stderr_data[pres.stderr_shown - 1] == 'Z',
              "T2 flood: stderr prefix+tail 'Z' dipertahankan");
        myc_proc_result_free(&pres);
    }

    /* ---- T3: env override menggantikan key induk, sisanya diwarisi ---- */
    {
        static const char *const env_ovr[] = {
            "MYC_T_OVR=replaced",
            "LC_ALL=C",
            NULL
        };
        myc_proc_result pres;
        set_env_keep("MYC_T_KEEP=keepval");
        pres = run_child(self, "--child-env", NULL, 0, 64u * 1024u, env_ovr,
                         30000);
        CHECK(pres.exit_code == 0, "T3 env: exit=0 (got %d)", pres.exit_code);
        CHECK(pres.stdout_data && strstr(pres.stdout_data, "MYC_T_OVR=replaced"),
              "T3 env: override MYC_T_OVR=replaced diterapkan");
        CHECK(pres.stdout_data && strstr(pres.stdout_data, "MYC_T_KEEP=keepval"),
              "T3 env: variabel induk MYC_T_KEEP diwarisi");
        CHECK(pres.stdout_data && strstr(pres.stdout_data, "LC_ALL=C"),
              "T3 env: LC_ALL=C di-override");
        myc_proc_result_free(&pres);
    }

    printf(g_fail ? "proc_flood: FAIL (%d)\n" : "proc_flood: OK (deadlock/flood/env)\n",
           g_fail);
    return g_fail ? 1 : 0;
}
