/*
 * proc_deadlock_matrix.c -- Deadlock matrix (PR-006, plan P1-T03).
 *
 * Stress test myc_proc_run (proc.c) terhadap proc_fixture (PR-005/P1-T02,
 * mode --matrix dari PR-006) sebagai child bermusuhan deterministik.
 *
 * Dimensi kombinasi (sesuai P1-T03):
 *   stdin  : 0 / small(4K) / >pipe(256K) / huge(8M)
 *   stdout : 0 / small(4K) / >pipe(256K) / huge(8M)
 *   stderr : 0 / small(4K) / >pipe(256K) / huge(8M)
 *   order  : read-first / write-first / interleave   (mode --matrix fixture)
 *   timeout: ya (child hang) / tidak (generous)
 *   cap    : hit (64K) / tidak (default 1M)
 *
 * Strategi: pairwise dulu (T2-T6: tiap faktor diuji berpasangan dengan
 * ukuran perwakilan), lalu full Cartesian (T1: 4x4x4 ukuran I/O pada order
 * interleave) dan stress loop (T7). Kegagalan apa pun memuat konfigurasi
 * lengkap (seed/config untuk reproduce, sesuai batch PR-006).
 *
 *   T1 Full Cartesian I/O      : 64 kombinasi (interleave), cap default 1M
 *   T2 Order                   : 3 order x 3 combo ukuran
 *   T3 Timeout                 : hang + stdin 8M (fix deadlock PR-006),
 *                                tree-kill + orphan check (--spawn-child),
 *                                child normal (timeout tidak terpicu)
 *   T4 Output cap              : hit / miss / cap=0 (default) / biner ring
 *   T5 EPIPE                   : child tak pernah baca stdin (exit dini)
 *   T6 Close descriptor        : --close-stdout / --close-stderr
 *   T7 Stress loop             : --stress N (default 100), repset + orphan
 *                                spot-check tiap 25 iterasi + bounded memory
 *                                (getrusage / GetProcessMemoryInfo)
 *   T8 Stdin EOF (PR-010)      : stdin KOSONG + child membaca sampai EOF
 *                                (--output-after-stdin / --stdin-after-output)
 *                                harus selesai CEPAT (EOF instan), bukan hang
 *                                sampai timeout (bug proc.c: write end pipe
 *                                stdin tak pernah ditutup saat stdin_len==0)
 *
 * Exit criteria P1-T03 (10.000 eksekusi berulang per OS): zero deadlock,
 * zero orphan, zero stuck drain worker, bounded memory. Jalankan penuh:
 *   proc_deadlock_matrix <fixture> --stress 10000
 * Suite CI memakai default (100 iterasi) agar tetap cepat; kepatuhan penuh
 * exit criteria diverifikasi manual dengan --stress 10000.
 *
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -Werror -I. -pthread \
 *       -o proc_deadlock_matrix proc_deadlock_matrix.c proc.c
 *   (Windows: tambah -lpsapi untuk GetProcessMemoryInfo)
 *
 * Penggunaan:
 *   proc_deadlock_matrix <path-proc_fixture> [--stress N]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <errno.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#endif

#include "myc.h"
#include "proc.h"

#define SZ_SMALL  4096u
#define SZ_PIPE   262144u         /* 256 KiB > pipe buffer 64 KiB */
#define SZ_HUGE   (8u << 20)      /* 8 MiB = MYC_MAX_STDIN_BYTES */
#define DEFAULT_CAP 0u            /* 0 = cap default 1 MiB/channel */
#define GEN_TIMEOUT 60000
#define MEM_THRESHOLD_KB (64u * 1024u)   /* 64 MiB allowance, generous */

static const size_t SIZES[4] = { 0, SZ_SMALL, SZ_PIPE, SZ_HUGE };
static const char *const SZSTR[4] = { "0", "4096", "262144", "8388608" };

static int g_fail = 0;
static int g_case_fail = 0;   /* reset di awal tiap kasus */

/* Deadline internal (review PR-006): matriks TIDAK boleh menggantung tanpa
 * batas bila myc regresi (mis. T3a kembali hang). Bila batas tercapai,
 * run_child mengembalikan hasil timeout sintetis dan main menghentikan
 * semua test dengan FAIL — test self-contained tanpa butuh timeout(1)
 * eksternal (guard eksternal di _audit018.sh tetap dipertahankan). */
#define MATRIX_DEADLINE_MS (10u * 60u * 1000u)   /* 10 menit */
static unsigned long long g_deadline_ms = 0;
static int g_deadline_hit = 0;

static unsigned long long now_ms(void)
{
#ifdef _WIN32
    return (unsigned long long)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

/* CHECK: cetak [OK]/[FAIL] per cek (untuk kasus besar, lihat CCK). */
#define CHECK(cond, ...) do {                                          \
        if (cond) { printf("[OK]   " __VA_ARGS__); printf("\n"); }     \
        else { fprintf(stderr, "[FAIL] " __VA_ARGS__);                 \
               fprintf(stderr, "\n"); g_fail++; }                      \
    } while (0)

/* CCK + CASE_OK: cek dalam kasus hanya mencatat detail kegagalan; kasus
 * dicetak OK bila tidak ada yang gagal (output matriks tetap ringkas). */
#define CCK(cond, ...) do {                                            \
        if (!(cond)) {                                                 \
            fprintf(stderr, "[FAIL]   " __VA_ARGS__);                  \
            fprintf(stderr, "\n");                                     \
            g_case_fail++;                                             \
        }                                                              \
    } while (0)

#define CASE_OK(tag, ctx) do {                                         \
        if (g_case_fail) g_fail += g_case_fail;                        \
        else printf("[OK]   %s %s\n", tag, ctx);                       \
    } while (0)

static int szindex(size_t n)
{
    int i;
    for (i = 0; i < 4; i++)
        if (SIZES[i] == n)
            return i;
    return 3;   /* fallback (tidak terjadi utk ukuran kanonik) */
}

static void sleep_ms(int ms)
{
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0) { /* EINTR: ulangi */ }
#endif
}

/* --- launcher --- */
static myc_proc_result run_child(const char *fixture, const char *const args[],
                                 const void *stdin_data, size_t stdin_len,
                                 size_t cap, int timeout_ms)
{
    myc_proc_request preq;
    myc_proc_result  pres;
    const char *argv[16];
    int i = 0, n = 0;

    argv[n++] = fixture;
    while (args[i] && n < 15)
        argv[n++] = args[i++];
    argv[n] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.stdin_data = stdin_data;
    preq.stdin_len = stdin_len;
    preq.timeout_ms = timeout_ms;
    preq.max_output_bytes = cap;
    memset(&pres, 0, sizeof(pres));
    if (g_deadline_ms && now_ms() >= g_deadline_ms) {
        /* Batas waktu matriks tercapai: hentikan (hasil timeout sintetis
         * agar test berikutnya ikut gagal, bukan hang). */
        g_deadline_hit = 1;
        pres.timed_out = 1;
        pres.err = MYC_ERR_TIMEOUT;
        pres.ok = 0;
        return pres;
    }
    myc_proc_run(&preq, &pres);
    return pres;
}

static int deadline_hit(void)
{
    return g_deadline_hit;
}

/* Invariant drain (PR-016): shown TIDAK boleh melebihi total, dan output
 * kosong (total==0) harus menghasilkan shown==0 + string kosong valid.
 * Bug PR-016 (drain_assemble): untuk output kosong versi lama memaksa
 * shown=1 padahal 0 byte pernah ditulis -> 1 byte heap stale bocor ke
 * stdout/stderr (uninitialized read). Matriks lama hanya mengassert total
 * sehingga bug ini tak terlihat (protocol-clean PR-016 menangkapnya). */
static void cck_drain_invariants(const char *ctx, const myc_proc_result *pres)
{
    CCK(pres->stdout_shown <= pres->stdout_total,
        "%s: invariant stdout shown<=total (shown=%zu total=%zu)",
        ctx, pres->stdout_shown, pres->stdout_total);
    CCK(pres->stderr_shown <= pres->stderr_total,
        "%s: invariant stderr shown<=total (shown=%zu total=%zu)",
        ctx, pres->stderr_shown, pres->stderr_total);
    if (pres->stdout_total == 0)
        CCK(pres->stdout_shown == 0 && pres->stdout_data &&
            pres->stdout_data[0] == '\0',
            "%s: stdout kosong -> shown=0+NUL (got shown=%zu)",
            ctx, pres->stdout_shown);
    if (pres->stderr_total == 0)
        CCK(pres->stderr_shown == 0 && pres->stderr_data &&
            pres->stderr_data[0] == '\0',
            "%s: stderr kosong -> shown=0+NUL (got shown=%zu)",
            ctx, pres->stderr_shown);
}

/* --- orphan check: apakah pid masih hidup --- */
static int process_exists(unsigned long pid)
{
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                           (DWORD)pid);
    if (!h)
        return 0;
    {
        DWORD code = 0;
        BOOL r = GetExitCodeProcess(h, &code);
        CloseHandle(h);
        if (r && code == STILL_ACTIVE)
            return 1;
        return 0;
    }
#else
    if (kill((pid_t)pid, 0) == 0)
        return 1;
    return errno != ESRCH;
#endif
}

/* Poll sampai pid hilang atau timeout; 1 = sudah hilang.
 * Catatan POSIX: grandchild yang dibunuh SIGKILL jadi zombie sampai
 * reparenting+reap oleh init; kill(pid,0) menganggap zombie masih "ada",
 * jadi poll 5 s umumnya cukup (false-fail hanya di setup PID-1 eksotis). */
static int wait_pid_gone(unsigned long pid, int timeout_ms)
{
    int waited = 0;
    while (process_exists(pid) && waited < timeout_ms) {
        sleep_ms(100);
        waited += 100;
    }
    return !process_exists(pid);
}

/* Ambil spawned_child=<pid> dari stdout; 0 bila tidak ketemu. */
static unsigned long parse_spawned_pid(const char *out)
{
    const char *p = out ? strstr(out, "spawned_child=") : NULL;
    unsigned long pid = 0;
    if (!p)
        return 0;
    p += strlen("spawned_child=");
    while (*p >= '0' && *p <= '9') {
        pid = pid * 10 + (unsigned long)(*p - '0');
        p++;
    }
    return pid;
}

/* --- bounded memory (peak) --- */
static unsigned long long peak_mem_kb(void)
{
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    memset(&pmc, 0, sizeof(pmc));
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        return (unsigned long long)(pmc.PeakWorkingSetSize / 1024u);
    return 0;
#else
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));
    if (getrusage(RUSAGE_SELF, &ru) == 0)
        return (unsigned long long)ru.ru_maxrss;   /* KB di Linux */
    return 0;
#endif
}

/* ================================================================== */
/* T1: full Cartesian 4x4x4 ukuran I/O, order interleave, cap default  */
/* ================================================================== */
static void test_t1(const char *fixture, const char *stdin_buf)
{
    int i, j, k, before = g_fail, cases = 0;

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            for (k = 0; k < 4; k++) {
                const char *args[] = { "--matrix", SZSTR[i], SZSTR[j],
                                       SZSTR[k], "interleave", NULL };
                char ctx[160];
                myc_proc_result pres;
                size_t total_out = SIZES[j] + SIZES[k];
                int truncated_expected = total_out > (size_t)(1u << 20);

                g_case_fail = 0;
                snprintf(ctx, sizeof(ctx),
                         "T1 in=%s out=%s err=%s order=interleave cap=default",
                         SZSTR[i], SZSTR[j], SZSTR[k]);
                pres = run_child(fixture, args,
                                 i ? stdin_buf : NULL, SIZES[i],
                                 DEFAULT_CAP, GEN_TIMEOUT);

                CCK(!pres.timed_out && pres.ok,
                    "%s: selesai tanpa timeout (dur=%llu ms, timed_out=%d)",
                    ctx, (unsigned long long)pres.duration_ms, pres.timed_out);
                CCK(pres.exit_code == 0, "%s: exit=0 (got %d)",
                    ctx, pres.exit_code);
                CCK(pres.duration_ms < (unsigned long long)GEN_TIMEOUT + 5000,
                    "%s: durasi terkendali (got %llu ms)", ctx,
                    (unsigned long long)pres.duration_ms);
                CCK(pres.stdout_total == SIZES[j],
                    "%s: stdout_total=%zu (got %zu)",
                    ctx, SIZES[j], pres.stdout_total);
                CCK(pres.stderr_total == SIZES[k],
                    "%s: stderr_total=%zu (got %zu)",
                    ctx, SIZES[k], pres.stderr_total);
                CCK(pres.truncated == truncated_expected,
                    "%s: truncated=%d (harap %d)",
                    ctx, pres.truncated, truncated_expected);
                if (SIZES[j] > 0)
                    CCK(pres.stdout_shown > 0 && pres.stdout_data &&
                        pres.stdout_data[0] == 'A' &&
                        pres.stdout_data[pres.stdout_shown - 1] == 'A',
                        "%s: stdout prefix+tail 'A'", ctx);
                if (SIZES[k] > 0)
                    CCK(pres.stderr_shown > 0 && pres.stderr_data &&
                        pres.stderr_data[0] == 'B' &&
                        pres.stderr_data[pres.stderr_shown - 1] == 'B',
                        "%s: stderr prefix+tail 'B'", ctx);
                CCK(pres.stdout_shown <= (size_t)(1u << 20) &&
                    pres.stderr_shown <= (size_t)(1u << 20),
                    "%s: shown dibatasi cap default 1M (got %zu/%zu)",
                    ctx, pres.stdout_shown, pres.stderr_shown);
                cck_drain_invariants(ctx, &pres);

                CASE_OK("", ctx);
                myc_proc_result_free(&pres);
                cases++;
            }
    printf("T1: %d kombinasi Cartesian I/O, %d gagal\n", cases, g_fail - before);
}

/* ================================================================== */
/* T2: dimensi order (read-first / write-first / interleave) x 3 combo */
/* ================================================================== */
static void test_t2(const char *fixture, const char *stdin_buf)
{
    static const size_t combos[3][3] = {
        { SZ_PIPE, SZ_PIPE, SZ_PIPE },
        { SZ_HUGE, SZ_PIPE, 0 },
        { 0, SZ_HUGE, SZ_PIPE },
    };
    static const char *const orders[3] = {
        "read-first", "write-first", "interleave"
    };
    int c, o, before = g_fail;

    for (c = 0; c < 3; c++)
        for (o = 0; o < 3; o++) {
            const char *args[] = { "--matrix",
                                   SZSTR[szindex(combos[c][0])],
                                   SZSTR[szindex(combos[c][1])],
                                   SZSTR[szindex(combos[c][2])],
                                   orders[o], NULL };
            char ctx[160];
            myc_proc_result pres;

            g_case_fail = 0;
            snprintf(ctx, sizeof(ctx), "T2 in=%s out=%s err=%s order=%s",
                     SZSTR[szindex(combos[c][0])],
                     SZSTR[szindex(combos[c][1])],
                     SZSTR[szindex(combos[c][2])], orders[o]);
            pres = run_child(fixture, args,
                             combos[c][0] ? stdin_buf : NULL, combos[c][0],
                             DEFAULT_CAP, GEN_TIMEOUT);
            CCK(!pres.timed_out && pres.ok,
                "%s: tanpa timeout (dur=%llu ms)",
                ctx, (unsigned long long)pres.duration_ms);
            CCK(pres.exit_code == 0, "%s: exit=0 (got %d)", ctx, pres.exit_code);
            CCK(pres.stdout_total == combos[c][1],
                "%s: stdout_total=%zu (got %zu)",
                ctx, combos[c][1], pres.stdout_total);
            CCK(pres.stderr_total == combos[c][2],
                "%s: stderr_total=%zu (got %zu)",
                ctx, combos[c][2], pres.stderr_total);
            CASE_OK("", ctx);
            myc_proc_result_free(&pres);
        }
    printf("T2: order dimension, %d gagal\n", g_fail - before);
}

/* ================================================================== */
/* T3: timeout (deadlock fix), tree-kill + orphan, normal              */
/* ================================================================== */
static void test_t3(const char *fixture, const char *stdin_buf)
{
    int before = g_fail;

    /* T3a: child hang + TIDAK membaca stdin + stdin 8M, timeout 1500 ms.
     * Tanpa fix PR-006 (writer stdin threaded), myc menggantung abadi:
     * write blocking pada pipe penuh tak tunduk pada timeout. */
    {
        const char *args[] = { "--hang-after-output", NULL };
        myc_proc_result pres = run_child(fixture, args, stdin_buf, SZ_HUGE,
                                         DEFAULT_CAP, 1500);
        CHECK(pres.timed_out,
              "T3a hang+stdin8M: timed_out=1 (dur=%llu ms)",
              (unsigned long long)pres.duration_ms);
        CHECK(pres.err == MYC_ERR_TIMEOUT,
              "T3a: err=TIMEOUT (got %d)", (int)pres.err);
        CHECK(pres.duration_ms < 30000,
              "T3a: durasi < 30s (deadlock fix, got %llu ms)",
              (unsigned long long)pres.duration_ms);
        CHECK(pres.stdout_data && strstr(pres.stdout_data, "hang_after_output"),
              "T3a: marker stdout tertangkap");
        myc_proc_result_free(&pres);
    }

    /* T3b: tree-kill: child spawns grandchild (--spawn-child --sleep 60000),
     * timeout 1500 ms -> seluruh pohon dibunuh; grandchild TIDAK boleh
     * jadi orphan (zero orphan, P1-T03). */
    {
        const char *args[] = { "--spawn-child", "--sleep", "60000", NULL };
        myc_proc_result pres = run_child(fixture, args, NULL, 0, DEFAULT_CAP,
                                         2500);
        unsigned long gpid = pres.stdout_data ? parse_spawned_pid(pres.stdout_data) : 0;
        int gone = 0;
        CHECK(pres.timed_out,
              "T3b spawn-child: timed_out=1 (dur=%llu ms)",
              (unsigned long long)pres.duration_ms);
        CHECK(gpid > 0, "T3b: spawned_child pid terbaca (got %lu)", gpid);
        if (gpid > 0) {
            gone = wait_pid_gone(gpid, 5000);
            CHECK(gone, "T3b: grandchild %lu ikut mati (zero orphan)", gpid);
        }
        myc_proc_result_free(&pres);
    }

    /* T3c: child selesai normal — timeout TIDAK terpicu. */
    {
        const char *args[] = { "--sleep", "50", NULL };
        myc_proc_result pres = run_child(fixture, args, NULL, 0, DEFAULT_CAP,
                                         5000);
        CHECK(!pres.timed_out && pres.ok,
              "T3c sleep50: tanpa timeout (dur=%llu ms)",
              (unsigned long long)pres.duration_ms);
        CHECK(pres.exit_code == 0, "T3c: exit=0 (got %d)", pres.exit_code);
        myc_proc_result_free(&pres);
    }
    printf("T3: timeout/orphan, %d gagal\n", g_fail - before);
}

/* ================================================================== */
/* T4: output cap                                                      */
/* ================================================================== */
static void test_t4(const char *fixture)
{
    int before = g_fail;

    /* T4a: cap 64K TERPUKUL — 8M stdout + 8M stderr write-first. */
    {
        const char *args[] = { "--matrix", "0", "8388608", "8388608",
                               "write-first", NULL };
        myc_proc_result pres = run_child(fixture, args, NULL, 0,
                                         64u * 1024u, GEN_TIMEOUT);
        CHECK(!pres.timed_out && pres.ok,
              "T4a cap-hit 64K: tanpa timeout (dur=%llu ms)",
              (unsigned long long)pres.duration_ms);
        CHECK(pres.truncated, "T4a: truncated=1");
        CHECK(pres.stdout_total == SZ_HUGE && pres.stderr_total == SZ_HUGE,
              "T4a: totals 8M/8M (got %zu/%zu)",
              pres.stdout_total, pres.stderr_total);
        CHECK(pres.stdout_shown <= 64u * 1024u &&
              pres.stderr_shown <= 64u * 1024u,
              "T4a: shown dibatasi 64K (got %zu/%zu)",
              pres.stdout_shown, pres.stderr_shown);
        CHECK(pres.stdout_shown > 0 && pres.stdout_data &&
              pres.stdout_data[0] == 'A' &&
              pres.stdout_data[pres.stdout_shown - 1] == 'A',
              "T4a: stdout prefix+tail 'A'");
        CHECK(pres.stderr_shown > 0 && pres.stderr_data &&
              pres.stderr_data[0] == 'B' &&
              pres.stderr_data[pres.stderr_shown - 1] == 'B',
              "T4a: stderr prefix+tail 'B'");
        myc_proc_result_free(&pres);
    }

    /* T4b: cap 64K TIDAK terpukul (output 4K) — truncated harus 0. */
    {
        const char *args[] = { "--matrix", "0", "4096", "4096",
                               "write-first", NULL };
        myc_proc_result pres = run_child(fixture, args, NULL, 0,
                                         64u * 1024u, GEN_TIMEOUT);
        CHECK(!pres.timed_out && pres.ok, "T4b cap-miss: tanpa timeout");
        CHECK(!pres.truncated, "T4b: truncated=0");
        CHECK(pres.stdout_total == SZ_SMALL && pres.stderr_total == SZ_SMALL,
              "T4b: totals 4K/4K (got %zu/%zu)",
              pres.stdout_total, pres.stderr_total);
        myc_proc_result_free(&pres);
    }

    /* T4c: cap=0 -> default 1M; 8M stdout -> truncated, shown bounded. */
    {
        const char *args[] = { "--matrix", "0", "8388608", "0",
                               "write-first", NULL };
        myc_proc_result pres = run_child(fixture, args, NULL, 0,
                                         DEFAULT_CAP, GEN_TIMEOUT);
        CHECK(!pres.timed_out && pres.ok, "T4c cap-default: tanpa timeout");
        CHECK(pres.truncated, "T4c: truncated=1 (8M > cap default 1M)");
        CHECK(pres.stdout_total == SZ_HUGE, "T4c: total 8M (got %zu)",
              pres.stdout_total);
        CHECK(pres.stdout_shown <= (size_t)(1u << 20) && pres.stdout_shown > 0,
              "T4c: shown dibatasi 1M (got %zu)", pres.stdout_shown);
        myc_proc_result_free(&pres);
    }

    /* T4d: output BINER 1M dengan cap 4K — ring prefix 0x00, tail 0xFF
     * (byte biner aman lewat truncation ring). */
    {
        const char *args[] = { "--binary-output", "1048576", NULL };
        myc_proc_result pres = run_child(fixture, args, NULL, 0, 4096,
                                         GEN_TIMEOUT);
        CHECK(!pres.timed_out && pres.ok, "T4d biner: tanpa timeout");
        CHECK(pres.truncated, "T4d: truncated=1");
        CHECK(pres.stdout_total == 1048576, "T4d: total 1M (got %zu)",
              pres.stdout_total);
        CHECK(pres.stdout_shown <= 4096 && pres.stdout_shown > 0,
              "T4d: shown dibatasi 4K (got %zu)", pres.stdout_shown);
        CHECK(pres.stdout_data &&
              (unsigned char)pres.stdout_data[0] == 0x00,
              "T4d: prefix 0x00");
        CHECK(pres.stdout_data &&
              (unsigned char)pres.stdout_data[pres.stdout_shown - 1] == 0xFF,
              "T4d: tail 0xFF");
        myc_proc_result_free(&pres);
    }
    printf("T4: output cap, %d gagal\n", g_fail - before);
}

/* ================================================================== */
/* T5: EPIPE — child tak pernah baca stdin                             */
/* ================================================================== */
static void test_t5(const char *fixture, const char *stdin_buf)
{
    int before = g_fail;

    /* T5a: --never-read-stdin + stdin 8M. Parent menulis 8M ke child yang
     * TIDAK membaca — harus selesai cepat (EPIPE/broken pipe), bukan
     * deadlock. */
    {
        const char *args[] = { "--never-read-stdin", NULL };
        myc_proc_result pres = run_child(fixture, args, stdin_buf, SZ_HUGE,
                                         DEFAULT_CAP, GEN_TIMEOUT);
        CHECK(!pres.timed_out && pres.ok,
              "T5a never-read+8M: tanpa timeout (dur=%llu ms)",
              (unsigned long long)pres.duration_ms);
        CHECK(pres.duration_ms < 30000,
              "T5a: durasi < 30s (EPIPE, bukan deadlock; got %llu ms)",
              (unsigned long long)pres.duration_ms);
        CHECK(pres.exit_code == 0, "T5a: exit=0 (got %d)", pres.exit_code);
        CHECK(pres.stdout_data && strstr(pres.stdout_data, "never_read_stdin"),
              "T5a: marker tertangkap");
        myc_proc_result_free(&pres);
    }

    /* T5b: child exit instan (--exit 0) dengan stdin 8M. */
    {
        const char *args[] = { "--exit", "0", NULL };
        myc_proc_result pres = run_child(fixture, args, stdin_buf, SZ_HUGE,
                                         DEFAULT_CAP, GEN_TIMEOUT);
        CHECK(!pres.timed_out && pres.ok,
              "T5b exit0+8M: tanpa timeout (dur=%llu ms)",
              (unsigned long long)pres.duration_ms);
        CHECK(pres.exit_code == 0, "T5b: exit=0 (got %d)", pres.exit_code);
        CHECK(pres.duration_ms < 30000,
              "T5b: durasi < 30s (got %llu ms)",
              (unsigned long long)pres.duration_ms);
        myc_proc_result_free(&pres);
    }
    printf("T5: EPIPE, %d gagal\n", g_fail - before);
}

/* ================================================================== */
/* T6: child menutup descriptor stdout/stderr                          */
/* ================================================================== */
static void test_t6(const char *fixture)
{
    int before = g_fail;
    const char *args_close_stdout[] = { "--close-stdout", NULL };
    const char *args_close_stderr[] = { "--close-stderr", NULL };
    myc_proc_result pres;

    pres = run_child(fixture, args_close_stdout, NULL, 0, DEFAULT_CAP, 5000);
    CHECK(!pres.timed_out && pres.ok,
          "T6 close-stdout: tanpa timeout (dur=%llu ms)",
          (unsigned long long)pres.duration_ms);
    CHECK(pres.exit_code == 0, "T6 close-stdout: exit=0 (got %d)",
          pres.exit_code);
    myc_proc_result_free(&pres);

    pres = run_child(fixture, args_close_stderr, NULL, 0, DEFAULT_CAP, 5000);
    CHECK(!pres.timed_out && pres.ok,
          "T6 close-stderr: tanpa timeout (dur=%llu ms)",
          (unsigned long long)pres.duration_ms);
    CHECK(pres.exit_code == 0, "T6 close-stderr: exit=0 (got %d)",
          pres.exit_code);
    myc_proc_result_free(&pres);
    printf("T6: close descriptor, %d gagal\n", g_fail - before);
}

/* ================================================================== */
/* T7: stress loop — repset + orphan spot-check + bounded memory        */
/* ================================================================== */
static void test_t7(const char *fixture, const char *stdin_buf, int iters)
{
    int before = g_fail;
    int i, execs = 0;
    unsigned long long mem_warm = 0, mem_final = 0;

    for (i = 0; i < iters; i++) {
        /* repset cepat: 3 eksekusi per iterasi (ukuran 256K: cepat). */
        {
            const char *args[] = { "--matrix", "262144", "262144", "262144",
                                   "interleave", NULL };
            myc_proc_result pres = run_child(fixture, args, stdin_buf, SZ_PIPE,
                                             DEFAULT_CAP, GEN_TIMEOUT);
            if (!pres.ok || pres.timed_out || pres.exit_code != 0) {
                fprintf(stderr,
                        "[FAIL] T7 iter %d: repset interleave in=256K out=256K "
                        "err=256K gagal (ok=%d timed_out=%d exit=%d)\n",
                        i, pres.ok, pres.timed_out, pres.exit_code);
                g_fail++;
            }
            execs++;
            myc_proc_result_free(&pres);
        }
        {
            const char *args[] = { "--matrix", "0", "262144", "0",
                                   "write-first", NULL };
            myc_proc_result pres = run_child(fixture, args, NULL, 0,
                                             DEFAULT_CAP, GEN_TIMEOUT);
            if (!pres.ok || pres.timed_out || pres.exit_code != 0) {
                fprintf(stderr,
                        "[FAIL] T7 iter %d: repset write-first in=0 out=256K "
                        "err=0 gagal (ok=%d timed_out=%d exit=%d)\n",
                        i, pres.ok, pres.timed_out, pres.exit_code);
                g_fail++;
            }
            execs++;
            myc_proc_result_free(&pres);
        }
        {
            const char *args[] = { "--never-read-stdin", NULL };
            myc_proc_result pres = run_child(fixture, args, stdin_buf, SZ_PIPE,
                                             DEFAULT_CAP, GEN_TIMEOUT);
            if (!pres.ok || pres.timed_out || pres.exit_code != 0) {
                fprintf(stderr,
                        "[FAIL] T7 iter %d: repset never-read-stdin gagal "
                        "(ok=%d timed_out=%d exit=%d)\n",
                        i, pres.ok, pres.timed_out, pres.exit_code);
                g_fail++;
            }
            execs++;
            myc_proc_result_free(&pres);
        }
        /* Setiap 25 iterasi: timeout + tree-kill + orphan spot-check. */
        if ((i + 1) % 25 == 0) {
            const char *args[] = { "--spawn-child", "--sleep", "60000", NULL };
            myc_proc_result pres = run_child(fixture, args, NULL, 0,
                                             DEFAULT_CAP, 2500);
            unsigned long gpid = pres.stdout_data
                                 ? parse_spawned_pid(pres.stdout_data) : 0;
            if (!pres.timed_out) {
                fprintf(stderr, "[FAIL] T7 iter %d: timeout case tak terpicu\n",
                        i);
                g_fail++;
            }
            if (gpid == 0) {
                fprintf(stderr, "[FAIL] T7 iter %d: spawned_child pid tak "
                        "terbaca setelah timeout\n", i);
                g_fail++;
            } else if (!wait_pid_gone(gpid, 5000)) {
                fprintf(stderr, "[FAIL] T7 iter %d: orphan grandchild %lu "
                        "masih hidup setelah kill pohon\n", i, gpid);
                g_fail++;
            }
            execs++;
            myc_proc_result_free(&pres);
        }
        if (i == 25)
            mem_warm = peak_mem_kb();
        if ((i + 1) % 250 == 0)
            printf("  T7 progress: %d/%d iterasi\n", i + 1, iters);
    }
    mem_final = peak_mem_kb();
    CHECK(mem_warm > 0 && mem_final > 0,
          "T7: memori terukur (warm=%llu KB, final=%llu KB)",
          mem_warm, mem_final);
    if (mem_warm > 0 && mem_final > mem_warm)
        CHECK(mem_final - mem_warm < (unsigned long long)MEM_THRESHOLD_KB,
              "T7: pertumbuhan memori bounded (< %u KB; delta=%llu KB)",
              (unsigned)MEM_THRESHOLD_KB, mem_final - mem_warm);
    printf("T7: %d iterasi, %d eksekusi myc_proc_run, %d gagal\n",
           iters, execs, g_fail - before);
}

/* ================================================================== */
/* T8: stdin KOSONG + child membaca sampai EOF (bug proc.c PR-010)      */
/* ================================================================== */
/* Saat stdin_len==0, write end pipe stdin TIDAK boleh tetap terbuka di
 * parent: child yang membaca stdin sampai EOF (mis. `gcc -dM -E -` di
 * assume.c, atau program --run yang membaca stdin tanpa --run-stdin)
 * memblok abadi menunggu EOF dan baru terbunuh pada timeout — pajak
 * diam-diam ~15 s di SETIAP panggilan myc_proc_run. Kedua mode fixture
 * membaca stdin sampai EOF; timeout 3000 ms membuktikan EOF instan
 * (bukan hang sampai timeout). */
static void test_t8(const char *fixture)
{
    int before = g_fail;

    {
        const char *args[] = { "--output-after-stdin", NULL };
        myc_proc_result pres = run_child(fixture, args, NULL, 0,
                                         DEFAULT_CAP, 3000);
        CHECK(!pres.timed_out && pres.ok,
              "T8a stdin0+read-EOF: selesai tanpa timeout (dur=%llu ms)",
              (unsigned long long)pres.duration_ms);
        CHECK(pres.exit_code == 0, "T8a: exit=0 (got %d)", pres.exit_code);
        CHECK(pres.stdout_data &&
              strstr(pres.stdout_data, "output_after_stdin="),
              "T8a: marker output_after_stdin tertangkap");
        cck_drain_invariants("T8a", &pres);
        myc_proc_result_free(&pres);
    }
    {
        const char *args[] = { "--stdin-after-output", NULL };
        myc_proc_result pres = run_child(fixture, args, NULL, 0,
                                         DEFAULT_CAP, 3000);
        CHECK(!pres.timed_out && pres.ok,
              "T8b stdin0+tulis-lalu-baca-EOF: tanpa timeout (dur=%llu ms)",
              (unsigned long long)pres.duration_ms);
        CHECK(pres.exit_code == 0, "T8b: exit=0 (got %d)", pres.exit_code);
        CHECK(pres.stdout_data &&
              strstr(pres.stdout_data, "stdin_after_output"),
              "T8b: marker stdin_after_output tertangkap");
        cck_drain_invariants("T8b", &pres);
        myc_proc_result_free(&pres);
    }
    printf("T8: stdin kosong -> EOF instan, %d gagal\n", g_fail - before);
}

int main(int argc, char **argv)
{
    const char *fixture;
    char *stdin_buf;
    int iters = 100;
    int i;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <proc_fixture> [--stress N]\n", argv[0]);
        return 2;
    }
    fixture = argv[1];
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--stress") == 0 && i + 1 < argc) {
            iters = atoi(argv[i + 1]);
            if (iters < 1)
                iters = 1;
            i++;
        }
    }

    /* Sanity: fixture tersedia + mendukung --matrix (PR-006). */
    {
        const char *args[] = { "--help", NULL };
        myc_proc_result pres = run_child(fixture, args, NULL, 0, 4096, 10000);
        if (!pres.ok || pres.exit_code != 0 ||
            !(pres.stdout_data && strstr(pres.stdout_data, "--matrix"))) {
            fprintf(stderr,
                    "[FAIL] fixture %s tidak tersedia / tidak mendukung mode "
                    "--matrix (PR-006 butuh proc_fixture terbaru)\n", fixture);
            myc_proc_result_free(&pres);
            return 1;
        }
        myc_proc_result_free(&pres);
        printf("[OK]   fixture sanity: %s siap (mode --matrix tersedia)\n",
               fixture);
    }

    stdin_buf = (char *)malloc(SZ_HUGE);
    if (!stdin_buf) {
        fprintf(stderr, "gagal alokasi stdin buffer 8M\n");
        return 2;
    }
    memset(stdin_buf, 'x', SZ_HUGE);

    g_deadline_ms = now_ms() + MATRIX_DEADLINE_MS;
    test_t1(fixture, stdin_buf);
    if (!deadline_hit()) test_t2(fixture, stdin_buf);
    if (!deadline_hit()) test_t3(fixture, stdin_buf);
    if (!deadline_hit()) test_t4(fixture);
    if (!deadline_hit()) test_t5(fixture, stdin_buf);
    if (!deadline_hit()) test_t6(fixture);
    if (!deadline_hit()) test_t7(fixture, stdin_buf, iters);
    if (!deadline_hit()) test_t8(fixture);

    free(stdin_buf);
    if (deadline_hit()) {
        fprintf(stderr,
                "[FAIL] proc_deadlock_matrix: batas waktu internal %u s tercapai "
                "(myc_proc_run kemungkinan hang — jalankan dengan log eksternal)\n",
                (unsigned)(MATRIX_DEADLINE_MS / 1000u));
        return 1;
    }
    printf(g_fail ? "proc_deadlock_matrix: FAIL (%d)\n"
                  : "proc_deadlock_matrix: OK (T1-T8, zero deadlock)\n",
           g_fail);
    return g_fail ? 1 : 0;
}
