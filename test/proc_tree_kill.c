/*
 * proc_tree_kill.c -- Process-tree cleanup tests (PR-007, plan P1-T04).
 *
 * Mengunci perilaku myc_proc_run (proc.c) saat TIMEOUT membunuh pohon
 * proses, memakai proc_fixture (PR-005/P1-T02) yang child-nya spawn child
 * lagi. Verifikasi Windows Job Object (nested process, breakaway attempt,
 * inherited handles, console/control) dan kill process group POSIX:
 *
 *   T1 Nested 3-level     : --spawn-grandchild (fixture -> child -> grandchild)
 *                           timeout -> SEMUA pid mati (zero orphan).
 *   T2 Breakaway attempt  : --spawn-breakaway -> Windows: CreateProcess dengan
 *                           CREATE_BREAKAWAY_FROM_JOB harus GAGAL
 *                           (breakaway_status=0) karena job myc tidak
 *                           mengizinkan breakaway; status=1 = lubang job
 *                           (assignment gagal / policy salah). POSIX: N/A
 *                           (status=2), berperilaku seperti --spawn-child.
 *   T3 Nested job         : --spawn-jobchild -> Windows: grandchild diletakkan
 *                           di Job Object milik fixture (nested job) — tetap
 *                           harus ikut mati saat myc membunuh pohon pada
 *                           timeout. POSIX: N/A (status=2).
 *   T4 Inherited handles  : --spawn-detach -> fixture exit 0, grandchild hidup
 *                           TANPA memegang pipe myc (bInheritHandles=FALSE
 *                           Windows / FD_CLOEXEC POSIX) -> myc mendapat EOF dan
 *                           kembali cepat, TIDAK menunggu grandchild; grandchild
 *                           self-clean (--sleep 5 s). Ini membuktikan handle
 *                           pipe myc TIDAK bocor ke cucu.
 *   T5 Normal chain exit  : --spawn-child --exit 7 -> exit 7, tanpa timeout
 *                           (alur normal 2 level; exit diteruskan).
 *
 * Catatan: pada normal completion (bukan timeout) myc TIDAK membunuh
 * keturunan yang masih hidup (direct child sudah exit; tree bukan tanggung
 * jawab myc lagi) — T4 menegaskan hal ini secara eksplisit.
 *
 * Kegagalan apa pun memuat konfigurasi lengkap (reproducible).
 *
 * Konsumen: test/_audit018.sh blok 10.
 *
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -Werror -I. -pthread \
 *       -o proc_tree_kill proc_tree_kill.c proc.c
 *
 * Penggunaan:
 *   proc_tree_kill <path-proc_fixture>
 */
/* kill, nanosleep butuh _POSIX_C_SOURCE; -std=c11 menonaktifkan extension
 * glibc. Wajib SEBELUM include sistem apa pun. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#endif

#include "myc.h"
#include "proc.h"

#define DEFAULT_CAP 0u
#define TREE_TIMEOUT 3000      /* timeout myc untuk kasus tree-kill */
#define ORPHAN_POLL_MS 5000    /* poll pid hilang */
#define FAIL_FAST 1

static int g_fail = 0;

#define CHECK(cond, ...) do {                                          \
        if (cond) { printf("[OK]   " __VA_ARGS__); printf("\n"); }     \
        else { fprintf(stderr, "[FAIL] " __VA_ARGS__);                 \
               fprintf(stderr, "\n"); g_fail++; }                      \
    } while (0)

static void sleep_ms(int ms)
{
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0) { /* EINTR */ }
#endif
}

/* --- launcher --- */
static myc_proc_result run_child(const char *fixture, const char *const args[],
                                 int timeout_ms)
{
    myc_proc_request preq;
    myc_proc_result  pres;
    const char *argv[12];
    int i = 0, n = 0;

    argv[n++] = fixture;
    while (args[i] && n < 11)
        argv[n++] = args[i++];
    argv[n] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.timeout_ms = timeout_ms;
    preq.max_output_bytes = DEFAULT_CAP;
    memset(&pres, 0, sizeof(pres));
    myc_proc_run(&preq, &pres);
    return pres;
}

/* --- process liveness + poll (sama dgn deadlock matrix) --- */
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

static int wait_pid_gone(unsigned long pid, int timeout_ms)
{
    int waited = 0;
    while (process_exists(pid) && waited < timeout_ms) {
        sleep_ms(100);
        waited += 100;
    }
    return !process_exists(pid);
}

/* Ambil SEMUA spawned_child=<pid> dari stdout; kembalikan jumlah. */
static int parse_all_spawned_pids(const char *out, unsigned long *pids, int max)
{
    int n = 0;
    const char *p = out;
    while (p && n < max) {
        p = strstr(p, "spawned_child=");
        if (!p)
            break;
        p += strlen("spawned_child=");
        {
            unsigned long pid = 0;
            while (*p >= '0' && *p <= '9') {
                pid = pid * 10 + (unsigned long)(*p - '0');
                p++;
            }
            if (pid)
                pids[n++] = pid;
        }
    }
    return n;
}

static int has_substr(const myc_proc_result *pres, const char *needle)
{
    return pres->stdout_data && strstr(pres->stdout_data, needle) != NULL;
}

/* Jumlah proses proc_fixture.exe yang masih hidup (Windows, Toolhelp).
 * Dipakai T1: baris pid cucu (C2) TIDAK terlihat karena fixture memakai
 * bInheritHandles=FALSE (hygiene handle) — verifikasi "nol stray" dengan
 * scan nama lebih kuat daripada cek pid per-kasus. -1 = gagal scan. */
#ifdef _WIN32
static int count_proc_fixture(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    int n = 0;
    if (snap == INVALID_HANDLE_VALUE)
        return -1;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"proc_fixture.exe") == 0)
                n++;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return n;
}
#endif

/* Poll sampai tidak ada proc_fixture tersisa; 1 = bersih. */
#ifdef _WIN32
static int wait_no_fixture(int timeout_ms)
{
    int waited = 0;
    while (waited < timeout_ms) {
        int n = count_proc_fixture();
        if (n == 0)
            return 1;
        sleep_ms(100);
        waited += 100;
    }
    return count_proc_fixture() == 0;
}
#endif

/* ================================================================== */
/* T1: nested 3-level (fixture -> child -> grandchild), semua mati      */
/* ================================================================== */
/* Catatan visibilitas: fixture memakai bInheritHandles=FALSE (hygiene
 * handle, PR-007), jadi baris spawned_child dari C1 (cucu) tidak sampai
 * ke pipe myc — yang terlihat hanya spawn langsung fixture (C1). Karena
 * itu T1 memverifikasi: (a) pid terlihat (C1) ikut mati; (b) Windows:
 * scan Toolhelp membuktikan TIDAK ADA proc_fixture tersisa sama sekali
 * (C2 juga mati walau pid-nya tak terlihat). POSIX: verifikasi 3-level
 * via kill process group sudah ditangani verify_descendants (MYC-AUDIT-
 * 011); di sini pid terlihat dicek. */
static void test_t1(const char *fixture)
{
    int before = g_fail, i;
    const char *args[] = { "--spawn-grandchild", NULL };
    myc_proc_result pres = run_child(fixture, args, TREE_TIMEOUT);
    unsigned long pids[4];
    int np = 0;

    CHECK(pres.timed_out,
          "T1 3-level: timed_out=1 (dur=%llu ms)",
          (unsigned long long)pres.duration_ms);
    if (pres.stdout_data)
        np = parse_all_spawned_pids(pres.stdout_data, pids, 4);
    CHECK(np >= 1,
          "T1 3-level: spawned_child pid terbaca (got %d)", np);
    for (i = 0; i < np; i++)
        CHECK(wait_pid_gone(pids[i], ORPHAN_POLL_MS),
              "T1 3-level: pid %lu ikut mati (zero orphan)", pids[i]);
#ifdef _WIN32
    CHECK(wait_no_fixture(ORPHAN_POLL_MS),
          "T1 3-level: nol proc_fixture tersisa (Toolhelp) — C2 juga mati");
#else
    printf("  [NOTE] T1 3-level POSIX: C2 (pid tak terlihat) dicakup "
           "verify_descendants (kill process group)\n");
#endif
    myc_proc_result_free(&pres);
    printf("T1: nested 3-level, %d gagal\n", g_fail - before);
}

/* ================================================================== */
/* T2: breakaway attempt (CREATE_BREAKAWAY_FROM_JOB)                   */
/* ================================================================== */
static void test_t2(const char *fixture)
{
    int before = g_fail;
    const char *args[] = { "--spawn-breakaway", "--sleep", "60000", NULL };
    myc_proc_result pres = run_child(fixture, args, TREE_TIMEOUT);

    CHECK(pres.timed_out,
          "T2 breakaway: timed_out=1 (dur=%llu ms)",
          (unsigned long long)pres.duration_ms);
#ifdef _WIN32
    CHECK(has_substr(&pres, "breakaway_status=0"),
          "T2 breakaway: CREATE_BREAKAWAY_FROM_JOB ditolak job myc "
          "(breakaway_status=0) — pohon terikat");
    /* Tidak ada breakaway_status=1 di output = penolakan konsisten.
     * (Label jujur: bila status=1 muncul, CHECK ini GAGAL — bukan OK.) */
    CHECK(!has_substr(&pres, "breakaway_status=1"),
          "T2 breakaway: TIDAK ada breakaway_status=1 (breakaway SUKSES "
          "= lubang job, wajib FAIL)");
#else
    {
        unsigned long pids[4];
        int np = 0, i;
        CHECK(has_substr(&pres, "breakaway_status=2"),
              "T2 breakaway (POSIX): N/A (breakaway_status=2)");
        if (pres.stdout_data)
            np = parse_all_spawned_pids(pres.stdout_data, pids, 4);
        for (i = 0; i < np; i++)
            CHECK(wait_pid_gone(pids[i], ORPHAN_POLL_MS),
                  "T2 breakaway (POSIX): pid %lu ikut mati", pids[i]);
    }
#endif
    myc_proc_result_free(&pres);
    printf("T2: breakaway attempt, %d gagal\n", g_fail - before);
}

/* ================================================================== */
/* T3: nested job (grandchild di Job Object milik fixture)             */
/* ================================================================== */
static void test_t3(const char *fixture)
{
    int before = g_fail, i;
    const char *args[] = { "--spawn-jobchild", "--sleep", "60000", NULL };
    myc_proc_result pres = run_child(fixture, args, TREE_TIMEOUT);
    unsigned long pids[4];
    int np = 0;

    CHECK(pres.timed_out,
          "T3 nested job: timed_out=1 (dur=%llu ms)",
          (unsigned long long)pres.duration_ms);
#ifdef _WIN32
    CHECK(has_substr(&pres, "jobchild_status=0"),
          "T3 nested job: grandchild masuk job fixture (jobchild_status=0)");
#else
    CHECK(has_substr(&pres, "jobchild_status=2"),
          "T3 nested job (POSIX): N/A (jobchild_status=2)");
#endif
    if (pres.stdout_data)
        np = parse_all_spawned_pids(pres.stdout_data, pids, 4);
    for (i = 0; i < np; i++)
        CHECK(wait_pid_gone(pids[i], ORPHAN_POLL_MS),
              "T3 nested job: pid %lu ikut mati walau di job fixture "
              "(zero orphan)", pids[i]);
    myc_proc_result_free(&pres);
    printf("T3: nested job, %d gagal\n", g_fail - before);
}

/* ================================================================== */
/* T4: inherited handles — grandchild hidup tidak memegang pipe myc     */
/* ================================================================== */
/* Grandchild tidur 5 s; bila pipe myc bocor ke dia, drain tidak dapat
 * EOF dan myc menunggu (Windows: join bounded ~2 s -> dur >= 2 s; POSIX:
 * join tanpa batas -> hang). Return < 1,5 s = EOF bersih (handle tidak
 * bocor). NASIB grandchild setelah myc return BERBEDA per platform:
 *   - Windows: KILL_ON_JOB_CLOSE — myc menutup handle job pada normal
 *     completion -> SELURUH anggota job (termasuk grandchild detach)
 *     ikut mati = nol stray walau bukan timeout (crash-safe hygiene).
 *   - POSIX: tidak ada job; myc tidak membunuh keturunan pada normal
 *     completion -> grandchild hidup dan self-clean (--sleep 5 s). */
static void test_t4(const char *fixture)
{
    int before = g_fail;
    const char *args[] = { "--spawn-detach", "--sleep", "5000", NULL };
    myc_proc_result pres = run_child(fixture, args, 15000);
    unsigned long pid = 0;
    int np = 0;

    if (pres.stdout_data)
        np = parse_all_spawned_pids(pres.stdout_data, &pid, 1);
    CHECK(!pres.timed_out && pres.ok,
          "T4 detach: selesai normal tanpa timeout (exit=%d dur=%llu ms)",
          pres.exit_code, (unsigned long long)pres.duration_ms);
    CHECK(pres.exit_code == 0, "T4 detach: exit=0 (got %d)", pres.exit_code);
    CHECK(pres.duration_ms < 1500,
          "T4 detach: myc TIDAK menunggu grandchild (dur < 1500 ms; got "
          "%llu ms) — handle pipe tidak bocor",
          (unsigned long long)pres.duration_ms);
#ifdef _WIN32
    /* KILL_ON_JOB_CLOSE: job ditutup saat normal completion -> grandchild
     * ikut mati (nol stray). Verifikasi dengan retry singkat. */
    CHECK(np == 1 && pid > 0 && !process_exists(pid),
          "T4 detach (Win): grandchild %lu ikut mati saat myc menutup job "
          "(KILL_ON_JOB_CLOSE, normal completion)", pid);
#else
    /* POSIX: tidak membunuh keturunan pada normal completion. */
    CHECK(np == 1 && pid > 0 && process_exists(pid),
          "T4 detach (POSIX): grandchild %lu hidup saat myc return "
          "(normal completion tidak membunuh keturunan)", pid);
    if (np == 1 && pid > 0)
        CHECK(wait_pid_gone(pid, ORPHAN_POLL_MS + 3000),
              "T4 detach (POSIX): grandchild %lu self-clean (--sleep 5 s)",
              pid);
#endif
    myc_proc_result_free(&pres);
    printf("T4: inherited handles, %d gagal\n", g_fail - before);
}

/* ================================================================== */
/* T5: normal chain exit propagation (bukan timeout)                   */
/* ================================================================== */
static void test_t5(const char *fixture)
{
    int before = g_fail;
    const char *args[] = { "--spawn-child", "--exit", "7", NULL };
    myc_proc_result pres = run_child(fixture, args, 10000);

    CHECK(!pres.timed_out && pres.ok,
          "T5 normal chain: tanpa timeout (dur=%llu ms)",
          (unsigned long long)pres.duration_ms);
    CHECK(pres.exit_code == 7, "T5 normal chain: exit=7 (got %d)",
          pres.exit_code);
    myc_proc_result_free(&pres);
    printf("T5: normal chain exit, %d gagal\n", g_fail - before);
}

int main(int argc, char **argv)
{
    const char *fixture;
    const char *args[] = { "--help", NULL };
    myc_proc_result pres;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <proc_fixture>\n", argv[0]);
        return 2;
    }
    fixture = argv[1];

    /* Sanity: fixture tersedia + mendukung mode PR-007. */
    pres = run_child(fixture, args, 10000);
    if (!pres.ok || pres.exit_code != 0 ||
        !(pres.stdout_data && strstr(pres.stdout_data, "--spawn-breakaway") &&
          strstr(pres.stdout_data, "--spawn-jobchild") &&
          strstr(pres.stdout_data, "--spawn-detach"))) {
        fprintf(stderr,
                "[FAIL] fixture %s tidak tersedia / tidak mendukung mode "
                "PR-007 (--spawn-breakaway/--spawn-jobchild/--spawn-detach)\n",
                fixture);
        myc_proc_result_free(&pres);
        return 1;
    }
    myc_proc_result_free(&pres);
    printf("[OK]   fixture sanity: %s siap (mode PR-007 tersedia)\n", fixture);

    test_t1(fixture);
    test_t2(fixture);
    test_t3(fixture);
    test_t4(fixture);
    test_t5(fixture);

    printf(g_fail ? "proc_tree_kill: FAIL (%d)\n"
                  : "proc_tree_kill: OK (T1-T5, zero orphan)\n",
           g_fail);
    return g_fail ? 1 : 0;
}
