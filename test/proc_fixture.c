/*
 * proc_fixture.c -- Hostile child process fixture (PR-005, plan P1-T02).
 *
 * Binary pembantu yang TIDAK bergantung pada myc sama sekali (standalone,
 * seperti argv_probe.c). Dipakai test PR-006 (deadlock matrix) dan PR-007
 * (timeout / process-tree kill) sebagai child yang perilakunya bermusuhan
 * dan DETERMINISTIK -- menggantikan tool shell arbitrer.
 *
 * Pola byte (agar harness bisa memverifikasi prefix/tail/menghitung byte):
 *   --stdout N            : N byte 0x41 ('A') ke stdout
 *   --stderr N            : N byte 0x42 ('B') ke stderr
 *   --both   N            : N byte 'A' (stdout) + N byte 'B' (stderr),
 *                           chunk 4 KiB diselingi (dua pipe penuh bersamaan)
 *   --binary-output [N]   : N byte 0x00..0xFF siklik (default 4096) -- berisi
 *                           NUL + byte 0xFF (uji penanganan biner/truncation)
 *
 * Mode (lihat juga --help):
 *   --exit N                 exit dengan kode N (0..255)
 *   --sleep MS               tidur MS ms lalu exit 0
 *   --stdout N               tulis N byte 'A' ke stdout, flush, exit 0
 *   --stderr N               tulis N byte 'B' ke stderr, flush, exit 0
 *   --both N                 tulis N 'A' stdout + N 'B' stderr (selang-seling)
 *   --read-stdin N           baca sampai N byte stdin (atau EOF), cetak
 *                            stdin_read=<aktual>, exit 0
 *   --never-read-stdin       TIDAK membaca stdin sama sekali; cetak marker,
 *                            exit 0 (uji: parent yang menulis pipe besar
 *                            tidak boleh deadlock / harus pegang EPIPE)
 *   --close-stdout           tutup descriptor stdout level OS lalu exit 0
 *   --close-stderr           tutup descriptor stderr level OS lalu exit 0
 *   --spawn-child [args..]   spawn diri sendiri dengan args (default:
 *                            --sleep 60000), cetak spawned_child=<pid>,
 *                            TUNGGU child, exit dengan status child
 *   --spawn-grandchild [args..] spawn child dengan args (default:
 *                            --spawn-child), cetak pid, tunggu, exit
 *   --spawn-breakaway [args..] (uji job PR-007) Windows: coba spawn child
 *                            dgn CREATE_BREAKAWAY_FROM_JOB; cetak
 *                            breakaway_status=0 (ditolak job, diharapkan) /
 *                            1 (sukses = lubang job); bila ditolak, hang
 *                            agar myc timeout. POSIX: status=2 (N/A)
 *   --spawn-jobchild [args..] (uji nested job PR-007) Windows: grandchild
 *                            diletakkan di Job Object baru milik fixture;
 *                            cetak jobchild_status=0/1 (0=OK) + pid; tetap
 *                            harus ikut mati saat myc kill pohon. POSIX: 2
 *   --spawn-detach [args..]  (uji inherited handles PR-007) spawn child lalu
 *                            LANGSUNG exit 0 tanpa menunggu; grandchild
 *                            TIDAK memegang pipe myc (bInheritHandles=FALSE
 *                            Windows / FD_CLOEXEC POSIX) jadi myc dapat EOF
 *                            tanpa menunggu grandchild. Default child:
 *                            --sleep 5000 (self-clean)
 *   --crash                  segfault (null deref) setelah marker stderr
 *   --hang-after-output      tulis marker stdout + flush, tidur selamanya
 *   --output-after-stdin     baca SEMUA stdin sampai EOF, lalu tulis marker
 *   --stdin-after-output     tulis marker + flush, lalu baca semua stdin
 *   --unicode-output         tulis teks UTF-8 multibyte ke stdout
 *   --binary-output [N]      tulis byte biner siklik 0x00..0xFF
 *   --self-pid               cetak pid=<pid> lalu exit 0
 *   --matrix S O E ORDER     kendali penuh ukuran stdin/stdout/stderr +
 *                            urutan I/O (deadlock matrix PR-006):
 *                              S = byte stdin yang dibaca (s.d. EOF)
 *                              O = byte 'A' ditulis ke stdout
 *                              E = byte 'B' ditulis ke stderr
 *                              ORDER = read-first | write-first | interleave
 *                            TIDAK mencetak apa pun selain payload (byte
 *                            count eksak untuk asersi harness).
 *   --help | -h              daftar mode, exit 0
 *
 * Exit codes: 0 = sukses mode; 1 = kegagalan I/O mode; 2 = usage/parse
 * error; 127 = gagal exec (POSIX child). Status child diteruskan oleh
 * --spawn-child / --spawn-grandchild (nilai negatif = spawn gagal ->
 * dipetakan ke exit 2). Catatan crash propagation: POSIX melaporkan
 * child yang mati sinyal sebagai 128+sig, Windows melaporkan raw
 * exception code (mis. 0xC0000005 = 3221225477) dari GetExitCodeProcess
 * -- konsumen HARUS cek "!= 0", bukan nilai spesifik lintas platform.
 *
 * Catatan platform: pada Windows, stream stdin/stdout/stderr dipaksa mode
 * BINER (set_binary_streams) agar byte count eksak di pipe (tanpa CRLF
 * translation / tanpa Ctrl-Z sebagai EOF) -- krusial untuk deadlock matrix.
 *
 * Build (portabel, Windows MinGW + POSIX):
 *   gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic \
 *       -o proc_fixture proc_fixture.c
 */
/* nanosleep, fileno, FD_CLOEXEC butuh _POSIX_C_SOURCE (sama seperti
 * proc.c); -std=c11 menonaktifkan extension glibc. Wajib SEBELUM
 * include sistem apa pun (glibc meng-cache feature test macro di
 * include guard). */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

#define FIXTURE_CHUNK (64u * 1024u)
#define FIXTURE_MAX_N (1u << 30)   /* batas N_BYTES: 1 GiB */
#define FIXTURE_MAX_MS 600000u     /* batas sleep/hang: 10 menit */

static void fixture_sleep(unsigned ms)
{
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    while (nanosleep(&ts, &ts) != 0) {
        /* EINTR: ts sudah diisi sisa waktu; ulangi. */
    }
#endif
}

static long fixture_pid(void)
{
#ifdef _WIN32
    return (long)GetCurrentProcessId();
#else
    return (long)getpid();
#endif
}

static void close_stdout_os(void)
{
#ifdef _WIN32
    _close(_fileno(stdout));
#else
    close(fileno(stdout));
#endif
}

static void close_stderr_os(void)
{
#ifdef _WIN32
    _close(_fileno(stderr));
#else
    close(fileno(stderr));
#endif
}

/* Parse 0..FIXTURE_MAX_N; -1 = error. */
static int parse_n(const char *s, unsigned long *out)
{
    char *end = NULL;
    unsigned long v;
    if (!s || !*s)
        return -1;
    v = strtoul(s, &end, 10);
    if (end == s || *end != '\0' || v > FIXTURE_MAX_N)
        return -1;
    *out = v;
    return 0;
}

/* Parse 0..255; -1 = error. */
static int parse_exit(const char *s)
{
    char *end = NULL;
    long v;
    if (!s || !*s)
        return -1;
    v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || v < 0 || v > 255)
        return -1;
    return (int)v;
}

/* Parse 0..FIXTURE_MAX_MS; -1 = error. */
static int parse_ms(const char *s, unsigned *out)
{
    char *end = NULL;
    unsigned long v;
    if (!s || !*s)
        return -1;
    v = strtoul(s, &end, 10);
    if (end == s || *end != '\0' || v > FIXTURE_MAX_MS)
        return -1;
    *out = (unsigned)v;
    return 0;
}

static int write_n(FILE *f, unsigned char c, unsigned long n)
{
    unsigned char buf[FIXTURE_CHUNK];
    memset(buf, c, sizeof(buf));
    while (n > 0) {
        size_t chunk = n > sizeof(buf) ? sizeof(buf) : (size_t)n;
        if (fwrite(buf, 1, chunk, f) != chunk)
            return -1;
        n -= (unsigned long)chunk;
    }
    return fflush(f) == 0 ? 0 : -1;
}

static int write_binary(FILE *f, unsigned long n)
{
    unsigned char buf[FIXTURE_CHUNK];
    unsigned long i;
    for (i = 0; i < sizeof(buf); i++)
        buf[i] = (unsigned char)(i & 0xFFu);
    while (n > 0) {
        size_t chunk = n > sizeof(buf) ? sizeof(buf) : (size_t)n;
        if (fwrite(buf, 1, chunk, f) != chunk)
            return -1;
        n -= (unsigned long)chunk;
    }
    return fflush(f) == 0 ? 0 : -1;
}

/* stdout 'A' + stderr 'B' selang-seling 4 KiB: dua pipe penuh bersamaan. */
static int write_both(unsigned long n)
{
    unsigned char a[4096], b[4096];
    memset(a, 'A', sizeof(a));
    memset(b, 'B', sizeof(b));
    while (n > 0) {
        size_t chunk = n > sizeof(a) ? sizeof(a) : (size_t)n;
        if (fwrite(a, 1, chunk, stdout) != chunk)
            return -1;
        if (fwrite(b, 1, chunk, stderr) != chunk)
            return -1;
        n -= (unsigned long)chunk;
    }
    fflush(stdout);
    fflush(stderr);
    return 0;
}

/* Baca SEMUA stdin sampai EOF; kembalikan jumlah byte. */
static unsigned long drain_stdin(void)
{
    unsigned char buf[FIXTURE_CHUNK];
    unsigned long total = 0;
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), stdin)) > 0)
        total += (unsigned long)r;
    return total;
}

/* Baca paling banyak `want` byte stdin (atau sampai EOF); hasil dibuang. */
static void read_upto_bytes(unsigned long want)
{
    unsigned char buf[8192];
    while (want > 0) {
        size_t chunk = want > sizeof(buf) ? sizeof(buf) : (size_t)want;
        size_t r = fread(buf, 1, chunk, stdin);
        if (r == 0)
            break;   /* EOF */
        want -= (unsigned long)r;
    }
}

/* Mode --matrix: kendali penuh ukuran stdin/stdout/stderr + urutan I/O
 * untuk deadlock matrix (PR-006, P1-T03).
 *   argv[2]=stdinN argv[3]=stdoutN argv[4]=stderrN argv[5]=order
 * order:
 *   read-first  : baca stdinN byte (atau EOF), tulis stdoutN 'A', stderrN 'B'
 *   write-first : tulis stdoutN 'A', stderrN 'B', lalu baca stdinN byte
 *   interleave  : loop 4 KiB: baca chunk stdin, tulis chunk stdout 'A',
 *                 tulis chunk stderr 'B' (dua pipe penuh bersamaan)
 * Tidak mencetak apa pun selain payload (byte count eksak).
 * Exit: 0 sukses, 1 I/O gagal, 2 usage. */
static int mode_matrix(int argc, char **argv)
{
    unsigned long sin, sout, serr;
    const char *order;
    unsigned char buf[4096];

    if (argc < 6)
        return 2;
    if (parse_n(argv[2], &sin) != 0 || parse_n(argv[3], &sout) != 0 ||
        parse_n(argv[4], &serr) != 0)
        return 2;
    order = argv[5];

    if (strcmp(order, "read-first") == 0) {
        read_upto_bytes(sin);
        if (write_n(stdout, 'A', sout) != 0)
            return 1;
        if (write_n(stderr, 'B', serr) != 0)
            return 1;
        return 0;
    }

    if (strcmp(order, "write-first") == 0) {
        if (write_n(stdout, 'A', sout) != 0)
            return 1;
        if (write_n(stderr, 'B', serr) != 0)
            return 1;
        read_upto_bytes(sin);
        return 0;
    }

    if (strcmp(order, "interleave") == 0) {
        while (sin > 0 || sout > 0 || serr > 0) {
            if (sin > 0) {
                size_t chunk = sin > sizeof(buf) ? sizeof(buf) : (size_t)sin;
                size_t r = fread(buf, 1, chunk, stdin);
                if (r == 0)
                    sin = 0;   /* EOF dini */
                else
                    sin -= (unsigned long)r;
            }
            if (sout > 0) {
                size_t chunk = sout > sizeof(buf) ? sizeof(buf) : (size_t)sout;
                if (write_n(stdout, 'A', (unsigned long)chunk) != 0)
                    return 1;
                sout -= (unsigned long)chunk;
            }
            if (serr > 0) {
                size_t chunk = serr > sizeof(buf) ? sizeof(buf) : (size_t)serr;
                if (write_n(stderr, 'B', (unsigned long)chunk) != 0)
                    return 1;
                serr -= (unsigned long)chunk;
            }
        }
        return 0;
    }

    return 2;   /* order tak dikenal */
}

#ifdef _WIN32
/* Spawn Windows dengan flags eksplisit + bInheritHandles=FALSE (grandchild
 * TIDAK mewarisi handle pipe myc — hygiene handle, PR-007/P1-T04). Command
 * line dibangun dengan aturan CommandLineToArgvW. CREATE_NO_WINDOW untuk
 * semua mode (console/control behavior: tidak memunculkan jendela console
 * dari child test). Kembali 1 sukses, 0 gagal. */
static int win_spawn(const char *self, char *const argv[], DWORD flags,
                     PROCESS_INFORMATION *pi_out)
{
    char cmd[4096];
    size_t used = 0;
    int i;
    STARTUPINFOA si;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(pi_out, 0, sizeof(*pi_out));

    for (i = 0; argv[i] != NULL && i < 32; i++) {
        const char *a = argv[i];
        size_t len = strlen(a);
        size_t j;
        if (used + len + 4 > sizeof(cmd))
            return 0;
        if (i > 0)
            cmd[used++] = ' ';
        cmd[used++] = '"';
        for (j = 0; j < len; j++) {
            if (a[j] == '"') {
                if (used + 2 > sizeof(cmd))
                    return 0;
                cmd[used++] = '\\';
            }
            cmd[used++] = a[j];
        }
        cmd[used++] = '"';
    }
    cmd[used] = '\0';

    return CreateProcessA(self, cmd, NULL, NULL, FALSE, flags, NULL, NULL,
                          &si, pi_out) ? 1 : 0;
}
#endif

/* Spawn + tunggu child. Mencetak spawned_child=<pid> SEBELUM menunggu
 * (agar baris pid selalu tertangkap walaupun parent dibunuh saat menunggu).
 * Kembali: status exit child (0..255), 128+sinyal (POSIX), atau -1 = gagal
 * spawn. child_argv[0] = self (diabaikan, dipakai self). */
static int spawn_and_wait(const char *self, char *const argv[], int *pid_out)
{
#ifdef _WIN32
    PROCESS_INFORMATION pi;
    DWORD code = 0;

    if (!win_spawn(self, argv, CREATE_NO_WINDOW, &pi))
        return -1;
    *pid_out = (int)pi.dwProcessId;
    printf("spawned_child=%d\n", *pid_out);
    fflush(stdout);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
#else
    pid_t pid = fork();
    int st = 0;
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execv(self, argv);
        _exit(127);
    }
    *pid_out = (int)pid;
    printf("spawned_child=%d\n", *pid_out);
    fflush(stdout);
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    if (WIFSIGNALED(st))
        return 128 + WTERMSIG(st);
    return -1;
#endif
}

/* Mode --spawn-child: child argv = self + args lanjutan (default sleep 60s). */
static int mode_spawn(const char *self, int argc, char **argv, int idx)
{
    char *child_argv[10];
    int n = 0, i, pid = 0, rc;

    child_argv[n++] = (char *)self;
    if (argc - idx <= 1) {
        child_argv[n++] = (char *)"--sleep";
        child_argv[n++] = (char *)"60000";
    } else {
        for (i = idx + 1; i < argc && n < 8; i++)
            child_argv[n++] = argv[i];
    }
    child_argv[n] = NULL;

    rc = spawn_and_wait(self, child_argv, &pid);
    if (rc < 0) {
        fprintf(stderr, "proc_fixture: spawn child gagal\n");
        return 2;
    }
    return rc;
}

/* Mode --spawn-breakaway: coba spawn child dengan CREATE_BREAKAWAY_FROM_JOB
 * (uji PR-007/P1-T04). Di dalam job myc (tanpa JOB_OBJECT_LIMIT_BREAKAWAY_OK)
 * CreateProcess HARUS gagal -> breakaway_status=0 dan fixture hang agar
 * myc timeout (uji cleanup pohon tanpa grandchild). Bila SUKSES
 * (breakaway_status=1) = lubang job myc / job assignment gagal: grandchild
 * lepas dari job dan akan jadi orphan saat timeout -> konsumen (proc_tree_kill
 * T2) menandai FAIL. POSIX: tidak ada job object -> breakaway_status=2 (N/A)
 * dan berperilaku seperti --spawn-child. */
static int mode_spawn_breakaway(const char *self, int argc, char **argv, int idx)
{
#ifdef _WIN32
    char *child_argv[10];
    int n = 0, i;
    PROCESS_INFORMATION pi;
    DWORD code = 0;

    child_argv[n++] = (char *)self;
    if (argc - idx <= 1) {
        child_argv[n++] = (char *)"--sleep";
        child_argv[n++] = (char *)"60000";
    } else {
        for (i = idx + 1; i < argc && n < 8; i++)
            child_argv[n++] = argv[i];
    }
    child_argv[n] = NULL;

    if (!win_spawn(self, child_argv,
                   CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB, &pi)) {
        /* Breakaway ditolak job (diharapkan). Hang agar myc timeout. */
        printf("breakaway_status=0\n");
        fflush(stdout);
        for (;;)
            fixture_sleep(FIXTURE_MAX_MS);
    }
    printf("breakaway_status=1\n");
    printf("spawned_child=%d\n", (int)pi.dwProcessId);
    fflush(stdout);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
#else
    printf("breakaway_status=2\n");
    fflush(stdout);
    return mode_spawn(self, argc, argv, idx);
#endif
}

/* Mode --spawn-jobchild: spawn grandchild lalu letakkan di Job Object baru
 * milik fixture (uji nested job, PR-007/P1-T04). Grandchild ada di DUA job
 * (job myc + job fixture); TerminateJobObject(milik myc) tetap harus
 * membunuhnya pada timeout. jobchild_status: 0=OK, 1=gagal setup,
 * 2=N/A (POSIX). */
static int mode_spawn_jobchild(const char *self, int argc, char **argv, int idx)
{
#ifdef _WIN32
    char *child_argv[10];
    int n = 0, i;
    HANDLE job = CreateJobObjectA(NULL, NULL);
    PROCESS_INFORMATION pi;
    DWORD code = 0;

    child_argv[n++] = (char *)self;
    if (argc - idx <= 1) {
        child_argv[n++] = (char *)"--sleep";
        child_argv[n++] = (char *)"60000";
    } else {
        for (i = idx + 1; i < argc && n < 8; i++)
            child_argv[n++] = argv[i];
    }
    child_argv[n] = NULL;

    if (!job) {
            printf("jobchild_status=1\n");
            fflush(stdout);
            return 1;
        }
        if (!win_spawn(self, child_argv, CREATE_NO_WINDOW, &pi)) {
            CloseHandle(job);
            printf("jobchild_status=1\n");
            fflush(stdout);
            return 1;
        }
    if (!AssignProcessToJobObject(job, pi.hProcess)) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(job);
        printf("jobchild_status=1\n");
        fflush(stdout);
        return 1;
    }
    printf("jobchild_status=0\n");
    printf("spawned_child=%d\n", (int)pi.dwProcessId);
    fflush(stdout);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(job);
    return (int)code;
#else
    printf("jobchild_status=2\n");
    fflush(stdout);
    return mode_spawn(self, argc, argv, idx);
#endif
}

/* Mode --spawn-detach: spawn child lalu LANGSUNG exit 0 (tanpa menunggu) —
 * uji inherited handles (PR-007/P1-T04). Grandchild yang hidup saat fixture
 * exit TIDAK boleh memegang pipe myc (Windows: bInheritHandles=FALSE;
 * POSIX: FD_CLOEXEC pada 0/1/2 sebelum exec), sehingga myc mendapat EOF dan
 * kembali cepat tanpa menunggu grandchild. Konsumen: proc_tree_kill T4. */
static int mode_spawn_detach(const char *self, int argc, char **argv, int idx)
{
    char *child_argv[10];
    int n = 0, i, pid = 0;

    child_argv[n++] = (char *)self;
    if (argc - idx <= 1) {
        child_argv[n++] = (char *)"--sleep";
        child_argv[n++] = (char *)"5000";
    } else {
        for (i = idx + 1; i < argc && n < 8; i++)
            child_argv[n++] = argv[i];
    }
    child_argv[n] = NULL;

#ifdef _WIN32
    {
        PROCESS_INFORMATION pi;
        if (!win_spawn(self, child_argv, CREATE_NO_WINDOW, &pi)) {
            fprintf(stderr, "proc_fixture: spawn detach gagal\n");
            return 2;
        }
        pid = (int)pi.dwProcessId;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
#else
    pid = fork();
    if (pid < 0)
        return 2;
    if (pid == 0) {
        /* Hygiene handle: grandchild detach TIDAK boleh memegang pipe myc
         * setelah exec (bila tidak, myc tak mendapat EOF sampai grandchild
         * keluar). FD_CLOEXEC pada stdin/stdout/stderr. */
        int fds[3] = { 0, 1, 2 };
        int k;
        for (k = 0; k < 3; k++) {
            int fl = fcntl(fds[k], F_GETFD, 0);
            if (fl >= 0)
                fcntl(fds[k], F_SETFD, fl | FD_CLOEXEC);
        }
        execv(self, child_argv);
        _exit(127);
    }
#endif
    printf("spawned_child=%d\n", pid);
    fflush(stdout);
    return 0;   /* TIDAK menunggu: fixture langsung exit */
}

/* Mode --spawn-grandchild: child argv = self + args lanjutan
 * (default: --spawn-child, yang kemudian spawn cucunya sendiri). */
static int mode_spawn_grand(const char *self, int argc, char **argv, int idx)
{
    char *child_argv[10];
    int n = 0, i, pid = 0, rc;

    child_argv[n++] = (char *)self;
    if (argc - idx <= 1) {
        child_argv[n++] = (char *)"--spawn-child";
    } else {
        for (i = idx + 1; i < argc && n < 8; i++)
            child_argv[n++] = argv[i];
    }
    child_argv[n] = NULL;

    rc = spawn_and_wait(self, child_argv, &pid);
    if (rc < 0) {
        fprintf(stderr, "proc_fixture: spawn grandchild gagal\n");
        return 2;
    }
    return rc;
}

static void usage(FILE *f)
{
    fprintf(f,
            "proc_fixture -- hostile child fixture (PR-005, P1-T02)\n"
            "  --exit N | --sleep MS | --self-pid\n"
            "  --stdout N | --stderr N | --both N\n"
            "  --read-stdin N | --never-read-stdin\n"
            "  --close-stdout | --close-stderr\n"
            "  --spawn-child [args..] | --spawn-grandchild [args..]\n"
            "  --spawn-breakaway [args..] | --spawn-jobchild [args..] |\n"
            "  --spawn-detach [args..]\n"
            "  --crash | --hang-after-output\n"
            "  --output-after-stdin | --stdin-after-output\n"
            "  --unicode-output | --binary-output [N]\n"
            "  --matrix S O E read-first|write-first|interleave\n"
            "  --help\n");
}

int main(int argc, char **argv)
{
    unsigned long n;
    unsigned ms;

#ifdef _WIN32
    {
        /* Mode biner eksak untuk byte count (CRLF translation / Ctrl-Z
         * EOF akan merusak deadlock matrix di Windows). */
        _setmode(_fileno(stdin), _O_BINARY);
        _setmode(_fileno(stdout), _O_BINARY);
        _setmode(_fileno(stderr), _O_BINARY);
    }
#endif

    if (argc < 2) {
        usage(stderr);
        return 2;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        usage(stdout);
        return 0;
    }

    if (strcmp(argv[1], "--exit") == 0) {
        int code = argc > 2 ? parse_exit(argv[2]) : -1;
        if (code < 0)
            return 2;
        return code;
    }

    if (strcmp(argv[1], "--sleep") == 0) {
        if (argc < 3 || parse_ms(argv[2], &ms) != 0)
            return 2;
        fixture_sleep(ms);
        return 0;
    }

    if (strcmp(argv[1], "--stdout") == 0) {
        if (argc < 3 || parse_n(argv[2], &n) != 0)
            return 2;
        return write_n(stdout, 'A', n) == 0 ? 0 : 1;
    }

    if (strcmp(argv[1], "--stderr") == 0) {
        if (argc < 3 || parse_n(argv[2], &n) != 0)
            return 2;
        return write_n(stderr, 'B', n) == 0 ? 0 : 1;
    }

    if (strcmp(argv[1], "--both") == 0) {
        if (argc < 3 || parse_n(argv[2], &n) != 0)
            return 2;
        return write_both(n) == 0 ? 0 : 1;
    }

    if (strcmp(argv[1], "--read-stdin") == 0) {
        unsigned long want, got = 0;
        unsigned char buf[8192];
        if (argc < 3 || parse_n(argv[2], &want) != 0)
            return 2;
        while (want > 0) {
            size_t chunk = want > sizeof(buf) ? sizeof(buf) : (size_t)want;
            size_t r = fread(buf, 1, chunk, stdin);
            got += (unsigned long)r;
            if (r == 0)
                break;   /* EOF */
            want -= (unsigned long)r;
        }
        printf("stdin_read=%lu\n", got);
        fflush(stdout);
        return 0;
    }

    if (strcmp(argv[1], "--never-read-stdin") == 0) {
        fputs("never_read_stdin\n", stdout);
        fflush(stdout);
        return 0;
    }

    if (strcmp(argv[1], "--close-stdout") == 0) {
        close_stdout_os();
        return 0;
    }

    if (strcmp(argv[1], "--close-stderr") == 0) {
        close_stderr_os();
        return 0;
    }

    if (strcmp(argv[1], "--spawn-child") == 0)
        return mode_spawn(argv[0], argc, argv, 1);

    if (strcmp(argv[1], "--spawn-grandchild") == 0)
        return mode_spawn_grand(argv[0], argc, argv, 1);

    if (strcmp(argv[1], "--spawn-breakaway") == 0)
        return mode_spawn_breakaway(argv[0], argc, argv, 1);

    if (strcmp(argv[1], "--spawn-jobchild") == 0)
        return mode_spawn_jobchild(argv[0], argc, argv, 1);

    if (strcmp(argv[1], "--spawn-detach") == 0)
        return mode_spawn_detach(argv[0], argc, argv, 1);

    if (strcmp(argv[1], "--crash") == 0) {
        volatile unsigned char *p = (volatile unsigned char *)0;
        fputs("crashing\n", stderr);
        fflush(stderr);
        *p = 1;   /* SIGSEGV / access violation */
        abort();  /* fallback bila platform aneh */
    }

    if (strcmp(argv[1], "--hang-after-output") == 0) {
        fputs("hang_after_output\n", stdout);
        fflush(stdout);
        for (;;)
            fixture_sleep(FIXTURE_MAX_MS);
    }

    if (strcmp(argv[1], "--output-after-stdin") == 0) {
        unsigned long total = drain_stdin();
        printf("output_after_stdin=%lu\n", total);
        fflush(stdout);
        return 0;
    }

    if (strcmp(argv[1], "--stdin-after-output") == 0) {
        unsigned long total;
        fputs("stdin_after_output\n", stdout);
        fflush(stdout);
        total = drain_stdin();
        printf("drained=%lu\n", total);
        fflush(stdout);
        return 0;
    }

    if (strcmp(argv[1], "--unicode-output") == 0) {
        fputs("unicode: h\u00e9llo w\u00f6rld \u2014 \u00fc\u00f1\u00ee\u00e7\u00f8\u00f0\u00e9 \u2713 \u4e2d\u6587\n",
              stdout);
        fputs("unicode: n\u00e4chste Zeile \u00e9\u00e8\u00ea \u2603\n", stdout);
        fflush(stdout);
        return 0;
    }

    if (strcmp(argv[1], "--binary-output") == 0) {
        if (argc > 2) {
            if (parse_n(argv[2], &n) != 0)
                return 2;
        } else {
            n = 4096;
        }
        return write_binary(stdout, n) == 0 ? 0 : 1;
    }

    if (strcmp(argv[1], "--self-pid") == 0) {
        printf("pid=%ld\n", fixture_pid());
        fflush(stdout);
        return 0;
    }

    if (strcmp(argv[1], "--matrix") == 0)
        return mode_matrix(argc, argv);

    fprintf(stderr, "proc_fixture: mode tak dikenal: %s (coba --help)\n",
            argv[1]);
    return 2;
}
