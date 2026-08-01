/*
 * proc.c -- Peluncur proses argv eksak untuk myc.
 *
 * Windows: CreateProcessA + command line yang dikonstruksi dengan aturan
 * CommandLineToArgvW, + Job Object untuk memastikan timeout membunuh
 * seluruh pohon proses. stdout/stderr di-drain dari thread terpisah
 * untuk menghindari deadlock. stdin ditulis sebagai data byte mentah.
 *
 * POSIX: fork + execvp, pembatasan sementara hanya via alarm (timeout
 * menyeluruh); drain serupa. Implementasi POSIX disederhanakan.
 */
#include "proc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

/* ------------------------------------------------------------------ */
/* Pencarian executable                                                */
/* ------------------------------------------------------------------ */

static int has_sep(const char *p)
{
    return strchr(p, '/') != NULL || strchr(p, '\\') != NULL;
}

#ifdef _WIN32
static char *path_join(const char *dir, const char *name, const char *ext)
{
    size_t dl = dir ? strlen(dir) : 0;
    size_t nl = strlen(name);
    size_t el = ext ? strlen(ext) : 0;
    size_t need = dl + 1 + nl + el + 1;
    char   *out = (char *)malloc(need);
    if (!out)
        return NULL;
    if (dir && dl) {
        memcpy(out, dir, dl);
        out[dl] = '\\';
        memcpy(out + dl + 1, name, nl);
        memcpy(out + dl + 1 + nl, ext, el);
        out[dl + 1 + nl + el] = '\0';
    } else {
        memcpy(out, name, nl);
        memcpy(out + nl, ext, el);
        out[nl + el] = '\0';
    }
    return out;
}
#endif

char *myc_find_executable(const char *program)
{
    if (!program || !*program)
        return NULL;

#ifdef _WIN32
    static const char *exts[] = { ".exe", "" };
    char *path_env;
    char *cand;
    DWORD attrs;
    int i;

    /* Bila ada separator, pakai langsung (tanpa scan PATH). */
    if (has_sep(program)) {
        cand = _strdup(program);
        if (!cand)
            return NULL;
        attrs = GetFileAttributesA(cand);
        if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY))
            return cand;
        free(cand);
        return NULL;
    }

    /* Cari di PATH. */
    path_env = getenv("PATH");
    if (!path_env)
        return NULL;

    {
        char *dup = _strdup(path_env);
        char *save = NULL;
        char *tok = strtok_s(dup, ";", &save);
        while (tok) {
            for (i = 0; i < 2; i++) {
                cand = path_join(tok, program, exts[i]);
                if (!cand) {
                    free(dup);
                    return NULL;
                }
                attrs = GetFileAttributesA(cand);
                if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                    free(dup);
                    return cand;
                }
                free(cand);
            }
            tok = strtok_s(NULL, ";", &save);
        }
        free(dup);
    }
    return NULL;
#else
    /* POSIX: gunakan execvp yang mencari PATH sendiri. */
    if (has_sep(program)) {
        if (access(program, X_OK) == 0)
            return _strdup(program);
        return NULL;
    }
    /* Delegasikan pencarian PATH ke execvp; tandai butuh PATH search. */
    return _strdup(program);
#endif
}

/* ------------------------------------------------------------------ */
/* Konstruksi command line Windows (aturan CommandLineToArgvW)          */
/* ------------------------------------------------------------------ */

#ifdef _WIN32
static void append_arg(char **buf, size_t *cap, size_t *len, const char *arg)
{
    size_t n = strlen(arg);
    size_t need;
    int    has_space = 0;
    const char *p;
    size_t i;

    /* Cek apakah perlu dikutip. */
    if (*arg == '\0')
        has_space = 1;
    for (p = arg; *p; p++) {
        if (*p == ' ' || *p == '\t') {
            has_space = 1;
            break;
        }
    }

    /* Estimasi ruang: tanda kutip + isi + penutup. */
    need = *len + 2 + n + 2 + 1;
    if (need > *cap) {
        size_t ncap = *cap ? *cap * 2 : 64;
        while (ncap < need)
            ncap *= 2;
        *buf = (char *)realloc(*buf, ncap);
        if (!*buf) {
            *cap = 0;
            return;
        }
        *cap = ncap;
    }

    if (!has_space) {
        memcpy(*buf + *len, arg, n + 1);
        *len += n;
        return;
    }

    (*buf)[(*len)++] = '"';
    for (i = 0; i < n; i++) {
        size_t bslashes = 0;
        while (i < n && arg[i] == '\\') {
            bslashes++;
            i++;
        }
        if (i == n) {
            /* Trailing backslashes: gandakan sebelum kutip penutup. */
            for (size_t j = 0; j < bslashes * 2; j++)
                (*buf)[(*len)++] = '\\';
            break;
        } else if (arg[i] == '"') {
            for (size_t j = 0; j < bslashes * 2 + 1; j++)
                (*buf)[(*len)++] = '\\';
            (*buf)[(*len)++] = '"';
        } else {
            for (size_t j = 0; j < bslashes; j++)
                (*buf)[(*len)++] = '\\';
            (*buf)[(*len)++] = arg[i];
        }
    }
    (*buf)[(*len)++] = '"';
    (*buf)[*len] = '\0';
}

static char *build_cmdline(const char *const *argv)
{
    char  *buf = NULL;
    size_t cap = 0, len = 0;
    int    i;

    if (!argv || !argv[0])
        return NULL;

    for (i = 0; argv[i]; i++) {
        append_arg(&buf, &cap, &len, argv[i]);
        if (!buf)
            return NULL;
        if (argv[i + 1]) {
            /* sisip spasi pemisah */
            if (len + 2 > cap) {
                size_t ncap = cap ? cap * 2 : 64;
                buf = (char *)realloc(buf, ncap);
                if (!buf) {
                    cap = 0;
                    return NULL;
                }
                cap = ncap;
            }
            buf[len++] = ' ';
            buf[len] = '\0';
        }
    }
    return buf;
}
#endif /* _WIN32 */

/* ------------------------------------------------------------------ */
/* Struktur drain thread                                                */
/* ------------------------------------------------------------------ */

typedef struct {
#ifdef _WIN32
    HANDLE  handle;
#else
    int     fd;
#endif
    char   *data;
    size_t  cap;
    size_t  len;        /* byte valid */
    size_t  total;      /* total byte dibaca (termasuk yang dibuang) */
    int     truncated;
    size_t  max;
    int     finished;
} drain_buf;

static int drain_init(drain_buf *d, size_t max)
{
    d->data = (char *)malloc(max ? max + 1 : 1);
    if (!d->data)
        return 0;
    d->cap = max;
    d->len = 0;
    d->total = 0;
    d->truncated = 0;
    d->max = max;
    d->finished = 0;
    return 1;
}

#ifdef _WIN32
static unsigned __stdcall drain_thread(void *arg)
{
    drain_buf *d = (drain_buf *)arg;
    char       tmp[8192];
    DWORD      rd;
    while (1) {
        if (!ReadFile(d->handle, tmp, sizeof(tmp), &rd, NULL)) {
            if (GetLastError() == ERROR_BROKEN_PIPE)
                break;
            /* Bisa terjadi saat handle ditutup oleh pembersihan; hentikan. */
            break;
        }
        if (rd == 0)
            break;
        d->total += rd;
        if (d->len < d->max) {
            size_t space = d->max - d->len;
            size_t take = rd < space ? rd : space;
            memcpy(d->data + d->len, tmp, take);
            d->len += take;
            if (take < rd)
                d->truncated = 1;
        } else {
            d->truncated = 1;
        }
    }
    if (d->data)
        d->data[d->len] = '\0';
    d->finished = 1;
    return 0;
}
#else
static void *drain_thread(void *arg)
{
    drain_buf *d = (drain_buf *)arg;
    char       tmp[8192];
    ssize_t    rd;
    while (1) {
        rd = read(d->fd, tmp, sizeof(tmp));
        if (rd <= 0)
            break;
        d->total += (size_t)rd;
        if (d->len < d->max) {
            size_t space = d->max - d->len;
            size_t take = (size_t)rd < space ? (size_t)rd : space;
            memcpy(d->data + d->len, tmp, take);
            d->len += take;
            if (take < (size_t)rd)
                d->truncated = 1;
        } else {
            d->truncated = 1;
        }
    }
    if (d->data)
        d->data[d->len] = '\0';
    d->finished = 1;
    return NULL;
}
#endif

void myc_proc_result_free(myc_proc_result *res)
{
    if (!res)
        return;
    free(res->stdout_data);
    free(res->stderr_data);
    res->stdout_data = NULL;
    res->stderr_data = NULL;
}

/* ------------------------------------------------------------------ */
/* Pelaksanaan utama                                                    */
/* ------------------------------------------------------------------ */

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

#ifdef _WIN32

static int proc_run_win(const myc_proc_request *req, myc_proc_result *res)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE  stdin_rd = NULL, stdin_wr = NULL;
    HANDLE  stdout_rd = NULL, stdout_wr = NULL;
    HANDLE  stderr_rd = NULL, stderr_wr = NULL;
    HANDLE  job = NULL;
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    char    *cmdline = NULL;
    char    *cmdline_copy = NULL;
    drain_buf out, err;
    unsigned long long t0;
    BOOL    started;
    int     done = 0;
    int     timed_out = 0;
    int     proc_alive = 1;
    HANDLE  drain_threads[2] = { NULL, NULL };
    size_t  max_out = req->max_output_bytes ? req->max_output_bytes : MYC_MAX_OUTPUT_BYTES;
    DWORD   timeout_ms = (DWORD)(req->timeout_ms > 0 ? req->timeout_ms : MYC_DEFAULT_TIMEOUT_MS);

    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    /* stdin pipe: child membaca stdin_rd */
    if (!CreatePipe(&stdin_rd, &stdin_wr, &sa, 0)) { res->err = MYC_ERR_INTERNAL; return 0; }
    SetHandleInformation(stdin_wr, HANDLE_FLAG_INHERIT, 0);
    /* stdout pipe: child menulis stdout_wr */
    if (!CreatePipe(&stdout_rd, &stdout_wr, &sa, 0)) { res->err = MYC_ERR_INTERNAL; goto cleanup; }
    SetHandleInformation(stdout_rd, HANDLE_FLAG_INHERIT, 0);
    if (!CreatePipe(&stderr_rd, &stderr_wr, &sa, 0)) { res->err = MYC_ERR_INTERNAL; goto cleanup; }
    SetHandleInformation(stderr_rd, HANDLE_FLAG_INHERIT, 0);

    /* Job Object: pastikan timeout membunuh seluruh pohon proses. */
    job = CreateJobObjectA(NULL, NULL);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
        memset(&jeli, 0, sizeof(jeli));
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    }

    memset(&pi, 0, sizeof(pi));
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = stdin_rd;
    si.hStdOutput = stdout_wr;
    si.hStdError = stderr_wr;

    cmdline = build_cmdline(req->argv);
    if (!cmdline) { res->err = MYC_ERR_INTERNAL; goto cleanup; }
    /* CreateProcessA dapat mengubah buffer; salin. */
    cmdline_copy = _strdup(cmdline);
    if (!cmdline_copy) { res->err = MYC_ERR_INTERNAL; goto cleanup; }

    t0 = now_ms();
    started = CreateProcessA(
        req->argv[0],
        cmdline_copy,
        NULL, NULL, TRUE,             /* bInheritHandles = TRUE */
        CREATE_NO_WINDOW,
        NULL,
        req->cwd,
        &si, &pi);

    if (!started) {
        res->err = MYC_ERR_EXECUTE_FAILED;
        res->ok = 0;
        goto cleanup;
    }

    /* Assign proses ke Job Object (jika ada) untuk cleanup pohon. */
    if (job)
        AssignProcessToJobObject(job, pi.hProcess);

    /* Tutup sisi yang diwarisi oleh proses induk. */
    CloseHandle(stdin_rd); stdin_rd = NULL;
    CloseHandle(stdout_wr); stdout_wr = NULL;
    CloseHandle(stderr_wr); stderr_wr = NULL;

    /* Mulai thread drain. */
    if (!drain_init(&out, max_out) || !drain_init(&err, max_out)) {
        free(out.data);
        free(err.data);
        res->err = MYC_ERR_INTERNAL;
        res->ok = 0;
        goto cleanup_pi;
    }
    out.handle = stdout_rd;
    err.handle = stderr_rd;
    {
        HANDLE th[2];
        th[0] = (HANDLE)_beginthreadex(NULL, 0, drain_thread, &out, 0, NULL);
        th[1] = (HANDLE)_beginthreadex(NULL, 0, drain_thread, &err, 0, NULL);
        /* simpan untuk ditunggu nanti */
        drain_threads[0] = th[0];
        drain_threads[1] = th[1];
    }

    /* Tulis stdin. */
    if (req->stdin_len > 0) {
        DWORD total_written = 0;
        DWORD wr;
        while (total_written < (DWORD)req->stdin_len) {
            DWORD chunk = (DWORD)req->stdin_len - total_written;
            if (chunk > 65536)
                chunk = 65536;
            if (!WriteFile(stdin_wr, (const char *)req->stdin_data + total_written, chunk, &wr, NULL)) {
                if (GetLastError() == ERROR_BROKEN_PIPE)
                    break; /* child keluar lebih dulu */
                res->err = MYC_ERR_EXECUTE_FAILED;
                break;
            }
            total_written += wr;
        }
    }
    CloseHandle(stdin_wr); stdin_wr = NULL;

    /* Tunggu proses, dengan batas waktu. */
    while (1) {
        DWORD wait = WaitForSingleObject(pi.hProcess, 50);
        unsigned long long elapsed = now_ms() - t0;
        if (wait == WAIT_OBJECT_0) {
            done = 1;
            break;
        }
        if (wait == WAIT_TIMEOUT) {
            if (timeout_ms && elapsed >= timeout_ms) {
                timed_out = 1;
                break;
            }
        } else {
            res->err = MYC_ERR_INTERNAL;
            break;
        }
    }

    if (timed_out) {
        /* Bunuh seluruh pohon proses. */
        if (job) {
            TerminateJobObject(job, 1);
        } else {
            TerminateProcess(pi.hProcess, 1);
        }
        proc_alive = 0;
        WaitForSingleObject(pi.hProcess, 5000);
        res->timed_out = 1;
        res->err = MYC_ERR_TIMEOUT;
        res->ok = 0;
    } else {
        DWORD code = 1;
        GetExitCodeProcess(pi.hProcess, &code);
        res->exit_code = (int)code;
        res->ok = 1;
        res->timed_out = 0;
        res->err = MYC_ERR_NONE;
    }

    res->duration_ms = now_ms() - t0;
    (void)proc_alive;

    /* Tunggu thread drain selesai (hasilnya sudah lengkap). */
    if (drain_threads[0]) {
        WaitForSingleObject(drain_threads[0], 2000);
        CloseHandle(drain_threads[0]);
    }
    if (drain_threads[1]) {
        WaitForSingleObject(drain_threads[1], 2000);
        CloseHandle(drain_threads[1]);
    }

    res->stdout_data = out.data; out.data = NULL;
    res->stderr_data = err.data; err.data = NULL;
    res->stdout_total = out.total;
    res->stderr_total = err.total;
    res->stdout_shown = out.len;
    res->stderr_shown = err.len;
    res->truncated = out.truncated || err.truncated;
    if (res->stdout_data)
        res->stdout_data[out.len] = '\0';
    if (res->stderr_data)
        res->stderr_data[err.len] = '\0';
    if (!res->stdout_data)
        res->stdout_data = (char *)malloc(1);
    if (!res->stderr_data)
        res->stderr_data = (char *)malloc(1);
    if (res->stdout_data && !out.len)
        res->stdout_data[0] = '\0';
    if (res->stderr_data && !err.len)
        res->stderr_data[0] = '\0';

cleanup_pi:
    if (stdin_rd) CloseHandle(stdin_rd);
    if (stdout_rd) CloseHandle(stdout_rd);
    if (stderr_rd) CloseHandle(stderr_rd);
    if (stdin_wr) CloseHandle(stdin_wr);
    if (stdout_wr) CloseHandle(stdout_wr);
    if (stderr_wr) CloseHandle(stderr_wr);
    if (job) {
        CloseHandle(job);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

cleanup:
    free(cmdline);
    free(cmdline_copy);
    if (done) {
        /* hasil sudah disalin */
    }
    return res->ok ? 1 : (res->err != MYC_ERR_NONE ? 0 : 1);
}

#endif /* _WIN32 */

#ifndef _WIN32

static int proc_run_posix(const myc_proc_request *req, myc_proc_result *res)
{
    int     in_pipe[2], out_pipe[2], err_pipe[2];
    pid_t   pid;
    drain_buf out, err;
    size_t  max_out = req->max_output_bytes ? req->max_output_bytes : MYC_MAX_OUTPUT_BYTES;
    unsigned long long t0;
    int     status;
    int     timed_out = 0;

    (void)max_out;
    if (pipe(in_pipe) < 0 || pipe(out_pipe) < 0 || pipe(err_pipe) < 0)
        return 0;

    t0 = now_ms();
    pid = fork();
    if (pid < 0)
        return 0;

    if (pid == 0) {
        /* Child. */
        dup2(in_pipe[0], 0);
        dup2(out_pipe[1], 1);
        dup2(err_pipe[1], 2);
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        if (req->cwd) {
            if (chdir(req->cwd) != 0)
                _exit(127);
        }
        execvp(req->argv[0], (char *const *)req->argv);
        _exit(127);
    }

    close(in_pipe[0]); close(out_pipe[1]); close(err_pipe[1]);

    /* tulis stdin */
    if (req->stdin_len > 0) {
        size_t off = 0;
        while (off < req->stdin_len) {
            ssize_t w = write(in_pipe[1], (const char *)req->stdin_data + off,
                              req->stdin_len - off);
            if (w <= 0)
                break;
            off += (size_t)w;
        }
    }
    close(in_pipe[1]);

    if (!drain_init(&out, max_out) || !drain_init(&err, max_out))
        return 0;
    out.fd = out_pipe[0];
    err.fd = err_pipe[0];
    {
        pthread_t to, te;
        pthread_create(&to, NULL, drain_thread, &out);
        pthread_create(&te, NULL, drain_thread, &err);
        (void)to; (void)te;
    }

    /* tunggu dengan timeout */
    while (1) {
        unsigned long long elapsed = now_ms() - t0;
        int r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            break;
        }
        if (req->timeout_ms > 0 && elapsed >= (unsigned long long)req->timeout_ms) {
            timed_out = 1;
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            break;
        }
        struct timespec ts = {0, 10 * 1000000};
        nanosleep(&ts, NULL);
    }

    if (timed_out) {
        res->timed_out = 1;
        res->err = MYC_ERR_TIMEOUT;
        res->ok = 0;
    } else if (WIFEXITED(status)) {
        res->exit_code = WEXITSTATUS(status);
        res->ok = 1;
        res->err = MYC_ERR_NONE;
    } else {
        res->exit_code = 1;
        res->ok = 0;
        res->err = MYC_ERR_EXECUTE_FAILED;
    }

    close(out_pipe[0]);
    close(err_pipe[0]);

    res->duration_ms = now_ms() - t0;
    res->stdout_data = out.data; out.data = NULL;
    res->stderr_data = err.data; err.data = NULL;
    res->stdout_total = out.total;
    res->stderr_total = err.total;
    res->stdout_shown = out.len;
    res->stderr_shown = err.len;
    res->truncated = out.truncated || err.truncated;
    return res->ok ? 1 : 0;
}

#endif /* !_WIN32 */

int myc_proc_run(const myc_proc_request *req, myc_proc_result *res)
{
    memset(res, 0, sizeof(*res));
    if (!req || !req->argv || !req->argv[0]) {
        res->err = MYC_ERR_INVALID_REQUEST;
        return 0;
    }
#ifdef _WIN32
    return proc_run_win(req, res);
#else
    return proc_run_posix(req, res);
#endif
}
