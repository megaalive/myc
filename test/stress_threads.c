/*
 * stress_threads.c -- Regression Fase 5 (MYC-AUDIT-008).
 *
 * Buktikan pemanggilan myc_run() paralel aman:
 *   1. Tidak ada data race dari static message ring (dihapus, diganti arena).
 *   2. Hasil deterministik: source_sha256 sama di semua iterasi thread yang
 *      sama (basi/race dari scratch state statis akan membuatnya berubah).
 *
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -DMYC_NO_MAIN -o stress_threads.exe
 *       stress_threads.c myc.c proc.c scanner.c policy.c compile.c report.c
 *       sha256.c lint.c run.c contract.c prove.c filc.c driver.c json.c gate.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <pthread.h>
#endif

#include "myc.h"

#define NTHREADS 8
#define NITER    200

typedef struct {
    int tid;
    int mismatch;
} worker_arg;

static void build_source(char *buf, size_t cap, int tid)
{
    snprintf(buf, cap, "static int myc_var_%d = %d;\n"
                       "int main(void){return myc_var_%d;}\n", tid, tid, tid);
}

static void worker_run(worker_arg *w)
{
    myc_request req;
    myc_result  res;
    char        buf[512];
    char       *sha_last = NULL;
    int         i;
    int         verdict_ok = 0;

    build_source(buf, sizeof(buf), w->tid);

    for (i = 0; i < NITER; i++) {
        myc_request_init(&req);
        req.source = buf;
        req.source_len = strlen(buf);
        req.run_lint = 1;
        myc_result_init(&res);
        myc_run(&req, &res);
        if (res.verdict == MC_OK || res.verdict == MC_VIOLATION ||
            res.verdict == MC_COMPILE_ERROR)
            verdict_ok++;
        if (res.source_sha256) {
            if (sha_last && strcmp(sha_last, res.source_sha256) != 0)
                w->mismatch = 1;
            free(sha_last);
            sha_last = strdup(res.source_sha256);
        }
        myc_result_free(&res);
    }
    free(sha_last);
    if (verdict_ok != NITER)
        w->mismatch = 1;
}

#ifdef _WIN32
static unsigned __stdcall thread_main(void *arg)
{
    worker_run((worker_arg *)arg);
    return 0;
}
#else
static void *thread_main(void *arg)
{
    worker_run((worker_arg *)arg);
    return NULL;
}
#endif

int main(void)
{
    worker_arg args[NTHREADS];
    int   i, fail = 0;

    for (i = 0; i < NTHREADS; i++) {
        args[i].tid = i;
        args[i].mismatch = 0;
    }

#ifdef _WIN32
    {
        HANDLE h[NTHREADS];
        for (i = 0; i < NTHREADS; i++)
            h[i] = (HANDLE)_beginthreadex(NULL, 0, thread_main, &args[i], 0, NULL);
        for (i = 0; i < NTHREADS; i++)
            if (h[i]) WaitForSingleObject(h[i], INFINITE);
        for (i = 0; i < NTHREADS; i++)
            if (h[i]) CloseHandle(h[i]);
    }
#else
    {
        pthread_t th[NTHREADS];
        for (i = 0; i < NTHREADS; i++)
            pthread_create(&th[i], NULL, thread_main, &args[i]);
        for (i = 0; i < NTHREADS; i++)
            pthread_join(th[i], NULL);
    }
#endif

    for (i = 0; i < NTHREADS; i++) {
        fprintf(stderr, "thread %d: %s\n", i,
                args[i].mismatch ? "MISMATCH (race/stale)" : "ok");
        if (args[i].mismatch)
            fail++;
    }
    printf(fail ? "stress_threads: FAIL (%d thread mismatch)\n"
                : "stress_threads: OK (deterministik, no race)\n", fail);
    return fail ? 1 : 0;
}