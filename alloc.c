/*
 * alloc.c -- Implementasi allocator wrapper (P7-T02, PR-019).
 *
 * Produksi (tanpa MYC_ALLOC_TEST): passthrough langsung ke libc — nol
 * overhead semantik, nol perubahan perilaku.
 *
 * Test build (MYC_ALLOC_TEST): menyisipkan hitung mundur kegagalan.
 *   myc_alloc_set_fail_after(N) berarti N alokasi pertama sukses lalu
 *   semua alokasi berikutnya mengembalikan NULL (nth-allocation failure).
 *   Nilai < 0 = passthrough penuh. Runner OOM mengulang myc_run untuk
 *   fail point 0..N sampai semua titik alokasi ter-exercise.
 */
/* POSIX: clock_gettime (myc_wall_ms) butuh _POSIX_C_SOURCE — harus
 * SEBELUM include sistem apa pun (pola sama dengan proc.c). */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "alloc.h"

#include <stdlib.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <time.h>
#endif

#ifdef MYC_ALLOC_TEST
static long g_fail_after = -1;   /* <0 passthrough; >=0 hitung mundur */
static long g_null_returned = 0; /* jumlah alokasi yang ditolak */
static long g_total_calls = 0;   /* total panggilan ter-wrap */

void myc_alloc_set_fail_after(long n)
{
    g_fail_after = n;
}

long myc_alloc_fail_count(void)
{
    return g_null_returned;
}

long myc_alloc_call_count(void)
{
    return g_total_calls;
}

static int should_fail(void)
{
    g_total_calls++;
    if (g_fail_after >= 0) {
        if (g_fail_after == 0) {
            g_null_returned++;
            return 1;
        }
        g_fail_after--;
    }
    return 0;
}

void *myc_malloc(size_t n)
{
    if (should_fail())
        return NULL;
    return malloc(n);
}

void *myc_calloc(size_t n, size_t sz)
{
    if (should_fail())
        return NULL;
    return calloc(n, sz);
}

void *myc_realloc(void *p, size_t n)
{
    if (should_fail())
        return NULL;
    return realloc(p, n);
}

void myc_free(void *p)
{
    free(p);
}
#else /* produksi: passthrough langsung ke libc */
void *myc_malloc(size_t n)
{
    return malloc(n);
}

void *myc_calloc(size_t n, size_t sz)
{
    return calloc(n, sz);
}

void *myc_realloc(void *p, size_t n)
{
    return realloc(p, n);
}

void myc_free(void *p)
{
    free(p);
}
#endif

/* Wall clock monotonic dalam milidetik (IDE-6, --watch-diff: timing
 * delta assurance). Windows: GetTickCount64; POSIX: CLOCK_MONOTONIC.
 * Return 0 bila clock tidak tersedia (caller hanya pakai SELISIH). */
unsigned long long myc_wall_ms(void)
{
#ifdef _WIN32
    return (unsigned long long)GetTickCount64();
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (unsigned long long)ts.tv_sec * 1000 +
           (unsigned long long)ts.tv_nsec / 1000000;
#endif
}
