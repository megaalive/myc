/*
 * alloc.h -- Allocator wrapper kontrak (P7-T02, PR-019).
 *
 * Wrapper alokasi formal yang dipakai SEMUA source myc (myc_malloc /
 * myc_calloc / myc_realloc / myc_free). Produksi memetakan langsung ke
 * libc (passthrough). Test build (MYC_ALLOC_TEST) dapat menggagalkan
 * alokasi ke-N (nth-allocation failure) untuk memaksa jalur OOM semua
 * titik alokasi.
 *
 * API hook test (hanya tersedia saat MYC_ALLOC_TEST):
 *   myc_alloc_set_fail_after(n)  -- n >= 0: n alokasi pertama sukses,
 *                                   lalu semua gagal; n < 0: passthrough.
 *   myc_alloc_fail_count()       -- jumlah alokasi yang ditolak.
 *   myc_alloc_call_count()       -- total panggilan ter-wrap.
 * Hook state adalah `_Thread_local` (B4): aman bila tes OOM jalan
 * ber-thread; produksi tanpa MYC_ALLOC_TEST tetap passthrough tanpa
 * state.
 */
#ifndef MYC_ALLOC_H
#define MYC_ALLOC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void *myc_malloc(size_t n);
void *myc_calloc(size_t n, size_t sz);
void *myc_realloc(void *p, size_t n);
void  myc_free(void *p);

#ifdef MYC_ALLOC_TEST
void  myc_alloc_set_fail_after(long n);
long  myc_alloc_fail_count(void);
long  myc_alloc_call_count(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* MYC_ALLOC_H */
