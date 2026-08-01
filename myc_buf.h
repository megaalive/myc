/*
 * myc_buf.h -- Header checked-build myc (D1.2): makro buffer aman.
 *
 * Dual-mode, source yang sama dibangun 2x:
 *   Produksi (tanpa -DMYC_CHECKED):
 *     MYC_BUF(T)     -> T *                       (pointer polos, overhead 0)
 *     MYC_NEW(b,T,n) -> b = calloc(n, sizeof(T))
 *     MYC_AT(b,T,i)  -> b[i]                      (index polos)
 *     MYC_FREE(b)    -> free(b); b = NULL
 *     MYC_IS_NULL(b) -> b == NULL
 *
 *   Checked (-DMYC_CHECKED=1, dipakai gate --checked / --run --checked):
 *     MYC_BUF(T)     -> myc_fat { void *data; size_t cap; }   (fat struct)
 *     MYC_NEW(b,T,n) -> alokasi + catat kapasitas
 *     MYC_AT(b,T,i)  -> akses dengan cek batas runtime (abort bila OOB)
 *     MYC_FREE(b)    -> free(data); data = NULL
 *     MYC_IS_NULL(b) -> data == NULL
 *
 * Di checked build MYC_BUF adalah STRUCT: akses langsung `b[i]` menjadi ERROR
 * kompilasi -> semua akses dipaksa lewat MYC_AT (yang dicek batas). Itu yang
 * memberi assurance L4 SPATIAL: transformasi fat-pointer tanpa fork bahasa.
 *
 * Catatan jujur:
 *   - Panjang TIDAK dilacak (user memegang len sendiri -- idiom C standar);
 *     cek batas berbasis kapasitas (cap).
 *   - Buffer di luar MYC_BUF (malloc polos, array stack) tidak tercakup
 *     transformasi ini -- tetap L1 / ASan.
 *   - MYC_AT mengharapkan LVALUE buffer (mis. `r->buf`), bukan pointer ke
 *     struct.
 */
#ifndef MYC_BUF_H
#define MYC_BUF_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef MYC_CHECKED

typedef struct {
    void  *data;
    size_t cap;                 /* kapasitas elemen */
} myc_fat;

static inline void *myc_buf_at(myc_fat *f, size_t elem, size_t i)
{
    if (!f->data) {
        fputs("MYC_CHECKED: akses buffer NULL (use-after-free?)\n", stderr);
        abort();
    }
    if (i >= f->cap) {
        fprintf(stderr,
                "MYC_CHECKED: out-of-bounds i=%llu cap=%llu elem=%llu\n",
                (unsigned long long)i, (unsigned long long)f->cap,
                (unsigned long long)elem);
        abort();
    }
    return (char *)f->data + i * elem;
}

static inline void myc_buf_free(myc_fat *f)
{
    free(f->data);
    f->data = NULL;
    f->cap = 0;
}

#define MYC_BUF(T)     myc_fat
#define MYC_NEW(b, T, n) do { \
    (b).data = calloc((size_t)(n), sizeof(T)); \
    (b).cap  = (b).data ? (size_t)(n) : 0; \
} while (0)
#define MYC_AT(b, T, i) \
    (*(T *)myc_buf_at(&(b), sizeof(T), (size_t)(i)))
#define MYC_FREE(b)    myc_buf_free(&(b))
#define MYC_IS_NULL(b) ((b).data == NULL)

#else /* produksi */

#define MYC_BUF(T)     T *
#define MYC_NEW(b, T, n) do { \
    (b) = (T *)calloc((size_t)(n), sizeof(T)); \
} while (0)
#define MYC_AT(b, T, i) ((b)[(i)])
#define MYC_FREE(b) do { \
    free((void *)(b)); \
    (b) = NULL; \
} while (0)
#define MYC_IS_NULL(b) ((b) == NULL)

#endif /* MYC_CHECKED */

#endif /* MYC_BUF_H */
