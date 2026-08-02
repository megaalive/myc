/*
 * myc_buf.h -- Header checked-build myc (D1.2 + MYC-AUDIT-012): makro buffer aman.
 *
 * Dual-mode, source yang sama dibangun 2x:
 *   Produksi (tanpa -DMYC_CHECKED):
 *     MYC_BUF(T)     -> T *                       (pointer polos, overhead 0)
 *     MYC_NEW(b,T,n) -> b = calloc(n, sizeof(T))  (calloc sendiri aman thd overflow)
 *     MYC_AT(b,T,i)  -> b[i]                      (index polos)
 *     MYC_FREE(b)    -> free(b); b = NULL
 *     MYC_IS_NULL(b) -> b == NULL
 *
 *   Checked (-DMYC_CHECKED=1, dipakai gate --checked / --run --checked;
 *   memerlukan gcc atau clang):
 *     MYC_BUF(T)     -> struct { T *data; byte_capacity; elem_size;
 *                                generation; cookie }     (fat struct TYPED)
 *     MYC_NEW(b,T,n) -> alokasi + catat metadata; overflow n*sizeof(T) -> trap
 *     MYC_AT(b,T,i)  -> cek compile-time UKURAN elemen sama dengan deklarasi
 *                        (trik sizeof(char[N]) dengan N=-1 = error) + cek
 *                        runtime (cookie, elem_size, bounds) -> abort bila
 *                        dilanggar; tetap LVALUE (assignment MYC_AT(...)=x valid)
 *     MYC_FREE(b)    -> free(data); data = NULL (deteksi use-after-free)
 *     MYC_IS_NULL(b) -> data == NULL
 *
 * Di checked build MYC_BUF adalah STRUCT: akses langsung `b[i]` menjadi ERROR
 * kompilasi -> semua akses dipaksa lewat MYC_AT (yang dicek batas). Itu yang
 * memberi assurance L4 SPATIAL: transformasi fat-pointer tanpa fork bahasa.
 *
 * Perbaikan MYC-AUDIT-012 (2026-08-02):
 *   - Tipe elemen kini DIPERTAHANKAN: member `data` bertipe T* (bukan void*).
 *     MYC_AT memverifikasi UKURAN elemen di compile time (trik array negatif,
 *     C11 murni, tanpa ekstensi) DAN membandingkan elem_size di runtime.
 *     Caller tidak bisa lagi memakai tipe dengan ukuran berbeda (mis. char
 *     pada MYC_BUF(int)) dengan rasa aman palsu. (Mismatch tipe ber-ukuran
 *     sama seperti int vs unsigned TIDAK dianggap berbahaya: bounds, offset,
 *     dan alignment identik.)
 *   - Multiplication dicek eksplisit: MYC_NEW menolak n*sizeof(T) > SIZE_MAX;
 *     MYC_AT memakai `i >= byte_capacity/elem` sehingga i*elem dijamin tidak
 *     overflow (bounds = checked multiplication dalam satu pembandingan).
 *   - byte_capacity disimpan dalam BYTE, bukan jumlah elemen, agar offset
 *     dihitung dari metadata yang konsisten dengan ukuran elemen.
 *   - cookie (magic) mendeteksi korupsi metadata; generation naik tiap
 *     NEW/FREE (metadata untuk invalidasi view/stale di masa depan).
 *   - n negatif (signed) ter-cast ke size_t raksasa -> tertangkap oleh cek
 *     overflow MYC_NEW.
 *
 * Catatan jujur:
 *   - Panjang TIDAK dilacak (user memegang len sendiri -- idiom C standar);
 *     cek batas berbasis kapasitas (byte_capacity).
 *   - MYC_AT harus tetap LVALUE agar `MYC_AT(b,T,i) = v` valid, sehingga
 *     seluruh cek diletakkan DI DALAM helper yang mengembalikan pointer;
 *     tidak ada operator komma di ekspresi MYC_AT.
 *   - MYC_NEW pada buffer yang MASIH AKTIF (data != NULL) tidak dapat
 *     dideteksi tanpa membaca memori indeterminate pada deklarasi segar,
 *     sehingga TIDAK di-trap -- pemakaian seperti itu adalah leak; free dulu.
 *   - Buffer di luar MYC_BUF (malloc polos, array stack) tidak tercakup
 *     transformasi ini -- tetap L1 / ASan.
 *   - MYC_AT mengharapkan LVALUE buffer (mis. `r->buf`), bukan pointer ke
 *     struct.
 */
#ifndef MYC_BUF_H
#define MYC_BUF_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef MYC_CHECKED

/* Magic metadata: berubah -> memory corruption di sekitar struct buffer. */
#define MYC_BUF_COOKIE 0x4D594342u /* "MYCB" */

/* MYC_BUF(T) = struct anonim dengan member data TYPED (T*). Tipe elemen
 * tersimpan di TYPE, sehingga MYC_AT dapat memverifikasi ukuran elemen
 * secara compile-time tanpa runtime cost. */
#define MYC_BUF(T) struct { \
    T       *data;            /* NULL setelah MYC_FREE (use-after-free) */ \
    size_t   byte_capacity;   /* kapasitas dalam BYTE = n * sizeof(T) */ \
    size_t   elem_size;       /* sizeof(T) saat MYC_NEW (cek tipe runtime) */ \
    uint32_t generation;      /* naik tiap NEW/FREE (metadata invalidasi) */ \
    uint32_t cookie;          /* MYC_BUF_COOKIE (deteksi korupsi) */ \
}

/* Alokasi dengan checked multiplication: n*elem overflow -> trap.
 * calloc(n, elem) sendiri aman, tapi di checked build overflow dianggap
 * bug pemrograman yang harus TERLIHAT (bukan sekadar NULL). */
static inline void *myc_buf_alloc(size_t n, size_t elem, size_t *out_bytes)
{
    if (elem == 0 || n > SIZE_MAX / elem) {
        fputs("MYC_CHECKED: MYC_NEW overflow: n*sizeof(T) melebihi SIZE_MAX\n",
              stderr);
        abort();
    }
    {
        void *p = calloc(n, elem);
        *out_bytes = p ? n * elem : 0;
        return p;
    }
}

/* Verifikasi akses lalu kembalikan pointer elemen ke-i. Cek: cookie
 * (korupsi), tipe elemen (runtime, defense-in-depth di atas cek
 * compile-time), dan bounds dengan checked multiplication:
 * `i >= byte_capacity/elem` setara dengan i*elem >= byte_capacity, dan
 * karena byte_capacity = n*elem (dari MYC_NEW yang sudah dicek overflow),
 * i*elem dijamin tidak overflow bila lolos. Deref hasilnya di makro
 * MYC_AT menjaga sifat LVALUE. */
static inline void *myc_buf_at_checked(const void *data, size_t byte_capacity,
                                       size_t elem_size, uint32_t cookie,
                                       size_t i, size_t elem)
{
    if (!data) {
        fputs("MYC_CHECKED: akses buffer NULL (use-after-free?)\n", stderr);
        abort();
    }
    if (cookie != MYC_BUF_COOKIE) {
        fputs("MYC_CHECKED: metadata buffer tidak valid (cookie mismatch; "
              "buffer belum di-MYC_NEW atau memory corruption?)\n", stderr);
        abort();
    }
    if (elem_size != elem) {
        fprintf(stderr,
                "MYC_CHECKED: tipe elemen tidak cocok (MYC_NEW sizeof=%llu, "
                "MYC_AT sizeof=%llu)\n",
                (unsigned long long)elem_size, (unsigned long long)elem);
        abort();
    }
    if (elem == 0) {
        fputs("MYC_CHECKED: elem_size nol (tipe elemen tidak valid)\n",
              stderr);
        abort();
    }
    if (i >= byte_capacity / elem) {
        fprintf(stderr,
                "MYC_CHECKED: out-of-bounds i=%llu cap_bytes=%llu elem=%llu\n",
                (unsigned long long)i, (unsigned long long)byte_capacity,
                (unsigned long long)elem);
        abort();
    }
    return (char *)data + i * elem;
}

#define MYC_NEW(b, T, n) do { \
    (b).data = myc_buf_alloc((size_t)(n), sizeof(T), &(b).byte_capacity); \
    (b).elem_size = sizeof(T); \
    (b).generation++; \
    (b).cookie = MYC_BUF_COOKIE; \
} while (0)

/* MYC_AT: cek UKURAN elemen secara compile-time via trik array negatif:
 * `sizeof(char[sizeof(T) == sizeof((b).data[0]) ? 1 : -1])` -> bila ukuran
 * T != ukuran elemen deklarasi, instansiasi `char[-1]` = compile error
 * (C11 murni, tanpa ekstensi; tidak memengaruhi lvalue karena hanya bagian
 * dari ARGUMEN helper). Lalu cek runtime, lalu deref pointer hasil.
 * Ekspresi utuh `*(T *)...` tetap LVALUE. */
#define MYC_AT(b, T, i) \
    (*(T *)myc_buf_at_checked((b).data, (b).byte_capacity, (b).elem_size, \
                              (b).cookie, (size_t)(i), \
                              sizeof(T) + 0 * sizeof(char[sizeof(T) == \
                                  sizeof((b).data[0]) ? 1 : -1])))

#define MYC_FREE(b) do { \
    if ((b).cookie != MYC_BUF_COOKIE) { \
        fputs("MYC_CHECKED: metadata buffer tidak valid sebelum free " \
              "(belum di-MYC_NEW atau memory corruption?)\n", stderr); \
        abort(); \
    } \
    free((void *)(b).data); \
    (b).data = NULL; \
    (b).byte_capacity = 0; \
    (b).generation++; \
} while (0)

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
