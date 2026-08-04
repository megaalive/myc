/*
 * oom_alloc.c -- Regression MYC-AUDIT-018: injeksi kegagalan alokasi (OOM).
 *
 * Memakai allocator injection GNU ld (--wrap) sehingga SEMUA panggilan
 * malloc/calloc/realloc dari source myc bisa dibuat gagal secara
 * terkendali: g_fail_after = N berarti N alokasi pertama sukses, lalu
 * alokasi berikutnya mengembalikan NULL. Myc RUN diulang untuk setiap
 * titik kegagalan 0..N; test menegaskan:
 *   - tidak crash (proses selesai normal),
 *   - tidak hang (runner timeout menangkap),
 *   - verdict selalu nilai enum yang valid,
 *   - result dapat dibebaskan utuh (myc_result_free),
 *   - injeksi benar-benar aktif (setidaknya satu alokasi ditolak),
 *   - kontrol tanpa OOM -> MC_OK.
 *
 * PENTING: selama loop OOM, TIDAK BOLEH memanggil printf (stdio dapat
 * mengalokasi) -- hasil dicetak setelah g_fail_after di-reset.
 *
 * Build (MinGW & glibc GNU ld):
 *   gcc -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN \
 *       -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc \
 *       -o oom_alloc oom_alloc.c myc.c proc.c scanner.c policy.c \
 *       compile.c report.c sha256.c lint.c run.c contract.c prove.c \
 *       filc.c driver.c json.c gate.c negative.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myc.h"
#include "json.h"

/* --- allocator injection (di-link via --wrap) --- */
void *__real_malloc(size_t n);
void *__real_calloc(size_t n, size_t sz);
void *__real_realloc(void *p, size_t n);

static long g_fail_after = -1;   /* <0 = passthrough; >=0 = hitung mundur */
static long g_null_returned = 0; /* jumlah alokasi yang ditolak */
static long g_total_calls = 0;   /* total panggilan ter-wrap */

void *__wrap_malloc(size_t n)
{
    g_total_calls++;
    if (g_fail_after >= 0) {
        if (g_fail_after == 0) {
            g_null_returned++;
            return NULL;
        }
        g_fail_after--;
    }
    return __real_malloc(n);
}

void *__wrap_calloc(size_t n, size_t sz)
{
    g_total_calls++;
    if (g_fail_after >= 0) {
        if (g_fail_after == 0) {
            g_null_returned++;
            return NULL;
        }
        g_fail_after--;
    }
    return __real_calloc(n, sz);
}

void *__wrap_realloc(void *p, size_t n)
{
    g_total_calls++;
    if (g_fail_after >= 0) {
        if (g_fail_after == 0) {
            g_null_returned++;
            return NULL;
        }
        g_fail_after--;
    }
    return __real_realloc(p, n);
}

/* --- fixture --- */

static const char SMALL_SRC[] =
    "static int g_arr[16];\n"
    "int main(void){int i,s=0;for(i=0;i<16;i++)s+=g_arr[i];return s&1;}\n";

/* Jumlah titik kegagalan; bisa dinaikkan via MYC_OOM_POINTS. */
static long oom_points(void)
{
    const char *e = getenv("MYC_OOM_POINTS");
    long n = e ? atol(e) : 48;
    return n > 200 ? 200 : (n < 1 ? 1 : n);
}

int main(void)
{
    myc_request req;
    myc_result  res;
    long        i, npoints;
    int         bad_verdict = 0;
    int         control_ok = 0;

    npoints = oom_points();

    /* kontrol: tanpa OOM, fixture valid harus MC_OK. */
    g_fail_after = -1;
    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = SMALL_SRC;
    req.input.len = strlen(SMALL_SRC);
    req.run_lint = 1;
    myc_result_init(&res);
    myc_run(&req, &res);
    control_ok = (res.verdict == MC_OK);
    myc_result_free(&res);

    /* loop titik kegagalan 0..N (semua alokasi myc bisa gagal). */
    for (i = 0; i <= npoints; i++) {
        g_fail_after = i;
        myc_request_init(&req);
        req.input.kind = MYC_SOURCE_MEMORY;
        req.input.data = SMALL_SRC;
        req.input.len = strlen(SMALL_SRC);
        req.run_lint = 1;
        myc_result_init(&res);
        myc_run(&req, &res);
        if (res.verdict < MC_OK || res.verdict > MC_INCONCLUSIVE)
            bad_verdict++;
        myc_result_free(&res);
    }

    /* --- fase JSON (MYC-AUDIT-009): OOM di konstruksi objek/array +
     * serialisasi. guard sb_reserve/json_obj_set/json_arr_push harus
     * mengembalikan NULL/free val tanpa crash. Semua alokasi json ter-wrap,
     * jadi loop fail point sama seperti myc_run. PENTING: TIDAK boleh printf
     * selama g_fail_after aktif (stdio bisa mengalokasi). */
    {
        long j;
        int  json_ok = 1;
        for (j = 0; j <= npoints; j++) {
            json_value *obj;
            int k;
            g_fail_after = j;
            obj = json_new_obj();
            if (obj) {
                for (k = 0; k < 8; k++) {
                    char key[24];
                    snprintf(key, sizeof(key), "key_%d", k);
                    json_obj_set(obj, key, json_new_num(k));
                }
                json_arr_push(obj, json_new_null());
                {
                    char *s = NULL;
                    json_serialize(obj, &s);
                    free(s);
                }
            }
            json_free(obj);
        }
        g_fail_after = -1;
        /* json_new_obj di fail point 0 bisa NULL (bukan kegagalan) --
         * yang kita uji adalah "tidak crash & json_free(NULL) aman". */
        (void)json_ok;
    }
    g_fail_after = -1;

    /* cetak hasil HANYA setelah reset (printf bisa mengalokasi). */
    if (!control_ok) {
        fprintf(stderr, "[FAIL] oom_alloc: kontrol tanpa OOM bukan MC_OK\n");
        return 1;
    }
    if (g_null_returned == 0) {
        fprintf(stderr, "[FAIL] oom_alloc: injeksi tidak pernah menolak alokasi "
                        "(--wrap tidak aktif?)\n");
        return 1;
    }
    if (bad_verdict) {
        fprintf(stderr, "[FAIL] oom_alloc: %d hasil verdict invalid di bawah OOM\n",
                bad_verdict);
        return 1;
    }
    printf("[OK] oom_alloc: %ld titik OOM (fail 0..%ld) tanpa crash; "
           "%ld alokasi ditolak; kontrol OK\n",
           npoints + 1, npoints, g_null_returned);
    return 0;
}
