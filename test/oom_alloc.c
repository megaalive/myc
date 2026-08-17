/*
 * oom_alloc.c -- Regression MYC-AUDIT-018/PR-019: injeksi kegagalan alokasi.
 *
 * PR-019 (P7-T02): memakai allocator wrapper FORMAL myc_malloc/calloc/realloc
 * (alloc.c) yang dikompilasi dengan -DMYC_ALLOC_TEST sehingga alokasi ke-N
 * dapat dibuat gagal via myc_alloc_set_fail_after(N). Loop titik kegagalan
 * 0..N menutup SEMUA situs alokasi myc. Test menegaskan:
 *   - tidak crash (proses selesai normal),
 *   - tidak hang (runner timeout menangkap),
 *   - verdict selalu nilai enum yang valid,
 *   - result dapat dibebaskan utuh (myc_result_free),
 *   - injeksi benar-benar aktif (setidaknya satu alokasi ditolak),
 *   - kontrol tanpa OOM -> MC_OK,
 *   - persistent state (ledger via myc_persist_atomic_write) TIDAK korup
 *     saat alokasi gagal di tengah penulisan (P7-T02: no corrupted state),
 *   - OOM di tengah loop berbentuk agent_check (check → patch → re-check),
 *     bukan hanya myc_run sekali (B3).
 *
 * Tidak lagi memakai --wrap (allocator injection GNU ld): wrapper formal
 * lebih portabel (tidak butuh flag linker) dan lintas platform.
 *
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -DMYC_ALLOC_TEST \
 *       -o oom_alloc oom_alloc.c alloc.c myc.c proc.c scanner.c policy.c \
 *       compile.c report.c sha256.c lint.c run.c contract.c prove.c \
 *       filc.c driver.c json.c gate.c negative.c persist.c
 *   (alloc.c WAJIB dibangun dengan -DMYC_ALLOC_TEST agar hook aktif.)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myc.h"
#include "compile.h"
#include "json.h"
#include "alloc.h"
#include "persist.h"

/* --- fixture --- */

static const char SMALL_SRC[] =
    "static int g_arr[16];\n"
    "int main(void){int i,s=0;for(i=0;i<16;i++)s+=g_arr[i];return s&1;}\n";

/* G3/agent_check: gets pada array lokal → template satu baris. */
static const char AGENT_SRC[] =
    "#include <stdio.h>\n"
    "int main(void){char buf[64];gets(buf);return 0;}\n";

static int verdict_in_range(myc_verdict v)
{
    return v >= MC_OK && v <= MC_INCONCLUSIVE;
}

/* Jumlah titik kegagalan; bisa dinaikkan via MYC_OOM_POINTS. */
static long oom_points(void)
{
    const char *e = getenv("MYC_OOM_POINTS");
    long n = e ? atol(e) : 64;
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
        myc_alloc_set_fail_after(i);
        myc_request_init(&req);
        req.input.kind = MYC_SOURCE_MEMORY;
        req.input.data = SMALL_SRC;
        req.input.len = strlen(SMALL_SRC);
        req.run_lint = 1;
        myc_result_init(&res);
        myc_run(&req, &res);
        if (!verdict_in_range(res.verdict))
            bad_verdict++;
        myc_result_free(&res);
    }
    myc_alloc_set_fail_after(-1);

    /* --- fase JSON (MYC-AUDIT-009): OOM di konstruksi objek/array +
     * serialisasi. guard sb_reserve/json_obj_set/json_arr_push harus
     * mengembalikan NULL/free val tanpa crash. Semua alokasi json memakai
     * myc_malloc (ter-wrap wrapper), jadi fail point sama seperti myc_run.
     * PENTING: TIDAK boleh printf selama g_fail_after aktif (stdio bisa
     * mengalokasi). */
    {
        long j;
        for (j = 0; j <= npoints; j++) {
            json_value *obj;
            int k;
            myc_alloc_set_fail_after(j);
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
                    myc_free(s);
                }
            }
            json_free(obj);
        }
        myc_alloc_set_fail_after(-1);
        /* json_new_obj di fail point 0 bisa NULL (bukan kegagalan) --
         * yang kita uji adalah "tidak crash & json_free(NULL) aman". */
    }

    /* --- fase persistent state (P7-T02: no corrupted persistent state):
     * myc_persist_atomic_write dipaksa gagal di tengah (fail point di
     * antara tulis-temp dan rename). Karena penulisan temp + flush terjadi
     * SEBELUM rename atomik, file target yang ada (atau tidak ada) harus
     * tetap utuh. Verifikasi: untuk tiap fail point, target yang tersisa
     * adalah baseline LAMA atau nilai BARU UTUH (tidak pernah setengah). */
    {
        const char *target = "test/.oom_alloc_persist.tmp";
        static const char OLD[] = "old-valid-state";
        static const char NEW[] = "new-valid-state";
        long p;

        /* baseline: tulis OLD tanpa OOM (harus sukses + utuh). */
        {
            FILE *fp = NULL;
            myc_alloc_set_fail_after(-1);
            if (!myc_persist_atomic_write(target, OLD, strlen(OLD))) {
                fprintf(stderr, "[FAIL] oom_alloc: baseline persist gagal "
                                "(tanpa OOM)\n");
                return 1;
            }
            fp = fopen(target, "r");
            if (!fp) {
                fprintf(stderr, "[FAIL] oom_alloc: baseline target tak ada\n");
                return 1;
            }
            fclose(fp);
        }

        /* loop fail point 0..12: tulis NEW dengan injeksi. Target yang
         * tersisa harus OLD utuh (temp gagal sebelum rename) ATAU NEW utuh
         * (rename sukses) -- tidak ada campuran/setengah. */
        for (p = 0; p <= 12; p++) {
            FILE *ck;
            char buf[96] = {0};
            size_t r;
            int ok_old = 0, ok_new = 0;

            myc_alloc_set_fail_after(p);
            myc_persist_atomic_write(target, NEW, strlen(NEW));
            myc_alloc_set_fail_after(-1);

            ck = fopen(target, "r");
            if (!ck) {
                fprintf(stderr, "[FAIL] oom_alloc: persist target hilang di "
                                "fail point %ld\n", p);
                return 1;
            }
            r = fread(buf, 1, sizeof(buf) - 1, ck);
            fclose(ck);
            ok_old = (r == strlen(OLD) && memcmp(buf, OLD, strlen(OLD)) == 0);
            ok_new = (r == strlen(NEW) && memcmp(buf, NEW, strlen(NEW)) == 0);
            if (!ok_old && !ok_new) {
                fprintf(stderr, "[FAIL] oom_alloc: persistent state korup "
                                "(bukan OLD juga bukan NEW) di fail point %ld "
                                "-> len %zu\n", p, r);
                return 1;
            }
        }

        /* final: tulis NEW tanpa OOM harus NEW utuh (file kembali hidup). */
        myc_alloc_set_fail_after(-1);
        if (myc_persist_atomic_write(target, NEW, strlen(NEW))) {
            FILE *ck;
            char buf[96] = {0};
            ck = fopen(target, "r");
            if (ck) {
                fread(buf, 1, sizeof(buf) - 1, ck);
                fclose(ck);
                if (strcmp(buf, NEW) != 0) {
                    fprintf(stderr, "[FAIL] oom_alloc: persist kembali gagal "
                                    "setelah pemulihan\n");
                    return 1;
                }
            }
            myc_free(NULL); /* myc_free(NULL) aman (idiom gratis) */
        }
        remove(target);
    }

    /* --- fase agent_check loop (B3): OOM pada re-check, bukan myc_run
     * sekali. Cermin tool_agent_check tanpa menarik mcp.c: iter 1
     * myc_pipeline (tanpa OOM) → myc_repair_source_line_patch → iter 2
     * myc_pipeline dengan fail_after(0). Jangan printf selama injeksi
     * aktif. */
    {
        myc_runtime_repair *crr = NULL;
        const char *patched;
        int line = 2;

        myc_alloc_set_fail_after(-1);
        myc_request_init(&req);
        req.input.kind = MYC_SOURCE_MEMORY;
        req.input.data = AGENT_SRC;
        req.input.len = strlen(AGENT_SRC);
        req.run_lint = 1;
        myc_result_init(&res);
        myc_pipeline(&req, &res);
        if (!verdict_in_range(res.verdict))
            bad_verdict++;
        if (res.verdict == MC_COMPILE_ERROR && res.diag_count > 0 &&
            res.diags[0].line > 0)
            line = res.diags[0].line;
        crr = myc_repair_source_line_patch(AGENT_SRC, strlen(AGENT_SRC),
                                           line);
        if (!crr || !crr->patched_source || crr->confidence < 80) {
            myc_result_free(&res);
            if (crr)
                myc_runtime_repair_free(crr);
            fprintf(stderr, "[FAIL] oom_alloc: fixture agent_check tidak "
                            "dapat di-patch (template gets)\n");
            return 1;
        }
        patched = crr->patched_source;

        myc_alloc_set_fail_after(0);
        {
            myc_request req2;
            myc_result  res2;

            myc_request_init(&req2);
            req2.input.kind = MYC_SOURCE_MEMORY;
            req2.input.data = patched;
            req2.input.len = strlen(patched);
            req2.run_lint = 1;
            myc_result_init(&res2);
            myc_pipeline(&req2, &res2);
            if (!verdict_in_range(res2.verdict))
                bad_verdict++;
            myc_result_free(&res2);
        }
        myc_alloc_set_fail_after(-1);
        myc_result_free(&res);
        myc_runtime_repair_free(crr);
    }

    /* cetak hasil HANYA setelah reset (printf bisa mengalokasi). */
    if (!control_ok) {
        fprintf(stderr, "[FAIL] oom_alloc: kontrol tanpa OOM bukan MC_OK\n");
        return 1;
    }
    if (myc_alloc_fail_count() == 0) {
        fprintf(stderr, "[FAIL] oom_alloc: injeksi tidak pernah menolak alokasi "
                        "(MYC_ALLOC_TEST tidak aktif?)\n");
        return 1;
    }
    if (bad_verdict) {
        fprintf(stderr, "[FAIL] oom_alloc: %d hasil verdict invalid di bawah OOM\n",
                bad_verdict);
        return 1;
    }
    printf("[OK] oom_alloc: %ld titik OOM (fail 0..%ld) tanpa crash; "
           "%ld alokasi ditolak (%ld total panggilan); kontrol OK\n",
           npoints + 1, npoints, myc_alloc_fail_count(),
           myc_alloc_call_count());
    return 0;
}