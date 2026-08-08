/* regress.c -- Counterexample Seeds -> Regression (Fase 6, Self-Challenge)
 *
 * Corpus memory: counterexample dari fuzz / exhaustive / driver
 * dipersisten ke `.myc/regression/`; `myc regression run` replay semua
 * seed. NON-blocking di kedua arah (save dan replay tidak mengubah
 * verdict run yang sedang berlangsung).
 */
#include "regress.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

#if defined(_WIN32)
#include <direct.h>
#define REG_MKDIR(p) _mkdir(p)
#else
#include <sys/stat.h>
#define REG_MKDIR(p) mkdir(p, 0700)
#endif

#define REG_DIR     ".myc/regression"
#define REG_INDEX   ".myc/regression/index.txt"

const char *myc_regress_kind_name(int kind)
{
    switch (kind) {
    case MYC_REG_FUZZ:       return "fuzz";
    case MYC_REG_EXHAUSTIVE: return "exhaustive";
    case MYC_REG_DRIVER:     return "driver";
    default:                 return "unknown";
    }
}

static void regress_mkdirs(void)
{
    REG_MKDIR(".myc");
    REG_MKDIR(REG_DIR);
}

void myc_regress_save(myc_result *res, const char *source, size_t len,
                      int kind, const char *detail, unsigned seed)
{
    char hash[65];
    char path[520];
    FILE *f;
    (void)res;

    sha256_hex(source ? source : "", source ? len : 0, hash);
    regress_mkdirs();
    snprintf(path, sizeof(path), "%s/%s_%.8s.c", REG_DIR,
             myc_regress_kind_name(kind), hash);
    if ((f = fopen(path, "rb")) != NULL) {
        fclose(f);   /* sudah ada (idempoten) */
        return;
    }
    f = fopen(path, "wb");
    if (!f)
        return;
    if (source && len > 0)
        fwrite(source, 1, len, f);
    fclose(f);

    /* append index: <kind> <sha8> <detail> [<seed>] */
    f = fopen(REG_INDEX, "ab");
    if (f) {
        fprintf(f, "%s %.8s %s %u\n", myc_regress_kind_name(kind), hash,
                detail ? detail : "", seed);
        fclose(f);
    }
}

int myc_regress_list(FILE *out)
{
    FILE *f = fopen(REG_INDEX, "rb");
    char line[512];
    int n = 0;

    fprintf(out, "regression corpus (Fase 6): %s\n", REG_DIR);
    if (!f) {
        fprintf(out, "  (kosong -- belum ada counterexample tersimpan)\n");
        return 0;
    }
    while (fgets(line, sizeof(line), f)) {
        char kind[32];
        char hash[16];
        char detail[128];
        char path[520];
        if (sscanf(line, "%31s %15s %127s", kind, hash, detail) < 2)
            continue;
        snprintf(path, sizeof(path), "%s/%s_%s.c", REG_DIR, kind, hash);
        fprintf(out, "  %-10s %s (%s)\n", kind, hash,
                fopen(path, "rb") ? "seed ada" : "seed HILANG");
        n++;
    }
    fclose(f);
    fprintf(out, "  total: %d seed\n", n);
    return 0;
}

/* Jalankan satu source dengan gate kind (seed PRNG untuk fuzz).
 * return 1 = violation, 0 = clean/OK, -1 = error. */
static int regress_run_one(const char *path, const char *kind,
                           unsigned seed, char *status_out, size_t status_cap)
{
    FILE *f;
    long sz;
    char *src;
    myc_request req;
    myc_result res;
    int violation;

    f = fopen(path, "rb");
    if (!f) {
        snprintf(status_out, status_cap, "FILE HILANG");
        return -1;
    }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > 262144) {
        fclose(f);
        snprintf(status_out, status_cap, "UKURAN TIDAK VALID");
        return -1;
    }
    src = (char *)malloc((size_t)sz + 1);
    if (!src) {
        fclose(f);
        snprintf(status_out, status_cap, "OOM");
        return -1;
    }
    if (fread(src, 1, (size_t)sz, f) != (size_t)sz) {
        free(src);
        fclose(f);
        snprintf(status_out, status_cap, "BACA GAGAL");
        return -1;
    }
    src[sz] = '\0';
    fclose(f);

    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = src;
    req.input.len = (size_t)sz;
    req.no_cache = 1;
    if (strcmp(kind, "fuzz") == 0) {
        req.fuzz = 1;
        req.fuzz_iters = 2000;
        req.fuzz_seed = seed;
    } else if (strcmp(kind, "exhaustive") == 0) {
        req.exhaustive = 1;
    } else if (strcmp(kind, "driver") == 0) {
        req.driver = 1;
    }
    myc_result_init(&res);
    myc_run(&req, &res);

    violation = (res.verdict == MC_DRIVER_VIOLATION ||
                 res.verdict == MC_RUNTIME_VIOLATION ||
                 res.verdict == MC_COMPILE_ERROR);
    if (violation)
        snprintf(status_out, status_cap, "STILL FAILING (%s)",
                 res.verdict == MC_DRIVER_VIOLATION ? "violation" :
                 res.verdict == MC_RUNTIME_VIOLATION ? "runtime" :
                                                       "compile");
    else if (res.verdict == MC_OK)
        snprintf(status_out, status_cap, "RESOLVED");
    else
        snprintf(status_out, status_cap, "OTHER (%d)", (int)res.verdict);

    myc_result_free(&res);
    free(src);
    return violation ? 1 : 0;
}

int myc_regress_run(FILE *out, const char *target_file)
{
    FILE *f = fopen(REG_INDEX, "rb");
    char line[512];
    int total = 0, failing = 0, resolved = 0;

    fprintf(out, "regression replay (Fase 6): %s\n",
            target_file ? target_file : "semua seed corpus (status deteksi)");
    if (!f) {
        fprintf(out, "  (corpus kosong)\n");
        return 0;
    }
    while (fgets(line, sizeof(line), f)) {
        char kind[32];
        char hash[16];
        char detail[128];
        char status[96];
        char path[520];
        unsigned seed = 0;
        int rc;
        if (sscanf(line, "%31s %15s %127s %u", kind, hash, detail,
                   &seed) < 2)
            continue;
        if (target_file)
            snprintf(path, sizeof(path), "%s", target_file);
        else
            snprintf(path, sizeof(path), "%s/%s_%s.c", REG_DIR, kind, hash);
        rc = regress_run_one(path, kind, seed, status, sizeof(status));
        total++;
        fprintf(out, "  [%s] %s_%s (seed=%u) %s\n",
                rc == 0 ? "OK  " : (rc < 0 ? "SKIP" : "FAIL"),
                kind, hash, seed, status);
        if (rc == 0)
            resolved++;
        else if (rc > 0)
            failing++;
    }
    fclose(f);
    fprintf(out, "  ringkasan: %d seed, %d resolved, %d masih gagal\n",
            total, resolved, failing);
    return failing;
}
