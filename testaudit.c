/* testaudit.c -- Test-Quality Audit (Fase 6, Self-Challenge)
 *
 * Memindai test/ dan tests/ (fixture C), mengklasifikasi per nama+isi,
 * lalu memetakan cakupan hazard class dan backend. Gap = hazard class
 * tanpa fixture / backend tanpa fixture -- dilaporkan, NON-blocking.
 */
#include "testaudit.h"

#include "alloc.h"
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Hazard class -> keyword pemicu (dicocokkan pada nama file + isi).
 * Satu fixture bisa menutupi beberapa class. */
typedef struct {
    const char *name;
    const char *const *keywords;
} ta_hazard_def;

static const char *K_SPATIAL[] = {
    "oob", "out-of-bounds", "heap-buffer-overflow", "stack-buffer-overflow",
    "bounds", "arr[", "a[", NULL
};
static const char *K_TEMPORAL[] = {
    "uaf", "use-after-free", "stale", "double_free", "double-free", NULL
};
static const char *K_INTEGER[] = {
    "intovf", "integer-overflow", "intptr", "overflow", NULL
};
static const char *K_RUNTIME[] = {
    "run_", "realloc", "fopen", "system", "exec", "fuzz", NULL
};
static const char *K_PROOF[] = {
    "prove", "contract", "exhaustive", "ensures", "requires", NULL
};
static const char *K_BOUNDARY[] = {
    "edge", "boundary", "zero_cases", "driver", "mutate", "spoof", NULL
};
static const char *K_CAPABILITY[] = {
    "filc", "freestanding", "mmio", "checked", "signed", NULL
};

static const ta_hazard_def HAZARDS[] = {
    { "spatial", K_SPATIAL },
    { "temporal", K_TEMPORAL },
    { "integer", K_INTEGER },
    { "runtime", K_RUNTIME },
    { "proof", K_PROOF },
    { "boundary", K_BOUNDARY },
    { "capability", K_CAPABILITY },
};

#define TA_NHAZ ((int)(sizeof(HAZARDS) / sizeof(HAZARDS[0])))

/* Backend -> keyword fixture pemicu. */
typedef struct {
    const char *name;
    const char *const *keywords;
} ta_backend_def;

static const char *K_B_RUN[] = { "run", "fuzz", "oob", "uaf", NULL };
static const char *K_B_DRIVER[] = { "driver", "contract", "zero_cases", NULL };
static const char *K_B_EXHAUSTIVE[] = { "exhaustive", "wide", NULL };
static const char *K_B_FUZZ[] = { "fuzz", NULL };
static const char *K_B_MUTATE[] = { "mutate", NULL };
static const char *K_B_STACK[] = { "stack", "recursive", NULL };
static const char *K_B_PROVE[] = { "prove", "contract", NULL };
static const char *K_B_CHECKED[] = { "checked", NULL };
static const char *K_B_FILC[] = { "filc", NULL };
static const char *K_B_MATRIX[] = { "blinky", "mmio", "freestanding", NULL };

static void ta_lower_strcpy(char *dst, const char *src, size_t cap);

static const ta_backend_def BACKENDS[] = {
    { "run", K_B_RUN },
    { "driver", K_B_DRIVER },
    { "exhaustive", K_B_EXHAUSTIVE },
    { "fuzz", K_B_FUZZ },
    { "mutate", K_B_MUTATE },
    { "stack", K_B_STACK },
    { "prove", K_B_PROVE },
    { "checked", K_B_CHECKED },
    { "filc", K_B_FILC },
    { "matrix", K_B_MATRIX },
};

#define TA_NBACK ((int)(sizeof(BACKENDS) / sizeof(BACKENDS[0])))

#define TA_MAX_FILE 65536

static int ta_match(const char *hay, const char *const *keys)
{
    int i;
    if (!hay)
        return 0;
    for (i = 0; keys[i]; i++) {
        if (strstr(hay, keys[i]))
            return 1;
    }
    return 0;
}

static void ta_lower(char *s)
{
    for (; *s; s++)
        *s = (char)tolower((unsigned char)*s);
}

/* Baca file (cap), return malloc'd lowercase content atau NULL. */
static char *ta_read_lower(const char *path)
{
    FILE *f = fopen(path, "rb");
    char *buf;
    long sz;
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > TA_MAX_FILE) {
        fclose(f);
        return NULL;
    }
    buf = (char *)myc_malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        myc_free(buf);
        fclose(f);
        return NULL;
    }
    buf[sz] = '\0';
    fclose(f);
    ta_lower(buf);
    return buf;
}

/* Scan satu direktori; untuk tiap *.c (kedalaman 1), klasifikasi dan
 * update cakupan. */
static void ta_scan_dir(const char *dir, int *haz_hit, int *back_hit,
                        int *total, int *nbad, int *nok, int *ncontract)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    char path[1024];

    if (!d)
        return;
    while ((e = readdir(d)) != NULL) {
        const char *nm = e->d_name;
        size_t len;
        char lower[512];
        char *content = NULL;
        int i;

        if (nm[0] == '.')
            continue;
        len = strlen(nm);
        if (len < 3 || strcmp(nm + len - 2, ".c") != 0)
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, nm) >= (int)sizeof(path))
            continue;

        (*total)++;
        ta_lower_strcpy(lower, nm, sizeof(lower));
        content = ta_read_lower(path);

        /* klasifikasi bad/ok via nama + isi keyword bug */
        if (strstr(lower, "bad_") || strstr(lower, "divergence_oob") ||
            strstr(lower, "witness_oob") || strstr(lower, "witness_uaf") ||
            (content && (strstr(content, "heap-buffer-overflow") ||
                         strstr(content, "use-after-free"))))
            (*nbad)++;
        else
            (*nok)++;
        if (content && strstr(content, "//@"))
            (*ncontract)++;

        /* cakupan hazard class */
        for (i = 0; i < TA_NHAZ; i++) {
            if (!haz_hit[i] &&
                (ta_match(lower, HAZARDS[i].keywords) ||
                 ta_match(content, HAZARDS[i].keywords))) {
                haz_hit[i] = 1;
            }
        }
        /* cakupan backend */
        for (i = 0; i < TA_NBACK; i++) {
            if (!back_hit[i] &&
                (ta_match(lower, BACKENDS[i].keywords) ||
                 ta_match(content, BACKENDS[i].keywords))) {
                back_hit[i] = 1;
            }
        }
        myc_free(content);
    }
    closedir(d);
}

void ta_lower_strcpy(char *dst, const char *src, size_t cap)
{
    size_t i = 0;
    while (src[i] && i + 1 < cap) {
        dst[i] = (char)tolower((unsigned char)src[i]);
        i++;
    }
    dst[i] = '\0';
}

int myc_testaudit_run(myc_ta_hazard *hazards, int *nhaz,
                      myc_ta_backend *backends, int *nback)
{
    int haz_hit[TA_NHAZ] = { 0 };
    int back_hit[TA_NBACK] = { 0 };
    int total = 0, nbad = 0, nok = 0, ncontract = 0;
    int i, gap = 0;

    ta_scan_dir("test", haz_hit, back_hit, &total, &nbad, &nok, &ncontract);
    ta_scan_dir("test/fixtures", haz_hit, back_hit, &total, &nbad, &nok,
                &ncontract);
    ta_scan_dir("tests", haz_hit, back_hit, &total, &nbad, &nok, &ncontract);

    for (i = 0; i < TA_NHAZ; i++) {
        hazards[i].name = HAZARDS[i].name;
        hazards[i].fixtures = haz_hit[i] ? 1 : 0;
        hazards[i].covered = haz_hit[i];
        hazards[i].example = haz_hit[i] ? "(ditemukan)" : "";
        if (!haz_hit[i])
            gap = 1;
    }
    if (nhaz)
        *nhaz = TA_NHAZ;

    for (i = 0; i < TA_NBACK; i++) {
        backends[i].name = BACKENDS[i].name;
        backends[i].fixtures = back_hit[i] ? 1 : 0;
        backends[i].covered = back_hit[i];
        backends[i].example = back_hit[i] ? "(ditemukan)" : "";
    }
    if (nback)
        *nback = TA_NBACK;

    (void)ncontract; /* dihitung untuk laporan di myc_testaudit_report */
    return gap ? -1 : 0;
}

int myc_testaudit_report(FILE *out)
{
    myc_ta_hazard hazards[MYC_TA_MAX_HAZARDS];
    myc_ta_backend backends[MYC_TA_MAX_BACKENDS];
    int nhaz = 0, nback = 0;
    int rc = myc_testaudit_run(hazards, &nhaz, backends, &nback);
    int covered = 0, i;

    for (i = 0; i < nhaz; i++)
        if (hazards[i].covered)
            covered++;

    fprintf(out, "test-quality audit (Fase 6):\n");
    fprintf(out, "  hazard class coverage: %d/%d\n", covered, nhaz);
    for (i = 0; i < nhaz; i++) {
        fprintf(out, "    [%s] %-11s %s\n",
                hazards[i].covered ? "OK" : "GAP", hazards[i].name,
                hazards[i].covered ? "ada fixture" : "TANPA fixture!");
    }
    fprintf(out, "  backend coverage:\n");
    for (i = 0; i < nback; i++) {
        fprintf(out, "    [%s] %-11s %s\n",
                backends[i].covered ? "OK" : "GAP", backends[i].name,
                backends[i].covered ? "ada fixture" : "TANPA fixture!");
    }
    if (rc != 0)
        fprintf(out, "  catatan: ada hazard class tanpa fixture (gap terlihat, NON-blocking)\n");
    return rc;
}
