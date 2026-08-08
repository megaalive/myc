/* perturb.c -- Environment Perturbation (Fase 6, Self-Challenge)
 *
 * Setelah run utama, jalankan ulang binary verification dengan env yang
 * diubah: TZ, locale (LC_ALL), PATH (disempitkan), HOME/TERM. Bandingkan
 * stdout (sha256) + exit code + deteksi sanitizer dengan baseline.
 * Perbedaan = program env-sensitive (observasi; hasil verifikasi bisa
 * berbeda di mesin lain). NON-blocking.
 */
#include "perturb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proc.h"
#include "sha256.h"

typedef struct {
    const char *name;
    const char *const *kvs;   /* override env "KEY=VALUE", NULL-terminated */
} perturb_variant;

static const char *KVS_TZ[] = { "TZ=UTC+14", NULL };
static const char *KVS_LC[] = { "LC_ALL=tr_TR.UTF-8", NULL };
static const char *KVS_PATH[] = { "PATH=/nonexistent-path-myc-perturb", NULL };
static const char *KVS_HOME[] = {
    "HOME=/nonexistent-home-myc-perturb", "TERM=dumb", NULL
};

static const perturb_variant VARIANTS[] = {
    { "TZ", KVS_TZ },
    { "locale", KVS_LC },
    { "PATH", KVS_PATH },
    { "HOME/TERM", KVS_HOME },
};

#define PERTURB_NVAR ((int)(sizeof(VARIANTS) / sizeof(VARIANTS[0])))

static void perturb_sha(const char *text, char out[65])
{
    sha256_hex(text ? text : "", text ? strlen(text) : 0, out);
}

int myc_perturb_gate(const myc_request *req, myc_result *res,
                     const char *exe_path, const char *cwd,
                     const char *const *base_env,
                     const void *stdin_data, size_t stdin_len)
{
    char base_sha[65];
    char changed_names[256];
    char report[1024];
    size_t roff = 0;
    int nbase = 0;
    int changed = 0, ran = 0;
    int i;

    if (!exe_path || !req->perturb)
        return 0;
    perturb_sha(res->run_stdout_text, base_sha);
    changed_names[0] = '\0';
    while (base_env && base_env[nbase])
        nbase++;

    for (i = 0; i < PERTURB_NVAR; i++) {
        const perturb_variant *v = &VARIANTS[i];
        const char **env = NULL;
        const char **run_argv = NULL;
        myc_proc_request preq;
        myc_proc_result pres;
        char out_sha[65];
        int n = 0, j;
        size_t kv_count = 0;
        size_t need;
        int differ;

        for (j = 0; v->kvs[j]; j++)
            kv_count++;
        need = (size_t)nbase + kv_count + 1;
        env = (const char **)malloc(sizeof(char *) * need);
        run_argv = (const char **)malloc(sizeof(char *) * 2);
        if (!env || !run_argv) {
            free(env);
            free(run_argv);
            break;
        }
        for (j = 0; j < nbase; j++)
            env[n++] = base_env[j];
        for (j = 0; v->kvs[j]; j++)
            env[n++] = v->kvs[j];
        env[n] = NULL;

        run_argv[0] = exe_path;
        run_argv[1] = NULL;

        memset(&preq, 0, sizeof(preq));
        preq.argv = run_argv;
        preq.cwd = cwd;
        preq.stdin_data = stdin_data;
        preq.stdin_len = stdin_len;
        preq.timeout_ms = req->timeout_ms;
        preq.max_output_bytes = req->max_output_bytes ?
                                req->max_output_bytes : 65536;
        preq.env = env;

        ran++;
        if (myc_proc_run(&preq, &pres)) {
            perturb_sha(pres.stdout_data, out_sha);
            differ = (pres.exit_code != res->exit_code) ||
                     (strcmp(out_sha, base_sha) != 0) ||
                     ((int)pres.sanitizer_detected !=
                      res->run_sanitizer_detected);
            if (differ) {
                changed++;
                if (changed_names[0])
                    strncat(changed_names, ", ",
                            sizeof(changed_names) - strlen(changed_names) - 1);
                strncat(changed_names, v->name,
                        sizeof(changed_names) - strlen(changed_names) - 1);
            }
            myc_proc_result_free(&pres);
        }
        free(env);
        free(run_argv);
    }

    res->perturb_ran = 1;
    res->perturb_changed = changed;

    roff += (size_t)snprintf(report + roff, sizeof(report) - roff,
        "perturb (Fase 6): %s -- %d env diubah, %d berbeda dari baseline",
        changed == 0 ? "DETERMINISTIK lintas env" :
                       "ENV-SENSITIVE (hasil berubah)",
        ran, changed);
    if (changed > 0 && changed_names[0])
        roff += (size_t)snprintf(report + roff, sizeof(report) - roff,
                                 " -- env: %s", changed_names);
    if (roff < sizeof(report)) {
        res->perturb_report = myc_result_arena_dup(res, report, 0);
        myc_result_add_evidence(res, MYC_GATE_RUNTIME,
                                MYC_EVIDENCE_DIAGNOSTIC,
                                res->perturb_report);
    }
    return 0;
}
