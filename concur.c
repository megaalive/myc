/* concur.c -- Concurrency Schedule / Lock-Order Probe (Fase 6)
 *
 * 1. Lock-order statis: parse source (strip komentar), lacak brace depth
 *    untuk membagi region fungsi, kumpulkan urutan mutex yang di-lock per
 *    region, lalu cari pasangan dengan urutan terbalik antar region
 *    (A->B di f1 vs B->A di f2) = lock-order inversion (observasi).
 * 2. TSan runtime: bila source memanggil pthread_create/CreateThread dan
 *    clang tersedia, build -fsanitize=thread + run; "data race" di
 *    output = race terdeteksi (observasi kuat; NON-blocking).
 */
#include "concur.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proc.h"

typedef struct {
    char name[64];        /* nama mutex (tanpa & atau *) */
} concur_mutex;

typedef struct {
    int  nlock;           /* jumlah lock berurutan dalam region */
    int  locks[8];        /* indeks ke concur_mutex[] */
    char func[64];        /* nama fungsi region (heuristik) */
} concur_region;

typedef struct {
    concur_mutex mutex[MYC_CONCUR_MAX_LOCKS];
    int          nmutex;
    concur_region region[16];
    int          nregion;
} concur_state;

/* Strip komentar // dan blok-komentar dari satu baris (in-place-safe:
 * hasil ke out, panjang <= src). */
static void concur_strip_line(char *dst, const char *src, size_t cap)
{
    size_t i = 0, o = 0;
    int in_str = 0;
    while (src[i] && o + 1 < cap) {
        if (in_str) {
            dst[o++] = src[i];
            if (src[i] == '"' && (i == 0 || src[i - 1] != '\\'))
                in_str = 0;
            i++;
        } else if (src[i] == '"') {
            in_str = 1;
            dst[o++] = src[i++];
        } else if (src[i] == '/' && src[i + 1] == '/') {
            break;
        } else if (src[i] == '/' && src[i + 1] == '*') {
            /* komentar blok: lewati sampai penutup komentar */
            i += 2;
            while (src[i] && !(src[i] == '*' && src[i + 1] == '/'))
                i++;
            if (src[i])
                i += 2;
        } else {
            dst[o++] = src[i++];
        }
    }
    dst[o] = '\0';
}

/* Cari lock `pthread_mutex_lock(&X)` / `mtx_lock(&X)` /
 * `EnterCriticalSection(&X)` PERTAMA pada/atau setelah `from`. Kalau
 * ketemu: nama mutex ke out, *next = posisi setelah panggilan (agar
 * lock berikutnya di baris yang sama tetap terdeteksi). */
static int concur_next_lock(const char *from,
                            char *out, size_t outcap, const char **next)
{
    static const char *const LOCKERS[] = {
        "pthread_mutex_lock", "mtx_lock", "EnterCriticalSection", NULL
    };
    const char *best = NULL;
    const char *best_end = NULL;
    int k;
    for (k = 0; LOCKERS[k]; k++) {
        const char *p = from ? strstr(from, LOCKERS[k]) : NULL;
        if (p && (!best || p < best)) {
            const char *q = strchr(p, '(');
            if (q) {
                const char *r = q + 1;
                const char *s;
                while (*r == ' ' || *r == '&' || *r == '*')
                    r++;
                s = r;
                while (*s && *s != ')' && *s != ' ' && *s != ',' &&
                       *s != ';')
                    s++;
                if (s > r) {
                    best = p;
                    best_end = s;
                }
            }
        }
    }
    if (best) {
        size_t n = (size_t)(best_end - best);
        const char *q = best;
        const char *r;
        /* nama mutex = argumen (setelah '(' dan '&') */
        q = strchr(best, '(');
        r = q + 1;
        while (*r == ' ' || *r == '&' || *r == '*')
            r++;
        n = 0;
        while (r[n] && r[n] != ')' && r[n] != ' ' && r[n] != ',' &&
               r[n] != ';' && n + 1 < outcap)
            n++;
        if (n > 0) {
            memcpy(out, r, n);
            out[n] = '\0';
            *next = best_end;
            return 1;
        }
    }
    return 0;
}

/* Deteksi nama fungsi dari baris: token sebelum '(' PERTAMA (bukan
 * terakhir -- baris satu-baris berisi banyak panggilan). */
static void concur_guess_func(const char *line, char *out, size_t outcap)
{
    const char *p = strchr(line, '(');
    const char *q;
    size_t n = 0;
    if (!p)
        return;
    q = p;
    while (q > line && (q[-1] == ' ' || q[-1] == '\t'))
        q--;
    while (q > line && q[-1] != ' ' && q[-1] != '\t' && q[-1] != '{' &&
           q[-1] != ';' && n + 1 < outcap) {
        q--;
        n++;
    }
    if (n == 0)
        return;
    memcpy(out, q, n);
    out[n] = '\0';
}

static int concur_mutex_id(concur_state *st, const char *name)
{
    int i;
    for (i = 0; i < st->nmutex; i++)
        if (strcmp(st->mutex[i].name, name) == 0)
            return i;
    if (st->nmutex >= MYC_CONCUR_MAX_LOCKS)
        return -1;
    snprintf(st->mutex[st->nmutex].name,
             sizeof(st->mutex[st->nmutex].name), "%s", name);
    return st->nmutex++;
}

/* Pass 1: kumpulkan region fungsi + urutan lock. Brace depth dilacak
 * per KARAKTER (bukan net per baris) agar fungsi satu-baris seperti
 * `void f(void) { lock(&a); lock(&b); ... }` terbuka sebagai region. */
static void concur_collect(const char *source, concur_state *st)
{
    char *work = (char *)myc_malloc(strlen(source) + 1);
    char *cur;
    int depth = 0;
    char pending_func[64] = "";

    if (!work)
        return;
    strcpy(work, source);

    /* Split baris manual (strtok_r adalah POSIX: tersembunyi di glibc
     * dengan -std=c11 -- tidak portabel). */
    cur = work;
    while (cur && *cur) {
        char *nl = strchr(cur, '\n');
        char linebuf[600];
        const char *line = cur;
        char cleaned[512];
        char mname[64];
        int i;
        size_t linelen;

        if (nl)
            *nl = '\0';
        linelen = strlen(cur);
        if (linelen > sizeof(linebuf) - 1)
            linelen = sizeof(linebuf) - 1;
        memcpy(linebuf, cur, linelen);
        linebuf[linelen] = '\0';
        line = linebuf;

        concur_strip_line(cleaned, line, sizeof(cleaned));

        /* nama fungsi terduga pada baris ini (heuristik) */
        if (strchr(cleaned, '(') && !strstr(cleaned, "if (") &&
            !strstr(cleaned, "for (") && !strstr(cleaned, "while (") &&
            !strstr(cleaned, "switch (")) {
            char f[64] = "";
            concur_guess_func(cleaned, f, sizeof(f));
            if (f[0])
                snprintf(pending_func, sizeof(pending_func), "%s", f);
        }

        /* walk per karakter: buka region saat depth 0->1 */
        for (i = 0; cleaned[i]; i++) {
            if (cleaned[i] == '{') {
                depth++;
                if (depth == 1 && st->nregion < 16) {
                    concur_region *r = &st->region[st->nregion];
                    r->nlock = 0;
                    if (pending_func[0])
                        snprintf(r->func, sizeof(r->func), "%s",
                                 pending_func);
                    st->nregion++;
                }
            } else if (cleaned[i] == '}') {
                if (depth > 0)
                    depth--;
            }
        }

        /* semua lock dalam region saat ini (bisa >1 per baris) */
        if (st->nregion > 0) {
            const char *scan = cleaned;
            while (concur_next_lock(scan, mname, sizeof(mname), &scan)) {
                concur_region *r = &st->region[st->nregion - 1];
                int id = concur_mutex_id(st, mname);
                if (id >= 0 && r->nlock < 8)
                    r->locks[r->nlock++] = id;
            }
        }
        cur = nl ? nl + 1 : cur + strlen(cur);
    }
    myc_free(work);
}

/* Pass 2: cari lock-order inversion antar region. */
static int concur_find_inversion(const concur_state *st,
                                 char *report, size_t rcap)
{
    size_t off = 0;
    int a, b;
    for (a = 0; a < st->nregion; a++) {
        const concur_region *ra = &st->region[a];
        int i;
        for (i = 0; i + 1 < ra->nlock; i++) {
            int m1 = ra->locks[i];
            int m2 = ra->locks[i + 1];
            for (b = 0; b < st->nregion; b++) {
                const concur_region *rb = &st->region[b];
                int j;
                if (b == a)
                    continue;
                for (j = 0; j + 1 < rb->nlock; j++) {
                    if (rb->locks[j] == m2 && rb->locks[j + 1] == m1) {
                        off += (size_t)snprintf(
                            report + off, rcap - off,
                            "  LOCK-ORDER INVERSION: %s lock %s->%s, "
                            "%s lock %s->%s (potensi deadlock)\n",
                            ra->func, st->mutex[m1].name,
                            st->mutex[m2].name, rb->func,
                            st->mutex[m2].name, st->mutex[m1].name);
                        return (int)off;
                    }
                }
            }
        }
    }
    return (int)off;
}

static int concur_uses_threads(const char *source)
{
    return strstr(source, "pthread_create") != NULL ||
           strstr(source, "CreateThread") != NULL ||
           strstr(source, "_beginthreadex") != NULL;
}

/* TSan best-effort: build+run source dengan -fsanitize=thread. */
static int concur_tsan(const myc_request *req, const char *source,
                       size_t source_len, char *note, size_t note_cap)
{
    char *clang = myc_find_executable("clang");
    char tmp_src[520];
    char tmp_exe[520];
    const char *build_argv[16];
    const char *run_argv[2];
    myc_proc_request preq;
    myc_proc_result pres;
    int b, r;
    int race = 0;
    static int tno = 0;

    if (!clang) {
        snprintf(note, note_cap,
                 "  TSan runtime: clang tidak tersedia -- race tidak diuji "
                 "(tercatat, bukan kesunyian)");
        return 0;
    }
    snprintf(tmp_src, sizeof(tmp_src), "myc_con_src_%d.c", tno);
    snprintf(tmp_exe, sizeof(tmp_exe), "myc_con_exe_%d.exe", tno);
    tno++;

    {
        FILE *fsrc = fopen(tmp_src, "wb");
        if (!fsrc || fwrite(source, 1, source_len, fsrc) != source_len) {
            if (fsrc)
                fclose(fsrc);
            myc_free(clang);
            snprintf(note, note_cap,
                     "  TSan runtime: gagal menulis source temp");
            return 0;
        }
        fclose(fsrc);
    }

    b = 0;
    build_argv[b++] = clang;
    build_argv[b++] = "-std=c11";
    build_argv[b++] = "-O1";
    build_argv[b++] = "-g";
    build_argv[b++] = "-fsanitize=thread";
    build_argv[b++] = tmp_src;
    build_argv[b++] = "-o";
    build_argv[b++] = tmp_exe;
    build_argv[b] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = build_argv;
    preq.cwd = ".";
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = req->max_output_bytes ?
                            req->max_output_bytes : 65536;
    if (!myc_proc_run(&preq, &pres)) {
        myc_proc_result_free(&pres);
        myc_free(clang);
        remove(tmp_src);
        snprintf(note, note_cap,
                 "  TSan runtime: clang tidak mendukung -fsanitize=thread "
                 "di platform ini -- race tidak diuji");
        return 0;
    }
    b = pres.exit_code;
    myc_proc_result_free(&pres);
    if (b != 0) {
        myc_free(clang);
        remove(tmp_src);
        snprintf(note, note_cap,
                 "  TSan runtime: build -fsanitize=thread gagal (exit %d) "
                 "-- race tidak diuji", b);
        return 0;
    }

    run_argv[0] = tmp_exe;
    run_argv[1] = NULL;
    memset(&preq, 0, sizeof(preq));
    preq.argv = run_argv;
    preq.cwd = ".";
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = req->max_output_bytes ?
                            req->max_output_bytes : 65536;
    r = myc_proc_run(&preq, &pres);
    if (r) {
        const char *out = pres.stdout_data ? pres.stdout_data : "";
        const char *err = pres.stderr_data ? pres.stderr_data : "";
        if (strstr(out, "ThreadSanitizer") || strstr(err, "ThreadSanitizer") ||
            strstr(out, "data race") || strstr(err, "data race")) {
            race = 1;
        }
        myc_proc_result_free(&pres);
    }
    myc_free(clang);
    remove(tmp_src);
    remove(tmp_exe);
    if (race)
        snprintf(note, note_cap,
                 "  TSan runtime: DATA RACE terdeteksi (ThreadSanitizer)");
    else
        snprintf(note, note_cap,
                 "  TSan runtime: tidak ada race terdeteksi");
    return race;
}

int myc_concur_gate(const myc_request *req, myc_result *res,
                    const char *source, size_t source_len)
{
    concur_state st;
    char report[2048];
    size_t off = 0;
    int inv_off;
    int race = 0;
    char tsan_note[256] = "";

    if (!req->thread_probe)
        return 0;
    memset(&st, 0, sizeof(st));

    concur_collect(source, &st);

    off += (size_t)snprintf(report + off, sizeof(report) - off,
        "concur (Fase 6): %d fungsi, %d mutex dilacak\n",
        st.nregion, st.nmutex);

    inv_off = concur_find_inversion(&st, report + off,
                                    sizeof(report) - off);
    if (inv_off > 0) {
        off += (size_t)inv_off;
    } else if (st.nmutex > 0) {
        off += (size_t)snprintf(report + off, sizeof(report) - off,
            "  lock-order: tidak ada inversi urutan lock\n");
    }

    if (concur_uses_threads(source)) {
        race = concur_tsan(req, source, source_len,
                           tsan_note, sizeof(tsan_note));
        off += (size_t)snprintf(report + off, sizeof(report) - off,
                                "%s\n", tsan_note);
    } else {
        off += (size_t)snprintf(report + off, sizeof(report) - off,
            "  runtime: source tanpa thread -- TSan tidak diperlukan\n");
    }

    res->concur_ran = 1;
    res->concur_race_detected = race;
    if (off < sizeof(report)) {
        res->concur_report = myc_result_arena_dup(res, report, 0);
        myc_result_add_evidence(res, MYC_GATE_CONCUR,
                                race ? MYC_EVIDENCE_FINDING :
                                       MYC_EVIDENCE_DIAGNOSTIC,
                                res->concur_report);
        if (race) {
            myc_gate_set_status(res, MYC_GATE_CONCUR,
                                MYC_GATE_COMPLETED_OBSERVATIONS,
                                "data race terdeteksi (TSan, observasi)");
        } else {
            myc_gate_set_status(res, MYC_GATE_CONCUR,
                                MYC_GATE_COMPLETED_CLEAN,
                                "probe selesai (tanpa finding)");
        }
    }
    return 0;
}
