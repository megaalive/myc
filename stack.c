/*
 * stack.c -- Gate Stack Budget Analyzer (C2, --stack, DS-10).
 *
 * Alur:
 *   1. Tulis source ke file temp, jalankan `gcc -c -O2 -fstack-usage
 *      -Wvla` (argv eksplisit, no shell).
 *   2. Parse `*.su` (gcc -fstack-usage): `file.c:func:size:align` ->
 *      frame per fungsi (bytes).
 *   3. Parse call graph dari source (definisi fungsi top-level + panggilan
 *      ident(...) di dalam body).
 *   4. DFS worst-path dari root ("main", fallback "_start" / fungsi yang
 *      tak dipanggil), DP + cycle detection (rekursi = komponen tak
 *      terbatas), deteksi alloca (substring) dan VLA (warning -Wvla).
 *   5. Bandingkan worst dengan budget (--stack-budget, default 4096).
 *
 * Semua hasil = OBSERVASI non-blocking (claim compiler: static worst-case
 * != dynamic worst-case; DS-10: bedakan static estimate vs unbounded).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stack.h"
#include "proc.h"
#include "sha256.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <direct.h>
#include <process.h>
#define stk_mkdir(path) _mkdir(path)
#define stk_rmdir(path) _rmdir(path)
#define stk_getpid() _getpid()
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define stk_mkdir(path) mkdir(path, 0700)
#define stk_rmdir(path) rmdir(path)
#define stk_getpid() getpid()
#endif

#define STK_MAX_FUNCS   256
#define STK_MAX_CALLS   512
#define STK_MAX_NAME    128
#define STK_DEF_BUDGET  4096
#define STK_MAX_PATH    32          /* kedalaman path DFS */

/* Tambah diagnostic ringan (string disalin ke arena hasil). */
static void add_diag_stk(myc_result *res, const char *msg)
{
    char *slot;
    if (res->diag_count >= MYC_MAX_DIAGNOSTICS)
        return;
    slot = myc_result_arena_dup(res, msg, 0);
    if (!slot)
        return;
    res->diags[res->diag_count].line = 0;
    res->diags[res->diag_count].col = 0;
    res->diags[res->diag_count].message = slot;
    res->diags[res->diag_count].confidence = MYC_CONF_OBSERVATION;
    res->diag_count++;
}

/* Satu fungsi hasil parse source. */
typedef struct {
    char name[STK_MAX_NAME];
    int  has_frame;                 /* ada entry di .su */
    long frame;                     /* bytes dari -fstack-usage */
    int  first_call[STK_MAX_CALLS]; /* index callee */
    int  ncall;
} stk_func;

typedef struct {
    char name[STK_MAX_NAME];
    long frame;
} stk_su_entry;

/* --- parse source: definisi fungsi top-level + panggilan --- */

static int stk_ident_start(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
static int stk_ident_char(int c)
{
    return stk_ident_start(c) || (c >= '0' && c <= '9');
}

/* Identifier tepat sebelum posisi `before` (lewati spasi). */
static int stk_ident_before(const char *s, size_t before,
                            char *out, size_t outcap)
{
    size_t end = before, start, n;
    while (end > 0 && (s[end - 1] == ' ' || s[end - 1] == '\t'))
        end--;
    start = end;
    while (start > 0 && stk_ident_char((unsigned char)s[start - 1]))
        start--;
    if (start == end)
        return 0;
    n = end - start;
    if (n >= outcap)
        n = outcap - 1;
    memcpy(out, s + start, n);
    out[n] = '\0';
    return 1;
}

/* Scan source: isi funcs[] (definisi top-level) + panggilan antar fungsi.
 * Mirip scanner kontrak driver tapi untuk SEMUA fungsi (tidak perlu
 * //@), karena stack analyzer bekerja pada seluruh program. */
static int stk_scan_source(const char *src, size_t len, stk_func *funcs,
                           int maxf)
{
    int    nf = 0;
    size_t i = 0;
    int    paren = 0, brace = 0;
    int    sig_closed = 0;
    char   name[STK_MAX_NAME];
    int    has_name = 0;
    int    in_body = -1;            /* index fungsi yang body-nya aktif */
    size_t body_start = 0;

    while (i < len) {
        char c = src[i];
        if (c == '/' && i + 1 < len && src[i + 1] == '/') {
            while (i < len && src[i] != '\n')
                i++;
            continue;
        }
        if (c == '/' && i + 1 < len && src[i + 1] == '*') {
            size_t e = i + 2;
            while (e + 1 < len && !(src[e] == '*' && src[e + 1] == '/'))
                e++;
            i = (e + 1 < len) ? e + 2 : e;
            continue;
        }
        if (c == '"' || c == '\'') {
            char q = c;
            size_t j = i + 1;
            while (j < len) {
                if (src[j] == '\\' && j + 1 < len)
                    j += 2;
                else if (src[j] == q) {
                    j++;
                    break;
                } else
                    j++;
            }
            i = j;
            continue;
        }
        if (c == '(') {
            if (brace == 0 && paren == 0)
                has_name = stk_ident_before(src, i, name, sizeof(name));
            paren++;
        } else if (c == ')') {
            if (paren > 0)
                paren--;
            if (paren == 0 && brace == 0 && has_name)
                sig_closed = 1;
        } else if (c == '{') {
            if (brace == 0 && paren == 0 && sig_closed && has_name) {
                if (nf < maxf) {
                    stk_func *f = &funcs[nf];
                    memset(f, 0, sizeof(*f));
                    snprintf(f->name, sizeof(f->name), "%s", name);
                    in_body = nf;
                    nf++;
                } else
                    in_body = -1;
            }
            brace++;
            if (in_body >= 0 && brace == 1)
                body_start = i;
        } else if (c == '}') {
            if (brace > 0)
                brace--;
            if (brace == 0 && in_body >= 0)
                in_body = -1;
            sig_closed = 0;
            has_name = 0;
        } else if (c == ';') {
            if (paren == 0 && brace == 0)
                sig_closed = 0, has_name = 0;
        } else if (stk_ident_start((unsigned char)c) && in_body >= 0 &&
                   i > body_start) {
            /* panggilan fungsi: ident diikuti '(' di dalam body */
            size_t j = i;
            char   cname[STK_MAX_NAME];
            size_t cj;
            size_t n;
            while (j < len && stk_ident_char((unsigned char)src[j]))
                j++;
            cj = j;
            while (cj < len && (src[cj] == ' ' || src[cj] == '\t'))
                cj++;
            if (cj < len && src[cj] == '(') {
                int   target = -1;
                int   k;
                n = j - i;
                if (n >= sizeof(cname))
                    n = sizeof(cname) - 1;
                memcpy(cname, src + i, n);
                cname[n] = '\0';
                for (k = 0; k < nf; k++) {
                    if (strcmp(funcs[k].name, cname) == 0) {
                        target = k;
                        break;
                    }
                }
                if (target >= 0 && funcs[in_body].ncall < STK_MAX_CALLS) {
                    int dup = 0;
                    int m;
                    for (m = 0; m < funcs[in_body].ncall; m++)
                        if (funcs[in_body].first_call[m] == target) {
                            dup = 1;
                            break;
                        }
                    if (!dup)
                        funcs[in_body]
                            .first_call[funcs[in_body].ncall++] = target;
                }
            }
            i = j - 1;
        }
        i++;
    }
    return nf;
}

/* --- parse .su (gcc -fstack-usage) --- */

static int stk_parse_su(const char *path, stk_su_entry *entries, int maxe)
{
    FILE *f;
    char  line[1024];
    int   n = 0;
    f = fopen(path, "rb");
    if (!f)
        return 0;
    /* Format gcc -fstack-usage:
     *   source.c:LINE:COL:func<TAB>bytes<TAB>alignment
     * (alignment boleh kosong). Fungsi bisa memuat ':' (mis. label?). */
    while (fgets(line, sizeof(line), f) && n < maxe) {
        char *tab = strchr(line, '\t');
        char *colon;
        char *fname;
        long  size;
        if (!tab)
            continue;
        *tab = '\0';
        size = strtol(tab + 1, NULL, 10);
        /* nama fungsi = setelah ':' TERAKHIR di kolom pertama */
        colon = strrchr(line, ':');
        if (!colon)
            continue;
        fname = colon + 1;
        /* nama bisa dibungkus kuot (nama rusak C++/asm) */
        if (*fname == '"' )
            fname++;
        if (*fname && *fname != '\r' && *fname != '\n') {
            char namebuf[STK_MAX_NAME];
            size_t flen = strlen(fname);
            if (flen >= sizeof(namebuf))
                flen = sizeof(namebuf) - 1;
            memcpy(namebuf, fname, flen);
            namebuf[flen] = '\0';
            /* buang '\r' bila ada */
            if (flen > 0 && namebuf[flen - 1] == '\r')
                namebuf[flen - 1] = '\0';
            snprintf(entries[n].name, sizeof(entries[n].name), "%s",
                     namebuf);
            entries[n].frame = size;
            n++;
        }
    }
    fclose(f);
    return n;
}

/* --- DFS worst-path + cycle detection --- */

static long stk_dfs(const stk_func *funcs, int nf, int fi, int depth,
                    int *visited, char path[][STK_MAX_NAME], int *npath,
                    char worst_path[][STK_MAX_NAME], int *worst_len,
                    long *worst_sum, long cur_sum, int *recursion)
{
    long best = funcs[fi].has_frame ? funcs[fi].frame : 0;
    int  i;
    long childbest = 0;
    if (depth >= STK_MAX_PATH)
        return best;
    if (visited[fi]) {
        *recursion = 1;             /* cycle di call graph */
        return best;
    }
    visited[fi] = 1;
    snprintf(path[*npath], STK_MAX_NAME, "%s", funcs[fi].name);
    (*npath)++;
    for (i = 0; i < funcs[fi].ncall; i++) {
        int ci = funcs[fi].first_call[i];
        long c = stk_dfs(funcs, nf, ci, depth + 1, visited, path, npath,
                         worst_path, worst_len, worst_sum,
                         cur_sum + best, recursion);
        if (c > childbest)
            childbest = c;
    }
    /* catat path TERBAIK sebelum pop (npath sudah memuat fungsi ini) */
    if (best + childbest > *worst_sum && *npath <= STK_MAX_PATH) {
        long total = best + childbest;
        int  k;
        if (total > *worst_sum) {
            *worst_sum = total;
            *worst_len = *npath;
            for (k = 0; k < *npath; k++)
                snprintf(worst_path[k], STK_MAX_NAME, "%s", path[k]);
        }
    }
    (*npath)--;
    visited[fi] = 0;
    return best + childbest;
}

/* --- gate --- */

int myc_stack_gate(const myc_request *req, const char *source,
                   size_t source_len, myc_result *res)
{
    char       *gcc_path = NULL;
    char       *tmp_dir = NULL;
    char       *src_path = NULL, *su_path = NULL, *obj_path = NULL;
    char       *dirbuf = NULL;
    FILE       *fsrc = NULL;
    int         nf = 0;
    stk_func    funcs[STK_MAX_FUNCS];
    stk_su_entry su[STK_MAX_FUNCS];
    int         nsu = 0;
    int         visited[STK_MAX_FUNCS];
    char        path[STK_MAX_PATH][STK_MAX_NAME];
    char        worst_path[STK_MAX_PATH][STK_MAX_NAME];
    int         npath = 0, worst_len = 0;
    long        worst_sum = 0;
    int         recursion = 0, alloca = 0, vla = 0, unknown = 0;
    long        budget = req->stack_budget > 0 ? req->stack_budget
                                               : STK_DEF_BUDGET;
    int         root = -1, i, k;
    char        rep[4096];
    size_t      roff = 0;
    myc_proc_request preq;
    myc_proc_result  pres;
    const char *argv_b[16];
    int         narg = 0;
    long        dynamic_comp = 0;

    myc_gate_set_status(res, MYC_GATE_STACK, MYC_GATE_NOT_APPLICABLE, NULL);
    memset(funcs, 0, sizeof(funcs));
    memset(su, 0, sizeof(su));
    memset(visited, 0, sizeof(visited));
    memset(path, 0, sizeof(path));
    memset(worst_path, 0, sizeof(worst_path));

    /* 1. scan source -> call graph */
    nf = stk_scan_source(source, source_len, funcs, STK_MAX_FUNCS);
    if (nf == 0) {
        add_diag_stk(res, "stack di-skip: tanpa fungsi top-level");
        myc_gate_set_status(res, MYC_GATE_STACK, MYC_GATE_NOT_APPLICABLE,
                            "tanpa fungsi");
        myc_result_add_evidence(res, MYC_GATE_STACK, MYC_EVIDENCE_SKIP,
                                "stack: tanpa fungsi");
        return 0;
    }

    /* 2. gcc + temp dir */
    gcc_path = myc_find_gcc(req->gcc_program);
    if (!gcc_path) {
        res->err = MYC_ERR_GCC_NOT_FOUND;
        myc_gate_set_status(res, MYC_GATE_STACK, MYC_GATE_UNAVAILABLE,
                            "gcc tidak ditemukan");
        myc_result_add_evidence(res, MYC_GATE_STACK, MYC_EVIDENCE_SKIP,
                                "stack di-skip: gcc hilang");
        return 0;
    }
    {
        char buf[512];
        int  r;
        snprintf(buf, sizeof(buf), ".myc_stk_%d", stk_getpid());
        tmp_dir = myc_strdup(buf);
        if (!tmp_dir) {
            res->err = MYC_ERR_INTERNAL;
            myc_free(gcc_path);
            return 0;
        }
        stk_mkdir(tmp_dir);
        r = snprintf(buf, sizeof(buf), "%s/myc_src.c", tmp_dir);
        if (r > 0)
            src_path = myc_strdup(buf);
        r = snprintf(buf, sizeof(buf), "%s/myc_src.su", tmp_dir);
        if (r > 0)
            su_path = myc_strdup(buf);
        r = snprintf(buf, sizeof(buf), "%s/myc_src.o", tmp_dir);
        if (r > 0)
            obj_path = myc_strdup(buf);
        if (!src_path || !su_path || !obj_path) {
            res->err = MYC_ERR_INTERNAL;
            goto out;
        }
    }
    fsrc = fopen(src_path, "wb");
    if (!fsrc) {
        res->err = MYC_ERR_INTERNAL;
        goto out;
    }
    fwrite(source, 1, source_len, fsrc);
    fclose(fsrc);
    fsrc = NULL;

    /* 3. gcc -c -O2 -fstack-usage -Wvla */
    argv_b[narg++] = gcc_path;
    argv_b[narg++] = "-c";
    argv_b[narg++] = "-O2";
    argv_b[narg++] = "-fstack-usage";
    argv_b[narg++] = "-Wvla";
    argv_b[narg++] = "-w";          /* jangan banjir stderr non-VLA */
    argv_b[narg++] = "myc_src.c";
    argv_b[narg++] = "-o";
    argv_b[narg++] = "myc_src.o";
    argv_b[narg] = NULL;
    memset(&preq, 0, sizeof(preq));
    preq.argv = argv_b;
    preq.cwd = tmp_dir;             /* .su dibuat di direktori kerja */
    preq.timeout_ms = req->timeout_ms;
    preq.max_output_bytes = req->max_output_bytes > 0
                                ? (size_t)req->max_output_bytes
                                : MYC_MAX_OUTPUT_BYTES;
    if (!myc_proc_run(&preq, &pres)) {
        res->err = pres.timed_out ? MYC_ERR_TIMEOUT : MYC_ERR_EXECUTE_FAILED;
        myc_proc_result_free(&pres);
        goto out;
    }
    res->duration_ms += pres.duration_ms;
    if (pres.exit_code != 0) {
        /* compile gagal: biar gate compile yang melaporkan; skip analisis */
        myc_proc_result_free(&pres);
        myc_gate_set_status(res, MYC_GATE_STACK, MYC_GATE_NOT_APPLICABLE,
                            "compile gagal");
        myc_result_add_evidence(res, MYC_GATE_STACK, MYC_EVIDENCE_SKIP,
                                "stack di-skip: compile gagal");
        goto out_ok;
    }
    if (pres.stderr_data &&
        (strstr(pres.stderr_data, "variable length array") ||
         strstr(pres.stderr_data, "VLA")))
        vla = 1;
    myc_proc_result_free(&pres);

    /* 4. parse .su */
    nsu = stk_parse_su(su_path, su, STK_MAX_FUNCS);
    for (i = 0; i < nf; i++) {
        for (k = 0; k < nsu; k++) {
            if (strcmp(funcs[i].name, su[k].name) == 0) {
                funcs[i].frame = su[k].frame;
                funcs[i].has_frame = 1;
                break;
            }
        }
    }
    /* 5. deteksi alloca (substring di source) */
    {
        const char *p = source;
        while ((p = strstr(p, "alloca")) != NULL) {
            alloca = 1;
            p += 6;
        }
    }
    /* 6. root: main, fallback _start, fallback fungsi yang tak dipanggil */
    for (i = 0; i < nf; i++)
        if (strcmp(funcs[i].name, "main") == 0)
            root = i;
    if (root < 0)
        for (i = 0; i < nf; i++)
            if (strcmp(funcs[i].name, "_start") == 0)
                root = i;
    if (root < 0) {
        /* fungsi yang tidak pernah dipanggil fungsi lain */
        for (i = 0; i < nf && root < 0; i++) {
            int called = 0, j;
            for (j = 0; j < nf; j++) {
                int m;
                for (m = 0; m < funcs[j].ncall; m++)
                    if (funcs[j].first_call[m] == i)
                        called = 1;
            }
            if (!called)
                root = i;
        }
    }
    /* 7. DFS worst-path */
    if (root >= 0)
        stk_dfs(funcs, nf, root, 0, visited, path, &npath,
                worst_path, &worst_len, &worst_sum, 0, &recursion);
    /* 8. unknown = panggilan ke fungsi tanpa frame (eksternal/inline) */
    for (i = 0; i < nf; i++) {
        int m;
        for (m = 0; m < funcs[i].ncall; m++) {
            int ci = funcs[i].first_call[m];
            if (!funcs[ci].has_frame)
                unknown++;
        }
    }
    /* 9. report */
    res->ran_stack = 1;
    res->stack_budget = budget;
    res->stack_worst_bytes = worst_sum;
    res->stack_recursion = recursion;
    res->stack_alloca = alloca;
    res->stack_vla = vla;
    res->stack_unknown = unknown;
    roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
        "stack (C2): budget %ld B (profil target)\\n", budget);
    if (root >= 0) {
        roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
            "  worst path : ");
        for (i = 0; i < worst_len; i++) {
            int r = snprintf(rep + roff, sizeof(rep) - roff, "%s%s",
                             i ? " -> " : "", worst_path[i]);
            if (r > 0)
                roff += (size_t)r;
            if (roff >= sizeof(rep))
                roff = sizeof(rep) - 1;
        }
        {
            int r = snprintf(rep + roff, sizeof(rep) - roff,
                " = %ld B (%ld%%)\\n", worst_sum,
                budget > 0 ? (worst_sum * 100) / budget : 0);
            if (r > 0)
                roff += (size_t)r;
            if (roff >= sizeof(rep))
                roff = sizeof(rep) - 1;
        }
        /* simpan path teks */
        {
            char pb[1024];
            size_t po = 0;
            for (i = 0; i < worst_len; i++) {
                int r = snprintf(pb + po, sizeof(pb) - po, "%s%s",
                                 i ? " -> " : "", worst_path[i]);
                if (r > 0)
                    po += (size_t)r;
                if (po >= sizeof(pb))
                    po = sizeof(pb) - 1;
            }
            res->stack_worst_path = myc_result_arena_dup(res, pb, 0);
        }
    } else {
        roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
            "  worst path : (tanpa root main/_start)\\n");
    }
    if (recursion)
        roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
            "  recursion  : cycle di call graph -- stack tak terbatas\\n");
    if (alloca)
        roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
            "  alloca     : dinamis, tak terhitung\\n");
    if (vla)
        roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
            "  VLA        : variable-length array terdeteksi (gcc -Wvla)\\n");
    if (unknown > 0)
        roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
            "  unknown    : %d panggilan ke fungsi tanpa frame .su\\n",
            unknown);
    roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
        "  catatan    : static worst-case != dynamic worst-case\\n");
    if (roff >= sizeof(rep))
        roff = sizeof(rep) - 1;
    res->stack_report = myc_result_arena_dup(res, rep, 0);
    if (worst_sum > budget || recursion) {
        if (worst_sum > budget)
            dynamic_comp = 1;
        add_diag_stk(res, "stack: worst-case melebihi budget atau ada "
                          "rekursi (observasi, non-blocking)");
        myc_gate_set_status(res, MYC_GATE_STACK,
                            MYC_GATE_COMPLETED_OBSERVATIONS,
                            "stack over budget / rekursi (observasi)");
        myc_result_add_evidence(res, MYC_GATE_STACK,
                                MYC_EVIDENCE_DIAGNOSTIC,
                                "stack: over budget / recursion "
                                "(observasi non-blocking)");
    } else {
        myc_gate_set_status(res, MYC_GATE_STACK, MYC_GATE_COMPLETED_CLEAN,
                            "stack dalam budget");
        myc_result_add_evidence(res, MYC_GATE_STACK,
                                MYC_EVIDENCE_GATE_END,
                                "stack: dalam budget");
    }
    (void)dynamic_comp;

out_ok:
    {
        int r = 1;
        (void)r;
    }
out:
    if (fsrc)
        fclose(fsrc);
    myc_free(dirbuf);
    myc_free(gcc_path);
    if (src_path) {
        remove(src_path);
        myc_free(src_path);
    }
    if (su_path) {
        remove(su_path);
        myc_free(su_path);
    }
    if (obj_path) {
        remove(obj_path);
        myc_free(obj_path);
    }
    if (tmp_dir) {
        stk_rmdir(tmp_dir);
        myc_free(tmp_dir);
    }
    return res->ran_stack ? 1 : 0;
}
