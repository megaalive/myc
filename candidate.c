/*
 * candidate.c -- Candidate Tournament dengan Pareto Frontier (Fase 7, SOL-10).
 *
 * Dari spec SOL-10: model sering menghasilkan 2-4 patch alternatif; memilih
 * berdasarkan "yang compile" terlalu lemah. Modul ini menilai tiap kandidat
 * pada DIMENSI terukur deterministik, lalu memilih kandidat pada Pareto
 * frontier (bukan satu skor ajaib). Lihat candidate.h utk daftar dimensi.
 *
 * Sifat (jujur, claim compiler):
 *   - Ukuran teks (churn, runtime_proxy, portability, readability) adalah
 *     PROKSI deterministik, bukan AST; perbedaan kecil antar kandidat
 *     sebaiknya tidak dianggap dominansi tunggal oleh harness.
 *   - stack_impact UNMEASURED di v1 (butuh gcc -fstack-usage per kandidat):
 *     gap TERLIHAT di laporan, bukan kesunyian (trust rule 4).
 *   - Anti-overclaim (spec): frontier = "tidak didominasi pada dimensi yang
 *     terukur", BUKAN klaim "terbaik secara umum". Harness/user memilih final.
 *   - NON-blocking: tidak mengubah verdict/exit program.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include "candidate.h"
#include "eig.h"
#include "frontier.h"
#include "contract.h"
#include "policy.h"
#include "json.h"

#define CAND_REPORT_CAP 8192

/* ---------- util teks deterministik ---------- */

/* FNV-1a 64-bit: hash baris utk churn. */
static uint64_t fnv1a(const char *s, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* Hash tiap baris non-kosong (strip \r). Gagal OOM -> *out=NULL, *n=0. */
static void hash_lines(const char *src, size_t len, uint64_t **out, int *n)
{
    uint64_t *arr = NULL;
    int cap = 0, cnt = 0;
    size_t i = 0;
    *out = NULL;
    *n = 0;
    while (i <= len) {
        size_t j = i;
        size_t sl;
        while (j < len && src[j] != '\n')
            j++;
        sl = j - i;
        if (sl > 0 && src[i + sl - 1] == '\r')
            sl--;
        if (sl > 0) {
            uint64_t h = fnv1a(src + i, sl);
            if (cnt >= cap) {
                int ncap = cap ? cap * 2 : 64;
                uint64_t *na =
                    (uint64_t *)realloc(arr, (size_t)ncap * sizeof(uint64_t));
                if (!na) {
                    free(arr);
                    return; /* *out tetap NULL = gagal */
                }
                arr = na;
                cap = ncap;
            }
            arr[cnt++] = h;
        }
        i = j + 1;
    }
    *out = arr;
    *n = cnt;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

/* Multiset delta dua kumpulan hash terurut. added = hash kandidat tak
 * tertutup baseline; removed = sebaliknya. Deterministik. */
static void line_delta(const uint64_t *base, int nb,
                       const uint64_t *cand, int nc,
                       int *added, int *removed)
{
    int i = 0, j = 0, add = 0, rem = 0;
    while (i < nb && j < nc) {
        if (base[i] < cand[j]) {
            rem++;
            i++;
        } else if (base[i] > cand[j]) {
            add++;
            j++;
        } else {
            int rb = 1, rc = 1;
            while (i + rb < nb && base[i + rb] == base[i])
                rb++;
            while (j + rc < nc && cand[j + rc] == cand[j])
                rc++;
            if (rb > rc)
                rem += rb - rc;
            else if (rc > rb)
                add += rc - rb;
            i += rb;
            j += rc;
        }
    }
    rem += nb - i;
    add += nc - j;
    *added = add;
    *removed = rem;
}

/* Ganti komentar (baris // dan blok) serta string/char literal dengan
 * spasi, pertahankan struktur baris. Deterministik. Caller free(). */
static char *strip_comments_strings(const char *src, size_t len)
{
    char *out = (char *)malloc(len + 1);
    size_t i;
    int in_block = 0, in_line = 0, in_str = 0, in_char = 0;
    if (!out)
        return NULL;
    for (i = 0; i < len; i++) {
        char c = src[i], n = i + 1 < len ? src[i + 1] : '\0';
        if (in_line) {
            out[i] = (c == '\n') ? '\n' : ' ';
            if (c == '\n')
                in_line = 0;
            continue;
        }
        if (in_block) {
            out[i] = (c == '\n') ? '\n' : ' ';
            if (c == '*' && n == '/') {
                out[i + 1] = ' ';
                i++;
                in_block = 0;
            }
            continue;
        }
        if (in_str) {
            out[i] = (c == '\n') ? '\n' : ' ';
            if (c == '\\') {
                out[i + 1] = ' ';
                i++;
            } else if (c == '"') {
                in_str = 0;
            }
            continue;
        }
        if (in_char) {
            out[i] = (c == '\n') ? '\n' : ' ';
            if (c == '\\') {
                out[i + 1] = ' ';
                i++;
            } else if (c == '\'') {
                in_char = 0;
            }
            continue;
        }
        if (c == '/' && n == '/') {
            out[i] = ' ';
            out[i + 1] = ' ';
            i++;
            in_line = 1;
            continue;
        }
        if (c == '/' && n == '*') {
            out[i] = ' ';
            out[i + 1] = ' ';
            i++;
            in_block = 1;
            continue;
        }
        if (c == '"') {
            out[i] = ' ';
            in_str = 1;
            continue;
        }
        if (c == '\'') {
            out[i] = ' ';
            in_char = 1;
            continue;
        }
        out[i] = c;
    }
    out[len] = '\0';
    return out;
}

static int is_kw_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/* Boundary kata: indeks sebelum/termasuk tidak boleh karakter identifier. */
static int boundary_ok(const char *s, long idx)
{
    return idx < 0 || !is_kw_char(s[idx]);
}

/* Proksi runtime: jumlah kata kunci loop (for/while/do) pada source yang
 * komentar/string-nya sudah dibuang. Proksi deterministik, bukan AST. */
static int count_loops(const char *clean)
{
    static const char *const kws[] = { "for", "while", "do" };
    int n = 0;
    size_t k;
    for (k = 0; k < sizeof(kws) / sizeof(kws[0]); k++) {
        const char *kw = kws[k];
        size_t kl = strlen(kw);
        const char *p = clean;
        while ((p = strstr(p, kw)) != NULL) {
            if (boundary_ok(clean, (long)(p - clean - 1)) &&
                !is_kw_char(p[kl]))
                n++;
            p += kl;
        }
    }
    return n;
}

/* Proksi portability: rasio #include whitelist policy (0..1000).
 * Parse per-baris (deterministik); include dalam komentar bisa ikut
 * terhitung -- proksi, bukan parser. */
static int portability_score(const char *src, size_t len)
{
    int total = 0, wl = 0;
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && src[j] != '\n')
            j++;
        {
            size_t k = i;
            while (k < j && (src[k] == ' ' || src[k] == '\t'))
                k++;
            if (k + 7 < j && src[k] == '#' &&
                strncmp(src + k + 1, "include", 7) == 0) {
                size_t m = k + 8;
                while (m < j && (src[m] == ' ' || src[m] == '\t'))
                    m++;
                if (m < j && (src[m] == '<' || src[m] == '"')) {
                    char name[128];
                    size_t p = 0;
                    char close = src[m] == '<' ? '>' : '"';
                    m++;
                    while (m < j && src[m] != close &&
                           p + 1 < sizeof(name))
                        name[p++] = src[m++];
                    name[p] = '\0';
                    total++;
                    if (p > 0 && myc_policy_allow_include(name))
                        wl++;
                }
            }
        }
        i = j + 1;
    }
    if (total == 0)
        return 1000; /* tanpa include = vakum portabel */
    return (int)((1000LL * wl) / total);
}

/* Proksi readability (0..1000): 1 - rasio baris non-kosong > 100 kolom. */
static int readability_score(const char *src, size_t len)
{
    int total = 0, long_lines = 0;
    size_t i = 0;
    while (i < len) {
        size_t j = i, k = i;
        int nonempty = 0;
        while (j < len && src[j] != '\n')
            j++;
        while (k < j) {
            if (src[k] != ' ' && src[k] != '\t' && src[k] != '\r') {
                nonempty = 1;
                break;
            }
            k++;
        }
        if (nonempty) {
            total++;
            if (j - i > 100)
                long_lines++;
        }
        i = j + 1;
    }
    if (total == 0)
        return 1000;
    return (int)((1000LL * (total - long_lines)) / total);
}

/* ---------- pengukuran per file ---------- */

/* Biaya verifikasi = jumlah biaya default (tabel DS-14) eksperimen utk
 * frontier yang masih terbuka (untested/unknown/observed). */
static int verification_cost(const myc_result *res)
{
    myc_frontier_set fs;
    int cost = 0, i;
    memset(&fs, 0, sizeof(fs));
    myc_frontier_build(res, &fs);
    for (i = 0; i < fs.count; i++) {
        const myc_frontier_item *it = &fs.items[i];
        if (strcmp(it->status, "untested") == 0 ||
            strcmp(it->status, "unknown") == 0 ||
            strcmp(it->status, "observed") == 0)
            cost += myc_eig_hazard_cost_ms(it->hazard);
    }
    myc_frontier_free(&fs);
    return cost;
}

/* Jalankan pipeline myc utk satu file dan isi dimensi terukur. measured_ok
 * = 0 bila pipeline gagal (source tak terbaca / MC_ERROR). */
static void measure_file(const char *path, const char *checked_header_dir,
                         myc_candidate_item *it)
{
    myc_source_input in;
    myc_request req;
    myc_result  res;
    const char *buf = NULL;
    size_t len = 0;
    int nf = 0;
    myc_error_code le;
    char *clean = NULL;

    it->dominated_by = -1;
    it->measured_ok = 0;

    memset(&in, 0, sizeof(in));
    in.kind = MYC_SOURCE_FILE;
    in.file_path = path;
    le = myc_source_load(&in, &buf, &len, &nf);
    if (le != MYC_ERR_NONE)
        return; /* tidak terbaca: tidak terukur (gap terlihat) */

    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_FILE;
    req.input.file_path = path;
    req.no_cache = 1;          /* deterministik: pipeline penuh selalu */
    req.run_lint = 1;
    req.checked_header_dir = checked_header_dir;
    myc_result_init(&res);
    myc_run(&req, &res);

    if (res.verdict == MC_ERROR) {
        myc_result_free(&res);
        if (nf)
            free((void *)buf);
        return;
    }

    it->measured_ok = 1;
    it->hard_gate = (res.verdict == MC_OK) ? 1 : 0;
    it->findings = res.lint_observations + res.negative_deviations;
    it->verification_cost = verification_cost(&res);

    clean = strip_comments_strings(buf, len);
    it->runtime_proxy = clean ? count_loops(clean) : 0;
    free(clean);

    it->portability = portability_score(buf, len);
    it->readability = readability_score(buf, len);

    myc_result_free(&res);
    if (nf)
        free((void *)buf);
}

/* ---------- Pareto ---------- */

/* A mendominasi B bila A >= B pada SEMUA dimensi terukur (arah
 * higher-better) dan ketat pada >= 1 dimensi. Tanpa bobot. */
static int cand_dominates(const myc_candidate_item *a,
                          const myc_candidate_item *b)
{
    int strict = 0;
    /* higher better: hard_gate, portability, readability */
    if (a->hard_gate != b->hard_gate && a->hard_gate < b->hard_gate)
        return 0;
    if (a->hard_gate > b->hard_gate)
        strict = 1;
    if (a->portability != b->portability &&
        a->portability < b->portability)
        return 0;
    if (a->portability > b->portability)
        strict = 1;
    if (a->readability != b->readability && a->readability < b->readability)
        return 0;
    if (a->readability > b->readability)
        strict = 1;
    /* lower better: findings, obligations_lost, churn, verification, runtime */
    if (a->findings > b->findings)
        return 0;
    if (a->findings < b->findings)
        strict = 1;
    if (a->obligations_lost > b->obligations_lost)
        return 0;
    if (a->obligations_lost < b->obligations_lost)
        strict = 1;
    if (a->churn_lines > b->churn_lines)
        return 0;
    if (a->churn_lines < b->churn_lines)
        strict = 1;
    if (a->verification_cost > b->verification_cost)
        return 0;
    if (a->verification_cost < b->verification_cost)
        strict = 1;
    if (a->runtime_proxy > b->runtime_proxy)
        return 0;
    if (a->runtime_proxy < b->runtime_proxy)
        strict = 1;
    return strict;
}

/* ---------- laporan teks ---------- */

static void bprintf(char *buf, size_t cap, int *off, const char *fmt, ...)
{
    int n;
    va_list ap;
    if ((size_t)*off >= cap - 1)
        return;
    va_start(ap, fmt);
    n = vsnprintf(buf + *off, cap - (size_t)*off, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if ((size_t)n >= cap - (size_t)*off) {
        buf[cap - 1] = '\0';
        *off = (int)cap - 1;
    } else {
        *off += n;
    }
}

static void item_line(char *buf, size_t cap, int *off,
                      const myc_candidate_item *it)
{
    if (!it->measured_ok) {
        bprintf(buf, cap, off, "  %s  (tidak terukur: pipeline gagal / OOM)\n",
                it->path);
        return;
    }
    bprintf(buf, cap, off,
            "  %s\n"
            "      hard_gate=%s findings=%d obligations_lost=%d churn=%d "
            "verification_cost=%d runtime_proxy=%d portability=%d/1000 "
            "readability=%d/1000 stack=unmeasured\n",
            it->path,
            it->hard_gate ? "OK" : "FAIL",
            it->findings, it->obligations_lost, it->churn_lines,
            it->verification_cost, it->runtime_proxy, it->portability,
            it->readability);
}

static char *build_report(const myc_candidate_set *cs)
{
    char *buf = (char *)malloc(CAND_REPORT_CAP);
    int off = 0;
    int i;
    if (!buf)
        return NULL;
    bprintf(buf, CAND_REPORT_CAP, &off,
            "candidate tournament (Fase 7, SOL-10): %d kandidat vs baseline "
            "%s\n",
            cs->ncandidates, cs->items[0].path);
    bprintf(buf, CAND_REPORT_CAP, &off,
            "dimensi terukur: %d dari 9 (stack_impact = UNMEASURED di v1: "
            "butuh gcc -fstack-usage per kandidat; gap terlihat, bukan "
            "kesunyian)\n",
            cs->measured_dims);
    bprintf(buf, CAND_REPORT_CAP, &off,
            "observasi NON-blocking: tidak mengubah verdict/exit. "
            "Anti-overclaim SOL-10: frontier = \"TIDAK didominasi pada "
            "dimensi yang terukur\", BUKAN klaim kandidat terbaik secara "
            "umum; harness/user memilih final.\n\n");

    bprintf(buf, CAND_REPORT_CAP, &off,
            "frontier (tidak didominasi pada dimensi yang terukur):\n");
    for (i = 0; i < cs->count; i++) {
        const myc_candidate_item *it = &cs->items[i];
        if (!it->frontier)
            continue;
        if (i == 0)
            bprintf(buf, CAND_REPORT_CAP, &off, "  [baseline] ");
        item_line(buf, CAND_REPORT_CAP, &off, it);
    }

    bprintf(buf, CAND_REPORT_CAP, &off, "\ndominated / tidak terukur:\n");
    for (i = 0; i < cs->count; i++) {
        const myc_candidate_item *it = &cs->items[i];
        if (it->frontier)
            continue;
        if (it->dominated_by >= 0) {
            bprintf(buf, CAND_REPORT_CAP, &off,
                    "  %s  (didominasi oleh: %s)\n",
                    it->path, cs->items[it->dominated_by].path);
            item_line(buf, CAND_REPORT_CAP, &off, it);
        } else {
            /* item_line mencetak "(tidak terukur: pipeline gagal / OOM)" */
            item_line(buf, CAND_REPORT_CAP, &off, it);
        }
    }

    return buf;
}

/* ---------- API ---------- */

int myc_candidate_tournament(const char *baseline_path,
                             const char *const *cand_paths, int ncands,
                             const char *checked_header_dir,
                             myc_candidate_set *out)
{
    myc_source_input in;
    const char *base_buf = NULL;
    size_t base_len = 0;
    int base_free = 0;
    myc_error_code le;
    uint64_t *base_hash = NULL;
    int base_nhash = 0;
    int i;
    char errbuf[512];

    memset(out, 0, sizeof(*out));
    out->measured_dims = 8;

    if (ncands < 1 || ncands > MYC_MAX_CANDIDATES - 1) {
        snprintf(errbuf, sizeof(errbuf),
                 "compare-candidates: jumlah kandidat harus 1..%d (dapat %d)\n",
                 MYC_MAX_CANDIDATES - 1, ncands);
        out->report = myc_strdup(errbuf);
        return 1;
    }

    out->count = ncands + 1;
    out->ncandidates = ncands;
    out->items[0].path = baseline_path;
    for (i = 0; i < ncands; i++)
        out->items[i + 1].path = cand_paths[i];

    /* Baseline wajib terbaca (fatal). Pipeline baseline boleh gagal
     * (measured_ok=0) tapi buffer tetap dipakai utk churn/obligations. */
    memset(&in, 0, sizeof(in));
    in.kind = MYC_SOURCE_FILE;
    in.file_path = baseline_path;
    le = myc_source_load(&in, &base_buf, &base_len, &base_free);
    if (le != MYC_ERR_NONE) {
        snprintf(errbuf, sizeof(errbuf),
                 "compare-candidates: baseline tidak terbaca %s (error=%s)\n",
                 baseline_path, myc_error_name(le));
        out->report = myc_strdup(errbuf);
        return 1;
    }

    measure_file(baseline_path, checked_header_dir, &out->items[0]);

    for (i = 1; i < out->count; i++)
        measure_file(out->items[i].path, checked_header_dir, &out->items[i]);

    /* churn + obligations vs baseline (butuh buffer kandidat; re-load —
     * file kecil, deterministik). */
    if (base_len > 0) {
        hash_lines(base_buf, base_len, &base_hash, &base_nhash);
        if (base_hash)
            qsort(base_hash, (size_t)base_nhash, sizeof(uint64_t), cmp_u64);
        else {
            /* OOM saat hash baseline: churn tak bisa diukur secara jujur —
             * kandidat tidak boleh diam-diam dianggap churn 0 (gap terlihat). */
            for (i = 1; i < out->count; i++)
                out->items[i].measured_ok = 0;
        }
    }
    for (i = 1; i < out->count; i++) {
        const char *cbuf = NULL;
        size_t clen = 0;
        int cfree = 0;
        myc_candidate_item *it = &out->items[i];
        myc_contract_delta d;

        memset(&in, 0, sizeof(in));
        in.kind = MYC_SOURCE_FILE;
        in.file_path = it->path;
        le = myc_source_load(&in, &cbuf, &clen, &cfree);
        if (le != MYC_ERR_NONE) {
            it->measured_ok = 0;
            continue;
        }
        if (base_hash) {
            uint64_t *ch = NULL;
            int nch = 0, add = 0, rem = 0;
            hash_lines(cbuf, clen, &ch, &nch);
            if (!ch) {
                it->measured_ok = 0;
                if (cfree)
                    free((void *)cbuf);
                continue;
            }
            qsort(ch, (size_t)nch, sizeof(uint64_t), cmp_u64);
            line_delta(base_hash, base_nhash, ch, nch, &add, &rem);
            it->churn_lines = add + rem;
            free(ch);
        }

        if (it->measured_ok) {
            memset(&d, 0, sizeof(d));
            if (!myc_contract_delta_compare(base_buf, base_len,
                                            cbuf, clen, &d)) {
                /* OOM: jangan diam-diam anggap CLEAN (contract.h). */
                it->measured_ok = 0;
            } else {
                it->obligations_lost =
                    d.n_removed_requires + d.n_removed_ensures;
                myc_contract_delta_free(&d);
            }
        }
        if (cfree)
            free((void *)cbuf);
    }
    free(base_hash);

    /* Pareto frontier: items tidak terukur tidak ikut perbandingan. */
    for (i = 0; i < out->count; i++) {
        myc_candidate_item *it = &out->items[i];
        int j;
        it->frontier = 0;
        it->dominated_by = -1;
        if (!it->measured_ok)
            continue;
        it->frontier = 1;
        for (j = 0; j < out->count; j++) {
            const myc_candidate_item *oj = &out->items[j];
            if (j == i || !oj->measured_ok)
                continue;
            if (cand_dominates(oj, it)) {
                it->frontier = 0;
                it->dominated_by = j; /* index terkecil menang (deterministik) */
                break;
            }
        }
    }
    for (i = 0; i < out->count; i++)
        if (out->items[i].frontier)
            out->frontier_count++;

    out->report = build_report(out);
    if (base_free)
        free((void *)base_buf);
    return 0;
}

char *myc_candidate_json(const myc_candidate_set *cs)
{
    json_value *root, *arr, *dims_arr;
    char *out = NULL;
    int ok, i;

    root = json_new_obj();
    if (!root)
        return NULL;
    json_obj_set(root, "schema", json_new_str("myc.candidate.v1"));
    json_obj_set(root, "baseline", json_new_str(cs->items[0].path));
    arr = json_new_arr();
    for (i = 1; i < cs->count; i++)
        json_arr_push(arr, json_new_str(cs->items[i].path));
    json_obj_set(root, "candidates", arr);
    json_obj_set(root, "ncandidates", json_new_num((int64_t)cs->ncandidates));
    json_obj_set(root, "measured_dims", json_new_num((int64_t)cs->measured_dims));
    dims_arr = json_new_arr();
    json_arr_push(dims_arr, json_new_str("stack_impact"));
    json_obj_set(root, "unmeasured_dims", dims_arr);

    arr = json_new_arr();
    for (i = 0; i < cs->count; i++) {
        const myc_candidate_item *it = &cs->items[i];
        json_value *o = json_new_obj();
        json_value *dims = json_new_obj();
        json_obj_set(o, "file", json_new_str(it->path));
        json_obj_set(o, "is_baseline", json_new_bool(i == 0 ? 1 : 0));
        json_obj_set(o, "measured", json_new_bool(it->measured_ok ? 1 : 0));
        json_obj_set(o, "frontier", json_new_bool(it->frontier ? 1 : 0));
        if (it->dominated_by >= 0)
            json_obj_set(o, "dominated_by",
                         json_new_str(cs->items[it->dominated_by].path));
        if (it->measured_ok) {
            json_obj_set(dims, "hard_gate",
                         json_new_num((int64_t)it->hard_gate));
            json_obj_set(dims, "findings",
                         json_new_num((int64_t)it->findings));
            json_obj_set(dims, "obligations_lost",
                         json_new_num((int64_t)it->obligations_lost));
            json_obj_set(dims, "churn_lines",
                         json_new_num((int64_t)it->churn_lines));
            json_obj_set(dims, "verification_cost",
                         json_new_num((int64_t)it->verification_cost));
            json_obj_set(dims, "runtime_proxy",
                         json_new_num((int64_t)it->runtime_proxy));
            json_obj_set(dims, "portability",
                         json_new_num((int64_t)it->portability));
            json_obj_set(dims, "readability",
                         json_new_num((int64_t)it->readability));
            json_obj_set(dims, "stack_impact", json_new_str("unmeasured"));
        }
        json_obj_set(o, "dims", dims);
        json_arr_push(arr, o);
    }
    json_obj_set(root, "items", arr);

    arr = json_new_arr();
    for (i = 0; i < cs->count; i++)
        if (cs->items[i].frontier)
            json_arr_push(arr, json_new_str(cs->items[i].path));
    json_obj_set(root, "frontier", arr);
    json_obj_set(root, "frontier_count",
                 json_new_num((int64_t)cs->frontier_count));
    json_obj_set(root, "note",
                 json_new_str("anti-overclaim SOL-10: frontier = tidak "
                              "didominasi pada dimensi yang terukur, bukan "
                              "klaim kandidat terbaik secara umum"));

    ok = json_serialize(root, &out);
    json_free(root);
    if (!ok)
        out = NULL;
    return out;
}

void myc_candidate_free(myc_candidate_set *cs)
{
    if (!cs)
        return;
    free(cs->report);
    memset(cs, 0, sizeof(*cs));
}
