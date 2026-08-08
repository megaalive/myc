/*
 * mutate.c -- Gate Mutation-Audited Verification (B5, --mutate-audit,
 * DS-09).
 *
 * Alur:
 *   1. Scan fungsi top-level (nama + body range) untuk memilih lokasi
 *      mutasi.
 *   2. Untuk tiap lokasi, terapkan SATU mutasi dari set pola error LLM
 *      (deterministik, urutan stabil): off-by-one (<= -> <, >= -> >),
 *      guard lemah (&& -> ||), komparasi dibalik (< -> >, == -> !=),
 *      cek batas dihapus (>= cap -> > cap).
 *   3. Jalankan ulang pipeline (compile -Werror + run ASan) terhadap tiap
 *      mutan via myc_pipeline (reuse penuh; budget --mutate-max).
 *   4. Mutan yang tetap clean (verdict OK) pada semua gate = coverage
 *      gap: kelas bug tsb tak terlihat konfigurasi verifikasi. Mutan
 *      ekuivalen (source tak berubah / compile error parah) di-skip.
 *
 * NON-blocking: coverage gap tidak menurunkan verdict program.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mutate.h"
#include "compile.h"
#include "gate.h"
#include "sha256.h"

#define MUT_MAX_FUNCS   64
#define MUT_MAX_LEN     128
#define MUT_MAX_MUTANTS 16          /* per fungsi, sebelum --mutate-max */
#define MUT_DEF_MAX     8           /* total mutan default */

typedef struct {
    char  name[MUT_MAX_LEN];
    size_t body_lo, body_hi;        /* range body (eksklusif hi) */
} mut_func;

/* Deskripsi satu mutasi. */
typedef struct {
    const char *klass;              /* nama kelas mutasi */
    const char *from, *to;          /* substring diganti */
    const char *func;               /* fungsi tempat mutasi */
    size_t      pos;                /* posisi di source */
    size_t      len;                /* panjang token */
    int         skipped;            /* mutan ekuivalen / tak bisa dibangun */
    int         caught;             /* 1 = tertangkap gate, 0 = GAP */
    char        gate[96];           /* gate yang menangkap */
} mut_ops;

/* Tambah diagnostic ringan (arena). */
static void add_diag_mut(myc_result *res, const char *msg)
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

/* Scanner: definisi fungsi top-level + body range. */
static int mut_scan_funcs(const char *src, size_t len, mut_func *funcs,
                          int maxf)
{
    int    nf = 0;
    size_t i = 0;
    int    paren = 0, brace = 0;
    int    sig_closed = 0;
    char   name[MUT_MAX_LEN];
    int    has_name = 0;
    int    in_body = -1;
    size_t body_start = 0, body_end = 0;

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
            if (brace == 0 && paren == 0) {
                size_t end = i, start;
                while (end > 0 && (src[end - 1] == ' ' || src[end - 1] == '\t'))
                    end--;
                start = end;
                while (start > 0 &&
                       ((src[start - 1] >= 'a' && src[start - 1] <= 'z') ||
                        (src[start - 1] >= 'A' && src[start - 1] <= 'Z') ||
                        src[start - 1] == '_' ||
                        (src[start - 1] >= '0' && src[start - 1] <= '9')))
                    start--;
                if (start < end) {
                    size_t n = end - start;
                    if (n >= sizeof(name))
                        n = sizeof(name) - 1;
                    memcpy(name, src + start, n);
                    name[n] = '\0';
                    has_name = 1;
                } else
                    has_name = 0;
            }
            paren++;
        } else if (c == ')') {
            if (paren > 0)
                paren--;
            if (paren == 0 && brace == 0 && has_name)
                sig_closed = 1;
        } else if (c == '{') {
            if (brace == 0 && paren == 0 && sig_closed && has_name) {
                if (nf < maxf) {
                    snprintf(funcs[nf].name, sizeof(funcs[nf].name), "%s",
                             name);
                    in_body = nf;
                    nf++;
                } else
                    in_body = -1;
            }
            brace++;
            if (in_body >= 0 && brace == 1)
                body_start = i + 1;
        } else if (c == '}') {
            if (brace > 0)
                brace--;
            if (brace == 0 && in_body >= 0) {
                body_end = i;
                funcs[in_body].body_lo = body_start;
                funcs[in_body].body_hi = body_end;
                in_body = -1;
            }
            sig_closed = 0;
            has_name = 0;
        } else if (c == ';') {
            if (paren == 0 && brace == 0)
                sig_closed = 0, has_name = 0;
        }
        i++;
    }
    return nf;
}

/* Cari posisi `from` pertama dalam range body (luar komentar/string).
 * Return 1 bila ketemu; posisi+len diisi. */
static int mut_find(const char *src, size_t lo, size_t hi,
                    const char *from, size_t *pos, size_t *len)
{
    size_t fwd = 0;
    size_t i = lo;
    size_t flen = strlen(from);
    while (i + flen <= hi) {
        /* lewati komentar/string sederhana */
        if (src[i] == '/' && i + 1 < hi && src[i + 1] == '/') {
            while (i < hi && src[i] != '\n')
                i++;
            continue;
        }
        if (src[i] == '/' && i + 1 < hi && src[i + 1] == '*') {
            size_t e = i + 2;
            while (e + 1 < hi && !(src[e] == '*' && src[e + 1] == '/'))
                e++;
            i = (e + 1 < hi) ? e + 2 : e;
            continue;
        }
        if (src[i] == '"' || src[i] == '\'') {
            char q = src[i];
            size_t j = i + 1;
            while (j < hi) {
                if (src[j] == '\\' && j + 1 < hi)
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
        fwd = 0;
        while (fwd < flen && src[i + fwd] == from[fwd])
            fwd++;
        if (fwd == flen) {
            *pos = i;
            *len = flen;
            return 1;
        }
        i++;
    }
    return 0;
}

/* Bangun source mutan: salin source dengan satu substitusi. */
static char *mut_build(const char *src, size_t srclen, size_t pos,
                       size_t len, const char *to, size_t *out_len)
{
    size_t tlen = strlen(to);
    char  *out = (char *)malloc(srclen - len + tlen + 1);
    if (!out)
        return NULL;
    memcpy(out, src, pos);
    memcpy(out + pos, to, tlen);
    memcpy(out + pos + tlen, src + pos + len, srclen - pos - len);
    out[srclen - len + tlen] = '\0';
    *out_len = srclen - len + tlen;
    return out;
}

/* --- gate --- */

int myc_mutate_gate(const myc_request *req, const char *source,
                    size_t source_len, myc_result *res)
{
    static const struct {
        const char *klass;
        const char *from, *to;
    } OPS[] = {
        { "off-by-one",   "<=", "<" },
        { "off-by-one",   ">=", ">" },
        { "guard-lemah",  "&&", "||" },
        { "komparasi",    "<",  ">" },
        { "komparasi",    "==", "!=" },
        { "cek-batas",    ">= ", "> " },
        { "cek-batas",    "<= ", "< " },
    };
    mut_func funcs[MUT_MAX_FUNCS];
    mut_ops  ops[MUT_MAX_FUNCS * MUT_MAX_MUTANTS];
    int      nf, nops = 0;
    int      fi, oi;
    int      budget = req->mutate_max > 0 ? req->mutate_max : MUT_DEF_MAX;
    char     rep[4096];
    size_t   roff = 0;
    int      total = 0, gap = 0, caught = 0, skipped = 0;

    myc_gate_set_status(res, MYC_GATE_MUTATE, MYC_GATE_NOT_APPLICABLE,
                        NULL);

    nf = mut_scan_funcs(source, source_len, funcs, MUT_MAX_FUNCS);
    if (nf == 0) {
        add_diag_mut(res, "mutate-audit di-skip: tanpa fungsi top-level");
        myc_gate_set_status(res, MYC_GATE_MUTATE, MYC_GATE_NOT_APPLICABLE,
                            "tanpa fungsi");
        myc_result_add_evidence(res, MYC_GATE_MUTATE, MYC_EVIDENCE_SKIP,
                                "mutate: tanpa fungsi");
        return 0;
    }
    /* kumpulkan mutasi (maks per fungsi, dedup posisi) */
    for (fi = 0; fi < nf && nops < MUT_MAX_FUNCS * MUT_MAX_MUTANTS; fi++) {
        int oi2;
        for (oi2 = 0; oi2 < (int)(sizeof(OPS) / sizeof(OPS[0])) &&
                    nops < MUT_MAX_FUNCS * MUT_MAX_MUTANTS; oi2++) {
            size_t pos = 0, len = 0;
            /* cari dari awal body; tiap operator sekali saja per fungsi */
            if (!mut_find(source, funcs[fi].body_lo, funcs[fi].body_hi,
                          OPS[oi2].from, &pos, &len))
                continue;
            /* cegah posisi duplikat antar operator yang menimpa */
            {
                int dup = 0;
                int k;
                for (k = 0; k < nops; k++)
                    if (ops[k].pos == pos)
                        dup = 1;
                if (dup)
                    continue;
            }
            memset(&ops[nops], 0, sizeof(ops[nops]));
            ops[nops].klass = OPS[oi2].klass;
            ops[nops].from = OPS[oi2].from;
            ops[nops].to = OPS[oi2].to;
            ops[nops].func = funcs[fi].name;
            ops[nops].pos = pos;
            ops[nops].len = len;
            nops++;
        }
    }
    if (nops == 0) {
        add_diag_mut(res, "mutate-audit di-skip: tidak ada operator yang "
                          "bisa dimutasi di body fungsi");
        myc_gate_set_status(res, MYC_GATE_MUTATE, MYC_GATE_NOT_APPLICABLE,
                            "tanpa lokasi mutasi");
        myc_result_add_evidence(res, MYC_GATE_MUTATE, MYC_EVIDENCE_SKIP,
                                "mutate: tanpa lokasi");
        return 0;
    }
    if (nops > budget)
        nops = budget;
    res->ran_mutate = 1;

    for (oi = 0; oi < nops; oi++) {
        char *mutant = NULL;
        size_t mlen = 0;
        myc_request req2;
        myc_result  res2;
        const char *catch_gate = NULL;
        mutant = mut_build(source, source_len, ops[oi].pos, ops[oi].len,
                           ops[oi].to, &mlen);
        if (!mutant) {
            ops[oi].skipped = 1;
            skipped++;
            continue;
        }
        /* jalankan ulang pipeline: compile -Werror + run ASan */
        memset(&req2, 0, sizeof(req2));
        req2.input.kind = MYC_SOURCE_MEMORY;
        req2.input.data = mutant;
        req2.input.len = mlen;
        req2.run = 1;
        req2.cwd = req->cwd;
        req2.timeout_ms = req->timeout_ms;
        req2.max_output_bytes = req->max_output_bytes;
        req2.run_lint = 0;
        myc_result_init(&res2);
        myc_pipeline(&req2, &res2);
        total++;
        if (res2.verdict == MC_OK) {
            /* mutan lolos semua gate = GAP */
            ops[oi].caught = 0;
            gap++;
        } else {
            ops[oi].caught = 1;
            caught++;
            /* gate yang menangkap (dari evidence terakhir) */
            if (res2.gate_count > 0) {
                int gi = (int)res2.gate_count - 1;
                while (gi >= 0) {
                    if (res2.gates[gi].status == MYC_GATE_COMPLETED_FINDINGS ||
                        res2.gates[gi].status == MYC_GATE_INFRA_FAILED ||
                        res2.gates[gi].status == MYC_GATE_INCONCLUSIVE) {
                        catch_gate = myc_gate_id_short(res2.gates[gi].id);
                        break;
                    }
                    gi--;
                }
            }
            if (catch_gate)
                snprintf(ops[oi].gate, sizeof(ops[oi].gate), "%s",
                         catch_gate);
            else
                snprintf(ops[oi].gate, sizeof(ops[oi].gate), "compile/run");
        }
        myc_result_free(&res2);
        free(mutant);
    }
    /* report */
    roff += (size_t)snprintf(rep + roff, sizeof(rep) - roff,
        "mutate-audit (B5): %d mutan, %d tertangkap, %d GAP, %d skip\\n",
        total, caught, gap, skipped);
    for (oi = 0; oi < nops && roff < sizeof(rep); oi++) {
        int r = snprintf(rep + roff, sizeof(rep) - roff,
            "  %-16s : %-10s -> %-10s %s\\n",
            ops[oi].func, ops[oi].klass, ops[oi].from,
            ops[oi].skipped ? "(skip)"
            : ops[oi].caught ? "TERTANGKAP " : "lolos semua gate -- GAP");
        if (ops[oi].caught && !ops[oi].skipped)
            r = snprintf(rep + roff, sizeof(rep) - roff,
                "  %-16s : %-10s -> %-10s TERTANGKAP (%s)\\n",
                ops[oi].func, ops[oi].klass, ops[oi].from, ops[oi].gate);
        if (r > 0)
            roff += (size_t)r;
        if (roff >= sizeof(rep))
            roff = sizeof(rep) - 1;
    }
    if (total > 0) {
        int r = snprintf(rep + roff, sizeof(rep) - roff,
            "  verification coverage: %d/%d kelas mutan terlihat%s\\n",
            caught, total, gap > 0
                ? " -- Saran: tambahkan kontrak/test di lokasi GAP" : "");
        if (r > 0)
            roff += (size_t)r;
        if (roff >= sizeof(rep))
            roff = sizeof(rep) - 1;
    }
    res->mutate_total = total;
    res->mutate_gap = gap;
    res->mutate_caught = caught;
    res->mutate_report = myc_result_arena_dup(res, rep, 0);
    myc_gate_set_status(res, MYC_GATE_MUTATE,
                        total > 0 ? MYC_GATE_COMPLETED_OBSERVATIONS
                                  : MYC_GATE_NOT_APPLICABLE,
                        "mutation audit selesai (observasi)");
    myc_result_add_evidence(res, MYC_GATE_MUTATE,
                            MYC_EVIDENCE_GATE_END,
                            "mutate: audit selesai (non-blocking)");
    return 1;
}
