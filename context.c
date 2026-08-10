/*
 * context.c -- Agent Context Compiler (Fase 3, SOL-22).
 *
 * Paket konteks MINIMAL untuk satu finding (bukan seluruh source/log):
 * function slice + callers/callees + contracts + witness + one action +
 * preservation obligations + target facts + exact verification command,
 * dengan budget token yang dapat dipilih (4K/8K/16K approximation).
 *
 * Semua isi DETERMINISTIK (input + flags sama -> paket sama, termasuk
 * context_sha256) dan NON-blocking: murni derivasi dari myc_result +
 * source + request; tidak mengubah verdict/gate/debt.
 */
#include "context.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "ledger.h"
#include "agent.h"
#include "causal.h"

/* ------------------------------------------------------------------ */
/* String builder kecil (heap, tanpa static mutable)                  */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *p;
    size_t len;
    size_t cap;
} ctx_sb;

static int sb_reserve(ctx_sb *b, size_t extra)
{
    size_t need = b->len + extra + 1;
    char  *np;
    size_t cap;

    if (need <= b->cap)
        return 0;
    cap = b->cap ? b->cap * 2 : 256;
    while (cap < need)
        cap *= 2;
    np = (char *)realloc(b->p, cap);
    if (!np)
        return -1;
    b->p = np;
    b->cap = cap;
    return 0;
}

/* Append dengan panjang eksplisit (slice bisa mengandung NUL/biner). */
static int sb_append(ctx_sb *b, const char *s, size_t l)
{
    if (sb_reserve(b, l) != 0)
        return -1;
    if (l) {
        memcpy(b->p + b->len, s, l);
        b->len += l;
        b->p[b->len] = '\0';
    }
    return 0;
}

static int sb_puts(ctx_sb *b, const char *s)
{
    size_t l = s ? strlen(s) : 0;
    return sb_append(b, s, l);
}

static int sb_printf(ctx_sb *b, const char *fmt, ...)
{
    va_list ap;
    int     n;

    va_start(ap, fmt);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0)
        return -1;
    if (sb_reserve(b, (size_t)n) != 0)
        return -1;
    va_start(ap, fmt);
    vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    b->len += (size_t)n;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Function range extractor (Allman-aware, lihat pelajaran cache.c)    */
/* ------------------------------------------------------------------ */

typedef struct {
    char   name[64];
    int    line;          /* baris nama fungsi (1-based) */
    size_t sig_start;     /* offset awal baris signature */
    size_t body_start;    /* offset '{' */
    size_t body_end;      /* offset SETELAH '}' penutup */
} ctx_func;

static int ctx_is_ident_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

static int ctx_is_keyword(const char *s, size_t n)
{
    static const char *const K[] = {
        "if", "for", "while", "switch", "do", "return", "sizeof",
        "case", "goto", "else", "typedef", "struct", "union", "enum",
        "static", "extern", "const", "volatile", "int", "char", "void",
        "unsigned", "signed", "long", "short", "double", "float", "ifdef",
        NULL
    };
    int i;
    for (i = 0; K[i]; i++) {
        size_t l = strlen(K[i]);
        if (l == n && strncmp(s, K[i], l) == 0)
            return 1;
    }
    return 0;
}

/* Skip whitespace (termasuk newline — dukung gaya Allman) + komentar. */
static size_t ctx_skip_ws_comments(const char *src, size_t srclen, size_t j)
{
    for (;;) {
        while (j < srclen &&
               (src[j] == ' ' || src[j] == '\t' || src[j] == '\n' ||
                src[j] == '\r'))
            j++;
        if (j + 1 < srclen && src[j] == '/' && src[j + 1] == '/') {
            while (j < srclen && src[j] != '\n')
                j++;
            continue;
        }
        if (j + 1 < srclen && src[j] == '/' && src[j + 1] == '*') {
            j += 2;
            while (j + 1 < srclen &&
                   !(src[j] == '*' && src[j + 1] == '/'))
                j++;
            j += 2;
            continue;
        }
        break;
    }
    return j;
}

/* Awal baris yang memuat offset off. */
static size_t ctx_line_start(const char *src, size_t off)
{
    (void)src;
    while (off > 0 && src[off - 1] != '\n')
        off--;
    return off;
}

/* Ekstrak semua fungsi dengan rentang body (gaya Allman + K&R). */
static int ctx_extract_functions(const char *src, size_t n,
                                 ctx_func *out, int cap)
{
    size_t i = 0;
    int    depth = 0;
    int    line = 1;
    int    cnt = 0;

    if (!src || !out || cap <= 0)
        return -1;

    while (i < n) {
        char c = src[i];

        if (c == '\n')
            line++;

        if (c == '/' && i + 1 < n) {
            if (src[i + 1] == '/') {
                while (i < n && src[i] != '\n')
                    i++;
                continue;
            }
            if (src[i + 1] == '*') {
                i += 2;
                while (i + 1 < n && !(src[i] == '*' && src[i + 1] == '/'))
                    i++;
                i += 2;
                continue;
            }
        }
        if (c == '"' || c == '\'') {
            char q = c;
            i++;
            while (i < n && src[i] != q) {
                if (src[i] == '\\')
                    i++;
                i++;
            }
            i++;
            continue;
        }
        if (c == '{') { depth++; i++; continue; }
        if (c == '}') { if (depth > 0) depth--; i++; continue; }
        if (c == '#') { while (i < n && src[i] != '\n') i++; continue; }

        if (depth == 0 && ctx_is_ident_char(c) &&
            !(c >= '0' && c <= '9')) {
            size_t start = i, name_end, j;

            while (i < n && ctx_is_ident_char(src[i]))
                i++;
            name_end = i;
            if (ctx_is_keyword(src + start, name_end - start))
                continue;

            j = ctx_skip_ws_comments(src, n, i);
            if (j >= n || src[j] != '(')
                continue;
            {
                int paren = 1;
                j++;
                while (j < n && paren > 0) {
                    if (src[j] == '(') paren++;
                    else if (src[j] == ')') paren--;
                    j++;
                }
            }
            j = ctx_skip_ws_comments(src, n, j);
            if (j >= n || src[j] != '{')
                continue;
            {
                size_t body_start = j;
                int    bd = 1;
                size_t k = j + 1;
                while (k < n && bd > 0) {
                    if (src[k] == '{') bd++;
                    else if (src[k] == '}') bd--;
                    k++;
                }
                if (bd == 0 && cnt < cap) {
                    ctx_func *fn = &out[cnt];
                    size_t    len = name_end - start;
                    size_t    sig = ctx_line_start(src, start);
                    if (len >= sizeof(fn->name))
                        len = sizeof(fn->name) - 1;
                    memcpy(fn->name, src + start, len);
                    fn->name[len] = '\0';
                    fn->line = line;
                    fn->sig_start = sig;
                    fn->body_start = body_start;
                    fn->body_end = k;
                    cnt++;
                }
            }
            continue;
        }
        i++;
    }
    return cnt;
}

/* Apakah token muncul utuh di rentang [start,end)? */
static int ctx_token_in_range(const char *src, size_t start, size_t end,
                              const char *needle)
{
    size_t nl = strlen(needle);
    size_t p = start;
    if (nl == 0 || end <= start)
        return 0;
    while (p + nl <= end) {
        const char *hit = memchr(src + p, needle[0], end - p);
        if (!hit)
            return 0;
        p = (size_t)(hit - src);
        if (p + nl <= end && strncmp(src + p, needle, nl) == 0 &&
            (p == start || !ctx_is_ident_char(src[p - 1])) &&
            (p + nl >= end || !ctx_is_ident_char(src[p + nl])))
            return 1;
        p += 1;
    }
    return 0;
}

/* Salin nama fungsi dengan bound 63 + NUL (menghindari -Wformat-truncation
 * yang jadi error di CI -Werror). */
static void ctx_cpyname(char dst[64], const char *src)
{
    size_t l = src ? strlen(src) : 0;
    if (l >= 64)
        l = 63;
    memcpy(dst, src, l);
    dst[l] = '\0';
}

/* ------------------------------------------------------------------ */
/* Line index                                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    int *starts;
    int  count;
} ctx_lines;

static int ctx_build_lines(const char *src, size_t n, ctx_lines *L)
{
    int cap = 64;
    size_t i;

    L->starts = (int *)malloc((size_t)cap * sizeof(int));
    if (!L->starts)
        return -1;
    L->starts[0] = 0;
    L->count = 1;
    for (i = 0; i < n; i++) {
        if (src[i] == '\n') {
            int *np;
            if (L->count >= cap) {
                cap *= 2;
                np = (int *)realloc(L->starts, (size_t)cap * sizeof(int));
                if (!np) {
                    free(L->starts);
                    L->starts = NULL;
                    return -1;
                }
                L->starts = np;
            }
            L->starts[L->count++] = (int)(i + 1);
        }
    }
    return 0;
}

static int ctx_line_of(const ctx_lines *L, size_t off)
{
    int lo = 0, hi = L->count - 1, ans = 0;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if ((size_t)L->starts[mid] <= off) {
            ans = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return ans + 1;   /* 1-based */
}

/* Fungsi yang memuat baris tertentu. */
static int ctx_func_for_line(const ctx_func *f, int cnt, int line,
                             const ctx_lines *L)
{
    int i;
    for (i = 0; i < cnt; i++) {
        int sl = ctx_line_of(L, f[i].sig_start);
        int el = f[i].body_end > f[i].sig_start
                     ? ctx_line_of(L, f[i].body_end - 1)
                     : sl;
        if (line >= sl && line <= el)
            return i;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Contracts: klausa //@ tepat di atas fungsi                          */
/* ------------------------------------------------------------------ */

static int ctx_contracts_at(const char *src, size_t n, size_t sig_start,
                            char clauses[][128], int cap)
{
    size_t cur = sig_start;
    int    cnt = 0;
    int    i, j;

    (void)n;

    while (cur > 0) {
        size_t prev = cur;
        size_t a, b;
        while (prev > 0 && src[prev - 1] != '\n')
            prev--;
        a = prev;
        b = cur;
        while (a < b && (src[a] == ' ' || src[a] == '\t'))
            a++;
        while (b > a && (src[b - 1] == '\r' || src[b - 1] == '\n' ||
                         src[b - 1] == ' ' || src[b - 1] == '\t'))
            b--;
        if (b - a >= 3 && src[a] == '/' && src[a + 1] == '/' &&
            src[a + 2] == '@') {
            size_t p = a + 3;
            while (p < b && (src[p] == ' ' || src[p] == '\t'))
                p++;
            if (cnt < cap) {
                size_t l = b - p;
                if (l >= 128)
                    l = 127;
                memcpy(clauses[cnt], src + p, l);
                clauses[cnt][l] = '\0';
                cnt++;
            }
        } else {
            break;
        }
        cur = prev;
    }
    /* dibaca dari bawah ke atas -> balik urutannya */
    for (i = 0, j = cnt - 1; i < j; i++, j--) {
        char t[128];
        memcpy(t, clauses[i], sizeof(t));
        memcpy(clauses[i], clauses[j], sizeof(t));
        memcpy(clauses[j], t, sizeof(t));
    }
    return cnt;
}

/* ------------------------------------------------------------------ */
/* Verify command + flags (deterministik)                             */
/* ------------------------------------------------------------------ */

static void ctx_verify_command(const myc_request *req, const char *path,
                               ctx_sb *out)
{
    sb_printf(out, "myc check %s", path && path[0] ? path : "-");
    if (req->strict) sb_puts(out, " --strict");
    if (req->run_analyzer) sb_puts(out, " --analyze");
    if (req->run) sb_puts(out, " --run");
    if (req->prove) sb_puts(out, " --prove");
    if (req->checked) sb_puts(out, " --checked");
    if (req->filc) sb_puts(out, " --filc");
    if (req->driver) sb_puts(out, " --driver");
    if (req->metamorphic) sb_puts(out, " --metamorphic");
    if (req->negative) sb_puts(out, " --negative");
    if (req->quorum) sb_puts(out, " --quorum");
    if (req->require_complete) sb_puts(out, " --require-complete");
    if (req->cwd && req->cwd[0])
        sb_printf(out, " --cwd %s", req->cwd);
    if (req->tx_finding_id && req->tx_finding_id[0])
        sb_printf(out, " --finding-id %s", req->tx_finding_id);
}

static void ctx_flag_string(const myc_request *req, ctx_sb *out)
{
    sb_printf(out,
              "strict=%d analyzer=%d run=%d prove=%d checked=%d filc=%d "
              "driver=%d metamorphic=%d negative=%d quorum=%d reqc=%d",
              req->strict, req->run_analyzer, req->run, req->prove,
              req->checked, req->filc, req->driver, req->metamorphic,
              req->negative, req->quorum, req->require_complete);
}

/* ------------------------------------------------------------------ */
/* Package builder                                                    */
/* ------------------------------------------------------------------ */

/* Section order = prioritas (rendah dibuang dulu saat budget penuh). */
enum {
    SEC_FINDING = 0,
    SEC_FUNC,
    SEC_CALLERS,
    SEC_CONTRACTS,
    SEC_WITNESS,
    SEC_ACTION,
    SEC_PRESERVE,
    SEC_CAUSAL,
    SEC_PACK,          /* Fase 7 (DS-15 wiring): pack proyek lokal --
                          prioritas terendah, dipotong pertama saat
                          budget penuh (konteks finding lebih penting
                          daripada instruksi proyek) */
    SEC_COUNT
};

static const char *const SEC_NAMES[SEC_COUNT] = {
    "finding", "function", "callers/callees", "contracts", "witness",
    "one action", "preservation obligations", "causal cluster",
    "project pack"
};

/* Pilih diagnostic target: finding_id (f-%08x / line) atau root causal. */
static int ctx_select_diag(const myc_result *res, const char *finding_id)
{
    int i;

    if (finding_id && finding_id[0]) {
        if (finding_id[0] == 'f' && finding_id[1] == '-') {
            char *end = NULL;
            unsigned long v = strtoul(finding_id + 2, &end, 16);
            if (end && end != finding_id + 2 && *end == '\0' && v <= 0x7fffffffUL)
                for (i = 0; i < res->diag_count; i++)
                    if (res->diags[i].line == (int)v)
                        return i;
        } else {
            /* argumen berupa line literal */
            char *end = NULL;
            long v = strtol(finding_id, &end, 10);
            if (end && end != finding_id && *end == '\0')
                for (i = 0; i < res->diag_count; i++)
                    if (res->diags[i].line == (int)v)
                        return i;
        }
        /* ID tidak cocok dengan diagnostic mana pun */
        return -2;
    }

    /* Auto: root cause confirmed (SOL-09), fallback diag pertama. */
    {
        myc_causal_graph cg;
        int ridx = -1;
        if (res->diag_count > 0) {
            myc_causal_build(res, &cg);
            ridx = myc_causal_first_confirmed_root(&cg);
            if (ridx < 0 && cg.repair_count > 0)
                ridx = cg.repair_order[0];
            if (ridx < 0)
                ridx = 0;
            myc_causal_free(&cg);
        }
        return ridx;
    }
}

/* Bangun satu section (isi, tanpa judul) — return 0 sukses. */
static int ctx_build_section(const myc_result *res, const char *src,
                             size_t srclen, int sec,
                             const ctx_func *f, int func_count,
                             int fidx, int diag_idx,
                             const myc_pack_info *pack, ctx_sb *out)
{
    const myc_diagnostic *d = NULL;
    int i;

    (void)srclen;
    if (diag_idx >= 0 && diag_idx < res->diag_count)
        d = &res->diags[diag_idx];

    switch (sec) {
    case SEC_FINDING:
        if (d) {
            if (d->line > 0)
                sb_printf(out, "line: %d col: %d\n", d->line, d->col);
            else
                sb_puts(out, "line: (lokasi tidak diketahui)\n");
            sb_printf(out, "confidence: %s\n",
                      myc_confidence_name(d->confidence));
            sb_printf(out, "message: %s\n",
                      d->message ? d->message : "(none)");
        } else {
            sb_puts(out, "line: (tidak cocok dengan diagnostic mana pun)\n");
        }
        break;

    case SEC_FUNC:
        if (fidx >= 0) {
            size_t a = f[fidx].sig_start;
            size_t b = f[fidx].body_end;
            size_t l = b > a ? b - a : 0;
            size_t p = a;
            int    k = 0;
            while (p < a + l && k < 60) {   /* cap 60 baris slice */
                size_t e = p;
                while (e < a + l && src[e] != '\n')
                    e++;
                if (k > 0 || e > p)
                    sb_printf(out, "%.*s\n", (int)(e - p), src + p);
                p = e + 1;
                k++;
            }
            if (p < a + l)
                sb_puts(out, "... (slice terpotong)\n");
        } else {
            sb_printf(out, "(baris finding di luar fungsi manapun)\n");
        }
        break;

    case SEC_CALLERS: {
        char callers[8][64];
        char callees[8][64];
        int  nc = 0, ncal = 0, i;

        if (fidx >= 0) {
            for (i = 0; i < func_count && ncal < 8; i++) {
                if (i == fidx)
                    continue;
                if (ctx_token_in_range(src, f[fidx].body_start,
                                       f[fidx].body_end, f[i].name))
                    ctx_cpyname(callees[ncal++], f[i].name);
            }
            for (i = 0; i < func_count && nc < 8; i++) {
                if (i == fidx)
                    continue;
                if (ctx_token_in_range(src, f[i].body_start,
                                       f[i].body_end, f[fidx].name))
                    ctx_cpyname(callers[nc++], f[fidx].name);
            }
        }
        sb_puts(out, "callers: ");
        if (nc == 0) sb_puts(out, "(none)");
        else { for (i = 0; i < nc; i++) sb_printf(out, "%s%s", i ? ", " : "", callers[i]); }
        sb_puts(out, "\ncallees: ");
        if (ncal == 0) sb_puts(out, "(none)");
        else { for (i = 0; i < ncal; i++) sb_printf(out, "%s%s", i ? ", " : "", callees[i]); }
        sb_puts(out, "\n");
        break;
    }

    case SEC_CONTRACTS: {
        char clauses[8][128];
        int  ncl = 0, i;
        if (fidx >= 0)
            ncl = ctx_contracts_at(src, srclen, f[fidx].sig_start,
                                   clauses, 8);
        if (ncl == 0)
            sb_puts(out, "(tidak ada kontrak //@ di atas fungsi)\n");
        else
            for (i = 0; i < ncl; i++)
                sb_printf(out, "%s\n", clauses[i]);
        break;
    }

    case SEC_WITNESS:
        if (res->witness) {
            const myc_witness *w = res->witness;
            sb_printf(out, "kind: %s\n",
                      w->violation_kind ? w->violation_kind : "?");
            if (w->violation_msg)
                sb_printf(out, "msg: %s\n", w->violation_msg);
            if (w->backend)
                sb_printf(out, "backend: %s\n", w->backend);
            if (w->pre_state)
                sb_printf(out, "pre_state: %s\n", w->pre_state);
            if (w->operation)
                sb_printf(out, "operation: %s\n", w->operation);
        } else {
            sb_puts(out, "(tidak ada witness untuk run ini)\n");
        }
        break;

    case SEC_ACTION: {
        /* one action: reuse derivasi agent (primary + next-best). */
        myc_agent_result ar;
        if (myc_build_agent_result(res, &ar, NULL, NULL, NULL) == 0) {
            if (ar.next_best_json && ar.next_best_json[0])
                sb_printf(out, "next-best experiment: %s\n", ar.next_best_json);
            if (ar.has_primary) {
                sb_printf(out, "primary action: %s",
                          ar.primary_finding.message
                              ? ar.primary_finding.message : "(none)");
                if (d)
                    sb_printf(out, " (line %d)", d->line);
                sb_puts(out, "\n");
            }
            myc_agent_result_free(&ar);
        } else {
            /* myc_build_agent_result sudah membebaskan ar internal saat
             * return -1 (payload > cap) -- jangan free lagi (double-free). */
            sb_puts(out, "(agent derivation gagal)\n");
        }
        if (!out->len)
            sb_puts(out, "(run bersih / tidak ada aksi perbaikan)\n");
        break;
    }

    case SEC_PRESERVE: {
        sb_puts(out,
                "- jangan ubah kode di luar fungsi yang disorot (anti-churn)\n");
        if (fidx >= 0)
            sb_printf(out,
                      "- jangan ubah/melemahkan kontrak //@ di atas %s\n",
                      f[fidx].name);
        else
            sb_puts(out,
                    "- jangan ubah/melemahkan kontrak //@ di atas fungsi target\n"
                    "  (lokasi target tidak ditemukan)\n");
        sb_puts(out,
                "- jangan menyempitkan domain verifikasi / mengubah scenario\n"
                "- jangan menurunkan assurance / menonaktifkan sanitizer,\n"
                "  warning, atau assert\n"
                "- pertahankan signature/ABI fungsi publik\n");
        break;
    }

    case SEC_CAUSAL: {
        int i, shown = 0;
        for (i = 0; i < res->diag_count && i < 8; i++) {
            const myc_diagnostic *di = &res->diags[i];
            sb_printf(out, "line %d %-11s %s%s\n",
                      di->line,
                      myc_confidence_name(di->confidence),
                      di->message ? di->message : "",
                      (d && di == d) ? " (target)" : "");
            shown++;
        }
        if (!shown)
            sb_puts(out, "(tidak ada diagnostic lain)\n");
        break;
    }

    case SEC_PACK: {
        /* Fase 7 (DS-15 wiring): pack proyek lokal. Setiap klaim punya
         * sumber (sha256 isi file) -- jujur, deterministik. Pack absen
         * ditandai eksplisit (gap terlihat, bukan kesunyian). */
        if (pack && (pack->prompt_present || pack->spec_present)) {
            if (pack->prompt_present) {
                sb_printf(out, "prompt.md (sha256 %s):\n",
                          pack->prompt_sha256[0] ? pack->prompt_sha256 : "?");
                if (pack->prompt_text) {
                    sb_puts(out, pack->prompt_text);
                    if (pack->prompt_text_len > 0 &&
                        pack->prompt_text[pack->prompt_text_len - 1] != '\n')
                        sb_puts(out, "\n");
                }
                if (pack->prompt_total_len > pack->prompt_text_len)
                    sb_printf(out, "[dipotong: %zu dari %zu byte, cap "
                              "MYC_PACK_PROMPT_CAP]\n",
                              pack->prompt_text_len, pack->prompt_total_len);
            } else {
                sb_puts(out, "(prompt.md tidak ada)\n");
            }
            if (pack->spec_present) {
                sb_printf(out, "spec.json (sha256 %s): name=%s domain=%s\n",
                          pack->spec_sha256[0] ? pack->spec_sha256 : "?",
                          pack->spec_name[0] ? pack->spec_name : "(none)",
                          pack->spec_domain[0] ? pack->spec_domain : "(none)");
                if (pack->spec_n_rules > 0) {
                    sb_puts(out, "rules:\n");
                    for (i = 0; i < pack->spec_n_rules &&
                                i < MYC_PACK_MAX_RULES; i++)
                        sb_printf(out, "  - %s\n", pack->spec_rules[i]);
                }
                if (pack->spec_n_allow > 0) {
                    sb_puts(out, "allow_headers:\n");
                    for (i = 0; i < pack->spec_n_allow &&
                                i < MYC_PACK_MAX_HEADS; i++)
                        sb_printf(out, "  - %s\n", pack->spec_allow[i]);
                }
                if (pack->spec_n_deny > 0) {
                    sb_puts(out, "deny_functions:\n");
                    for (i = 0; i < pack->spec_n_deny &&
                                i < MYC_PACK_MAX_DENIES; i++)
                        sb_printf(out, "  - %s\n", pack->spec_deny[i]);
                }
            } else {
                sb_puts(out, "(spec.json tidak ada)\n");
            }
        } else {
            sb_puts(out, "(tidak ada pack proyek lokal: "
                         "myc.prompt.md / myc.spec.json)\n");
        }
        break;
    }

    default:
        break;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Entry                                                               */
/* ------------------------------------------------------------------ */

char *myc_context_build(const myc_result *res,
                        const char *src, size_t srclen,
                        const myc_request *req,
                        const myc_pack_info *pack,
                        const char *finding_id,
                        int budget_tokens,
                        char hash_out[65])
{
    ctx_func  funcs[256];
    ctx_lines lines;
    ctx_sb    body = { NULL, 0, 0 };
    ctx_sb    header = { NULL, 0, 0 };
    ctx_sb    deliver = { NULL, 0, 0 };
    const char *path;
    char      *scen = NULL;
    int        func_count, fidx = -1, diag_idx;
    int        i;
    size_t     budget_bytes;

    if (!res || !src || !req)
        return NULL;
    if (hash_out)
        hash_out[0] = '\0';
    if (budget_tokens < 1024)
        budget_tokens = MYC_CONTEXT_BUDGET_DEFAULT;
    budget_bytes = (size_t)budget_tokens * 4;   /* approx chars/token */

    func_count = ctx_extract_functions(src, srclen, funcs, 256);
    if (func_count < 0)
        func_count = 0;
    if (ctx_build_lines(src, srclen, &lines) != 0)
        return NULL;

    diag_idx = ctx_select_diag(res, finding_id);
    if (diag_idx >= 0 && diag_idx < res->diag_count)
        fidx = ctx_func_for_line(funcs, func_count,
                                 res->diags[diag_idx].line, &lines);

    path = req->input.file_path ? req->input.file_path : "";

    /* Body: semua section lengkap (untuk hash deterministik). */
    for (i = 0; i < SEC_COUNT; i++) {
        sb_printf(&body, "## %s\n", SEC_NAMES[i]);
        ctx_build_section(res, src, srclen, i,
                          funcs, func_count, fidx, diag_idx,
                          pack, &body);
        sb_puts(&body, "\n");
    }

    /* Hash sha256 dari body penuh (tanpa baris hash). */
    sha256_hex(body.p, body.len, hash_out);

    /* Header (selalu dikirim). */
    sb_puts(&header, "myc context v1 (schema myc.context.v1)\n");
    sb_printf(&header, "context_sha256: %s\n",
              hash_out ? hash_out : "?");
    sb_printf(&header, "budget: %d tokens (chars/4 approx) | "
                       "delivered: (lihat akhir) | full: %zu bytes\n",
              budget_tokens, body.len);
    sb_printf(&header, "source_sha256: %s | receipt_sha256: %s\n",
              res->source_sha256 ? res->source_sha256 : "?",
              res->receipt_sha256);
    sb_printf(&header, "verdict: %s | finding: %s | claim: %s\n",
              myc_verdict_name(res->verdict),
              myc_finding_name(res->finding),
              myc_claim_status_name(res->claim_status));
    {
        int k;
        static const char DIMS[] = "CSRBPDF";
        sb_puts(&header, "assurance: ");
        for (k = 0; k < MYC_DIM_COUNT; k++)
            sb_printf(&header, "%c=%s ",
                      k < (int)sizeof(DIMS) - 1 ? DIMS[k] : '?',
                      myc_dim_status_name(res->assurance_vector.status[k]));
        sb_puts(&header, "\n");
    }
    scen = myc_ledger_build_scenario_hash(req, NULL);
    sb_printf(&header, "scenario: %s\n", scen ? scen : "?");
    sb_puts(&header, "flags: ");
    ctx_flag_string(req, &header);
    sb_puts(&header, "\n");
    sb_puts(&header, "target: ");
    if (res->resolved_gcc)
        sb_printf(&header, "gcc=%s", res->resolved_gcc);
    if (res->gcc_version)
        sb_printf(&header, " | gcc_version=%s", res->gcc_version);
    if (res->clang_version)
        sb_printf(&header, " | clang=%s", res->clang_version);
    sb_puts(&header, "\n");
    sb_puts(&header, "verify: ");
    ctx_verify_command(req, path, &header);
    sb_puts(&header, "\n");
    free(scen);

    /* Deliver: header + section berprioritas sampai budget. */
    sb_puts(&deliver, header.p ? header.p : "");
    {
        size_t used = deliver.len;
        int    omitted = 0;
        for (i = 0; i < SEC_COUNT; i++) {
            /* cari awal section di body */
            char  marker[96];
            size_t sec_start = SIZE_MAX, sec_end, j;
            int    found = 0;

            snprintf(marker, sizeof(marker), "## %s\n", SEC_NAMES[i]);
            for (j = 0; j + strlen(marker) <= body.len; j++) {
                if (strncmp(body.p + j, marker, strlen(marker)) == 0) {
                    sec_start = j;
                    break;
                }
            }
            if (sec_start == SIZE_MAX)
                continue;
            sec_end = body.len;
            for (j = sec_start + strlen(marker); j + 3 <= body.len; j++) {
                if (body.p[j] == '\n' && body.p[j + 1] == '#' &&
                    body.p[j + 2] == '#') {
                    sec_end = j + 1;
                    break;
                }
            }
            {
                size_t slen = sec_end - sec_start;
                if (used + slen <= budget_bytes) {
                    sb_append(&deliver, body.p + sec_start, slen);
                    sb_puts(&deliver, "\n");
                    used += slen + 1;
                    found = 1;
                }
            }
            if (!found) {
                sb_printf(&deliver, "[omitted: %s (budget %d tokens)]\n",
                          SEC_NAMES[i], budget_tokens);
                omitted++;
            }
        }
        /* perbarui baris "delivered" — sederhana: catat di akhir */
        sb_printf(&deliver, "# delivered %zu bytes (%d tokens) | full %zu "
                  "bytes | omitted sections: %d | context_sha256 di atas "
                  "mencakup paket penuh (deterministik, tidak tergantung "
                  "budget)\n",
                  deliver.len, budget_tokens, body.len, omitted);
    }

    free(body.p);
    free(header.p);
    free(lines.starts);
    return deliver.p;
}
