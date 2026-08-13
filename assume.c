/*
 * assume.c -- Assumption Closure (Fase 4, A1 + DS-01).
 *
 * Implementasi:
 *   - myc_assume_fetch_facts: `gcc -dM -E -` (stdin kosong) -> macro
 *     predefined toolchain (char signedness, lebar int/pointer,
 *     endianness, __STDC_VERSION__, CHAR_BIT). Deterministik, tidak
 *     bergantung source (predefined macro murni).
 *   - myc_assume_run: tokenize source (comment/string-aware, line-
 *     tracked) lalu deteksi 5 kelas taruhan:
 *       char-signedness  : char var dibandingkan dgn literal negatif /
 *                          < 0 / >= 0
 *       int-width        : int menerima hasil strlen/sizeof
 *       bitfield-endian  : bit-field di struct/union
 *       alignment-cast   : cast (uint16_t *) dst dari pointer byte
 *       sizeof-assumption: sizeof(T) dibandingkan dgn konstanta
 *     Setiap asumsi: id = asm-<kind>-<8hex sha256(anchor)>; anchor =
 *     myc_ledger_build_anchor (stabil). Status lifecycle dipersisten di
 *     .myc/assumptions.json (NON-blocking: gagal tulis = dilewati).
 *   - myc_assume_ack_validate/terapkan: --assumption-ack "id:status,..."
 *     (fail-fast pada format salah; id tidak terdeteksi = catatan saja).
 *   - myc_assume_enforce: --require-assumptions-closed — unclosed > 0
 *     -> debt MYC-INCOMPLETE-ASSUMPTIONS-OPEN + INCONCLUSIVE (pola 9.10).
 *
 * Kejujuran (P5): semua deteksi adalah OBSERVASI ber-confidence,
 * NON-blocking. Verdict hanya turun bila user EKSPLISIT meminta
 * --require-assumptions-closed. Tidak ada klaim "terbukti portabel".
 */
#include "assume.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gate.h"
#include "json.h"
#include "sha256.h"
#include "proc.h"
#include "ledger.h"
#include "persist.h"

#ifdef _WIN32
#include <direct.h>
#define myc_mkdir(path) _mkdir(path)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define myc_mkdir(path) mkdir(path, 0700)
#endif

#define ASM_MAX_TOK 100000
#define ASM_FACTS_CAP (64u * 1024)

/* ------------------------------------------------------------------ */
/* Nama status                                                         */
/* ------------------------------------------------------------------ */

const char *myc_assumption_status_name(myc_assumption_status s)
{
    switch (s) {
    case MYC_ASM_OBSERVED:      return "observed";
    case MYC_ASM_DECLARED:      return "declared";
    case MYC_ASM_TESTED:        return "tested";
    case MYC_ASM_CONTRADICTED:  return "contradicted";
    case MYC_ASM_ELIMINATED:    return "eliminated";
    case MYC_ASM_ACCEPTED_RISK: return "accepted-risk";
    default:                    return "unknown";
    }
}

static int asm_status_from_name(const char *s)
{
    if (strcmp(s, "declared") == 0)      return MYC_ASM_DECLARED;
    if (strcmp(s, "tested") == 0)        return MYC_ASM_TESTED;
    if (strcmp(s, "contradicted") == 0)  return MYC_ASM_CONTRADICTED;
    if (strcmp(s, "eliminated") == 0)    return MYC_ASM_ELIMINATED;
    if (strcmp(s, "accepted-risk") == 0) return MYC_ASM_ACCEPTED_RISK;
    return MYC_ASM_OBSERVED;
}

/* ------------------------------------------------------------------ */
/* Fetch fakta toolchain: gcc -dM -E - (stdin kosong)                  */
/* ------------------------------------------------------------------ */

static long asm_parse_long(const char *s, size_t len)
{
    long v = 0;
    size_t i;
    int neg = 0;
    if (len == 0)
        return 0;
    i = 0;
    if (s[0] == '-') { neg = 1; i = 1; }
    for (; i < len; i++) {
        if (s[i] < '0' || s[i] > '9')
            break;
        v = v * 10 + (s[i] - '0');
        if (v > 0x7FFFFFFFL)
            return neg ? -0x7FFFFFFFL : 0x7FFFFFFFL;
    }
    return neg ? -v : v;
}

static int asm_name_eq(const char *np, size_t nlen, const char *name)
{
    size_t l = strlen(name);
    return nlen == l && memcmp(np, name, l) == 0;
}

/* Parse output -dM: baris "#define NAME VALUE". Mengisi out; return 1. */
static int asm_facts_parse(myc_host_facts *f, const char *txt, size_t len)
{
    const char *p = txt;
    const char *end = txt + len;
    char byte_order_v[64] = "", order_little_v[64] = "";
    int  have_byte_order = 0, have_order_little = 0;

    f->char_unsigned = 0;
    f->int_bits = 0;
    f->ptr_bits = 0;
    f->little_endian = -1;
    f->stdc_version = 0;
    f->char_bit = 8;

    while (p < end) {
        const char *nl = (const char *)memchr(p, '\n', (size_t)(end - p));
        size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);
        if (llen >= 9 && memcmp(p, "#define ", 8) == 0) {
            const char *np = p + 8;
            const char *nend = np;
            const char *vstart;
            size_t nlen, vlen;
            while (nend < end && *nend != ' ' && *nend != '\t' &&
                   *nend != '\n' && *nend != '\r')
                nend++;
            vstart = nend;
            while (vstart < end && (*vstart == ' ' || *vstart == '\t'))
                vstart++;
            nlen = (size_t)(nend - np);
            vlen = (size_t)((nl ? nl : end) - vstart);

            if (asm_name_eq(np, nlen, "__CHAR_UNSIGNED__"))
                f->char_unsigned = 1;
            else if (asm_name_eq(np, nlen, "__SIZEOF_INT__"))
                f->int_bits = 8 * (int)asm_parse_long(vstart, vlen);
            else if (asm_name_eq(np, nlen, "__SIZEOF_POINTER__"))
                f->ptr_bits = 8 * (int)asm_parse_long(vstart, vlen);
            else if (asm_name_eq(np, nlen, "__BYTE_ORDER__")) {
                /* Value bisa ANGKA (1234) atau TOKEN
                 * (__ORDER_LITTLE_ENDIAN__); simpan teks lalu bandingkan
                 * teks — bukan angka (gcc mendefinisikan __BYTE_ORDER__
                 * sebagai __ORDER_LITTLE_ENDIAN__). Trim trailing CR
                 * (output gcc Windows memakai \r\n). */
                while (vlen > 0 && (vstart[vlen - 1] == '\r' ||
                                    vstart[vlen - 1] == '\n' ||
                                    vstart[vlen - 1] == ' ' ||
                                    vstart[vlen - 1] == '\t'))
                    vlen--;
                if (vlen < sizeof(byte_order_v)) {
                    memcpy(byte_order_v, vstart, vlen);
                    byte_order_v[vlen] = '\0';
                    have_byte_order = 1;
                }
            } else if (asm_name_eq(np, nlen, "__ORDER_LITTLE_ENDIAN__")) {
                while (vlen > 0 && (vstart[vlen - 1] == '\r' ||
                                    vstart[vlen - 1] == '\n' ||
                                    vstart[vlen - 1] == ' ' ||
                                    vstart[vlen - 1] == '\t'))
                    vlen--;
                if (vlen < sizeof(order_little_v)) {
                    memcpy(order_little_v, vstart, vlen);
                    order_little_v[vlen] = '\0';
                    have_order_little = 1;
                }
            } else if (asm_name_eq(np, nlen, "__STDC_VERSION__"))
                f->stdc_version = asm_parse_long(vstart, vlen);
            else if (asm_name_eq(np, nlen, "CHAR_BIT"))
                f->char_bit = (int)asm_parse_long(vstart, vlen);
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    if (have_byte_order && have_order_little) {
        /* gcc: `__BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__` (value = TOKEN)
         * sedangkan `__ORDER_LITTLE_ENDIAN__ 1234` (value = angka).
         * Cocok bila teks sama ATAU value BYTE_ORDER adalah token
         * __ORDER_LITTLE_ENDIAN__ (berarti merujuk nilai order_little). */
        if (strcmp(byte_order_v, order_little_v) == 0 ||
            strcmp(byte_order_v, "__ORDER_LITTLE_ENDIAN__") == 0)
            f->little_endian = 1;
        else
            f->little_endian = 0;
    }
    return 1;
}

int myc_assume_fetch_facts(const char *gcc, myc_host_facts *out)
{
    myc_proc_request preq;
    myc_proc_result pres;
    const char *argv[5];
    int ok = 0;

    if (!out)
        return 0;
    memset(out, 0, sizeof(*out));
    if (!gcc)
        gcc = "gcc";

    argv[0] = gcc;
    argv[1] = "-dM";
    argv[2] = "-E";
    argv[3] = "-";
    argv[4] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.timeout_ms = 15000;
    preq.max_output_bytes = ASM_FACTS_CAP;
    /* stdin KOSONG: hanya macro predefined (deterministik, tidak
     * bergantung isi source / syntax error). */
    preq.stdin_data = NULL;
    preq.stdin_len = 0;

    memset(&pres, 0, sizeof(pres));
    if (myc_proc_run(&preq, &pres)) {
        if (pres.exit_code == 0 && pres.stdout_data && pres.stdout_total > 0) {
            ok = asm_facts_parse(out, pres.stdout_data, pres.stdout_total);
            if (ok)
                out->ok = 1;
        }
    }
    myc_proc_result_free(&pres);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Tokenizer ringan (comment/string-aware, line-tracked)               */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *start, *end;
    int  line;
    int  kind;   /* 0 = punct, 1 = identifier, 2 = angka */
} asm_tok;

static void asm_skip_ws(const char **pp, const char *end, int *line)
{
    const char *p = *pp;
    while (p < end) {
        if (*p == ' ' || *p == '\t' || *p == '\r') { p++; continue; }
        if (*p == '\n') { p++; (*line)++; continue; }
        break;
    }
    *pp = p;
}

/* Lewati spasi + komentar + literal string/char. Update line. */
static void asm_skip_ws_comments(const char **pp, const char *end, int *line)
{
    const char *p = *pp;
    for (;;) {
        asm_skip_ws(&p, end, line);
        if (p + 1 < end && p[0] == '/' && p[1] == '/') {
            while (p < end && *p != '\n') p++;
            continue;
        }
        if (p + 1 < end && p[0] == '/' && p[1] == '*') {
            p += 2;
            while (p + 1 < end && !(p[0] == '*' && p[1] == '/')) {
                if (*p == '\n') (*line)++;
                p++;
            }
            if (p + 1 < end) p += 2;
            continue;
        }
        if (p < end && (*p == '"' || *p == '\'')) {
            char q = *p;
            p++;
            while (p < end && *p != q) {
                if (*p == '\\' && p + 1 < end) p += 2;
                else p++;
            }
            if (p < end) p++;
            continue;
        }
        break;
    }
    *pp = p;
}

static int asm_is_ident_start(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int asm_is_ident_char(char c)
{
    return asm_is_ident_start(c) || (c >= '0' && c <= '9');
}

static int asm_is_digit(char c)
{
    return c >= '0' && c <= '9';
}

/* Operator 2-karakter yang dijadikan SATU token (==, <=, >=, !=, <<, >>,
 * &&, ||, +=, dst). Tanpa ini, `==` terpecah jadi '=' '=' dan detektor
 * pembanding tidak pernah cocok. */
static int asm_two_char_op(char a, char b)
{
    switch (a) {
    case '<': return b == '=' || b == '<';
    case '>': return b == '=' || b == '>';
    case '=': return b == '=';
    case '!': return b == '=';
    case '&': return b == '&';
    case '|': return b == '|';
    case '+': return b == '+' || b == '=';
    case '-': return b == '-' || b == '=' || b == '>';
    case '*': return b == '=';
    case '/': return b == '=';
    case '%': return b == '=';
    case '^': return b == '=';
    case '#': return b == '#';
    default:  return 0;
    }
}

static int asm_tokenize(const char *src, size_t len, asm_tok *toks, int cap)
{
    const char *p = src;
    const char *end = src + len;
    int line = 1;
    int n = 0;

    while (n < cap) {
        asm_skip_ws_comments(&p, end, &line);
        if (p >= end)
            break;
        if (asm_is_ident_start(*p)) {
            const char *s = p;
            while (p < end && asm_is_ident_char(*p)) p++;
            toks[n].start = s; toks[n].end = p; toks[n].line = line;
            toks[n].kind = 1; n++;
        } else if (asm_is_digit(*p)) {
            const char *s = p;
            if (p + 1 < end && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
                p += 2;
                while (p < end && ((*p >= '0' && *p <= '9') ||
                                   (*p >= 'a' && *p <= 'f') ||
                                   (*p >= 'A' && *p <= 'F')))
                    p++;
            } else {
                while (p < end && asm_is_digit(*p)) p++;
            }
            toks[n].start = s; toks[n].end = p; toks[n].line = line;
            toks[n].kind = 2; n++;
        } else {
            toks[n].start = p; toks[n].end = p + 1; toks[n].line = line;
            toks[n].kind = 0; n++;
            if (p + 1 < end && asm_two_char_op(*p, p[1]))
                toks[n - 1].end = p + 2;   /* operator 2-karakter */
            p = toks[n - 1].end;
        }
    }
    return n;
}

static int asm_tok_eq(const asm_tok *t, const char *s)
{
    size_t l = strlen(s);
    return (size_t)(t->end - t->start) == l && memcmp(t->start, s, l) == 0;
}

static int asm_tok_is(const asm_tok *t, char c)
{
    return t->kind == 0 && t->end - t->start == 1 && t->start[0] == c;
}

static long asm_tok_num(const asm_tok *t)
{
    const char *p = t->start;
    const char *e = t->end;
    long v = 0;
    int hex = 0;
    if (p + 1 < e && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        hex = 1; p += 2;
    }
    for (; p < e; p++) {
        int d;
        if (*p >= '0' && *p <= '9') d = *p - '0';
        else if (hex && *p >= 'a' && *p <= 'f') d = *p - 'a' + 10;
        else if (hex && *p >= 'A' && *p <= 'F') d = *p - 'A' + 10;
        else break;
        v = v * (hex ? 16 : 10) + d;
        if (v > 0x7FFFFFFFL) return 0x7FFFFFFFL;
    }
    return v;
}

/* Klasifikasi operator pembanding: 0 none, 1 '<', 2 '>', 3 '<=',
 * 4 '>=', 5 '==', 6 '!='. */
static int asm_cmp_op(const asm_tok *t)
{
    size_t l = (size_t)(t->end - t->start);
    if (t->kind != 0 || l > 2)
        return 0;
    if (l == 1) {
        if (t->start[0] == '<') return 1;
        if (t->start[0] == '>') return 2;
    } else {
        if (t->start[0] == '<' && t->start[1] == '=') return 3;
        if (t->start[0] == '>' && t->start[1] == '=') return 4;
        if (t->start[0] == '=' && t->start[1] == '=') return 5;
        if (t->start[0] == '!' && t->start[1] == '=') return 6;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Deteksi: hasil sementara (buffer tetap; arena di tahap berikutnya)  */
/* ------------------------------------------------------------------ */

typedef struct {
    char kind[32];
    int  line;
    char host_fact[96];
    char risk[192];
    char next_action[192];
    int  confidence;
} asm_det;

static const char *asm_char_fact(const myc_host_facts *f)
{
    if (f->ok)
        return f->char_unsigned ? "char=unsigned" : "char=signed";
    return "char=?";
}

/* D1: char-signedness — char var vs literal negatif / <0 / >=0. */
static void asm_detect_char_signedness(const asm_tok *toks, int n,
                                       const myc_host_facts *facts,
                                       asm_det *out, int cap, int *count)
{
    /* Pass 1: kumpulkan nama char var (bukan pointer/array, bukan
     * signed/unsigned char eksplisit). */
    asm_tok cvars[256];
    int     nc = 0;
    int     i;

    for (i = 0; i + 1 < n && nc < 256; i++) {
        if (toks[i].kind != 1 || !asm_tok_eq(&toks[i], "char"))
            continue;
        if (i > 0 && toks[i - 1].kind == 1 &&
            (asm_tok_eq(&toks[i - 1], "unsigned") ||
             asm_tok_eq(&toks[i - 1], "signed")))
            continue;   /* tidak ada taruhan */
        if (toks[i + 1].kind != 1)
            continue;   /* sizeof(char) / (char)x / typedef */
        if (i + 2 < n && toks[i + 2].kind == 0 &&
            (toks[i + 2].start[0] == '*' || toks[i + 2].start[0] == '['))
            continue;   /* char *p / char buf[] */
        cvars[nc] = toks[i + 1];
        nc++;
    }

    /* Pass 2: untuk tiap char var (nama unik — banyak `char c` di fungsi
     * berbeda memakai nama sama; hindari scan ulang O(nc x n)), cari
     * perbandingan bertanda. */
    for (i = 0; i < nc && *count < cap; i++) {
        const char *vname = cvars[i].start;
        size_t vlen = (size_t)(cvars[i].end - cvars[i].start);
        int k;
        int dup = 0;
        for (k = 0; k < i; k++) {
            if (cvars[k].end - cvars[k].start == (long)vlen &&
                memcmp(cvars[k].start, vname, vlen) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup)
            continue;
        for (k = 0; k + 1 < n && *count < cap; k++) {
            int op, emit = 0, conf = 80;
            int j, neg = 0;
            long val;
            if (toks[k].kind != 1 ||
                (size_t)(toks[k].end - toks[k].start) != vlen ||
                memcmp(toks[k].start, vname, vlen) != 0)
                continue;
            if (toks[k + 1].kind != 0)
                continue;
            op = asm_cmp_op(&toks[k + 1]);
            if (!op)
                continue;
            j = k + 2;
            if (j < n && asm_tok_is(&toks[j], '-')) { neg = 1; j++; }
            if (j >= n || toks[j].kind != 2)
                continue;
            val = asm_tok_num(&toks[j]);
            if (neg) { emit = 1; conf = 90; }
            else if (val == 0 && (op == 1 || op == 4)) { emit = 1; conf = 80; }
            if (!emit)
                continue;
            snprintf(out[*count].kind, sizeof(out[*count].kind),
                     "char-signedness");
            out[*count].line = toks[k].line;
            snprintf(out[*count].host_fact, sizeof(out[*count].host_fact),
                     "%s", asm_char_fact(facts));
            snprintf(out[*count].risk, sizeof(out[*count].risk),
                     "di target dengan char=unsigned, cabang <0/>=0 mati "
                     "total; perilaku berubah");
            snprintf(out[*count].next_action, sizeof(out[*count].next_action),
                     "gunakan signed char/unsigned char eksplisit, atau "
                     "bandingkan setelah cast (int)c");
            out[*count].confidence = conf;
            (*count)++;
        }
    }
}

/* D2: int-width — int menerima hasil strlen/sizeof (asumsi int cukup). */
static void asm_detect_int_width(const asm_tok *toks, int n,
                                 const myc_host_facts *facts,
                                 asm_det *out, int cap, int *count)
{
    int i;
    for (i = 0; i + 3 < n && *count < cap; i++) {
        if (toks[i].kind != 1 || !asm_tok_eq(&toks[i], "int"))
            continue;
        if (i > 0 && toks[i - 1].kind == 1 &&
            (asm_tok_eq(&toks[i - 1], "unsigned") ||
             asm_tok_eq(&toks[i - 1], "signed") ||
             asm_tok_eq(&toks[i - 1], "long") ||
             asm_tok_eq(&toks[i - 1], "short")))
            continue;
        if (toks[i + 1].kind != 1)      /* var name */
            continue;
        if (!asm_tok_is(&toks[i + 2], '='))
            continue;
        if (toks[i + 3].kind != 1 ||
            !(asm_tok_eq(&toks[i + 3], "strlen") ||
              asm_tok_eq(&toks[i + 3], "wcslen") ||
              asm_tok_eq(&toks[i + 3], "strnlen") ||
              asm_tok_eq(&toks[i + 3], "sizeof")))
            continue;
        snprintf(out[*count].kind, sizeof(out[*count].kind), "int-width");
        out[*count].line = toks[i].line;
        snprintf(out[*count].host_fact, sizeof(out[*count].host_fact),
                 facts->int_bits ? "int=%d-bit" : "int=?",
                 facts->int_bits ? facts->int_bits : 0);
        snprintf(out[*count].risk, sizeof(out[*count].risk),
                 "int mungkin tak cukup menampung size_t/ukuran buffer "
                 "besar (>2GiB) di target lain");
        snprintf(out[*count].next_action, sizeof(out[*count].next_action),
                 "gunakan size_t untuk panjang/ukuran");
        out[*count].confidence = 75;
        (*count)++;
    }
}

/* D3: bitfield-endian — bit-field di struct/union. */
static void asm_detect_bitfield(const asm_tok *toks, int n,
                                const myc_host_facts *facts,
                                asm_det *out, int cap, int *count)
{
    int i;
    for (i = 0; i < n && *count < cap; i++) {
        int j, depth, k, emitted = 0;
        if (toks[i].kind != 1 ||
            !(asm_tok_eq(&toks[i], "struct") || asm_tok_eq(&toks[i], "union")))
            continue;
        j = i + 1;
        if (j < n && toks[j].kind == 1) j++;   /* tag opsional */
        if (j >= n || !asm_tok_is(&toks[j], '{'))
            continue;
        depth = 1;
        k = j + 1;
        while (k < n && depth > 0) {
            if (asm_tok_is(&toks[k], '{')) depth++;
            else if (asm_tok_is(&toks[k], '}')) depth--;
            else if (depth == 1 && !emitted && asm_tok_is(&toks[k], ':') &&
                     k + 1 < n && toks[k + 1].kind == 2) {
                snprintf(out[*count].kind, sizeof(out[*count].kind),
                         "bitfield-endian");
                out[*count].line = toks[i].line;
                snprintf(out[*count].host_fact, sizeof(out[*count].host_fact),
                         "%s, gcc ABI",
                         facts->little_endian == 1 ? "little-endian" :
                         facts->little_endian == 0 ? "big-endian" : "endian=?");
                snprintf(out[*count].risk, sizeof(out[*count].risk),
                         "layout bit-field implementation-defined "
                         "(endianness/ABI); berubah di target lain");
                snprintf(out[*count].next_action,
                         sizeof(out[*count].next_action),
                         "gunakan shift/mask eksplisit bila layout lintas "
                         "target dibutuhkan");
                out[*count].confidence = 70;
                (*count)++;
                emitted = 1;
            }
            k++;
        }
    }
}

static int asm_wide_ptr_type(const asm_tok *t)
{
    static const char *const w[] = {
        "int16_t", "int32_t", "int64_t", "uint16_t", "uint32_t",
        "uint64_t", "uintptr_t", "intptr_t", "size_t", "float", "double"
    };
    size_t i;
    if (t->kind != 1)
        return 0;
    for (i = 0; i < sizeof(w) / sizeof(w[0]); i++)
        if (asm_tok_eq(t, w[i]))
            return 1;
    return 0;
}

/* D4: alignment-cast — (uint16_t *) dst dari buffer byte. */
static void asm_detect_alignment_cast(const asm_tok *toks, int n,
                                      const myc_host_facts *facts,
                                      asm_det *out, int cap, int *count)
{
    int i;
    for (i = 0; i + 3 < n && *count < cap; i++) {
        int t;
        if (toks[i].kind != 0 || toks[i].start[0] != '(')
            continue;
        t = i + 1;
        /* Kualifikasi opsional di dalam cast: (const uint32_t *).
         * Guard `t + 2 < n`: butuh minimal 3 token tersisa (tipe, '*',
         * ')') agar akses toks[t..t+2] selalu dalam batas array. */
        while (t + 2 < n && toks[t].kind == 1 &&
               (asm_tok_eq(&toks[t], "const") ||
                asm_tok_eq(&toks[t], "volatile") ||
                asm_tok_eq(&toks[t], "restrict")))
            t++;
        if (t + 2 >= n)
            continue;
        if (!(asm_wide_ptr_type(&toks[t]) &&
              asm_tok_is(&toks[t + 1], '*') && asm_tok_is(&toks[t + 2], ')'))) {
            /* (long long *) / (long double *) */
            if (!(t + 3 < n && asm_tok_eq(&toks[t], "long") &&
                  toks[t + 1].kind == 1 &&
                  (asm_tok_eq(&toks[t + 1], "long") ||
                   asm_tok_eq(&toks[t + 1], "double")) &&
                  asm_tok_is(&toks[t + 2], '*') &&
                  asm_tok_is(&toks[t + 3], ')')))
                continue;
        }
        snprintf(out[*count].kind, sizeof(out[*count].kind),
                 "alignment-cast");
        out[*count].line = toks[i].line;
        snprintf(out[*count].host_fact, sizeof(out[*count].host_fact),
                 facts->ptr_bits ? "%s, unaligned-ok di x86, ptr=%d-bit"
                                 : "%s, unaligned-ok di x86, ptr=?",
                 facts->little_endian == 1 ? "little-endian" :
                 facts->little_endian == 0 ? "big-endian" : "endian=?",
                 facts->ptr_bits ? facts->ptr_bits : 0);
        snprintf(out[*count].risk, sizeof(out[*count].risk),
                 "alignment fault di ARM/MIPS; endianness mengubah "
                 "interpretasi byte buffer");
        snprintf(out[*count].next_action, sizeof(out[*count].next_action),
                 "gunakan memcpy + konverter endian eksplisit");
        out[*count].confidence = 80;
        (*count)++;
    }
}

/* D5: sizeof-assumption — sizeof(T) dibandingkan konstanta. */
static void asm_detect_sizeof(const asm_tok *toks, int n,
                              const myc_host_facts *facts,
                              asm_det *out, int cap, int *count)
{
    int i;
    for (i = 0; i + 5 < n && *count < cap; i++) {
        int j, k, neg = 0;
        if (toks[i].kind != 1 || !asm_tok_eq(&toks[i], "sizeof"))
            continue;
        if (!asm_tok_is(&toks[i + 1], '(') || toks[i + 2].kind != 1)
            continue;
        j = i + 3;
        if (j < n && asm_tok_is(&toks[j], '*')) j++;   /* void * */
        if (j >= n || !asm_tok_is(&toks[j], ')'))
            continue;
        if (j + 1 >= n || !asm_cmp_op(&toks[j + 1]))
            continue;
        k = j + 2;
        if (k < n && asm_tok_is(&toks[k], '-')) { neg = 1; k++; }
        if (k >= n || toks[k].kind != 2)
            continue;
        (void)neg;
        snprintf(out[*count].kind, sizeof(out[*count].kind),
                 "sizeof-assumption");
        out[*count].line = toks[i].line;
        if (facts->int_bits && facts->ptr_bits)
            snprintf(out[*count].host_fact, sizeof(out[*count].host_fact),
                     "int=%d-bit, ptr=%d-bit",
                     facts->int_bits, facts->ptr_bits);
        else if (facts->int_bits)
            snprintf(out[*count].host_fact, sizeof(out[*count].host_fact),
                     "int=%d-bit, ptr=?", facts->int_bits);
        else if (facts->ptr_bits)
            snprintf(out[*count].host_fact, sizeof(out[*count].host_fact),
                     "int=?, ptr=%d-bit", facts->ptr_bits);
        else
            snprintf(out[*count].host_fact, sizeof(out[*count].host_fact),
                     "int=?, ptr=?");
        snprintf(out[*count].risk, sizeof(out[*count].risk),
                 "sizeof(T) implementation-defined; tebakan ini bisa "
                 "salah di target lain");
        snprintf(out[*count].next_action, sizeof(out[*count].next_action),
                 "gunakan nilai sizeof aktual atau static_assert");
        out[*count].confidence = 80;
        (*count)++;
    }
}

/* ------------------------------------------------------------------ */
/* State .myc/assumptions.json                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    char id[64];
    int  status;          /* myc_assumption_status */
    char source_sha256[65];
    char kind[32];
    int  line;
    char host_fact[96];
    char risk[192];
    char next_action[192];
} asm_state_entry;

typedef struct {
    asm_state_entry e[MYC_ASSUME_MAX_STATE];
    int  count;
} asm_state;

static int asm_ensure_dir(const char *path)
{
    myc_mkdir(path);
    return 1;
}

static void asm_state_load(asm_state *st)
{
    FILE *f;
    char *buf;
    long fsize;
    json_value *root, *arr;
    size_t i;

    memset(st, 0, sizeof(*st));
    f = fopen(MYC_ASSUME_FILE, "rb");
    if (!f)
        return;
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > (long)(4u << 20)) {   /* cap 4 MiB */
        fclose(f);
        return;
    }
    buf = (char *)myc_malloc((size_t)fsize + 1);
    if (!buf) {
        fclose(f);
        return;
    }
    if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        myc_free(buf);
        fclose(f);
        return;
    }
    buf[fsize] = '\0';
    fclose(f);

    if (!json_parse_cstr(buf, &root) || !root) {
        myc_free(buf);
        return;
    }
    arr = json_get(root, "assumptions");
    if (arr && arr->type == JSON_ARR) {
        for (i = 0; i < arr->len && st->count < MYC_ASSUME_MAX_STATE; i++) {
            json_value *e = arr->items[i];
            json_value *v;
            asm_state_entry *se = &st->e[st->count];
            const char *s;
            if (!e || e->type != JSON_OBJ)
                continue;
            memset(se, 0, sizeof(*se));
            s = json_get_str(e, "id");
            if (s) snprintf(se->id, sizeof(se->id), "%s", s);
            s = json_get_str(e, "status");
            se->status = s ? asm_status_from_name(s) : MYC_ASM_OBSERVED;
            s = json_get_str(e, "source_sha256");
            if (s) snprintf(se->source_sha256, sizeof(se->source_sha256), "%s", s);
            s = json_get_str(e, "kind");
            if (s) snprintf(se->kind, sizeof(se->kind), "%s", s);
            v = json_get(e, "line");
            if (v && v->type == JSON_NUM) se->line = (int)v->num;
            s = json_get_str(e, "host_fact");
            if (s) snprintf(se->host_fact, sizeof(se->host_fact), "%s", s);
            s = json_get_str(e, "risk");
            if (s) snprintf(se->risk, sizeof(se->risk), "%s", s);
            s = json_get_str(e, "next_action");
            if (s) snprintf(se->next_action, sizeof(se->next_action), "%s", s);
            if (se->id[0])
                st->count++;
        }
    }
    json_free(root);
    myc_free(buf);
}

static void asm_state_save(const asm_state *st)
{
    json_value *root, *arr;
    char *js = NULL;
    int i;

    if (!st || st->count == 0)
        return;
    asm_ensure_dir(MYC_ASSUME_DIR);
    root = json_new_obj();
    if (!root)
        return;
    arr = json_new_arr();
    if (!arr) {
        json_free(root);
        return;
    }
    for (i = 0; i < st->count; i++) {
        const asm_state_entry *se = &st->e[i];
        json_value *e = json_new_obj();
        json_obj_set(e, "id", json_new_str(se->id));
        json_obj_set(e, "status",
                     json_new_str(myc_assumption_status_name(
                         (myc_assumption_status)se->status)));
        json_obj_set(e, "source_sha256", json_new_str(se->source_sha256));
        json_obj_set(e, "kind", json_new_str(se->kind));
        json_obj_set(e, "line", json_new_num((int64_t)se->line));
        json_obj_set(e, "host_fact", json_new_str(se->host_fact));
        json_obj_set(e, "risk", json_new_str(se->risk));
        json_obj_set(e, "next_action", json_new_str(se->next_action));
        json_arr_push(arr, e);
    }
    json_obj_set(root, "assumptions", arr);
    json_serialize(root, &js);
    json_free(root);
    if (!js)
        return;
    /* PR-012 (MYC-AUDIT-044, P3-T03): tulis ATOMIK (temp+flush+fsync+
     * rename). Crash kapan pun -> assumptions.json OLD valid ATAU NEW
     * valid, tidak pernah setengah. NON-blocking: gagal diabaikan. */
    (void)myc_persist_atomic_write_str(MYC_ASSUME_FILE, js);
    myc_free(js);
}

/* ------------------------------------------------------------------ */
/* Ack --assumption-ack "id:status,..."                               */
/* ------------------------------------------------------------------ */

typedef struct {
    char id[64];
    int  status;
} asm_ack;

static int asm_parse_acks(const char *spec, asm_ack *acks, int cap,
                          int *count)
{
    const char *p = spec;
    while (p && *p && *count < cap) {
        const char *colon = strchr(p, ',');
        const char *end = colon ? colon : p + strlen(p);
        const char *c = (const char *)memchr(p, ':', (size_t)(end - p));
        size_t idlen, sllen;
        int st;
        if (!c)
            return -1;
        idlen = (size_t)(c - p);
        sllen = (size_t)(end - (c + 1));
        if (idlen == 0 || idlen >= sizeof(acks[*count].id) || sllen == 0)
            return -1;
        memcpy(acks[*count].id, p, idlen);
        acks[*count].id[idlen] = '\0';
        {
            char stbuf[24];
            if (sllen >= sizeof(stbuf))
                return -1;
            memcpy(stbuf, c + 1, sllen);
            stbuf[sllen] = '\0';
            st = asm_status_from_name(stbuf);
            if (st == MYC_ASM_OBSERVED && strcmp(stbuf, "observed") != 0)
                return -1;   /* status tidak dikenal */
        }
        acks[*count].status = st;
        (*count)++;
        p = colon ? colon + 1 : NULL;
    }
    return 0;
}

int myc_assume_ack_validate(const char *spec)
{
    asm_ack acks[MYC_ASSUME_MAX_ACKS];
    int count = 0;
    if (!spec || !*spec)
        return -1;
    return asm_parse_acks(spec, acks, MYC_ASSUME_MAX_ACKS, &count);
}

/* ------------------------------------------------------------------ */
/* Run penuh: deteksi + state + ack + report                          */
/* ------------------------------------------------------------------ */

static void asm_make_id(char *out, size_t outsz, const char *kind,
                        const char *anchor)
{
    sha256_ctx ctx;
    uint8_t md[32];
    char hex[65];
    sha256_init(&ctx);
    sha256_update(&ctx, anchor, strlen(anchor));
    sha256_final(&ctx, md);
    sha256_hex(md, 32, hex);
    snprintf(out, outsz, "asm-%.24s-%.8s", kind, hex);
}

static const char *asm_stdc_name(long v)
{
    if (v == 199901L) return "C99";
    if (v == 201112L) return "C11";
    if (v == 201710L) return "C17";
    if (v == 202311L) return "C23";
    if (v == 199409L) return "C94";
    return "?";
}

void myc_assume_run(const myc_request *req, myc_result *res,
                    const char *src, size_t srclen,
                    const myc_host_facts *facts)
{
    asm_tok *toks;
    asm_det  det[MYC_MAX_ASSUMPTIONS];
    int      count = 0;
    int      i, unclosed = 0;
    asm_state st;
    char     rep[2048];
    size_t   off = 0;
    int      ack_ignored = 0;
    char     src_hash[65];

    if (!req || !res || !src)
        return;

    /* 0. Fakta toolchain: diberikan (cache-hit) atau fetch (pipeline). */
    if (facts && facts->ok) {
        res->host_facts = *facts;
        res->assumption_facts_ok = 1;
    } else if (!res->assumption_facts_ok) {
        const char *gcc = req->gcc_program;
        if (!gcc)
            gcc = res->resolved_gcc;
        if (!gcc)
            gcc = "gcc";
        res->assumption_facts_ok =
            myc_assume_fetch_facts(gcc, &res->host_facts);
    }
    facts = &res->host_facts;

    /* 1. Deteksi (tokenize + 5 pola). */
    toks = (asm_tok *)myc_malloc(sizeof(asm_tok) * (size_t)ASM_MAX_TOK);
    if (!toks)
        return;   /* OOM: non-blocking, lewati asumsi */
    {
        int ntok = asm_tokenize(src, srclen, toks, ASM_MAX_TOK);
        asm_detect_char_signedness(toks, ntok, facts, det,
                                   MYC_MAX_ASSUMPTIONS, &count);
        asm_detect_int_width(toks, ntok, facts, det,
                             MYC_MAX_ASSUMPTIONS, &count);
        asm_detect_bitfield(toks, ntok, facts, det,
                            MYC_MAX_ASSUMPTIONS, &count);
        asm_detect_alignment_cast(toks, ntok, facts, det,
                                  MYC_MAX_ASSUMPTIONS, &count);
        asm_detect_sizeof(toks, ntok, facts, det,
                          MYC_MAX_ASSUMPTIONS, &count);
    }
    myc_free(toks);

    /* 2. Materialisasi ke res (arena) + status awal observed. */
    sha256_hex(src, srclen, src_hash);
    for (i = 0; i < count; i++) {
        myc_assumption *a = &res->assumptions[i];
        char *anchor = myc_ledger_build_anchor(src, srclen, det[i].line, 0, 128);
        char idbuf[64];
        asm_make_id(idbuf, sizeof(idbuf), det[i].kind,
                    anchor ? anchor : "?");
        memset(a, 0, sizeof(*a));
        a->id = myc_result_arena_dup(res, idbuf, 0);
        a->kind = myc_result_arena_dup(res, det[i].kind, 0);
        a->line = det[i].line;
        a->anchor = myc_result_arena_dup(res, anchor ? anchor : "", 0);
        a->host_fact = myc_result_arena_dup(res, det[i].host_fact, 0);
        a->risk = myc_result_arena_dup(res, det[i].risk, 0);
        a->next_action = myc_result_arena_dup(res, det[i].next_action, 0);
        a->status = MYC_ASM_OBSERVED;
        a->confidence = det[i].confidence;
        myc_free(anchor);
    }
    res->assumption_detected = count;
    res->assumption_count = count;

    /* 3. Merge status persisten dari .myc/assumptions.json. */
    asm_state_load(&st);
    for (i = 0; i < count; i++) {
        int j;
        for (j = 0; j < st.count; j++) {
            if (strcmp(st.e[j].id, res->assumptions[i].id) == 0) {
                res->assumptions[i].status = st.e[j].status;
                break;
            }
        }
    }

    /* 4. Terapkan --assumption-ack. */
    if (req->assumption_acks && *req->assumption_acks) {
        asm_ack acks[MYC_ASSUME_MAX_ACKS];
        int nack = 0;
        if (asm_parse_acks(req->assumption_acks, acks,
                           MYC_ASSUME_MAX_ACKS, &nack) == 0) {
            int a;
            for (a = 0; a < nack; a++) {
                int found = 0;
                for (i = 0; i < count; i++) {
                    if (strcmp(acks[a].id, res->assumptions[i].id) == 0) {
                        res->assumptions[i].status = acks[a].status;
                        res->assumption_ack_applied++;
                        found = 1;
                        break;
                    }
                }
                if (!found)
                    ack_ignored++;
            }
        }
    }

    /* 5. Unclosed + ok. */
    for (i = 0; i < count; i++) {
        if (res->assumptions[i].status == MYC_ASM_OBSERVED ||
            res->assumptions[i].status == MYC_ASM_CONTRADICTED)
            unclosed++;
    }
    res->assumption_unclosed = unclosed;
    res->assumption_ok = (unclosed == 0);

    /* 6. Persist state: detected (status final) + lama (dilestarikan). */
    {
        asm_state ns;
        memset(&ns, 0, sizeof(ns));
        for (i = 0; i < count && ns.count < MYC_ASSUME_MAX_STATE; i++) {
            const myc_assumption *a = &res->assumptions[i];
            asm_state_entry *se = &ns.e[ns.count];
            snprintf(se->id, sizeof(se->id), "%s", a->id ? a->id : "");
            se->status = a->status;
            snprintf(se->source_sha256, sizeof(se->source_sha256), "%s", src_hash);
            snprintf(se->kind, sizeof(se->kind), "%s", a->kind ? a->kind : "");
            se->line = a->line;
            snprintf(se->host_fact, sizeof(se->host_fact), "%s",
                     a->host_fact ? a->host_fact : "");
            snprintf(se->risk, sizeof(se->risk), "%s", a->risk ? a->risk : "");
            snprintf(se->next_action, sizeof(se->next_action), "%s",
                     a->next_action ? a->next_action : "");
            ns.count++;
        }
        for (i = 0; i < st.count && ns.count < MYC_ASSUME_MAX_STATE; i++) {
            int dup = 0, j;
            for (j = 0; j < ns.count; j++)
                if (strcmp(ns.e[j].id, st.e[i].id) == 0) { dup = 1; break; }
            if (!dup)
                ns.e[ns.count++] = st.e[i];
        }
        /* Simpan HANYA bila state berubah (ack / status baru / id baru)
         * — hindari rewrite .myc/assumptions.json pada cache-hit yang
         * identik (churn mtime tanpa perubahan konten). */
        {
            int changed = res->assumption_ack_applied > 0;
            for (i = 0; i < count && !changed; i++) {
                int j, found = 0;
                for (j = 0; j < st.count; j++) {
                    if (strcmp(st.e[j].id, res->assumptions[i].id) == 0) {
                        found = 1;
                        if (st.e[j].status != res->assumptions[i].status)
                            changed = 1;
                        break;
                    }
                }
                if (!found)
                    changed = 1;
            }
            if (changed)
                asm_state_save(&ns);
        }
    }

    /* 7. Report (teks). */
#define A_APPEND(...) do { \
        int _n = snprintf(rep + off, sizeof(rep) - off, __VA_ARGS__); \
        if (_n > 0) off += (size_t)_n; \
        if (off >= sizeof(rep)) off = sizeof(rep) - 1; \
    } while (0)
    if (facts->ok) {
        A_APPEND("toolchain: char=%s, int=%d-bit, ptr=%d-bit, %s, %s\n",
                 asm_char_fact(facts),
                 facts->int_bits ? facts->int_bits : 0,
                 facts->ptr_bits ? facts->ptr_bits : 0,
                 facts->little_endian == 1 ? "little-endian" :
                 facts->little_endian == 0 ? "big-endian" : "endian=?",
                 asm_stdc_name(facts->stdc_version));
    }
    A_APPEND("%d asumsi terdeteksi, %d terbuka "
             "(status: observed/contradicted)\n",
             count, unclosed);
    for (i = 0; i < count; i++) {
        const myc_assumption *a = &res->assumptions[i];
        A_APPEND("  [%d] %s line %d %s (conf %d) status=%s\n",
                 i + 1, a->id ? a->id : "(null)", a->line,
                 a->kind ? a->kind : "(null)", a->confidence,
                 myc_assumption_status_name(
                     (myc_assumption_status)a->status));
        A_APPEND("      host: %s | risiko: %s\n",
                 a->host_fact ? a->host_fact : "(null)",
                 a->risk ? a->risk : "(null)");
        A_APPEND("      next: %s\n",
                 a->next_action ? a->next_action : "(null)");
    }
    if (res->assumption_ack_applied > 0)
        A_APPEND("ack: %d asumsi ditutup run ini (--assumption-ack)\n",
                 res->assumption_ack_applied);
    if (ack_ignored > 0)
        A_APPEND("ack: %d id tidak terdeteksi (diabaikan)\n", ack_ignored);
    res->assumption_report = myc_result_arena_dup(res, rep, off);
#undef A_APPEND
}

/* ------------------------------------------------------------------ */
/* Enforce --require-assumptions-closed                               */
/* ------------------------------------------------------------------ */

void myc_assume_enforce(const myc_request *req, myc_result *res)
{
    int present = 0;
    int rebuilt = 0;
    size_t i;

    if (!req || !res || !req->require_assumptions_closed)
        return;
    if (res->assumption_unclosed == 0)
        return;

    for (i = 0; i < res->debt_count; i++) {
        if (res->debt[i].type == MYC_DEBT_ASSUMPTION)
            present = 1;
    }
    if (!present && res->debt_count < MYC_MAX_DEBT) {
        res->debt[res->debt_count].type = MYC_DEBT_ASSUMPTION;
        res->debt[res->debt_count].text =
            "asumsi portabilitas belum ditutup (lihat assumption_report)";
        res->debt_count++;
        rebuilt = 1;
    }

    /* Verdict findings (bug nyata) TIDAK diturunkan; hanya gap yang
     * membuat OK -> INCONCLUSIVE (pola enforce_require_complete). */
    if (res->verdict == MC_OK) {
        res->verdict = MC_INCONCLUSIVE;
        if (res->finding == MYC_FINDING_CLEAN)
            res->finding = MYC_FINDING_INCONCLUSIVE;
        if (res->completeness == MYC_COMPLETENESS_COMPLETE)
            res->completeness = MYC_COMPLETENESS_INCOMPLETE;
        rebuilt = 1;
    }

    /* Receipt berubah (debt baru / verdict flip) -> bangun ulang SEKALI
     * agar sidik jari sesuai hasil akhir (pola 9.10). */
    if (rebuilt)
        myc_rebuild_receipt(res);
}
