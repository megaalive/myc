/*
 * parser_fuzz.c -- PR-010 (P2-T03 tahap 2): parser fuzz harness.
 *
 * Seed awal = korpus PR-009 (payload backend_fake.c) + contoh JSON konsumen
 * nyata + tepi. Mesin mutasi deterministik (xorshift32, --seed) menerapkan
 * SEMUA kelas mutasi P2-T03:
 *   1. grammar-aware (dup key, reorder, unknown enum)
 *   2. truncation di SETIAP posisi byte (pass khusus untuk seed kecil)
 *   3. duplicate keys
 *   4. extreme nesting (melewati JSON_MAX_DEPTH)
 *   5. extreme numbers (huge int / 1e999 / INT64_MIN literal)
 *   6. embedded NUL
 *   7. invalid UTF-8 (overlong, surrogate-encoded, lone continuation)
 *   8. oversized strings (hingga 32 KB)
 *   9. reordered fields
 *  10. unknown enum values
 *  + bit flip / byte insert-delete-set / splice dua seed / truncate.
 *
 * Target:
 *   A. json_parse LANGSUNG + round-trip (serialize -> parse ulang wajib
 *      valid, MYC-AUDIT-042) + json_clone (serialize(clone)==serialize).
 *   B. Konsumen JSON langsung (fail-closed INV-011): myc_budget_parse,
 *      myc_calib_outcome_parse/id_valid, myc_scenario_apply (file korup),
 *      myc_cache_try_replay (file cache korup -> miss, tidak crash).
 *   C. Parser backend E2E via fake backend mode payload-file: GCC
 *      diagnostics (ingest_gcc_diagnostics), Fil-C report
 *      (parse_filc_report), Frama-C Eva (count_eva_alarms) -- byte mutasi
 *      APA SAJA mencapai parser asli. Invariant INV-006: garbage tanpa
 *      marker kanonik TIDAK pernah jadi finding; marker kanonik + exit!=0
 *      = bukti sah (positive control harus tetap terdeteksi).
 *
 * Crash / semantic seed dipersist ke .myc/regression/parser_<sha8>.bin +
 * parser-index.txt (idempoten); `--replay` menjalankan ulang semua seed
 * tersimpan (backstop: parser berhenti menangkap = terlihat). POSIX:
 * handler sinyal menulis seed saat ini ke
 * .myc/regression/parser_crash_last.bin sebelum exit non-zero.
 *
 * Exit: 0 = bersih; 1 = semantic violation ditemukan; crash = sinyal/ASan
 * (non-zero). Deterministik: seed PRNG + iterasi cukup untuk reproduce.
 *
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
 *       -o test/parser_fuzz test/parser_fuzz.c <SRCS>
 * ASan lane (crash detector utama):
 *   gcc -O1 -g -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN \
 *       -fsanitize=address,undefined -fno-omit-frame-pointer \
 *       -o test/parser_fuzz_asan test/parser_fuzz.c <SRCS>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(_WIN32)
#include <direct.h>
#include <process.h>
#define mkdir_one(p) _mkdir(p)
#define rmdir_one(p) _rmdir(p)
#define chdir_one(p) _chdir(p)
#define getcwd_one(b, n) _getcwd(b, n)
#else
#include <sys/stat.h>
#include <unistd.h>
#define mkdir_one(p) mkdir(p, 0700)
#define rmdir_one(p) rmdir(p)
#define chdir_one(p) chdir(p)
#define getcwd_one(b, n) getcwd(b, n)
#endif

#include "budget.h"
#include "cache.h"
#include "calibrate.h"
#include "json.h"
#include "myc.h"
#include "scenario.h"
#include "sha256.h"

static int g_fail = 0;
static uint64_t g_n_json = 0;      /* iterasi json langsung (valid+invalid) */
static uint64_t g_n_json_ok = 0;

/* Source bersih untuk run E2E (compile OK di semua toolchain). */
static const char *SRC_CLEAN = "int main(void) { return 0; }\n";

#define CHECK(cond, fmt, ...) do {                                    \
        if (cond) {                                                   \
            printf("[OK]   " fmt "\n", ##__VA_ARGS__);                \
        } else {                                                      \
            fprintf(stderr, "[FAIL] " fmt "\n", ##__VA_ARGS__);       \
            g_fail++;                                                 \
        }                                                             \
    } while (0)

/* ------------------------------------------------------------------ */
/* PRNG xorshift32 deterministik                                       */
/* ------------------------------------------------------------------ */
static uint32_t g_rng;

static uint32_t rng_next(void)
{
    uint32_t x = g_rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng = x;
    return x;
}

static uint32_t rng_below(uint32_t n)
{
    return n ? rng_next() % n : 0;
}

/* ------------------------------------------------------------------ */
/* Seed corpus (PR-009 + konsumen + tepi)                              */
/* ------------------------------------------------------------------ */
typedef struct {
    const char *name;
    const char *data;
    size_t      len;
} corpus_seed;

#define S(n, s) { n, s, sizeof(s) - 1 }

/* Payload di-transkripsi dari tests/backend_fake.c (PR-009) + bentuk
 * JSON konsumen nyata (budget/scenario/cache/calib/MCP) + tepi P2-T03. */
static const corpus_seed g_corpus[] = {
    /* ---- GCC JSON diagnostics (PR-009) ---- */
    S("gcc-json-valid",
      "[{\"kind\":\"error\",\"message\":\"fake oob at index\","
      "\"locations\":[{\"caret\":{\"line\":3,\"column\":7}}]}]"),
    S("gcc-json-truncated", "[{\"kind\":\"error\",\"message\":\"fake oo"),
    S("gcc-json-garbage", "[{\"kind\": error, \"message\": \xff\xfe"),
    S("gcc-json-dupkeys",
      "[{\"kind\":\"error\",\"message\":\"m1\",\"kind\":\"warning\","
      "\"message\":\"m2\"}]"),
    S("gcc-json-hugenum",
      "[{\"kind\":\"error\",\"message\":\"x\",\"locations\":[{\"caret\":"
      "{\"line\":99999999999999999999,\"column\":-9223372036854775808}}]}]"),
    S("gcc-json-utf8", "[{\"kind\":\"error\",\"message\":\"\xff\xfe bad utf8\"}]"),
    S("gcc-json-reordered",
      "[{\"message\":\"reordered ok\",\"kind\":\"error\",\"locations\":"
      "[{\"caret\":{\"column\":2,\"line\":9}}]}]"),
    S("gcc-json-unknown-kind", "[{\"kind\":\"bogus\",\"message\":\"unknown\"}]"),
    S("gcc-json-note-only", "[{\"kind\":\"note\",\"message\":\"note only\"}]"),
    /* ---- GCC text fallback (PR-009) ---- */
    S("gcc-text-valid", "<stdin>:5:9: error: fake text oob\n"),
    S("gcc-text-hugeloc",
      "<stdin>:99999999999999999999:99999999999999999999: error: huge\n"),
    S("gcc-text-garbage",
      "cc1.exe: fatal error: this is not a diagnostic\n"
      "  'main': events\nsome random text without location\n"),
    S("gcc-text-nocolon", "<stdin>:abc:def: error: no line/col\n"),
    S("gcc-exit0-garbage",
      "ERROR: AddressSanitizer: fake\n[{\"kind\":\"error\",\"message\":\"x\""),
    /* ---- Fil-C report (PR-009) ---- */
    S("filc-panic-valid",
      "filc safety error: cannot write pointer with ptr >= upper.\n"
      "    pointer: 0x7ffb53684238\n"
      "semantic origin:\n"
      "    (fake) /tmp/f.c:2:43: main\n"
      "[12345] filc panic: thwarted a futile attempt to violate memory"
      " safety.\n"),
    S("filc-panic-exit0",
      "filc safety error: cannot write pointer with ptr >= upper.\n"
      "[12345] filc panic: thwarted a futile attempt to violate memory"
      " safety.\n"),
    S("filc-panic-truncated", "[123] filc pan"),
    S("filc-dup",
      "[1] filc panic: dup case 1\n[2] filc panic: dup case 2\n"
      "[3] filc panic: dup case 3\n"),
    /* ---- Frama-C Eva (PR-009) ---- */
    S("eva-alarm-valid",
      "[eva:alarm] /tmp/f.c:3: Warning: out of bounds read\n"
      "ANALYSIS SUMMARY\n0 alarms generated by the analysis.\n"),
    S("eva-alarm-hugeline",
      "[eva:alarm] /tmp/f.c:99999999999999999999: Warning: x\n"
      "ANALYSIS SUMMARY\n"),
    S("eva-garbage-summary", "some garbage without alarms\nANALYSIS SUMMARY\n"),
    /* ---- JSON konsumen nyata ---- */
    S("budget-valid", "{\"required\":{\"compile\":\"clean\"},\"max_time_ms\":"
                      "10000,\"max_output_bytes\":16384}"),
    S("budget-wrongschema", "{\"gates\":{\"compile\":\"clean\"}}"),
    S("scenario-pack", "{\"version\":1,\"scenarios\":[{\"name\":\"cli\","
                       "\"desc\":\"x\",\"flags\":[\"--run\"],\"env\":{}}]}"),
    S("cache-entry", "{\"entries\":[{\"key_sha256\":\"abc\",\"verdict\":0,"
                     "\"receipt_sha256\":\"def\"}]}"),
    S("calib-ledger", "{\"schema\":\"myc.calibration.v1\",\"entries\":["
                      "{\"rule\":\"lint\",\"counts\":[1,0,0,0,0,0],"
                      "\"match\":\"oob\"}]}"),
    S("mcp-request", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                     "\"params\":{\"name\":\"check\",\"arguments\":{\"file\":"
                     "\"x.c\"}}}"),
    /* ---- tepi P2-T03 ---- */
    S("empty", ""),
    S("one-space", " "),
    S("lbrace", "{"),
    S("lbracket", "["),
    S("quote", "\""),
    S("nul-json", "\x00"),
    S("ff-byte", "\xff"),
    S("deep-arr", "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
                  "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
                  "1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
                  "]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"),
    S("huge-int", "99999999999999999999999999999999999999999999999999"),
    S("huge-neg", "-92233720368547758080"),
    S("int64-min", "-9223372036854775808"),
    S("one-e999", "1e999"),
    S("utf8-overlong", "\"\xc0\xaf\""),
    S("utf8-surrogate", "\"\xed\xa0\x80\""),
    S("utf8-lone-cont", "\"\x80\""),
    S("esc-nul", "\"\\u0000\""),
    S("esc-lone-high", "\"\\ud800\""),
    S("reordered-obj", "{\"b\":2,\"a\":1}"),
    S("dup-key-obj", "{\"a\":1,\"a\":2}"),
    S("unknown-enum", "[{\"kind\":\"bogus\",\"level\":\"nonsense\"}]"),
    S("control-chars", "{\"a\":\"\x01\x02\x1f\"}"),
    S("valid-arr", "[1,2,{\"b\":\"c\"}]"),
    S("valid-obj", "{\"a\":1,\"b\":[true,false,null]}"),
    S("trailing-garbage", "[1] x"),
    S("missing-close", "{\"a\":1"),
};

static const size_t g_corpus_n = sizeof(g_corpus) / sizeof(g_corpus[0]);

/* ------------------------------------------------------------------ */
/* Mesin mutasi                                                        */
/* ------------------------------------------------------------------ */
#define MAX_SEED 65536

/* byte "menarik" untuk mutasi: NUL, kontrol, delimiter JSON, UTF-8
 * invalid, digit, e/E/-/. dst. */
static const unsigned char g_interesting[] = {
    0x00, 0x09, 0x0a, 0x0d, 0x1f, 0x20, 0x22, 0x2c, 0x3a, 0x5b, 0x5c,
    0x5d, 0x7b, 0x7d, 0x7f, 0x80, 0xc0, 0xed, 0xfe, 0xff,
    '0', '1', '9', 'e', 'E', '-', '+', '.', 'u', 't', 'f', 'n', 'a'
};
static const size_t g_interesting_n = sizeof(g_interesting) / sizeof(g_interesting[0]);

enum {
    M_BITFLIP, M_SETBYTE, M_INSERT, M_DELETE, M_TRUNCATE, M_SPLICE,
    M_DUPKEY, M_DEEP, M_HUGENUM, M_NUL, M_UTF8, M_OVERSIZE, M_REORDER,
    M_ENUM, M_COUNT
};

/* Terapkan satu mutasi pada buffer [b,len); return len baru (cap MAX_SEED). */
static size_t mutate_once(unsigned char *b, size_t len)
{
    uint32_t op = rng_below(M_COUNT);
    size_t   pos, i, n;
    switch (op) {
    case M_BITFLIP:
        if (len == 0) return 0;
        pos = rng_below((uint32_t)len);
        b[pos] ^= (unsigned char)(1u << rng_below(8));
        break;
    case M_SETBYTE:
        if (len == 0) return 0;
        pos = rng_below((uint32_t)len);
        b[pos] = g_interesting[rng_below((uint32_t)g_interesting_n)];
        break;
    case M_INSERT:
        if (len + 1 >= MAX_SEED) break;
        pos = rng_below((uint32_t)(len + 1));
        memmove(b + pos + 1, b + pos, len - pos);
        b[pos] = g_interesting[rng_below((uint32_t)g_interesting_n)];
        len++;
        break;
    case M_DELETE:
        if (len == 0) return 0;
        pos = rng_below((uint32_t)len);
        memmove(b + pos, b + pos + 1, len - pos - 1);
        len--;
        break;
    case M_TRUNCATE:
        if (len == 0) return 0;
        len = rng_below((uint32_t)len);
        break;
    case M_SPLICE: {
        /* tempel ekor seed acak lain ke ujung buffer. */
        const corpus_seed *cs = &g_corpus[rng_below((uint32_t)g_corpus_n)];
        size_t tail = rng_below((uint32_t)(cs->len + 1));
        if (len + (cs->len - tail) >= MAX_SEED) break;
        memcpy(b + len, cs->data + tail, cs->len - tail);
        len += cs->len - tail;
        break;
    }
    case M_DUPKEY: {
        static const char frag[] = ",\"k\":1";
        if (len + sizeof(frag) - 1 >= MAX_SEED) break;
        pos = rng_below((uint32_t)(len + 1));
        memmove(b + pos + sizeof(frag) - 1, b + pos, len - pos);
        memcpy(b + pos, frag, sizeof(frag) - 1);
        len += sizeof(frag) - 1;
        break;
    }
    case M_DEEP: {
        /* gelombang '[[' melewati JSON_MAX_DEPTH (64): parser harus
         * menolak tanpa stack overflow. */
        static const char wave[] = "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[";
        size_t w = sizeof(wave) - 1;
        if (len + w >= MAX_SEED) break;
        pos = rng_below((uint32_t)(len + 1));
        memmove(b + pos + w, b + pos, len - pos);
        memcpy(b + pos, wave, w);
        len += w;
        break;
    }
    case M_HUGENUM: {
        static const char huge[] = "99999999999999999999999999999999";
        if (len + sizeof(huge) - 1 >= MAX_SEED) break;
        pos = rng_below((uint32_t)(len + 1));
        memmove(b + pos + sizeof(huge) - 1, b + pos, len - pos);
        memcpy(b + pos, huge, sizeof(huge) - 1);
        len += sizeof(huge) - 1;
        break;
    }
    case M_NUL:
        if (len + 1 >= MAX_SEED) break;
        pos = rng_below((uint32_t)(len + 1));
        memmove(b + pos + 1, b + pos, len - pos);
        b[pos] = 0;
        len++;
        break;
    case M_UTF8: {
        /* urutan UTF-8 invalid deterministik. */
        static const unsigned char bad[][4] = {
            { 0xff }, { 0xfe }, { 0x80 }, { 0xc0, 0xaf },
            { 0xed, 0xa0, 0x80 }, { 0xf4, 0x90, 0x80, 0x80 },
            { 0xe2, 0x82 }, { 0xf0, 0x9f, 0x92 }
        };
        static const size_t blen[] = { 1, 1, 1, 2, 3, 4, 2, 3 };
        n = rng_below((uint32_t)(sizeof(blen) / sizeof(blen[0])));
        if (len + blen[n] >= MAX_SEED) break;
        pos = rng_below((uint32_t)(len + 1));
        memmove(b + pos + blen[n], b + pos, len - pos);
        memcpy(b + pos, bad[n], blen[n]);
        len += blen[n];
        break;
    }
    case M_OVERSIZE: {
        /* ledakkan string: 8..32 KB 'A' di dalam buffer. */
        size_t run = 8192 + rng_below(24576);
        if (len + run >= MAX_SEED) run = MAX_SEED - len - 1;
        if (run == 0) break;
        pos = rng_below((uint32_t)(len + 1));
        memmove(b + pos + run, b + pos, len - pos);
        memset(b + pos, 'A', run);
        len += run;
        break;
    }
    case M_REORDER: {
        /* tukar dua potong buffer. */
        size_t a, c, k;
        if (len < 4) break;
        a = rng_below((uint32_t)(len / 2));
        c = (len / 2) + rng_below((uint32_t)(len - (len / 2)));
        k = 1 + rng_below((uint32_t)(len / 4));
        if (k > len / 2) k = len / 2;
        if (a + k > len) k = len - a;
        if (c + k > len) k = len - c;
        for (i = 0; i < k; i++) {
            unsigned char t = b[a + i];
            b[a + i] = b[c + i];
            b[c + i] = t;
        }
        break;
    }
    case M_ENUM: {
        static const char frag[] = "\"level\":\"nonsense\"";
        if (len + sizeof(frag) - 1 >= MAX_SEED) break;
        pos = rng_below((uint32_t)(len + 1));
        memmove(b + pos + sizeof(frag) - 1, b + pos, len - pos);
        memcpy(b + pos, frag, sizeof(frag) - 1);
        len += sizeof(frag) - 1;
        break;
    }
    default:
        break;
    }
    return len;
}

/* Bangkitkan satu seed mutasi dari corpus: 1..4 mutasi berantai. */
static size_t make_seed(unsigned char *b, size_t cap)
{
    const corpus_seed *cs = &g_corpus[rng_below((uint32_t)g_corpus_n)];
    size_t len = cs->len < cap ? cs->len : cap;
    uint32_t rounds = 1 + rng_below(4);
    uint32_t r;
    memcpy(b, cs->data, len);
    for (r = 0; r < rounds; r++)
        len = mutate_once(b, len);
    return len;
}

/* ------------------------------------------------------------------ */
/* Crash-seed capture + persist ke regression corpus                   */
/* ------------------------------------------------------------------ */
#define REG_DIR   ".myc/regression"
#define REG_INDEX ".myc/regression/parser-index.txt"
#define REG_CRASH ".myc/regression/parser_crash_last.bin"

static unsigned char g_cur_seed[MAX_SEED];
static size_t        g_cur_len = 0;
static const char   *g_cur_tag = "json";

#if !defined(_WIN32)
#include <fcntl.h>
#include <signal.h>
static void crash_handler(int sig)
{
    int fd;
    (void)sig;
    fd = open(REG_CRASH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        if (g_cur_len > 0)
            (void)write(fd, g_cur_seed, g_cur_len);
        close(fd);
    }
    _Exit(128 + sig);
}

static void install_crash_handlers(void)
{
    signal(SIGSEGV, crash_handler);
    signal(SIGBUS, crash_handler);
    signal(SIGILL, crash_handler);
    signal(SIGFPE, crash_handler);
    signal(SIGABRT, crash_handler);
}
#else
static void install_crash_handlers(void)
{
    /* Windows: MinGW tidak menjamin signal() menangkap access violation.
     * Deteksi crash = ASan lane (parser_fuzz_asan) + exit code; seed saat
     * ini dijamin repro via --seed/--iters (deterministik). */
}
#endif

static void save_seed_file(const char *sha8, const unsigned char *b,
                           size_t len, const char *target, uint64_t iter,
                           const char *reason)
{
    char  path[560];
    FILE *f;
    mkdir_one(".myc");
    mkdir_one(REG_DIR);
    snprintf(path, sizeof(path), "%s/parser_%.8s.bin", REG_DIR, sha8);
    if ((f = fopen(path, "rb")) != NULL) {   /* idempoten per sha8 */
        fclose(f);
        return;
    }
    f = fopen(path, "wb");
    if (!f)
        return;
    if (len > 0)
        fwrite(b, 1, len, f);
    fclose(f);
    f = fopen(REG_INDEX, "ab");
    if (f) {
        fprintf(f, "parser %.8s %s %llu %s\n", sha8, target,
                (unsigned long long)iter, reason ? reason : "");
        fclose(f);
    }
}

static void persist_seed(const unsigned char *b, size_t len,
                         const char *target, uint64_t iter, const char *reason)
{
    char hash[65];
    sha256_hex(b, len, hash);
    save_seed_file(hash, b, len, target, iter, reason);
}

/* ------------------------------------------------------------------ */
/* Pemeriksaan semantik langsung                                       */
/* ------------------------------------------------------------------ */

/* json_parse + round-trip + clone. Return 1 = inconsistent (bug). */
static int run_json_check(const unsigned char *b, size_t len)
{
    json_value *v = NULL;
    int         ok = json_parse((const char *)b, len, &v);
    g_n_json++;
    if (ok && !v) {
        fprintf(stderr, "[FAIL] json_parse ok==1 tapi v==NULL (len=%u)\n",
                (unsigned)len);
        g_fail++;
        return 1;
    }
    if (!ok && v) {
        fprintf(stderr, "[FAIL] json_parse ok==0 tapi v!=NULL (len=%u)\n",
                (unsigned)len);
        json_free(v);
        g_fail++;
        return 1;
    }
    if (!ok)
        return 0;
    g_n_json_ok++;
    {
        char       *s = NULL;
        json_value *v2 = NULL;
        if (!json_serialize(v, &s) || !s) {
            fprintf(stderr, "[FAIL] json_serialize gagal utk input valid\n");
            json_free(v);
            g_fail++;
            return 1;
        }
        if (!json_parse(s, strlen(s), &v2)) {
            fprintf(stderr,
                    "[FAIL] round-trip: serialize tidak ter-parse ulang "
                    "(ok==1, len=%u)\n", (unsigned)len);
            free(s);
            json_free(v);
            g_fail++;
            return 1;
        }
        {
            json_value *c = json_clone(v);
            char       *sc = NULL;
            if (!c) {
                fprintf(stderr, "[FAIL] json_clone NULL utk input valid\n");
                free(s);
                json_free(v2);
                json_free(v);
                g_fail++;
                return 1;
            }
            if (!json_serialize(c, &sc) || !sc || strcmp(s, sc) != 0) {
                /* Review PR-010: branch ini SEMPAT false-green (print
                 * [FAIL] tanpa g_fail++/persist/return). Invariant clone
                 * adalah backstop — kegagalan harus menggagalkan run dan
                 * menyimpan seed. */
                fprintf(stderr,
                        "[FAIL] json_clone hasilkan tree berbeda "
                        "(serialize mismatch)\n");
                g_fail++;
                persist_seed(b, len, "json", g_n_json,
                             "clone serialize mismatch");
            }
            free(sc);
            json_free(c);
        }
        free(s);
        json_free(v2);
    }
    json_free(v);
    return 0;
}

/* Konsumen JSON: budget fail-closed. */
static void run_budget_check(const unsigned char *b, size_t len)
{
    myc_budget_contract bc;
    int rc;
    memset(&bc, 0, sizeof(bc));
    rc = myc_budget_parse((const char *)b, len, &bc);
    if (rc != -1 && rc != 0) {
        fprintf(stderr, "[FAIL] myc_budget_parse rc=%d (harus -1/0)\n", rc);
        g_fail++;
        persist_seed(b, len, "budget", g_n_json, "rc aneh");
    } else if (rc == 0 && bc.active != 1) {
        fprintf(stderr, "[FAIL] budget rc==0 tapi active!=1\n");
        g_fail++;
        persist_seed(b, len, "budget", g_n_json, "active tak ter-set");
    } else if (rc == -1 && bc.active != 0) {
        fprintf(stderr, "[FAIL] budget rc==-1 tapi active!=0\n");
        g_fail++;
        persist_seed(b, len, "budget", g_n_json, "active ter-set saat gagal");
    }
    myc_budget_free(&bc);
}

/* Konsumen JSON: calib enum fail-closed (INV-011). */
static void run_calib_check(const unsigned char *b, size_t len)
{
    char              s[256];
    size_t            n = len < sizeof(s) - 1 ? len : sizeof(s) - 1;
    myc_calib_outcome oc;
    int               rc;
    memcpy(s, b, n);
    s[n] = '\0';
    rc = myc_calib_outcome_parse(s, &oc);
    if (rc != -1 && rc != 0) {
        fprintf(stderr, "[FAIL] myc_calib_outcome_parse rc=%d (harus -1/0)\n",
                rc);
        g_fail++;
        persist_seed(b, len, "calib", g_n_json, "outcome rc aneh");
    }
    if (myc_calib_id_valid(s) != 0 && myc_calib_id_valid(s) != 1) {
        fprintf(stderr, "[FAIL] myc_calib_id_valid rc aneh\n");
        g_fail++;
        persist_seed(b, len, "calib", g_n_json, "id_valid rc aneh");
    }
}

/* Konsumen JSON: scenario profile file korup -> fail-closed, verdict
 * TIDAK boleh berubah (scenario non-blocking). */
static void run_scenario_check(const unsigned char *b, size_t len)
{
    static const char *path = "test/.parser_fuzz_scen.json";
    FILE             *f = fopen(path, "wb");
    myc_request       req;
    myc_result        res;
    myc_verdict       before;
    int               rc;
    if (!f)
        return;
    fwrite(b, 1, len, f);
    fclose(f);
    myc_request_init(&req);
    myc_result_init(&res);
    before = res.verdict;   /* myc_result_init -> MC_ERROR (sentinel "belum
                               dijalankan"); scenario TIDAK boleh mengubah */
    rc = myc_scenario_apply(&req, "fz", SRC_CLEAN, strlen(SRC_CLEAN),
                            path, &res);
    if (rc < -2 || rc > 0) {
        fprintf(stderr, "[FAIL] myc_scenario_apply rc=%d (harus -2..0)\n", rc);
        g_fail++;
        persist_seed(b, len, "scenario", g_n_json, "rc di luar -2..0");
    }
    if (res.verdict != before) {
        fprintf(stderr,
                "[FAIL] scenario mengubah verdict (scenario harus "
                "non-blocking; sebelum=%d sesudah=%d)\n",
                (int)before, (int)res.verdict);
        g_fail++;
        persist_seed(b, len, "scenario", g_n_json, "verdict berubah");
    }
    myc_result_free(&res);
    remove(path);
}

/* Konsumen JSON: cache file korup -> miss (0), tidak crash, tidak pernah
 * dipercaya (INV-012). */
static void run_cache_check(const unsigned char *b, size_t len)
{
    char         old_cwd[1024];
    char         dir[128], myc_dir[160], cache_path[200];
    FILE        *f;
    myc_request  req;
    myc_result   res;
    int          rc;
    const char  *cd;

    cd = getcwd_one(old_cwd, sizeof(old_cwd));
    if (!cd)
        return;
    snprintf(dir, sizeof(dir), "test/.parser_fuzz_cache");
    mkdir_one(dir);
    snprintf(myc_dir, sizeof(myc_dir), "%s/.myc", dir);
    mkdir_one(myc_dir);
    snprintf(cache_path, sizeof(cache_path), "%s/evidence_cache.json",
             myc_dir);
    f = fopen(cache_path, "wb");
    if (f) {
        fwrite(b, 1, len, f);
        fclose(f);
    }
    chdir_one(dir);
    myc_request_init(&req);
    myc_result_init(&res);
    rc = myc_cache_try_replay(&req, &res, (const char *)b, len);
    if (rc != 0 && rc != 1) {
        fprintf(stderr, "[FAIL] myc_cache_try_replay rc=%d (harus 0/1)\n", rc);
        g_fail++;
        persist_seed(b, len, "cache", g_n_json, "replay rc aneh");
    }
    myc_result_free(&res);
    chdir_one(old_cwd);
    remove(cache_path);
    rmdir_one(myc_dir);
    rmdir_one(dir);
}

/* ------------------------------------------------------------------ */
/* E2E via fake backend (mode payload-file)                            */
/* ------------------------------------------------------------------ */
static void env_set(const char *name, const char *value)
{
    size_t n = strlen(name) + 1 + strlen(value) + 1;
    char  *e = (char *)malloc(n);
    if (!e)
        return;
    snprintf(e, n, "%s=%s", name, value);
#if defined(_WIN32)
    _putenv(e);
#else
    setenv(name, value, 1);
#endif
    free(e);
}

static char *g_saved_path = NULL;

static void path_prepend(const char *dir)
{
    const char *old = getenv("PATH");
    const char *sep = ";";
    size_t      n;
    char       *p;
#if !defined(_WIN32)
    sep = ":";
#endif
    if (g_saved_path) {
        free(g_saved_path);
        g_saved_path = NULL;
    }
    g_saved_path = old ? strdup(old) : NULL;
    n = strlen(dir) + 1 + (old ? strlen(old) : 0) + 1;
    p = (char *)malloc(n);
    if (!p)
        return;
    snprintf(p, n, "%s%s%s", dir, sep, old ? old : "");
    env_set("PATH", p);
    free(p);
}

static void path_restore(void)
{
    if (g_saved_path) {
        env_set("PATH", g_saved_path);
        free(g_saved_path);
        g_saved_path = NULL;
    }
}

static int has_marker(const unsigned char *b, size_t len, const char *pat)
{
    size_t pl = strlen(pat);
    size_t i;
    if (pl == 0 || pl > len)
        return 0;
    for (i = 0; i + pl <= len; i++)
        if (memcmp(b + i, pat, pl) == 0)
            return 1;
    return 0;
}

static void run_src(myc_request *req, myc_result *res, int filc,
                   int prove, const char *gcc_program)
{
    myc_request_init(req);
    req->input.kind = MYC_SOURCE_MEMORY;
    req->input.data = SRC_CLEAN;
    req->input.len = strlen(SRC_CLEAN);
    req->cwd = ".";
    req->run_lint = 1;
    req->filc = filc;
    req->prove = prove;
    req->gcc_program = gcc_program;
    req->no_cache = 1;   /* deterministik: jangan biarkan cache ikut campur */
    myc_result_init(res);
    myc_run(req, res);
}

/* Tulis payload ke file untuk fake backend (payload-file mode). */
static void write_payload_file(const unsigned char *b, size_t len)
{
    FILE *f = fopen("test/.parser_fuzz_payload.bin", "wb");
    if (f) {
        if (len > 0)
            fwrite(b, 1, len, f);
        fclose(f);
    }
}

/* GCC diagnostics parser E2E. exit1 -> COMPILE_ERROR (exit-code evidence),
 * exit0 -> OK (garbage di stderr tidak jadi finding). */
static void e2e_gcc(const char *fake_gcc, int iters)
{
    int i;
    for (i = 0; i < iters; i++) {
        unsigned char b[MAX_SEED];
        size_t        len = make_seed(b, MAX_SEED);
        myc_request   req;
        myc_result    res;
        int           exit1 = (int)(i & 1);
        write_payload_file(b, len);
        env_set("MYC_FAKE_ROLE", "gcc");
        env_set("MYC_FAKE_MODE", "payload-file");
        env_set("MYC_FAKE_PAYLOAD_FILE", "test/.parser_fuzz_payload.bin");
        env_set("MYC_FAKE_EXIT", exit1 ? "1" : "0");
        memcpy(g_cur_seed, b, len);
        g_cur_len = len;
        g_cur_tag = "gcc";
        run_src(&req, &res, 0, 0, fake_gcc);
        if (exit1) {
            CHECK(res.verdict == MC_COMPILE_ERROR,
                  "E2E gcc iter %d (exit 1) -> COMPILE_ERROR "
                  "(verdict=%d, diag=%d)", i, (int)res.verdict,
                  res.diag_count);
        } else {
            CHECK(res.verdict == MC_OK,
                  "E2E gcc iter %d (exit 0) -> OK, garbage stderr TIDAK jadi "
                  "finding (verdict=%d, diag=%d)", i, (int)res.verdict,
                  res.diag_count);
        }
        CHECK(res.diag_count <= 1000,
              "E2E gcc iter %d diag_count terikat (<=1000, got=%d)", i,
              res.diag_count);
        if (res.verdict != (exit1 ? MC_COMPILE_ERROR : MC_OK) ||
            res.diag_count > 1000)
            persist_seed(b, len, "gcc", (uint64_t)i, "verdict/diag aneh");
        myc_result_free(&res);
    }
}

/* Fil-C report parser E2E. Marker kanonik "filc panic:" + exit!=0 -> bukti
 * (positive control); exit 0 + marker -> BUKAN violation (PR-008 rule);
 * garbage tanpa marker -> BUKAN violation (INV-006). */
static void e2e_filc(const char *fake_dir, int iters)
{
    int i;
    path_prepend(fake_dir);
    for (i = 0; i < iters; i++) {
        unsigned char b[MAX_SEED];
        size_t        len = make_seed(b, MAX_SEED);
        myc_request   req;
        myc_result    res;
        int           exit1 = (int)(i & 1);
        int           mk = has_marker(b, len, "filc panic:");
        write_payload_file(b, len);
        env_set("MYC_FAKE_ROLE", "filc");
        env_set("MYC_FAKE_MODE", "payload-file");
        env_set("MYC_FAKE_PAYLOAD_FILE", "test/.parser_fuzz_payload.bin");
        env_set("MYC_FAKE_EXIT", exit1 ? "1" : "0");
        memcpy(g_cur_seed, b, len);
        g_cur_len = len;
        g_cur_tag = "filc";
        run_src(&req, &res, 1, 0, NULL);
        if (exit1 && mk) {
            CHECK(res.verdict == MC_FILC_VIOLATION,
                  "E2E filc iter %d (exit1+marker) -> FILC_VIOLATION "
                  "(panics=%d)", i, res.filc_panics);
            if (res.verdict != MC_FILC_VIOLATION)
                persist_seed(b, len, "filc", (uint64_t)i,
                             "marker terlewat (detektor mati)");
        } else {
            CHECK(res.verdict != MC_FILC_VIOLATION,
                  "E2E filc iter %d -> BUKAN FILC_VIOLATION (exit1=%d "
                  "marker=%d; verdict=%d, panics=%d)", i, exit1, mk,
                  (int)res.verdict, res.filc_panics);
            if (res.verdict == MC_FILC_VIOLATION)
                persist_seed(b, len, "filc", (uint64_t)i,
                             "false violation (INV-006)");
        }
        CHECK(res.filc_panics <= 1000,
              "E2E filc iter %d panics terikat (<=1000, got=%d)", i,
              res.filc_panics);
        myc_result_free(&res);
    }
    env_set("MYC_FAKE_MODE", "");
    path_restore();
}

/* Frama-C Eva parser E2E (POSIX-only; Windows memakai WSL). Marker
 * "[eva:alarm]" -> PROVE_VIOLATION (positive control); tanpa marker ->
 * BUKAN violation. */
#if !defined(_WIN32)
static void e2e_eva(const char *fake_dir, int iters)
{
    int i;
    path_prepend(fake_dir);
    for (i = 0; i < iters; i++) {
        unsigned char b[MAX_SEED];
        size_t        len = make_seed(b, MAX_SEED);
        myc_request   req;
        myc_result    res;
        int           mk = has_marker(b, len, "[eva:alarm]");
        write_payload_file(b, len);
        env_set("MYC_FAKE_ROLE", "eva");
        env_set("MYC_FAKE_MODE", "payload-file");
        env_set("MYC_FAKE_PAYLOAD_FILE", "test/.parser_fuzz_payload.bin");
        env_set("MYC_FAKE_EXIT", "0");
        memcpy(g_cur_seed, b, len);
        g_cur_len = len;
        g_cur_tag = "eva";
        run_src(&req, &res, 0, 1, NULL);
        if (mk) {
            CHECK(res.verdict == MC_PROVE_VIOLATION,
                  "E2E eva iter %d ([eva:alarm]) -> PROVE_VIOLATION "
                  "(alarms=%d)", i, res.prove_alarms);
            if (res.verdict != MC_PROVE_VIOLATION)
                persist_seed(b, len, "eva", (uint64_t)i,
                             "alarm terlewat (detektor mati)");
        } else {
            CHECK(res.verdict != MC_PROVE_VIOLATION,
                  "E2E eva iter %d -> BUKAN PROVE_VIOLATION (verdict=%d, "
                  "alarms=%d)", i, (int)res.verdict, res.prove_alarms);
            if (res.verdict == MC_PROVE_VIOLATION)
                persist_seed(b, len, "eva", (uint64_t)i,
                             "false violation (INV-006)");
        }
        CHECK(res.prove_alarms <= 1000,
              "E2E eva iter %d alarms terikat (<=1000, got=%d)", i,
              res.prove_alarms);
        myc_result_free(&res);
    }
    env_set("MYC_FAKE_MODE", "");
    path_restore();
}
#endif

/* ------------------------------------------------------------------ */
/* Replay corpus tersimpan                                             */
/* ------------------------------------------------------------------ */
static int replay_corpus(void)
{
    FILE *f = fopen(REG_INDEX, "rb");
    char  line[512];
    int   total = 0, fail = 0, skip = 0;
    printf("=== replay corpus parser (%s) ===\n", REG_INDEX);
    if (!f) {
        printf("[OK]   corpus kosong (tidak ada seed tersimpan)\n");
        return 0;
    }
    while (fgets(line, sizeof(line), f)) {
        char        kind[32], sha[16], target[32], reason[160];
        char        path[560];
        FILE       *sf;
        long        sz;
        unsigned char *buf;
        uint64_t    iter = 0;
        if (sscanf(line, "%31s %15s %31s %llu %159[^\n]", kind, sha, target,
                   (unsigned long long *)&iter, reason) < 3)
            continue;
        if (strcmp(kind, "parser") != 0)
            continue;
        snprintf(path, sizeof(path), "%s/parser_%.8s.bin", REG_DIR, sha);
        sf = fopen(path, "rb");
        if (!sf) {
            printf("[FAIL] parser %s: file seed HILANG (%s)\n", sha, path);
            fail++;
            g_fail++;
            continue;
        }
        fseek(sf, 0, SEEK_END);
        sz = ftell(sf);
        fseek(sf, 0, SEEK_SET);
        if (sz < 0 || (size_t)sz > MAX_SEED) {
            fclose(sf);
            printf("[SKIP] parser %s: ukuran seed aneh (%ld)\n", sha, sz);
            skip++;
            continue;
        }
        buf = (unsigned char *)malloc((size_t)sz + 1);
        if (!buf) {
            fclose(sf);
            printf("[SKIP] parser %s: OOM\n", sha);
            skip++;
            continue;
        }
        if (fread(buf, 1, (size_t)sz, sf) != (size_t)sz) {
            free(buf);
            fclose(sf);
            printf("[SKIP] parser %s: baca gagal\n", sha);
            skip++;
            continue;
        }
        buf[sz] = '\0';
        fclose(sf);
        total++;
        memcpy(g_cur_seed, buf, (size_t)sz);
        g_cur_len = (size_t)sz;
        g_cur_tag = target;
        if (strcmp(target, "json") == 0) {
            int bad = run_json_check(buf, (size_t)sz);
            printf(bad ? "[FAIL] parser %s (json): seed MASIH "
                          "bermasalah\n" : "[OK]   parser %s (json)\n", sha);
            if (bad)
                fail++;
        } else if (strcmp(target, "gcc") == 0) {
            const char *fg = getenv("MYC_FAKE_GCC");
            if (fg && *fg) {
                int e, ok = 1;
                /* Review PR-010: replay KEDUA exit code (1 dan 0). Seed
                 * bisa dipersist di bawah anomaly exit-0 (mis. garbage +
                 * exit 0 harus BUKAN violation — guard INV-006); replay
                 * satu exit saja bisa lulus trivial dan melewatkan anomaly
                 * asli. Invariant penuh diuji untuk tiap exit. */
                for (e = 0; e < 2 && ok; e++) {
                    myc_request req;
                    myc_result  res;
                    write_payload_file(buf, (size_t)sz);
                    env_set("MYC_FAKE_ROLE", "gcc");
                    env_set("MYC_FAKE_MODE", "payload-file");
                    env_set("MYC_FAKE_PAYLOAD_FILE",
                            "test/.parser_fuzz_payload.bin");
                    env_set("MYC_FAKE_EXIT", e ? "1" : "0");
                    run_src(&req, &res, 0, 0, fg);
                    if (e) {
                        if (res.verdict != MC_COMPILE_ERROR) ok = 0;
                    } else {
                        if (res.verdict != MC_OK) ok = 0;
                    }
                    if (res.diag_count > 1000) ok = 0;
                    myc_result_free(&res);
                }
                if (!ok) {
                    printf("[FAIL] parser %s (gcc): replay invariant gagal "
                           "(exit 0/1)\n", sha);
                    fail++;
                    g_fail++;
                } else {
                    printf("[OK]   parser %s (gcc)\n", sha);
                }
            } else {
                printf("[SKIP] parser %s (gcc: MYC_FAKE_GCC tidak di-set)\n",
                       sha);
                skip++;
            }
        } else if (strcmp(target, "filc") == 0) {
            const char *fd = getenv("MYC_FAKE_FILC_DIR");
            if (fd && *fd) {
                int e, ok = 1;
                /* Review PR-010: replay KEDUA exit code (lihat gcc):
                 * invariant INV-006 (marker + exit!=0 = bukti; selain itu
                 * BUKAN violation) diuji untuk exit 1 DAN 0. */
                for (e = 0; e < 2 && ok; e++) {
                    myc_request req;
                    myc_result  res;
                    int         mk;
                    write_payload_file(buf, (size_t)sz);
                    env_set("MYC_FAKE_ROLE", "filc");
                    env_set("MYC_FAKE_MODE", "payload-file");
                    env_set("MYC_FAKE_PAYLOAD_FILE",
                            "test/.parser_fuzz_payload.bin");
                    env_set("MYC_FAKE_EXIT", e ? "1" : "0");
                    path_prepend(fd);
                    run_src(&req, &res, 1, 0, NULL);
                    mk = has_marker(buf, (size_t)sz, "filc panic:");
                    if (e && mk) {
                        if (res.verdict != MC_FILC_VIOLATION) ok = 0;
                    } else {
                        if (res.verdict == MC_FILC_VIOLATION) ok = 0;
                    }
                    if (res.filc_panics > 1000) ok = 0;
                    myc_result_free(&res);
                    path_restore();
                }
                if (!ok) {
                    printf("[FAIL] parser %s (filc): replay invariant gagal "
                           "(exit 0/1)\n", sha);
                    fail++;
                    g_fail++;
                } else {
                    printf("[OK]   parser %s (filc)\n", sha);
                }
            } else {
                printf("[SKIP] parser %s (filc: MYC_FAKE_FILC_DIR tidak "
                       "di-set)\n", sha);
                skip++;
            }
        } else if (strcmp(target, "eva") == 0) {
#if defined(_WIN32)
            printf("[SKIP] parser %s (eva: Windows memakai WSL)\n", sha);
            skip++;
#else
            const char *fd = getenv("MYC_FAKE_FRAMA_DIR");
            if (fd && *fd) {
                myc_request req;
                myc_result  res;
                write_payload_file(buf, (size_t)sz);
                env_set("MYC_FAKE_ROLE", "eva");
                env_set("MYC_FAKE_MODE", "payload-file");
                env_set("MYC_FAKE_PAYLOAD_FILE",
                        "test/.parser_fuzz_payload.bin");
                env_set("MYC_FAKE_EXIT", "0");
                path_prepend(fd);
                run_src(&req, &res, 0, 1, NULL);
                if (has_marker(buf, (size_t)sz, "[eva:alarm]") &&
                    res.verdict != MC_PROVE_VIOLATION) {
                    printf("[FAIL] parser %s (eva): alarm terlewat pada "
                           "replay (verdict=%d)\n", sha, (int)res.verdict);
                    fail++;
                    g_fail++;
                } else {
                    printf("[OK]   parser %s (eva)\n", sha);
                }
                myc_result_free(&res);
                path_restore();
            } else {
                printf("[SKIP] parser %s (eva: MYC_FAKE_FRAMA_DIR tidak "
                       "di-set)\n", sha);
                skip++;
            }
#endif
        } else {
            printf("[SKIP] parser %s: target tak dikenal (%s)\n", sha, target);
            skip++;
        }
        free(buf);
    }
    fclose(f);
    printf("  ringkasan replay: %d seed, %d fail, %d skip\n", total, fail,
           skip);
    return fail;
}

/* ------------------------------------------------------------------ */
/* Truncation pass: parse prefix di SETIAP posisi byte (seed <= 1 KB). */
/* ------------------------------------------------------------------ */
static void truncation_pass(void)
{
    size_t si;
    for (si = 0; si < g_corpus_n; si++) {
        const corpus_seed *cs = &g_corpus[si];
        size_t             pos;
        if (cs->len > 1024)
            continue;
        for (pos = 0; pos <= cs->len; pos++) {
            json_value *v = NULL;
            int         ok = json_parse(cs->data, pos, &v);
            g_n_json++;
            if (ok && !v) {
                fprintf(stderr, "[FAIL] trunc pass %s pos %u ok tapi v==NULL\n",
                        cs->name, (unsigned)pos);
                g_fail++;
                persist_seed((const unsigned char *)cs->data, pos, "json",
                             (uint64_t)pos, "trunc ok v==NULL");
            }
            if (!ok && v) {
                fprintf(stderr, "[FAIL] trunc pass %s pos %u !ok tapi "
                        "v!=NULL\n", cs->name, (unsigned)pos);
                g_fail++;
                json_free(v);
                persist_seed((const unsigned char *)cs->data, pos, "json",
                             (uint64_t)pos, "trunc !ok v!=NULL");
            }
            json_free(v);
        }
    }
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    uint64_t  iters = 20000;
    int       e2e_iters = 16;
    int       progress = 2000;
    int       replay = 0;
    int       i;
    const char *fake_gcc = getenv("MYC_FAKE_GCC");
    const char *fake_filc = getenv("MYC_FAKE_FILC_DIR");
#if !defined(_WIN32)
    const char *fake_frama = getenv("MYC_FAKE_FRAMA_DIR");
#else
    const char *fake_frama = NULL;
    (void)fake_frama;
#endif

    g_rng = 0x9E3779B9u;   /* seed default deterministik */

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc)
            iters = strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--e2e-iters") == 0 && i + 1 < argc)
            e2e_iters = atoi(argv[++i]);
        else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc)
            g_rng = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--progress") == 0 && i + 1 < argc)
            progress = atoi(argv[++i]);
        else if (strcmp(argv[i], "--replay") == 0)
            replay = 1;
        else {
            fprintf(stderr, "parser_fuzz: argumen tak dikenal: %s\n",
                    argv[i]);
            fprintf(stderr, "usage: parser_fuzz [--iters N] [--e2e-iters N] "
                    "[--seed S] [--progress N] [--replay]\n");
            return 2;
        }
    }

    install_crash_handlers();

    if (replay) {
        int rc = replay_corpus();
        /* Review PR-010: jalur --replay bisa menulis payload (target
         * gcc/filc/eva) tanpa membersihkannya; hapus di sini juga agar
         * harness self-cleaning pada SEMUA jalur keluar (suite cleanup
         * tetap jadi belt-and-braces). */
        remove("test/.parser_fuzz_payload.bin");
        remove("test/.parser_fuzz_scen.json");
        printf(rc ? "parser_fuzz --replay: FAIL (%d)\n" : "parser_fuzz "
               "--replay: OK\n", rc);
        return rc ? 1 : 0;
    }

    printf("=== Parser fuzz harness (PR-010 / P2-T03 tahap 2) ===\n");
    printf("seed=%08x iters=%llu e2e_iters=%d progress=%d\n",
           (unsigned)g_rng, (unsigned long long)iters, e2e_iters, progress);

    /* pass 1: truncation tiap byte untuk korpus kecil. */
    truncation_pass();
    printf("[OK]   truncation pass (%llu parse)\n",
           (unsigned long long)g_n_json);

    /* pass 2: mutasi PRNG -> json langsung + konsumen (sampled). */
    {
        uint64_t it;
        for (it = 0; it < iters; it++) {
            unsigned char b[MAX_SEED];
            size_t        len = make_seed(b, MAX_SEED);
            memcpy(g_cur_seed, b, len);
            g_cur_len = len;
            g_cur_tag = "json";
            if (run_json_check(b, len))
                persist_seed(b, len, "json", it, "semantic json bug");
            if ((it % 16) == 0)
                run_budget_check(b, len);
            if ((it % 64) == 0)
                run_calib_check(b, len);
            if ((it % 256) == 0)
                run_scenario_check(b, len);
            if ((it % 256) == 0)
                run_cache_check(b, len);
            if (progress > 0 && (it % (uint64_t)progress) == 0)
                printf("[iter] %llu ok=%llu fail=%d\n",
                       (unsigned long long)it,
                       (unsigned long long)g_n_json_ok, g_fail);
        }
    }
    printf("[OK]   direct: %llu json (valid=%llu), consumers sampled, "
           "fail=%d\n", (unsigned long long)g_n_json,
           (unsigned long long)g_n_json_ok, g_fail);

    /* pass 3: E2E parser backend via fake backend payload-file. */
    if (e2e_iters > 0) {
        if (fake_gcc && *fake_gcc)
            e2e_gcc(fake_gcc, e2e_iters);
        else
            printf("[SKIP] E2E gcc (MYC_FAKE_GCC tidak di-set)\n");
        if (fake_filc && *fake_filc)
            e2e_filc(fake_filc, e2e_iters);
        else
            printf("[SKIP] E2E filc (MYC_FAKE_FILC_DIR tidak di-set)\n");
#if !defined(_WIN32)
        if (fake_frama && *fake_frama)
            e2e_eva(fake_frama, e2e_iters);
        else
            printf("[SKIP] E2E eva (MYC_FAKE_FRAMA_DIR tidak di-set)\n");
#else
        printf("[SKIP] E2E eva (Windows memakai WSL; fake frama-c "
               "POSIX-only)\n");
#endif
    }

    remove("test/.parser_fuzz_payload.bin");
    remove("test/.parser_fuzz_scen.json");

    printf(g_fail ? "parser_fuzz: FAIL (%d)\n" : "parser_fuzz: OK\n", g_fail);
    return g_fail ? 1 : 0;
}
