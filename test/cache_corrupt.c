/*
 * cache_corrupt.c -- PR-013 (MYC-AUDIT-045, P3-T04): cache corruption
 * recovery.
 *
 * Mengunci perilaku Incremental Evidence Cache (cache.c, SOL-18) terhadap
 * file cache yang KORUP. P3-T04 mensyaratkan: ignore/quarantine entry,
 * emit diagnostic, recompute evidence — NEVER crash dan NEVER trust.
 *
 * Dua lapis pertahanan (cache.c):
 *   L1 INTEGRITAS: sidecar `.myc/evidence_cache.sha256` berisi sha256 hex
 *      atas byte MENTAH evidence_cache.json. Sidecar hilang/stale/tampered
 *      = seluruh file di-ignore (fail-closed) -> replay MISS -> recompute.
 *      (Hash atas byte mentah, bukan re-serialisasi JSON — teks backend
 *      bisa berisi byte non-UTF8 yang tidak round-trip stabil.)
 *   L2 SEMANTIK (bila byte file lolos L1): tiap entry divalidasi sebelum
 *      parse — key/source wajib 64-hex, enum di range (verdict
 *      out-of-range TIDAK di-clamp ke OK!), state mustahil (MC_ERROR tanpa
 *      err) ditolak, gates id/status di range, entry duplikat didedup.
 *      Entry korup dikarantina: dilewati + diagnostic `myc: cache:` +
 *      file di-heal (rewrite tanpa entry tsb).
 *
 * Injeksi korupsi deterministik:
 *   T1  baseline: store -> replay HIT; sidecar sha256 ada (64 hex)
 *   T2  truncated JSON (file dipotong, sidecar stale) -> L1 -> MISS +
 *       recompute (store segar -> HIT)
 *   T3  flipped bits (nilai numerik diubah, tanpa update sidecar) -> L1
 *   T4  unknown schema (field asing, tanpa update sidecar) -> L1
 *   T5  sidecar ditamper (hex salah) -> L1
 *   T6  duplicate entries + sidecar SAH -> L2 dedup: replay HIT dari entry
 *       pertama, file di-heal ke 1 entry
 *   T7  stale backend version (tool diubah): tanpa sidecar -> L1 MISS;
 *       dengan sidecar SAH -> diterima (key beda) -> MISS
 *   T8  malformed timestamp (duration_ms negatif): tanpa sidecar -> L1
 *       MISS; dengan sidecar SAH -> L2 reject -> karantina
 *   T9  impossible gate state dengan sidecar SAH (file "ditulis ulang"
 *       konsisten): (a) MC_ERROR tanpa err, (b) verdict out-of-range ->
 *       lapisan SEMANTIK menolak; (c) control entry valid -> diterima
 *       (TIDAK dikarantina), MISS hanya karena key beda
 *   T10 schema lama: entry TANPA sidecar -> L1 fail-closed -> MISS
 *   T11 non-object entry + sidecar SAH -> L2 karantina -> MISS
 *   T12 garbage + sidecar cocok -> parse fail -> MISS (tidak crash)
 *   T13 recompute E2E: store segar setelah semua korupsi -> replay HIT
 *
 * Observasi "dikarantina" (L2): cache_read_all meng-heal file (rewrite
 * tanpa entry korup) -> jumlah entry setelah replay-attempt = 0 untuk
 * entry korup, = 1 untuk entry valid yang tidak dicocokkan (control T9c).
 * L1 (integritas) TIDAK menyentuh file -> jumlah entry tetap.
 * Diagnostic stderr "myc: cache: ..." diverifikasi di _audit018.sh
 * (grep 'myc: cache:').
 *
 * Jalankan di direktori temp (test/.cache_corrupt_tmp); dibersihkan
 * sendiri. Build (portabel, Windows MinGW + POSIX):
 *   gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -DMYC_NO_MAIN \
 *       -o cache_corrupt cache_corrupt.c <seluruh SRCS myc>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#define T_MKDIR(p) _mkdir(p)
#define T_CHDIR(p) _chdir(p)
#define T_RMDIR(p) _rmdir(p)
#define T_GETCWD(b, n) _getcwd((b), (n))
#else
#include <sys/stat.h>
#include <unistd.h>
#define T_MKDIR(p) mkdir((p), 0700)
#define T_CHDIR(p) chdir(p)
#define T_RMDIR(p) rmdir(p)
#define T_GETCWD(b, n) getcwd((b), (n))
#endif

#include "cache.h"
#include "json.h"
#include "myc.h"
#include "proc.h"
#include "sha256.h"

static int g_ok = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_ok++; } \
    else { g_fail++; fprintf(stderr, "[FAIL] %s (line %d)\n", (msg), __LINE__); } \
} while (0)

/* ------------------------------------------------------------------ */
/* Infra: direktori temp + helper store/replay/file                    */
/* ------------------------------------------------------------------ */

static char        g_old_cwd[1024];
static const char *g_dir = "test/.cache_corrupt_tmp";
static const char *g_cache = ".myc/evidence_cache.json";
static const char *g_sha = ".myc/evidence_cache.sha256";

static void save_cwd(void)
{
    if (T_GETCWD(g_old_cwd, sizeof(g_old_cwd)) == NULL)
        g_old_cwd[0] = '\0';
}

static int chdir_one(const char *p)
{
    if (T_CHDIR(p) != 0) {
        fprintf(stderr, "[FAIL] chdir %s gagal\n", p);
        return -1;
    }
    return 0;
}

static void mkdir_one(const char *p)
{
    T_MKDIR(p);
}

static void rmdir_one(const char *p)
{
    T_RMDIR(p);
}

static const char SRC_A[] = "int f(void){return 0;}\n";
#define SL(x) (sizeof(x) - 1)

static void base_req(myc_request *r, const char *cwd)
{
    myc_request_init(r);
    r->input.kind = MYC_SOURCE_MEMORY;
    r->input.data = NULL;
    r->input.len = 0;
    r->run_lint = 1;
    r->cwd = cwd;
}

static void cache_store_ex(const myc_request *req, const char *src,
                           size_t len, int marker)
{
    myc_result res;
    myc_result_init(&res);
    res.verdict = MC_OK;
    res.err = MYC_ERR_NONE;
    res.lint_observations = 1000 + marker;
    memset(res.receipt_sha256, 'a', 64);
    res.receipt_sha256[64] = '\0';
    myc_cache_store(req, &res, src, len);
    myc_result_free(&res);
}

static int cache_replay_ex(const myc_request *req, const char *src,
                           size_t len)
{
    myc_result res;
    int rc;
    myc_result_init(&res);
    rc = myc_cache_try_replay(req, &res, src, len);
    myc_result_free(&res);
    return rc;
}

/* Jumlah entry di .myc/evidence_cache.json; -1 = file tak ter-parse. */
static int cache_entry_count(void)
{
    FILE *f;
    long  sz;
    char *buf;
    json_value *root, *arr;
    int n = -1;

    f = fopen(g_cache, "rb");
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (32 << 20)) {
        fclose(f);
        return -1;
    }
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return -1;
    }
    buf[sz] = '\0';
    fclose(f);

    if (!json_parse(buf, (size_t)sz, &root) || !root ||
        root->type != JSON_OBJ) {
        if (root)
            json_free(root);
        free(buf);
        return -1;
    }
    arr = json_get(root, "entries");
    if (arr && arr->type == JSON_ARR)
        n = (int)arr->len;
    json_free(root);
    free(buf);
    return n;
}

static void write_cache_raw(const char *text)
{
    FILE *f = fopen(g_cache, "wb");
    if (f) {
        fputs(text, f);
        fclose(f);
    }
}

/* Tulis sidecar sha256 atas byte mentah file cache (algoritma SAMA dengan
 * cache_write_all: sha256_hex atas byte file). */
static void write_sidecar(void)
{
    FILE *f, *g;
    long  sz;
    char *buf;
    char hex[65];

    f = fopen(g_cache, "rb");
    if (!f)
        return;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return;
    }
    fclose(f);
    sha256_hex(buf, (size_t)sz, hex);
    free(buf);
    g = fopen(g_sha, "wb");
    if (g) {
        fputs(hex, g);
        fclose(g);
    }
}

static void reset_cache(void)
{
    write_cache_raw("{\"entries\":[]}");
    remove(g_sha);
}

/* 1 bila sidecar ada dan berisi 64 hex. */
static int sidecar_ok(void)
{
    FILE *f;
    char tmp[96];
    size_t n;

    f = fopen(g_sha, "rb");
    if (!f)
        return 0;
    n = fread(tmp, 1, sizeof(tmp) - 1, f);
    fclose(f);
    return n == 64;
}

/* Baca file cache, ubah SATU field entry[0] (replace), tulis ulang.
 * Sidecar TIDAK di-update di sini (simulasi korupsi; pemanggil bisa
 * memanggil write_sidecar() bila ingin menguji lapisan SEMANTIK). */
static void corrupt_entry_field(const char *field, const char *strval,
                                int64_t numval, int is_num)
{
    FILE *f;
    long  sz;
    char *buf;
    json_value *root, *arr, *e;

    f = fopen(g_cache, "rb");
    if (!f)
        return;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return;
    }
    buf[sz] = '\0';
    fclose(f);

    if (!json_parse(buf, (size_t)sz, &root) || !root) {
        if (root)
            json_free(root);
        free(buf);
        return;
    }
    arr = json_get(root, "entries");
    if (arr && arr->type == JSON_ARR && arr->len > 0 &&
        arr->items[0]->type == JSON_OBJ) {
        e = arr->items[0];
        json_obj_set(e, field,
                     is_num ? json_new_num(numval) : json_new_str(strval));
    }
    {
        char *out = NULL;
        if (json_serialize(root, &out) && out) {
            write_cache_raw(out);
            free(out);
        }
    }
    json_free(root);
    free(buf);
}

/* Tamper sidecar dengan hex yang salah. */
static void tamper_sidecar(void)
{
    FILE *f = fopen(g_sha, "wb");
    if (f) {
        fputs("0000000000000000000000000000000000000000000000000000000000000000",
              f);
        fclose(f);
    }
}

/* Duplikat entry[0] (salinan utuh). Sidecar TIDAK di-update. */
static void duplicate_entry(void)
{
    FILE *f;
    long  sz;
    char *buf;
    json_value *root, *arr;

    f = fopen(g_cache, "rb");
    if (!f)
        return;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return;
    }
    buf[sz] = '\0';
    fclose(f);

    if (!json_parse(buf, (size_t)sz, &root) || !root) {
        if (root)
            json_free(root);
        free(buf);
        return;
    }
    arr = json_get(root, "entries");
    if (arr && arr->type == JSON_ARR && arr->len > 0)
        json_arr_push(arr, json_clone(arr->items[0]));
    {
        char *out = NULL;
        if (json_serialize(root, &out) && out) {
            write_cache_raw(out);
            free(out);
        }
    }
    json_free(root);
    free(buf);
}

/* Bangun file cache dengan SATU entry buatan test + sidecar SAH (artinya
 * file "ditulis ulang" secara konsisten — lapisan L2 SEMANTIK yang diuji,
 * bukan L1). */
static void write_forged_entry(int64_t verdict, int64_t err,
                               int64_t duration_ms)
{
    json_value *root, *arr, *e;
    char key[65], src[65], *s = NULL;
    int i;

    for (i = 0; i < 64; i++) {
        key[i] = 'a';
        src[i] = 'b';
    }
    key[64] = '\0';
    src[64] = '\0';

    e = json_new_obj();
    json_obj_set(e, "key", json_new_str(key));
    json_obj_set(e, "source", json_new_str(src));
    json_obj_set(e, "scenario", json_new_str("0123456789abcdef"));
    json_obj_set(e, "tool", json_new_str("gcc:test"));
    json_obj_set(e, "cwd", json_new_str(g_dir));
    json_obj_set(e, "path", json_new_str(""));
    json_obj_set(e, "receipt", json_new_str(""));
    json_obj_set(e, "fingerprint", json_new_str(""));
    json_obj_set(e, "verdict", json_new_num(verdict));
    json_obj_set(e, "err", json_new_num(err));
    if (duration_ms >= 0)
        json_obj_set(e, "duration_ms", json_new_num(duration_ms));
    arr = json_new_arr();
    json_arr_push(arr, e);
    root = json_new_obj();
    json_obj_set(root, "entries", arr);
    if (json_serialize(root, &s) && s) {
        write_cache_raw(s);
        free(s);
    }
    json_free(root);
    write_sidecar();
}

/* ------------------------------------------------------------------ */
/* Test cases                                                          */
/* ------------------------------------------------------------------ */

static void test_baseline(void)
{
    myc_request a;

    base_req(&a, g_dir);
    cache_store_ex(&a, SRC_A, SL(SRC_A), 1);
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 1,
          "T1: store+replay HIT (sidecar sha256 byte-mentah stabil)");
    CHECK(cache_entry_count() == 1, "T1: satu entry tersimpan");
    CHECK(sidecar_ok(),
          "T1: sidecar .myc/evidence_cache.sha256 ada (64 hex)");
}

static void test_truncated(void)
{
    myc_request a;
    FILE *f;
    char *buf;

    base_req(&a, g_dir);
    reset_cache();
    cache_store_ex(&a, SRC_A, SL(SRC_A), 1);

    /* potong file jadi setengah -> byte berubah, sidecar stale (L1) */
    f = fopen(g_cache, "rb");
    if (f) {
        long half;
        fseek(f, 0, SEEK_END);
        half = ftell(f) / 2;
        fseek(f, 0, SEEK_SET);
        buf = (char *)malloc((size_t)half + 1);
        if (buf) {
            if (fread(buf, 1, (size_t)half, f) == (size_t)half) {
                fclose(f);
                write_cache_raw(buf);   /* tulis setengah -> truncated */
                free(buf);
            } else {
                free(buf);
                fclose(f);
            }
        } else {
            fclose(f);
        }
    }
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T2: truncated JSON (sidecar stale) -> L1 MISS, tidak crash");
    CHECK(cache_entry_count() == -1, "T2: file terpotong tak ter-parse");
    /* recompute: store segar menimpa file + sidecar -> replay HIT */
    cache_store_ex(&a, SRC_A, SL(SRC_A), 2);
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 1,
          "T2: recompute -> replay HIT (bukti dihitung ulang)");
}

static void test_flip_bits(void)
{
    myc_request a;

    base_req(&a, g_dir);
    reset_cache();
    cache_store_ex(&a, SRC_A, SL(SRC_A), 1);
    corrupt_entry_field("lint_obs", NULL, 9999, 1);   /* nilai di-flip */
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T3: flipped bit (nilai numerik, sidecar stale) -> L1 MISS");
    CHECK(cache_entry_count() == 1,
          "T3: L1 tidak menyentuh file (entry tetap, tapi tidak di-replay)");
}

static void test_unknown_schema(void)
{
    myc_request a;

    base_req(&a, g_dir);
    reset_cache();
    cache_store_ex(&a, SRC_A, SL(SRC_A), 1);
    corrupt_entry_field("evil_unknown_field", "1", 0, 0);
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T4: unknown schema (field asing, sidecar stale) -> L1 MISS");
    CHECK(cache_entry_count() == 1, "T4: L1 tidak menyentuh file");
}

static void test_sidecar_tampered(void)
{
    myc_request a;

    base_req(&a, g_dir);
    reset_cache();
    cache_store_ex(&a, SRC_A, SL(SRC_A), 1);
    tamper_sidecar();
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T5: sidecar ditamper (hex salah) -> L1 MISS");
    CHECK(cache_entry_count() == 1, "T5: L1 tidak menyentuh file");
}

static void test_duplicate(void)
{
    myc_request a;

    base_req(&a, g_dir);
    reset_cache();
    cache_store_ex(&a, SRC_A, SL(SRC_A), 1);
    CHECK(cache_entry_count() == 1, "T6: baseline 1 entry");
    duplicate_entry();
    write_sidecar();                 /* byte file konsisten -> L2 diuji */
    CHECK(cache_entry_count() == 2, "T6: entry di-duplikat (2 entry)");
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 1,
          "T6: duplikat dikarantina (L2 dedup), replay HIT dari entry pertama");
    CHECK(cache_entry_count() == 1, "T6: file di-heal ke 1 entry (dedup)");
}

static void test_stale_version(void)
{
    myc_request a;

    base_req(&a, g_dir);

    /* tanpa update sidecar -> L1 */
    reset_cache();
    cache_store_ex(&a, SRC_A, SL(SRC_A), 1);
    corrupt_entry_field("tool", "gcc:stale-v99|clang:?", 0, 0);
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T7a: stale backend version (sidecar stale) -> L1 MISS");

    /* byte konsisten (sidecar di-update) -> L2 menerima (bukan korupsi
     * struktural); field `tool` adalah METADATA informasi — key replay
     * memakai tool identity LIVE (cache_tool_key), bukan field ini. */
    reset_cache();
    cache_store_ex(&a, SRC_A, SL(SRC_A), 1);
    corrupt_entry_field("tool", "gcc:stale-v99|clang:?", 0, 0);
    write_sidecar();
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 1,
          "T7b: field tool (metadata) berubah + sidecar sah -> replay HIT");
    CHECK(cache_entry_count() == 1,
          "T7b: entry konsisten TIDAK dikarantina");

    /* T7c: stale backend version yang NYATA = tool identity LIVE berubah
     * (gcc_program beda) -> key beda -> MISS (lane sama dgn T8
     * cache_key_matrix; diulang di sini agar korpus PR-013 mandiri). */
    {
        myc_request b;
        char *gcc = myc_find_executable("gcc");
        if (gcc) {
            free(gcc);
            reset_cache();
            cache_store_ex(&a, SRC_A, SL(SRC_A), 1);
            base_req(&b, g_dir);
            b.gcc_program = "myc-no-such-gcc-987654";
            CHECK(cache_replay_ex(&b, SRC_A, SL(SRC_A)) == 0,
                  "T7c: live tool identity beda -> MISS (stale version lane)");
        } else {
            printf("[SKIP] T7c: gcc tidak ditemukan di PATH\n");
        }
    }
}

static void test_bad_timestamp(void)
{
    myc_request a;

    base_req(&a, g_dir);

    /* tanpa update sidecar -> L1 */
    reset_cache();
    cache_store_ex(&a, SRC_A, SL(SRC_A), 1);
    corrupt_entry_field("duration_ms", NULL, -7, 1);
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T8a: malformed timestamp (sidecar stale) -> L1 MISS");

    /* byte konsisten (sidecar di-update) -> L2 SEMANTIK menolak. */
    reset_cache();
    cache_store_ex(&a, SRC_A, SL(SRC_A), 1);
    corrupt_entry_field("duration_ms", NULL, -7, 1);
    write_sidecar();
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T8b: duration_ms negatif + sidecar sah -> L2 reject, MISS");
    CHECK(cache_entry_count() == 0,
          "T8b: entry mustahil dikarantina (file di-heal)");
}

static void test_semantic_forged(void)
{
    myc_request a;

    base_req(&a, g_dir);

    /* (a) state mustahil dgn sidecar SAH: MC_ERROR tanpa err. */
    reset_cache();
    write_forged_entry(MC_ERROR, MYC_ERR_NONE, -1);
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T9a: MC_ERROR tanpa err (file konsisten) -> L2 reject SEMANTIK");
    CHECK(cache_entry_count() == 0,
          "T9a: entry state-mustahil dikarantina (healed)");

    /* (b) verdict out-of-range dgn sidecar SAH. */
    reset_cache();
    write_forged_entry(999, MYC_ERR_NONE, -1);
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T9b: verdict out-of-range (file konsisten) -> L2 reject "
          "(tidak di-clamp ke OK)");
    CHECK(cache_entry_count() == 0,
          "T9b: entry out-of-range dikarantina");

    /* (c) control: entry VALID dgn sidecar SAH -> diterima (tidak
     * di-heal), MISS hanya karena key tidak cocok dgn source test. */
    reset_cache();
    write_forged_entry(MC_OK, MYC_ERR_NONE, -1);
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T9c: entry valid (file konsisten) -> MISS (key beda, bukan korupsi)");
    CHECK(cache_entry_count() == 1,
          "T9c: entry valid TIDAK dikarantina (diterima pembaca)");
}

static void test_old_schema(void)
{
    myc_request a;
    char key[65], src[65], buf[700];
    int i;

    base_req(&a, g_dir);
    for (i = 0; i < 64; i++) {
        key[i] = 'a';
        src[i] = 'b';
    }
    key[64] = '\0';
    src[64] = '\0';
    /* Entry tanpa sidecar (file cache lama pra-PR-013) -> fail-closed. */
    reset_cache();
    snprintf(buf, sizeof(buf),
             "{\"entries\":[{\"key\":\"%s\",\"source\":\"%s\","
             "\"verdict\":0,\"err\":0,\"lint_obs\":1001}]}", key, src);
    write_cache_raw(buf);
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T10: file cache tanpa sidecar (schema lama) -> L1 fail-closed MISS");
    CHECK(cache_entry_count() == 1, "T10: file tidak disentuh (ignored)");
}

static void test_malformed_file(void)
{
    myc_request a;

    base_req(&a, g_dir);

    /* non-object entry + sidecar SAH -> L2 karantina. */
    reset_cache();
    write_cache_raw("{\"entries\":[42]}");
    write_sidecar();
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T11: non-object entry di array -> L2 karantina, MISS, tidak crash");
    CHECK(cache_entry_count() == 0, "T11: non-object entry dikarantina");

    /* garbage + sidecar cocok -> parse fail (di-ignore), tidak crash. */
    reset_cache();
    write_cache_raw("{{{ ini bukan json sama sekali ");
    write_sidecar();
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 0,
          "T12: garbage file (sidecar sah) -> parse fail MISS, tidak crash");
    CHECK(cache_entry_count() == -1, "T12: file garbage tak ter-parse");
}

static void test_recompute(void)
{
    myc_request a;

    base_req(&a, g_dir);
    reset_cache();
    cache_store_ex(&a, SRC_A, SL(SRC_A), 7);
    CHECK(cache_replay_ex(&a, SRC_A, SL(SRC_A)) == 1,
          "T13: recompute E2E: store segar setelah semua korupsi -> HIT");
    CHECK(cache_entry_count() == 1, "T13: satu entry valid tersimpan");
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    save_cwd();
    mkdir_one(g_dir);
    if (chdir_one(g_dir) != 0)
        return 1;
    mkdir_one(".myc");

    test_baseline();
    test_truncated();
    test_flip_bits();
    test_unknown_schema();
    test_sidecar_tampered();
    test_duplicate();
    test_stale_version();
    test_bad_timestamp();
    test_semantic_forged();
    test_old_schema();
    test_malformed_file();
    test_recompute();

    if (g_old_cwd[0])
        chdir_one(g_old_cwd);
    remove("test/.cache_corrupt_tmp/.myc/evidence_cache.json");
    remove("test/.cache_corrupt_tmp/.myc/evidence_cache.sha256");
    rmdir_one("test/.cache_corrupt_tmp/.myc");
    rmdir_one(g_dir);

    printf("cache_corrupt: %d OK, %d FAIL\n", g_ok, g_fail);
    return g_fail == 0 ? 0 : 1;
}
