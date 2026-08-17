/*
 * mcp_abuse.c -- MCP abuse & soak (PR-016, plan P4-T04 / batch PR-016).
 *
 * Menguji mcp.exe (MCP server stdio, JSON-RPC 2.0 newline-delimited)
 * sebagai proses yang TIDAK dipercaya: korpus protokol malformed
 * deterministik + 1.000+ request soak, sesuai P4-T04:
 *
 *   valid request; missing field; unknown field; wrong type; huge
 *   payload; duplicate request ID; malformed JSON-RPC; notification vs
 *   request; agent cancellation/EOF; multiple sequential requests;
 *   1.000-request soak.
 *
 * Invariant kunci (P4-T04): stdout TETAP protocol-clean -- setiap baris
 * yang dicetak mcp adalah objek JSON-RPC 2.0 yang sah (jsonrpc=="2.0",
 * id di-echo, tepat satu result ATAU error). Tidak ada log/diagnostik
 * bocor ke stdout. mcp tidak pernah crash/hang pada input apa pun.
 *
 * Test:
 *   T0 sanity       : stdin kosong -> exit 0, NOL baris stdout (EOF =
 *                     cancellation, server berhenti bersih).
 *   T1 baseline     : batch valid + notification + parse error + jsonrpc
 *                     salah + flag tak dikenal + flags tipe salah ->
 *                     protocol-clean, count tepat, id di-echo, error
 *                     code benar, stderr kosong, structuredContent ada.
 *   T2 corpus       : ~35 kasus protokol malformed, tiap kasus dijalankan
 *                     SENDIRI + canary ping (isolasi + timeout per kasus):
 *                     json tidak valid, truncated, root non-objek,
 *                     jsonrpc hilang/salah, method hilang/tipe salah, id
 *                     tipe salah, unknown method, tools/call params/name/
 *                     arguments/tipe salah, flags non-array/entry non-
 *                     string (PR-016 hardening), unknown flag, id null/
 *                     string (sah), params ekstra, unknown field, dup key.
 *                     Notifikasi valid -> TANPA respons; notifikasi tanpa
 *                     method -> -32600 (perilaku terdokumentasi).
 *   T3 huge payload : baris ~7,9 MiB (< cap 8 MiB) dan ~9 MiB (> cap) ->
 *                     Parse error -32700 + canary ping OK, tidak hang,
 *                     tidak crash (MCP_MAX_LINE 8 MiB, read_line drain).
 *   T4 dup id       : beberapa request ber-id sama -> SEMUA dijawab
 *                     (server stateless, id di-echo apa adanya).
 *   T5 notifications: notifikasi valid -> nol respons; request ber-id di
 *                     tengahnya tetap dijawab.
 *   T6 ordering     : 20 ping id 1..20 -> 20 respons urut id 1..20.
 *   T7 soak         : 1.090 request (1.000 ping + 30 notifikasi + 20
 *                     version + 10 policy + 5 lint + 5 contracts + 5
 *                     check + 2 repair + 2 agent_check + 3 unknown tool
 *                     + 8 malformed) -> tepat 1.060 respons valid,
 *                     semua id ping 1..1000 muncul, 11 error dgn code
 *                     yang diharapkan, exit 0, stderr kosong.
 *
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I. -pthread \
 *       -o test/mcp_abuse test/mcp_abuse.c proc.c json.c
 *
 * Penggunaan:
 *   mcp_abuse <path-mcp>      (mcp binary: root/mcp atau root/mcp.exe)
 */
#if !defined(_WIN32)
#define _DEFAULT_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "json.h"
#include "myc.h"
#include "proc.h"

#define TMP_DIR    "test/.mcp_abuse_tmp"
#define CAP_DEFAULT (8u << 20)      /* 8 MiB per channel: cukup utk soak */
#define CANARY_BASE 9000

static int g_fail = 0;
static char g_mcp_abs[1024] = "";

/* CHECK: cetak [OK]/[FAIL] per cek. */
#define CHECK(cond, ...) do {                                         \
        if (cond) { printf("[OK]   " __VA_ARGS__); printf("\n"); }     \
        else { fprintf(stderr, "[FAIL] " __VA_ARGS__);                 \
               fprintf(stderr, "\n"); g_fail++; }                      \
    } while (0)

/* ------------------------- util portabel --------------------------- */

static void make_dir(const char *path)
{
#ifdef _WIN32
    _mkdir(path);
#else
    mkdir(path, 0700);
#endif
}

static void change_dir(const char *path)
{
#ifdef _WIN32
    if (_chdir(path) != 0) {
        /* non-critical di test */
    }
#else
    if (chdir(path) != 0) {
        /* non-critical di test */
    }
#endif
}

/* Path absolut (resolusi sebelum chdir). Gagal -> 0. */
static int abs_path(const char *path, char *out, size_t outcap)
{
#ifdef _WIN32
    if (!_fullpath(out, path, (unsigned)outcap))
        return 0;
    return 1;
#else
    if (!realpath(path, out))
        return 0;
    return strlen(out) < outcap;
#endif
}

/* ------------------------- runner ---------------------------------- */

static myc_proc_result run_mcp(const char *stdin_data, size_t stdin_len,
                               size_t cap, int timeout_ms)
{
    myc_proc_request preq;
    myc_proc_result  pres;
    const char *argv[4];

    argv[0] = g_mcp_abs;
    argv[1] = NULL;

    memset(&preq, 0, sizeof(preq));
    preq.argv = argv;
    preq.stdin_data = stdin_data;
    preq.stdin_len = stdin_len;
    preq.timeout_ms = timeout_ms;
    preq.max_output_bytes = cap;
    memset(&pres, 0, sizeof(pres));
    myc_proc_run(&preq, &pres);
    return pres;
}

/* ------------------------- parsing respons ------------------------- */

typedef struct {
    json_value *root;       /* parse hasil; caller json_free */
    int         ok;         /* jsonrpc=="2.0" + id + tepat satu result/error */
    int         is_error;
    int         err_code;   /* is_error ? error.code : 0 */
    char        id_text[96];
} mcp_resp;

static void resp_init(mcp_resp *r)
{
    memset(r, 0, sizeof(*r));
    r->ok = 0;
}

/* Parse satu baris stdout mcp sebagai respons JSON-RPC. Mengisi r. */
static void parse_response(const char *line, mcp_resp *r)
{
    json_value *jrpc, *id, *res, *err, *code;

    resp_init(r);
    if (!json_parse_cstr(line, &r->root) || !r->root ||
        r->root->type != JSON_OBJ)
        return;
    jrpc = json_get(r->root, "jsonrpc");
    if (!jrpc || jrpc->type != JSON_STR || strcmp(jrpc->str, "2.0") != 0)
        return;
    id = json_get(r->root, "id");
    if (!id)                    /* mcp SELALU meng-echo id (null pun ada) */
        return;
    if (id->type == JSON_NULL)
        snprintf(r->id_text, sizeof(r->id_text), "null");
    else if (id->type == JSON_NUM)
        snprintf(r->id_text, sizeof(r->id_text), "%lld",
                 (long long)id->num);
    else if (id->type == JSON_STR) {
        snprintf(r->id_text, sizeof(r->id_text), "%.80s", id->str);
        r->id_text[80] = '\0';
    } else
        return;                 /* id tipe tak sah di respons */
    res = json_get(r->root, "result");
    err = json_get(r->root, "error");
    if ((res != NULL) == (err != NULL))     /* tepat satu */
        return;
    if (err) {
        r->is_error = 1;
        code = json_get(err, "code");
        if (code && code->type == JSON_NUM)
            r->err_code = (int)code->num;
    }
    r->ok = 1;
}

/* ------------------------- batch helpers --------------------------- */

/* Jalankan mcp dengan [buf,len]; validasi SETIAP baris stdout adalah
 * respons JSON-RPC sah (protocol-clean) dan kembalikan jumlah respons. */
static size_t run_and_count(const char *buf, size_t len,
                            size_t cap, int timeout_ms,
                            myc_proc_result *pres, const char *tag)
{
    const char *p, *end;
    size_t n = 0;

    *pres = run_mcp(buf, len, cap, timeout_ms);
    if (pres->timed_out) {
        fprintf(stderr, "[FAIL] %s: mcp TIMEOUT (%llu ms)\n", tag,
                (unsigned long long)pres->duration_ms);
        g_fail++;
        return 0;
    }
    if (!pres->ok) {
        fprintf(stderr, "[FAIL] %s: myc_proc_run gagal (err=%d)\n",
                tag, (int)pres->err);
        g_fail++;
        return 0;
    }
    if (pres->stdout_data) {
        p = pres->stdout_data;
        end = p + pres->stdout_shown;
        while (p < end) {
            const char *nl = memchr(p, '\n', (size_t)(end - p));
            size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);
            char  *line = (char *)malloc(llen + 1);
            mcp_resp r;
            if (!line) {
                g_fail++;
                return 0;
            }
            memcpy(line, p, llen);
            line[llen] = '\0';
            /* buang \r penutup (mode teks teoritis) */
            if (llen && line[llen - 1] == '\r')
                line[llen - 1] = '\0';
            parse_response(line, &r);
            if (!r.ok) {
                fprintf(stderr, "[FAIL] %s: baris stdout BUKAN JSON-RPC "
                        "sah (protocol-clean rusak): %.120s\n", tag, line);
                g_fail++;
            }
            json_free(r.root);
            free(line);
            n++;
            if (!nl)
                break;
            p = nl + 1;
        }
    }
    return n;
}

/* Ambil respons ke-idx (0-based) dari stdout; 0 = tidak ada. */
static int response_at(const myc_proc_result *pres, size_t idx, mcp_resp *r)
{
    const char *p, *end;
    size_t n = 0;

    if (!pres->stdout_data)
        return 0;
    p = pres->stdout_data;
    end = p + pres->stdout_shown;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);
        char  *line = (char *)malloc(llen + 1);
        if (!line)
            return 0;
        memcpy(line, p, llen);
        line[llen] = '\0';
        if (llen && line[llen - 1] == '\r')
            line[llen - 1] = '\0';
        if (n == idx) {
            parse_response(line, r);
            free(line);
            return r->ok ? 1 : 0;
        }
        free(line);
        n++;
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

/* ------------------------- T0: sanity ------------------------------ */

static void test_t0(void)
{
    myc_proc_result pres;
    size_t n;
    int before = g_fail;

    /* EOF tanpa request = cancellation: mcp harus EXIT 0 bersih. */
    (void)before;
    n = run_and_count(NULL, 0, 4096, 10000, &pres, "T0 empty stdin");
    CHECK(n == 0, "T0: stdin kosong -> nol respons (got %zu)", n);
    CHECK(pres.exit_code == 0, "T0: exit 0 (got %d)", pres.exit_code);
    CHECK(pres.stderr_shown == 0,
          "T0: stderr kosong (got %zu byte)", pres.stderr_shown);
    myc_proc_result_free(&pres);
    printf("T0: sanity EOF, %d gagal\n", g_fail - before);
}

/* ------------------------- T1: baseline ---------------------------- */

/* SUMBER C dalam JSON harus SATU BARIS: `\n` di sini adalah escape JSON
 * (dua karakter backslash-n), BUKAN newline asli -- newline asli (0x0A)
 * memecah framing newline-delimited MCP (request terbelah -> respons
 * ekstra). C yang valid cukup satu baris. */
#define T1_SAFE "int main(void){return 0;}"
#define T1_OKSRC "#include <stdlib.h> int main(void){int *p=(int*)malloc(4*sizeof(int));p[0]=1;free(p);return 0;}"

static void test_t1(void)
{
    /* 18 baris; 2 notifikasi (tanpa id) -> 16 respons. */
    static const char *const lines[] = {
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"mcp_abuse\",\"version\":\"1.0\"}}}",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}",
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"version\"}}",
        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"policy\"}}",
        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"contracts\",\"arguments\":{\"source\":\"//@ requires n <= 4; //@ ensures r >= 0; int f(int *a, int n) { return n >= 0 && n <= 4 ? a[n] : 0; }\"}}}",
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"lint\",\"arguments\":{\"source\":\"int main(void){return 0;}\"}}}",
        "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":{\"source\":\"" T1_OKSRC "\"}}}",
        "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"repair\",\"arguments\":{\"source\":\"" T1_SAFE "\"}}}",
        "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\",\"params\":{\"name\":\"agent_check\",\"arguments\":{\"source\":\"" T1_SAFE "\",\"no_pack\":true}}}",
        "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/call\",\"params\":{\"name\":\"nope\",\"arguments\":{}}}",
        "bukan json sama sekali {",
        "{\"jsonrpc\":\"1.0\",\"id\":12,\"method\":\"ping\"}",
        "{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":{\"source\":\"" T1_SAFE "\",\"flags\":[\"--rnu\"]}}}",
        "{\"jsonrpc\":\"2.0\",\"id\":14,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":{\"source\":\"" T1_SAFE "\",\"flags\":\"--run\"}}}",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\"}",
        "{\"jsonrpc\":\"2.0\",\"id\":15,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":{}}}",
    };
    char *buf;
    size_t len = 0, n;
    int i, before = g_fail;
    myc_proc_result pres;
    mcp_resp r = {0};

    (void)before;
    for (i = 0; i < 18; i++)
        len += strlen(lines[i]) + 1;
    buf = (char *)malloc(len + 1);
    if (!buf) {
        fprintf(stderr, "[FAIL] T1: OOM\n");
        g_fail++;
        return;
    }
    {
        size_t off = 0;
        for (i = 0; i < 18; i++) {
            size_t l = strlen(lines[i]);
            memcpy(buf + off, lines[i], l);
            off += l;
            buf[off++] = '\n';
        }
        buf[off] = '\0';
    }
    n = run_and_count(buf, len, CAP_DEFAULT, 120000, &pres, "T1 baseline");
    CHECK(n == 16, "T1: 16 respons utk 18 baris (2 notifikasi) (got %zu)", n);
    if (n >= 16) {
        /* id 8 (check) -> result.structuredContent schema myc.result.v1
         * (structuredContent ADA DI DALAM result, bukan top-level). */
        CHECK(response_at(&pres, 7, &r) && !r.is_error &&
              r.root && json_get(json_get(r.root, "result"),
                                 "structuredContent") &&
              strcmp(r.id_text, "8") == 0,
              "T1: respons check id=8 result + structuredContent");
        json_free(r.root);
        /* id 11 unknown tool -> -32602 */
        CHECK(response_at(&pres, 10, &r) && r.is_error &&
              r.err_code == -32602 && strcmp(r.id_text, "11") == 0,
              "T1: unknown tool id=11 -> -32602");
        json_free(r.root);
        /* parse error -> -32700 id null */
        CHECK(response_at(&pres, 11, &r) && r.is_error &&
              r.err_code == -32700 && strcmp(r.id_text, "null") == 0,
              "T1: parse error -> -32700 id null");
        json_free(r.root);
        /* jsonrpc 1.0 -> -32600 id null */
        CHECK(response_at(&pres, 12, &r) && r.is_error &&
              r.err_code == -32600 && strcmp(r.id_text, "null") == 0,
              "T1: jsonrpc 1.0 -> -32600 id null");
        json_free(r.root);
        /* flag --rnu -> -32602 (MYC-AUDIT-016 fail-fast) */
        CHECK(response_at(&pres, 13, &r) && r.is_error &&
              r.err_code == -32602 && strcmp(r.id_text, "13") == 0,
              "T1: unknown flag id=13 -> -32602");
        json_free(r.root);
        /* flags string -> -32602 (PR-016 hardening) */
        CHECK(response_at(&pres, 14, &r) && r.is_error &&
              r.err_code == -32602 && strcmp(r.id_text, "14") == 0,
              "T1: flags non-array id=14 -> -32602");
        json_free(r.root);
        /* check tanpa source -> -32602 */
        CHECK(response_at(&pres, 15, &r) && r.is_error &&
              r.err_code == -32602 && strcmp(r.id_text, "15") == 0,
              "T1: check tanpa source id=15 -> -32602");
        json_free(r.root);
        /* id 3 tools/list -> result berisi tools */
        CHECK(response_at(&pres, 2, &r) && !r.is_error &&
              r.root && json_get(r.root, "result") &&
              json_get(json_get(r.root, "result"), "tools"),
              "T1: tools/list result.tools");
        json_free(r.root);
    }
    CHECK(pres.exit_code == 0, "T1: exit 0 (got %d)", pres.exit_code);
    CHECK(pres.stderr_shown == 0,
          "T1: stderr kosong (got %zu byte)", pres.stderr_shown);
    myc_proc_result_free(&pres);
    free(buf);
    printf("T1: baseline protocol-clean, %d gagal\n", g_fail - before);
}

/* ------------------------- T2: malformed corpus --------------------- */

typedef struct {
    const char *name;
    const char *line;
    int  expect_response;   /* 1 = baris ini menghasilkan respons */
    int  expect_code;       /* 0 = result; selainnya error code */
} abuse_case;

static const abuse_case CASES[] = {
    /* json tidak valid */
    { "garbage", "not json at all {", 1, -32700 },
    { "truncated-json", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"", 1, -32700 },
    { "empty-line", "", 1, -32700 },
    /* root bukan objek */
    { "array-root", "[1,2,3]", 1, -32600 },
    { "string-root", "\"hello\"", 1, -32600 },
    { "number-root", "42", 1, -32600 },
    { "null-root", "null", 1, -32600 },
    /* jsonrpc bermasalah */
    { "missing-jsonrpc", "{\"id\":1,\"method\":\"ping\"}", 1, -32600 },
    { "jsonrpc-1.0", "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"ping\"}", 1, -32600 },
    { "jsonrpc-number", "{\"jsonrpc\":2,\"id\":1,\"method\":\"ping\"}", 1, -32600 },
    /* method bermasalah */
    { "missing-method", "{\"jsonrpc\":\"2.0\",\"id\":1}", 1, -32600 },
    { "method-number", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":5}", 1, -32600 },
    /* id tipe salah */
    { "id-bool", "{\"jsonrpc\":\"2.0\",\"id\":true,\"method\":\"ping\"}", 1, -32600 },
    { "id-array", "{\"jsonrpc\":\"2.0\",\"id\":[1],\"method\":\"ping\"}", 1, -32600 },
    { "id-object", "{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"ping\"}", 1, -32600 },
    /* method tak dikenal */
    { "unknown-method", "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"no/such\"}", 1, -32601 },
    /* tools/call params/name/arguments salah */
    { "tools-call-no-params", "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\"}", 1, -32602 },
    { "tools-call-params-string", "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":\"x\"}", 1, -32602 },
    { "tools-call-no-name", "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\",\"params\":{}}", 1, -32602 },
    { "tools-call-name-number", "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/call\",\"params\":{\"name\":5}}", 1, -32602 },
    { "tools-call-unknown-tool", "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"tools/call\",\"params\":{\"name\":\"nope\",\"arguments\":{}}}", 1, -32602 },
    { "tools-call-args-string", "{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":\"src\"}}", 1, -32602 },
    /* check source / flags salah */
    { "check-missing-source", "{\"jsonrpc\":\"2.0\",\"id\":14,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":{}}}", 1, -32602 },
    { "check-source-number", "{\"jsonrpc\":\"2.0\",\"id\":15,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":{\"source\":42}}}", 1, -32602 },
    { "check-flags-string", "{\"jsonrpc\":\"2.0\",\"id\":16,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":{\"source\":\"" T1_SAFE "\",\"flags\":\"--run\"}}}", 1, -32602 },
    { "check-flags-nonstring", "{\"jsonrpc\":\"2.0\",\"id\":17,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":{\"source\":\"" T1_SAFE "\",\"flags\":[1,2]}}}", 1, -32602 },
    { "check-unknown-flag", "{\"jsonrpc\":\"2.0\",\"id\":18,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":{\"source\":\"" T1_SAFE "\",\"flags\":[\"--rnu\"]}}}", 1, -32602 },
    { "contracts-missing-source", "{\"jsonrpc\":\"2.0\",\"id\":19,\"method\":\"tools/call\",\"params\":{\"name\":\"contracts\",\"arguments\":{}}}", 1, -32602 },
    { "lint-missing-source", "{\"jsonrpc\":\"2.0\",\"id\":20,\"method\":\"tools/call\",\"params\":{\"name\":\"lint\",\"arguments\":{}}}", 1, -32602 },
    { "agent-check-missing-source", "{\"jsonrpc\":\"2.0\",\"id\":21,\"method\":\"tools/call\",\"params\":{\"name\":\"agent_check\",\"arguments\":{}}}", 1, -32602 },
    /* sah-tapi-tepi (harus result) */
    { "id-null-ping", "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}", 1, 0 },
    { "id-string-ping", "{\"jsonrpc\":\"2.0\",\"id\":\"abc\",\"method\":\"ping\"}", 1, 0 },
    { "params-ignored-ping", "{\"jsonrpc\":\"2.0\",\"id\":22,\"method\":\"ping\",\"params\":{\"x\":1}}", 1, 0 },
    { "unknown-field-top", "{\"jsonrpc\":\"2.0\",\"id\":23,\"method\":\"ping\",\"extra\":[1,2,3]}", 1, 0 },
    { "dup-key-identical", "{\"jsonrpc\":\"2.0\",\"id\":24,\"method\":\"ping\",\"method\":\"ping\"}", 1, 0 },
    /* notifikasi: valid -> tanpa respons; tanpa method -> -32600 */
    { "notification-initialized", "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", 0, 0 },
    { "notification-unknown", "{\"jsonrpc\":\"2.0\",\"method\":\"no/such/notification\"}", 0, 0 },
    { "notification-cancelled", "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\"}", 0, 0 },
    { "notification-missing-method", "{\"jsonrpc\":\"2.0\"}", 1, -32600 },
};

static void test_t2(void)
{
    int before = g_fail;
    size_t c;

    for (c = 0; c < sizeof(CASES) / sizeof(CASES[0]); c++) {
        const abuse_case *cs = &CASES[c];
        char canary[64];
        char *buf;
        size_t clen = strlen(cs->line), blen;
        myc_proc_result pres;
        mcp_resp r = {0};
        char id_canary[32];
        int expect = cs->expect_response ? 2 : 1;
        size_t n;

        snprintf(canary, sizeof(canary),
                 "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"ping\"}",
                 CANARY_BASE + (int)c);
        snprintf(id_canary, sizeof(id_canary), "%d", CANARY_BASE + (int)c);
        blen = clen + 1 + strlen(canary) + 1;
        buf = (char *)malloc(blen + 1);
        if (!buf) {
            fprintf(stderr, "[FAIL] T2 %s: OOM\n", cs->name);
            g_fail++;
            continue;
        }
        memcpy(buf, cs->line, clen);
        buf[clen] = '\n';
        strcpy(buf + clen + 1, canary);
        buf[blen - 1] = '\n';
        buf[blen] = '\0';

        n = run_and_count(buf, blen, 65536, 20000, &pres, cs->name);
        if (n != (size_t)expect) {
            fprintf(stderr, "[FAIL] T2 %s: %d respons diharapkan, got %zu\n",
                    cs->name, expect, n);
            g_fail++;
        } else if (cs->expect_response) {
            /* respons[0] = kasus; respons[1] = canary */
            if (response_at(&pres, 0, &r) &&
                (cs->expect_code == 0 ? !r.is_error
                                      : (r.is_error && r.err_code == cs->expect_code)))
                printf("[OK]   T2 %s -> %s\n", cs->name,
                       cs->expect_code ? "error" : "result");
            else {
                fprintf(stderr, "[FAIL] T2 %s: code=%d diharapkan (is_error=%d err=%d id=%s)\n",
                        cs->name, cs->expect_code, r.is_error, r.err_code, r.id_text);
                g_fail++;
            }
            json_free(r.root);
            if (response_at(&pres, 1, &r) && !r.is_error &&
                strcmp(r.id_text, id_canary) == 0)
                ;
            else {
                fprintf(stderr, "[FAIL] T2 %s: canary ping hilang/tak sah (id=%s)\n",
                        cs->name, r.id_text);
                g_fail++;
            }
            json_free(r.root);
        } else {
            /* hanya canary */
            if (response_at(&pres, 0, &r) && !r.is_error &&
                strcmp(r.id_text, id_canary) == 0)
                printf("[OK]   T2 %s -> tanpa respons (notification)\n", cs->name);
            else {
                fprintf(stderr, "[FAIL] T2 %s: notification TIDAK boleh dijawab (id=%s)\n",
                        cs->name, r.id_text);
                g_fail++;
            }
            json_free(r.root);
        }
        if (pres.exit_code != 0) {
            fprintf(stderr, "[FAIL] T2 %s: exit %d\n", cs->name, pres.exit_code);
            g_fail++;
        }
        myc_proc_result_free(&pres);
        free(buf);
    }
    printf("T2: %zu kasus malformed, %d gagal\n",
           sizeof(CASES) / sizeof(CASES[0]), g_fail - before);
}

/* ------------------------- T3: huge payload ------------------------ */

static void test_t3(void)
{
    int before = g_fail;
    size_t sizes[2] = { 8290000u, 9437184u };   /* < 8 MiB dan > 8 MiB */
    const char *tags[2] = { "T3a ~7.9MiB (< cap)", "T3b ~9MiB (> cap 8MiB)" };
    int t;

    for (t = 0; t < 2; t++) {
        char  *buf;
        const char *canary = "{\"jsonrpc\":\"2.0\",\"id\":9901,\"method\":\"ping\"}\n";
        size_t blen = sizes[t] + 1 + strlen(canary);
        myc_proc_result pres;
        mcp_resp r = {0};
        size_t n;

        buf = (char *)malloc(blen + 1);
        if (!buf) {
            fprintf(stderr, "[FAIL] %s: OOM\n", tags[t]);
            g_fail++;
            continue;
        }
        memset(buf, 'a', sizes[t]);
        buf[sizes[t]] = '\n';
        memcpy(buf + sizes[t] + 1, canary, strlen(canary));
        buf[blen] = '\0';

        n = run_and_count(buf, blen, 65536, 60000, &pres, tags[t]);
        CHECK(n == 2, "%s: 2 respons (parse error + canary) (got %zu)",
              tags[t], n);
        if (n >= 1) {
            CHECK(response_at(&pres, 0, &r) && r.is_error &&
                  r.err_code == -32700 && strcmp(r.id_text, "null") == 0,
                  "%s: respons pertama Parse error -32700", tags[t]);
            json_free(r.root);
        }
        if (n >= 2) {
            CHECK(response_at(&pres, 1, &r) && !r.is_error &&
                  strcmp(r.id_text, "9901") == 0,
                  "%s: canary ping setelahnya tetap dijawab", tags[t]);
            json_free(r.root);
        }
        CHECK(!pres.timed_out && pres.ok, "%s: tanpa timeout/hang",
              tags[t]);
        myc_proc_result_free(&pres);
        free(buf);
    }
    printf("T3: huge payload, %d gagal\n", g_fail - before);
}

/* ------------------------- T4: duplicate id ------------------------ */

static void test_t4(void)
{
    int before = g_fail;
    static const char *const lines[] = {
        "{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"ping\"}",
        "{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"ping\"}",
        "{\"jsonrpc\":\"2.0\",\"id\":\"dup\",\"method\":\"ping\"}",
        "{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"tools/list\"}",
    };
    char *buf;
    size_t len = 0, n;
    int i, before2 = g_fail;
    myc_proc_result pres;
    mcp_resp r = {0};
    int seen42 = 0, seendup = 0;

    (void)before;
    for (i = 0; i < 4; i++)
        len += strlen(lines[i]) + 1;
    buf = (char *)malloc(len + 1);
    if (!buf) {
        fprintf(stderr, "[FAIL] T4: OOM\n");
        g_fail++;
        return;
    }
    {
        size_t off = 0;
        for (i = 0; i < 4; i++) {
            size_t l = strlen(lines[i]);
            memcpy(buf + off, lines[i], l);
            off += l;
            buf[off++] = '\n';
        }
        buf[off] = '\0';
    }
    n = run_and_count(buf, len, 65536, 30000, &pres, "T4 dup id");
    CHECK(n == 4, "T4: 4 request ber-id (duplikat) -> 4 respons (got %zu)", n);
    for (i = 0; i < 4; i++) {
        if (response_at(&pres, (size_t)i, &r) && !r.is_error) {
            if (strcmp(r.id_text, "42") == 0)
                seen42++;
            if (strcmp(r.id_text, "dup") == 0)
                seendup++;
        }
        json_free(r.root);
    }
    CHECK(seen42 == 3, "T4: id 42 dijawab 3x (stateless, tanpa dedup) (got %d)",
          seen42);
    CHECK(seendup == 1, "T4: id 'dup' dijawab 1x (got %d)", seendup);
    CHECK(pres.exit_code == 0, "T4: exit 0 (got %d)", pres.exit_code);
    myc_proc_result_free(&pres);
    free(buf);
    printf("T4: duplicate id, %d gagal\n", g_fail - before2);
}

/* ------------------------- T5: notifications ------------------------ */

static void test_t5(void)
{
    int before = g_fail;
    static const char *const lines[] = {
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\"}",
        "{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}",
        "{\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"ping\"}",
        "{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}",
        "{\"jsonrpc\":\"2.0\",\"method\":\"no/such\"}",
    };
    char *buf;
    size_t len = 0, n;
    int i, before2 = g_fail;
    myc_proc_result pres;
    mcp_resp r = {0};

    (void)before;
    for (i = 0; i < 6; i++)
        len += strlen(lines[i]) + 1;
    buf = (char *)malloc(len + 1);
    if (!buf) {
        fprintf(stderr, "[FAIL] T5: OOM\n");
        g_fail++;
        return;
    }
    {
        size_t off = 0;
        for (i = 0; i < 6; i++) {
            size_t l = strlen(lines[i]);
            memcpy(buf + off, lines[i], l);
            off += l;
            buf[off++] = '\n';
        }
        buf[off] = '\0';
    }
    n = run_and_count(buf, len, 65536, 30000, &pres, "T5 notifications");
    CHECK(n == 1, "T5: 5 notifikasi tanpa respons + 1 ping ber-id (got %zu)", n);
    if (n >= 1) {
        CHECK(response_at(&pres, 0, &r) && !r.is_error &&
              strcmp(r.id_text, "77") == 0,
              "T5: satu-satunya respons = ping id 77");
        json_free(r.root);
    }
    myc_proc_result_free(&pres);
    free(buf);
    printf("T5: notification vs request, %d gagal\n", g_fail - before2);
}

/* ------------------------- T6: ordering ---------------------------- */

static void test_t6(void)
{
    int before = g_fail;
    char  *buf;
    size_t len, off = 0, n;
    int    i, before2 = g_fail;
    myc_proc_result pres;
    mcp_resp r = {0};
    int    order_ok = 1;

    (void)before;
    len = 0;
    for (i = 1; i <= 20; i++)
        len += (size_t)(64 + (i > 9 ? 1 : 0));
    buf = (char *)malloc(len + 1);
    if (!buf) {
        fprintf(stderr, "[FAIL] T6: OOM\n");
        g_fail++;
        return;
    }
    for (i = 1; i <= 20; i++) {
        int w = snprintf(buf + off, len + 1 - off,
                         "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"ping\"}\n",
                         i);
        if (w > 0)
            off += (size_t)w;
    }
    n = run_and_count(buf, off, 65536, 30000, &pres, "T6 ordering");
    CHECK(n == 20, "T6: 20 ping -> 20 respons (got %zu)", n);
    for (i = 1; i <= 20; i++) {
        char want[32];
        snprintf(want, sizeof(want), "%d", i);
        if (!response_at(&pres, (size_t)(i - 1), &r) || r.is_error ||
            strcmp(r.id_text, want) != 0) {
            fprintf(stderr, "[FAIL] T6: respons ke-%d id=%s (harap %s)\n",
                    i, r.id_text, want);
            order_ok = 0;
            g_fail++;
        }
        json_free(r.root);
    }
    CHECK(order_ok, "T6: urutan respons = urutan request (1..20)");
    myc_proc_result_free(&pres);
    free(buf);
    printf("T6: sequential ordering, %d gagal\n", g_fail - before2);
}

/* ------------------------- T7: soak 1000+ --------------------------- */

/* Bangun 1.090 baris: 1.000 ping + 30 notifikasi + 20 version + 10
 * policy + 5 lint + 5 contracts + 5 check + 2 repair + 2 agent_check +
 * 3 unknown tool + 8 malformed (2 parse error, 2 jsonrpc-1.0, 1 missing
 * method, 1 flags non-array, 2 flags entry non-string). 30 notifikasi
 * valid -> tanpa respons; SEMUA baris lain -> 1 respons = 1.060 respons
 * (1.049 result + 11 error). */
#define SOAK_PINGS     1000
#define SOAK_NOTIF     30
#define SOAK_LINES     (SOAK_PINGS + SOAK_NOTIF + 20 + 10 + 5 + 5 + 5 + 2 + 2 + 3 + 8)

static void test_t7(void)
{
    int before = g_fail;
    char *buf;
    size_t cap = 1u << 22;      /* 4 MiB input buffer */
    size_t off = 0, n;
    int i, p;
    myc_proc_result pres;
    mcp_resp r = {0};
    static char present[SOAK_PINGS + 1];
    int result_resp = 0, err_resp = 0;

    buf = (char *)malloc(cap);
    if (!buf) {
        fprintf(stderr, "[FAIL] T7: OOM\n");
        g_fail++;
        return;
    }
    memset(present, 0, sizeof(present));

#define PUSH(...) do {                                              \
        int w = snprintf(buf + off, cap - off, __VA_ARGS__);        \
        if (w > 0) off += (size_t)w;                                \
    } while (0)

    for (i = 1; i <= SOAK_PINGS; i++)
        PUSH("{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"ping\"}\n", i);
    for (i = 0; i < SOAK_NOTIF; i++)
        PUSH("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n");
    for (i = 2001; i <= 2020; i++)
        PUSH("{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"tools/call\",\"params\":{\"name\":\"version\"}}\n", i);
    for (i = 2101; i <= 2110; i++)
        PUSH("{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"tools/call\",\"params\":{\"name\":\"policy\"}}\n", i);
    for (i = 2201; i <= 2205; i++)
        PUSH("{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"tools/call\",\"params\":{\"name\":\"lint\",\"arguments\":{\"source\":\"int main(void){return 0;}\"}}}\n", i);
    for (i = 2301; i <= 2305; i++)
        PUSH("{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"tools/call\",\"params\":{\"name\":\"contracts\",\"arguments\":{\"source\":\"//@ requires n <= 4; int f(int *a, int n) { return n >= 0 && n <= 4 ? a[n] : 0; }\"}}}\n", i);
    for (i = 2401; i <= 2405; i++)
        PUSH("{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":{\"source\":\"" T1_SAFE "\"}}}\n", i);
    for (i = 2501; i <= 2502; i++)
        PUSH("{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"tools/call\",\"params\":{\"name\":\"repair\",\"arguments\":{\"source\":\"" T1_SAFE "\"}}}\n", i);
    for (i = 2601; i <= 2602; i++)
        PUSH("{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"tools/call\",\"params\":{\"name\":\"agent_check\",\"arguments\":{\"source\":\"" T1_SAFE "\",\"no_pack\":true}}}\n", i);
    for (i = 2701; i <= 2703; i++)
        PUSH("{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"tools/call\",\"params\":{\"name\":\"nope\",\"arguments\":{}}}\n", i);
    PUSH("not json {}\n");
    /* truncated JSON (tanpa kurung tutup) -> Parse error -32700 */
    PUSH("{\"jsonrpc\":\"2.0\",\"id\":2801,\"method\":\"ping\"\n");
    PUSH("{\"jsonrpc\":\"1.0\",\"id\":2802,\"method\":\"ping\"}\n");
    PUSH("{\"jsonrpc\":\"1.0\",\"id\":2803,\"method\":\"ping\"}\n");
    PUSH("{\"jsonrpc\":\"2.0\",\"id\":2804}\n");      /* missing method */
    PUSH("{\"jsonrpc\":\"2.0\",\"id\":2805,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":{\"source\":\"" T1_SAFE "\",\"flags\":\"--run\"}}}\n");
    PUSH("{\"jsonrpc\":\"2.0\",\"id\":2806,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":{\"source\":\"" T1_SAFE "\",\"flags\":[1]}}}\n");
    PUSH("{\"jsonrpc\":\"2.0\",\"id\":2807,\"method\":\"tools/call\",\"params\":{\"name\":\"check\",\"arguments\":{\"source\":\"" T1_SAFE "\",\"flags\":[1,2]}}}\n");
#undef PUSH

    n = run_and_count(buf, off, CAP_DEFAULT, 300000, &pres, "T7 soak");
    /* 1.090 baris - 30 notifikasi = 1.060 respons */
    CHECK(n == 1060, "T7: 1.060 respons utk 1.090 baris (30 notifikasi) "
          "(got %zu)", n);
    for (p = 0; p < (int)n; p++) {
        if (!response_at(&pres, (size_t)p, &r))
            continue;
        if (r.is_error) {
            err_resp++;
            /* 3 unknown tool (-32602) + 2 parse (-32700) + 2 jsonrpc-1.0
             * (-32600) + 1 missing method (-32600) + 1 flags non-array
             * (-32602) + 2 flags entry non-string (-32602) = 11 error. */
            CHECK(r.err_code == -32600 || r.err_code == -32601 ||
                  r.err_code == -32602 || r.err_code == -32700,
                  "T7: error code sah (got %d)", r.err_code);
        } else {
            result_resp++;
            /* semua ping id 1..1000 harus hadir */
            if (r.id_text[0] >= '1' && r.id_text[0] <= '9' &&
                strlen(r.id_text) <= 4) {
                long v = strtol(r.id_text, NULL, 10);
                if (v >= 1 && v <= SOAK_PINGS) {
                    if (present[v]) {
                        fprintf(stderr,
                                "[FAIL] T7: ping id %ld muncul 2x\n", v);
                        g_fail++;
                    }
                    present[v] = 1;
                }
            }
        }
        json_free(r.root);
    }
    CHECK(result_resp == 1049, "T7: 1.049 result (got %d)", result_resp);
    CHECK(err_resp == 11, "T7: 11 error (got %d)", err_resp);
    {
        int all = 1, missing = 0;
        for (i = 1; i <= SOAK_PINGS; i++)
            if (!present[i]) {
                all = 0;
                if (missing < 3)
                    fprintf(stderr, "[FAIL] T7: ping id %d TIDAK dijawab\n", i);
                missing++;
            }
        CHECK(all, "T7: semua 1.000 ping id 1..1000 dijawab tepat 1x "
              "(%d hilang)", missing);
    }
    CHECK(pres.exit_code == 0, "T7: exit 0 (got %d)", pres.exit_code);
    CHECK(pres.stderr_shown == 0,
          "T7: stderr kosong (got %zu byte)", pres.stderr_shown);
    myc_proc_result_free(&pres);
    free(buf);
    printf("T7: soak 1.090 request, %d gagal\n", g_fail - before);
}

/* ------------------------- main ------------------------------------ */

int main(int argc, char **argv)
{
    char tmp_abs[1024];

    if (argc < 2) {
        fprintf(stderr, "usage: %s <path-mcp>\n", argv[0]);
        return 2;
    }
    if (!abs_path(argv[1], g_mcp_abs, sizeof(g_mcp_abs))) {
        fprintf(stderr, "tidak dapat resolve mcp: %s\n", argv[1]);
        return 2;
    }
    /* Kerja di direktori temp sendiri agar .myc/ (cache/ledger) yang
     * ditulis mcp selama soak tidak mencemari repo. */
    make_dir(TMP_DIR);
    if (!abs_path(TMP_DIR, tmp_abs, sizeof(tmp_abs))) {
        fprintf(stderr, "tidak dapat resolve tmp dir\n");
        return 2;
    }
    change_dir(tmp_abs);

    test_t0();
    test_t1();
    test_t2();
    test_t3();
    test_t4();
    test_t5();
    test_t6();
    test_t7();

    printf(g_fail ? "mcp_abuse: FAIL (%d)\n" : "mcp_abuse: OK "
           "(T0-T7, protocol-clean + soak 1k+)\n", g_fail);
    return g_fail ? 1 : 0;
}
