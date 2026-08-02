/*
 * mcp.c -- MCP server myc (P9): ekspos pipeline verifikasi sebagai tool MCP.
 *
 * Transport: stdio, JSON-RPC 2.0, newline-delimited (satu pesan per baris).
 * Hanya menulis pesan MCP yang valid ke stdout; log/diagnostik ke stderr.
 * Tidak ada dependensi eksternal; memakai json.c (parser/serializer sendiri).
 *
 * Tool yang diekspos (tools/list + tools/call):
 *   check   -- jalankan pipeline myc pada source C (verdict/assurance/dll)
 *   version -- versi myc + ketersediaan gcc/clang
 *   policy  -- whitelist header default
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include "json.h"
#include "myc.h"
#include "policy.h"
#include "proc.h"
#include "report.h"

#include "contract.h"
#include "lint.h"

#define MCP_VERSION  "0.1.0"
#define MCP_PROTOCOL "2024-11-05"
#define MCP_MAX_LINE (8u << 20)   /* 8 MiB per pesan masuk */

static char *g_exe_dir;           /* dirname mcp.exe (untuk checked_header_dir) */

/* ------------------------- pembaca baris ---------------------------- */

/* Baca satu baris (sampai '\n') dari stdin; buang '\r' penutup.
 * Mengembalikan string malloc'd (diakhiri NUL) atau NULL saat EOF.
 * Baris lebih panjang dari MCP_MAX_LINE dibuang (drain) dan mengembalikan
 * penanda overflow (string kosong) agar caller bisa balas Parse error. */
static char *read_line(void)
{
    size_t cap = 4096, len = 0;
    char  *buf = (char *)malloc(cap);
    int    c;
    int    overflow = 0;
    if (!buf)
        return NULL;
    for (;;) {
        c = getchar();
        if (c == EOF)
            break;
        if (c == '\n')
            break;
        if (c == '\r')
            continue;
        if (len + 2 > cap) {
            if (cap >= MCP_MAX_LINE) {
                overflow = 1;       /* hentikan akumulasi, tetap drain */
                continue;
            }
            size_t ncap = cap * 2;
            if (ncap > MCP_MAX_LINE)
                ncap = MCP_MAX_LINE;
            char  *nb = (char *)realloc(buf, ncap);
            if (!nb) {
                free(buf);
                return NULL;
            }
            buf = nb;
            cap = ncap;
        }
        if (!overflow)
            buf[len++] = (char)c;
    }
    if (len == 0 && c == EOF) {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    if (overflow) {
        /* penanda: json_parse akan gagal -> respons Parse error */
        free(buf);
        buf = (char *)malloc(1);
        if (!buf)
            return NULL;
        buf[0] = '\0';
    }
    return buf;
}

/* ------------------------- pengirim respons ------------------------- */

static void send_raw(const char *json)
{
    printf("%s\n", json);
    fflush(stdout);
}

/* Kirim result/error. id: nilai "id" pesan asal (boleh NULL -> null). */
static void send_response(json_value *id, json_value *body, int is_error)
{
    json_value *msg = json_new_obj();
    char       *s = NULL;
    if (!msg) {
        json_free(body);    /* OOM: jangan bocor body */
        return;
    }
    json_obj_set(msg, "jsonrpc", json_new_str("2.0"));
    json_obj_set(msg, "id", id ? json_clone(id) : json_new_null());
    json_obj_set(msg, is_error ? "error" : "result", body);
    if (json_serialize(msg, &s) && s)
        send_raw(s);
    free(s);
    json_free(msg);
}

static void send_result(json_value *id, json_value *result)
{
    send_response(id, result, 0);
}

static void send_error(json_value *id, int code, const char *message)
{
    json_value *err = json_new_obj();
    json_obj_set(err, "code", json_new_num(code));
    json_obj_set(err, "message", json_new_str(message));
    send_response(id, err, 1);
}

/* ------------------------- tool: check ------------------------------ */

static void tool_check(json_value *id, json_value *args)
{
    myc_request req;
    myc_result  res;
    const char *source = NULL;
    const char *cwd = NULL;
    const char *run_stdin = NULL;
    json_value *flags = NULL;
    char       *text = NULL;
    json_value *result = NULL;
    json_value *content = NULL;
    json_value *item = NULL;
    size_t      i;

    if (!args) {
        send_error(id, -32602, "Invalid params: arguments wajib");
        return;
    }
    source = json_get_str(args, "source");
    if (!source) {
        send_error(id, -32602, "Invalid params: 'source' wajib (string kode C)");
        return;
    }
    cwd = json_get_str(args, "cwd");
    run_stdin = json_get_str(args, "run_stdin");
    flags = json_get(args, "flags");

    myc_request_init(&req);
    req.source = source;
    req.source_len = strlen(source);
    req.run_lint = 1;               /* lint memory-safety default ON */
    req.checked_header_dir = g_exe_dir;
    if (cwd)
        req.cwd = cwd;
    /* stdin program verification: dikonsumsi gate --run (run.c) dan
     * --filc (filc.c); hanya efektif bila salah satu flag diminta; aman
     * karena string hidup selama blok tool_check ini. */
    if (run_stdin) {
        req.run_stdin = run_stdin;
        req.run_stdin_len = strlen(run_stdin);
    }

    if (flags && flags->type == JSON_ARR) {
        for (i = 0; i < flags->len; i++) {
            const char *f = flags->items[i] && flags->items[i]->type == JSON_STR
                                ? flags->items[i]->str : NULL;
            if (!f)
                continue;
            if (strcmp(f, "--run") == 0)
                req.run = 1;
            else if (strcmp(f, "--prove") == 0)
                req.prove = 1;
            else if (strcmp(f, "--checked") == 0)
                req.checked = 1;
            else if (strcmp(f, "--filc") == 0)
                req.filc = 1;
            else if (strcmp(f, "--driver") == 0)
                req.driver = 1;
            else if (strcmp(f, "--analyze") == 0)
                req.run_analyzer = 1;
            else if (strcmp(f, "--strict") == 0)
                req.strict = 1;
            else if (strcmp(f, "--no-lint") == 0)
                req.run_lint = 0;
            else if (strcmp(f, "--quorum") == 0)
                req.quorum = 1;
            else if (strcmp(f, "--metamorphic") == 0)
                req.metamorphic = 1;
            else if (strcmp(f, "--negative") == 0)
                req.negative = 1;
        }
    }

    myc_result_init(&res);
    myc_run(&req, &res);

    text = myc_result_to_json(&res);

    /* content: [{type:"text", text:"<json result>"}] */
    result = json_new_obj();
    content = json_new_arr();
    item = json_new_obj();
    json_obj_set(item, "type", json_new_str("text"));
    json_obj_set(item, "text", json_new_str(text ? text : "{}"));
    json_arr_push(content, item);
    json_obj_set(result, "content", content);
    json_obj_set(result, "isError", json_new_bool(
        res.verdict == MC_ERROR || res.verdict == MC_TIMEOUT ||
        res.verdict == MC_CANCELLED || res.verdict == MC_PROVE_VIOLATION ||
        res.verdict == MC_DRIVER_VIOLATION ? 1 : 0));

    send_result(id, result);

    free(text);
    myc_result_free(&res);
}

/* ------------------------- tool: version ---------------------------- */

static void tool_version(json_value *id)
{
    json_sb b;
    char   *gcc = NULL;
    char   *clang = NULL;
    json_value *result = NULL;
    json_value *content = NULL;
    json_value *item = NULL;

    if (!json_sb_init(&b)) {
        send_error(id, -32603, "Internal error");
        return;
    }
    gcc = myc_find_executable("gcc");
    clang = myc_find_executable("clang");
    json_sb_printf(&b, "myc %s\n", MCP_VERSION);
    if (gcc)
        json_sb_printf(&b, "gcc: %s\n", gcc);
    else
        json_sb_puts(&b, "gcc: TIDAK DITEMUKAN\n");
    if (clang)
        json_sb_printf(&b, "clang: %s\n", clang);
    else
        json_sb_puts(&b, "clang: TIDAK DITEMUKAN (--run tidak tersedia)\n");
    json_sb_putc(&b, '\0');

    result = json_new_obj();
    content = json_new_arr();
    item = json_new_obj();
    json_obj_set(item, "type", json_new_str("text"));
    json_obj_set(item, "text", json_new_str(b.buf));
    json_arr_push(content, item);
    json_obj_set(result, "content", content);
    json_obj_set(result, "isError", json_new_bool(0));
    send_result(id, result);

    free(gcc);
    free(clang);
    json_sb_free(&b);
}

/* ------------------------- tool: contracts -------------------------- */

static void tool_contracts(json_value *id, json_value *args)
{
    const char *source = NULL;
    char      **reqs = NULL;
    char      **ensures = NULL;
    int         nreqs = 0, nens = 0;
    json_sb     b;
    json_value *result = NULL;
    json_value *content = NULL;
    json_value *item = NULL;
    int         i;

    if (!args) {
        send_error(id, -32602, "Invalid params: arguments wajib");
        return;
    }
    source = json_get_str(args, "source");
    if (!source) {
        send_error(id, -32602, "Invalid params: 'source' wajib (string kode C)");
        return;
    }

    myc_contract_list(source, strlen(source), &reqs, &nreqs,
                      &ensures, &nens);

    if (!json_sb_init(&b)) {
        send_error(id, -32603, "Internal error");
        goto out;
    }
    json_sb_printf(&b, "contracts: requires=%d ensures=%d\n", nreqs, nens);
    for (i = 0; i < nreqs; i++)
        json_sb_printf(&b, "  requires %s;\n", reqs[i]);
    for (i = 0; i < nens; i++)
        json_sb_printf(&b, "  ensures  %s;\n", ensures[i]);
    json_sb_putc(&b, '\0');

    result = json_new_obj();
    content = json_new_arr();
    item = json_new_obj();
    json_obj_set(item, "type", json_new_str("text"));
    json_obj_set(item, "text", json_new_str(b.buf));
    json_arr_push(content, item);
    json_obj_set(result, "content", content);
    json_obj_set(result, "isError", json_new_bool(0));
    send_result(id, result);
    json_sb_free(&b);

out:
    for (i = 0; i < nreqs; i++)
        free(reqs[i]);
    free(reqs);
    for (i = 0; i < nens; i++)
        free(ensures[i]);
    free(ensures);
}

/* ------------------------- tool: lint ------------------------------- */

static void tool_lint(json_value *id, json_value *args)
{
    const char *source = NULL;
    myc_result  res;
    json_sb     b;
    json_value *result = NULL;
    json_value *content = NULL;
    json_value *item = NULL;
    int         i;

    if (!args) {
        send_error(id, -32602, "Invalid params: arguments wajib");
        return;
    }
    source = json_get_str(args, "source");
    if (!source) {
        send_error(id, -32602, "Invalid params: 'source' wajib (string kode C)");
        return;
    }

    myc_result_init(&res);
    /* Catatan: myc_lint_source TIDAK mengisi res->verdict; verdict
     * disimpulkan dari nilai kembalian (0 = VIOLATION, 1 = OK). */
    {
        int lv = myc_lint_source(source, strlen(source), &res);
        if (!json_sb_init(&b)) {
            send_error(id, -32603, "Internal error");
            myc_result_free(&res);
            return;
        }
        json_sb_printf(&b, "lint verdict: %s\n", lv ? "OK" : "VIOLATION");
    }
    for (i = 0; i < res.diag_count; i++) {
        const myc_diagnostic *d = &res.diags[i];
        json_sb_printf(&b, "  [%d:%d] %s\n", d->line, d->col,
                       d->message ? d->message : "");
    }
    json_sb_putc(&b, '\0');

    result = json_new_obj();
    content = json_new_arr();
    item = json_new_obj();
    json_obj_set(item, "type", json_new_str("text"));
    json_obj_set(item, "text", json_new_str(b.buf));
    json_arr_push(content, item);
    json_obj_set(result, "content", content);
    json_obj_set(result, "isError", json_new_bool(0));
    send_result(id, result);
    json_sb_free(&b);
    myc_result_free(&res);
}

/* ------------------------- tool: policy ----------------------------- */

static void tool_policy(json_value *id)
{
    size_t n = 0, i;
    const char *const *h = myc_policy_allowed_headers(&n);
    json_sb b;
    json_value *result = NULL;
    json_value *content = NULL;
    json_value *item = NULL;

    if (!json_sb_init(&b)) {
        send_error(id, -32603, "Internal error");
        return;
    }
    json_sb_printf(&b, "whitelist header (%llu):\n", (unsigned long long)n);
    for (i = 0; i < n; i++)
        json_sb_printf(&b, "  <%s>\n", h[i]);
    json_sb_putc(&b, '\0');

    result = json_new_obj();
    content = json_new_arr();
    item = json_new_obj();
    json_obj_set(item, "type", json_new_str("text"));
    json_obj_set(item, "text", json_new_str(b.buf));
    json_arr_push(content, item);
    json_obj_set(result, "content", content);
    json_obj_set(result, "isError", json_new_bool(0));
    send_result(id, result);

    json_sb_free(&b);
}

/* ------------------------- dispatcher ------------------------------- */

/* Bangun respons tools/list. */
static json_value *tools_list_body(void)
{
    json_value *result = json_new_obj();
    json_value *tools = json_new_arr();
    json_value *t;

    /* check */
    t = json_new_obj();
    json_obj_set(t, "name", json_new_str("check"));
    json_obj_set(t, "description", json_new_str(
        "Verifikasi kode C dengan pipeline myc (memory-safety): verdict, "
        "assurance L0-L5, error, diagnostics, output gate run/prove/checked/"
        "filc. source: kode C (string, wajib). flags: array string opsional "
        "dari [--run --prove --checked --filc --driver --analyze --strict --no-lint --quorum --metamorphic --negative]. "
        "--quorum: analisis differential backend (bandingkan status semua gate "
        "yang diminta, laporkan konflik/inkonsistensi). "
        "--metamorphic: verifikasi metamorphic (build ganda clang ASan -O0/-O2, "
        "bandingkan hasil; beda = kemungkinan UB/toolchain-sensitive). "
        "--negative: negative-space analysis (observasi konvensi pemeriksaan "
        "hasil alokasi per callsite; HANYA diagnostic + confidence, non-blocking). "
        "run_stdin: string stdin untuk program verification (opsional; efektif "
        "bila --run atau --filc diminta). cwd: direktori kerja opsional."));
    {
        json_value *schema = json_new_obj();
        json_value *props = json_new_obj();
        json_value *p;
        json_value *items;

        json_obj_set(schema, "type", json_new_str("object"));

        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(p, "description", json_new_str("Kode sumber C yang akan diperiksa (wajib)."));
        json_obj_set(props, "source", p);

        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("array"));
        items = json_new_obj();
        json_obj_set(items, "type", json_new_str("string"));
        json_obj_set(p, "items", items);
        json_obj_set(p, "description", json_new_str(
            "Flag opsional: --run --prove --checked --filc --driver --analyze --strict --no-lint --quorum --metamorphic --negative"));
        json_obj_set(props, "flags", p);

        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(p, "description", json_new_str(
            "stdin untuk program verification (opsional; efektif bila --run "
            "atau --filc diminta)."));
        json_obj_set(props, "run_stdin", p);

        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(p, "description", json_new_str("Direktori kerja (opsional)."));
        json_obj_set(props, "cwd", p);

        json_obj_set(schema, "properties", props);
        {
            json_value *req = json_new_arr();
            json_arr_push(req, json_new_str("source"));
            json_obj_set(schema, "required", req);
        }
        json_obj_set(t, "inputSchema", schema);
    }
    json_arr_push(tools, t);

    /* version */
    t = json_new_obj();
    json_obj_set(t, "name", json_new_str("version"));
    json_obj_set(t, "description", json_new_str(
        "Versi myc dan ketersediaan gcc/clang di PATH."));
    {
        json_value *schema = json_new_obj();
        json_obj_set(schema, "type", json_new_str("object"));
        json_obj_set(t, "inputSchema", schema);
    }
    json_arr_push(tools, t);

    /* policy */
    t = json_new_obj();
    json_obj_set(t, "name", json_new_str("policy"));
    json_obj_set(t, "description", json_new_str(
        "Tampilkan whitelist header default myc."));
    {
        json_value *schema = json_new_obj();
        json_obj_set(schema, "type", json_new_str("object"));
        json_obj_set(t, "inputSchema", schema);
    }
    json_arr_push(tools, t);

    /* contracts */
    t = json_new_obj();
    json_obj_set(t, "name", json_new_str("contracts"));
    json_obj_set(t, "description", json_new_str(
        "Scan kontrak-lite //@ requires/ensures pada source dan tampilkan "
        "semua ekspresi kontrak. source: kode C (string, wajib)."));
    {
        json_value *schema = json_new_obj();
        json_value *props = json_new_obj();
        json_value *p;
        json_obj_set(schema, "type", json_new_str("object"));
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(p, "description", json_new_str("Kode sumber C yang akan dipindai kontraknya (wajib)."));
        json_obj_set(props, "source", p);
        json_obj_set(schema, "properties", props);
        {
            json_value *req = json_new_arr();
            json_arr_push(req, json_new_str("source"));
            json_obj_set(schema, "required", req);
        }
        json_obj_set(t, "inputSchema", schema);
    }
    json_arr_push(tools, t);

    /* lint */
    t = json_new_obj();
    json_obj_set(t, "name", json_new_str("lint"));
    json_obj_set(t, "description", json_new_str(
        "Jalankan lint memory-safety myc (heuristik) pada source dan "
        "tampilkan verdict + diagnostic. source: kode C (string, wajib)."));
    {
        json_value *schema = json_new_obj();
        json_value *props = json_new_obj();
        json_value *p;
        json_obj_set(schema, "type", json_new_str("object"));
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(p, "description", json_new_str("Kode sumber C yang akan di-lint (wajib)."));
        json_obj_set(props, "source", p);
        json_obj_set(schema, "properties", props);
        {
            json_value *req = json_new_arr();
            json_arr_push(req, json_new_str("source"));
            json_obj_set(schema, "required", req);
        }
        json_obj_set(t, "inputSchema", schema);
    }
    json_arr_push(tools, t);

    json_obj_set(result, "tools", tools);
    return result;
}

static void handle_tools_call(json_value *id, json_value *params)
{
    const char *name = NULL;
    json_value *args = NULL;

    if (params) {
        name = json_get_str(params, "name");
        args = json_get(params, "arguments");
    }
    if (!name) {
        send_error(id, -32602, "Invalid params: 'name' wajib");
        return;
    }
    if (strcmp(name, "check") == 0)
        tool_check(id, args);
    else if (strcmp(name, "version") == 0)
        tool_version(id);
    else if (strcmp(name, "policy") == 0)
        tool_policy(id);
    else if (strcmp(name, "contracts") == 0)
        tool_contracts(id, args);
    else if (strcmp(name, "lint") == 0)
        tool_lint(id, args);
    else
        send_error(id, -32602, "Unknown tool");
}

static void handle_initialize(json_value *id, json_value *params)
{
    json_value *result = json_new_obj();
    json_value *caps = json_new_obj();
    json_value *tcaps = json_new_obj();
    json_value *info = json_new_obj();
    const char *ver = MCP_PROTOCOL;

    if (params) {
        const char *pv = json_get_str(params, "protocolVersion");
        if (pv && pv[0])
            ver = pv;
    }
    json_obj_set(tcaps, "listChanged", json_new_bool(0));
    json_obj_set(caps, "tools", tcaps);
    json_obj_set(info, "name", json_new_str("myc"));
    json_obj_set(info, "version", json_new_str(MCP_VERSION));
    json_obj_set(result, "protocolVersion", json_new_str(ver));
    json_obj_set(result, "capabilities", caps);
    json_obj_set(result, "serverInfo", info);
    send_result(id, result);
}

static void handle_message(json_value *msg)
{
    json_value *m = NULL;
    json_value *id = NULL;
    json_value *params = NULL;
    const char *method = NULL;

    if (!msg || msg->type != JSON_OBJ) {
        send_error(NULL, -32600, "Invalid Request");
        return;
    }
    m = json_get(msg, "method");
    if (!m || m->type != JSON_STR) {
        send_error(NULL, -32600, "Invalid Request");
        return;
    }
    method = m->str;
    id = json_get(msg, "id");
    params = json_get(msg, "params");

    if (strcmp(method, "initialize") == 0) {
        handle_initialize(id, params);
        return;
    }
    if (strcmp(method, "ping") == 0) {
        send_result(id, json_new_obj());
        return;
    }
    if (strcmp(method, "tools/list") == 0) {
        send_result(id, tools_list_body());
        return;
    }
    if (strcmp(method, "tools/call") == 0) {
        handle_tools_call(id, params);
        return;
    }
    /* notification (metode diawali "notifications/", tidak ber-id):
     * selalu diabaikan tanpa respons (aturan JSON-RPC 2.0). */
    if (strncmp(method, "notifications/", 14) == 0)
        return;
    /* method tak dikenal: error hanya untuk pesan ber-id; notification
     * tak dikenal dibuang diam-diam. */
    if (id)
        send_error(id, -32601, "Method not found");
}

int main(int argc, char **argv)
{
    (void)argc;
    g_exe_dir = myc_exe_dirname(argv[0]);

#ifdef _WIN32
    /* binary mode: jaga agar '\n' tetap '\n' (framing MCP = satu baris). */
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    for (;;) {
        char       *line = read_line();
        json_value *msg = NULL;
        if (!line)
            break;               /* EOF: klien menutup stdin */
        if (!json_parse_cstr(line, &msg)) {
            send_error(NULL, -32700, "Parse error");
        } else {
            handle_message(msg);
            json_free(msg);
        }
        free(line);
    }

    free(g_exe_dir);
    return 0;
}
