/*
 * mcp.c -- MCP server myc (P9): ekspos pipeline verifikasi sebagai tool MCP.
 *
 * Transport: stdio, JSON-RPC 2.0, newline-delimited (satu pesan per baris).
 * Hanya menulis pesan MCP yang valid ke stdout; log/diagnostik ke stderr.
 * Tidak ada dependensi eksternal; memakai json.c (parser/serializer sendiri).
 *
 * Tool yang diekspos (tools/list + tools/call):
 *   agent_check -- protokol agent myc.agent.v2 + pack proyek lokal
 *                  opsional (pack_dir/no_pack, MYC-AUDIT-039)
 *   verify / context / next / compare_candidates -- permukaan agen (G1/G4)
 *   check   -- jalankan pipeline myc pada source C (verdict/assurance/dll)
 *   repair  -- kembalikan patch minimal untuk finding compile tertentu
 *   version -- versi myc + ketersediaan gcc/clang
 *   policy  -- whitelist header default
 *   contracts -- scan kontrak-lite //@ requires/ensures
 *   lint    -- lint memory-safety (heuristik, non-blocking)
 *
 * MYC-AUDIT-016 (2026-08-02):
 *   - JSON-RPC ketat: field "jsonrpc" wajib "2.0", id hanya string/angka/null,
 *     pesan tanpa id = notification (diproses tanpa balasan).
 *   - Negosiasi protokol strict: initialize selalu mengumumkan versi server.
 *   - tool check: hasil juga tersedia sebagai objek structuredContent
 *     (schema myc.result.v1) -- konsumen mesin tidak perlu parse JSON di
 *     dalam JSON. isError HANYA untuk kegagalan tool/protocol (ERROR/
 *     TIMEOUT/CANCELLED), bukan finding pada kode (PROVE/DRIVER_VIOLATION
 *     dll. dikirim sebagai hasil biasa).
 *   - Unknown flag pada tool check ditolak (fail-fast), tidak diabaikan.
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
#include "compile.h"

#include "contract.h"
#include "lint.h"
#include "agent.h"
#include "regress.h"
#include "ledger.h"
#include "scenario.h"
#include "context.h"
#include "eig.h"
#include "frontier.h"
#include "observation.h"
#include "candidate.h"

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
    char  *buf = (char *)myc_malloc(cap);
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
            char  *nb = (char *)myc_realloc(buf, ncap);
            if (!nb) {
                myc_free(buf);
                return NULL;
            }
            buf = nb;
            cap = ncap;
        }
        if (!overflow)
            buf[len++] = (char)c;
    }
    if (len == 0 && c == EOF) {
        myc_free(buf);
        return NULL;
    }
    buf[len] = '\0';
    if (overflow) {
        /* penanda: json_parse akan gagal -> respons Parse error */
        myc_free(buf);
        buf = (char *)myc_malloc(1);
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
    myc_free(s);
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

/* ------------------------- flags bersama ----------------------------- */

/* Terapkan array flags ke request. Mengembalikan 0 bila sukses, -1 bila
 * flags bukan array string / ada entry non-string / flag tak dikenal
 * (fail-fast, MYC-AUDIT-016/048). err diisi pesan error (max errsz). */
static int mcp_apply_flags(json_value *flags, myc_request *req,
                           char *err, size_t errsz)
{
    size_t i;

    if (!flags)
        return 0;
    if (flags->type != JSON_ARR) {
        snprintf(err, errsz, "Invalid params: 'flags' harus array string");
        return -1;
    }
    for (i = 0; i < flags->len; i++) {
        const char *f = flags->items[i] && flags->items[i]->type == JSON_STR
                            ? flags->items[i]->str : NULL;
        if (!f) {
            snprintf(err, errsz, "Invalid params: 'flags' harus array string");
            return -1;
        }
        if (strcmp(f, "--run") == 0)
            req->run = 1;
        else if (strcmp(f, "--prove") == 0)
            req->prove = 1;
        else if (strcmp(f, "--checked") == 0)
            req->checked = 1;
        else if (strcmp(f, "--filc") == 0)
            req->filc = 1;
        else if (strcmp(f, "--driver") == 0)
            req->driver = 1;
        else if (strcmp(f, "--analyze") == 0)
            req->run_analyzer = 1;
        else if (strcmp(f, "--strict") == 0)
            req->strict = 1;
        else if (strcmp(f, "--no-lint") == 0)
            req->run_lint = 0;
        else if (strcmp(f, "--watch-diff") == 0 ||
                 strcmp(f, "--delta") == 0)
            req->watch_diff = 1;   /* IDE-6: delta assurance per-fungsi */
        else if (strcmp(f, "--quorum") == 0)
            req->quorum = 1;
        else if (strcmp(f, "--metamorphic") == 0)
            req->metamorphic = 1;
        else if (strcmp(f, "--negative") == 0)
            req->negative = 1;
        else if (strcmp(f, "--require-complete") == 0)
            req->require_complete = 1;
        else if (strcmp(f, "--eig-apply") == 0)
            req->eig_apply = 1;
        else if (strcmp(f, "--parallel-gates") == 0)
            req->parallel_gates = 1;
        else {
            snprintf(err, errsz, "Invalid params: flag tidak dikenal: %.100s", f);
            return -1;
        }
    }
    return 0;
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
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = source;
    req.input.len = strlen(source);
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

    /* Flags wajib array string (PR-016, MYC-AUDIT-048): tipe salah
     * (mis. "flags":"--run") atau entry non-string TIDAK boleh di-abaikan
     * diam-diam -- mematikan gate tanpa sepengetahuan pemanggil = silent
     * misbehavior. Fail-fast -32602, konsisten dengan kebijakan unknown
     * flag (MYC-AUDIT-016). */
    {
        char ferr[160];
        if (mcp_apply_flags(flags, &req, ferr, sizeof(ferr)) != 0) {
            send_error(id, -32602, ferr);
            return;
        }
    }

    myc_result_init(&res);
    myc_run(&req, &res);

    text = myc_result_to_json(&res);

    /* content: [{type:"text", text:"<json result>"}] — teks tetap memuat
     * laporan penuh (backward compatible). Konsumen mesin memakai
     * structuredContent (MYC-AUDIT-016) sehingga TIDAK perlu parse JSON
     * di dalam JSON. */
    result = json_new_obj();
    content = json_new_arr();
    item = json_new_obj();
    json_obj_set(item, "type", json_new_str("text"));
    json_obj_set(item, "text", json_new_str(text ? text : "{}"));
    json_arr_push(content, item);
    json_obj_set(result, "content", content);

    /* structuredContent: hasil parse penuh + schema version. */
    {
        json_value *sc = NULL;
        if (text && json_parse_cstr(text, &sc) && sc->type == JSON_OBJ)
            json_obj_set(sc, "schema", json_new_str("myc.result.v1"));
        else {
            json_free(sc);
            sc = json_new_obj();
            if (sc)
                json_obj_set(sc, "schema", json_new_str("myc.result.v1"));
        }
        if (sc)
            json_obj_set(result, "structuredContent", sc);
    }
    /* isError HANYA untuk kegagalan tool/protocol (ERROR input/validasi,
     * TIMEOUT, CANCELLED). PROVE_VIOLATION/DRIVER_VIOLATION dan finding
     * lain adalah temuan pada KODE -> isError=false (verdict membawa
     * maknanya; dua sumbu finding+completeness tetap di hasil). */
    json_obj_set(result, "isError", json_new_bool(
        res.verdict == MC_ERROR || res.verdict == MC_TIMEOUT ||
        res.verdict == MC_CANCELLED ? 1 : 0));

    send_result(id, result);

    myc_free(text);
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

    myc_free(gcc);
    myc_free(clang);
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
        myc_free(reqs[i]);
    myc_free(reqs);
    for (i = 0; i < nens; i++)
        myc_free(ensures[i]);
    myc_free(ensures);
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
    /* MYC-AUDIT-014: myc_lint_source mengembalikan JUMLAH OBSERVASI
     * (heuristik teks), bukan verdict. Lint NON-blocking: tidak pernah
     * menolak kode; hard evidence dari gate semantik. */
    {
        int lv = myc_lint_source(source, strlen(source), 0, &res);
        if (!json_sb_init(&b)) {
            send_error(id, -32603, "Internal error");
            myc_result_free(&res);
            return;
        }
        json_sb_printf(&b, "lint: %d observasi (heuristik teks, "
                            "NON-blocking -- MYC-AUDIT-014)\n", lv);
    }
    for (i = 0; i < res.diag_count; i++) {
        const myc_diagnostic *d = &res.diags[i];
        const char *why = myc_lint_why(d->message);
        const char *fix = myc_lint_fix(d->message);
        json_sb_printf(&b, "  [%d:%d] [%s] %s\n", d->line, d->col,
                       myc_confidence_name(d->confidence),
                       d->message ? d->message : "");
        if (why)
            json_sb_printf(&b, "    why: %s\n", why);
        if (fix)
            json_sb_printf(&b, "    fix: %s\n", fix);
    }
    json_sb_putc(&b, '\0');

    result = json_new_obj();
    content = json_new_arr();
    item = json_new_obj();
    json_obj_set(item, "type", json_new_str("text"));
    json_obj_set(item, "text", json_new_str(b.buf));
    json_arr_push(content, item);
    json_obj_set(result, "content", content);
    {
        json_value *structured = json_new_obj();
        json_value *diag_arr = json_new_arr();
        json_obj_set(structured, "observations", json_new_num(res.diag_count));
        json_obj_set(structured, "diagnostics", diag_arr);
        for (i = 0; i < res.diag_count; i++) {
            const myc_diagnostic *d = &res.diags[i];
            json_value *diag = json_new_obj();
            json_obj_set(diag, "line", json_new_num(d->line));
            json_obj_set(diag, "col", json_new_num(d->col));
            json_obj_set(diag, "confidence",
                         json_new_str(myc_confidence_name(d->confidence)));
            json_obj_set(diag, "message",
                         json_new_str(d->message ? d->message : ""));
            json_obj_set(diag, "why",
                         json_new_str(myc_lint_why(d->message)
                                      ? myc_lint_why(d->message) : ""));
            json_obj_set(diag, "fix",
                         json_new_str(myc_lint_fix(d->message)
                                      ? myc_lint_fix(d->message) : ""));
            json_arr_push(diag_arr, diag);
        }
        json_obj_set(result, "structuredContent", structured);
    }
    json_obj_set(result, "isError", json_new_bool(0));
    send_result(id, result);
    json_sb_free(&b);
    myc_result_free(&res);
}

/* ------------------------- tool: agent_check ------------------------ */

/* IDE-3 (qwen-review, T4): bounded repair loop di agent_check.
 * agent_check(source, flags, max_iter):
 *   1. check(mode) -> verdict
 *   2. bila findings: repair(template) -> patch
 *   3. apply patch di memori -> check lagi -> bandingkan verdict
 *   4. ulangi maks max_iter; tiap iterasi tercatat receipt chain (ledger)
 *   5. hasil: verdict akhir + array langkah + preservation obligations
 * Bounded: max_iter dibatasi 1..8 (anti loop tak terbatas). Deterministik:
 * tiap iterasi myc_pipeline (tanpa cache — sanloc fresh, konsisten IDE-2).
 * Timeout (B3): additive, bukan bersama. Setiap myc_pipeline memakai
 * req.timeout_ms penuh (default MYC_DEFAULT_TIMEOUT_MS). Worst-case
 * dinding jam ≈ max_iter × timeout satu pipeline; spawn backend di dalam
 * pipeline tetap timeout_ms per proses (PR-006/007). Bukan satu deadline
 * untuk seluruh panggilan.
 * Anti-overclaim: template tidak yakin / verdict tanpa template -> why
 * jujur, loop berhenti (patch TIDAK pernah menebak). */
static void tool_agent_check(json_value *id, json_value *args)
{
    const char *source = NULL;
    const char *pack_dir = NULL;
    int         no_pack = 0;
    json_value *flags = NULL;
    int         max_iter = 3;
    myc_pack_info pinfo;
    int         pinfo_loaded = 0;
    json_value *result = NULL;
    json_value *content = NULL;
    json_value *item = NULL;
    const char *js = NULL;
    char       *text_out = NULL;
    char       *current = NULL;      /* source saat ini (malloc'd) */
    char       *prev_receipt = NULL; /* receipt iterasi sebelumnya (chain) */
    const char *prev_verdict = NULL; /* verdict iterasi sebelumnya (delta) */
    myc_result  pending;             /* hasil check yang sudah ada (skip re-run) */
    int         have_pending = 0;
    myc_result  final_res;           /* hasil terakhir (utk agent result) */
    int         have_final = 0;
    json_value *steps = NULL;
    int         iterations = 0;
    int         converged = 0;
    myc_agent_result ar;
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
    /* Fase 7 (MYC-AUDIT-039): pack proyek lokal opsional (myc.prompt.md
     * + myc.spec.json). pack_dir: NULL = cwd server (konsisten CLI);
     * no_pack: true = nonaktifkan (perilaku = pack absen). */
    pack_dir = json_get_str(args, "pack_dir");
    {
        json_value *np = json_get(args, "no_pack");
        if (np && np->type == JSON_BOOL && np->boolean)
            no_pack = 1;
    }
    flags = json_get(args, "flags");
    {
        /* IDE-3: bounded loop. max_iter default 3, dibatasi 1..8 (anti
         * loop tak terbatas; deterministik). Tipe salah = fail-fast. */
        json_value *mi = json_get(args, "max_iter");
        if (mi) {
            if (mi->type != JSON_NUM || mi->num < 1 || mi->num > 8) {
                send_error(id, -32602,
                           "Invalid params: 'max_iter' harus number 1..8");
                return;
            }
            max_iter = (int)mi->num;
        }
    }

    /* Fase 7 (MYC-AUDIT-039): muat pack proyek lokal. spec.json ADA tapi
     * invalid = error tool -32602 (fail-fast, pola CLI exit 2); OOM/IO =
     * -32603. Tidak mempengaruhi verdict (NON-blocking). */
    memset(&pinfo, 0, sizeof(pinfo));
    if (!no_pack) {
        int prc = myc_pack_load(pack_dir, no_pack, &pinfo);
        if (prc == -1) {
            send_error(id, -32602,
                       "Invalid params: myc.spec.json invalid (skema: "
                       "version=1, name wajib; rules/allow_headers/"
                       "deny_functions = array string)");
            return;
        }
        if (prc == -2) {
            send_error(id, -32603,
                       "Internal error: gagal membaca pack proyek (OOM/IO)");
            return;
        }
        pinfo_loaded = 1;
    }

    current = myc_strdup(source);
    if (!current) {
        send_error(id, -32603, "Internal error: OOM");
        if (pinfo_loaded)
            myc_free(pinfo.prompt_text);
        return;
    }
    steps = json_new_arr();
    if (!steps) {
        send_error(id, -32603, "Internal error: OOM");
        myc_free(current);
        if (pinfo_loaded)
            myc_free(pinfo.prompt_text);
        return;
    }
    myc_result_init(&pending);
    myc_result_init(&final_res);

    for (i = 1; i <= max_iter && !converged; i++) {
        myc_request req;
        myc_result  res;
        char        ferr[160];
        json_value *step;
        const char *this_receipt;

        myc_request_init(&req); /* timeout_ms = MYC_DEFAULT_TIMEOUT_MS (additive) */
        req.input.kind = MYC_SOURCE_MEMORY;
        req.input.data = current;
        req.input.len = strlen(current);
        req.run_lint = 1;
        req.checked_header_dir = g_exe_dir;
        if (mcp_apply_flags(flags, &req, ferr, sizeof(ferr)) != 0) {
            send_error(id, -32602, ferr);
            myc_free(current);
            myc_free(prev_receipt);
            myc_result_free(&pending);
            myc_result_free(&final_res);
            json_free(steps);
            if (pinfo_loaded)
                myc_free(pinfo.prompt_text);
            return;
        }

        if (have_pending) {
            /* hasil check patched dari iterasi sebelumnya: tanpa re-run */
            res = pending;
            myc_result_init(&pending);
            have_pending = 0;
        } else {
            myc_result_init(&res);
            myc_pipeline(&req, &res);
        }
        this_receipt = res.receipt_sha256[0] ? res.receipt_sha256 : NULL;

        step = json_new_obj();
        if (!step) {
            send_error(id, -32603, "Internal error: OOM");
            myc_result_free(&res);
            myc_free(current);
            myc_free(prev_receipt);
            myc_result_free(&pending);
            myc_result_free(&final_res);
            json_free(steps);
            if (pinfo_loaded)
                myc_free(pinfo.prompt_text);
            return;
        }
        json_obj_set(step, "iter", json_new_num(i));
        json_obj_set(step, "verdict",
                     json_new_str(myc_verdict_name(res.verdict)));
        json_obj_set(step, "finding",
                     json_new_str(myc_finding_name(res.finding)));
        if (res.source_sha256)
            json_obj_set(step, "source_sha256",
                         json_new_str(res.source_sha256));
        if (this_receipt)
            json_obj_set(step, "receipt_sha256", json_new_str(this_receipt));
        if (prev_receipt && prev_receipt[0])
            json_obj_set(step, "parent_receipt", json_new_str(prev_receipt));

        /* IDE-3: tiap iterasi tercatat receipt chain di ledger
         * (.myc/ledger.json, NON-blocking). receipt_parent = receipt
         * iterasi sebelumnya; verdict/finding/scenario tercatat agar
         * harness bisa mendeteksi cherry-pick / regresi antar iterasi. */
        {
            myc_ledger_entry e;
            char *scenario_hash;
            memset(&e, 0, sizeof(e));
            e.source_sha256 = res.source_sha256 ? res.source_sha256 : (char *)"";
            e.receipt_sha256 = this_receipt ? (char *)this_receipt : (char *)"";
            e.receipt_parent = prev_receipt;
            scenario_hash = myc_ledger_build_scenario_hash(&req, NULL);
            e.scenario_hash = scenario_hash;
            e.timestamp = myc_ledger_timestamp();
            e.verdict = (char *)myc_verdict_name(res.verdict);
            e.finding = (char *)myc_finding_name(res.finding);
            /* delta vs iterasi SEBELUMNYA (bukan klaim global):
             * VIOLATION->OK = FIXED, OK->VIOLATION = NEW, sama =
             * PERSISTENT, selain itu CHURN. Tanpa pembanding (iterasi
             * 1) = PERSISTENT (netral, tanpa klaim transisi). */
            if (prev_verdict && prev_verdict[0]) {
                const char *cv = myc_verdict_name(res.verdict);
                if (strstr(prev_verdict, "VIOLATION") &&
                    strcmp(cv, "OK") == 0)
                    e.delta = MYC_DELTA_FIXED;
                else if (strstr(cv, "VIOLATION") &&
                         strcmp(prev_verdict, "OK") == 0)
                    e.delta = MYC_DELTA_NEW;
                else if (strcmp(prev_verdict, cv) == 0)
                    e.delta = MYC_DELTA_PERSISTENT;
                else
                    e.delta = MYC_DELTA_CHURN;
            } else {
                e.delta = MYC_DELTA_PERSISTENT;
            }
            myc_ledger_write(&e);
            myc_free(scenario_hash);
            myc_free(e.timestamp);
        }

        iterations = i;

        if (res.verdict == MC_OK) {
            /* konvergen: verdict OK, tanpa patch */
            converged = 1;
            json_arr_push(steps, step);
            final_res = res;
            myc_result_init(&res);
            have_final = 1;
            break;
        }

        if (res.verdict == MC_RUNTIME_VIOLATION && res.sanloc_have) {
            /* IDE-2: template runtime deterministik berbasis lokasi */
            myc_runtime_repair *rr =
                myc_repair_runtime_patch(&res, current, strlen(current));
            if (rr && rr->patched_source) {
                char *new_src = myc_strdup(rr->patched_source);
                json_obj_set(step, "patch_applied", json_new_bool(1));
                if (rr->patch_text)
                    json_obj_set(step, "patch", json_new_str(rr->patch_text));
                if (rr->confidence > 0)
                    json_obj_set(step, "confidence",
                                 json_new_num(rr->confidence));
                if (new_src) {
                    myc_free(current);
                    current = new_src;
                    /* apply patch di memori -> check lagi (bukti) */
                    {
                        myc_request preq;
                        myc_result  pres;
                        const char *after;
                        const char *pres_receipt;
                        char        pres_rbuf[65];
                        myc_request_init(&preq);
                        preq.input.kind = MYC_SOURCE_MEMORY;
                        preq.input.data = current;
                        preq.input.len = strlen(current);
                        preq.run_lint = 1;
                        preq.checked_header_dir = g_exe_dir;
                        (void)mcp_apply_flags(flags, &preq, ferr,
                                              sizeof(ferr));
                        myc_result_init(&pres);
                        myc_pipeline(&preq, &pres);
                        after = myc_verdict_name(pres.verdict);
                        /* salin ke buffer lokal: `pending = pres` +
                         * `myc_result_init(&pres)` meng-zero struct
                         * asal sehingga pointer ke receipt_sha256 di
                         * dalamnya jadi invalid (bug T4 v1). */
                        if (pres.receipt_sha256[0])
                            memcpy(pres_rbuf, pres.receipt_sha256, 65);
                        else
                            pres_rbuf[0] = '\0';
                        pres_receipt = pres_rbuf[0] ? pres_rbuf : NULL;
                        json_obj_set(step, "verdict_after_patch",
                                     json_new_str(after));
                        if (pres.verdict == MC_OK) {
                            /* IDE-4: replay corpus regression terhadap
                             * kode baru (bug lama hidup kembali = debt
                             * eksplisit, bukan kesunyian). */
                            int total = 0, resolved = 0, failing = 0;
                            char rb[256];
                            myc_regress_replay_mem(current,
                                                   strlen(current),
                                                   &total, &resolved,
                                                   &failing);
                            if (failing > 0)
                                snprintf(rb, sizeof(rb),
                                         "regression_replay: %d/%d clean, "
                                         "%d masih gagal (bug lama hidup "
                                         "kembali)", resolved, total,
                                         failing);
                            else if (total > 0)
                                snprintf(rb, sizeof(rb),
                                         "regression_replay: %d/%d clean",
                                         resolved, total);
                            else
                                snprintf(rb, sizeof(rb),
                                         "regression_replay: corpus kosong "
                                         "(0 seed)");
                            json_obj_set(step, "regression_replay",
                                         json_new_str(rb));
                            converged = 1;
                            final_res = pres;
                            myc_result_init(&pres);
                            have_final = 1;
                        } else {
                            /* masih violation: iterasi berikutnya pakai
                             * hasil check ini (tanpa re-run) */
                            pending = pres;
                            myc_result_init(&pres);
                            have_pending = 1;
                            /* parent chain iterasi berikutnya = hasil
                             * PATCHED (pres), bukan check lama (res) */
                            myc_free(prev_receipt);
                            prev_receipt = pres_receipt
                                               ? myc_strdup(pres_receipt)
                                               : NULL;
                            prev_verdict = after;
                        }
                    }
                }
            } else {
                json_obj_set(step, "patch_applied", json_new_bool(0));
                json_obj_set(step, "why", json_new_str(
                    rr && rr->why ? rr->why
                                  : "tidak ada template repair yang yakin "
                                    "(jujur, anti-overclaim)"));
                final_res = res;
                myc_result_init(&res);
                have_final = 1;
            }
            if (rr)
                myc_runtime_repair_free(rr);
        } else if (res.verdict == MC_COMPILE_ERROR && res.diag_count > 0) {
            /* G3: apply in-memory hanya bila template satu baris
             * (gets/sprintf array lokal) + confidence tinggi + re-check
             * tidak menambah diagnostic. Selain itu saran teks, berhenti. */
            int cline = res.diags[0].line;
            myc_runtime_repair *crr = NULL;
            if (cline > 0)
                crr = myc_repair_source_line_patch(current, strlen(current),
                                                   cline);
            if (crr && crr->patched_source && crr->confidence >= 80) {
                char *new_src = myc_strdup(crr->patched_source);
                int orig_diags = res.diag_count;
                json_obj_set(step, "patch_applied", json_new_bool(1));
                if (crr->patch_text)
                    json_obj_set(step, "patch",
                                 json_new_str(crr->patch_text));
                json_obj_set(step, "confidence",
                             json_new_num(crr->confidence));
                if (new_src) {
                    myc_request preq;
                    myc_result  pres;
                    char ferr2[160];
                    myc_free(current);
                    current = new_src;
                    myc_request_init(&preq);
                    preq.input.kind = MYC_SOURCE_MEMORY;
                    preq.input.data = current;
                    preq.input.len = strlen(current);
                    preq.run_lint = 1;
                    preq.checked_header_dir = g_exe_dir;
                    if (mcp_apply_flags(flags, &preq, ferr2,
                                        sizeof(ferr2)) != 0) {
                        myc_runtime_repair_free(crr);
                        send_error(id, -32602, ferr2);
                        myc_free(current);
                        myc_free(prev_receipt);
                        myc_result_free(&res);
                        myc_result_free(&pending);
                        myc_result_free(&final_res);
                        json_free(steps);
                        json_free(step);
                        if (pinfo_loaded)
                            myc_free(pinfo.prompt_text);
                        return;
                    }
                    myc_result_init(&pres);
                    myc_pipeline(&preq, &pres);
                    if (pres.diag_count > orig_diags) {
                        json_obj_set(step, "patch_reverted",
                                     json_new_bool(1));
                        json_obj_set(step, "why", json_new_str(
                            "re-check menambah diagnostic; patch "
                            "dibatalkan (anti-churn)"));
                        myc_result_free(&pres);
                        final_res = res;
                        myc_result_init(&res);
                        have_final = 1;
                    } else if (pres.verdict == MC_OK) {
                        pending = pres;
                        myc_result_init(&pres);
                        have_pending = 1;
                    } else {
                        pending = pres;
                        myc_result_init(&pres);
                        have_pending = 1;
                    }
                } else {
                    json_obj_set(step, "patch_applied", json_new_bool(0));
                    json_obj_set(step, "why", json_new_str("OOM saat apply"));
                    final_res = res;
                    myc_result_init(&res);
                    have_final = 1;
                }
            } else {
                const char *code = repair_find_code(res.diags[0].message);
                char *p = code ? myc_repair_get_patch(code) : NULL;
                json_obj_set(step, "patch_applied", json_new_bool(0));
                if (p) {
                    json_obj_set(step, "patch", json_new_str(p));
                    myc_free(p);
                }
                json_obj_set(step, "why", json_new_str(
                    crr && crr->why ? crr->why
                                    : "template compile = saran teks "
                                      "atau bukan satu baris lokal; "
                                      "tidak diterapkan (anti-churn)"));
                final_res = res;
                myc_result_init(&res);
                have_final = 1;
            }
            if (crr)
                myc_runtime_repair_free(crr);
        } else {
            json_obj_set(step, "patch_applied", json_new_bool(0));
            json_obj_set(step, "why", json_new_str(
                "verdict tidak memiliki template repair (jujur)"));
            final_res = res;
            myc_result_init(&res);
            have_final = 1;
        }

        json_arr_push(steps, step);
        if (converged || have_final)
            break;

        /* lanjut iterasi: parent chain = receipt state berikutnya.
         * Bila pending (hasil patched) sudah diset di blok patch,
         * jangan timpa — res di sini adalah check LAMA. */
        if (!have_pending) {
            myc_free(prev_receipt);
            prev_receipt = this_receipt ? myc_strdup(this_receipt) : NULL;
            prev_verdict = myc_verdict_name(res.verdict);
        }
        myc_result_free(&res);
    }

    /* loop habis karena max_iter: hasil check terakhir (pending) jadi
     * hasil akhir bila ada (bukan kesunyian — debt/verdict terlihat). */
    if (have_pending) {
        final_res = pending;
        myc_result_init(&pending);
        have_pending = 0;
        have_final = 1;
    }
    if (!have_final) {
        /* tidak mungkin (loop selalu break dgn final atau converged),
         * tapi jaga-jaga agar tidak build dari struct kosong. */
        send_error(id, -32603, "Internal error: loop agent_check kosong");
        myc_free(current);
        myc_free(prev_receipt);
        myc_result_free(&pending);
        myc_result_free(&final_res);
        json_free(steps);
        if (pinfo_loaded)
            myc_free(pinfo.prompt_text);
        return;
    }

    memset(&ar, 0, sizeof(ar));
    if (myc_build_agent_result(&final_res, &ar, NULL, NULL,
                               pinfo_loaded ? &pinfo : NULL,
                               current,
                               current ? strlen(current) : 0) < 0) {
        /* Catatan: myc_build_agent_result SUDAH membebaskan ar secara
         * internal sebelum return -1 (payload > cap) -- jangan free lagi
         * di sini (double-free). */
        send_error(id, -32603, "Internal error: gagal build agent result");
        myc_free(current);
        myc_free(prev_receipt);
        myc_result_free(&pending);
        myc_result_free(&final_res);
        json_free(steps);
        if (pinfo_loaded)
            myc_free(pinfo.prompt_text);
        return;
    }

    js = myc_agent_result_json(&ar);

    /* Text: JSON agent v2 + repair_loop (bounded loop steps) +
     * preservation_obligations (anti-churn, konsisten context.c). */
    {
        json_value *root = NULL;
        if (js && json_parse_cstr(js, &root) && root &&
            root->type == JSON_OBJ) {
            json_value *loop = json_new_obj();
            json_value *pres = json_new_arr();
            static const char *const OBLIG[] = {
                "- jangan ubah kode di luar fungsi yang disorot "
                "(anti-churn)",
                "- jangan ubah/melemahkan kontrak //@ di atas fungsi "
                "target",
                "- jangan menyempitkan domain verifikasi / mengubah "
                "scenario",
                "- jangan menurunkan assurance / menonaktifkan "
                "sanitizer, warning, atau assert",
                "- pertahankan signature/ABI fungsi publik"
            };
            size_t k;
            if (loop) {
                json_obj_set(loop, "max_iter", json_new_num(max_iter));
                json_obj_set(loop, "iterations", json_new_num(iterations));
                json_obj_set(loop, "converged", json_new_bool(converged));
                json_obj_set(loop, "steps", steps);
                steps = NULL;
                json_obj_set(root, "repair_loop", loop);
            }
            if (pres) {
                for (k = 0; k < sizeof(OBLIG) / sizeof(OBLIG[0]); k++)
                    json_arr_push(pres, json_new_str(OBLIG[k]));
                json_obj_set(root, "preservation_obligations", pres);
            }
            if (!json_serialize(root, &text_out) || !text_out)
                text_out = myc_strdup(js ? js : "{}");
            json_free(root);
        } else {
            text_out = myc_strdup(js ? js : "{}");
        }
        if (steps) {
            json_free(steps);
            steps = NULL;
        }
    }

    result = json_new_obj();
    content = json_new_arr();
    item = json_new_obj();
    json_obj_set(item, "type", json_new_str("text"));
    json_obj_set(item, "text", json_new_str(text_out ? text_out : "{}"));
    json_arr_push(content, item);
    json_obj_set(result, "content", content);

    /* structuredContent: objek agent v2 + ringkasan loop */
    {
        json_value *structured = json_new_obj();
        json_obj_set(structured, "schema", json_new_str("myc.agent.v2"));
        json_obj_set(structured, "verdict",
                     json_new_str(myc_verdict_name(ar.verdict)));
        json_obj_set(structured, "finding",
                     json_new_str(myc_finding_name(ar.finding)));
        json_obj_set(structured, "primary_action",
                     json_new_str(ar.has_primary ? "investigate" : "none"));
        json_obj_set(structured, "witness",
                     json_new_str(ar.witness_text ? ar.witness_text : ""));
        json_obj_set(structured, "next_check_command",
                     json_new_str(ar.next_check.command
                                  ? ar.next_check.command : ""));
        json_obj_set(structured, "payload_size",
                     json_new_num((int64_t)ar.payload_size));
        json_obj_set(structured, "pack_present",
                     json_new_bool(ar.pack_json ? 1 : 0));
        json_obj_set(structured, "repair_loop_max_iter",
                     json_new_num(max_iter));
        json_obj_set(structured, "repair_loop_iterations",
                     json_new_num(iterations));
        json_obj_set(structured, "repair_loop_converged",
                     json_new_bool(converged));
        json_obj_set(result, "structuredContent", structured);
    }

    json_obj_set(result, "isError", json_new_bool(0));
    send_result(id, result);

    myc_free(text_out);
    if (js) myc_free((void *)js);
    myc_agent_result_free(&ar);
    myc_free(current);
    myc_free(prev_receipt);
    myc_result_free(&pending);
    myc_result_free(&final_res);
    if (pinfo_loaded)
        myc_free(pinfo.prompt_text);
}

/* ------------------------- tool: repair ---------------------------- */

static void tool_repair(json_value *id, json_value *args)
{
    const char *source = NULL;
    const char *patched_source = NULL;
    myc_request req;
    myc_result  res;
    const char *finding_code = NULL;
    char       *patch = NULL;
    const char *applied_verdict = NULL;
    int         confidence = 0;
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
    patched_source = json_get_str(args, "patched_source");
    finding_code = json_get_str(args, "finding_code");

    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = source;
    req.input.len = strlen(source);
    req.run_lint = 1;
    {
        /* IDE-2 (qwen-review): repair RUNTIME_VIOLATION butuh gate run
         * agar sanitizer_location (IDE-1) terisi. Arg opsional `run`
         * (0/1); default 0 (perilaku lama, compile-only). Bila run=1,
         * cache di-nonaktifkan (no_cache): cache replay SOL-18 TIDAK
         * menyimpan sanloc_* (IDE-1), jadi cache-hit akan kehilangan
         * lokasi pelanggaran — repair harus melihat bukti fresh. */
        json_value *rv = json_get(args, "run");
        if (rv && rv->type == JSON_NUM && rv->num == 1)
            req.run = 1;
        else if (rv && rv->type == JSON_BOOL && rv->num == 1)
            req.run = 1;
        if (req.run)
            req.no_cache = 1;
    }
    myc_result_init(&res);
    myc_run(&req, &res);

    applied_verdict = myc_verdict_name(res.verdict);

    if (res.diag_count > 0 && !finding_code) {
        const char *code = repair_find_code(res.diags[0].message);
        if (code)
            finding_code = code;
    }

    if (finding_code) {
        patch = myc_repair_get_patch(finding_code);
        for (i = 0; i < (int)REPAIR_TEMPLATES_COUNT; i++) {
            if (strcmp(REPAIR_TEMPLATES[i].finding_code, finding_code) == 0) {
                confidence = REPAIR_TEMPLATES[i].confidence;
                break;
            }
        }
    }

    /* IDE-2/IDE-4 (qwen-review):
     *  - IDE-2: bila verdict RUNTIME_VIOLATION + sanitizer_location
     *    (IDE-1) tersedia, generate patch template DETERMINISTIK
     *    (strcpy/strcat->snprintf, memset/memcpy->clamp, UAF->NULL-kan)
     *    yang mengganti baris pelanggaran, lalu re-run source yang
     *    di-patch -> new_verdict_after_patch (BUKTI, bukan klaim).
     *  - IDE-4: bila caller menyertakan patched_source (kode baru setelah
     *    patch diterapkan), re-check kode itu; bila verdict berubah jadi
     *    OK, replay corpus regression -> regression_replay: K/N clean.
     *    Mencegah pola klasik LLM: memperbaiki bug A sambil menghidupkan
     *    kembali bug B. NON-blocking (replay tidak mengubah verdict). */
    {
        const char       *new_verdict = NULL;
        const char       *why_runtime = NULL;
        int               total = 0, resolved = 0, failing = 0;
        char              replay_buf[256] = "";
        myc_runtime_repair *rr = NULL;
        char             *effective_patched = NULL; /* malloc'd: IDE-2 */
        int               run_for_patched = 0;

        /* IDE-2: template runtime patch dari lokasi sanitizer */
        if (res.verdict == MC_RUNTIME_VIOLATION && res.sanloc_have) {
            rr = myc_repair_runtime_patch(&res, source, strlen(source));
            if (rr) {
                if (rr->patched_source) {
                    patch = myc_strdup(rr->patch_text ? rr->patch_text
                                                      : "patch runtime");
                    confidence = rr->confidence;
                    if (!finding_code && res.sanloc_kind)
                        finding_code = res.sanloc_kind;
                    effective_patched = myc_strdup(rr->patched_source);
                    run_for_patched = 1;
                } else if (rr->why) {
                    why_runtime = rr->why;
                }
            }
        }

        if (patched_source) {
            effective_patched = myc_strdup(patched_source);
        }

        if (effective_patched) {
            myc_request preq;
            myc_result  pres;
            myc_request_init(&preq);
            preq.input.kind = MYC_SOURCE_MEMORY;
            preq.input.data = effective_patched;
            preq.input.len = strlen(effective_patched);
            preq.run_lint = 1;
            preq.run = run_for_patched; /* IDE-2 butuh gate run utk bukti */
            myc_result_init(&pres);
            myc_run(&preq, &pres);
            new_verdict = myc_verdict_name(pres.verdict);
            /* Replay corpus terhadap kode baru BILA kode baru verifikasi
             * OK (repair berhasil). Catatan: check di sini compile-only
             * bila caller (bukan IDE-2), jadi source runtime-buggy tetap
             * punya res.verdict OK -- yang menentukan replay adalah
             * verdict KODE BARU, bukan verdict source lama. */
            if (pres.verdict == MC_OK) {
                myc_regress_replay_mem(effective_patched,
                                       strlen(effective_patched),
                                       &total, &resolved, &failing);
                if (failing > 0)
                    snprintf(replay_buf, sizeof(replay_buf),
                             "regression_replay: %d/%d clean, "
                             "%d masih gagal (bug lama hidup kembali)",
                             resolved, total, failing);
                else if (total > 0)
                    snprintf(replay_buf, sizeof(replay_buf),
                             "regression_replay: %d/%d clean",
                             resolved, total);
                else
                    snprintf(replay_buf, sizeof(replay_buf),
                             "regression_replay: corpus kosong "
                             "(0 seed)");
            }
            myc_result_free(&pres);
        }

        result = json_new_obj();
        content = json_new_arr();
        item = json_new_obj();
        json_obj_set(item, "type", json_new_str("text"));
        if (patch) {
            char buf[1024];
            snprintf(buf, sizeof(buf),
                     "repair: finding=%s\nconfidence=%d\napplied_verdict=%s\n"
                     "%s%s\n%s\npatch:\n%s\n",
                     finding_code ? finding_code : "unknown",
                     confidence,
                     applied_verdict,
                     new_verdict ? "new_verdict_after_patch=" : "",
                     new_verdict ? new_verdict : "",
                     why_runtime ? why_runtime : "",
                     patch);
            json_obj_set(item, "text", json_new_str(buf));
        } else {
            char buf[512];
            snprintf(buf, sizeof(buf),
                     "repair: patch tidak tersedia%s%s\n",
                     why_runtime ? " — " : "",
                     why_runtime ? why_runtime : "");
            json_obj_set(item, "text", json_new_str(buf));
        }
        json_arr_push(content, item);
        json_obj_set(result, "content", content);

        {
            json_value *structured = json_new_obj();
            json_obj_set(structured, "finding", json_new_str(finding_code ? finding_code : "unknown"));
            json_obj_set(structured, "applied_verdict", json_new_str(applied_verdict));
            json_obj_set(structured, "confidence", json_new_num(confidence));
            json_obj_set(structured, "patch", json_new_str(patch ? patch : "null"));
            if (new_verdict)
                json_obj_set(structured, "new_verdict_after_patch",
                             json_new_str(new_verdict));
            if (why_runtime)
                json_obj_set(structured, "why",
                             json_new_str(why_runtime));
            if (replay_buf[0])
                json_obj_set(structured, "regression_replay",
                             json_new_str(replay_buf));
            json_obj_set(structured, "schema", json_new_str("myc.repair.v1"));
            json_obj_set(result, "structuredContent", structured);
        }

        myc_free(effective_patched);
        if (rr)
            myc_runtime_repair_free(rr);
    }

    json_obj_set(result, "isError", json_new_bool(0));
    send_result(id, result);

    myc_free(patch);
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

/* ------------------------- tool: verify (myc.lite.v1) --------------- */

static void tool_verify(json_value *id, json_value *args)
{
    const char *source = NULL;
    json_value *flags = NULL;
    myc_request req;
    myc_result  res;
    myc_lite_result lr;
    char       *js = NULL;
    json_value *result = NULL;
    json_value *content = NULL;
    json_value *item = NULL;
    int         use_auto = 1;

    if (!args) {
        send_error(id, -32602, "Invalid params: arguments wajib");
        return;
    }
    source = json_get_str(args, "source");
    if (!source) {
        send_error(id, -32602,
                   "Invalid params: 'source' wajib (string kode C)");
        return;
    }
    flags = json_get(args, "flags");
    if (flags && flags->type == JSON_ARR && flags->len > 0)
        use_auto = 0;

    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = source;
    req.input.len = strlen(source);
    req.run_lint = 1;
    req.checked_header_dir = g_exe_dir;
    myc_result_init(&res);

    if (use_auto) {
        int serc = myc_scenario_apply(&req, "auto", source, strlen(source),
                                      NULL, &res);
        if (serc != 0) {
            send_error(id, -32603,
                       "Internal error: scenario auto gagal");
            myc_result_free(&res);
            return;
        }
    } else {
        char ferr[160];
        if (mcp_apply_flags(flags, &req, ferr, sizeof(ferr)) != 0) {
            send_error(id, -32602, ferr);
            myc_result_free(&res);
            return;
        }
    }

    myc_run(&req, &res);
    if (myc_build_lite_result(&res, &lr, source, strlen(source)) != 0) {
        send_error(id, -32603, "Internal error: gagal build lite result");
        myc_result_free(&res);
        return;
    }
    js = myc_lite_result_json(&lr);
    result = json_new_obj();
    content = json_new_arr();
    item = json_new_obj();
    json_obj_set(item, "type", json_new_str("text"));
    json_obj_set(item, "text", json_new_str(js ? js : "{}"));
    json_arr_push(content, item);
    json_obj_set(result, "content", content);
    {
        json_value *sc = NULL;
        if (js && json_parse_cstr(js, &sc) && sc && sc->type == JSON_OBJ)
            json_obj_set(result, "structuredContent", sc);
        else {
            json_free(sc);
            sc = json_new_obj();
            if (sc)
                json_obj_set(sc, "schema", json_new_str(MYC_LITE_SCHEMA));
            json_obj_set(result, "structuredContent", sc);
        }
    }
    json_obj_set(result, "isError", json_new_bool(
        res.verdict == MC_ERROR || res.verdict == MC_TIMEOUT ||
        res.verdict == MC_CANCELLED ? 1 : 0));
    send_result(id, result);
    myc_free(js);
    myc_lite_result_free(&lr);
    myc_result_free(&res);
}

static void mcp_send_json_text(json_value *id, const char *js, int is_error)
{
    json_value *result = json_new_obj();
    json_value *content = json_new_arr();
    json_value *item = json_new_obj();
    json_value *sc = NULL;

    json_obj_set(item, "type", json_new_str("text"));
    json_obj_set(item, "text", json_new_str(js ? js : "{}"));
    json_arr_push(content, item);
    json_obj_set(result, "content", content);
    if (js && json_parse_cstr(js, &sc) && sc && sc->type == JSON_OBJ)
        json_obj_set(result, "structuredContent", sc);
    else {
        json_free(sc);
        json_obj_set(result, "structuredContent", json_new_obj());
    }
    json_obj_set(result, "isError", json_new_bool(is_error ? 1 : 0));
    send_result(id, result);
}

static void tool_context(json_value *id, json_value *args)
{
    const char *source;
    json_value *flags;
    myc_request req;
    myc_result res;
    char hash[65];
    char *pkg;
    int budget = 4096;
    const char *finding_id = NULL;
    json_value *bv;

    if (!args) {
        send_error(id, -32602, "Invalid params: arguments wajib");
        return;
    }
    source = json_get_str(args, "source");
    if (!source) {
        send_error(id, -32602, "Invalid params: 'source' wajib");
        return;
    }
    finding_id = json_get_str(args, "finding_id");
    bv = json_get(args, "budget");
    if (bv) {
        if (bv->type != JSON_NUM || bv->num < 4096 || bv->num > 16384) {
            send_error(id, -32602,
                       "Invalid params: 'budget' harus number 4096..16384");
            return;
        }
        budget = (int)bv->num;
    }
    flags = json_get(args, "flags");
    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = source;
    req.input.len = strlen(source);
    req.run_lint = 1;
    req.checked_header_dir = g_exe_dir;
    if (flags) {
        char ferr[160];
        if (mcp_apply_flags(flags, &req, ferr, sizeof(ferr)) != 0) {
            send_error(id, -32602, ferr);
            return;
        }
    }
    myc_result_init(&res);
    myc_run(&req, &res);
    memset(hash, 0, sizeof(hash));
    pkg = myc_context_build(&res, source, strlen(source), &req, NULL,
                            finding_id, budget, hash);
    {
        json_value *result = json_new_obj();
        json_value *content = json_new_arr();
        json_value *item = json_new_obj();
        json_value *sc = json_new_obj();
        json_obj_set(item, "type", json_new_str("text"));
        json_obj_set(item, "text", json_new_str(pkg ? pkg : ""));
        json_arr_push(content, item);
        json_obj_set(result, "content", content);
        json_obj_set(sc, "context_sha256", json_new_str(hash));
        json_obj_set(sc, "budget", json_new_num(budget));
        json_obj_set(result, "structuredContent", sc);
        json_obj_set(result, "isError", json_new_bool(
            res.verdict == MC_ERROR || res.verdict == MC_TIMEOUT ? 1 : 0));
        send_result(id, result);
    }
    myc_free(pkg);
    myc_result_free(&res);
}

static void tool_next(json_value *id, json_value *args)
{
    const char *source;
    json_value *flags;
    myc_request req;
    myc_result res;
    myc_frontier_set fs;
    myc_experiment_set exps;
    myc_eig_set eig;
    myc_eig_input in;
    char *js;
    json_value *bv;
    int budget_ms = 5000;

    if (!args) {
        send_error(id, -32602, "Invalid params: arguments wajib");
        return;
    }
    source = json_get_str(args, "source");
    if (!source) {
        send_error(id, -32602, "Invalid params: 'source' wajib");
        return;
    }
    bv = json_get(args, "budget_ms");
    if (bv) {
        if (bv->type != JSON_NUM || bv->num < 0) {
            send_error(id, -32602,
                       "Invalid params: 'budget_ms' harus number >= 0");
            return;
        }
        budget_ms = (int)bv->num;
    }
    flags = json_get(args, "flags");
    myc_request_init(&req);
    req.input.kind = MYC_SOURCE_MEMORY;
    req.input.data = source;
    req.input.len = strlen(source);
    req.run_lint = 1;
    req.checked_header_dir = g_exe_dir;
    if (flags) {
        char ferr[160];
        if (mcp_apply_flags(flags, &req, ferr, sizeof(ferr)) != 0) {
            send_error(id, -32602, ferr);
            return;
        }
    }
    myc_result_init(&res);
    myc_run(&req, &res);
    memset(&fs, 0, sizeof(fs));
    memset(&exps, 0, sizeof(exps));
    memset(&eig, 0, sizeof(eig));
    memset(&in, 0, sizeof(in));
    myc_frontier_build(&res, &fs);
    myc_observation_to_experiment(&res, &exps);
    in.source_changed = 1;
    in.budget_time_ms = budget_ms;
    myc_eig_plan(&fs, &exps, &in, &eig);
    js = myc_eig_json(&eig);
    mcp_send_json_text(id, js, 0);
    myc_free(js);
    myc_eig_free(&eig);
    myc_experiment_free(&exps);
    myc_frontier_free(&fs);
    myc_result_free(&res);
}

static void tool_compare_candidates(json_value *id, json_value *args)
{
    const char *base;
    json_value *cands;
    const char *paths[MYC_MAX_CANDIDATES];
    int n = 0;
    size_t i;
    myc_candidate_set cs;
    char *js;

    if (!args) {
        send_error(id, -32602, "Invalid params: arguments wajib");
        return;
    }
    base = json_get_str(args, "baseline_path");
    if (!base) {
        send_error(id, -32602, "Invalid params: 'baseline_path' wajib");
        return;
    }
    cands = json_get(args, "candidate_paths");
    if (!cands || cands->type != JSON_ARR || cands->len < 1) {
        send_error(id, -32602,
                   "Invalid params: 'candidate_paths' wajib array string");
        return;
    }
    if (cands->len > MYC_MAX_CANDIDATES - 1) {
        send_error(id, -32602,
                   "Invalid params: terlalu banyak kandidat (maks 7)");
        return;
    }
    for (i = 0; i < cands->len; i++) {
        if (!cands->items[i] || cands->items[i]->type != JSON_STR ||
            !cands->items[i]->str) {
            send_error(id, -32602,
                       "Invalid params: 'candidate_paths' harus array string");
            return;
        }
        paths[n++] = cands->items[i]->str;
    }
    memset(&cs, 0, sizeof(cs));
    myc_candidate_tournament(base, paths, n, g_exe_dir, &cs);
    js = myc_candidate_json(&cs);
    mcp_send_json_text(id, js, 0);
    myc_free(js);
    myc_candidate_free(&cs);
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
        "Verify C source with myc. source (string, required). "
        "flags (array of strings, optional): --run --analyze --checked "
        "--driver --strict --no-lint --require-complete. "
        "Result: structuredContent myc.result.v1. isError=true only for "
        "tool/protocol failure, not for compile/runtime findings."));
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
            "Flag opsional: --run --prove --checked --filc --driver --analyze --strict --no-lint --quorum --metamorphic --negative --require-complete"));
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

    /* repair */
    t = json_new_obj();
    json_obj_set(t, "name", json_new_str("repair"));
    json_obj_set(t, "description", json_new_str(
        "Kembalikan patch minimal untuk finding (compile gcc ATAU runtime "
        "sanitizer). source: kode C (string, wajib). "
        "finding_code: opsional, contoh gcc-use-after-free, "
        "gcc-null-dereference, gcc-array-bounds, gcc-stringop-overflow. "
        "Jika tidak diisi, repair menggunakan diagnostic pertama dari check. "
        "run: opsional (0/1, default 0) -- jalankan gate runtime sehingga "
        "RUNTIME_VIOLATION + sanitizer_location terisi; repair lalu "
        "menghasilkan patch template deterministik (strcpy/strcat->snprintf "
        "ber-batas, memset/memcpy->clamp n, UAF->NULL-kan setelah free), "
        "menerapkannya ke source, dan me-re-run -> new_verdict_after_patch "
        "(bukti, bukan klaim). "
        "patched_source: opsional, kode baru setelah patch diterapkan -- "
        "bila verdict berubah jadi OK, myc replay corpus regression dan "
        "melampirkan regression_replay (IDE-4)."));
    {
        json_value *schema = json_new_obj();
        json_value *props = json_new_obj();
        json_value *p;

        json_obj_set(schema, "type", json_new_str("object"));

        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(p, "description", json_new_str("Kode sumber C yang akan diperbaiki (wajib)."));
        json_obj_set(props, "source", p);

        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(p, "description", json_new_str(
            "Kode finding (opsional). Contoh: gcc-use-after-free, "
            "gcc-null-dereference, gcc-array-bounds, gcc-stringop-overflow. "
            "Jika kosong, repair menggunakan diagnostic pertama."));
        json_obj_set(props, "finding_code", p);

        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("number"));
        json_obj_set(p, "description", json_new_str(
            "0/1 (default 0). Bila 1, repair menjalankan gate runtime "
            "sehingga RUNTIME_VIOLATION terdeteksi dan patch template "
            "runtime (IDE-2) dihasilkan + diverifikasi re-run."));
        json_obj_set(props, "run", p);

        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(p, "description", json_new_str(
            "Kode baru setelah patch diterapkan (opsional). Bila verdict "
            "berubah jadi OK, myc me-replay corpus regression terhadap "
            "kode ini dan melampirkan regression_replay (IDE-4)."));
        json_obj_set(props, "patched_source", p);

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

    /* agent_check */
    t = json_new_obj();
    json_obj_set(t, "name", json_new_str("agent_check"));
    json_obj_set(t, "description", json_new_str(
        "Jalankan pipeline myc pada source dan kembalikan hasil dalam "
        "format protokol agent (myc.agent.v2): finding_id, primary action, "
        "witness, next_check. Untuk konsumsi LLM agent. "
        "source: kode C (string, wajib). "
        "flags: array string opsional dari [--run --prove --checked --filc "
        "--driver --analyze --strict --no-lint --quorum --metamorphic "
        "--negative --require-complete] (sama seperti tool check; wajib "
        "array string). "
        "max_iter: number opsional 1..8 (default 3, IDE-3/qwen-review): "
        "bounded repair loop -- check -> repair(template) -> apply patch "
        "di memori -> check lagi -> bandingkan verdict, ulangi maks "
        "max_iter. Tiap iterasi tercatat receipt chain di ledger; hasil "
        "memuat repair_loop (steps, converged, iterations) + "
        "preservation_obligations. Template tidak yakin = berhenti jujur "
        "(why, tanpa menebak). "
        "pack_dir: direktori pack proyek lokal myc.prompt.md + myc.spec.json "
        "(opsional; default cwd server, Fase 7 MYC-AUDIT-039). no_pack: "
        "boolean opsional, true = nonaktifkan pack. Pack NON-blocking: "
        "verdict tidak berubah; structuredContent memuat pack_present."));
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
            "Flag opsional: --run --prove --checked --filc --driver "
            "--analyze --strict --no-lint --quorum --metamorphic "
            "--negative --require-complete (wajib array string)."));
        json_obj_set(props, "flags", p);
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("number"));
        json_obj_set(p, "description", json_new_str(
            "Bounded repair loop iterations 1..8 (default 3). "
            "check -> repair -> apply -> check, maks max_iter. "
            "Timeout additive: tiap iterasi myc_pipeline memakai "
            "timeout_ms penuh (default 30000 ms); bukan timeout "
            "bersama untuk seluruh panggilan."));
        json_obj_set(props, "max_iter", p);
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(p, "description", json_new_str(
            "Direktori pack proyek lokal (opsional; default cwd server). "
            "Spec.json ADA tapi invalid = error tool -32602."));
        json_obj_set(props, "pack_dir", p);
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("boolean"));
        json_obj_set(p, "description", json_new_str(
            "Nonaktifkan pack (opsional; perilaku = pack absen)."));
        json_obj_set(props, "no_pack", p);
        json_obj_set(schema, "properties", props);
        {
            json_value *req = json_new_arr();
            json_arr_push(req, json_new_str("source"));
            json_obj_set(schema, "required", req);
        }
        json_obj_set(t, "inputSchema", schema);
    }
    json_arr_push(tools, t);

    /* verify (myc.lite.v1) */
    t = json_new_obj();
    json_obj_set(t, "name", json_new_str("verify"));
    json_obj_set(t, "description", json_new_str(
        "Lite check for coding agents (myc.lite.v1). Default recipe is "
        "--scenario auto. Returns one action: STOP_COMPILE_CLEAN, FIX_ONE, "
        "ESCALATE_RUNTIME, ESCALATE_CONTRACT, or GIVE_UP_NO_TEMPLATE. "
        "source required. flags optional array; omit to use scenario auto. "
        "STOP_COMPILE_CLEAN is compile_clean, not memory-safe."));
    {
        json_value *schema = json_new_obj();
        json_value *props = json_new_obj();
        json_value *p;
        json_value *items;
        json_obj_set(schema, "type", json_new_str("object"));
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(p, "description", json_new_str("Kode sumber C (wajib)."));
        json_obj_set(props, "source", p);
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("array"));
        items = json_new_obj();
        json_obj_set(items, "type", json_new_str("string"));
        json_obj_set(p, "items", items);
        json_obj_set(p, "description", json_new_str(
            "Flag opsional. Kosong/absen = --scenario auto."));
        json_obj_set(props, "flags", p);
        json_obj_set(schema, "properties", props);
        {
            json_value *req = json_new_arr();
            json_arr_push(req, json_new_str("source"));
            json_obj_set(schema, "required", req);
        }
        json_obj_set(t, "inputSchema", schema);
    }
    json_arr_push(tools, t);

    /* context */
    t = json_new_obj();
    json_obj_set(t, "name", json_new_str("context"));
    json_obj_set(t, "description", json_new_str(
        "Minimal context pack for one finding (myc context --budget 4K). "
        "source required. flags optional. budget number 4096..16384. "
        "Does not change verdict."));
    {
        json_value *schema = json_new_obj();
        json_value *props = json_new_obj();
        json_value *p;
        json_obj_set(schema, "type", json_new_str("object"));
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(props, "source", p);
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("array"));
        json_obj_set(props, "flags", p);
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(props, "finding_id", p);
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("number"));
        json_obj_set(props, "budget", p);
        json_obj_set(schema, "properties", props);
        {
            json_value *req = json_new_arr();
            json_arr_push(req, json_new_str("source"));
            json_obj_set(schema, "required", req);
        }
        json_obj_set(t, "inputSchema", schema);
    }
    json_arr_push(tools, t);

    /* next (EIG, no apply) */
    t = json_new_obj();
    json_obj_set(t, "name", json_new_str("next"));
    json_obj_set(t, "description", json_new_str(
        "EIG recommendations only (does not run extra gates). "
        "source required. budget_ms optional (default 5000). "
        "Use --eig-apply on check to execute at most one."));
    {
        json_value *schema = json_new_obj();
        json_value *props = json_new_obj();
        json_value *p;
        json_obj_set(schema, "type", json_new_str("object"));
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(props, "source", p);
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("array"));
        json_obj_set(props, "flags", p);
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("number"));
        json_obj_set(props, "budget_ms", p);
        json_obj_set(schema, "properties", props);
        {
            json_value *req = json_new_arr();
            json_arr_push(req, json_new_str("source"));
            json_obj_set(schema, "required", req);
        }
        json_obj_set(t, "inputSchema", schema);
    }
    json_arr_push(tools, t);

    /* compare_candidates */
    t = json_new_obj();
    json_obj_set(t, "name", json_new_str("compare_candidates"));
    json_obj_set(t, "description", json_new_str(
        "Pareto frontier of patch candidates. myc does not pick a winner; "
        "the harness chooses. baseline_path + candidate_paths required."));
    {
        json_value *schema = json_new_obj();
        json_value *props = json_new_obj();
        json_value *p;
        json_value *items;
        json_obj_set(schema, "type", json_new_str("object"));
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("string"));
        json_obj_set(props, "baseline_path", p);
        p = json_new_obj();
        json_obj_set(p, "type", json_new_str("array"));
        items = json_new_obj();
        json_obj_set(items, "type", json_new_str("string"));
        json_obj_set(p, "items", items);
        json_obj_set(props, "candidate_paths", p);
        json_obj_set(schema, "properties", props);
        {
            json_value *req = json_new_arr();
            json_arr_push(req, json_new_str("baseline_path"));
            json_arr_push(req, json_new_str("candidate_paths"));
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
    else if (strcmp(name, "repair") == 0)
        tool_repair(id, args);
    else if (strcmp(name, "version") == 0)
        tool_version(id);
    else if (strcmp(name, "policy") == 0)
        tool_policy(id);
    else if (strcmp(name, "contracts") == 0)
        tool_contracts(id, args);
    else if (strcmp(name, "lint") == 0)
        tool_lint(id, args);
    else if (strcmp(name, "agent_check") == 0)
        tool_agent_check(id, args);
    else if (strcmp(name, "verify") == 0)
        tool_verify(id, args);
    else if (strcmp(name, "context") == 0)
        tool_context(id, args);
    else if (strcmp(name, "next") == 0)
        tool_next(id, args);
    else if (strcmp(name, "compare_candidates") == 0)
        tool_compare_candidates(id, args);
    else
        send_error(id, -32602, "Unknown tool");
}

static void handle_initialize(json_value *id, json_value *params)
{
    json_value *result = json_new_obj();
    json_value *caps = json_new_obj();
    json_value *tcaps = json_new_obj();
    json_value *info = json_new_obj();
    (void)params;

    json_obj_set(tcaps, "listChanged", json_new_bool(0));
    json_obj_set(caps, "tools", tcaps);
    json_obj_set(info, "name", json_new_str("myc"));
    json_obj_set(info, "version", json_new_str(MCP_VERSION));
    /* Negosiasi STRICT (MYC-AUDIT-016): server mengumumkan versi protokol
     * yang didukungnya sendiri, bukan meng-echo permintaan klien. */
    json_obj_set(result, "protocolVersion", json_new_str(MCP_PROTOCOL));
    json_obj_set(result, "capabilities", caps);
    json_obj_set(result, "serverInfo", info);
    send_result(id, result);
}

static void handle_message(json_value *msg)
{
    json_value *m = NULL;
    json_value *id = NULL;
    json_value *params = NULL;
    json_value *jrpc = NULL;
    const char *method = NULL;

    if (!msg || msg->type != JSON_OBJ) {
        send_error(NULL, -32600, "Invalid Request");
        return;
    }
    /* JSON-RPC 2.0 ketat (MYC-AUDIT-016): "jsonrpc" wajib == "2.0". */
    jrpc = json_get(msg, "jsonrpc");
    if (!jrpc || jrpc->type != JSON_STR || strcmp(jrpc->str, "2.0") != 0) {
        send_error(NULL, -32600, "Invalid Request: jsonrpc harus \"2.0\"");
        return;
    }
    m = json_get(msg, "method");
    if (!m || m->type != JSON_STR) {
        send_error(NULL, -32600, "Invalid Request: method wajib string");
        return;
    }
    method = m->str;
    id = json_get(msg, "id");
    /* Typed ID (JSON-RPC 2.0): hanya string/angka/null yang sah. */
    if (id && id->type != JSON_STR && id->type != JSON_NUM &&
        id->type != JSON_NULL) {
        send_error(NULL, -32600,
                   "Invalid Request: id harus string/angka/null");
        return;
    }
    /* Semantik notification (JSON-RPC 2.0): pesan tanpa "id" adalah
     * notification -- diproses TANPA balasan apa pun (termasuk pesan
     * MCP ber-prefiks "notifications/" yang tidak punya aksi di sini). */
    if (!id)
        return;
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
        myc_free(line);
    }

    myc_free(g_exe_dir);
    return 0;
}
