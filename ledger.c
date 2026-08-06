/*
 * ledger.c -- Temporal Ledger (Fase 2, roadmap 7.2).
 *
 * Persistent append-only ledger di .myc/ledger.json.
 * Lihat ledger.h untuk dokumen penuh.
 */
#include "ledger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "json.h"
#include "sha256.h"
#include "gate.h"

#ifdef _WIN32
#include <direct.h>
#define myc_mkdir(path) _mkdir(path)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define myc_mkdir(path) mkdir(path, 0700)
#endif

/* String pool bergilir untuk timestamp (tidak perlu persisten). */
char *myc_ledger_timestamp(void)
{
    time_t now = time(NULL);
    struct tm *tm_info;
    char *buf;
#ifdef _WIN32
    struct tm tm_buf;
    localtime_s(&tm_buf, &now);
    tm_info = &tm_buf;
#else
    tm_info = localtime(&now);
#endif
    buf = (char *)malloc(32);
    if (buf)
        strftime(buf, 32, "%Y-%m-%dT%H:%M:%SZ", tm_info);
    return buf;
}

/* Bangun semantic anchor dari source: "<function_name>:<token_hash>:<line>.
 * Token hash: SHA256 dari source window di sekitar violation line. */
char *myc_ledger_build_anchor(const char *source, size_t source_len,
                              int line, int col, size_t window_chars)
{
    char buf[512];
    char *func = NULL;
    const char *p;
    char hex[65];
    sha256_ctx ctx;
    uint8_t md[32];
    int cur_line = 1;
    const char *anchor_start = source;
    const char *anchor_end = source + source_len;
    size_t hash_start;
    (void)col;
    (void)window_chars;

    if (!source || source_len == 0)
        return NULL;

    /* Temukan line_start dan line_end untuk violation line. */
    p = source;
    while (p < source + source_len && *p != '\0') {
        if (cur_line == line) {
            anchor_start = p;
            const char *nl = strchr(p, '\n');
            anchor_end = nl ? nl : source + source_len;
            break;
        }
        if (*p == '\n')
            cur_line++;
        p++;
    }

    /* Cari nama fungsi dengan backtracking ke kunci { sebelum line. */
    p = anchor_start;
    while (p > source) {
        p--;
        if (*p == '{') {
            const char *name_end = p;
            const char *name_start = p;
            /* mundur ke awal nama fungsi (sebelum ( atau spasi) */
            while (name_start > source && *name_start != '(' &&
                   *name_start != '\n' && *name_start != ';')
                name_start--;
            if (*name_start == '(') {
                name_start--;
                while (name_start > source && *name_start != '\n' &&
                       *name_start != ';' && *name_start != '{')
                    name_start--;
                name_start++;
            }
            if (name_end > name_start && name_end - name_start < 128) {
                size_t nl = (size_t)(name_end - name_start);
                char *t = (char *)malloc(nl + 1);
                if (t) {
                    memcpy(t, name_start, nl);
                    t[nl] = '\0';
                    /* trim trailing whitespace */
                    while (nl > 0 && (t[nl-1] == ' ' || t[nl-1] == '\t' ||
                                       t[nl-1] == '\n' || t[nl-1] == '\r'))
                        t[--nl] = '\0';
                    func = t;
                }
            }
            break;
        }
    }

    if (!func)
        func = myc_strdup("unknown");

    /* Hash source window around violation line */
    hash_start = (anchor_start >= source) ? (size_t)(anchor_start - source) : 0;
    if (hash_start > 128)
        hash_start -= 128;
    else
        hash_start = 0;
    {
        size_t extra = (size_t)(anchor_end - anchor_start);
        const char *ext_end = anchor_end;
        if (extra < 256 && (anchor_end + 256) <= (source + source_len))
            ext_end = anchor_end + 256;
        sha256_init(&ctx);
        sha256_update(&ctx, source + hash_start, (size_t)(ext_end - (source + hash_start)));
        sha256_final(&ctx, md);
        sha256_hex(md, 32, hex);

        snprintf(buf, sizeof(buf), "%s:%d:%s", func, line, hex);
    }

    free(func);
    return myc_strdup(buf);
}

/* Bangun scenario hash: H(flags + tool versions + intent_hash).
 * Hasil: substring hex pertama (16 karakter). */
char *myc_ledger_build_scenario_hash(const myc_request *req,
                                     const char *intent_hash)
{
    sha256_ctx ctx;
    uint8_t md[32];
    char hex[65];
    char buf[512];
    int n = 0;

    n += snprintf(buf + n, sizeof(buf) - n,
                  "strict=%d|analyzer=%d|run=%d|prove=%d|checked=%d|filc=%d|"
                  "driver=%d|metamorphic=%d|negative=%d|quorum=%d|"
                  "require_complete=%d",
                  req->strict, req->run_analyzer, req->run, req->prove,
                  req->checked, req->filc, req->driver,
                  req->metamorphic, req->negative, req->quorum,
                  req->require_complete);
    if (n >= (int)sizeof(buf))
        n = sizeof(buf) - 1;
    if (intent_hash)
        n += snprintf(buf + n, sizeof(buf) - n, "|%s", intent_hash);
    if (n >= (int)sizeof(buf))
        n = sizeof(buf) - 1;

    sha256_init(&ctx);
    sha256_update(&ctx, buf, (size_t)n);
    sha256_final(&ctx, md);
    sha256_hex(md, 32, hex);

    /* Truncate to 16 hex chars (8 bytes) for readability */
    {
        char *short_hex = (char *)malloc(17);
        if (short_hex) {
            memcpy(short_hex, hex, 16);
            short_hex[16] = '\0';
        }
        return short_hex;
    }
}

/* Periksa apakah direktori ada, buat jika belum */
static int ensure_dir(const char *path)
{
    myc_mkdir(path);
    return 1;
}

/* Baca ledger dari .myc/ledger.json */
int myc_ledger_read(myc_ledger *ledger)
{
    FILE *f;
    char *buf;
    long fsize;
    size_t nread;
    json_value *root;
    json_value *arr;
    size_t i;

    if (!ledger)
        return 0;
    memset(ledger, 0, sizeof(*ledger));
    ledger->parent_found = 0;

    f = fopen(MYC_LEDGER_FILE, "rb");
    if (!f)
        return 0;

    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0) {
        fclose(f);
        return 0;
    }
    buf = (char *)malloc((size_t)fsize + 1);
    if (!buf) {
        fclose(f);
        return 0;
    }
    nread = fread(buf, 1, (size_t)fsize, f);
    buf[nread] = '\0';
    fclose(f);

    if (!json_parse_cstr(buf, &root) || !root) {
        free(buf);
        return 0;
    }

    arr = json_get(root, "entries");
    if (arr && arr->type == JSON_ARR) {
        for (i = 0; i < arr->len && i < MYC_LEDGER_MAX_ENTRIES; i++) {
            json_value *e = arr->items[i];
            json_value *v;
            myc_ledger_entry *le = &ledger->entries[ledger->count];

            memset(le, 0, sizeof(*le));

            v = json_get(e, "source_sha256");
            if (v && v->type == JSON_STR)
                le->source_sha256 = myc_strdup(v->str);
            v = json_get(e, "anchor");
            if (v && v->type == JSON_STR)
                le->anchor = myc_strdup(v->str);
            v = json_get(e, "receipt_sha256");
            if (v && v->type == JSON_STR)
                le->receipt_sha256 = myc_strdup(v->str);
            v = json_get(e, "receipt_parent");
            if (v && v->type == JSON_STR)
                le->receipt_parent = myc_strdup(v->str);
            v = json_get(e, "scenario_hash");
            if (v && v->type == JSON_STR)
                le->scenario_hash = myc_strdup(v->str);
            v = json_get(e, "timestamp");
            if (v && v->type == JSON_STR)
                le->timestamp = myc_strdup(v->str);
            v = json_get(e, "source_anchor_line");
            if (v && v->type == JSON_STR)
                le->source_anchor_line = myc_strdup(v->str);
            v = json_get(e, "delta");
            if (v && v->type == JSON_STR) {
                if (strcmp(v->str, "fixed") == 0) le->delta = MYC_DELTA_FIXED;
                else if (strcmp(v->str, "new") == 0) le->delta = MYC_DELTA_NEW;
                else if (strcmp(v->str, "persistent") == 0) le->delta = MYC_DELTA_PERSISTENT;
                else if (strcmp(v->str, "churn") == 0) le->delta = MYC_DELTA_CHURN;
            }
            v = json_get(e, "gate_id");
            if (v && v->type == JSON_STR)
                le->gate_id = myc_strdup(v->str);
            v = json_get(e, "gate_status");
            if (v && v->type == JSON_STR)
                le->gate_status = myc_strdup(v->str);
            v = json_get(e, "verdict");
            if (v && v->type == JSON_STR)
                le->verdict = myc_strdup(v->str);
            v = json_get(e, "finding");
            if (v && v->type == JSON_STR)
                le->finding = myc_strdup(v->str);

            ledger->count++;
        }
    }

    json_free(root);
    free(buf);
    return ledger->count > 0 ? 1 : 0;
}

static const char *delta_name(myc_delta_kind d)
{
    switch (d) {
    case MYC_DELTA_FIXED:    return "fixed";
    case MYC_DELTA_NEW:      return "new";
    case MYC_DELTA_PERSISTENT: return "persistent";
    case MYC_DELTA_CHURN:    return "churn";
    default:                 return "unknown";
    }
}

/* Tulis ledger (rewrite penuh karena ukuran kecil < 256 entries).
 * Jika entry dengan source_sha sama sudah ada, replace; jika baru, append. */
int myc_ledger_write(const myc_ledger_entry *entry)
{
    myc_ledger ledger;
    json_value *root;
    json_value *arr;
    char *js;
    FILE *f;
    int i;
    int replaced = 0;

    if (!entry || !entry->source_sha256)
        return 0;

    ensure_dir(MYC_LEDGER_DIR);

    memset(&ledger, 0, sizeof(ledger));
    myc_ledger_read(&ledger);

    root = json_new_obj();
    if (!root) {
        myc_ledger_free(&ledger);
        return 0;
    }

    arr = json_new_arr();
    if (!arr) {
        json_free(root);
        myc_ledger_free(&ledger);
        return 0;
    }

    /* Salin entry yang ada, kecuali yang diganti oleh source_sha yang sama */
    for (i = 0; i < ledger.count; i++) {
        const myc_ledger_entry *le = &ledger.entries[i];
        if (le->source_sha256 &&
            strcmp(le->source_sha256, entry->source_sha256) == 0) {
            replaced = 1;
            continue;
        }
        {
            json_value *e = json_new_obj();
            json_obj_set(e, "source_sha256", json_new_str(le->source_sha256 ? le->source_sha256 : ""));
            json_obj_set(e, "anchor", json_new_str(le->anchor ? le->anchor : ""));
            json_obj_set(e, "receipt_sha256", json_new_str(le->receipt_sha256 ? le->receipt_sha256 : ""));
            json_obj_set(e, "receipt_parent", json_new_str(le->receipt_parent ? le->receipt_parent : ""));
            json_obj_set(e, "scenario_hash", json_new_str(le->scenario_hash ? le->scenario_hash : ""));
            json_obj_set(e, "timestamp", json_new_str(le->timestamp ? le->timestamp : ""));
            json_obj_set(e, "source_anchor_line", json_new_str(le->source_anchor_line ? le->source_anchor_line : ""));
            json_obj_set(e, "delta", json_new_str(delta_name(le->delta)));
            json_obj_set(e, "gate_id", json_new_str(le->gate_id ? le->gate_id : ""));
            json_obj_set(e, "gate_status", json_new_str(le->gate_status ? le->gate_status : ""));
            json_obj_set(e, "verdict", json_new_str(le->verdict ? le->verdict : ""));
            json_obj_set(e, "finding", json_new_str(le->finding ? le->finding : ""));
            json_arr_push(arr, e);
        }
    }

    /* Tambahkan entry baru (atau entry yang diganti) */
    {
        json_value *e = json_new_obj();
        json_obj_set(e, "source_sha256", json_new_str(entry->source_sha256));
        json_obj_set(e, "anchor", json_new_str(entry->anchor ? entry->anchor : ""));
        json_obj_set(e, "receipt_sha256", json_new_str(entry->receipt_sha256 ? entry->receipt_sha256 : ""));
        json_obj_set(e, "receipt_parent", json_new_str(entry->receipt_parent ? entry->receipt_parent : ""));
        json_obj_set(e, "scenario_hash", json_new_str(entry->scenario_hash ? entry->scenario_hash : ""));
        json_obj_set(e, "timestamp", json_new_str(entry->timestamp ? entry->timestamp : ""));
        json_obj_set(e, "source_anchor_line", json_new_str(entry->source_anchor_line ? entry->source_anchor_line : ""));
        json_obj_set(e, "delta", json_new_str(delta_name(entry->delta)));
        json_obj_set(e, "gate_id", json_new_str(entry->gate_id ? entry->gate_id : ""));
        json_obj_set(e, "gate_status", json_new_str(entry->gate_status ? entry->gate_status : ""));
        json_obj_set(e, "verdict", json_new_str(entry->verdict ? entry->verdict : ""));
        json_obj_set(e, "finding", json_new_str(entry->finding ? entry->finding : ""));
        json_arr_push(arr, e);
    }
    json_obj_set(root, "entries", arr);

    js = NULL;
    if (json_serialize(root, &js) == 0)
        js = NULL;
    json_free(root);
    myc_ledger_free(&ledger);

    if (!js)
        return 0;

    f = fopen(MYC_LEDGER_FILE, "w");
    if (!f) {
        free(js);
        return 0;
    }
    fprintf(f, "%s\n", js);
    fclose(f);
    free(js);

    (void)replaced;
    return 1;
}

/* Cari entry terakhir untuk source_sha yang diberikan */
const myc_ledger_entry *myc_ledger_find(const myc_ledger *ledger,
                                        const char *source_sha256)
{
    int i;
    if (!ledger || !source_sha256)
        return NULL;
    for (i = ledger->count - 1; i >= 0; i--) {
        if (ledger->entries[i].source_sha256 &&
            strcmp(ledger->entries[i].source_sha256, source_sha256) == 0)
            return &ledger->entries[i];
    }
    return NULL;
}

/* Hitung delta: bandingkan gate status string.
 * Simplifikasi: "completed_findings" → "completed_clean" = FIXED;
 * "completed_clean" → "completed_findings" = NEW;
 * sama = PERSISTENT; berbeda (non-trivial) = CHURN */
myc_delta_kind myc_ledger_compute_delta(const char *prev_status,
                                        const char *curr_status)
{
    if (!prev_status || !curr_status)
        return MYC_DELTA_CHURN;

    if (strcmp(prev_status, curr_status) == 0)
        return MYC_DELTA_PERSISTENT;

    if (strcmp(prev_status, "completed_findings") == 0 &&
        strcmp(curr_status, "completed_clean") == 0)
        return MYC_DELTA_FIXED;

    if (strcmp(prev_status, "completed_clean") == 0 &&
        strcmp(curr_status, "completed_findings") == 0)
        return MYC_DELTA_NEW;

    return MYC_DELTA_CHURN;
}

/* Bebaskan ledger entries */
void myc_ledger_free(myc_ledger *ledger)
{
    int i;
    if (!ledger)
        return;
    for (i = 0; i < ledger->count; i++) {
        myc_ledger_entry *le = &ledger->entries[i];
        free(le->source_sha256);
        free(le->anchor);
        free(le->receipt_sha256);
        free(le->receipt_parent);
        free(le->scenario_hash);
        free(le->timestamp);
        free(le->source_anchor_line);
        free(le->gate_id);
        free(le->gate_status);
        free(le->verdict);
        free(le->finding);
    }
    memset(ledger, 0, sizeof(*ledger));
}
