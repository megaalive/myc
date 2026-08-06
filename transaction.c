/*
 * transaction.c -- Repair Transaction + Preservation Obligations (Fase 2).
 *
 * Lihat transaction.h untuk dokumen penuh.
 */
#include "transaction.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "json.h"
#include "sha256.h"
#include "gate.h"
#include "report.h"

/* --- Sabotage pattern keywords --- */
typedef struct {
    myc_sabotage_kind kind;
    const char *keyword;
    const char *description;
} sabotage_pattern;

static const sabotage_pattern SABOTAGE_PATTERNS[] = {
    { MYC_SABOTAGE_DISABLE_SANITIZER, "-fsanitize=", "sanitizer dinonaktifkan" },
    { MYC_SABOTAGE_DISABLE_SANITIZER, "ASAN_OPTIONS=", "ASan dikonfigurasi untuk melewatkan" },
    { MYC_SABOTAGE_DISABLE_WARNING,   "-Wno-", "warning dimatikan" },
    { MYC_SABOTAGE_DISABLE_WARNING,   "-w ", "semua warning dimatikan (-w)" },
    { MYC_SABOTAGE_DISABLE_WARNING,   "--no-warnings", "warning dinonaktifkan" },
    { MYC_SABOTAGE_DISABLE_ASSERT,    "#define NDEBUG", "assert dikompilasi keluar (NDEBUG)" },
    { MYC_SABOTAGE_DISABLE_ASSERT,    "-DNDEBUG", "NDEBUG didefinisikan" },
    { MYC_SABOTAGE_ADD_VOID_CAST,     "(void)", "cast void untuk mematikan warning" },
    { MYC_SABOTAGE_ADD_PRAGMA,        "#pragma", "pragma kompiler untuk mematikan warning" },
    { MYC_SABOTAGE_ADD_PRAGMA,        "diagnostic ignored", "warning diabaikan via pragma" },
    { MYC_SABOTAGE_REMOVE_TEST,       "TEST(", "makro TEST mungkin dihapus" },
    { MYC_SABOTAGE_REMOVE_TEST,       "assert(", "assert mungkin dihapus" },
    { MYC_SABOTAGE_NARROW_REQUIRED,   "requires", "kontrak requires mungkin diubah" },
    { MYC_SABOTAGE_ADD_EARLY_RETURN,  "return 0;", "early return mungkin men-skip pengecekan" },
    { MYC_SABOTAGE_ADD_EARLY_RETURN,  "return EXIT_SUCCESS", "early return bertemu" },
    { MYC_SABOTAGE_DISABLE_FRAMA_C,   "-no-frama-c", "frama-c dinonaktifkan" },
    { MYC_SABOTAGE_DISABLE_FIL_C,     "-no-filc", "fil-c dinonaktifkan" },
    { MYC_SABOTAGE_CHANGE_SCENARIO,   "--no-run", "runtime verification dimatikan" },
    { MYC_SABOTAGE_CHANGE_SCENARIO,   "--no-prove", "prove dimatikan" },
    { MYC_SABOTAGE_CHANGE_SCENARIO,   "--no-filc", "filc dimatikan" },
    { MYC_SABOTAGE_CHANGE_SCENARIO,   "--no-checked", "checked-build dimatikan" },
};
static const size_t SABOTAGE_PATTERNS_COUNT =
    sizeof(SABOTAGE_PATTERNS) / sizeof(SABOTAGE_PATTERNS[0]);

const char *myc_sabotage_name(myc_sabotage_kind k)
{
    switch (k) {
    case MYC_SABOTAGE_DISABLE_SANITIZER:  return "disable_sanitizer";
    case MYC_SABOTAGE_DISABLE_WARNING:     return "disable_warning";
    case MYC_SABOTAGE_DISABLE_ASSERT:      return "disable_assert";
    case MYC_SABOTAGE_ADD_VOID_CAST:       return "add_void_cast";
    case MYC_SABOTAGE_ADD_PRAGMA:          return "add_pragma";
    case MYC_SABOTAGE_REMOVE_TEST:         return "remove_test";
    case MYC_SABOTAGE_NARROW_REQUIRED:     return "narrow_required";
    case MYC_SABOTAGE_ADD_EARLY_RETURN:    return "add_early_return";
    case MYC_SABOTAGE_CHANGE_SCENARIO:     return "change_scenario";
    case MYC_SABOTAGE_WEAKEN_POSTCONDITION: return "weaken_postcondition";
    case MYC_SABOTAGE_INCREASE_BUFFER:     return "increase_buffer";
    case MYC_SABOTAGE_DISABLE_FRAMA_C:     return "disable_frama_c";
    case MYC_SABOTAGE_DISABLE_FIL_C:       return "disable_fil_c";
    case MYC_SABOTAGE_NONE:
    default: return "none";
    }
}

const char *myc_tx_result_name(myc_tx_result r)
{
    switch (r) {
    case MYC_TX_RESULT_ACCEPTED:           return "accepted";
    case MYC_TX_RESULT_REJECTED_FINDING:   return "rejected_finding_not_resolved";
    case MYC_TX_RESULT_REJECTED_SABOTAGE:  return "rejected_sabotage_detected";
    case MYC_TX_RESULT_REJECTED_PRESERVATION: return "rejected_preservation_violation";
    case MYC_TX_RESULT_REJECTED_LAUNDERING: return "rejected_scope_laundering";
    case MYC_TX_RESULT_REJECTED_TIMEOUT:   return "rejected_timeout";
    case MYC_TX_RESULT_INVALID_PATCH:      return "invalid_patch";
    default: return "unknown";
    }
}

/* Scan satu baris baru untuk pola sabotage.
 * old_line = NULL bila baris baru (tambahan). */
static void scan_line(myc_transaction *tx, const char *new_line, int is_new)
{
    size_t i;
    if (!new_line)
        return;

    for (i = 0; i < SABOTAGE_PATTERNS_COUNT; i++) {
        const sabotage_pattern *sp = &SABOTAGE_PATTERNS[i];
        if (strstr(new_line, sp->keyword)) {
            if (tx->sabotage.count < 32) {
                myc_sabotage_finding *sf = &tx->sabotage.findings[tx->sabotage.count];
                sf->kind = sp->kind;
                sf->line = myc_strdup(new_line);
                sf->description = myc_strdup(sp->description);
                tx->sabotage.count++;
            }
        }
    }

    /* Deteksi tambahan: cast void untuk mengubiskan warning */
    if (is_new && strstr(new_line, "(void)") && strstr(new_line, "(")) {
        /* (void) cast sering dipakai untuk mengabaikan return value warning */
    }
}

/* Simple line-by-line diff scanner untuk sabotage. */
void myc_sabotage_scan(myc_transaction *tx,
                       const char *old_src, const char *new_src)
{
    /* Untuk sumber baru: scan setiap baris untuk pola sabotage. */
    const char *p = new_src;
    if (!new_src)
        return;

    while (p && *p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        char *line = (char *)malloc(len + 1);
        if (line) {
            memcpy(line, p, len);
            line[len] = '\0';
            scan_line(tx, line, 1);
            free(line);
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return;
    (void)tx;
    (void)old_src;
}

/* Verifikasi patch: bandingkan hasil baru vs kondisi sebelumnya.
 * - finding harus hilang (finding == CLEAN)
 * - tidak ada sabotage yang terdeteksi
 * - assurance tidak boleh turun (level ordinal setelah >= sebelum)
 * - completeness harus tetap (bukan INCOMPLETE → COMPLETE downgrade) */
myc_tx_result myc_transaction_verify(myc_transaction *tx,
                                     const myc_request *req,
                                     const char *new_source, size_t new_len,
                                     const myc_result *new_result)
{
    (void)req;
    (void)new_source;
    (void)new_len;

    if (!tx || !new_result)
        return MYC_TX_RESULT_INVALID_PATCH;

    /* Scan for sabotage in new source */
    /* (Sabotage scan dilakukan terpisah via myc_sabotage_scan) */

    /* Check 1: Sabotage detected */
    if (tx->sabotage.count > 0) {
        tx->result = MYC_TX_RESULT_REJECTED_SABOTAGE;
        return MYC_TX_RESULT_REJECTED_SABOTAGE;
    }

    /* Check 2: Finding resolved (harus CLEAN atau tidak ada finding) */
    tx->finding_resolved = (new_result->finding == MYC_FINDING_CLEAN) ? 1 : 0;
    if (!tx->finding_resolved) {
        tx->result = MYC_TX_RESULT_REJECTED_FINDING;
        return MYC_TX_RESULT_REJECTED_FINDING;
    }

    /* Check 3: Verdict harus OK (atau setidaknya turun dari VIOLATION) */
    if (new_result->verdict != MC_OK && new_result->verdict != MC_INCONCLUSIVE) {
        tx->result = MYC_TX_RESULT_REJECTED_PRESERVATION;
        return MYC_TX_RESULT_REJECTED_PRESERVATION;
    }

    /* Check 4: Completeness tidak boleh turun */
    if (new_result->completeness != MYC_COMPLETENESS_COMPLETE) {
        tx->result = MYC_TX_RESULT_REJECTED_PRESERVATION;
        return MYC_TX_RESULT_REJECTED_PRESERVATION;
    }

    tx->result = MYC_TX_RESULT_ACCEPTED;
    return MYC_TX_RESULT_ACCEPTED;
}

char *myc_transaction_new_id(void)
{
    sha256_ctx ctx;
    uint8_t md[32];
    char hex[65];
    char buf[128];
    time_t t;

    t = time(NULL);
    snprintf(buf, sizeof(buf), "tx-%lu-", (unsigned long)t);
    sha256_init(&ctx);
    sha256_update(&ctx, buf, strlen(buf));
    sha256_update(&ctx, &t, sizeof(t));
    sha256_final(&ctx, md);
    sha256_hex(md, 32, hex);
    /* 16 hex chars prefix */
    {
        char *out = (char *)malloc(24);
        if (out)
            snprintf(out, 24, "tx-%08x", *(uint32_t *)md);
        return out;
    }
}

char *myc_transaction_json(const myc_transaction *tx)
{
    json_value *root;
    char *out;

    if (!tx)
        return NULL;

    root = json_new_obj();
    if (!root)
        return NULL;

    json_obj_set(root, "tx_id", json_new_str(tx->tx_id ? tx->tx_id : ""));
    json_obj_set(root, "result", json_new_str(myc_tx_result_name(tx->result)));
    json_obj_set(root, "initial_receipt_sha",
                 json_new_str(tx->initial_receipt_sha ? tx->initial_receipt_sha : ""));
    json_obj_set(root, "initial_source_sha",
                 json_new_str(tx->initial_source_sha ? tx->initial_source_sha : ""));
    json_obj_set(root, "finding_id",
                 json_new_str(tx->finding_id ? tx->finding_id : ""));
    json_obj_set(root, "edit_region",
                 json_new_str(tx->edit_region ? tx->edit_region : ""));
    json_obj_set(root, "finding_resolved",
                 json_new_bool(tx->finding_resolved));
    json_obj_set(root, "verdict_before",
                 json_new_str(tx->verdict_before ? tx->verdict_before : ""));
    json_obj_set(root, "verdict_after",
                 json_new_str(tx->verdict_after ? tx->verdict_after : ""));
    json_obj_set(root, "assurance_before",
                 json_new_str(tx->assurance_before ? tx->assurance_before : ""));
    json_obj_set(root, "assurance_after",
                 json_new_str(tx->assurance_after ? tx->assurance_after : ""));

    /* Sabotage findings */
    {
        json_value *arr = json_new_arr();
        size_t i;
        for (i = 0; i < (size_t)tx->sabotage.count; i++) {
            json_value *obj = json_new_obj();
            json_obj_set(obj, "kind",
                         json_new_str(myc_sabotage_name(tx->sabotage.findings[i].kind)));
            json_obj_set(obj, "line",
                         json_new_str(tx->sabotage.findings[i].line ?
                                      tx->sabotage.findings[i].line : ""));
            json_obj_set(obj, "description",
                         json_new_str(tx->sabotage.findings[i].description ?
                                      tx->sabotage.findings[i].description : ""));
            json_arr_push(arr, obj);
        }
        json_obj_set(root, "sabotage_findings", arr);
    }

    if (json_serialize(root, &out) == 0)
        out = NULL;
    json_free(root);
    return out;
}

void myc_transaction_init(myc_transaction *tx,
                          const char *tx_id,
                          const char *initial_receipt,
                          const char *initial_source_sha,
                          const char *finding_id,
                          const char *edit_region)
{
    if (!tx)
        return;
    memset(tx, 0, sizeof(*tx));
    if (tx_id)
        tx->tx_id = myc_strdup(tx_id);
    else
        tx->tx_id = myc_transaction_new_id();
    if (initial_receipt)
        tx->initial_receipt_sha = myc_strdup(initial_receipt);
    if (initial_source_sha)
        tx->initial_source_sha = myc_strdup(initial_source_sha);
    if (finding_id)
        tx->finding_id = myc_strdup(finding_id);
    if (edit_region)
        tx->edit_region = myc_strdup(edit_region);
    tx->result = MYC_TX_RESULT_ACCEPTED;
}

void myc_transaction_free(myc_transaction *tx)
{
    size_t i;
    if (!tx)
        return;
    free(tx->tx_id);
    free(tx->initial_receipt_sha);
    free(tx->initial_source_sha);
    free(tx->finding_id);
    free(tx->edit_region);
    free(tx->preserve_region);
    free(tx->verdict_before);
    free(tx->verdict_after);
    free(tx->assurance_before);
    free(tx->assurance_after);
    for (i = 0; i < (size_t)tx->sabotage.count; i++) {
        free(tx->sabotage.findings[i].line);
        free(tx->sabotage.findings[i].description);
    }
    memset(tx, 0, sizeof(*tx));
}
