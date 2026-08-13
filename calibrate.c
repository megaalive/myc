/*
 * calibrate.c -- Trust Calibration Ledger (Fase 7, SOL-21).
 *
 * Opt-in ledger untuk mencatat feedback user/harness terhadap rule heuristik.
 * Lihat calibrate.h untuk dokumentasi lengkap.
 */
#include "calibrate.h"
#include "json.h"
#include "persist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <direct.h>
#define calib_mkdir(p) _mkdir(p)
#else
#include <sys/stat.h>
#define calib_mkdir(p) mkdir(p, 0700)
#endif

static const char *OUTCOME_NAMES[MYC_CALIB_OUTCOME_COUNT] = {
    "accepted",
    "rejected",
    "confirmed_later",
    "missed",
    "useful_fix",
    "harmful_fix"
};

static const char *STATE_NAMES[] = {
    "UNKNOWN",
    "OK",
    "LOW",
    "DISABLED"
};

static int calib_id_ok(const char *id)
{
    const char *p;
    size_t n;
    if (!id || !*id)
        return 0;
    n = strlen(id);
    if (n > MYC_CALIB_ID_MAX)
        return 0;
    for (p = id; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

int myc_calib_id_valid(const char *id)
{
    return calib_id_ok(id);
}

int myc_calib_outcome_parse(const char *s, myc_calib_outcome *out)
{
    if (!s || !out)
        return -1;
    for (int i = 0; i < MYC_CALIB_OUTCOME_COUNT; i++) {
        if (strcmp(s, OUTCOME_NAMES[i]) == 0) {
            *out = (myc_calib_outcome)i;
            return 0;
        }
    }
    return -1;
}

static void calib_ensure_dir(void)
{
    calib_mkdir(MYC_CALIB_DIR);
}

static void calib_path(char *buf, size_t cap)
{
    snprintf(buf, cap, "%s/calibration.json", MYC_CALIB_DIR);
}

/* Load ledger dari disk. Return: 1 = ada, 0 = tak ada/rusak. */
static int calib_load(myc_calib_entry *entries, int *count)
{
    char path[256];
    FILE *f;
    long fsize;
    char *buf;
    json_value *root, *arr;
    int i, n = 0;

    memset(entries, 0, MYC_CALIB_MAX_ENTRIES * sizeof(myc_calib_entry));
    calib_path(path, sizeof(path));
    f = fopen(path, "rb");
    if (!f)
        return 0;
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > (long)(4u << 20)) {
        fclose(f);
        return 0;
    }
    buf = (char *)myc_malloc((size_t)fsize + 1);
    if (!buf) {
        fclose(f);
        return 0;
    }
    if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        myc_free(buf);
        fclose(f);
        return 0;
    }
    buf[fsize] = '\0';
    fclose(f);

    if (!json_parse_cstr(buf, &root) || !root) {
        myc_free(buf);
        return 0;
    }
    arr = json_get(root, "entries");
    if (arr && arr->type == JSON_ARR) {
        for (i = 0; i < (int)arr->len && n < MYC_CALIB_MAX_ENTRIES; i++) {
            json_value *e = arr->items[i];
            if (!e || e->type != JSON_OBJ)
                continue;
            const char *rule = json_get_str(e, "rule");
            if (!rule)
                continue;
            myc_calib_entry *ent = &entries[n];
            memset(ent, 0, sizeof(*ent));
            snprintf(ent->rule, sizeof(ent->rule), "%s", rule);
            for (int oc = 0; oc < MYC_CALIB_OUTCOME_COUNT; oc++) {
                json_value *v = json_get(e, OUTCOME_NAMES[oc]);
                if (v && v->type == JSON_NUM)
                    ent->counts[oc] = v->num;
            }
            const char *match = json_get_str(e, "match");
            if (match)
                snprintf(ent->match, sizeof(ent->match), "%s", match);
            n++;
        }
    }
    json_free(root);
    myc_free(buf);
    *count = n;
    return n > 0 ? 1 : 0;
}

/* Save ledger ke disk. NON-blocking: gagal = dilewati. */
static void calib_save(const myc_calib_entry *entries, int count)
{
    char path[256];
    json_value *root, *arr;
    char *js = NULL;
    int i;

    if (count <= 0)
        return;
    calib_ensure_dir();
    calib_path(path, sizeof(path));
    root = json_new_obj();
    if (!root)
        return;
    json_obj_set(root, "schema", json_new_str(MYC_CALIB_SCHEMA));
    arr = json_new_arr();
    if (!arr) {
        json_free(root);
        return;
    }
    for (i = 0; i < count; i++) {
        const myc_calib_entry *e = &entries[i];
        if (!e->rule[0])
            continue;
        json_value *ent = json_new_obj();
        if (!ent)
            continue;
        json_obj_set(ent, "rule", json_new_str(e->rule));
        for (int oc = 0; oc < MYC_CALIB_OUTCOME_COUNT; oc++) {
            json_obj_set(ent, OUTCOME_NAMES[oc], json_new_num(e->counts[oc]));
        }
        if (e->match[0]) {
            json_obj_set(ent, "match", json_new_str(e->match));
        }
        json_arr_push(arr, ent);
    }
    json_obj_set(root, "entries", arr);
    if (!json_serialize(root, &js)) {
        json_free(root);
        return;
    }
    /* PR-012 (MYC-AUDIT-044, P3-T03): tulis ATOMIK (temp+flush+fsync+
     * rename). Crash kapan pun -> calibration.json OLD valid ATAU NEW
     * valid, tidak pernah setengah. NON-blocking: gagal diabaikan. */
    (void)myc_persist_atomic_write_str(path, js);
    myc_free(js);
    json_free(root);
}

/* Find entry index by rule. -1 if not found. */
static int find_entry(const myc_calib_entry *entries, int count, const char *rule)
{
    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].rule, rule) == 0)
            return i;
    }
    return -1;
}

int myc_calib_mark(const char *rule, const char *outcome, const char *match)
{
    myc_calib_entry entries[MYC_CALIB_MAX_ENTRIES];
    int count = 0;
    myc_calib_outcome oc;

    if (!calib_id_ok(rule) || myc_calib_outcome_parse(outcome, &oc) != 0)
        return -2;

    calib_load(entries, &count);
    int idx = find_entry(entries, count, rule);
    if (idx == -1) {
        if (count >= MYC_CALIB_MAX_ENTRIES)
            return 0; /* silently ignore, NON-blocking */
        idx = count++;
        memset(&entries[idx], 0, sizeof(entries[idx]));
        snprintf(entries[idx].rule, sizeof(entries[idx].rule), "%s", rule);
    }
    entries[idx].counts[oc]++;
    if (match && *match) {
        snprintf(entries[idx].match, sizeof(entries[idx].match), "%s", match);
    }
    calib_save(entries, count);
    return 0;
}

int myc_calib_read_counts(const char *rule,
                          long long counts[MYC_CALIB_OUTCOME_COUNT],
                          int *found)
{
    myc_calib_entry entries[MYC_CALIB_MAX_ENTRIES];
    int count = 0;
    int idx;

    if (!calib_id_ok(rule) || !counts)
        return -2;
    if (found)
        *found = 0;
    memset(counts, 0, MYC_CALIB_OUTCOME_COUNT * sizeof(long long));

    if (!calib_load(entries, &count))
        return 0;
    idx = find_entry(entries, count, rule);
    if (idx == -1)
        return 0;
    memcpy(counts, entries[idx].counts,
           MYC_CALIB_OUTCOME_COUNT * sizeof(long long));
    if (found)
        *found = 1;
    return 0;
}

static const char *state_name(myc_calib_state s)
{
    if (s >= 0 && s < (int)(sizeof(STATE_NAMES)/sizeof(STATE_NAMES[0])))
        return STATE_NAMES[s];
    return "?";
}

myc_calib_state myc_calib_derive_state(const long long *counts)
{
    long long total = 0;
    for (int i = 0; i < MYC_CALIB_OUTCOME_COUNT; i++)
        total += counts[i];

    if (total < MYC_CALIB_MIN_FEEDBACK)
        return MYC_CALIB_STATE_UNKNOWN;

    long long score = 2 * counts[MYC_CALIB_ACCEPTED]
                      + counts[MYC_CALIB_CONFIRMED_LATER]
                      - 2 * counts[MYC_CALIB_REJECTED]
                      - counts[MYC_CALIB_HARMFUL_FIX];

    if (score > 0)
        return MYC_CALIB_STATE_OK;
    if (score <= -4)
        return MYC_CALIB_STATE_DISABLED;
    if (score <= -2)
        return MYC_CALIB_STATE_LOW;
    return MYC_CALIB_STATE_OK;
}

int myc_calib_show(const char *rule, char *buf, size_t cap)
{
    myc_calib_entry entries[MYC_CALIB_MAX_ENTRIES];
    int count = 0;

    if (!calib_id_ok(rule))
        return -2;

    if (!calib_load(entries, &count))
        return -1;

    int idx = find_entry(entries, count, rule);
    if (idx == -1)
        return -1;

    const myc_calib_entry *e = &entries[idx];

    size_t off = 0;
    off += snprintf(buf + off, cap - off, "rule      : %s\n", e->rule);
    off += snprintf(buf + off, cap - off, "state     : %s\n", state_name(myc_calib_derive_state(e->counts)));
    for (int i = 0; i < MYC_CALIB_OUTCOME_COUNT; i++) {
        off += snprintf(buf + off, cap - off, "  %-16s : %lld\n", OUTCOME_NAMES[i], e->counts[i]);
    }
    long long total = 0;
    for (int i = 0; i < MYC_CALIB_OUTCOME_COUNT; i++)
        total += e->counts[i];
    off += snprintf(buf + off, cap - off, "total     : %lld\n", total);
    if (e->match[0]) {
        off += snprintf(buf + off, cap - off, "match     : %s\n", e->match);
    }
    return 0;
}

int myc_calib_list(char *buf, size_t cap)
{
    myc_calib_entry entries[MYC_CALIB_MAX_ENTRIES];
    int count = 0;

    if (!calib_load(entries, &count)) {
        buf[0] = '\0';
        return 0;
    }

    size_t off = 0;
    off += snprintf(buf + off, cap - off, "calibration entries: %d\n", count);
    for (int i = 0; i < count && off < cap - 2; i++) {
        const myc_calib_entry *e = &entries[i];
        myc_calib_state st = myc_calib_derive_state(e->counts);
        long long total = 0;
        for (int k = 0; k < MYC_CALIB_OUTCOME_COUNT; k++)
            total += e->counts[k];
        off += snprintf(buf + off, cap - off, "  %-24s state=%-9s total=%-4lld",
                        e->rule, state_name(st), total);
        if (e->match[0]) {
            off += snprintf(buf + off, cap - off, " match=\"%s\"", e->match);
        }
        off += snprintf(buf + off, cap - off, "\n");
    }
    return 0;
}

int myc_calib_reset(const char *rule)
{
    myc_calib_entry entries[MYC_CALIB_MAX_ENTRIES];
    int count = 0;

    if (rule && !calib_id_ok(rule))
        return -2;

    calib_load(entries, &count);
    if (count == 0)
        return -1;

    if (rule) {
        int idx = find_entry(entries, count, rule);
        if (idx == -1)
            return -1;
        /* shift down */
        for (int i = idx; i < count - 1; i++)
            entries[i] = entries[i + 1];
        count--;
    } else {
        count = 0;
    }

    char path[256];
    calib_path(path, sizeof(path));
    if (count == 0) {
        remove(path);
    } else {
        calib_save(entries, count);
    }
    return 0;
}

/* Apply calibration ke result: cari diag yang match rule LOW/DISABLED.
 * Return jumlah anotasi yang dihasilkan (buf berisi teks anotasi). */
int myc_calib_apply(const myc_result *res, char *buf, size_t cap)
{
    myc_calib_entry entries[MYC_CALIB_MAX_ENTRIES];
    int count = 0;
    int annotated = 0;

    if (!res || !buf || cap == 0)
        return 0;

    buf[0] = '\0';
    if (!calib_load(entries, &count))
        return 0;

    for (int i = 0; i < res->diag_count; i++) {
        const myc_diagnostic *d = &res->diags[i];
        if (!d->message)
            continue;

        for (int j = 0; j < count; j++) {
            const myc_calib_entry *e = &entries[j];
            if (!e->match[0])
                continue;
            myc_calib_state st = myc_calib_derive_state(e->counts);
            if (st != MYC_CALIB_STATE_LOW && st != MYC_CALIB_STATE_DISABLED)
                continue;
            if (strstr(d->message, e->match)) {
                size_t off = strlen(buf);
                if (off + 128 < cap) {
                    off += snprintf(buf + off, cap - off,
                                    "[calibrated: %s] rule=%s match=\"%s\"\n",
                                    state_name(st), e->rule, e->match);
                    annotated++;
                }
            }
        }
    }
    return annotated;
}