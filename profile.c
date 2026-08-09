/*
 * profile.c -- Model/Harness Error Fingerprint (Fase 7, SOL-20).
 *
 * Opt-in agregator statistik per model/harness. TIDAK menyimpan source:
 * file profil hanya berisi agregat deterministik dari myc_result. Baca
 * docs/audit-history.md (28) untuk desain & batas jujur.
 *
 * Layout:
 *   .myc/profiles/index.txt      -- satu id per baris (untuk `list`, tanpa
 *                                   enumerasi direktori portabel)
 *   .myc/profiles/<id>.json      -- agregat per id
 *
 * Semua fungsi NON-blocking: tidak pernah menurunkan verdict, tidak pernah
 * gagal check, tidak pernah error fatal. Gagal tulis diabaikan (pola
 * .myc/assumptions.json).
 */
#include "profile.h"
#include "json.h"
#include "gate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <direct.h>   /* _mkdir (Windows) */
#define prof_mkdir(p) _mkdir(p)
#else
#include <sys/stat.h>
#define prof_mkdir(p) mkdir(p, 0700)
#endif

#define PARENT_DIR        ".myc"
#define PROFILE_DIR       MYC_PROFILE_DIR
#define PROFILE_INDEX     ".myc/profiles/index.txt"
#define PROFILE_FILE_CAP  96

#define PROFILE_MAX_CLASSES   32

/* jumlah elemen myc_gate_status (=8) */
#define MYC_STATUS_N      8

/* --- identitas: satu profile, agregat schema v1 ---- */
typedef struct {
    char        id[MYC_PROFILE_ID_MAX + 1];
    long long   checks;              /* total check yang tercatat */
    long long   checks_ok;          /* verdict OK */
    long long   checks_findings;    /* ada finding terkonfirmasi */
    long long   checks_inconclusive;
    long long   duration_ms_total;  /* proksi time/token */
    long long   duration_ms_max;
    long long   gate_status[MYC_STATUS_N][MYC_GATE_COUNT];
    char        class_name[PROFILE_MAX_CLASSES][64];
    long long   class_count[PROFILE_MAX_CLASSES];
    int         class_n;
} my_profile;

static int prof_id_ok(const char *id)
{
    const char *p;
    size_t n;
    if (!id || !*id)
        return 0;
    n = strlen(id);
    if (n > MYC_PROFILE_ID_MAX)
        return 0;
    for (p = id; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

int myc_profile_id_valid(const char *id)
{
    return prof_id_ok(id);
}

static void prof_path_id(const char *id, char *buf, size_t cap)
{
    snprintf(buf, cap, "%s/%s.json", PROFILE_DIR, id);
}

static void prof_ensure_dir(void)
{
    prof_mkdir(PARENT_DIR);
    prof_mkdir(PROFILE_DIR);
}

static void prof_index_add(const char *id)
{
    FILE *f;
    char cur[MYC_PROFILE_ID_MAX + 1];
    int  seen = 0;
    f = fopen(PROFILE_INDEX, "rb");
    if (f) {
        while (fgets(cur, sizeof(cur), f)) {
            cur[strcspn(cur, "\r\n")] = '\0';
            if (strcmp(cur, id) == 0) { seen = 1; break; }
        }
        fclose(f);
    }
    if (seen)
        return;
    f = fopen(PROFILE_INDEX, "ab");
    if (f) {
        fprintf(f, "%s\n", id);
        fclose(f);
    }
}

/* Nama pendek status gate (self-contained; report.c juga punya). */
static const char *prof_status_name(myc_gate_status s)
{
    switch (s) {
    case MYC_GATE_NOT_REQUESTED:     return "not_requested";
    case MYC_GATE_NOT_APPLICABLE:    return "not_applicable";
    case MYC_GATE_UNAVAILABLE:       return "unavailable";
    case MYC_GATE_INFRA_FAILED:      return "infra_failed";
    case MYC_GATE_INCONCLUSIVE:      return "inconclusive";
    case MYC_GATE_COMPLETED_CLEAN:   return "clean";
    case MYC_GATE_COMPLETED_FINDINGS:return "findings";
    case MYC_GATE_COMPLETED_OBSERVATIONS:
        return "observations";
    default:                         return "?";
    }
}

/* Load profile dari disk. Return: 1 = ada, 0 = tak ada/rusak. */
static int prof_load(my_profile *pf, const char *id)
{
    char path[PROFILE_FILE_CAP];
    FILE *f;
    long fsize;
    char *buf;
    json_value *root, *v;
    int i;
    int g, s;
    memset(pf, 0, sizeof(*pf));
    snprintf(pf->id, sizeof(pf->id), "%s", id);
    prof_path_id(id, path, sizeof(path));
    f = fopen(path, "rb");
    if (!f)
        return 0;
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > (long)(4u << 20)) { fclose(f); return 0; }
    buf = (char *)malloc((size_t)fsize + 1);
    if (!buf) { fclose(f); return 0; }
    if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        free(buf); fclose(f); return 0;
    }
    buf[fsize] = '\0';
    fclose(f);

    if (!json_parse_cstr(buf, &root) || !root) {
        free(buf);
        return 0;
    }
    v = json_get(root, "checks");
    if (v && v->type == JSON_NUM) pf->checks = v->num;
    v = json_get(root, "checks_ok");
    if (v && v->type == JSON_NUM) pf->checks_ok = v->num;
    v = json_get(root, "checks_findings");
    if (v && v->type == JSON_NUM) pf->checks_findings = v->num;
    v = json_get(root, "checks_inconclusive");
    if (v && v->type == JSON_NUM) pf->checks_inconclusive = v->num;
    v = json_get(root, "duration_ms_total");
    if (v && v->type == JSON_NUM) pf->duration_ms_total = v->num;
    v = json_get(root, "duration_ms_max");
    if (v && v->type == JSON_NUM) pf->duration_ms_max = v->num;
    v = json_get(root, "gates");
    if (v && v->type == JSON_OBJ) {
        for (g = 0; g < MYC_GATE_COUNT; g++) {
            for (s = 0; s < MYC_STATUS_N; s++) {
                char key[48];
                json_value *cell, *vn;
                snprintf(key, sizeof(key), "%s^%s",
                         myc_gate_id_short((myc_gate_id)g),
                         prof_status_name((myc_gate_status)s));
                cell = json_get(v, key);
                if (cell && cell->type == JSON_OBJ) {
                    vn = json_get(cell, "n");
                    if (vn && vn->type == JSON_NUM)
                        pf->gate_status[s][g] = vn->num;
                }
            }
        }
    }
    v = json_get(root, "classes");
    if (v && v->type == JSON_ARR) {
        for (i = 0; i < (int)v->len && pf->class_n < PROFILE_MAX_CLASSES; i++) {
            json_value *e = v->items[i];
            json_value *cn, *cc;
            if (!e || e->type != JSON_OBJ)
                continue;
            cn = json_get(e, "name");
            cc = json_get(e, "count");
            if (!cn || cn->type != JSON_STR || !cc || cc->type != JSON_NUM)
                continue;
            snprintf(pf->class_name[pf->class_n],
                     sizeof(pf->class_name[pf->class_n]), "%s",
                     cn->str);
            pf->class_count[pf->class_n] = cc->num;
            pf->class_n++;
        }
    }
    json_free(root);
    free(buf);
    return 1;
}

static void save_profile(const my_profile *pf)
{
    char path[PROFILE_FILE_CAP];
    json_value *root, *ob;
    char *js = NULL;
    FILE *f;
    int i, g, s;
    prof_ensure_dir();
    prof_path_id(pf->id, path, sizeof(path));
    root = json_new_obj();
    if (!root) return;
    json_obj_set(root, "schema", json_new_str(MYC_PROFILE_SCHEMA));
    json_obj_set(root, "id", json_new_str(pf->id));
    json_obj_set(root, "checks", json_new_num(pf->checks));
    json_obj_set(root, "checks_ok", json_new_num(pf->checks_ok));
    json_obj_set(root, "checks_findings", json_new_num(pf->checks_findings));
    json_obj_set(root, "checks_inconclusive",
                 json_new_num(pf->checks_inconclusive));
    json_obj_set(root, "duration_ms_total",
                 json_new_num(pf->duration_ms_total));
    json_obj_set(root, "duration_ms_max", json_new_num(pf->duration_ms_max));
    ob = json_new_obj();
    if (ob) {
        for (g = 0; g < MYC_GATE_COUNT; g++) {
            for (s = 0; s < MYC_STATUS_N; s++) {
                if (pf->gate_status[s][g] > 0) {
                    char key[48];
                    json_value *cell = json_new_obj();
                    snprintf(key, sizeof(key), "%s^%s",
                             myc_gate_id_short((myc_gate_id)g),
                             prof_status_name((myc_gate_status)s));
                    json_obj_set(cell, "n",
                                 json_new_num(pf->gate_status[s][g]));
                    json_obj_set(ob, key, cell);
                }
            }
        }
        json_obj_set(root, "gates", ob);
    }
    ob = json_new_arr();
    if (ob) {
        for (i = 0; i < pf->class_n; i++) {
            json_value *e = json_new_obj();
            json_obj_set(e, "name", json_new_str(pf->class_name[i]));
            json_obj_set(e, "count", json_new_num(pf->class_count[i]));
            json_arr_push(ob, e);
        }
        json_obj_set(root, "classes", ob);
    }
    json_serialize(root, &js);
    json_free(root);
    if (!js)
        return;
    f = fopen(path, "wb");
    if (f) {
        fputs(js, f);
        fclose(f);
        prof_index_add(pf->id);
    }
    free(js);
}

static void prof_bump_class(my_profile *pf, const char *name)
{
    int i;
    for (i = 0; i < pf->class_n; i++) {
        if (strcmp(pf->class_name[i], name) == 0) {
            pf->class_count[i]++;
            return;
        }
    }
    if (pf->class_n < PROFILE_MAX_CLASSES) {
        snprintf(pf->class_name[pf->class_n],
                 sizeof(pf->class_name[pf->class_n]), "%s", name);
        pf->class_count[pf->class_n] = 1;
        pf->class_n++;
    }
}

/* Kelas finding dari satu hasil: untuk tiap gate dengan status
 * findings/observations, count satu kemunculan per class (kecenderungan),
 * bukan volume bug. */
static void prof_collect_classes(my_profile *pf, const myc_result *res)
{
    size_t i;
    for (i = 0; i < res->gate_count; i++) {
        const myc_gate_result *gr = &res->gates[i];
        char name[48];
        if (gr->id >= MYC_GATE_COUNT)
            continue;
        if (gr->status == MYC_GATE_COMPLETED_FINDINGS ||
            gr->status == MYC_GATE_COMPLETED_OBSERVATIONS) {
            snprintf(name, sizeof(name), "%s/%s",
                     myc_gate_id_short(gr->id),
                     gr->status == MYC_GATE_COMPLETED_FINDINGS
                         ? "findings" : "observations");
            prof_bump_class(pf, name);
        }
    }
    if (res->finding == MYC_FINDING_FINDINGS)
        prof_bump_class(pf, "verdict-findings");
    else if (res->finding == MYC_FINDING_INCONCLUSIVE)
        prof_bump_class(pf, "verdict-inconclusive");
    if (res->diag_count > 0)
        prof_bump_class(pf, "diagnostics");
    if (res->debt_count > 0)
        prof_bump_class(pf, "unverified-debt");
}

void myc_profile_record(const myc_result *res, const char *id)
{
    my_profile pf;
    size_t i;
    if (!res || !prof_id_ok(id))
        return;
    prof_load(&pf, id);
    pf.checks++;
    if (res->finding == MYC_FINDING_FINDINGS)
        pf.checks_findings++;
    else if (res->finding == MYC_FINDING_INCONCLUSIVE)
        pf.checks_inconclusive++;
    else
        pf.checks_ok++;
    pf.duration_ms_total += (long long)res->duration_ms;
    if ((long long)res->duration_ms > pf.duration_ms_max)
        pf.duration_ms_max = (long long)res->duration_ms;
    for (i = 0; i < res->gate_count; i++) {
        const myc_gate_result *gr = &res->gates[i];
        int st, gid;
        if (gr->id >= MYC_GATE_COUNT)
            continue;
        st = (int)gr->status;
        gid = (int)gr->id;
        if (st >= 0 && st < MYC_STATUS_N)
            pf.gate_status[st][gid]++;
    }
    prof_collect_classes(&pf, res);
    save_profile(&pf);
}

/* --- subcommand text output --- */
static int prof_format(const my_profile *pf, char *buf, size_t cap)
{
    int off = 0;
    int i, g;
    off += snprintf(buf + off, cap - (size_t)off,
                    "schema  : %s\n", MYC_PROFILE_SCHEMA);
    off += snprintf(buf + off, cap - (size_t)off,
                    "id      : %s\n", pf->id);
    off += snprintf(buf + off, cap - (size_t)off,
                    "checks  : %lld (ok=%lld findings=%lld inconcl=%lld)\n",
                    pf->checks, pf->checks_ok, pf->checks_findings,
                    pf->checks_inconclusive);
    off += snprintf(buf + off, cap - (size_t)off,
                    "duration: total=%lld ms max=%lld ms\n",
                    pf->duration_ms_total, pf->duration_ms_max);
    off += snprintf(buf + off, cap - (size_t)off, "gates   :\n");
    for (g = 0; g < MYC_GATE_COUNT; g++) {
        int nonz = 0;
        int s;
        for (s = 0; s < MYC_STATUS_N; s++)
            if (pf->gate_status[s][g] > 0) { nonz = 1; break; }
        if (!nonz)
            continue;
        off += snprintf(buf + off, cap - (size_t)off, "  %-12s ",
                        myc_gate_id_short((myc_gate_id)g));
        for (s = 0; s < MYC_STATUS_N; s++) {
            if (pf->gate_status[s][g] > 0)
                off += snprintf(buf + off, cap - (size_t)off, "%s=%lld ",
                                prof_status_name((myc_gate_status)s),
                                pf->gate_status[s][g]);
        }
        off += snprintf(buf + off, cap - (size_t)off, "\n");
    }
    if (pf->class_n > 0) {
        off += snprintf(buf + off, cap - (size_t)off, "classes :\n");
        for (i = 0; i < pf->class_n; i++) {
            off += snprintf(buf + off, cap - (size_t)off, "  %s=%lld\n",
                            pf->class_name[i], pf->class_count[i]);
        }
    }
    return 0;
}

int myc_profile_show(const char *id, char *buf, size_t cap)
{
    my_profile pf;
    if (!prof_id_ok(id))
        return -2;
    if (!prof_load(&pf, id))
        return -1;
    return prof_format(&pf, buf, cap);
}

int myc_profile_list(char *buf, size_t cap)
{
    FILE *f;
    int off = 0;
    char id[MYC_PROFILE_ID_MAX + 1];
    f = fopen(PROFILE_INDEX, "rb");
    if (!f)
        return 0;
    while (fgets(id, sizeof(id), f)) {
        id[strcspn(id, "\r\n")] = '\0';
        if (*id)
            off += snprintf(buf + off, cap - (size_t)off, "%s\n", id);
    }
    fclose(f);
    return 0;
}

int myc_profile_reset(const char *id)
{
    char path[PROFILE_FILE_CAP];
    char cur[MYC_PROFILE_ID_MAX + 1];
    char tmpname[PROFILE_FILE_CAP + 8];
    FILE *f, *r;
    int  found = 0;
    if (!prof_id_ok(id))
        return -2;
    prof_path_id(id, path, sizeof(path));
    if (remove(path) != 0)
        return -1;
    snprintf(tmpname, sizeof(tmpname), "%s.tmp", PROFILE_INDEX);
    f = fopen(PROFILE_INDEX, "rb");
    if (!f)
        return 0;
    r = fopen(tmpname, "wb");
    if (!r) { fclose(f); return 0; }
    while (fgets(cur, sizeof(cur), f)) {
        cur[strcspn(cur, "\r\n")] = '\0';
        if (strcmp(cur, id) != 0)
            fprintf(r, "%s\n", cur);
        else
            found = 1;
    }
    fclose(f);
    fclose(r);
    if (found) {
        remove(PROFILE_INDEX);
        rename(tmpname, PROFILE_INDEX);
    } else {
        remove(tmpname);
    }
    return 0;
}