/*
 * scenario.c -- C5: Scenario Packs (--scenario) + D3 auto budget (DS-12).
 *
 * Profil = DATA JSON (bukan hardcode logika). Skema divalidasi parser
 * ketat json.c (strict: menolak malformed). Urutan resolusi profil:
 *   1. --scenario-file <path> (eksplisit);
 *   2. scenarios.json di cwd (user-defined, menimpa/menambah bawaan);
 *   3. profil bawaan (embedded JSON).
 *
 * Skema profil (satu file = satu root object):
 *   { "version": 1,
 *     "scenarios": [
 *       { "name": "...", "desc": "...",
 *         "flags": ["run","analyzer","driver","exhaustive","fuzz",
 *                   "stack","freestanding","divergence","prove",
 *                   "checked","metamorphic","negative"],
 *         "env": { "stack_budget": 4096, "no_heap": true,
 *                  "no_recursion": true } } ] }
 *
 * D3 (--scenario auto): tebak resep dari struktur source (main / //@
 * contract / pola firmware / heap), laporkan alasan. DS-12: env contract
 * (dunia tempat program hidup) dicatat di scenario_report; enforcement
 * dilakukan gate terkait yang diaktifkan (freestanding trap heap, stack
 * gate rekursi). Verdict tidak pernah berubah karena scenario.
 */
#include "scenario.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

/* --- Profil bawaan (data JSON, bukan hardcode) --- */
static const char *builtin_profiles_json =
    "{"
    " \"version\": 1,"
    " \"scenarios\": ["
    "  {\"name\":\"cli-daily\","
    "   \"desc\":\"CLI harian: compile + run + analyzer\","
    "   \"flags\":[\"run\",\"analyzer\"],\"env\":{}},"
    "  {\"name\":\"library\","
    "   \"desc\":\"Fungsi library murni: driver + exhaustive\","
    "   \"flags\":[\"driver\",\"exhaustive\"],\"env\":{}},"
    "  {\"name\":\"parser\","
    "   \"desc\":\"Parser input tak terduga: fuzz + run\","
    "   \"flags\":[\"fuzz\",\"run\"],\"env\":{}},"
    "  {\"name\":\"firmware\","
    "   \"desc\":\"Firmware bare-metal: freestanding + stack + divergence + MMIO rules\","
    "   \"flags\":[\"freestanding\",\"stack\",\"divergence\"],"
    "   \"env\":{\"stack_budget\":4096,\"no_heap\":true,\"no_recursion\":true}},"
    "  {\"name\":\"auto\","
    "   \"desc\":\"Auto (D3): tebak resep terkecil yang cukup dari struktur source\","
    "   \"flags\":[],\"env\":{}}"
    " ]"
    "}";

/* --- helpers --- */

static int has_substr(const char *src, size_t len, const char *w)
{
    size_t wl = strlen(w);
    size_t i;
    if (!src || len < wl)
        return 0;
    for (i = 0; i + wl <= len; i++)
        if (strncmp(src + i, w, wl) == 0)
            return 1;
    return 0;
}

/* Ambil member objek json secara linear (profil kecil). */
static json_value *obj_member(json_value *obj, const char *key)
{
    size_t i;
    if (!obj || obj->type != JSON_OBJ)
        return NULL;
    for (i = 0; i < obj->mlen; i++)
        if (strcmp(obj->members[i].key, key) == 0)
            return obj->members[i].val;
    return NULL;
}

/* Cari root JSON profil: parse teks, validasi skema, kembalikan root
 * (caller json_free). NULL bila invalid. */
static json_value *parse_profiles(const char *text, size_t len)
{
    json_value *root = NULL;
    json_value *ver, *arr;
    size_t i;
    /* json_parse: return 1 = sukses, 0 = gagal. */
    if (json_parse(text, len, &root) == 0 || !root)
        return NULL;
    if (root->type != JSON_OBJ)
        goto bad;
    ver = obj_member(root, "version");
    if (!ver || ver->type != JSON_NUM || ver->num != 1)
        goto bad;
    arr = obj_member(root, "scenarios");
    if (!arr || arr->type != JSON_ARR || arr->len == 0)
        goto bad;
    for (i = 0; i < arr->len; i++) {
        json_value *s = arr->items[i];
        if (!s || s->type != JSON_OBJ)
            goto bad;
        if (!json_get_str(s, "name") || !json_get_str(s, "desc"))
            goto bad;
        if (obj_member(s, "flags") &&
            obj_member(s, "flags")->type != JSON_ARR)
            goto bad;
        if (obj_member(s, "env") &&
            obj_member(s, "env")->type != JSON_OBJ)
            goto bad;
    }
    return root;
bad:
    json_free(root);
    return NULL;
}

/* Baca file profil (via loader canonical myc_source_load). Kembalikan 0
 * dan isi *text serta *len (needs_free) bila file terbaca; -1 = file
 * tidak ada (fallback ke bawaan); -2 = file ada tapi tidak valid. */
static int load_profile_file(const char *path, const char **text,
                             size_t *len, int *needs_free)
{
    myc_source_input in;
    myc_error_code   le;
    json_value      *root;
    if (!path || path[0] == '\0')
        return -1;
    in.kind = MYC_SOURCE_FILE;
    in.data = NULL;
    in.len = 0;
    in.file_path = path;
    le = myc_source_load(&in, text, len, needs_free);
    if (le == MYC_ERR_INVALID_PATH)
        return -1;                      /* tidak ada -> fallback bawaan */
    if (le != MYC_ERR_NONE)
        return -2;
    root = parse_profiles(*text, *len);
    if (!root)
        return -2;                      /* ada tapi invalid */
    json_free(root);
    return 0;
}

/* --- resolusi profil: bawaan + (user bila tersedia & valid) ---
 * root yang dikembalikan = profil EFEKTIF (user menimpa bawaan utk nama
 * sama, menambah utk nama baru). */
static json_value *effective_root(const char *profile_path,
                                  const char **text_out, int *free_out)
{
    json_value *user_root = NULL;
    json_value *builtin_root = NULL;
    json_value *eff = NULL;
    const char *utext = NULL;
    size_t      ulen = 0;
    int         ufree = 0;
    int         rc;
    const char *path = profile_path;
    size_t      blen = strlen(builtin_profiles_json);

    if (!path || path[0] == '\0')
        path = "scenarios.json";        /* default user profil di cwd */
    rc = load_profile_file(path, &utext, &ulen, &ufree);
    if (rc == 0)
        user_root = parse_profiles(utext, ulen);
    /* builtin selalu tersedia */
    builtin_root = parse_profiles(builtin_profiles_json, blen);

    if (user_root && builtin_root) {
        /* merge: item user (name sama) menimpa bawaan */
        json_value *uarr = obj_member(user_root, "scenarios");
        json_value *barr = obj_member(builtin_root, "scenarios");
        size_t i, j;
        for (i = 0; i < uarr->len; i++) {
            json_value *us = uarr->items[i];
            const char *uname = json_get_str(us, "name");
            int replaced = 0;
            for (j = 0; j < barr->len; j++) {
                json_value *bs = barr->items[j];
                if (strcmp(json_get_str(bs, "name"), uname) == 0) {
                    barr->items[j] = us;
                    replaced = 1;
                    break;
                }
            }
            if (!replaced && barr->len < barr->cap)
                barr->items[barr->len++] = us;
        }
        eff = builtin_root;
        /* Catatan: item user yang di-merge menunjuk ke memory milik
         * user_root, jadi user_root TIDAK boleh di-free di sini (leak
         * kecil, sekali per proses, lebih aman daripada use-after-free). */
    } else if (user_root) {
        eff = user_root;
        json_free(builtin_root);
    } else {
        eff = builtin_root;
    }

    if (ufree && utext)
        free((void *)utext);
    if (text_out)
        *text_out = NULL;
    if (free_out)
        *free_out = 0;
    return eff;
}

/* --- apply flag / env --- */

static void apply_flag(myc_request *req, const char *flag)
{
    if (strcmp(flag, "run") == 0)
        req->run = 1;
    else if (strcmp(flag, "analyzer") == 0)
        req->run_analyzer = 1;
    else if (strcmp(flag, "driver") == 0)
        req->driver = 1;
    else if (strcmp(flag, "exhaustive") == 0)
        req->exhaustive = 1;
    else if (strcmp(flag, "fuzz") == 0)
        req->fuzz = 1;
    else if (strcmp(flag, "stack") == 0)
        req->stack = 1;
    else if (strcmp(flag, "freestanding") == 0)
        req->freestanding = 1;
    else if (strcmp(flag, "divergence") == 0)
        req->divergence = 1;
    else if (strcmp(flag, "prove") == 0)
        req->prove = 1;
    else if (strcmp(flag, "checked") == 0)
        req->checked = 1;
    else if (strcmp(flag, "metamorphic") == 0)
        req->metamorphic = 1;
    else if (strcmp(flag, "negative") == 0)
        req->negative = 1;
    /* flag tak dikenal: diabaikan (data profil, non-blocking) */
}

/* Bangun teks "desc; flags aktif: ...; env: ..." ke buf. */
static void build_report(json_value *sc, char *buf, size_t cap)
{
    json_value *flags = obj_member(sc, "flags");
    json_value *env = obj_member(sc, "env");
    json_value *desc = obj_member(sc, "desc");
    size_t      off = 0;
    size_t      i;

    if (desc && desc->type == JSON_STR)
        off += (size_t)snprintf(buf + off, off < cap ? cap - off : 0,
                                "%s; ", desc->str);
    if (flags && flags->type == JSON_ARR) {
        off += (size_t)snprintf(buf + off, off < cap ? cap - off : 0,
                                "flags aktif: ");
        for (i = 0; i < flags->len; i++) {
            if (flags->items[i] && flags->items[i]->type == JSON_STR)
                off += (size_t)snprintf(
                    buf + off, off < cap ? cap - off : 0, "%s%s",
                    i > 0 ? ", " : "", flags->items[i]->str);
        }
    }
    if (env && env->type == JSON_OBJ && env->mlen > 0) {
        off += (size_t)snprintf(buf + off, off < cap ? cap - off : 0,
                                "; env (DS-12): ");
        for (i = 0; i < env->mlen; i++) {
            json_value *v = env->members[i].val;
            char        tmp[64] = "";
            if (v && v->type == JSON_NUM)
                snprintf(tmp, sizeof(tmp), "%lld", (long long)v->num);
            else if (v && v->type == JSON_BOOL)
                snprintf(tmp, sizeof(tmp), "%s",
                         v->boolean ? "true" : "false");
            off += (size_t)snprintf(
                buf + off, off < cap ? cap - off : 0, "%s%s=%s",
                i > 0 ? ", " : "", env->members[i].key, tmp);
        }
    }
    if (off > 0 && off < cap)
        buf[off] = '\0';
}

/* --- D3: deteksi struktur source -> resep --- */

static void detect_auto(const char *src, size_t len, int *is_fw,
                        int *has_contract, int *has_main)
{
    *is_fw = has_substr(src, len, "volatile") ||
             has_substr(src, len, "_isr") ||
             has_substr(src, len, "_irq") ||
             has_substr(src, len, "interrupt") ||
             has_substr(src, len, "packed");
    *has_contract = has_substr(src, len, "//@");
    *has_main = has_substr(src, len, "main(") ||
                has_substr(src, len, "main(void)");
}

/* Resep D3: firmware > library (contract) > cli-daily. */
static const char *auto_target(const char *src, size_t len, char *why,
                               size_t whycap)
{
    int is_fw, has_contract, has_main;
    detect_auto(src, len, &is_fw, &has_contract, &has_main);
    if (is_fw) {
        snprintf(why, whycap,
                 "terdeteksi pola firmware (volatile/ISR/packed)");
        return "firmware";
    }
    if (has_contract) {
        snprintf(why, whycap,
                 "terdeteksi kontrak //@ (fungsi library murni)");
        return "library";
    }
    if (has_main) {
        snprintf(why, whycap,
                 "terdeteksi main() (program utuh)");
        return "cli-daily";
    }
    snprintf(why, whycap, "struktur umum; resep baseline");
    return "cli-daily";
}

/* --- API publik --- */

int myc_scenario_apply(myc_request *req, const char *name,
                       const char *src, size_t srclen,
                       const char *profile_path, myc_result *res)
{
    json_value  *root;
    json_value  *arr, *sc = NULL;
    json_value  *flags, *env;
    char         why[256] = "";
    char         buf[1024];
    size_t       i;
    int          is_auto = (strcmp(name, "auto") == 0);
    const char  *target = name;

    root = effective_root(profile_path, NULL, NULL);
    if (!root)
        return -2;                      /* profil invalid */

    if (is_auto) {
        target = auto_target(src, srclen, why, sizeof(why));
        res->scenario_auto = 1;
    }

    arr = obj_member(root, "scenarios");
    for (i = 0; i < arr->len; i++) {
        if (strcmp(json_get_str(arr->items[i], "name"), target) == 0) {
            sc = arr->items[i];
            break;
        }
    }
    if (!sc) {
        json_free(root);
        return -1;                      /* scenario tak dikenal */
    }

    /* apply flags */
    flags = obj_member(sc, "flags");
    if (flags && flags->type == JSON_ARR) {
        for (i = 0; i < flags->len; i++)
            if (flags->items[i] && flags->items[i]->type == JSON_STR)
                apply_flag(req, flags->items[i]->str);
    }
    /* apply env (DS-12) */
    env = obj_member(sc, "env");
    if (env && env->type == JSON_OBJ) {
        for (i = 0; i < env->mlen; i++) {
            json_value *v = env->members[i].val;
            if (strcmp(env->members[i].key, "stack_budget") == 0 &&
                v && v->type == JSON_NUM)
                req->stack_budget = (int)v->num;
        }
    }

    build_report(sc, buf, sizeof(buf));
    res->scenario_applied = 1;
    res->scenario_name = myc_result_arena_dup(res, target, 0);
    if (is_auto)
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
                 " (auto: %s)", why);
    res->scenario_report = myc_result_arena_dup(res, buf, 0);

    json_free(root);
    return 0;
}

int myc_scenario_list(const char *profile_path, char *out, size_t cap)
{
    json_value *root = effective_root(profile_path, NULL, NULL);
    json_value *arr;
    size_t      i, off = 0;
    if (!root)
        return -2;
    arr = obj_member(root, "scenarios");
    for (i = 0; i < arr->len; i++) {
        json_value *s = arr->items[i];
        off += (size_t)snprintf(out + off, off < cap ? cap - off : 0,
                                "%-14s %s\n", json_get_str(s, "name"),
                                json_get_str(s, "desc"));
        if (off >= cap)
            break;
    }
    json_free(root);
    return 0;
}

int myc_scenario_info(const char *name, const char *profile_path,
                      char *out, size_t cap)
{
    json_value *root = effective_root(profile_path, NULL, NULL);
    json_value *arr;
    json_value *sc = NULL;
    size_t      i;
    if (!root)
        return -2;
    arr = obj_member(root, "scenarios");
    for (i = 0; i < arr->len; i++) {
        if (strcmp(json_get_str(arr->items[i], "name"), name) == 0) {
            sc = arr->items[i];
            break;
        }
    }
    if (!sc) {
        json_free(root);
        return -1;
    }
    build_report(sc, out, cap);
    json_free(root);
    return 0;
}
