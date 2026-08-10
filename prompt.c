/*
 * prompt.c -- D4 (System-Prompt Contract Generator, DS-15).
 *
 * Render deterministik (bukan AI) dari:
 *   1. fakta target host: myc_assume_fetch_facts (gcc -dM -E);
 *   2. denylist fungsi (policy.c): fungsi berbahaya yang TERDETEKSI
 *      dipanggil di source (non-blocking warning di myc biasa);
 *   3. konvensi pemeriksaan alokasi: myc_negative_space (9.8);
 *   4. idiom checked-buffer: pemakaian MYC_BUF / MYC_AT di source;
 *   5. aturan proses: anti-churn + perintah verifikasi.
 *
 * Keluaran <= 12 baris, setiap klaim menyertakan sumbernya.
 */
#include "prompt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myc.h"
#include "policy.h"
#include "negative.h"
#include "assume.h"
#include "proc.h"
#include "json.h"
#include "sha256.h"

/* Skip literal string/char dengan escape; return posisi setelah tutup. */
static size_t skip_str(const char *s, size_t len, size_t i)
{
    char q = s[i];
    size_t j = i + 1;
    while (j < len) {
        if (s[j] == '\\' && j + 1 < len)
            j += 2;
        else if (s[j] == q) {
            j++;
            break;
        } else
            j++;
    }
    return j;
}

/* Skip komentar; return posisi token berikutnya. */
static size_t skip_comment(const char *s, size_t len, size_t i)
{
    if (i + 1 < len && s[i] == '/' && s[i + 1] == '/') {
        while (i < len && s[i] != '\n')
            i++;
    } else if (i + 1 < len && s[i] == '/' && s[i + 1] == '*') {
        i += 2;
        while (i + 1 < len && !(s[i] == '*' && s[i + 1] == '/'))
            i++;
        i += 2;
        if (i > len)
            i = len;
    }
    return i;
}

/* Kumpulkan identifier yang merupakan pemanggilan fungsi denylist.
 * out[] diisi (nama); return jumlah. Maks MYC_PROMPT_MAX_DENIED. */
#define MYC_PROMPT_MAX_DENIED 8

static int scan_denied_calls(const char *s, size_t len,
                             char out[][64], int maxout)
{
    size_t i = 0;
    int    n = 0;
    while (i < len) {
        char c = s[i];
        if (c == '"' || c == '\'') {
            i = skip_str(s, len, i);
            continue;
        }
        if (c == '/' && i + 1 < len &&
            (s[i + 1] == '/' || s[i + 1] == '*')) {
            i = skip_comment(s, len, i);
            continue;
        }
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
            char w[64];
            size_t wl = 0, j = i;
            while (j < len && wl + 1 < sizeof(w) &&
                   ((s[j] >= 'a' && s[j] <= 'z') ||
                    (s[j] >= 'A' && s[j] <= 'Z') ||
                    (s[j] >= '0' && s[j] <= '9') || s[j] == '_'))
                w[wl++] = s[j++];
            w[wl] = '\0';
            /* pemanggilan fungsi: identifier diikuti '(' tanpa spasi? gcc
             * style bebas spasi; lewati spasi lalu cek '(' */
            {
                size_t k = j;
                while (k < len && (s[k] == ' ' || s[k] == '\t'))
                    k++;
                if (k < len && s[k] == '(' && myc_policy_deny_function(w) &&
                    n < maxout) {
                    /* dedupe */
                    int dup = 0, d;
                    for (d = 0; d < n; d++)
                        if (strcmp(out[d], w) == 0)
                            dup = 1;
                    if (!dup)
                        snprintf(out[n++], 64, "%s", w);
                }
            }
            i = j;
            continue;
        }
        i++;
    }
    return n;
}

char *myc_prompt_build(const char *source, size_t len)
{
    char *rep = NULL;
    size_t replen = 0, repcap = 0;
    char  line[512];
    char  denied[MYC_PROMPT_MAX_DENIED][64];
    int   ndenied;
    int   uses_buf;
    myc_host_facts facts;
    myc_result tmp;
    int   facts_ok = 0;
    char *gcc = NULL;

#define PAPPEND(s) do {                                                 \
        size_t _l = strlen(s);                                          \
        if (replen + _l + 1 > repcap) {                                 \
            size_t ncap = repcap ? repcap * 2 : 2048;                   \
            char *nb;                                                   \
            while (ncap < replen + _l + 1)                              \
                ncap *= 2;                                              \
            nb = (char *)realloc(rep, ncap);                            \
            if (!nb) {                                                  \
                free(rep);                                              \
                rep = NULL;                                             \
                replen = repcap = 0;                                    \
                goto done;                                              \
            }                                                           \
            rep = nb;                                                   \
            repcap = ncap;                                              \
        }                                                               \
        memcpy(rep + replen, s, _l);                                    \
        replen += _l;                                                   \
        rep[replen] = '\0';                                             \
    } while (0)

    memset(&facts, 0, sizeof(facts));
    gcc = myc_find_executable("gcc");
    if (gcc) {
        facts_ok = myc_assume_fetch_facts(gcc, &facts);
        free(gcc);
    }

    ndenied = scan_denied_calls(source, len, denied, MYC_PROMPT_MAX_DENIED);

    /* konvensi pemeriksaan alokasi via negative-space (murni teks) */
    myc_result_init(&tmp);
    myc_negative_space(source, len, &tmp);
    uses_buf = (strstr(source, "MYC_BUF(") != NULL ||
                strstr(source, "MYC_AT(") != NULL);

    PAPPEND("# Aturan C untuk proyek ini (dari myc -- deterministik, "
            "bukan AI)\n");
    if (facts_ok) {
        snprintf(line, sizeof(line),
                 "- Target host (fakta gcc host): char=%s, int=%d-bit, "
                 "ptr=%d-bit, %s, CHAR_BIT=%d, STDC_VERSION=%ld\n",
                 facts.char_unsigned ? "UNSIGNED" : "signed",
                 facts.int_bits, facts.ptr_bits,
                 facts.little_endian ? "little-endian" : "big-endian",
                 facts.char_bit ? facts.char_bit : 8,
                 facts.stdc_version ? facts.stdc_version : 0L);
        PAPPEND(line);
    } else {
        PAPPEND("- Target host: TIDAK terdeteksi (gcc tidak tersedia) -- "
                "jangan berasumsi signedness/lebar tipe\n");
    }
    if (ndenied > 0) {
        int i;
        snprintf(line, sizeof(line),
                 "- Fungsi denylist dipanggil di file ini (non-blocking "
                 "warning di myc):");
        PAPPEND(line);
        for (i = 0; i < ndenied; i++) {
            snprintf(line, sizeof(line), " %.60s()", denied[i]);
            PAPPEND(line);
        }
        PAPPEND(" -- hindari: ini kelas bug berbahaya\n");
    } else {
        PAPPEND("- Tidak ada panggilan fungsi denylist di file ini "
                "(system/exec/fopen/dll)\n");
    }
    if (tmp.negative_callsites > 0) {
        snprintf(line, sizeof(line),
                 "- Konvensi alokasi (dari negative-space): %d/%d callsite "
                 "memeriksa hasil -- cek NULL di SEMUA alokasi\n",
                 tmp.negative_callsites - tmp.negative_deviations,
                 tmp.negative_callsites);
        PAPPEND(line);
    }
    if (uses_buf) {
        PAPPEND("- Gunakan disiplin MYC_BUF/MYC_AT untuk buffer dinamis "
                "(verifikasi L4 SPATIAL) -- jangan akses di luar MYC_AT\n");
    }
    PAPPEND("- Anti-churn: jangan ubah fungsi yang tidak terkait dengan "
            "finding\n");
    PAPPEND("- Sebelum mengirim jawaban, jalankan: myc check <file.c> "
            "--delta\n");
    PAPPEND("- Klaim keamanan hanya dari bukti myc (gate matrix), bukan "
            "perasaan\n");
done:
    myc_result_free(&tmp);
    return rep;
#undef PAPPEND
}

/* ================= Project-local prompt/spec pack (Fase 7) =============
 *
 * Dua file opsional di direktori proyek (version-controllable, BUKAN
 * .myc/ yang gitignored):
 *
 *   myc.prompt.md   teks bebas proyek (hingga MYC_PACK_PROMPT_CAP byte),
 *                   disisipkan verbatim ke snippet prompt.
 *   myc.spec.json   spec terstruktur (skema divalidasi json.c):
 *                   { "version": 1, "name": "..", "domain": "..",
 *                     "rules": [".."], "allow_headers": [".."],
 *                     "deny_functions": [".."] }
 *
 * NON-blocking penuh: pack TIDAK pernah mengubah verdict/hasil run.
 * spec.json yang ADA tapi invalid = fail-fast (pola scenario -2).
 * Deterministik + sha256 isi file dilaporkan agar harness bisa verifikasi.
 */

/* Baca file teks via loader canonical (myc_source_load).
 * Return: 0 = OK (mengisi *text malloc'd + *present);
 *         -2 = IO error fatal. *present=0 bila file tidak ada. */
static int pack_read_file(const char *path, char **text, size_t *len,
                          int *present)
{
    myc_source_input in;
    const char *buf;
    size_t      blen;
    int         needs_free = 0;
    myc_error_code le;

    memset(&in, 0, sizeof(in));
    in.kind = MYC_SOURCE_FILE;
    in.file_path = path;
    le = myc_source_load(&in, &buf, &blen, &needs_free);
    if (le == MYC_ERR_INVALID_PATH) {
        *present = 0;
        return 0;
    }
    if (le != MYC_ERR_NONE)
        return -2;
    *text = (char *)malloc(blen + 1);
    if (!*text) {
        if (needs_free)
            free((void *)buf);
        return -2;
    }
    memcpy(*text, buf, blen);
    (*text)[blen] = '\0';
    *len = blen;
    if (needs_free)
        free((void *)buf);
    *present = 1;
    return 0;
}

/* Susun path <dir>/<name>; dir NULL = cwd (" ."). Return 0 = OK. */
static int pack_path(char *out, size_t cap, const char *dir,
                     const char *name)
{
    if (!dir || dir[0] == '\0')
        dir = ".";
    if (snprintf(out, cap, "%s/%s", dir, name) >= (int)cap)
        return -1;
    return 0;
}

/* Salin array JSON string ke baris dst[row][maxlen]; return 0 = OK,
 * -1 = invalid (bukan array / elemen bukan string / melebihi batas).
 * v NULL = opsional, nol-kan *outn dan return 0. */
static int pack_strlist(json_value *v, char *dst, size_t rowsz, int maxn,
                        int maxlen, int *outn)
{
    size_t i;
    *outn = 0;
    if (!v)
        return 0;
    if (v->type != JSON_ARR || v->len > (size_t)maxn)
        return -1;
    for (i = 0; i < v->len; i++) {
        json_value *it = v->items[i];
        const char *s;
        if (!it || it->type != JSON_STR || !it->str)
            return -1;
        s = it->str;
        if (strlen(s) >= (size_t)maxlen)
            return -1;
        memcpy(dst + i * rowsz, s, strlen(s) + 1);
    }
    *outn = (int)v->len;
    return 0;
}

/* Parse + validasi myc.spec.json. Return 0 = valid, -1 = invalid. */
static int pack_parse_spec(const char *text, size_t len, myc_pack_info *info)
{
    json_value *root = NULL;
    json_value *v;
    const char *s;
    int rc = -1;

    if (!json_parse(text, len, &root) || !root)
        return -1;
    if (root->type != JSON_OBJ)
        goto out;
    v = json_get(root, "version");
    if (!v || v->type != JSON_NUM || v->num != 1)
        goto out;
    s = json_get_str(root, "name");
    if (!s || s[0] == '\0' || strlen(s) >= sizeof(info->spec_name))
        goto out;
    snprintf(info->spec_name, sizeof(info->spec_name), "%s", s);
    s = json_get_str(root, "domain");
    if (s) {
        if (strlen(s) >= sizeof(info->spec_domain))
            goto out;
        snprintf(info->spec_domain, sizeof(info->spec_domain), "%s", s);
    }
    v = json_get(root, "rules");
    if (pack_strlist(v, (char *)info->spec_rules,
                     sizeof(info->spec_rules[0]), MYC_PACK_MAX_RULES,
                     MYC_PACK_RULE_LEN, &info->spec_n_rules) != 0)
        goto out;
    v = json_get(root, "allow_headers");
    if (pack_strlist(v, (char *)info->spec_allow,
                     sizeof(info->spec_allow[0]), MYC_PACK_MAX_HEADS,
                     MYC_PACK_HEAD_LEN, &info->spec_n_allow) != 0)
        goto out;
    v = json_get(root, "deny_functions");
    if (pack_strlist(v, (char *)info->spec_deny,
                     sizeof(info->spec_deny[0]), MYC_PACK_MAX_DENIES,
                     MYC_PACK_DENY_LEN, &info->spec_n_deny) != 0)
        goto out;
    rc = 0;
out:
    json_free(root);
    return rc;
}

int myc_pack_load(const char *pack_dir, int no_pack, myc_pack_info *info)
{
    char  path[512];
    char *ptext = NULL;
    size_t plen = 0;
    int   present = 0;

    memset(info, 0, sizeof(*info));
    if (no_pack)
        return 0;

    /* myc.prompt.md -- opsional; teks disisipkan verbatim (cap diterapkan). */
    if (pack_path(path, sizeof(path), pack_dir, MYC_PACK_PROMPT_FILE) != 0)
        return -2;
    if (pack_read_file(path, &ptext, &plen, &present) != 0)
        return -2;
    if (present) {
        size_t used = plen;
        info->prompt_total_len = plen;
        if (used > MYC_PACK_PROMPT_CAP)
            used = MYC_PACK_PROMPT_CAP;
        info->prompt_text = (char *)malloc(used + 1);
        if (!info->prompt_text) {
            free(ptext);
            return -2;
        }
        memcpy(info->prompt_text, ptext, used);
        info->prompt_text[used] = '\0';
        info->prompt_text_len = used;
        info->prompt_present = 1;
        sha256_hex(info->prompt_text, used, info->prompt_sha256);
    }
    free(ptext);
    ptext = NULL;

    /* myc.spec.json -- opsional; ADA tapi invalid = fail-fast (-1). */
    if (pack_path(path, sizeof(path), pack_dir, MYC_PACK_SPEC_FILE) != 0)
        return -2;
    present = 0;
    if (pack_read_file(path, &ptext, &plen, &present) != 0) {
        free(info->prompt_text);
        info->prompt_text = NULL;
        return -2;
    }
    if (present) {
        sha256_hex(ptext, plen, info->spec_sha256);
        if (pack_parse_spec(ptext, plen, info) != 0) {
            free(info->prompt_text);
            info->prompt_text = NULL;
            free(ptext);
            return -1;
        }
        info->spec_present = 1;
    }
    free(ptext);
    return 0;
}

/* Ganti newline/CR dengan spasi (agar isi pack tidak merusak struktur
 * prompt). out harus cap >= cap. */
static void pack_sanitize(const char *s, char *out, size_t cap)
{
    size_t i, o = 0;
    for (i = 0; s[i] && o + 1 < cap; i++) {
        char c = s[i];
        if (c == '\n' || c == '\r')
            c = ' ';
        out[o++] = c;
    }
    out[o] = '\0';
}

char *myc_prompt_build_packed(const char *source, size_t len,
                              const myc_pack_info *info)
{
    char *core;
    char *out;
    char *blk = NULL;
    size_t bcap = 0, blen = 0;
    size_t core_len;
    char  line[512];
    int   i;

    if (!info || (!info->prompt_present && !info->spec_present))
        return myc_prompt_build(source, len);

    core = myc_prompt_build(source, len);
    if (!core)
        return NULL;
    core_len = strlen(core);

#define PK_APPEND(s) do {                                               \
        size_t _l = strlen(s);                                          \
        if (blen + _l + 1 > bcap) {                                     \
            size_t ncap = bcap ? bcap * 2 : 512;                        \
            char *nb;                                                   \
            while (ncap < blen + _l + 1)                                \
                ncap *= 2;                                              \
            nb = (char *)realloc(blk, ncap);                            \
            if (!nb) { free(blk); free(core); return NULL; }            \
            blk = nb;                                                   \
            bcap = ncap;                                                \
        }                                                               \
        memcpy(blk + blen, s, _l);                                      \
        blen += _l;                                                     \
        blk[blen] = '\0';                                               \
    } while (0)

    PK_APPEND("\n# Pack proyek (project-local, NON-blocking)\n");
    if (info->prompt_present) {
        snprintf(line, sizeof(line),
                 "Dari myc.prompt.md (sha256 %s):\n", info->prompt_sha256);
        PK_APPEND(line);
        PK_APPEND(info->prompt_text);
        if (info->prompt_text_len > 0 &&
            info->prompt_text[info->prompt_text_len - 1] != '\n')
            PK_APPEND("\n");
        if (info->prompt_total_len > info->prompt_text_len) {
            snprintf(line, sizeof(line),
                     "(pack prompt dipotong: %d byte > cap %d)\n",
                     (int)info->prompt_total_len, (int)MYC_PACK_PROMPT_CAP);
            PK_APPEND(line);
        }
    }
    if (info->spec_present) {
        snprintf(line, sizeof(line),
                 "Spec myc.spec.json (sha256 %s): proyek \"%s\", "
                 "domain \"%s\"\n",
                 info->spec_sha256, info->spec_name, info->spec_domain);
        PK_APPEND(line);
        for (i = 0; i < info->spec_n_rules; i++) {
            char s[MYC_PACK_RULE_LEN];
            pack_sanitize(info->spec_rules[i], s, sizeof(s));
            snprintf(line, sizeof(line), "- Rule (dari spec.json): %s\n", s);
            PK_APPEND(line);
        }
        for (i = 0; i < info->spec_n_allow; i++) {
            char s[MYC_PACK_HEAD_LEN];
            pack_sanitize(info->spec_allow[i], s, sizeof(s));
            snprintf(line, sizeof(line),
                     "- Header diizinkan (dari spec.json): %s\n", s);
            PK_APPEND(line);
        }
        for (i = 0; i < info->spec_n_deny; i++) {
            char s[MYC_PACK_DENY_LEN];
            pack_sanitize(info->spec_deny[i], s, sizeof(s));
            snprintf(line, sizeof(line),
                     "- Fungsi denylist tambahan (dari spec.json): %s\n", s);
            PK_APPEND(line);
        }
    }
    PK_APPEND("- Pack TIDAK memengaruhi verdict myc (observasi NON-blocking)\n");

    out = (char *)malloc(core_len + blen + 1);
    if (!out) {
        free(blk);
        free(core);
        return NULL;
    }
    memcpy(out, core, core_len);
    memcpy(out + core_len, blk, blen + 1);
    free(blk);
    free(core);
    return out;
#undef PK_APPEND
}
