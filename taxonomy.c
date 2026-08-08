/*
 * taxonomy.c -- B3 (LLM Error Taxonomy + coaching transcript, DS-07).
 *
 * Classifier rule-based (substring deterministik, case-insensitive) dari
 * pesan diagnostic/evidence ke kelas kesalahan KOGNITIF, lalu menyusun
 * coaching transcript (5-10 baris) yang ditulis untuk dibaca model.
 *
 * Kejujuran:
 *   - Klasifikasi = observasi. Tidak pernah menaikkan/menurunkan verdict.
 *   - Deterministik: urutan diagnosis disimpan; transcript stabil.
 *   - Strategi per kelas bersifat template (bukan klaim spesifik kode).
 */
#include "taxonomy.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *myc_taxonomy_name(myc_taxonomy_class c)
{
    switch (c) {
    case MYC_TAX_HALLUCINATED_API: return "hallucinated_api";
    case MYC_TAX_MISSING_GUARD:    return "missing_guard";
    case MYC_TAX_OFF_BY_ONE:       return "off_by_one";
    case MYC_TAX_UB_ASSUMPTION:    return "ub_assumption";
    case MYC_TAX_TYPE_CONFUSION:   return "type_confusion";
    case MYC_TAX_IGNORED_RETURN:   return "ignored_return";
    case MYC_TAX_WRONG_CONSTANT:   return "wrong_constant";
    case MYC_TAX_CHURN:            return "churn";
    default:                       return "unclassified";
    }
}

const char *myc_taxonomy_strategy(myc_taxonomy_class c)
{
    switch (c) {
    case MYC_TAX_HALLUCINATED_API:
        return "API ini tampaknya dianggap lebih aman dari kenyataannya; "
               "periksa kontrak fungsi (banyak fungsi C tidak "
               "men-NUL-terminate / tidak memeriksa batas). Gunakan pola "
               "yang dibuktikan -- jangan sentuh callsite lain tanpa "
               "finding yang terkait.";
    case MYC_TAX_MISSING_GUARD:
        return "Tambahkan guard: cek NULL pada hasil alokasi, cek batas "
               "sebelum akses, dan inisialisasi sebelum baca.";
    case MYC_TAX_OFF_BY_ONE:
        return "Periksa batas loop/index: '<' vs '<=', ukuran buffer vs "
               "panjang data, dan kasus tepi 0 / MAX.";
    case MYC_TAX_UB_ASSUMPTION:
        return "Kode bertaruh pada perilaku implementation-defined/UB; "
               "gunakan tipe eksplisit (uint32_t/size_t/intptr_t) dan "
               "hindari overflow / shift negatif / akses unaligned.";
    case MYC_TAX_TYPE_CONFUSION:
        return "Tipe atau pointer tidak cocok; periksa cast, signedness "
               "char/int, dan lebar tipe antar platform.";
    case MYC_TAX_IGNORED_RETURN:
        return "Return value dibuang; proyek ini mengharuskan hasil "
               "dicek (error / EOF / short read / NULL).";
    case MYC_TAX_WRONG_CONSTANT:
        return "Konstanta atau nilai batas kemungkinan salah; verifikasi "
               "terhadap spesifikasi (bukan dugaan).";
    case MYC_TAX_CHURN:
        return "Anda mengubah kode yang TIDAK terkait finding -- "
               "kembalikan; fokus ke finding utama (anti-churn).";
    default:
        return "Periksa pesan finding di atas dan bandingkan dengan "
               "kontrak/scope yang dilaporkan.";
    }
}

/* Classify satu pesan (case-insensitive). Prioritas: deteksi paling
 * spesifik lebih dulu agar pesan ganda tidak salah kelas. */
myc_taxonomy_class myc_taxonomy_classify(const char *message)
{
    char low[512];
    size_t i, n;
    static const char *const api_markers[] = {
        "strncpy", "strcpy", "sprintf", "gets", "strcat", "scanf",
        "memcpy", "memset", "strtok", "read(", "write(", "fread",
        "fwrite", "system", "popen", "malloc(", "calloc(", "realloc(",
        NULL
    };
    static const char *const guard_markers[] = {
        "null", "dereference", "uninitialized", "dangling", "free",
        NULL
    };
    static const char *const type_markers[] = {
        "incompatible", "conversion", "cast", "conflicting types",
        "different types", "wrong type", NULL
    };
    static const char *const oob_markers[] = {
        "out of bounds", "array subscript", "off by one", "index",
        "buffer overflow", "stack overflow", "exceeds", "too large",
        "too small", NULL
    };
    static const char *const ub_markers[] = {
        "signed overflow", "shift", "negative", "unsequenced",
        "indeterminate", "undefined", "alignment", "volatile",
        "misaligned", NULL
    };
    static const char *const ignored_markers[] = {
        "ignoring return", "ignored return", "unused result",
        "return value ignored", NULL
    };
    static const char *const const_markers[] = {
        "comparison always", "always true", "always false",
        "out of range", "constant", NULL
    };
    size_t k;

    if (!message)
        return MYC_TAX_UNCLASSIFIED;
    n = 0;
    for (i = 0; message[i] && n + 1 < sizeof(low); i++) {
        char c = message[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
        low[n++] = c;
    }
    low[n] = '\0';

    for (k = 0; ignored_markers[k]; k++)
        if (strstr(low, ignored_markers[k]))
            return MYC_TAX_IGNORED_RETURN;

    for (k = 0; guard_markers[k]; k++)
        if (strstr(low, guard_markers[k]))
            return MYC_TAX_MISSING_GUARD;

    for (k = 0; api_markers[k]; k++)
        if (strstr(low, api_markers[k]))
            return MYC_TAX_HALLUCINATED_API;

    for (k = 0; type_markers[k]; k++)
        if (strstr(low, type_markers[k]))
            return MYC_TAX_TYPE_CONFUSION;

    for (k = 0; oob_markers[k]; k++)
        if (strstr(low, oob_markers[k]))
            return MYC_TAX_OFF_BY_ONE;

    for (k = 0; ub_markers[k]; k++)
        if (strstr(low, ub_markers[k]))
            return MYC_TAX_UB_ASSUMPTION;

    for (k = 0; const_markers[k]; k++)
        if (strstr(low, const_markers[k]))
            return MYC_TAX_WRONG_CONSTANT;

    return MYC_TAX_UNCLASSIFIED;
}

/* Tambah satu item coaching (dedupe by class+line+where-hash sederhana). */
static void coach_add(myc_result *res, myc_taxonomy_class cls, int line,
                      const char *where)
{
    int i;
    char *slot;
    if (res->coaching_count >= MYC_MAX_COACHING)
        return;
    /* dedupe: kelas sama + baris sama + pesan sama tidak ditambah dua kali */
    for (i = 0; i < res->coaching_count; i++) {
        const myc_coaching_item *c = &res->coaching[i];
        if (c->cls == cls && c->line == line && c->where &&
            strcmp(c->where, where) == 0)
            return;
    }
    slot = myc_result_arena_dup(res, where, 0);
    if (!slot)
        return;
    res->coaching[res->coaching_count].cls = cls;
    res->coaching[res->coaching_count].line = line;
    res->coaching[res->coaching_count].where = slot;
    res->coaching_count++;
    if (cls >= 0 && cls < MYC_TAX_COUNT)
        res->coaching_class_count[cls]++;
}

/* Urutan prioritas coaching (angka kecil = diprioritaskan). */
static int coach_priority(myc_taxonomy_class c)
{
    switch (c) {
    case MYC_TAX_HALLUCINATED_API: return 1;
    case MYC_TAX_MISSING_GUARD:    return 2;
    case MYC_TAX_OFF_BY_ONE:       return 3;
    case MYC_TAX_UB_ASSUMPTION:    return 4;
    case MYC_TAX_TYPE_CONFUSION:   return 5;
    case MYC_TAX_IGNORED_RETURN:   return 6;
    case MYC_TAX_WRONG_CONSTANT:   return 7;
    case MYC_TAX_CHURN:            return 8;
    default:                       return 9;
    }
}

/* Bubble sort stabil kecil: prioritas naik, lalu line naik. */
static void coach_sort(myc_result *res)
{
    int i, j;
    for (i = 0; i < res->coaching_count - 1; i++) {
        for (j = 0; j < res->coaching_count - 1 - i; j++) {
            myc_coaching_item *a = &res->coaching[j];
            myc_coaching_item *b = &res->coaching[j + 1];
            int pa = coach_priority(a->cls);
            int pb = coach_priority(b->cls);
            if (pa > pb || (pa == pb && a->line > b->line)) {
                myc_coaching_item t = *a;
                *a = *b;
                *b = t;
            }
        }
    }
}

void myc_coach_build(myc_result *res)
{
    int i;
    char linebuf[640];

    if (!res)
        return;
    res->coaching_count = 0;
    for (i = 0; i < MYC_TAX_COUNT; i++)
        res->coaching_class_count[i] = 0;

    /* Sumber: diagnostics terstruktur (gcc/lint/negative/contract). */
    for (i = 0; i < res->diag_count && res->coaching_count < MYC_MAX_COACHING;
         i++) {
        const myc_diagnostic *d = &res->diags[i];
        myc_taxonomy_class cls;
        if (!d->message)
            continue;
        cls = myc_taxonomy_classify(d->message);
        if (cls == MYC_TAX_UNCLASSIFIED)
            continue;
        if (d->line > 0)
            snprintf(linebuf, sizeof(linebuf), "line %d: %s",
                     d->line, d->message);
        else
            snprintf(linebuf, sizeof(linebuf), "%s", d->message);
        coach_add(res, cls, d->line, linebuf);
    }

    /* Sumber: witness (hard finding terkonfirmasi). */
    if (res->witness && res->witness->violation_msg &&
        res->coaching_count < MYC_MAX_COACHING) {
        myc_taxonomy_class cls =
            myc_taxonomy_classify(res->witness->violation_msg);
        if (cls != MYC_TAX_UNCLASSIFIED) {
            if (res->witness->violation_line > 0)
                snprintf(linebuf, sizeof(linebuf), "line %d: %s",
                         res->witness->violation_line,
                         res->witness->violation_msg);
            else
                snprintf(linebuf, sizeof(linebuf), "%s",
                         res->witness->violation_msg);
            coach_add(res, cls, res->witness->violation_line, linebuf);
        }
    }

    /* Sumber: delta ledger -- churn (kode diubah tanpa finding terkait). */
    if (res->delta_kind && strcmp(res->delta_kind, "churn") == 0 &&
        res->coaching_count < MYC_MAX_COACHING) {
        coach_add(res, MYC_TAX_CHURN, 0,
                  "delta: kode berubah tanpa finding terkonfirmasi "
                  "(fix-churn)");
    }

    coach_sort(res);

    if (res->coaching_count == 0)
        return;

    /* Transcript teks (ditulis untuk dibaca model, bukan manusia). */
    {
        char *rep = NULL;
        size_t replen = 0, repcap = 0;
        int n;
#define TAPPEND(s) do {                                                 \
            size_t _l = strlen(s);                                      \
            if (replen + _l + 1 > repcap) {                             \
                size_t ncap = repcap ? repcap * 2 : 1024;               \
                char *nb;                                               \
                while (ncap < replen + _l + 1)                          \
                    ncap *= 2;                                          \
                nb = (char *)realloc(rep, ncap);                        \
                if (!nb) {                                              \
                    free(rep);                                          \
                    rep = NULL;                                         \
                    replen = repcap = 0;                                \
                    goto done;                                          \
                }                                                       \
                rep = nb;                                               \
                repcap = ncap;                                          \
            }                                                           \
            memcpy(rep + replen, s, _l);                                \
            replen += _l;                                               \
            rep[replen] = '\0';                                         \
        } while (0)

        TAPPEND("coaching (B3, untuk model -- bukan manusia):\n");
        for (n = 0; n < res->coaching_count; n++) {
            const myc_coaching_item *c = &res->coaching[n];
            char head[512];
            snprintf(head, sizeof(head), "%d. [%s] %s\n   strategi: %s\n",
                     n + 1, myc_taxonomy_name(c->cls),
                     c->where ? c->where : "(lokasi tidak tersedia)",
                     myc_taxonomy_strategy(c->cls));
            TAPPEND(head);
        }
        TAPPEND("   (taksonomi = observasi; satu aksi utama saja per "
                "iterasi)\n");
done:
        if (rep) {
            res->coaching_report = myc_result_arena_dup(res, rep, 0);
            free(rep);
        }
    }
#undef TAPPEND
}
