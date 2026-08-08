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
