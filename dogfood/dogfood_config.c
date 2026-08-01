/*
 * dogfood_config.c -- Tool dogfooding lintas-program myc (aturan AGENTS.md).
 *
 * Parser konfigurasi key=value sederhana (relevan: aplikasi web/server —
 * membaca blok config "port=8080\nhost=..."). Murni API whitelist
 * (stdio/stdlib/string), tanpa system/fopen. Ditulis dan diperiksa dengan
 * myc untuk mematangkan jalur "lolos" (OK) pada kode yang sah.
 *
 * Uji nyata yang melatih myc:
 *   - realloc idiom aman ke MEMBER struct (`cfg->items = tmp`) — regresi
 *     perbaikan lint.c P7 (read_arg_ident/ident_before membaca rantai
 *     member), sehingga tidak boleh false VIOLATION;
 *   - copy byte memakai loop eksplisit (bukan memcpy tanpa sizeof) agar lint
 *     tidak memberi warning bounds;
 *   - alokasi dengan sizeof eksplisit (tidak ada multiplikasi tanpa sizeof).
 *   - `--run` harus L3 RUNTIME (program executable, ASan bersih).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CFG_MAX_ENTRIES 64
#define CFG_KEY_MAX     32
#define CFG_VAL_MAX     128
#define CFG_LINE_MAX    256

struct entry {
    char key[CFG_KEY_MAX];
    char value[CFG_VAL_MAX];
};

struct config {
    struct entry *items;
    size_t        count;
    size_t        cap;
};

/* Salin string dengan batas maks; return 0 bila terpotong (terlalu panjang).
 * Copy per-byte (bukan snprintf) agar gcc -Werror=format-truncation tidak
 * bising; bukan memcpy tanpa sizeof agar lint tidak memberi warning bounds. */
static int copy_bounded(char *dst, size_t dstcap,
                        const char *src)
{
    size_t n = 0;
    while (n + 1 < dstcap && src[n]) {
        dst[n] = src[n];
        n++;
    }
    if (src[n])
        return 0;                   /* tidak muat */
    dst[n] = '\0';
    return 1;
}

/* Tambah satu entri. Idiom realloc aman: tmp -> lalu sinkronkan member. */
static int config_add(struct config *cfg, const char *key, const char *value)
{
    struct entry *tmp;
    size_t        ncap;
    struct entry *e;

    if (cfg->count == cfg->cap) {
        ncap = cfg->cap ? cfg->cap * 2 : 8;
        if (ncap > CFG_MAX_ENTRIES)
            ncap = CFG_MAX_ENTRIES;
        /* batas entri tercapai: JANGAN tumbuh ke kapasitas yang sama lalu
         * menulis items[count] (OOB). Gagal saja, bukan overflow. */
        if (ncap <= cfg->cap)
            return 0;
        tmp = (struct entry *)realloc(cfg->items, ncap * sizeof(*tmp));
        if (!tmp)
            return 0;
        cfg->items = tmp;
        cfg->cap = ncap;
    }
    e = &cfg->items[cfg->count];
    if (!copy_bounded(e->key, sizeof(e->key), key))
        return 0;
    if (!copy_bounded(e->value, sizeof(e->value), value))
        return 0;
    cfg->count++;
    return 1;
}

/* Parse blok "key=value" satu per baris; abaikan baris kosong/komentar #. */
static int config_parse(struct config *cfg, const char *text)
{
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t      linelen = nl ? (size_t)(nl - p) : strlen(p);
        char        line[CFG_LINE_MAX];
        char       *eq;
        size_t      i;

        if (linelen == 0 || *p == '#') {
            p = nl ? nl + 1 : p + linelen;
            continue;
        }
        if (linelen >= sizeof(line))
            linelen = sizeof(line) - 1;
        for (i = 0; i < linelen; i++)
            line[i] = p[i];
        line[linelen] = '\0';

        eq = strchr(line, '=');
        if (eq) {
            *eq = '\0';
            if (!config_add(cfg, line, eq + 1))
                return 0;
        }
        p = nl ? nl + 1 : p + linelen;
    }
    return 1;
}

/* Hitung total nilai numerik (mis. port + workers). */
static unsigned long config_sum_numeric(const struct config *cfg)
{
    unsigned long total = 0;
    size_t        i;
    for (i = 0; i < cfg->count; i++)
        total += strtoul(cfg->items[i].value, NULL, 10);
    return total;
}

int main(void)
{
    static const char conf[] =
        "# server demo\n"
        "port=8080\n"
        "workers=4\n"
        "retries=2\n";
    struct config cfg;
    unsigned long total;

    memset(&cfg, 0, sizeof(cfg));
    if (!config_parse(&cfg, conf)) {
        printf("parse gagal\n");
        return 1;
    }
    total = config_sum_numeric(&cfg);
    printf("entries=%llu total=%lu\n",
           (unsigned long long)cfg.count, total);

    free(cfg.items);
    return 0;
}
