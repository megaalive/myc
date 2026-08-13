/*
 * json.c -- Implementasi parser & serializer JSON minimal (P9, MCP server).
 *
 * Amati prinsip myc: source (data tidak tepercaya) hanya lewat stdin, parser
 * menolak input ganas (depth cap), tidak pernah menulis ke shell string.
 */
#include "json.h"

#include "alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------- dynamic buffer (json_sb) ------------------- */

int json_sb_init(json_sb *b)
{
    memset(b, 0, sizeof(*b));
    b->cap = 256;
    b->buf = (char *)myc_malloc(b->cap);
    if (!b->buf) {
        b->cap = 0;
        return 0;
    }
    return 1;
}

void json_sb_free(json_sb *b)
{
    myc_free(b->buf);
    b->buf = NULL;
    b->len = b->cap = 0;
}

/* Pastikan ada ruang ekstra >= need (di luar len, plus NUL).
 * Guard overflow: bila len+need+1 meluap size_t, gagal (bukan UB/korup). */
static int sb_reserve(json_sb *b, size_t need)
{
    size_t want = b->len + need + 1;
    if (want <= b->len)                     /* overflow size_t */
        return 0;
    if (want <= b->cap)
        return 1;
    {
        size_t ncap = b->cap ? b->cap : 256;
        char  *nb;
        if (ncap > (SIZE_MAX / 2))
            return 0;
        while (ncap < want) {
            if (ncap > (SIZE_MAX / 2)) {
                ncap = want;
                break;
            }
            ncap *= 2;
        }
        nb = (char *)myc_realloc(b->buf, ncap);
        if (!nb)
            return 0;
        b->buf = nb;
        b->cap = ncap;
    }
    return 1;
}

int json_sb_putc(json_sb *b, char c)
{
    if (!sb_reserve(b, 1))
        return 0;
    b->buf[b->len++] = c;
    return 1;
}

int json_sb_puts(json_sb *b, const char *s)
{
    size_t n = strlen(s);
    if (!sb_reserve(b, n))
        return 0;
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    return 1;
}

int json_sb_printf(json_sb *b, const char *fmt, ...)
{
    va_list ap;
    int     n;
    if (!sb_reserve(b, 128))
        return 0;
    va_start(ap, fmt);
    n = vsnprintf(b->buf + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    if (n < 0)
        return 0;
    if ((size_t)n >= b->cap - b->len) {
        if (!sb_reserve(b, (size_t)n))
            return 0;
        va_start(ap, fmt);
        n = vsnprintf(b->buf + b->len, b->cap - b->len, fmt, ap);
        va_end(ap);
        if (n < 0)
            return 0;
    }
    b->len += (size_t)n;
    return 1;
}

/* ------------------------- parser ---------------------------- */

typedef struct {
    const char *p;
    const char *end;
    int depth;
    int failed;
} jp;

static void skip_ws(jp *j)
{
    while (j->p < j->end &&
           (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r'))
        j->p++;
}

static json_value *val_new(json_type t)
{
    json_value *v = (json_value *)myc_calloc(1, sizeof(*v));
    if (v)
        v->type = t;
    return v;
}

static json_value *parse_value(jp *j);

/* Validasi satu urutan UTF-8 mulai dari p (byte pertama harus memulai
 * urutan valid). Majukan p melewati seluruh codepoint bila valid dan
 * mengembalikan panjang (1..4); kembalikan 0 bila invalid/terpotong.
 * Menolak: overlong, byte kontinu tanpa lead, lead terpotong di akhir,
 * surrogate U+D800..DFFF yang di-encode sebagai UTF-8. */
static size_t utf8_valid(const char *p, const char *end)
{
    const unsigned char *u = (const unsigned char *)p;
    size_t n;
    unsigned long cp;
    if (u >= (const unsigned char *)end)
        return 0;
    if (u[0] < 0x80)
        return 1;
    if (u[0] >= 0xC2 && u[0] <= 0xDF) {
        n = 2;
        cp = (unsigned long)(u[0] & 0x1F);
    } else if (u[0] >= 0xE0 && u[0] <= 0xEF) {
        n = 3;
        cp = (unsigned long)(u[0] & 0x0F);
    } else if (u[0] >= 0xF0 && u[0] <= 0xF4) {
        n = 4;
        cp = (unsigned long)(u[0] & 0x07);
    } else {
        return 0;                       /* byte kontinu / 0xC0/0xC1 / 0xF5+ */
    }
    if (end - p < (ptrdiff_t)n)
        return 0;                       /* terpotong di akhir */
    {
        size_t k;
        for (k = 1; k < n; k++) {
            if ((u[k] & 0xC0) != 0x80)
                return 0;
            cp = (cp << 6) | (unsigned long)(u[k] & 0x3F);
        }
    }
    /* cegah overlong: cp >= nilai minimum utk n byte */
    if (n == 2 && cp < 0x80) return 0;
    if (n == 3 && cp < 0x800) return 0;
    if (n == 4 && cp < 0x10000) return 0;
    /* cek surrogate (U+D800..UDPFF) tak boleh lewat UTF-8 */
    if (cp >= 0xD800 && cp <= 0xDFFF) return 0;
    return n;
}

/* string JSON: '"' ... '"' dengan escape dan \uXXXX (incl. surrogate pair).
 * Mengembalikan json_value tipe JSON_STR atau NULL (set failed). */
static json_value *parse_string(jp *j)
{
    json_sb sb;
    int     closed = 0;
    if (j->p >= j->end || *j->p != '"') {
        j->failed = 1;
        return NULL;
    }
    j->p++;
    if (!json_sb_init(&sb)) {
        j->failed = 1;
        return NULL;
    }
    while (j->p < j->end) {
        unsigned char c = (unsigned char)*j->p;
        if (c == '"') {
            j->p++;
            closed = 1;
            break;
        }
        if (c == '\\') {
            j->p++;
            if (j->p >= j->end) {
                j->failed = 1;
                json_sb_free(&sb);
                return NULL;
            }
            c = (unsigned char)*j->p++;
            switch (c) {
            case '"': case '\\': case '/':
                json_sb_putc(&sb, (char)c);
                break;
            case 'b': json_sb_putc(&sb, '\b'); break;
            case 'f': json_sb_putc(&sb, '\f'); break;
            case 'n': json_sb_putc(&sb, '\n'); break;
            case 'r': json_sb_putc(&sb, '\r'); break;
            case 't': json_sb_putc(&sb, '\t'); break;
            case 'u': {
                unsigned long cp = 0;
                int k;
                for (k = 0; k < 4; k++) {
                    unsigned char h;
                    if (j->p >= j->end) {
                        j->failed = 1;
                        json_sb_free(&sb);
                        return NULL;
                    }
                    h = (unsigned char)*j->p++;
                    cp <<= 4;
                    if (h >= '0' && h <= '9') cp |= (unsigned long)(h - '0');
                    else if (h >= 'a' && h <= 'f') cp |= (unsigned long)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') cp |= (unsigned long)(h - 'A' + 10);
                    else {
                        j->failed = 1;
                        json_sb_free(&sb);
                        return NULL;
                    }
                }
                /* surrogate pair */
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    /* high surrogate: WAJIB diikuti '\u' + low surrogate;
                     * lone high-surrogate invalid. */
                    if (j->end - j->p >= 6 && j->p[0] == '\\' && j->p[1] == 'u') {
                        const char   *save = j->p;
                        unsigned long lo = 0;
                        int ok = 1;
                        j->p += 2;
                        for (k = 0; k < 4; k++) {
                            unsigned char h;
                            if (j->p >= j->end) { ok = 0; break; }
                            h = (unsigned char)*j->p++;
                            lo <<= 4;
                            if (h >= '0' && h <= '9') lo |= (unsigned long)(h - '0');
                            else if (h >= 'a' && h <= 'f') lo |= (unsigned long)(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') lo |= (unsigned long)(h - 'A' + 10);
                            else { ok = 0; break; }
                        }
                        if (ok && lo >= 0xDC00 && lo <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        } else {
                            /* bukan low surrogate --> lone high surrogate */
                            j->p = save;
                            j->failed = 1;
                            json_sb_free(&sb);
                            return NULL;
                        }
                    } else {
                        j->failed = 1;
                        json_sb_free(&sb);
                        return NULL;
                    }
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    /* lone low surrogate tanpa high: invalid */
                    j->failed = 1;
                    json_sb_free(&sb);
                    return NULL;
                } else if (cp == 0) {
                    /* \u0000 = embedded NUL: consumer memakai strlen sehingga
                     * string akan terpotong diam-diam --> tolak. */
                    j->failed = 1;
                    json_sb_free(&sb);
                    return NULL;
                }
                /* encode UTF-8 */
                if (cp < 0x80)
                    json_sb_putc(&sb, (char)cp);
                else if (cp < 0x800) {
                    json_sb_putc(&sb, (char)(0xC0 | (cp >> 6)));
                    json_sb_putc(&sb, (char)(0x80 | (cp & 0x3F)));
                } else if (cp < 0x10000) {
                    json_sb_putc(&sb, (char)(0xE0 | (cp >> 12)));
                    json_sb_putc(&sb, (char)(0x80 | ((cp >> 6) & 0x3F)));
                    json_sb_putc(&sb, (char)(0x80 | (cp & 0x3F)));
                } else {
                    json_sb_putc(&sb, (char)(0xF0 | (cp >> 18)));
                    json_sb_putc(&sb, (char)(0x80 | ((cp >> 12) & 0x3F)));
                    json_sb_putc(&sb, (char)(0x80 | ((cp >> 6) & 0x3F)));
                    json_sb_putc(&sb, (char)(0x80 | (cp & 0x3F)));
                }
                break;
            }
            default:
                j->failed = 1;
                json_sb_free(&sb);
                return NULL;
            }
        } else if (c < 0x20) {
            j->failed = 1;
            json_sb_free(&sb);
            return NULL;
        } else if (c >= 0x80) {
            /* byte multibyte: harus berupa urutan UTF-8 valid, dan
             * salin SEMUA byte urutan itu (bukan hanya lead byte). */
            size_t nb = utf8_valid(j->p, j->end);
            size_t k;
            if (nb == 0) {
                j->failed = 1;
                json_sb_free(&sb);
                return NULL;
            }
            for (k = 0; k < nb; k++) {
                if (!json_sb_putc(&sb, (char)j->p[k])) {
                    j->failed = 1;
                    json_sb_free(&sb);
                    return NULL;
                }
            }
            j->p += nb;
        } else {
            json_sb_putc(&sb, (char)c);
            j->p++;
        }
    }
    if (!closed) {
        j->failed = 1;
        json_sb_free(&sb);
        return NULL;
    }
    if (!json_sb_putc(&sb, '\0')) {
        j->failed = 1;
        json_sb_free(&sb);
        return NULL;
    }
    {
        json_value *v = val_new(JSON_STR);
        if (!v) {
            json_sb_free(&sb);
            j->failed = 1;
            return NULL;
        }
        v->str = sb.buf;
        return v;
    }
}

/* number: konsumsi JSON number grammar, simpan bagian integer (int64).
 * Akumulasi dengan uint64 agar -2^63 (INT64_MIN) bisa direpresentasikan;
 * saturasi saat overflow (angka raksasa dibatasi, bukan UB). */
static json_value *parse_number(jp *j)
{
    const char *s = j->p;
    int         neg = 0;
    uint64_t    acc = 0;
    int         digits = 0;
    int64_t     val;
    json_value *v;
    if (s < j->end && *s == '-') {
        neg = 1;
        s++;
    }
    /* Strict (RFC 8259): "0" polos TANPA leading zero; angka >1 digit
     * harus diawali digit 1-9. */
    if (s < j->end && *s == '0') {
        /* "0" boleh, tetapi "0x" / "01" TIDAK: digit berikutnya harus bukan
         * angka (diproses nanti oleh caller sebagai delimiter). */
        acc = 0;
        digits = 1;
        s++;
    } else {
        while (s < j->end && *s >= '0' && *s <= '9') {
            unsigned d = (unsigned)(*s - '0');
            if (acc > (UINT64_MAX - d) / 10)
                acc = UINT64_MAX;       /* saturasi */
            else
                acc = acc * 10 + d;
            digits++;
            s++;
        }
    }
    if (!digits) {
        j->failed = 1;
        return NULL;
    }
    /* Strict: bila int dimulai dengan '0' dan kini diikuti digit lain
     * (mis. "01": s memunjuk '1'), tolak (leading zero). */
    if (digits == 1 && s - j->p - (neg ? 1 : 0) == 1 &&
        s[-1] == '0' && s < j->end && *s >= '0' && *s <= '9') {
        j->failed = 1;
        return NULL;
    }
    if (s < j->end && *s == '.') {
        /* Strict: fraction WAJIB minimal satu digit setelah '.'. */
        s++;
        if (s >= j->end || *s < '0' || *s > '9') {
            j->failed = 1;
            return NULL;
        }
        while (s < j->end && *s >= '0' && *s <= '9')
            s++;
    }
    if (s < j->end && (*s == 'e' || *s == 'E')) {
        /* Strict: exponent WAJIB minimal satu digit setelah [sign]. */
        s++;
        if (s < j->end && (*s == '+' || *s == '-'))
            s++;
        if (s >= j->end || *s < '0' || *s > '9') {
            j->failed = 1;
            return NULL;
        }
        while (s < j->end && *s >= '0' && *s <= '9')
            s++;
    }
    if (neg) {
        /* acc == 2^63 (INT64_MIN) harus dipetakan langsung, jangan
         * dinegasi (meng-negasi INT64_MIN = signed overflow / UB). */
        if (acc >= ((uint64_t)1 << 63))
            val = INT64_MIN;
        else
            val = -(int64_t)acc;   /* aman: acc <= 2^63 - 1 */
    } else {
        val = acc > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)acc;
    }
    v = val_new(JSON_NUM);
    if (!v) {
        j->failed = 1;
        return NULL;
    }
    v->num = val;
    j->p = s;
    return v;
}

static json_value *parse_array(jp *j)
{
    json_value *arr;
    if (j->p >= j->end || *j->p != '[') {
        j->failed = 1;
        return NULL;
    }
    j->p++;
    arr = val_new(JSON_ARR);
    if (!arr) {
        j->failed = 1;
        return NULL;
    }
    if (j->depth >= JSON_MAX_DEPTH) {
        j->failed = 1;
        json_free(arr);
        return NULL;
    }
    j->depth++;
    skip_ws(j);
    if (j->p < j->end && *j->p == ']') {
        j->p++;
        j->depth--;
        return arr;
    }
    for (;;) {
        json_value *item = parse_value(j);
        if (!item) {
            j->failed = 1;
            json_free(arr);
            return NULL;
        }
        json_arr_push(arr, item);
        skip_ws(j);
        if (j->p >= j->end) {
            j->failed = 1;
            json_free(arr);
            return NULL;
        }
        if (*j->p == ',') {
            j->p++;
            skip_ws(j);
            continue;
        }
        if (*j->p == ']') {
            j->p++;
            j->depth--;
            return arr;
        }
        j->failed = 1;
        json_free(arr);
        return NULL;
    }
}

static json_value *parse_object(jp *j)
{
    json_value *obj;
    if (j->p >= j->end || *j->p != '{') {
        j->failed = 1;
        return NULL;
    }
    j->p++;
    obj = val_new(JSON_OBJ);
    if (!obj) {
        j->failed = 1;
        return NULL;
    }
    if (j->depth >= JSON_MAX_DEPTH) {
        j->failed = 1;
        json_free(obj);
        return NULL;
    }
    j->depth++;
    skip_ws(j);
    if (j->p < j->end && *j->p == '}') {
        j->p++;
        j->depth--;
        return obj;
    }
    for (;;) {
        json_value *key;
        json_value *val;
        skip_ws(j);
        key = parse_string(j);
        if (!key || key->type != JSON_STR) {
            json_free(key);
            j->failed = 1;
            json_free(obj);
            return NULL;
        }
        skip_ws(j);
        if (j->p >= j->end || *j->p != ':') {
            json_free(key);
            j->failed = 1;
            json_free(obj);
            return NULL;
        }
        j->p++;
        val = parse_value(j);
        if (!val) {
            json_free(key);
            j->failed = 1;
            json_free(obj);
            return NULL;
        }
        json_obj_set(obj, key->str, val);
        json_free(key);
        skip_ws(j);
        if (j->p >= j->end) {
            j->failed = 1;
            json_free(obj);
            return NULL;
        }
        if (*j->p == ',') {
            j->p++;
            continue;
        }
        if (*j->p == '}') {
            j->p++;
            j->depth--;
            return obj;
        }
        j->failed = 1;
        json_free(obj);
        return NULL;
    }
}

static json_value *parse_value(jp *j)
{
    skip_ws(j);
    if (j->p >= j->end) {
        j->failed = 1;
        return NULL;
    }
    switch (*j->p) {
    case '{':
        return parse_object(j);
    case '[':
        return parse_array(j);
    case '"':
        return parse_string(j);
    case 't':
        if (j->end - j->p >= 4 && memcmp(j->p, "true", 4) == 0) {
            json_value *v = val_new(JSON_BOOL);
            if (!v) { j->failed = 1; return NULL; }
            v->boolean = 1;
            j->p += 4;
            return v;
        }
        break;
    case 'f':
        if (j->end - j->p >= 5 && memcmp(j->p, "false", 5) == 0) {
            json_value *v = val_new(JSON_BOOL);
            if (!v) { j->failed = 1; return NULL; }
            v->boolean = 0;
            j->p += 5;
            return v;
        }
        break;
    case 'n':
        if (j->end - j->p >= 4 && memcmp(j->p, "null", 4) == 0) {
            json_value *v = val_new(JSON_NULL);
            if (!v) { j->failed = 1; return NULL; }
            j->p += 4;
            return v;
        }
        break;
    default:
        if (*j->p == '-' || (*j->p >= '0' && *j->p <= '9'))
            return parse_number(j);
        break;
    }
    j->failed = 1;
    return NULL;
}

int json_parse(const char *text, size_t len, json_value **out)
{
    jp          j;
    json_value *v;
    *out = NULL;
    j.p = text;
    j.end = text + len;
    j.depth = 0;
    j.failed = 0;
    v = parse_value(&j);
    if (!v || j.failed) {
        json_free(v);
        return 0;
    }
    skip_ws(&j);
    if (j.p != j.end) {
        json_free(v);
        return 0;
    }
    *out = v;
    return 1;
}

int json_parse_cstr(const char *text, json_value **out)
{
    return json_parse(text, strlen(text), out);
}

void json_free(json_value *v)
{
    size_t i;
    if (!v)
        return;
    switch (v->type) {
    case JSON_STR:
        myc_free(v->str);
        break;
    case JSON_ARR:
        for (i = 0; i < v->len; i++)
            json_free(v->items[i]);
        myc_free(v->items);
        break;
    case JSON_OBJ:
        for (i = 0; i < v->mlen; i++) {
            myc_free(v->members[i].key);
            json_free(v->members[i].val);
        }
        myc_free(v->members);
        break;
    default:
        break;
    }
    myc_free(v);
}

/* ------------------------- akses ---------------------------- */

json_value *json_get(const json_value *obj, const char *key)
{
    size_t i;
    if (!obj || obj->type != JSON_OBJ || !key)
        return NULL;
    for (i = 0; i < obj->mlen; i++)
        if (strcmp(obj->members[i].key, key) == 0)
            return obj->members[i].val;
    return NULL;
}

const char *json_get_str(const json_value *obj, const char *key)
{
    json_value *v = json_get(obj, key);
    if (!v || v->type != JSON_STR)
        return NULL;
    return v->str;
}

/* ------------------------- konstruksi ---------------------------- */

static char *dup_str(const char *s)
{
    size_t n = strlen(s) + 1;
    char  *d = (char *)myc_malloc(n);
    if (d)
        memcpy(d, s, n);
    return d;
}

json_value *json_new_obj(void)
{
    return val_new(JSON_OBJ);
}

json_value *json_new_arr(void)
{
    return val_new(JSON_ARR);
}

json_value *json_new_null(void)
{
    return val_new(JSON_NULL);
}

json_value *json_new_bool(int b)
{
    json_value *v = val_new(JSON_BOOL);
    if (v)
        v->boolean = b ? 1 : 0;
    return v;
}

json_value *json_new_num(int64_t n)
{
    json_value *v = val_new(JSON_NUM);
    if (v)
        v->num = n;
    return v;
}

json_value *json_new_str(const char *s)
{
    json_value *v = val_new(JSON_STR);
    if (!v)
        return NULL;
    v->str = dup_str(s ? s : "");
    if (!v->str) {
        myc_free(v);
        return NULL;
    }
    return v;
}

void json_obj_set(json_value *obj, const char *key, json_value *val)
{
    size_t i;
    if (!obj || obj->type != JSON_OBJ || !key || !val)
        return;
    for (i = 0; i < obj->mlen; i++) {
        if (strcmp(obj->members[i].key, key) == 0) {
            myc_free(obj->members[i].key);
            json_free(obj->members[i].val);
            obj->members[i].key = dup_str(key);
            obj->members[i].val = val;
            return;
        }
    }
    if (obj->mlen == obj->mcap) {
        size_t      ncap = obj->mcap ? obj->mcap : 8;
        json_member *nm;
        if (ncap > (SIZE_MAX / 2)) {
            json_free(val);
            return;
        }
        ncap *= 2;
        nm = (json_member *)myc_realloc(obj->members,
                                    ncap * sizeof(*nm));
        if (!nm) {
            json_free(val);
            return;
        }
        obj->members = nm;
        obj->mcap = ncap;
    }
    obj->members[obj->mlen].key = dup_str(key);
    if (!obj->members[obj->mlen].key) {
        json_free(val);
        return;
    }
    obj->members[obj->mlen].val = val;
    obj->mlen++;
}

void json_arr_push(json_value *arr, json_value *v)
{
    if (!arr || arr->type != JSON_ARR || !v) {
        json_free(v);
        return;
    }
    if (arr->len == arr->cap) {
        size_t          ncap = arr->cap ? arr->cap : 8;
        json_value    **ni;
        if (ncap > (SIZE_MAX / 2)) {
            json_free(v);
            return;
        }
        ncap *= 2;
        ni = (json_value **)myc_realloc(arr->items, ncap * sizeof(*ni));
        if (!ni) {
            json_free(v);
            return;
        }
        arr->items = ni;
        arr->cap = ncap;
    }
    arr->items[arr->len++] = v;
}

/* ------------------------- serializer ---------------------------- */

static int ser_escape(json_sb *b, const char *s)
{
    if (!s)
        return json_sb_puts(b, "\"\"");
    if (!json_sb_putc(b, '"'))
        return 0;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':
            if (!json_sb_puts(b, "\\\"")) return 0;
            break;
        case '\\':
            if (!json_sb_puts(b, "\\\\")) return 0;
            break;
        case '\n':
            if (!json_sb_puts(b, "\\n")) return 0;
            break;
        case '\r':
            if (!json_sb_puts(b, "\\r")) return 0;
            break;
        case '\t':
            if (!json_sb_puts(b, "\\t")) return 0;
            break;
        default:
            if (c < 0x20) {
                if (!json_sb_printf(b, "\\u%04x", (unsigned)c)) return 0;
            } else if (c < 0x80) {
                if (!json_sb_putc(b, (char)c)) return 0;
            } else {
                /* Byte >= 0x80: parser (utf8_valid) HANYA menerima urutan
                 * UTF-8 valid; menulis byte non-UTF8 mentah membuat JSON
                 * tidak bisa di-parse ulang (cache round-trip rusak,
                 * MYC-AUDIT-042). UTF-8 valid disalin apa adanya;
                 * byte/sequence invalid di-escape \u00XX agar round-trip
                 * deterministik. */
                size_t nb = 0;
                size_t k;
                int    ok;
                if (c >= 0xC2 && c <= 0xDF)      nb = 2;
                else if (c >= 0xE0 && c <= 0xEF) nb = 3;
                else if (c >= 0xF0 && c <= 0xF4) nb = 4;
                ok = (nb >= 2);
                for (k = 1; ok && k < nb; k++) {
                    unsigned char cc = (unsigned char)s[k];
                    if (cc == 0 || (cc & 0xC0) != 0x80)
                        ok = 0;
                }
                if (ok) {
                    for (k = 0; k < nb; k++)
                        if (!json_sb_putc(b, s[k])) return 0;
                    s += nb - 1;
                } else {
                    if (!json_sb_printf(b, "\\u%04x", (unsigned)c)) return 0;
                }
            }
            break;
        }
    }
    return json_sb_putc(b, '"');
}

static int ser_value(json_sb *b, const json_value *v)
{
    size_t i;
    if (!v)
        return json_sb_puts(b, "null");
    switch (v->type) {
    case JSON_NULL:
        return json_sb_puts(b, "null");
    case JSON_BOOL:
        return json_sb_puts(b, v->boolean ? "true" : "false");
    case JSON_NUM:
        return json_sb_printf(b, "%lld", (long long)v->num);
    case JSON_STR:
        return ser_escape(b, v->str);
    case JSON_ARR:
        if (!json_sb_putc(b, '['))
            return 0;
        for (i = 0; i < v->len; i++) {
            if (i && !json_sb_putc(b, ','))
                return 0;
            if (!ser_value(b, v->items[i]))
                return 0;
        }
        return json_sb_putc(b, ']');
    case JSON_OBJ:
        if (!json_sb_putc(b, '{'))
            return 0;
        for (i = 0; i < v->mlen; i++) {
            if (i && !json_sb_putc(b, ','))
                return 0;
            if (!ser_escape(b, v->members[i].key))
                return 0;
            if (!json_sb_putc(b, ':'))
                return 0;
            if (!ser_value(b, v->members[i].val))
                return 0;
        }
        return json_sb_putc(b, '}');
    }
    return 0;
}

int json_serialize(const json_value *v, char **out)
{
    json_sb b;
    *out = NULL;
    if (!json_sb_init(&b))
        return 0;
    if (!ser_value(&b, v)) {
        json_sb_free(&b);
        return 0;
    }
    if (!json_sb_putc(&b, '\0')) {
        json_sb_free(&b);
        return 0;
    }
    *out = b.buf;
    return 1;
}

json_value *json_clone(const json_value *v)
{
    size_t i;
    if (!v)
        return NULL;
    switch (v->type) {
    case JSON_NULL:
        return json_new_null();
    case JSON_BOOL:
        return json_new_bool(v->boolean);
    case JSON_NUM:
        return json_new_num(v->num);
    case JSON_STR:
        return json_new_str(v->str ? v->str : "");
    case JSON_ARR: {
        json_value *a = json_new_arr();
        if (!a)
            return NULL;
        for (i = 0; i < v->len; i++) {
            json_value *c = json_clone(v->items[i]);
            if (!c) {
                json_free(a);
                return NULL;
            }
            json_arr_push(a, c);
        }
        return a;
    }
    case JSON_OBJ: {
        json_value *o = json_new_obj();
        if (!o)
            return NULL;
        for (i = 0; i < v->mlen; i++) {
            json_value *c = json_clone(v->members[i].val);
            if (!c) {
                json_free(o);
                return NULL;
            }
            json_obj_set(o, v->members[i].key, c);
        }
        return o;
    }
    }
    return NULL;
}
