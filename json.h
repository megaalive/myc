/*
 * json.h -- Parser & serializer JSON minimal untuk MCP server (P9).
 *
 * Tidak bergantung pustaka eksternal. Mendukung objek, array, string
 * (dengan escape + \uXXXX, termasuk surrogate pair), integer, true/false/null.
 * Parser KETAT (Fase 6, MYC-AUDIT-009): menolak leading zero, fraction/
 * exponent tanpa digit, lone surrogate, embedded NUL, dan raw UTF-8 invalid;
 * string length-aware (bukan strlen) dan kapasitas dilindungi overflow.
 * Depth dibatasi (JSON_MAX_DEPTH) untuk menolak input ganas tanpa stack
 * overflow. Angka disimpan sebagai int64 (bagian pecahan dibuang).
 *
 * Semua komentar ditulis dalam Bahasa Indonesia; identifier berbahasa Inggris.
 */
#ifndef MYC_JSON_H
#define MYC_JSON_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#define JSON_MAX_DEPTH 64

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUM,
    JSON_STR,
    JSON_ARR,
    JSON_OBJ
} json_type;

typedef struct json_value json_value;

typedef struct {
    char       *key;
    json_value *val;
} json_member;

struct json_value {
    json_type    type;
    int          boolean;
    int64_t      num;
    char        *str;
    json_value **items;
    size_t       len, cap;
    json_member *members;
    size_t       mlen, mcap;
};

/* Dynamic buffer untuk membangun string (JSON, context, MCP teks).
 * P3: ini myc_sb bersama — context.c tidak menyalin builder. */
typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} json_sb;
typedef json_sb myc_sb;

int  json_sb_init(json_sb *b);
void json_sb_free(json_sb *b);
int  json_sb_putc(json_sb *b, char c);
int  json_sb_puts(json_sb *b, const char *s);
int  json_sb_append(json_sb *b, const char *s, size_t n);
int  json_sb_printf(json_sb *b, const char *fmt, ...);
/* Ambil ownership buf (NUL-terminated). Caller myc_free. */
char *json_sb_steal(json_sb *b);

/* Parse satu nilai JSON dari teks [len]. Sukses -> 1, *out diisi (harus
 * json_free). Gagal -> 0, *out = NULL. */
int json_parse(const char *text, size_t len, json_value **out);

/* Parse dari teks NUL-terminated. */
int json_parse_cstr(const char *text, json_value **out);

void json_free(json_value *v);

/* Akses member objek; NULL bila bukan objek / key tak ada. */
json_value *json_get(const json_value *obj, const char *key);
/* Nilai string member; NULL bila bukan string. */
const char *json_get_str(const json_value *obj, const char *key);

/* Konstruksi (untuk membangun respons). */
json_value *json_new_obj(void);
json_value *json_new_arr(void);
json_value *json_new_str(const char *s);
json_value *json_new_num(int64_t n);
json_value *json_new_bool(int b);
json_value *json_new_null(void);
void json_obj_set(json_value *obj, const char *key, json_value *val);
void json_arr_push(json_value *arr, json_value *v);

/* Serialisasi ke string malloc'd (diakhiri NUL). Sukses -> 1. */
int json_serialize(const json_value *v, char **out);

/* Klon pohon JSON (deep copy). NULL bila gagal alokasi. */
json_value *json_clone(const json_value *v);

#endif /* MYC_JSON_H */
