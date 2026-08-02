/*
 * json_abuse.c -- Regression Fase 6 (MYC-AUDIT-009): parser JSON ketat & aman.
 *
 * Menjaga: parser menolak JSON invalid (strict number grammar, lone
 * surrogate, embedded NUL, UTF-8 invalid), tidak crash, tidak hang, dan
 * tidak memotong string diam-diam. Serializer harus menghasilkan JSON valid.
 *
 * Build:
 *   gcc -O2 -std=c11 -Wall -Wextra -o json_abuse.exe json_abuse.c json.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

typedef struct {
    const char *label;
    const char *input;
    int         expect;   /* 1 = valid, 0 = invalid */
} corpus_case;

static const corpus_case CORPUS[] = {
    /* --- valid --- */
    { "object dasar",            "{\"a\":1,\"b\":[true,null,\"x\"]}", 1 },
    { "array",                   "[1,2,3]",                             1 },
    { "string normal",           "\"hello\"",                           1 },
    { "string escape",           "\"a\\\"b\\\\c\\/d\\b\\f\\n\\r\\t\"",  1 },
    { "string unicode BMP",      "\"\\u0041\\u00e9\\u4e2d\"",           1 }, /* A é 中 */
    { "string surrogate pair",   "\"\\uD83D\\uDE00\"",                  1 }, /* 😀 */
    { "integer positif",         "42",                                  1 },
    { "integer negatif",         "-17",                                 1 },
    { "nol",                     "0",                                   1 },
    { "negatif nol",             "-0",                                  1 },
    { "desimal",                 "3.14",                                1 },
    { "eksponen",                "1e5",                                 1 },
    { "eksponen sign",           "1e+5",                                1 },
    { "eksponen neg",            "1e-5",                                1 },
    { "frac lalu exp",           "3.14e-2",                             1 },
    { "true/false/null",         "null",                                1 },
    { "nested array",            "[[[[1]]]]",                            1 },
    { "raw utf8 2byte",          "\"\xc3\xa9\"",                         1 }, // "é"
    { "raw utf8 3byte",          "\"\xe4\xb8\xad\"",                      1 },   // "中"
    { "raw utf8 smilies 4byte",  "\"\xf0\x9f\x98\x80\"",                   1 },  // 😀

    /* ---- invalid (harus ditolak) ---- */
    { "leading zero",            "01",                                   0 },
    { "leading zero via minus",  "-01",                                  0 },
    { "fraction tanpa digit",    "1.",                                   0 },
    { "eksponen tanpa digit",    "1e",                                   0 },
    { "eksponen tanpa digit sign", "1e+",                                0 },
    { "eksponen neg tanpa digit","1e-",                                  0 },
    { "dot saja",                ".5",                                   0 },
    { "minus saja",              "-",                                    0 },
    { "key tak ber-string",      "{a:1}",                                0 },
    { "object tanpa colon",     "{\"a\" 1}",                             0 },
    { "trailing comma",          "[1,2,]",                               0 },
    { "double comma",            "[1,,2]",                               0 },
    { "unclosed object",         "{\"a\":1",                             0 },
    { "unclosed array",          "[1,2",                                 0 },
    { "unclosed string",         "\"abc",                                0 },
    { "lone high surrogate",     "\"\\uD800\"",                          0 },
    { "lone low surrogate",      "\"\\uDC00\"",                          0 },
    { "high+nonlow surrogate",   "\"\\uD800\\u0041\"",                   0 },
    { "embedded NUL",            "\"\\u0000\"",                          0 },
    { "loose utf8 cont",         "\"\x80\"",                             0 },
    { "utf8 0xC0 (overlong)",    "\"\xc0\x80\"",                         0 },
    { "utf8 0xC1 (overlong)",    "\"\xc1\xbf\"",                         0 },
    { "utf8 surrogate encode",   "\"\\xED\\xA0\x80\"",                    0 },   /* uD800 in UTF-8 */
    { "truncated utf8 lead",     "\"\xf0\x9f\x98\"",                     0 },
    { "utf8 0xFF",               "\"\xff\"",                             0 },
    { "bad escape",              "\"\\q\"",                              0 },
    { "escaped newline",         "\"\\uD8\"",                            0 },
    { "raw control char",        "\"\x01\"",                             0 },
    { "trailing garbage",        "1 2",                                  0 },
    { "two roots",               "{} []",                                0 },
    { "empty",                   "",                                     0 },
};

#define NCASES ((int)(sizeof(CORPUS) / sizeof(CORPUS[0])))

int main(void)
{
    int  i, fail = 0;
    char deep[512];
    int  d;

    /* deep nesting: jelas melebihi JSON_MAX_DEPTH (64) -> invalid. */
    memset(deep, '[', sizeof(deep));
    for (d = 0; d < 200; d++)
        deep[d] = '[';
    /* ternak '1' di tengah lalu 200 ']' */
    deep[200] = '1';
    for (d = 0; d < 200; d++)
        deep[201 + d] = ']';
    deep[401] = '\0';

    for (i = 0; i < NCASES; i++) {
        json_value *v = NULL;
        int ok;
        const char *inp = CORPUS[i].input;
        size_t      inl = strlen(inp);
        ok = json_parse(inp, inl, &v);
        if (ok != CORPUS[i].expect) {
            fprintf(stderr, "[FAIL] %s: expect %s, got %s\n",
                    CORPUS[i].label,
                    CORPUS[i].expect ? "valid" : "invalid",
                    ok ? "valid" : "invalid");
            fail++;
        } else if (!ok) {
            if (v) {
                fprintf(stderr, "[FAIL] %s: invalid tetapi v!=NULL\n",
                        CORPUS[i].label);
                fail++;
            }
        } else {
            char *out = NULL;
            if (json_serialize(v, &out) && out) {
                json_value *r2 = NULL;
                if (!json_parse(out, strlen(out), &r2)) {
                    fprintf(stderr, "[FAIL] %s: serialisasi tidak dapat "
                            "re-parse (tidak idempoten)\n", CORPUS[i].label);
                    fail++;
                }
                json_free(r2);
            } else {
                fprintf(stderr, "[FAIL] %s: serialize gagal\n",
                        CORPUS[i].label);
                fail++;
            }
            free(out);
        }
        json_free(v);
    }

    /* deep nesting: input berkedalaman 200 harus DITOLAK (depth cap). */
    {
        json_value *v = NULL;
        int ok = json_parse(deep, strlen(deep), &v);
        if (ok) {
            fprintf(stderr, "[FAIL] deep nesting: harus ditolak depth cap\n");
            fail++;
        }
        json_free(v);
    }

    printf(fail ? "json_abuse: FAIL (%d case)\n" : "json_abuse: OK (%d case)\n",
           fail ? fail : (NCASES + 1) );
    return fail ? 1 : 0;
}