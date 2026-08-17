/*
 * runtime_repair_test.c -- IDE-2 (qwen-review): repair template untuk
 * RUNTIME_VIOLATION berbasis sanitizer_location (IDE-1).
 *
 * Menguji myc_repair_runtime_patch dengan myc_result FIXTURE (sanloc_*
 * diisi manual) + source C deterministik. TIDAK butuh clang/runtime
 * ASan — hanya string ops murni. Kasus:
 *
 *   T1 strcpy stack overflow  : template B -> patched_source berisi copy
 *                               ber-batas + null-terminate, deklarasi
 *                               array di baris SAMA tetap ada (segmen
 *                               replace, bukan replace baris).
 *   T2 memset heap overflow   : template A (alloc line) -> clamp n ke
 *                               kapasitas malloc, ';' tetap utuh.
 *   T3 memset array lokal     : template A -> clamp ke sizeof(array).
 *   T4 UAF                    : template C -> NULL-kan setelah free di
 *                               baris alloc (free).
 *   T5 UBSan (undefined)      : template tidak yakin -> patched_source
 *                               NULL + why (jujur, bukan overclaim).
 *   T6 strcat overflow        : template B strcat -> copy offset +
 *                               null-terminate.
 *   T8 memcpy array lokal     : template A cabang memcpy + array lokal.
 *   T9 memcpy heap            : template A cabang memcpy + alloc line.
 *   T10 strcpy multi-baris    : deklarasi array di baris LAIN dari
 *                               violation (scan ke belakang + segmen
 *                               replace lintas baris).
 *   T11 UAF var lain          : template C generik terhadap nama (p).
 *   T12 strcpy sumber global  : template B generik (bukan literal).
 *   T13 strcat sumber global  : template B strcat + sumber non-literal.
 *   T14 overflow non-template : penulisan indeks langsung -> jujur NULL
 *                               + why (di luar mem* / str*).
 *   T15 memset heap 2-digit   : rt_alloc_size_at baca kapasitas 2-digit
 *                               (malloc(12) -> clamp ke 12).
 *   T7 anti-overclaim         : sanloc_have=0 -> NULL (tidak menebak).
 *
 * Jalankan: gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I.
 *           -DMYC_NO_MAIN -o runtime_repair_test runtime_repair_test.c
 *           <SRCS> ; ./runtime_repair_test
 * Membutuhkan myc_repair_runtime_patch (compile.c) di SRCS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myc.h"
#include "compile.h"

static int PASS = 0;
static int FAIL = 0;

/* Akuntansi template patch (M2 di run_success_metrics.sh): tiap kasus
 * template yang dicoba dihitung di PATCH_TOTAL. Kasus yang WAJIB
 * memproduksi patched_source: PATCH_CASE (sukses -> PATCH_OK++). Kasus
 * jujur-null (UBSan, operasi di luar template): HONEST_CASE — dihitung
 * di PATCH_TOTAL (template dicoba, hasil jujur) tapi TIDAK di PATCH_OK.
 * Keduanya ikut PASS/FAIL agar exit code test tetap bermakna. Kasus
 * anti-overclaim (T7 sanloc_have=0) TIDAK dihitung (bukan kasus
 * template). */
static int PATCH_TOTAL = 0;
static int PATCH_OK = 0;

#define PATCH_CASE(cond, msg)                                             \
    do {                                                                  \
        PATCH_TOTAL++;                                                    \
        if (cond) {                                                       \
            PATCH_OK++;                                                   \
            PASS++;                                                       \
        } else {                                                          \
            FAIL++;                                                       \
            fprintf(stderr, "[FAIL] %s (%s:%d)\n", msg, __FILE__,        \
                    __LINE__);                                            \
        }                                                                 \
    } while (0)

#define HONEST_CASE(cond, msg)                                            \
    do {                                                                  \
        PATCH_TOTAL++;                                                    \
        if (cond) {                                                       \
            PASS++;                                                       \
        } else {                                                          \
            FAIL++;                                                       \
            fprintf(stderr, "[FAIL] %s (%s:%d)\n", msg, __FILE__,        \
                    __LINE__);                                            \
        }                                                                 \
    } while (0)

#define CHECK(cond, msg)                                              \
    do {                                                              \
        if (cond) {                                                   \
            PASS++;                                                   \
        } else {                                                      \
            FAIL++;                                                   \
            fprintf(stderr, "[FAIL] %s (%s:%d)\n", msg, __FILE__,     \
                    __LINE__);                                        \
        }                                                             \
    } while (0)

static myc_result make_res(const char *kind, int line, int alloc_line,
                           const char *snippet)
{
    myc_result res;
    myc_result_init(&res);
    res.sanloc_have = 1;
    if (kind)
        res.sanloc_kind = myc_strdup(kind);
    res.sanloc_line = line;
    res.sanloc_alloc_line = alloc_line;
    if (snippet)
        res.sanloc_snippet = myc_strdup(snippet);
    return res;
}

static void free_res(myc_result *res)
{
    myc_free(res->sanloc_kind);
    myc_free(res->sanloc_snippet);
    myc_result_free(res);
}

int main(void)
{
    /* T1: strcpy ke array lokal, deklarasi di baris SAMA (single-line
     * dari MCP) — segmen replace harus mempertahankan deklarasi. */
    {
        const char *src =
            "#include <string.h>\n"
            "int f(void){char b[6]; strcpy(b, \"abcdefghij\"); return b[0];}\n"
            "int main(void){(void)f(); return 0;}\n";
        myc_result res = make_res("stack-buffer-overflow", 2, 0,
            "int f(void){char b[6]; strcpy(b, \"abcdefghij\"); return b[0];}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source,
                   "T1: patch tersedia (strcpy stack)");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "char b[6]") != NULL,
                  "T1: deklarasi array dipertahankan");
            CHECK(strstr(rr->patched_source, "memcpy(b, \"abcdefghij\", _n)") != NULL,
                  "T1: copy ber-batas memcpy");
            CHECK(strstr(rr->patched_source, "b[_n] = '\\0'") != NULL,
                  "T1: null-terminate");
            CHECK(strstr(rr->patched_source, "strcpy(") == NULL,
                  "T1: strcpy asli diganti");
            CHECK(rr->confidence >= 70, "T1: confidence");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T2: memset heap overflow — clamp n ke kapasitas malloc (alloc
     * line menunjuk baris alokasi) + ';' dipertahankan. */
    {
        const char *src =
            "#include <stdlib.h>\n"
            "#include <string.h>\n"
            "int main(void){char *b = (char *)malloc(8); if (!b) return 1; "
            "memset(b, 'A', 16); free(b); return 0;}\n";
        myc_result res = make_res("heap-buffer-overflow", 3, 3,
            "int main(void){char *b = (char *)malloc(8); if (!b) return 1; "
            "memset(b, 'A', 16); free(b); return 0;}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source,
                   "T2: patch tersedia (memset heap)");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "memset(b, 'A', 8);") != NULL,
                  "T2: clamp ke kapasitas malloc");
            CHECK(strstr(rr->patched_source, "free(b);") != NULL,
                  "T2: statement setelah memset tetap utuh");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T3: memset array lokal — clamp ke sizeof(array). */
    {
        const char *src =
            "#include <string.h>\n"
            "int main(void){char b[4]; memset(b, 'A', 16); return b[0];}\n";
        myc_result res = make_res("stack-buffer-overflow", 2, 0,
            "int main(void){char b[4]; memset(b, 'A', 16); return b[0];}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source,
                   "T3: patch tersedia (memset array lokal)");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "memset(b, 'A', sizeof(b));") != NULL,
                  "T3: clamp ke sizeof array");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T4: UAF — NULL-kan setelah free di baris alloc. */
    {
        const char *src =
            "#include <stdlib.h>\n"
            "static char *g;\n"
            "static void teardown(void){free(g);}\n"
            "int main(void){teardown(); return g ? g[0] : 0;}\n";
        myc_result res = make_res("heap-use-after-free", 4, 3,
            "int main(void){teardown(); return g ? g[0] : 0;}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source,
                   "T4: patch tersedia (UAF)");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "free(g); g = NULL;") != NULL,
                  "T4: NULL-kan setelah free");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T5: UBSan undefined-behavior — template TIDAK yakin, jujur why
     * (bukan klaim palsu). */
    {
        const char *src =
            "#include <limits.h>\n"
            "#include <stdio.h>\n"
            "int main(void){int x = INT_MAX; printf(\"%d\\n\", x + 1); "
            "return 0;}\n";
        myc_result res = make_res("undefined-behavior", 3, 0,
            "int main(void){int x = INT_MAX; printf(\"%d\\n\", x + 1); "
            "return 0;}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        HONEST_CASE(rr && rr->patched_source == NULL && rr->why != NULL,
                    "T5: UBSan jujur NULL + why");
        if (rr) {
            CHECK(rr->why != NULL, "T5: why terisi");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T6: strcat overflow — copy offset + null-terminate. */
    {
        const char *src =
            "#include <string.h>\n"
            "int f(void){char b[6]; b[0]='a'; b[1]='\\0'; strcat(b, "
            "\"bcdefghij\"); return b[0];}\n"
            "int main(void){(void)f(); return 0;}\n";
        myc_result res = make_res("stack-buffer-overflow", 2, 0,
            "int f(void){char b[6]; b[0]='a'; b[1]='\\0'; strcat(b, "
            "\"bcdefghij\"); return b[0];}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source,
                   "T6: patch tersedia (strcat)");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "memcpy(b + _o,") != NULL,
                  "T6: copy offset strcat");
            CHECK(strstr(rr->patched_source, "b[_o + _n] = '\\0'") != NULL,
                  "T6: null-terminate offset");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T8: memcpy array lokal overflow — template A (cabang array
     * lokal) dengan memcpy (bukan memset). */
    {
        const char *src =
            "#include <string.h>\n"
            "int f(void){char b[4]; memcpy(b, \"abcdefghij\", 10); return b[0];}\n"
            "int main(void){(void)f(); return 0;}\n";
        myc_result res = make_res("stack-buffer-overflow", 2, 0,
            "int f(void){char b[4]; memcpy(b, \"abcdefghij\", 10); return b[0];}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source,
                   "T8: patch tersedia (memcpy array lokal)");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source,
                         "memcpy(b, \"abcdefghij\", sizeof(b));") != NULL,
                  "T8: clamp ke sizeof array (memcpy)");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T9: memcpy heap overflow — template A (cabang alloc line). */
    {
        const char *src =
            "#include <stdlib.h>\n"
            "#include <string.h>\n"
            "int main(void){char *b = (char *)malloc(8); if (!b) return 1; "
            "memcpy(b, \"abcdefghij\", 10); free(b); return 0;}\n";
        myc_result res = make_res("heap-buffer-overflow", 3, 3,
            "int main(void){char *b = (char *)malloc(8); if (!b) return 1; "
            "memcpy(b, \"abcdefghij\", 10); free(b); return 0;}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source,
                   "T9: patch tersedia (memcpy heap)");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "memcpy(b, \"abcdefghij\", 8);") != NULL,
                  "T9: clamp ke kapasitas malloc (memcpy)");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T10: strcpy multi-baris — deklarasi array di baris LAIN dari
     * lokasi violation (rt_is_local_array scan ke belakang + segmen
     * replace lintas baris). */
    {
        const char *src =
            "#include <string.h>\n"
            "int f(void)\n"
            "{\n"
            "    char b[6];\n"
            "    strcpy(b, \"abcdefghij\");\n"
            "    return b[0];\n"
            "}\n"
            "int main(void){(void)f(); return 0;}\n";
        myc_result res = make_res("stack-buffer-overflow", 5, 0,
            "    strcpy(b, \"abcdefghij\");");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source,
                   "T10: patch tersedia (strcpy multi-baris)");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "char b[6];") != NULL,
                  "T10: deklarasi baris lain dipertahankan");
            CHECK(strstr(rr->patched_source, "memcpy(b, \"abcdefghij\", _n)") != NULL,
                  "T10: copy ber-batas di baris lokasi");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T11: UAF dengan nama variabel LAIN (p, bukan g) — template C
     * generik terhadap nama. */
    {
        const char *src =
            "#include <stdlib.h>\n"
            "static char *p;\n"
            "static void lepas(void){free(p);}\n"
            "int main(void){lepas(); return p ? p[0] : 0;}\n";
        myc_result res = make_res("heap-use-after-free", 4, 3,
            "int main(void){lepas(); return p ? p[0] : 0;}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source,
                   "T11: patch tersedia (UAF var lain)");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "free(p); p = NULL;") != NULL,
                  "T11: NULL-kan p setelah free");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T12: strcpy dengan SUMBER GLOBAL (bukan literal) — template B
     * generik terhadap bentuk sumber. */
    {
        const char *src =
            "#include <string.h>\n"
            "static char g_src[] = \"abcdefghij\";\n"
            "int f(void){char b[6]; strcpy(b, g_src); return b[0];}\n"
            "int main(void){(void)f(); return 0;}\n";
        myc_result res = make_res("stack-buffer-overflow", 3, 0,
            "int f(void){char b[6]; strcpy(b, g_src); return b[0];}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source,
                   "T12: patch tersedia (strcpy sumber global)");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "memcpy(b, g_src, _n)") != NULL,
                  "T12: copy ber-batas sumber global");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T13: strcat dengan SUMBER GLOBAL — template B strcat + sumber
     * non-literal. */
    {
        const char *src =
            "#include <string.h>\n"
            "static char g_src[] = \"bcdefghij\";\n"
            "int f(void){char b[6]; b[0]='a'; b[1]='\\0'; strcat(b, g_src); "
            "return b[0];}\n"
            "int main(void){(void)f(); return 0;}\n";
        myc_result res = make_res("stack-buffer-overflow", 3, 0,
            "int f(void){char b[6]; b[0]='a'; b[1]='\\0'; strcat(b, g_src); "
            "return b[0];}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source,
                   "T13: patch tersedia (strcat sumber global)");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "memcpy(b + _o, g_src, _n)") != NULL,
                  "T13: copy offset sumber global");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T14: overflow DI LUAR fungsi template (penulisan indeks langsung,
     * bukan memset/memcpy/strcpy/strcat) — template tidak yakin, jujur
     * NULL + why (anti-overclaim). */
    {
        const char *src =
            "int f(void){char b[6]; b[16] = 0; return b[0];}\n"
            "int main(void){(void)f(); return 0;}\n";
        myc_result res = make_res("stack-buffer-overflow", 1, 0,
            "int f(void){char b[6]; b[16] = 0; return b[0];}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        HONEST_CASE(rr && rr->patched_source == NULL && rr->why != NULL,
                    "T14: overflow non-template jujur NULL + why");
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T15: memset heap dengan kapasitas 2-digit (malloc(12)) —
     * rt_alloc_size_at harus membaca semua digit. */
    {
        const char *src =
            "#include <stdlib.h>\n"
            "#include <string.h>\n"
            "int main(void){char *b = (char *)malloc(12); if (!b) return 1; "
            "memset(b, 'A', 24); free(b); return 0;}\n";
        myc_result res = make_res("heap-buffer-overflow", 3, 3,
            "int main(void){char *b = (char *)malloc(12); if (!b) return 1; "
            "memset(b, 'A', 24); free(b); return 0;}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source,
                   "T15: patch tersedia (memset heap 2-digit)");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "memset(b, 'A', 12);") != NULL,
                  "T15: clamp ke kapasitas malloc 2-digit");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T7: anti-overclaim — sanloc_have=0 -> NULL (tidak menebak). */
    {
        const char *src = "int main(void){return 0;}\n";
        myc_result res;
        myc_result_init(&res);
        res.sanloc_have = 0;
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        CHECK(rr == NULL, "T7: sanloc_have=0 -> NULL");
        if (rr)
            myc_runtime_repair_free(rr);
        myc_result_free(&res);
    }

    /* T16: gets pada array lokal -> fgets + sizeof. */
    {
        const char *src =
            "#include <stdio.h>\n"
            "int main(void){char b[8]; gets(b); return b[0];}\n";
        myc_result res = make_res("stack-buffer-overflow", 2, 0,
            "int main(void){char b[8]; gets(b); return b[0];}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source, "T16: patch gets -> fgets");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "fgets(b, sizeof(b), stdin);") != NULL,
                  "T16: fgets + sizeof");
            CHECK(strstr(rr->patched_source, "gets(b)") == NULL,
                  "T16: gets asli diganti");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T17: sprintf pada array lokal -> snprintf + sizeof. */
    {
        const char *src =
            "#include <stdio.h>\n"
            "int main(void){char b[8]; sprintf(b, \"%s\", \"abcdefghij\"); "
            "return b[0];}\n";
        myc_result res = make_res("stack-buffer-overflow", 2, 0,
            "int main(void){char b[8]; sprintf(b, \"%s\", \"abcdefghij\"); "
            "return b[0];}");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source,
                   "T17: patch sprintf -> snprintf");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source,
                         "snprintf(b, sizeof(b), \"%s\", \"abcdefghij\");") != NULL,
                  "T17: snprintf + sizeof");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T18: gets, deklarasi array di baris lain. */
    {
        const char *src =
            "char b[8];\n"
            "int f(void)\n"
            "{\n"
            "  gets(b);\n"
            "  return b[0];\n"
            "}\n";
        myc_result res = make_res("stack-buffer-overflow", 4, 0, "  gets(b);");
        myc_runtime_repair *rr = myc_repair_runtime_patch(&res, src,
                                                          strlen(src));
        PATCH_CASE(rr && rr->patched_source, "T18: gets multi-baris");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "fgets(b, sizeof(b), stdin);") != NULL,
                  "T18: fgets pada baris gets");
            CHECK(strstr(rr->patched_source, "char b[8];") != NULL,
                  "T18: deklarasi tetap");
        }
        if (rr)
            myc_runtime_repair_free(rr);
        free_res(&res);
    }

    /* T19: compile-path tanpa sanloc — sprintf via source_line_patch. */
    {
        const char *src =
            "#include <stdio.h>\n"
            "int main(void){char b[16]; sprintf(b, \"%s %d\", \"x\", 1); "
            "return b[0];}\n";
        myc_runtime_repair *rr = myc_repair_source_line_patch(src, strlen(src), 2);
        PATCH_CASE(rr && rr->patched_source,
                   "T19: source_line_patch sprintf");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "snprintf(b, sizeof(b),") != NULL,
                  "T19: snprintf");
            CHECK(rr->confidence >= 80, "T19: confidence tinggi");
        }
        if (rr)
            myc_runtime_repair_free(rr);
    }

    printf("runtime_repair_test: PASS=%d FAIL=%d\n", PASS, FAIL);
    printf("M2-TEMPLATE-PATCH: %d/%d\n", PATCH_OK, PATCH_TOTAL);
    return FAIL == 0 ? 0 : 1;
}
