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
        CHECK(rr != NULL, "T1: patch tersedia");
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
        } else {
            CHECK(0, "T1: patched_source ada");
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
        CHECK(rr != NULL, "T2: patch tersedia");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "memset(b, 'A', 8);") != NULL,
                  "T2: clamp ke kapasitas malloc");
            CHECK(strstr(rr->patched_source, "free(b);") != NULL,
                  "T2: statement setelah memset tetap utuh");
        } else {
            CHECK(0, "T2: patched_source ada");
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
        CHECK(rr != NULL, "T3: patch tersedia");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "memset(b, 'A', sizeof(b));") != NULL,
                  "T3: clamp ke sizeof array");
        } else {
            CHECK(0, "T3: patched_source ada");
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
        CHECK(rr != NULL, "T4: patch tersedia");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "free(g); g = NULL;") != NULL,
                  "T4: NULL-kan setelah free");
        } else {
            CHECK(0, "T4: patched_source ada");
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
        CHECK(rr != NULL, "T5: hasil ada");
        if (rr) {
            CHECK(rr->patched_source == NULL, "T5: patched_source NULL (jujur)");
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
        CHECK(rr != NULL, "T6: patch tersedia");
        if (rr && rr->patched_source) {
            CHECK(strstr(rr->patched_source, "memcpy(b + _o,") != NULL,
                  "T6: copy offset strcat");
            CHECK(strstr(rr->patched_source, "b[_o + _n] = '\\0'") != NULL,
                  "T6: null-terminate offset");
        } else {
            CHECK(0, "T6: patched_source ada");
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

    printf("runtime_repair_test: PASS=%d FAIL=%d\n", PASS, FAIL);
    return FAIL == 0 ? 0 : 1;
}
