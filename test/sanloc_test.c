/*
 * sanloc_test.c -- IDE-1 (qwen-review): Sanitizer Location Extractor.
 *
 * Menguji myc_sanloc_extract dengan FIXTURE report sanitizer (ASan/UBSan)
 * yang ditulis manual mengikuti format nyata clang ASan -O0 -g (Windows +
 * POSIX). Deterministik — TIDAK butuh clang/runtime ASan. Kasus:
 *
 *   T1 stack-buffer-overflow  : kind + location (line/fungsi) + snippet,
 *                               tanpa allocation (stack, bukan heap).
 *   T2 heap-buffer-overflow   : kind + location + allocation (blok
 *                               "allocated by") + snippet.
 *   T3 use-after-free         : kind + location + allocation (blok
 *                               "freed by") + snippet.
 *   T4 UBSan (runtime error)  : kind undefined-behavior + location
 *                               (line+col) + snippet.
 *   T5 frame runtime di-skip  : frame pertama milik target diambil,
 *                               frame dll/vctools/KERNEL32 dilewati.
 *   T6 remap line (kontrak)   : build_src = source + baris inject
 *                               (include assert + assert), nomor baris
 *                               laporan dikurangi offset.
 *   T7 anti-overclaim         : report tanpa frame target -> sanloc_have=0,
 *                               verdict TIDAK berubah (0 = bukan finding).
 *   T8 path Windows + stdin   : "<stdin>" di path absolut cocok target.
 *
 * Jalankan: gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -I.
 *           -DMYC_NO_MAIN -o sanloc_test sanloc_test.c <SRCS> ; ./sanloc_test
 * Membutuhkan myc_sanloc_extract (sanloc.c) di SRCS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myc.h"
#include "sanloc.h"

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

/* helper: jalankan extract pada fixture + source, isi result */
static myc_result run_extract(const char *rpt, const char *source,
                              const char *build_src, size_t build_len,
                              const char *target)
{
    myc_result res;
    myc_result_init(&res);
    res.witness = (myc_witness *)myc_malloc(sizeof(myc_witness));
    if (res.witness)
        myc_witness_init(res.witness);
    myc_sanloc_extract(&res, rpt, source ? source : "",
                       source ? strlen(source) : 0,
                       build_src, build_len, target);
    return res;
}

/* fixture: stack-buffer-overflow (format nyata clang ASan Windows) */
static const char FIX_STACK[] =
    "=================================================================\n"
    "==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address "
    "0x00f1ef73fd84 at pc 0x7ffbc35e85b8 bp 0x00f1ef73f460 sp 0x00f1ef73f4a8\n"
    "WRITE of size 25 at 0x00f1ef73fd84 thread T0\n"
    "    #0 0x7ffbc35e85b7  "
    "(D:\\Temp\\asan_rpt\\clang_rt.asan_dynamic-x86_64.dll+0x1800485b7)\n"
    "    #1 0x7ff7fb9d2ac4 in copy D:\\_proj\\myc\\<stdin>:3\n"
    "    #2 0x7ff7fb9d2a3d in main D:\\_proj\\myc\\<stdin>:7\n"
    "    #3 0x7ff7fb9d2e0e in invoke_main "
    "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcstartup\\src\\startup\\exe_common.inl:78\n"
    "    #4 0x7ffcc342ccb6  (C:\\WINDOWS\\System32\\KERNEL32.DLL+0x18002ccb6)\n"
    "Address 0x00f1ef73fd84 is located in stack of thread T0 at offset 36 in frame\n"
    "SUMMARY: AddressSanitizer: stack-buffer-overflow D:\\_proj\\myc\\<stdin>:3 in copy\n";

/* fixture: heap-buffer-overflow dengan blok "allocated by" */
static const char FIX_HEAP[] =
    "=================================================================\n"
    "==16836==ERROR: AddressSanitizer: heap-buffer-overflow on address "
    "0x121a187a01b8 at pc 0x7ffbc35eb6dc bp 0x0057c32ff460 sp 0x0057c32ff4a0\n"
    "WRITE of size 64 at 0x121a187a01b8 thread T0\n"
    "    #0 0x7ffbc35eb6db  "
    "(D:\\Temp\\asan_rpt\\clang_rt.asan_dynamic-x86_64.dll+0x18004b6db)\n"
    "    #1 0x7ff75c652997 in fill D:\\_proj\\myc\\<stdin>:4\n"
    "    #2 0x7ff75c652c8e in invoke_main "
    "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcstartup\\src\\startup\\exe_common.inl:78\n"
    "0x121a187a01b8 is located 0 bytes after 8-byte region "
    "[0x121a187a01b0,0x121a187a01b8)\n"
    "allocated by thread T0 here:\n"
    "    #0 0x7ffbc35ec92f  "
    "(D:\\Temp\\asan_rpt\\clang_rt.asan_dynamic-x86_64.dll+0x18004c92f)\n"
    "    #1 0x7ff75c652493 in malloc "
    "S:\\compiler-rt\\lib\\asan\\asan_malloc_win_thunk.cpp:64\n"
    "    #2 0x7ff75c65297d in main D:\\_proj\\myc\\<stdin>:7\n"
    "SUMMARY: AddressSanitizer: heap-buffer-overflow D:\\_proj\\myc\\<stdin>:4 in fill\n";

/* fixture: use-after-free dengan blok "freed by" */
static const char FIX_UAF[] =
    "=================================================================\n"
    "==1688==ERROR: AddressSanitizer: heap-use-after-free on address "
    "0x11506aba01b0 at pc 0x7ff6379c2a06 bp 0x004b6a9cfac0 sp 0x004b6a9cfb08\n"
    "READ of size 4 at 0x11506aba01b0 thread T0\n"
    "    #0 0x7ff6379c2a05 in use D:\\_proj\\myc\\<stdin>:8\n"
    "    #1 0x7ff6379c2cfe in invoke_main "
    "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcstartup\\src\\startup\\exe_common.inl:78\n"
    "0x11506aba01b0 is located 0 bytes inside of 16-byte region "
    "[0x11506aba01b0,0x11506aba01c0)\n"
    "freed by thread T0 here:\n"
    "    #0 0x7ffbc35ec81f  "
    "(D:\\Temp\\asan_rpt\\clang_rt.asan_dynamic-x86_64.dll+0x18004c81f)\n"
    "    #1 0x7ff6379c2433 in free "
    "S:\\compiler-rt\\lib\\asan\\asan_malloc_win_thunk.cpp:52\n"
    "    #2 0x7ff6379c2998 in make D:\\_proj\\myc\\<stdin>:5\n"
    "previously allocated by thread T0 here:\n"
    "    #0 0x7ffbc35ec92f  "
    "(D:\\Temp\\asan_rpt\\clang_rt.asan_dynamic-x86_64.dll+0x18004c92f)\n"
    "    #2 0x7ff6379c2989 in make D:\\_proj\\myc\\<stdin>:3\n"
    "SUMMARY: AddressSanitizer: heap-use-after-free D:\\_proj\\myc\\<stdin>:8 in use\n";

/* fixture: UBSan (signed integer overflow) */
static const char FIX_UBSAN[] =
    "D:\\_proj\\myc\\<stdin>:4:9: runtime error: signed integer overflow: "
    "2147483647 + 1 cannot be represented in type 'int'\n";

/* fixture: report dengan marker tapi TANPA frame target (anti-overclaim) */
static const char FIX_NOFRAME[] =
    "=================================================================\n"
    "==777==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x1\n"
    "    #0 0x7ffbc35e85b7  "
    "(D:\\Temp\\asan_rpt\\clang_rt.asan_dynamic-x86_64.dll+0x1800485b7)\n"
    "    #1 0x7ff7fb9d2a3d in invoke_main "
    "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcstartup\\src\\startup\\exe_common.inl:78\n"
    "SUMMARY: AddressSanitizer: stack-buffer-overflow\n";

static const char SRC_STACK[] =
    "#include <string.h>\n"
    "static void copy(char *dst, const char *src) {\n"
    "    strcpy(dst, src);\n"
    "}\n"
    "int main(void) {\n"
    "    char d[4];\n"
    "    copy(d, \"hello world this is long\");\n"
    "    return 0;\n"
    "}\n";

static const char SRC_HEAP[] =
    "#include <stdlib.h>\n"
    "#include <string.h>\n"
    "static void fill(char *p) {\n"
    "    memset(p, 'A', 64);\n"
    "}\n"
    "int main(void) {\n"
    "    char *p = malloc(8);\n"
    "    fill(p);\n"
    "    free(p);\n"
    "    return 0;\n"
    "}\n";

static const char SRC_UAF[] =
    "#include <stdlib.h>\n"
    "static int *g;\n"
    "static void make(void) {\n"
    "    g = malloc(16);\n"
    "    free(g);\n"
    "}\n"
    "static int use(void) {\n"
    "    return g[0];\n"
    "}\n"
    "int main(void) {\n"
    "    make();\n"
    "    return use();\n"
    "}\n";

static const char SRC_UBSAN[] =
    "#include <limits.h>\n"
    "int main(void) {\n"
    "    int x = INT_MAX;\n"
    "    return x + 1;\n"
    "}\n";

static void t1_stack(void)
{
    myc_result res = run_extract(FIX_STACK, SRC_STACK, NULL, 0, "<stdin>");
    CHECK(res.sanloc_have == 1, "T1 sanloc_have");
    CHECK(res.sanloc_kind && strcmp(res.sanloc_kind,
                                    "stack-buffer-overflow") == 0,
          "T1 kind");
    CHECK(res.sanloc_line == 3, "T1 line (copy:3)");
    CHECK(res.sanloc_function && strcmp(res.sanloc_function, "copy") == 0,
          "T1 function");
    CHECK(res.sanloc_alloc_line == 0, "T1 tanpa allocation (stack)");
    CHECK(res.sanloc_snippet &&
          strstr(res.sanloc_snippet, "strcpy") != NULL,
          "T1 snippet memuat strcpy");
    if (res.witness)
        CHECK(res.witness->violation_line == 3, "T1 witness line");
    myc_result_free(&res);
}

static void t2_heap(void)
{
    myc_result res = run_extract(FIX_HEAP, SRC_HEAP, NULL, 0, "<stdin>");
    CHECK(res.sanloc_have == 1, "T2 sanloc_have");
    CHECK(res.sanloc_kind && strcmp(res.sanloc_kind,
                                    "heap-buffer-overflow") == 0,
          "T2 kind");
    CHECK(res.sanloc_line == 4, "T2 line (fill:4)");
    CHECK(res.sanloc_function && strcmp(res.sanloc_function, "fill") == 0,
          "T2 function");
    CHECK(res.sanloc_alloc_line == 7, "T2 alloc line (main:7)");
    CHECK(res.sanloc_alloc_function &&
          strcmp(res.sanloc_alloc_function, "main") == 0,
          "T2 alloc function");
    myc_result_free(&res);
}

static void t3_uaf(void)
{
    myc_result res = run_extract(FIX_UAF, SRC_UAF, NULL, 0, "<stdin>");
    CHECK(res.sanloc_have == 1, "T3 sanloc_have");
    CHECK(res.sanloc_kind && strcmp(res.sanloc_kind,
                                    "heap-use-after-free") == 0,
          "T3 kind");
    CHECK(res.sanloc_line == 8, "T3 line (use:8)");
    CHECK(res.sanloc_function && strcmp(res.sanloc_function, "use") == 0,
          "T3 function");
    CHECK(res.sanloc_alloc_line == 5, "T3 alloc line (make:5, freed by)");
    CHECK(res.sanloc_alloc_function &&
          strcmp(res.sanloc_alloc_function, "make") == 0,
          "T3 alloc function");
    if (res.witness)
        CHECK(res.witness->pre_state &&
              strstr(res.witness->pre_state, "baris 5") != NULL,
              "T3 witness pre_state menunjuk baris free");
    myc_result_free(&res);
}

static void t4_ubsan(void)
{
    myc_result res = run_extract(FIX_UBSAN, SRC_UBSAN, NULL, 0, "<stdin>");
    CHECK(res.sanloc_have == 1, "T4 sanloc_have");
    CHECK(res.sanloc_kind && strcmp(res.sanloc_kind,
                                    "undefined-behavior") == 0,
          "T4 kind");
    CHECK(res.sanloc_line == 4, "T4 line");
    CHECK(res.sanloc_col == 9, "T4 col");
    myc_result_free(&res);
}

static void t5_skip_runtime(void)
{
    myc_result res = run_extract(FIX_STACK, SRC_STACK, NULL, 0, "<stdin>");
    /* frame #0 dll dan #3/#4 runtime di-skip; target = copy:3 */
    CHECK(res.sanloc_have == 1, "T5 sanloc_have");
    CHECK(res.sanloc_function && strcmp(res.sanloc_function, "copy") == 0,
          "T5 frame runtime dilewati, target diambil");
    myc_result_free(&res);
}

static void t6_remap(void)
{
    /* build_src = source + 1 baris include assert + 1 baris assert di
     * atas copy() — laporan line 5 harus remap ke source line 3. */
    const char *build =
        "#include <assert.h>\n"
        "#include <string.h>\n"
        "static void copy(char *dst, const char *src) {\n"
        "    assert(dst != NULL);\n"
        "    strcpy(dst, src);\n"
        "}\n"
        "int main(void) {\n"
        "    char d[4];\n"
        "    copy(d, \"hello world this is long\");\n"
        "    return 0;\n"
        "}\n";
    /* report menunjuk line 5 pada build_src (= baris strcpy) */
    char rpt[2048];
    snprintf(rpt, sizeof(rpt),
             "==9==ERROR: AddressSanitizer: stack-buffer-overflow on "
             "address 0x1 at pc 0x2\n"
             "    #1 0x3 in copy D:\\_proj\\myc\\<stdin>:5\n"
             "    #2 0x4 in main D:\\_proj\\myc\\<stdin>:9\n"
             "SUMMARY: AddressSanitizer: stack-buffer-overflow "
             "D:\\_proj\\myc\\<stdin>:5 in copy\n");
    myc_result res = run_extract(rpt, SRC_STACK, build, strlen(build),
                                 "<stdin>");
    CHECK(res.sanloc_have == 1, "T6 sanloc_have");
    CHECK(res.sanloc_line == 3, "T6 remap 5 -> 3 (strcpy di source asli)");
    CHECK(res.sanloc_snippet &&
          strstr(res.sanloc_snippet, "strcpy") != NULL,
          "T6 snippet dari source asli");
    myc_result_free(&res);
}

static void t7_no_overclaim(void)
{
    myc_result res = run_extract(FIX_NOFRAME, SRC_STACK, NULL, 0, "<stdin>");
    /* kind boleh terisi (additive) tapi lokasi TIDAK dipastikan */
    CHECK(res.sanloc_have == 0, "T7 sanloc_have = 0 (anti-overclaim)");
    CHECK(res.sanloc_line == 0, "T7 line = 0");
    myc_result_free(&res);
}

static void t8_stdin_path(void)
{
    /* path absolut Windows + <stdin> di tengah — harus cocok target */
    myc_result res = run_extract(FIX_STACK, SRC_STACK, NULL, 0, "<stdin>");
    CHECK(res.sanloc_have == 1, "T8 path Windows + <stdin> cocok");
    CHECK(res.sanloc_file && strstr(res.sanloc_file, "<stdin>") != NULL,
          "T8 file mengandung <stdin>");
    myc_result_free(&res);
}

int main(void)
{
    /* Output hasil ke STDOUT agar pipeline `| findstr` (regress_run.bat)
     * dan grep (audit018.sh) dapat memverifikasi; detail [FAIL] ke
     * stderr. */
    printf("sanloc_test: IDE-1 Sanitizer Location Extractor\n");
    t1_stack();
    t2_heap();
    t3_uaf();
    t4_ubsan();
    t5_skip_runtime();
    t6_remap();
    t7_no_overclaim();
    t8_stdin_path();
    printf("sanloc_test: PASS=%d FAIL=%d\n", PASS, FAIL);
    return FAIL == 0 ? 0 : 1;
}
