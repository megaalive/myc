/*
 * backend_fake.c -- Fake backend deterministik untuk parser-abuse corpus
 * (PR-009 / P2-T03 tahap 1: korpus malformed SEBELUM fuzzing PR-010).
 *
 * Berperan sebagai gcc / filc-clang / frama-c dengan output MALFORMED yang
 * dipilih via env MYC_FAKE_MODE; exit code via MYC_FAKE_EXIT (default per
 * mode). Memungkinkan unit test memicu parser backend nyata (compile.c
 * ingest_gcc_diagnostics, prove.c count_eva_alarms, filc.c parse_filc_report)
 * dengan input yang TIDAK PERNAH dihasilkan backend sungguhan, deterministik
 * dan portabel (Windows git-bash + POSIX).
 *
 * Mode invokasi:
 *   - argc > 1 = mode BACKEND (dipanggil myc sebagai backend):
 *       --version / -version -> baris versi, exit 0
 *       -dM                   -> macro dump (assumption facts), exit 0
 *       -E                    -> salin stdin ke stdout (preprocess), exit 0
 *       -eva                  -> output Eva per mode (frama-c)
 *       -c                    -> stderr = payload malformed per mode (gcc)
 *       -o <exe>              -> salin DIRI SENDIRI ke <exe> (filc build)
 *   - argc == 1 = mode PROGRAM (hasil build filc dijalankan myc): emit
 *       payload per mode ke stdout+stderr, exit sesuai mode.
 *
 * Role dipilih env MYC_FAKE_ROLE (gcc|filc|eva); fallback sniff argv[0].
 *
 * Build: gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic
 *        -o test/backend_fake tests/backend_fake.c
 */
/* readlink(2) butuh _POSIX_C_SOURCE di glibc dengan -std=c11 (pola sama
 * seperti proc_fixture.c); define harus sebelum include sistem apa pun. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

/* Ukuran buffer payload (oversized strings / report besar). */
#define PAYLOAD_CAP 170000

/* ------------------------------------------------------------------ */
/* Payload korpus per mode (deterministik).                            */
/* ------------------------------------------------------------------ */
/* exit default per mode: gcc compile-fail = 1, eva clean = 0, dst. */
static size_t build_payload(const char *mode, char *buf, size_t cap, int *pexit)
{
    size_t n = 0;
    *pexit = 0;

    /* ---------- GCC JSON diagnostics ---------- */
    if (strcmp(mode, "gcc-json-valid") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(
            buf, cap,
            "[{\"kind\":\"error\",\"message\":\"fake oob at index\","
            "\"locations\":[{\"caret\":{\"line\":3,\"column\":7}}]}]");
    } else if (strcmp(mode, "gcc-json-truncated") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(buf, cap,
                             "[{\"kind\":\"error\",\"message\":\"fake oo");
    } else if (strcmp(mode, "gcc-json-garbage") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(buf, cap, "[{\"kind\": error, \"message\": \xff\xfe");
    } else if (strcmp(mode, "gcc-json-dupkeys") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(
            buf, cap,
            "[{\"kind\":\"error\",\"message\":\"m1\",\"kind\":\"warning\","
            "\"message\":\"m2\"}]");
    } else if (strcmp(mode, "gcc-json-deep") == 0) {
        int d;
        *pexit = 1;
        for (d = 0; d < 200 && n + 1 < cap; d++)
            buf[n++] = '[';
        buf[n++] = '1';
        for (d = 0; d < 200 && n + 1 < cap; d++)
            buf[n++] = ']';
    } else if (strcmp(mode, "gcc-json-hugenum") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(
            buf, cap,
            "[{\"kind\":\"error\",\"message\":\"x\",\"locations\":[{\"caret\":"
            "{\"line\":99999999999999999999,\"column\":-9223372036854775808}}]}]");
    } else if (strcmp(mode, "gcc-json-nul") == 0) {
        /* embedded NUL di dalam payload (fwrite eksplisit). */
        static const char head[] = "[{\"kind\":\"error\",\"message\":\"a";
        static const char tail[] = "b\"}]";
        *pexit = 1;
        memcpy(buf, head, sizeof(head) - 1);
        n = sizeof(head) - 1;
        buf[n++] = '\0';
        memcpy(buf + n, tail, sizeof(tail) - 1);
        n += sizeof(tail) - 1;
    } else if (strcmp(mode, "gcc-json-utf8") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(buf, cap,
                             "[{\"kind\":\"error\",\"message\":\"\xff\xfe bad"
                             " utf8\"}]");
    } else if (strcmp(mode, "gcc-json-oversized") == 0) {
        /* string pesan 100 KB (melewati batas masuk akal). */
        size_t i;
        *pexit = 1;
        n = (size_t)snprintf(buf, cap, "[{\"kind\":\"error\",\"message\":\"");
        for (i = 0; i < 100000 && n + 1 < cap; i++)
            buf[n++] = 'A';
        n += (size_t)snprintf(buf + n, cap - n, "\"}]");
    } else if (strcmp(mode, "gcc-json-reordered") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(
            buf, cap,
            "[{\"message\":\"reordered ok\",\"kind\":\"error\",\"locations\":"
            "[{\"caret\":{\"column\":2,\"line\":9}}]}]");
    } else if (strcmp(mode, "gcc-json-unknown-kind") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(buf, cap,
                             "[{\"kind\":\"bogus\",\"message\":\"unknown kind"
                             " msg\"}]");
    } else if (strcmp(mode, "gcc-json-note-only") == 0) {
        /* hanya note: harus dilewati parser (bukan diagnostic). */
        *pexit = 1;
        n = (size_t)snprintf(buf, cap,
                             "[{\"kind\":\"note\",\"message\":\"note only\"}]");
    }

    /* ---------- GCC text fallback diagnostics ---------- */
    else if (strcmp(mode, "gcc-text-valid") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(buf, cap,
                             "<stdin>:5:9: error: fake text oob\n");
    } else if (strcmp(mode, "gcc-text-hugeloc") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(
            buf, cap,
            "<stdin>:99999999999999999999:99999999999999999999: error: huge\n");
    } else if (strcmp(mode, "gcc-text-garbage") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(buf, cap,
                             "cc1.exe: fatal error: this is not a diagnostic\n"
                             "  'main': events\n"
                             "some random text without location\n");
    } else if (strcmp(mode, "gcc-text-nul") == 0) {
        static const char head[] = "<stdin>:3:7: error: x";
        static const char tail[] = "y\n";
        *pexit = 1;
        memcpy(buf, head, sizeof(head) - 1);
        n = sizeof(head) - 1;
        buf[n++] = '\0';
        memcpy(buf + n, tail, sizeof(tail) - 1);
        n += sizeof(tail) - 1;
    } else if (strcmp(mode, "gcc-text-nocolon") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(buf, cap,
                             "<stdin>:abc:def: error: no line/col\n");
    } else if (strcmp(mode, "gcc-exit0-garbage") == 0) {
        /* malformed + exit 0: TIDAK boleh jadi violation (PR-008 rule). */
        *pexit = 0;
        n = (size_t)snprintf(buf, cap,
                             "ERROR: AddressSanitizer: fake\n"
                             "[{\"kind\":\"error\",\"message\":\"x\"");
    }

    /* ---------- Fil-C report ---------- */
    else if (strcmp(mode, "filc-panic-valid") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(
            buf, cap,
            "filc safety error: cannot write pointer with ptr >= upper.\n"
            "    pointer: 0x7ffb53684238\n"
            "semantic origin:\n"
            "    (fake) /tmp/f.c:2:43: main\n"
            "[12345] filc panic: thwarted a futile attempt to violate memory"
            " safety.\n");
    } else if (strcmp(mode, "filc-panic-exit0") == 0) {
        *pexit = 0;
        n = (size_t)snprintf(
            buf, cap,
            "filc safety error: cannot write pointer with ptr >= upper.\n"
            "[12345] filc panic: thwarted a futile attempt to violate memory"
            " safety.\n");
    } else if (strcmp(mode, "filc-panic-truncated") == 0) {
        *pexit = 1;
        n = (size_t)snprintf(buf, cap, "[123] filc pan");
    } else if (strcmp(mode, "filc-garbage") == 0) {
        size_t i;
        *pexit = 1;
        for (i = 0; i < 4096 && n + 1 < cap; i++)
            buf[n++] = (char)(i % 256);
        n += (size_t)snprintf(buf + n, cap - n, "FIL-C SAFE\n");
    } else if (strcmp(mode, "filc-dup") == 0) {
        int k;
        *pexit = 1;
        for (k = 0; k < 500; k++)
            n += (size_t)snprintf(buf + n, cap - n,
                                  "[%d] filc panic: dup case %d\n", k + 1, k);
    } else if (strcmp(mode, "filc-oversized") == 0) {
        size_t i;
        *pexit = 1;
        for (i = 0; i < 100000 && n + 1 < cap; i++)
            buf[n++] = (char)('a' + (i % 26));
    }

    /* ---------- Frama-C Eva output ---------- */
    else if (strcmp(mode, "eva-alarm-valid") == 0) {
        *pexit = 0;
        n = (size_t)snprintf(
            buf, cap,
            "[eva:alarm] /tmp/f.c:3: Warning: out of bounds read\n"
            "ANALYSIS SUMMARY\n"
            "0 alarms generated by the analysis.\n");
    } else if (strcmp(mode, "eva-alarm-hugeline") == 0) {
        *pexit = 0;
        n = (size_t)snprintf(
            buf, cap,
            "[eva:alarm] /tmp/f.c:99999999999999999999: Warning: x\n"
            "ANALYSIS SUMMARY\n");
    } else if (strcmp(mode, "eva-garbage") == 0) {
        size_t i;
        *pexit = 1;
        for (i = 0; i < 4096 && n + 1 < cap; i++)
            buf[n++] = (char)(i % 256);
    } else if (strcmp(mode, "eva-garbage-exit0") == 0) {
        size_t i;
        *pexit = 0;
        for (i = 0; i < 4096 && n + 1 < cap; i++)
            buf[n++] = (char)(i % 256);
    } else if (strcmp(mode, "eva-garbage-summary") == 0) {
        *pexit = 0;
        n = (size_t)snprintf(buf, cap,
                             "some garbage without alarms\n"
                             "ANALYSIS SUMMARY\n");
    }

    /* ---------- payload-file: byte APA SAJA dari file (PR-010) ---------- */
    /* Dipakai fuzz harness (test/parser_fuzz.c): MYC_FAKE_PAYLOAD_FILE
     * memuat hasil mutasi; fake mengeluarkannya apa adanya sehingga parser
     * backend ASLI (ingest_gcc_diagnostics / parse_filc_report /
     * count_eva_alarms) menerima input fuzz yang tidak terbatas pada korpus
     * tetap. Exit code dari MYC_FAKE_EXIT (default 0). */
    else if (strcmp(mode, "payload-file") == 0) {
        const char *pf = getenv("MYC_FAKE_PAYLOAD_FILE");
        FILE       *f  = pf ? fopen(pf, "rb") : NULL;
        *pexit = 0;
        if (!f) {
            *pexit = 1;
            n = (size_t)snprintf(buf, cap, "payload-file: file tak terbaca\n");
        } else {
            n = fread(buf, 1, cap, f);
            fclose(f);
        }
    }

    /* default: tidak dikenal -> garbage pendek, exit 1 (fail-closed). */
    else {
        *pexit = 1;
        n = (size_t)snprintf(buf, cap, "unknown mode: %s\n",
                             mode ? mode : "(null)");
    }

    if (n >= cap)
        n = cap - 1;
    return n;
}

/* ------------------------------------------------------------------ */
/* Bantuan                                                             */
/* ------------------------------------------------------------------ */

static const char *role_of(int argc, char **argv)
{
    const char *r = getenv("MYC_FAKE_ROLE");
    if (r && *r)
        return r;
    if (argc > 0 && argv[0]) {
        if (strstr(argv[0], "filc-clang"))
            return "filc";
        if (strstr(argv[0], "frama-c"))
            return "eva";
    }
    return "gcc";
}

static int has_arg(int argc, char **argv, const char *s)
{
    int i;
    for (i = 1; i < argc; i++)
        if (strcmp(argv[i], s) == 0)
            return 1;
    return 0;
}

static void copy_stdin_stdout(void)
{
    char  buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0)
        fwrite(buf, 1, n, stdout);
}

static int exit_of(const char *mode, int defexit)
{
    const char *e = getenv("MYC_FAKE_EXIT");
    if (e && *e)
        return atoi(e);
    (void)mode;
    return defexit;
}

/* Salin diri sendiri ke target (build filc: -o <exe>). */
static int self_copy(int argc, char **argv)
{
    const char *target = NULL;
    char        self[4096];
    FILE       *in, *out;
    char        buf[65536];
    size_t      n;
    int         i;

    for (i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            target = argv[i + 1];
            break;
        }
    }
    if (!target)
        return 1;

#if defined(_WIN32)
    if (!GetModuleFileNameA(NULL, self, (DWORD)sizeof(self)))
        snprintf(self, sizeof(self), "%s", argv[0]);
#else
    {
        ssize_t r = readlink("/proc/self/exe", self, sizeof(self) - 1);
        if (r > 0) {
            self[r] = '\0';
        } else {
            snprintf(self, sizeof(self), "%s", argv[0]);
        }
    }
#endif

    in = fopen(self, "rb");
    if (!in)
        return 1;
    out = fopen(target, "wb");
    if (!out) {
        fclose(in);
        return 1;
    }
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
        fwrite(buf, 1, n, out);
    fclose(out);
    fclose(in);
#if !defined(_WIN32)
    chmod(target, 0755);
#endif
    return 0;
}

int main(int argc, char **argv)
{
    const char *role = role_of(argc, argv);
    const char *mode = getenv("MYC_FAKE_MODE");
    char        buf[PAYLOAD_CAP];
    size_t      n;
    int         ex;

    if (argc > 1 && (strcmp(argv[1], "--help") == 0 ||
                     strcmp(argv[1], "-h") == 0)) {
        printf("backend_fake: fake gcc/filc-clang/frama-c (PR-009)\n"
               "env: MYC_FAKE_ROLE=gcc|filc|eva, MYC_FAKE_MODE=<case>,\n"
               "    MYC_FAKE_EXIT=<code>\n");
        return 0;
    }

    /* ---------- mode PROGRAM (hasil build filc dijalankan myc) ---------- */
    if (argc <= 1) {
        if (!mode)
            mode = "filc-garbage";
        n = build_payload(mode, buf, sizeof(buf), &ex);
        fwrite(buf, 1, n, stdout);
        fwrite(buf, 1, n, stderr);
        return exit_of(mode, ex);
    }

    /* ---------- mode BACKEND (dipanggil myc) ---------- */

    if (has_arg(argc, argv, "--version") || has_arg(argc, argv, "-version")) {
        if (strcmp(role, "filc") == 0)
            printf("clang version 20.1.8 (Fil-C 0.681 fake)\n");
        else if (strcmp(role, "eva") == 0)
            printf("frama-c (fake) 33.0 (Arsenic)\n");
        else
            printf("gcc (GCC) 15.2.0 (fake backend for parser abuse)\n");
        return 0;
    }

    if (has_arg(argc, argv, "-dM")) {
        printf("__GNUC__ 15\n__SIZEOF_INT__ 4\n__SIZEOF_POINTER__ 8\n"
               "__CHAR_UNSIGNED__\n");
        return 0;
    }

    if (has_arg(argc, argv, "-E")) {
        copy_stdin_stdout();
        return 0;
    }

    if (has_arg(argc, argv, "-eva")) {
        if (!mode)
            mode = "eva-garbage";
        n = build_payload(mode, buf, sizeof(buf), &ex);
        fwrite(buf, 1, n, stdout);
        return exit_of(mode, ex);
    }

    if (has_arg(argc, argv, "-c")) {
        if (!mode)
            mode = "gcc-json-garbage";
        n = build_payload(mode, buf, sizeof(buf), &ex);
        fwrite(buf, 1, n, stderr);
        return exit_of(mode, ex);
    }

    if (has_arg(argc, argv, "-o"))
        return self_copy(argc, argv);

    /* invokasi tak dikenal: berperilaku seperti gcc --version. */
    printf("gcc (GCC) 15.2.0 (fake backend for parser abuse)\n");
    return 0;
}
