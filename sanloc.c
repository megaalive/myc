/*
 * sanloc.c -- Sanitizer Location Extractor (IDE-1, qwen-review).
 *
 * Mengubah report sanitizer (ASan/UBSan) yang sudah dibaca dari log_path
 * menjadi lokasi pelanggaran TERSTRUKTUR untuk repair loop agent.
 *
 * Format report yang diparse (dari clang ASan, -O0 -g):
 *
 *   ==NN==ERROR: AddressSanitizer: stack-buffer-overflow on address ...
 *   WRITE of size 25 at ... thread T0
 *       #1 0xADDR in copy D:\Temp\...\t.c:3
 *       #2 0xADDR in main D:\Temp\...\t.c:7
 *   ...
 *   freed by thread T0 here:
 *       #2 0xADDR in main D:\Temp\...\uaf.c:4
 *   previously allocated by thread T0 here:
 *       #2 0xADDR in main D:\Temp\...\uaf.c:3
 *   SUMMARY: AddressSanitizer: stack-buffer-overflow D:\...\t.c:3 in copy
 *
 *   UBSan:  FILE:LINE:COL: runtime error: MSG
 *
 * Strategi deterministik (tanpa proses tambahan):
 *   1. violation_kind  : dari baris "ERROR: AddressSanitizer: <kind>".
 *   2. location        : frame "#N ... in FN FILE:LINE" PERTAMA yang
 *        FILE-nya milik source target (skip frame runtime/libc/asan).
 *   3. allocation      : frame pertama pada blok "freed by" /
 *        "previously allocated by" / "allocated by" yang FILE-nya milik
 *        target.
 *   4. UBSan           : pola "FILE:LINE:COL: runtime error:" langsung
 *        memberi lokasi (line + col).
 *   5. Remap line      : bila build_src != source (kontrak di-inject),
 *        hitung jumlah baris tambahan sebelum baris laporan (inject hanya
 *        MENAMBAH baris, tidak mengubah baris source) lalu kurangi.
 *
 * Anti-overclaim: bila tidak ada frame yang jelas milik target,
 * sanloc_line = 0, sanloc_have = 0 — TIDAK pernah menebak lokasi.
 */
#include "sanloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Helper string scan kecil                                            */
/* ------------------------------------------------------------------ */

/* Akhiri baris (indeks setelah '\n' atau akhir buffer). */
static size_t line_end(const char *s, size_t len, size_t pos)
{
    while (pos < len && s[pos] != '\n')
        pos++;
    if (pos < len && s[pos] == '\n')
        pos++;
    return pos;
}

/* Panjang baris (tanpa '\n'/\r). */
static size_t line_content_len(const char *s, size_t len, size_t pos)
{
    size_t e = pos;
    while (e < len && s[e] != '\n' && s[e] != '\r')
        e++;
    return e - pos;
}

/* Ekstrak baris (trim trailing \r\n) — mengembalikan pointer di dalam
 * buffer + panjang. */
static const char *line_at(const char *s, size_t len, int n, size_t *out_len)
{
    size_t pos = 0;
    int    cur = 1;
    while (cur < n && pos < len) {
        pos = line_end(s, len, pos);
        cur++;
    }
    if (cur != n || pos >= len)
        return NULL;
    *out_len = line_content_len(s, len, pos);
    return s + pos;
}

/* Cari substring; kembalikan pointer atau NULL. */
static const char *find_str(const char *hay, size_t hlen, const char *needle)
{
    size_t nlen = strlen(needle);
    size_t i;
    if (nlen == 0)
        return hay;
    if (nlen > hlen)
        return NULL;
    for (i = 0; i + nlen <= hlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0)
            return hay + i;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Frame parser: "#N 0xADDR in FN FILE:LINE"                          */
/* ------------------------------------------------------------------ */

typedef struct {
    int         line;        /* 0 = tidak ada */
    int         col;         /* 0 = tidak ada (ASan tidak memberi col) */
    const char *func;        /* pointer di dalam rpt (bukan NUL-terminated) */
    size_t      func_len;
    const char *file;        /* pointer di dalam rpt */
    size_t      file_len;
} sanloc_frame;

/* Parse satu baris frame. Kembali 1 bila berbentuk frame sah. */
static int parse_frame_line(const char *line, size_t len, sanloc_frame *f)
{
    const char *p;
    size_t      fn_start, fn_end;
    size_t      file_start;
    size_t      colon;       /* ':' sebelum nomor baris */
    const char *digits;

    /* bentuk: "#N ... in FN FILE:LINE" — cari " in " */
    p = find_str(line, len, " in ");
    if (!p)
        return 0;
    /* fungsi = teks setelah " in " sampai spasi / tab berikutnya */
    fn_start = (size_t)(p - line) + 4;
    fn_end = fn_start;
    while (fn_end < len && line[fn_end] != ' ' && line[fn_end] != '\t')
        fn_end++;
    if (fn_end == fn_start || fn_end >= len)
        return 0;
    /* file dimulai setelah spasi; file bisa berisi spasi (path Windows) */
    file_start = fn_end;
    while (file_start < len && (line[file_start] == ' ' ||
                                line[file_start] == '\t'))
        file_start++;
    if (file_start >= len)
        return 0;
    /* nomor baris = digit setelah ':' TERAKHIR pada bagian file */
    colon = len;
    while (colon > file_start && line[colon - 1] != ':')
        colon--;
    if (colon <= file_start)
        return 0;
    digits = line + colon;   /* setelah ':' */
    if (digits >= line + len)
        return 0;
    {
        long ln = 0;
        int  any = 0;
        const char *d = digits;
        while (d < line + len && *d >= '0' && *d <= '9') {
            ln = ln * 10 + (*d - '0');
            if (ln > 100000000L) { ln = 0; any = 0; break; }
            any = 1;
            d++;
        }
        if (!any)
            return 0;
        f->line = (int)ln;
    }
    f->func = line + fn_start;
    f->func_len = fn_end - fn_start;
    f->file = line + file_start;
    f->file_len = colon - file_start;
    f->col = 0;
    return 1;
}

/* Apakah nama file di frame milik runtime/libc/asan (harus di-skip)? */
static int frame_file_is_runtime(const char *file, size_t len)
{
    static const char *const RUNTIME_SUB[] = {
        "clang_rt.asan", "asan_malloc", "compiler-rt", "vctools",
        "KERNEL32", "ntdll", "\\crt\\", "/crt/", "crt\\src", ".dll",
        "windows kits", "Windows Kits", "\\ucrt\\", "/ucrt/", "startup\\",
        NULL
    };
    int i;
    for (i = 0; RUNTIME_SUB[i]; i++) {
        if (find_str(file, len, RUNTIME_SUB[i]))
            return 1;
    }
    return 0;
}

/* Apakah file di frame milik source target?
 * Cocok bila: (a) target_file non-NULL dan file mengandung target_file
 * (path bisa absolut, mis. "D:\Temp\...\<stdin>"); (b) file berakhiran
 * nama source (basename); (c) "<stdin>" ada di file (build via stdin). */
static int frame_file_is_target(const char *file, size_t len,
                                const char *target_file)
{
    size_t i;
    if (target_file && *target_file) {
        size_t tl = strlen(target_file);
        /* cocok substring (path absolut vs nama) */
        for (i = 0; i + tl <= len; i++) {
            if (memcmp(file + i, target_file, tl) == 0)
                return 1;
        }
        /* cocok basename (akhiran) */
        if (tl <= len && memcmp(file + len - tl, target_file, tl) == 0)
            return 1;
    }
    /* build via stdin: clang memberi nama "<stdin>" */
    if (find_str(file, len, "<stdin>"))
        return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Remap nomor baris build_src -> source asli                         */
/* ------------------------------------------------------------------ */

/* Hitung berapa baris tambahan (dari inject kontrak) yang ada di
 * build_src SEBELUM baris ke-line_report. Inject hanya MENAMBAH baris
 * (include assert di awal + assert per fungsi), tidak mengubah baris
 * source. Kembali offset (>= 0). */
static int remap_offset_before(const char *build, size_t blen,
                               const char *src, size_t slen,
                               int line_report)
{
    size_t bi = 0, si = 0;
    int    bl = 1, sl = 1;
    int    offset = 0;
    if (line_report <= 1)
        return 0;
    while (bl < line_report && bi < blen) {
        size_t be = line_end(build, blen, bi);
        size_t se = (si < slen) ? line_end(src, slen, si) : si;
        size_t blc = be - bi;
        size_t slc = (se >= si) ? (se - si) : 0;
        /* bandingkan isi baris (tanpa newline) */
        if (si < slen && blc == slc &&
            memcmp(build + bi, src + si, blc) == 0) {
            bi = be;
            si = se;
            bl++;
            sl++;
        } else {
            /* baris build tidak cocok dengan baris source saat ini:
             * baris tambahan dari inject */
            bi = be;
            bl++;
            offset++;
        }
    }
    return offset;
}

/* ------------------------------------------------------------------ */
/* API                                                                */
/* ------------------------------------------------------------------ */

int myc_sanloc_extract(myc_result *res, const char *rpt,
                       const char *source, size_t source_len,
                       const char *build_src, size_t build_len,
                       const char *target_file)
{
    const char *p;
    const char *q;
    const char *kind = NULL;
    size_t      kind_len = 0;
    sanloc_frame loc;
    sanloc_frame alloc;
    int          have_loc = 0;
    int          have_alloc = 0;
    int          line_off = 0;
    int          line_asli = 0;
    const char *snippet = NULL;
    size_t      snippet_len = 0;

    if (!res || !rpt)
        return 0;

    memset(&loc, 0, sizeof(loc));
    memset(&alloc, 0, sizeof(alloc));

    /* ---------- 1. violation_kind ---------- */
    /* ASan: "ERROR: AddressSanitizer: <kind> on address ..." */
    p = find_str(rpt, strlen(rpt), "ERROR: AddressSanitizer: ");
    if (p) {
        q = p + strlen("ERROR: AddressSanitizer: ");
        kind = q;
        while (q[0] && q[0] != '\n' && q[0] != '\r') {
            if (q[0] == ' ' && q[1] == 'o' && q[2] == 'n' &&
                (q[3] == ' ' || q[3] == '\0'))
                break;
            q++;
        }
        kind_len = (size_t)(q - kind);
        /* fallback: "SUMMARY: AddressSanitizer: <kind> FILE:LINE in FN" */
        if (kind_len == 0) {
            p = find_str(rpt, strlen(rpt), "SUMMARY: AddressSanitizer: ");
            if (p) {
                kind = p + strlen("SUMMARY: AddressSanitizer: ");
                q = kind;
                while (q[0] && q[0] != '\n' && q[0] != '\r' &&
                       q[0] != ' ' && q[0] != '\t')
                    q++;
                kind_len = (size_t)(q - kind);
            }
        }
    }
    /* UBSan: "runtime error:" — kind generik + pesan */
    if (!kind || kind_len == 0) {
        p = find_str(rpt, strlen(rpt), "runtime error:");
        if (p) {
            kind = "undefined-behavior";
            kind_len = strlen(kind);
        }
    }
    if (kind && kind_len > 0) {
        /* kind presisi disimpan di arena (trim spasi) */
        while (kind_len > 0 && (kind[0] == ' ' || kind[0] == '\t')) {
            kind++;
            kind_len--;
        }
        while (kind_len > 0 && (kind[kind_len - 1] == ' ' ||
                                kind[kind_len - 1] == '\t' ||
                                kind[kind_len - 1] == '\r' ||
                                kind[kind_len - 1] == '\n'))
            kind_len--;
        if (kind_len > 0)
            res->sanloc_kind = myc_result_arena_dup(res, kind, kind_len);
    }

    /* ---------- 2. location: frame target pertama ---------- */
    {
        size_t rlen = strlen(rpt);
        size_t pos = 0;
        int    line_no = 0;
        while (pos < rlen) {
            size_t e = line_end(rpt, rlen, pos);
            size_t cl = line_content_len(rpt, rlen, pos);
            const char *line = rpt + pos;
            sanloc_frame f;
            line_no++;
            /* frame ASan: baris dengan indentasi lalu '#' (mis.
             * "    #1 0x... in FN FILE:LINE"). Caranya: skip spasi/
             * tab di awal, lalu cek karakter pertama non-spasi = '#'. */
            {
                size_t sk = 0;
                while (sk < cl && (line[sk] == ' ' || line[sk] == '\t'))
                    sk++;
                if (sk + 1 < cl && line[sk] == '#' &&
                    parse_frame_line(line, cl, &f) &&
                    !frame_file_is_runtime(f.file, f.file_len) &&
                    frame_file_is_target(f.file, f.file_len, target_file)) {
                    if (!have_loc) {
                        loc = f;
                        have_loc = 1;
                    }
                }
            }
            pos = e;
        }
    }

    /* ---------- 3. allocation: blok freed/allocated ---------- */
    /* ASan menempatkan frame alokasi pada blok "freed by thread" /
     * "previously allocated by" / "allocated by" SETELAH frame pelanggaran.
     * Frame TARGET pertama pada blok tersebut = alokasi. Strategi: cari
     * marker blok, lalu frame target pertama SETELAH marker. */
    if (have_loc) {
        static const char *const BLOCK_MARKERS[] = {
            "freed by thread",
            "previously allocated by thread",
            "allocated by thread",
            "deallocated by thread",
            NULL
        };
        const char *best = NULL;
        int         bi;
        for (bi = 0; BLOCK_MARKERS[bi]; bi++) {
            const char *m = find_str(rpt, strlen(rpt), BLOCK_MARKERS[bi]);
            if (m && (!best || m < best))
                best = m;
        }
        if (best) {
            const char *after = best;
            size_t      rlen = strlen(rpt);
            size_t      pos = (size_t)(after - rpt);
            while (pos < rlen) {
                size_t e = line_end(rpt, rlen, pos);
                size_t cl = line_content_len(rpt, rlen, pos);
                const char *line = rpt + pos;
                sanloc_frame f;
                size_t      sk = 0;
                while (sk < cl && (line[sk] == ' ' || line[sk] == '\t'))
                    sk++;
                if (sk + 1 < cl && line[sk] == '#' &&
                    parse_frame_line(line, cl, &f) &&
                    !frame_file_is_runtime(f.file, f.file_len) &&
                    frame_file_is_target(f.file, f.file_len, target_file)) {
                    alloc = f;
                    have_alloc = 1;
                    break;
                }
                pos = e;
            }
        }
    }

    /* ---------- 4. UBSan: "FILE:LINE:COL: runtime error:" ---------- */
    if (!have_loc) {
        p = find_str(rpt, strlen(rpt), ": runtime error:");
        if (p) {
            /* cari FILE:LINE:COL sebelum marker — parse dua ':' terakhir */
            const char *s = p;
            long        col = 0, ln = 0;
            const char *d;
            int         any_col = 0, any_line = 0;
            /* col: digit sebelum ": runtime error:" */
            d = s - 1;
            while (d >= rpt && *d >= '0' && *d <= '9') {
                col = col + (*d - '0') * (any_col ? 10 : 1);
                /* backward digit accumulation */
                any_col = 1;
                d--;
            }
            /* NOTE: perakitan backward di atas salah arah untuk >1 digit;
             * ganti dengan scan maju dari d+1. */
            if (any_col) {
                const char *digits = d + 1;
                long        acc = 0;
                while (*digits >= '0' && *digits <= '9') {
                    acc = acc * 10 + (*digits - '0');
                    digits++;
                }
                col = acc;
            }
            if (any_col && d > rpt && *d == ':') {
                d--;
                while (d >= rpt && *d >= '0' && *d <= '9') {
                    any_line = 1;
                    d--;
                }
                if (any_line) {
                    const char *digits = d + 1;
                    long        acc = 0;
                    while (*digits >= '0' && *digits <= '9') {
                        acc = acc * 10 + (*digits - '0');
                        digits++;
                    }
                    ln = acc;
                }
            }
            if (any_line) {
                loc.line = (int)ln;
                loc.col = (int)col;
                /* file = teks dari awal baris sampai ':' sebelum line */
                {
                    size_t i = (size_t)(d - rpt);
                    while (i > 0 && rpt[i - 1] != '\n')
                        i--;
                    loc.file = rpt + i;
                    loc.file_len = (size_t)(d - rpt) - i;
                }
                /* func tidak diketahui untuk UBSan (tanpa frame) */
                loc.func = NULL;
                loc.func_len = 0;
                have_loc = 1;
            }
        }
    }

    /* ---------- 5. remap line build_src -> source asli ---------- */
    if (have_loc && loc.line > 0 && build_src && build_src != source) {
        line_off = remap_offset_before(build_src, build_len,
                                       source, source_len, loc.line);
        line_asli = loc.line - line_off;
        if (line_asli < 1)
            line_asli = 1;
    } else if (have_loc && loc.line > 0) {
        line_asli = loc.line;
    }

    /* ---------- 6. simpan ke result + witness ---------- */
    if (have_loc && line_asli > 0) {
        res->sanloc_have = 1;
        res->sanloc_line = line_asli;
        res->sanloc_col = loc.col;
        if (loc.func && loc.func_len > 0)
            res->sanloc_function = myc_result_arena_dup(res, loc.func,
                                                        loc.func_len);
        if (loc.file && loc.file_len > 0)
            res->sanloc_file = myc_result_arena_dup(res, loc.file,
                                                    loc.file_len);
        /* snippet: baris source asli di line_asli */
        snippet = line_at(source, source_len, line_asli, &snippet_len);
        if (snippet && snippet_len > 0)
            res->sanloc_snippet = myc_result_arena_dup(res, snippet,
                                                       snippet_len);

        /* witness: violation_line + operation + pre_state (kronologi) */
        if (res->witness) {
            res->witness->violation_line = line_asli;
            res->witness->violation_col = loc.col;
            if (res->witness->operation == NULL && loc.func &&
                loc.func_len > 0) {
                char buf[256];
                snprintf(buf, sizeof(buf), "%.*s di baris %d",
                         (int)(loc.func_len > 128 ? 128 : loc.func_len),
                         loc.func, line_asli);
                res->witness->operation =
                    myc_result_arena_dup(res, buf, 0);
            }
            if (have_alloc && alloc.line > 0) {
                int alloc_asli = alloc.line;
                if (build_src && build_src != source)
                    alloc_asli = alloc.line - remap_offset_before(
                        build_src, build_len, source, source_len,
                        alloc.line);
                if (alloc_asli < 1)
                    alloc_asli = 1;
                if (res->witness->pre_state == NULL) {
                    char buf[256];
                    if (alloc.func && alloc.func_len > 0) {
                        snprintf(buf, sizeof(buf),
                                 "objek dibebaskan/dialokasikan di baris %d "
                                 "(fungsi %.*s)", alloc_asli,
                                 (int)(alloc.func_len > 128 ? 128
                                                            : alloc.func_len),
                                 alloc.func);
                    } else {
                        snprintf(buf, sizeof(buf),
                                 "objek dibebaskan/dialokasikan di baris %d",
                                 alloc_asli);
                    }
                    res->witness->pre_state =
                        myc_result_arena_dup(res, buf, 0);
                }
                res->sanloc_alloc_line = alloc_asli;
                if (alloc.func && alloc.func_len > 0)
                    res->sanloc_alloc_function =
                        myc_result_arena_dup(res, alloc.func,
                                             alloc.func_len);
            }
        }
        return 1;
    }

    /* lokasi tidak dapat dipastikan — sanloc_kind tetap (additive),
     * sanloc_have = 0 */
    return 0;
}
