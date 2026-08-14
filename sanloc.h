/*
 * sanloc.h -- Sanitizer Location Extractor (IDE-1, qwen-review).
 *
 * Parse report sanitizer (ASan/UBSan) yang sudah dibaca dari log_path
 * (myc_read_sanitizer_report) menjadi lokasi pelanggaran TERSTRUKTUR
 * untuk repair loop agent: violation_kind presisi, baris/fungsi lokasi,
 * baris/fungsi alokasi (freed by / previously allocated by), dan snippet
 * baris source. Murni string scan + atoi — deterministik, TIDAK menambah
 * proses/subproses. TIDAK mengubah verdict/gate semantics (lokasi adalah
 * ekstraksi dari bukti non-spoofable yang sudah ada).
 */
#ifndef MYC_SANLOC_H
#define MYC_SANLOC_H

#include "myc.h"

/*
 * Ekstrak lokasi pelanggaran dari report sanitizer ke dalam myc_result
 * (field sanloc_*) dan lengkapi witness (violation_line, operation,
 * pre_state) bila ada. Mengembalikan 1 bila lokasi pelanggaran berhasil
 * diekstrak, 0 bila tidak (report tetap bukti — lokasi hanya ADDITIVE).
 *
 * rpt          : isi report sanitizer (bukan NULL).
 * source       : source asli yang diverifikasi (untuk snippet + remap line).
 * source_len   : panjang source asli.
 * build_src    : source yang SEBENARNYA di-build (bisa berbeda dari source
 *                bila kontrak requires di-inject) — dipakai untuk remap
 *                nomor baris; NULL = build_src == source.
 * build_len    : panjang build_src.
 * target_file  : nama file yang tampil di frame milik source target
 *                (mis. "<stdin>" untuk build via stdin, atau nama file
 *                source). NULL = coba nama file source / "<stdin>".
 *
 * Anti-overclaim: bila lokasi tidak bisa dipastikan milik source target,
 * sanloc_line = 0 dan sanloc_have tetap 0 — tidak pernah menebak.
 */
int myc_sanloc_extract(myc_result *res, const char *rpt,
                       const char *source, size_t source_len,
                       const char *build_src, size_t build_len,
                       const char *target_file);

#endif /* MYC_SANLOC_H */
