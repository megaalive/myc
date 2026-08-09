/*
 * profile.h -- Model/Harness Error Fingerprint (Fase 7, SOL-20).
 *
 * Opt-in profil lokal yang menjawab: "harness/model ini cenderung memicu
 * kelas finding apa, dan gate mana yang menemukannya?" Aggregasi kasarnya
 * DIPAKAI calon scheduler EIG (task #3) untuk memprioritaskan pemeriksaan.
 *
 * PRIVACY (exit criteria Fase 7):
 *   - opt-in: hanya aktif bila `--profile <id>` atau env MYC_PROFILE_ID;
 *   - lokal:  `.myc/profiles/<id>.json`, tanpa telemetry;
 *   - TANPA source: file TIDAK pernah berisi source_sha256 atau snippet;
 *     hanya agregat count per class/gate + duration proksi.
 *
 * NON-blocking (trust rule 1 & 3): profil adalah observasi. Ia TIDAK pernah
 * menaikkan/menurunkan verdict. Gagal tulis = dilewati diam-diam (pola
 * .myc/assumptions.json). Kalibrasi rendah (count kecil) = observation
 * saja, bukan klaim.
 *
 * Batas jujur: agregat count per gate/class, tanpa urutan temporal, tanpa
 * per-finding detail, tanpa source hash. fix-success/regression/churn/
 * false-positive feedback sengaja DITUNDA ke Trust Calibration Ledger
 * (task #2) -- di luar scope task #1.
 *
 * File hanya ditulis/umum oleh subcommand `myc profile` dan saat check
 * memakai --profile. Tata letak file: .myc/profiles/<id>.json
 */
#ifndef MYC_PROFILE_H
#define MYC_PROFILE_H

#include "myc.h"
#include <stddef.h>

#define MYC_PROFILE_ID_MAX    63
#define MYC_PROFILE_DIR       ".myc/profiles"
#define MYC_PROFILE_SCHEMA    "myc.profile.v1"

/* Validasi identifier: charset [A-Za-z0-9._-], panjang 1..63.
 * 1 = valid, 0 = invalid (path-traversal/whitespace/sedikit). */
int myc_profile_id_valid(const char *id);

/* Record satu hasil check ke profil <id>. Load-or-init .myc/profiles/<id>.json,
 * update agregat, save. NON-blocking: tidak ada hasil error yang fatal;
 * gagal baca/tulis = profil diabaikan. Memanggil dengan id invalid = no-op. */
void myc_profile_record(const myc_result *res, const char *id);

/* Laporan teks profil <id> ke buf (malloc'd? TIDAK -- isi buf, return kode).
 *   0  = ok, buf terisi;
 *  -1  = profil tak ada;
 *  -2  = id invalid;
 *  -3  = file profil rusak (invalid JSON). */
int  myc_profile_show(const char *id, char *buf, size_t cap);

/* Daftar file profil (*.json) di .myc/profiles, satu baris per id.
 * 0 = ok (tidur; buf mungkin kosong bila tak ada), -2 = dir tak ada. */
int  myc_profile_list(char *buf, size_t cap);

/* Hapus file profil <id>. 0 = terhapus, -1 = tak ada, -2 = id invalid. */
int  myc_profile_reset(const char *id);

#endif /* MYC_PROFILE_H */