# Production Readiness — definisi level rilis myc

> Dokumen ini membekukan **arti operasional** dari istilah "production ready"
> untuk myc, sesuai batch PR-001 dari `myc-production-readiness-plan.md`.
> Ini adalah **kontrak level rilis**, bukan daftar fitur. Klaim di dokumen ini
> tidak boleh lebih kuat dari bukti yang benar-benar dihasilkan pipeline.
> Referensi implementasi: `AGENTS.md`, `docs/capabilities.md`,
> `docs/production-invariants.md`, `docs/verdict-state-inventory.md`.

myc adalah **evidence orchestrator dan trust broker untuk C yang ditulis
agent dan manusia**: ia mengoordinasikan backend semantik (gcc, clang
ASan/UBSan, Frama-C Eva, Fil-C, checked MYC_BUF, driver harness),
menormalkan bukti ke typed gate status, mengekspos verification debt,
mempertahankan provenance, menghasilkan receipt deterministik, dan membantu
agent memutuskan eksperimen apa yang harus dijalankan berikutnya.

Production readiness **bukan** berarti:

- menggantikan GCC/Clang/Frama-C/Fil-C;
- menjadikan setiap heuristik aturan blocking;
- menambah puluhan famili fitur baru;
- mengklaim `OK` berarti "program aman";
- mengejar coverage bug maksimal dengan mengorbankan kepercayaan.

---

## Level rilis

### PR-0 — Experimental

Diizinkan:

- fitur boleh tidak lengkap;
- perilaku backend boleh berubah;
- field JSON boleh berubah;
- regresi ditoleransi.

Tidak diizinkan: diiklankan sebagai stabil.

### PR-1 — Usable (posisi myc saat ini, 2026-08-11)

Persyaratan:

- check primer berfungsi (compile + lint + opsi gate runtime/checked/
  prove/filc/driver/negative);
- CI hijau di Windows + Linux (`.github/workflows/ci.yml` menjalankan
  `_ci_linux.sh` dan `_regress_run.bat`; `_audit018.sh` portabel);
- keterbatasan terdokumentasi (`docs/capabilities.md`, `README.md`);
- test anti-false-OK ada (`test/_anti_false_ok.bat`, `test/_anti_false_ok.sh`,
  `tests/spoof_marker_run.c`, `tests/bad_driver_spoof.c`).

### PR-2 — Dependable

Persyaratan (status tiap item tercantum):

| Item | Status |
|---|---|
| Trust-core invariants diuji (INV-001..015) | INV-001/002/003/011 diuji eksplisit oleh `test/reducer_exhaustive.c` (PR-003); sisanya diuji via regresi per modul — lihat `docs/production-invariants.md` |
| Transisi verdict/state diuji exhaustif | `test/reducer_exhaustive.c` (kombinasi status gate; PR-003) |
| Process runner tahan abuse | Sebagian: `test/proc_flood.c`, `test/verify_descendants.c`, `test/stress_threads.c`; matriks deadlock penuh = P1-T03 (PR-006) |
| Cache/receipt replay deterministik | Ya (`_regress_run.bat` blok cache + receipt; MYC-AUDIT-042) |
| Schema punya versi + test kompatibilitas | `myc.result.v1` beku di `docs/result-schema.md` + `test/_schema_golden.sh`; kompatibilitas menyeluruh = P4 (PR-015) |
| Backend tak tersedia jadi typed debt | Ya (`myc_build_debt` gate.c; MYC-AUDIT-040/041/042) |
| Crash/hang corpus adversial = 0 | Sebagian: `test/_corpus_abuse.bat`, `test/oom_alloc.c`; corpus penuh = P2/P7 |

### PR-3 — Production Ready (target plan ini)

Semua kondisi PR-2 **plus**:

- matriks platform/backend didukung didefinisikan formal (P5/P6);
- rilis kandidat lolos soak/fault/adversarial suite (PR-A);
- tidak ada bug trust-core P0/P1 terbuka (PR-004 closure + P0-T05);
- artefak rilis punya provenance + checksum (P11);
- rilis dapat dibangun ulang reproducible dalam toleransi terdokumentasi (P11);
- kontrak kompatibilitas CLI/JSON/MCP/receipt ada (P4);
- threshold benchmark mencegah regresi kualitas senyap (P9);
- prosedur insiden produksi ada (P15);
- ≥2 codebase C eksternal nyata di-dogfood terus-menerus (P9-T03);
- myc bertahan beban verifikasi self-hosted berulang tanpa leak, deadlock,
  cache basi, atau verdict drift (PR-A01).

### PR-4 — High Assurance

**Di luar scope plan ini secara eksplisit.** Membutuhkan klaim formal-method
yang jauh lebih kuat, review independen, semantik diformalkan, dan mungkin
proof sebagian trust core. **Jangan** memblokir milestone production-ready
karena PR-4.

---

## Apa arti `OK` (kontrak satu halaman)

Dekat README top, kontrak berikut harus tetap pendek dan stabil:

```text
OK berarti:
gate semantik yang diminta dan tersedia selesai tanpa mendeteksi pelanggaran,
sesuai scope terdokumentasi masing-masing.

OK TIDAK berarti:
program benar,
semua jalur dieksekusi,
semua bug memori mustahil,
OS/toolchain dipercaya,
atau backend proof yang tidak diminta ikut berjalan.
```

---

## Rekomendasi eksekusi

Urutan kerja dari plan §21 (P0 → P1 → ... → P15 → PR-A). Batch PR-001..004
(P0) adalah fondasi yang sedang dikerjakan; lihat `myc-production-readiness-plan.md`
untuk detail mileston per batch.
