# Production Readiness — definisi level rilis myc

> Dokumen ini membekukan **arti operasional** dari istilah "production ready"
> untuk myc, sesuai batch PR-001 dari `myc-production-readiness-plan.md`.
> Ini adalah **kontrak level rilis**, bukan daftar fitur. Klaim di dokumen ini
> tidak boleh lebih kuat dari bukti yang benar-benar dihasilkan pipeline.
> Referensi implementasi: `AGENTS.md`, `docs/capabilities.md`,
> `docs/production-invariants.md`, `docs/verdict-state-inventory.md`.
> Level rilis saat ini: **PR-3 Production Ready** (2026-08-17). PR-4
> di luar scope.

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

### PR-1 — Usable (tercapai 2026-08-11)

Persyaratan:

- check primer berfungsi (compile + lint + opsi gate runtime/checked/
  prove/filc/driver/negative);
- CI hijau di Windows + Linux (`.github/workflows/ci.yml` menjalankan
  `_ci_linux.sh` dan `_regress_run.bat`; `_audit018.sh` portabel);
- keterbatasan terdokumentasi (`docs/capabilities.md`, `README.md`);
- test anti-false-OK ada (`test/_anti_false_ok.bat`, `test/_anti_false_ok.sh`,
  `tests/spoof_marker_run.c`, `tests/bad_driver_spoof.c`).

### PR-2 — Dependable (tercapai 2026-08-17)

Persyaratan (status tiap item tercantum):

| Item | Status |
|---|---|
| Trust-core invariants diuji (INV-001..015) | INV-001..015 ditegakkan. `--production` (P12) = require-complete + floor min_version. INV-001/002/003/011: `test/reducer_exhaustive.c`; INV-011 cache: `test/cache_corrupt.c` (PR-013); INV-015: `test/production_mode.c` |
| Transisi verdict/state diuji exhaustif | `test/reducer_exhaustive.c` (PR-003) |
| Process runner tahan abuse | Ya: `proc_flood`, `verify_descendants`, `stress_threads`, deadlock matrix PR-006, process-tree kill PR-007 |
| Cache/receipt replay deterministik | Ya (`_regress_run.bat` blok cache + receipt; MYC-AUDIT-042); PR-A01 soak miss/hit tanpa drift |
| Schema punya versi + test kompatibilitas | `myc.result.v1` + registry `docs/schema-registry.md` + `test/schema_compat.c` (PR-015) |
| Backend tak tersedia jadi typed debt | Ya (`myc_build_debt` gate.c; MYC-AUDIT-040/041/042) |
| Crash/hang corpus adversial = 0 | `test/_corpus_abuse.bat`, `oom_alloc`, `mcp_abuse`; soak `test/pra01_soak.c` |

### PR-3 — Production Ready (posisi myc saat ini, 2026-08-17)

Semua kondisi PR-2 **plus** item di bawah. Klaim ini **bukan** PR-4
(High Assurance) dan **bukan** "OK = program aman".

| Item | Status | Bukti |
|---|---|---|
| P5/P6 matriks platform/backend | Ditutup | `docs/backends.md` tier A/B/C + min_version; P6-T01 host Windows/Linux x86-64; ARM/RISC-V = target `--matrix` saja |
| PR-A soak / adversarial | Ditutup dengan batas jujur | `test/pra01_soak.c`, `mcp_abuse`, corpus abuse, `proc_*`. Job `linux-asan` = `continue-on-error`, **bukan** gate rilis |
| PR-004 / P0-T05 trust-core P0/P1 | Ditutup | Closure `docs/audit-closure/MYC-AUDIT-001`..`005.md`; regresi di CI sejak 2026-08-12 |
| P11 provenance + checksum | Ditutup | `release.yml` → `SHA256SUMS` + stempel `git:`; rebuild di `docs/release.md`. **Bukan** bit-identical |
| P4 kontrak CLI/JSON/MCP/receipt | Ditutup | PR-015 `docs/schema-registry.md` + `test/schema_compat.c` |
| P9 threshold benchmark | Ditutup | `bench/run_bench.sh` (20 task, mismatch = FAIL CI); `bench/run_success_metrics.sh` M1–M10 |
| P15 prosedur insiden | Ditutup | `docs/incident.md` |
| P9-T03 ≥2 C eksternal | Ditutup | `dogfood/dogfood_ring.c`, `dogfood_config.c`, `dogfood_tilemap.c` di `_ci_linux.sh` + `_regress_run.bat` |
| PR-A01 soak berulang | Ditutup | `test/pra01_soak.c`: N× no-cache + miss/hit persist tanpa drift verdict/receipt |
| P12 `--production` | Ditutup | INV-015: floor min_version; `test/production_mode.c` |

Batas yang tetap terlihat (bukan utang tersembunyi):

- Frama-C / Fil-C = Tier B (ketiadaan = UNAVAILABLE + debt, bukan FAIL).
- `linux-asan` tidak memblokir rilis.
- Rebuild rilis tidak dijamin bit-identical.
- Heuristik tetap non-blocking.

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

PR-0..PR-3 tertutup di dokumen ini. PR-4 (High Assurance) **tetap di luar
scope**. Rilis biner: `docs/release.md`. Insiden: `docs/incident.md`.
