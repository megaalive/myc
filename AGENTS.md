# AGENTS.md — Aturan proyek myc

Dokumen ini hanya memuat **aturan stabil**. Sejarah implementasi dan audit
(MYC-AUDIT-001..030 dan fase pengembangan) ada di
[`docs/audit-history.md`](docs/audit-history.md).

## Tujuan & filosofi (keputusan 2026-08-01)

**Tujuan myc adalah memory-safety dan minimnya bug yang ditimbulkannya —
BUKAN membatasi library yang boleh dipakai user.**

- User memakai **banyak agent harness yang berbeda** dan **model yang
  berbeda** di masing-masing harness; permintaan beragam (hardware, game,
  web, dst). Tiap domain butuh library berbeda.
- Karena itu **tidak boleh** membatasi dengan white/black list
  library/header. Header yang user butuhkan harus diizinkan.
- Yang diinginkan user dari myc: **memory-safety** dan **minimal bug**
  memori (buffer overflow, use-after-free, double-free, null deref,
  integer overflow, dst).

Konsekuensi desain:
- Whitelist header hanyalah *default konservatif*, bukan larangan mutlak.
- Denylist fungsi berbahaya (system, exec*, fopen, ...) adalah *safety*
  tambahan, bukan fokus utama, dan tidak menghalangi program yang sah.
- Focus utama: **static analysis untuk memory-safety** (`-fanalyzer`,
  menangkap jalur yang melewati batas buffer, dll).

## Non-negotiable trust rules

1. **Heuristik teks = observasi ber-confidence, non-blocking.** Lint,
   negative-space, scanner, dan contract adalah observasi — tidak pernah
   menurunkan verdict.
2. **Satu-satunya gate hard = bukti semantik.** Gate gcc (tier memori
   `-Werror`, `-fanalyzer`), sanitizer runtime (ASan/UBSan), proof (Eva),
   checked (L4), Fil-C.
3. **Jangan pernah mengklaim lebih dari bukti** (claim compiler):
   `L2 (EVA)` bukan "L2 PROVEN"; `L5 (FILC)` bukan "L5 FULL";
   exhaustive hanya untuk domain yang dideklarasikan.
4. **Verification gap harus terlihat, bukan kesunyian** — gunakan
   `--require-complete`; backend tak tersedia = `UNAVAILABLE` + debt.
5. **Deterministik**: input + tool + scenario sama → receipt sama.

## Pipeline & gate

```
scan includes (whitelist, non-blocking) → lint heuristik ber-confidence
→ gcc -E → scan marker "# 1" depth-2 → scan denylist calls (non-blocking)
→ gcc -c -O2 -Wall -Wextra -Werror -pedantic + memory tier        [HARD]
→ --analyze   : gcc -fanalyzer
→ --run       : clang ASan/UBSan (non-spoofable via log_path report)
→ --metamorphic : -O0 vs -O2 (deteksi UB/toolchain-sensitive)
→ --checked   : MYC_BUF fat-pointer (L4 SPATIAL)
→ --prove     : Frama-C Eva (L2 EVA)
→ --filc      : Fil-C (L5)
→ --driver    : harness kasus tepi dari kontrak
→ --negative  : observasi pola hilang (confidence 0.55–0.98)
→ --quorum    : bandingkan semua backend yang diminta
→ --require-complete : gap verifikasi = kegagalan CI (MYC-INCOMPLETE-*)
```

## Module ownership

| Modul | Fungsi |
|---|---|
| `myc.c`/`myc.h` | Pipeline inti, request/result, arena, ingress canonical |
| `compile.c` | Gate compile gcc + memory tier, ingest diagnostik GCC JSON |
| `run.c` | Gate runtime clang ASan/UBSan, canary semantik, metamorfik |
| `driver.c` | Generator harness kasus tepi dari kontrak (budget kombinatorial) |
| `prove.c` / `filc.c` | Backend Frama-C Eva (via WSL) dan Fil-C |
| `contract.c` | Contract-lite `//@ requires/ensures` + validasi purity |
| `negative.c` | Negative-space: mining "pola yang hilang" |
| `lint.c` | Heuristik memory-safety ber-confidence (non-blocking) + `why`/`fix` |
 | `gate.c` | Status gate bertipe, evidence, claim compiler, debt, receipt |
 | `ledger.c` | Temporal ledger (receipt chain, delta detection) |
 | `transaction.c` | Repair transaction, preservation obligations, sabotage detector |
 | `frontier.c` | Verification frontier map per hazard class (Fase 3, SOL-02) |
 | `observation.c` | Observation-to-Experiment Compiler (Fase 3, SOL-17) |
 | `causal.c` | Causal Finding Graph: root cause dulu, dependent ditahan (Fase 3, SOL-09) |
 | `nextbest.c` | Next-Best Experiment Rule Table: eksperimen termurah untuk maju dari frontier (Fase 3, SOL-03) |
 | `cache.c` | Incremental Evidence Cache: replay hasil bila input+scenario+tool sama, delta fungsi+dependents (Fase 3, SOL-18) |
 | `context.c` | Agent Context Compiler: paket konteks minimal per finding (SOL-22) |
 | `budget.c` | Assurance Budget Contract: target assurance eksplisit per gate + budget waktu/output, tak tercapai = INCONCLUSIVE + report (SOL-30) |
 | `proc.c` | Exec program+argv eksplisit tanpa shell, env deterministik, WSLENV |
 | `mcp.c` | MCP server (JSON-RPC 2.0 ketat) |
 | `report.c` / `json.c` | Laporan teks/JSON, capsule, parser JSON ketat |
 | `policy.c` | Profil header/fungsi (non-blocking) |
 | `scanner.c` | Scanner leksikal source |
 | `witness.c` | Witness pipeline: repro, minimizer, slice |
 | `agent.c` | Agent Evidence Protocol (myc.agent.v2) |

## Dogfooding (wajib dipertahankan)

1. **Self-dogfooding**: seluruh source myc harus `verdict: OK` via
   `./myc check <file>` — dipertahankan di setiap perubahan.
2. **Dogfooding lintas-program**: tool di `dogfood/` (ring buffer MYC_BUF,
   parser config, tilemap flood-fill) sebagai uji nyata jalur OK.

## CI Guards (checklist wajib sebelum push)

Setiap perubahan ke kode inti myc **wajib** melewati checklist ini:

1. **Compile `-Werror` eksplisit** (Linux + Windows):
   - Linux: `gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -Werror=implicit-function-declaration -c prove.c`
   - Windows (MSYS2 gcc): compile `prove.c` dengan `-Werror` via `build.bat`
   - `prove.c` adalah kantor terdepan untuk `-Werror` (WSL/Frama-C code).
2. **Pre-flight `prove.c` di CI script**: `_ci_linux.sh` dan
   `_regress_run.bat` memuat step pre-flight `prove.c -Werror`.
3. **Audit static mutable global**: setiap `static` non-`const` yang
   **ditulis** harus `_Thread_local` atau dipindah ke arena `myc_result`.
   Cek cepat:
   `grep -rn '^static .*=' myc.c proc.c ... | grep -v 'static const' | grep -v '_Thread_local'`
4. **Build + test lokal**: `build.bat` (Windows) / `bash build.sh` (POSIX)
   sukses; `test/_tmp_ci_subset.sh` PASS; `test/_regress_run.bat` (Windows)
   PASS.
5. **Self-dogfooding**: semua source myc harus `verdict: OK` (termasuk
      `ledger.c`, `transaction.c`, `witness.c`, `agent.c`, `frontier.c`,
      `observation.c`, `causal.c`, `nextbest.c`, `cache.c`, `context.c`,
      `budget.c`).
6. **Git hygiene**: `git diff --check` — tidak ada whitespace/CRLF issue.
7. **Release process** (wajib untuk setiap release):
   - Jalankan `bash release-guard.sh` — verifikasi `master` sudah di-push,
     CI hijau untuk `master`, workflow release siap.
   - Buat tag hanya setelah semua cek di atas lolos: `git tag vX.Y.Z` +
     `git push --tags`; workflow `release.yml` build binary + buat Release.
   - **Jangan pernah membuat tag** sebelum `master` di-push dan CI hijau.

## Catatan build

- Gunakan `bash build.sh` (POSIX) atau `build.bat` (Windows) untuk build
  lengkap `myc`, `mcp`, dan `argv_probe`.
- Build langsung dengan `gcc` mungkin tidak memperbarui binary karena
  masalah filesystem/cache; `build.sh` direkomendasikan.

## Pointer dokumen lain

| Dokumen | Isi |
|---|---|
| [`docs/audit-history.md`](docs/audit-history.md) | Sejarah MYC-AUDIT-001..030, fase pengembangan, catatan bug lama |
| [`README.md`](README.md) | Penggunaan publik |
| [`docs/capabilities.md`](docs/capabilities.md) | Kapabilitas gate/flag |
| [`docs/quickstart.md`](docs/quickstart.md) | Memulai cepat |
