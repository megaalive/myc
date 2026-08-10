# AGENTS.md â€” Aturan proyek myc

Dokumen ini hanya memuat **aturan stabil**. Sejarah implementasi dan audit
(MYC-AUDIT-001..030 dan fase pengembangan) ada di
[`docs/audit-history.md`](docs/audit-history.md).

## Tujuan & filosofi (keputusan 2026-08-01)

**Tujuan myc adalah memory-safety dan minimnya bug yang ditimbulkannya â€”
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
   negative-space, scanner, dan contract adalah observasi â€” tidak pernah
   menurunkan verdict.
2. **Satu-satunya gate hard = bukti semantik.** Gate gcc (tier memori
   `-Werror`, `-fanalyzer`), sanitizer runtime (ASan/UBSan), proof (Eva),
   checked (L4), Fil-C.
3. **Jangan pernah mengklaim lebih dari bukti** (claim compiler):
   `L2 (EVA)` bukan "L2 PROVEN"; `L5 (FILC)` bukan "L5 FULL";
   exhaustive hanya untuk domain yang dideklarasikan.
4. **Verification gap harus terlihat, bukan kesunyian** â€” gunakan
   `--require-complete`; backend tak tersedia = `UNAVAILABLE` + debt.
5. **Deterministik**: input + tool + scenario sama â†’ receipt sama.

## Pipeline & gate

```
scan includes (whitelist, non-blocking) â†’ lint heuristik ber-confidence
â†’ gcc -E â†’ scan marker "# 1" depth-2 â†’ scan denylist calls (non-blocking)
â†’ gcc -c -O2 -Wall -Wextra -Werror -pedantic + memory tier        [HARD]
â†’ --analyze   : gcc -fanalyzer
â†’ --run       : clang ASan/UBSan (non-spoofable via log_path report)
â†’ --metamorphic : -O0 vs -O2 (deteksi UB/toolchain-sensitive)
â†’ --checked   : MYC_BUF fat-pointer (L4 SPATIAL)
â†’ --prove     : Frama-C Eva (L2 EVA)
â†’ --filc      : Fil-C (L5)
â†’ --driver    : harness kasus tepi dari kontrak
â†’ --negative  : observasi pola hilang (confidence 0.55â€“0.98)
â†’ --quorum    : bandingkan semua backend yang diminta
â†’ --require-complete : gap verifikasi = kegagalan CI (MYC-INCOMPLETE-*)
```

## Module ownership

| Modul | Fungsi |
|---|---|
| `myc.c`/`myc.h` | Pipeline inti, request/result, arena, ingress canonical |
| `compile.c` | Gate compile gcc + memory tier, ingest diagnostik GCC JSON |
| `run.c` | Gate runtime clang ASan/UBSan, canary semantik, metamorfik, cross-toolchain divergence (A2/DS-02) |
| `driver.c` | Generator harness kasus tepi dari kontrak (budget kombinatorial) |
| `prove.c` / `filc.c` | Backend Frama-C Eva (via WSL) dan Fil-C |
| `contract.c` | Contract-lite `//@ requires/ensures` + validasi purity + klasifikasi relasional (Fase 5) |
| `state.c` | State-Machine Ghosting: ghost machine dari `//@ sm state/event/trans`, deteksi sink/unreachable/no-recovery/undeclared/unused + witness urutan event BFS (Fase 5, SOL-13) |
| `abi.c` | ABI/FFI Surface Certificate: snapshot exported symbols + struct size/align/offset (helper program sizeof/offsetof) + enum + target triple + header digest; ABI delta tak diminta = hard transaction failure (Fase 5, SOL-14, `--abi`, `myc abi`) |
| `resource.c` / `resource.h` | Resource Linearity Ledger: profil acquire->release (default POSIX/Win32 + kustom `//@ resource ACQ -> REL;`) ditelusuri per fungsi => leaked/double-release/transfer/unknown; observasi teks NON-blocking, verdict TIDAK pernah turun (Fase 5, SOL-12, `myc resource`) |
| `units.c` / `units.h` | Units / Shape / Provenance Contracts: annotation ringan `//@ unit|shape|provenance|endian` ditelusuri deterministik (assignment mismatch, shape-dim, unbound identifier, annotation bertentangan); observasi teks NON-blocking, verdict TIDAK pernah turun (Fase 5, SOL-11, `myc units`) |
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
 | `assume.c` | Assumption Closure: ledger taruhan fakta implementation-defined vs macro dump toolchain (`gcc -dM -E`), lifecycle observed..accepted-risk, ack + require-assumptions-closed (Fase 4, A1/DS-01) |
 | `proc.c` | Exec program+argv eksplisit tanpa shell, env deterministik, WSLENV |
 | `mcp.c` | MCP server (JSON-RPC 2.0 ketat) |
 | `report.c` / `json.c` | Laporan teks/JSON, capsule, parser JSON ketat |
 | `policy.c` | Profil header/fungsi (non-blocking) |
 | `scanner.c` | Scanner leksikal source |
| `prompt.c` | D4 (DS-15) System-Prompt Contract Generator + project-local prompt/spec pack (Fase 7, item terakhir + MYC-AUDIT-038): `myc.prompt.md` teks bebas + `myc.spec.json` spec terstruktur (version:1, name wajib; rules/allow_headers/deny_functions) dicari di direktori proyek (--pack-dir, --no-pack), sha256 dilaporkan, NON-blocking (verdict tak pernah berubah), spec invalid = fail-fast; pack di-wire ke `myc check --agent` (objek `pack` di agent JSON, dibuang terakhir saat cap) dan `myc context` (section `project pack` prioritas terendah) |
| `test/_schema_golden.sh` | Golden schema + malformed-input tests (Fase 0): myc.result.v1 field wajib + enum verdict + corpus korup |
| `bench/` | Baseline benchmark 20 task (Fase -1, SOL-24): detection + false-positive + binary/latency/payload; report deterministik di bench/reports/ |
| `docs/result-schema.md` | Truth freeze myc.result.v1 + myc.agent.v2 (Fase -1, SOL-24) |
| `witness.c` | Witness pipeline: repro, minimizer, slice |
| `agent.c` | Agent Evidence Protocol (myc.agent.v2) |
| `canary.c` | Canary Swarm (Fase 6): tiap backend yang bisa klaim memory-safety dibuktikan hidup via canary positif/negatif; `myc canary list | run [backend]`; canary gagal = backend UNRELIABLE |
| `testaudit.c` | Test-Quality Audit (Fase 6): cakupan corpus test per hazard class + backend; `myc audit-tests`; gap eksplisit, NON-blocking |
| `perturb.c` | Environment Perturbation (Fase 6): run ulang dgn env diubah (TZ/locale/PATH/HOME), bandingkan stdout+exit+sanitizer; ENV-SENSITIVE vs DETERMINISTIK, NON-blocking |
| `concur.c` | Concurrency Probe (Fase 6): lock-order statis (inversi urutan mutex = potensi deadlock) + TSan runtime best-effort (data race); NON-blocking observasi |
| `regress.c` | Regression Corpus (Fase 6): counterexample (fuzz/exhaustive/driver) auto-tersimpan ke .myc/regression; `myc regression list|run [file.c]`; replay seed = RESOLVED/STILL FAILING |\| run [backend]`; canary gagal = backend UNRELIABLE |
| `stack.c` | Stack Budget Analyzer: `gcc -fstack-usage` + call graph worst-path, rekursi/VLA/alloca (Fase 5, C2/DS-10, `--stack`) |
| `mutate.c` | Mutation-Audited Verification: verifier mengaudit diri via mutan pola error LLM, coverage gap (Fase 5, B5/DS-09, `--mutate-audit`) |
| `scenario.c` | Scenario Packs: profil JSON resep gate per domain + auto budget (Fase 5, C5/D3/DS-12, `--scenario`, `myc scenario list/info`) |
| `matrix.c` | Target Matrix bare metal: cross-compile + macro dump per target, portability matrix (Fase 5, C4, `--matrix`) |
| `eig.c` / `eig.h` | Expected-Information-Gain Scheduler: rekomendasi eksperimen terurut skor `expected_value = P(new_evidence) x severity x scope / (time x token)`, prior tabel deterministik dikalibrasi dari ledger SOL-21 (`eig-<slug>`) + profil SOL-20; `myc eig <file> [--profile <id>] [--budget-ms N] [--unchanged] [--json]`; observasi NON-blocking (Fase 7, #2029/DS-14) |
| `candidate.c` / `candidate.h` | Candidate Tournament Pareto Frontier: menilai kandidat patch pada dimensi terukur deterministik (hard_gate/findings/obligations_lost/churn/verification_cost/runtime_proxy/portability/readability; stack_impact UNMEASURED v1, gap terlihat); Pareto frontier = TIDAK didominasi pada dimensi yang terukur, anti-overclaim SOL-10 (bukan "terbaik umum", harness/user memilih final); `myc compare-candidates <base.c> <c1.c> [c2.c ...] [--json]`; observasi NON-blocking (Fase 7, SOL-10) |

## Dogfooding (wajib dipertahankan)

1. **Self-dogfooding**: seluruh source myc harus `verdict: OK` via
   `./myc check <file>` â€” dipertahankan di setiap perubahan.
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
      `budget.c`, `assume.c`).
6. **Git hygiene**: `git diff --check` â€” tidak ada whitespace/CRLF issue.
7. **Release process** (wajib untuk setiap release):
   - Jalankan `bash release-guard.sh` â€” verifikasi `master` sudah di-push,
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
| [`CHANGELOG.md`](CHANGELOG.md) | Release notes per rilis (Keep a Changelog) |
| [`docs/audit-history.md`](docs/audit-history.md) | Sejarah MYC-AUDIT-001..039, fase pengembangan, catatan bug lama |
| [`README.md`](README.md) | Penggunaan publik |
| [`docs/capabilities.md`](docs/capabilities.md) | Kapabilitas gate/flag |
| [`docs/quickstart.md`](docs/quickstart.md) | Memulai cepat |
