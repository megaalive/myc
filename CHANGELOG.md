# Changelog

Semua perubahan penting pada `myc` dicatat di sini. Format mengikuti
[Keep a Changelog](https://keepachangelog.com/id-ID/1.1.0/); versioning
semantik per tag rilis (`vX.Y.Z`).

Sejarah implementasi & audit terperinci (MYC-AUDIT-001..039, fase
pengembangan) ada di [`docs/audit-history.md`](docs/audit-history.md).

## [v2026-08-13] — PR-019: Allocator wrapper formal (P7-T02) - 2026-08-13

### Added

- **Allocator wrapper FORMAL (`alloc.c/h`) — MYC-AUDIT-051 (PR-019/P7-T02).**
  Semua alokasi source myc kini lewat `myc_malloc/calloc/realloc/free`:
  produksi = passthrough ke libc. Build `-DMYC_ALLOC_TEST` mengaktifkan hook
  `myc_alloc_set_fail_after(N)` (N alokasi pertama sukses, sisanya NULL) +
  `myc_alloc_fail_count`/`myc_alloc_call_count` untuk OOM injection tanpa GNU
  `ld --wrap`. Migrasi penuh 853 situs di seluruh `.c` pipeline via
  `test/_migrate_alloc.py` (tokenizer C-aware; member access `x->free`/
  `x.free` dan string literal/komentar tak tersentuh). Block 22 di
  `test/_audit018.sh` memverifikasi tak ada panggilan `malloc/calloc/realloc/
  free` mentah di source selain implementasi wrapper. `test/oom_alloc.c`
  ditulis ulang memakai hook `myc_alloc` (tanpa `--wrap` build).

## [v2026-08-11] — Hotfix MYC-AUDIT-042 - 2026-08-11

### Fixed

- POSIX `myc_find_executable` (proc.c) mengembalikan string nama program
  tanpa memeriksa keberadaan file di PATH — backend hilang (mis. `wsl.exe`
  di Linux) dilaporkan `GATE-INFRA-FAILED` alih-alih `GATE-UNAVAILABLE`.
  Kini iterasi `PATH` dengan `access(candidate, X_OK)` seperti cabang
  `_WIN32`; konsisten dengan kontrak `filc.c` (042).

## [v2026-08-10] — Fase 7: Trust Calibration, Scheduler, Pack & Privacy - 2026-08-10

Fase 7 menyelesaikan rencana `gptsol_deepseek-plan.md` **81/81** — dari
"model/harness error fingerprint" hingga pack proyek lokal yang di-wire ke
semua jalur konsumsi model (CLI prompt, `--agent`, context SOL-22, MCP).
Seluruh fitur Fase 7 bersifat **NON-blocking**: observasi/rekomendasi
TIDAK pernah menurunkan verdict (trust rules 1–3); satu-satunya gate hard
tetaplah bukti semantik (gcc tier, sanitizer, EVA, Fil-C, L4).

### Added (MYC-AUDIT-032..039)

- **Model/Harness Error Fingerprint — SOL-20 (`profile.c/h`, MYC-AUDIT-032).**
  `myc profile list|show <id>|reset <id>` + flag `--profile ID` / env
  `MYC_PROFILE_ID` (flag menang atas env). Agregat opt-in per
  model/harness di `.myc/profiles/<id>.json` (schema `myc.profile.v1`):
  **hanya angka** (count per gate / finding class, checks, duration) —
  source TIDAK pernah disimpan (privacy-first). Id charset
  `[A-Za-z0-9._-]` max 63, invalid = fail-fast exit 2.
- **Trust Calibration Ledger — SOL-21 (`calibrate.c/h`, MYC-AUDIT-033).**
  `myc calibrate mark <rule> <outcome>` / `show` / `list` / `reset` +
  flag `--calibrate`. Ledger `.myc/calibration.json` (schema
  `myc.calibration.v1`) mencatat 6 outcome (`accepted`/`rejected`/
  `confirmed_later`/`missed`/`useful_fix`/`harmful_fix`) per rule
  heuristik; state turunan deterministik `OK`/`LOW`/`DISABLED`/`UNKNOWN`
  (min 3 feedback) — kalibrasi rendah hanya melabeli observasi, TIDAK
  pernah menghapus rule atau menyentuh verdict.
- **Expected-Information-Gain Scheduler — DS-14 (`eig.c/h`,
  MYC-AUDIT-034).** `myc eig <file.c> [--profile ID] [--budget-ms N]
  [--unchanged] [--json]`. `expected_value = P(new-evidence) × severity ×
  scope / (time_cost × token_cost)` (int64 deterministik); prior tabel
  dikalibrasi dari ledger SOL-21 (`eig-<slug-hazard>` rules) + profil
  SOL-20; `--unchanged` = prior/2; 6 rekomendasi eksperimen terurut
  (EV desc) + command + rationale.
- **Candidate Tournament dengan Pareto Frontier — SOL-10
  (`candidate.c/h`, MYC-AUDIT-035).** `myc compare-candidates
  <baseline.c> <c1.c> [c2.c … ≤7] [--json]`. Menilai kandidat patch pada
  8 dimensi terukur deterministik (`hard_gate`, `findings`,
  `obligations_lost`, `churn_lines` FNV-1a multiset, `verification_cost`,
  `runtime_proxy`, `portability`, `readability`) + `stack_impact`
  UNMEASURED v1 (**gap terlihat**, bukan kesunyian — trust rule 4);
  Pareto dominance murni tanpa bobot, baseline ikut sebagai opsi;
  anti-overclaim SOL-10 ("tidak didominasi pada dimensi terukur", bukan
  "terbaik umum"); schema `myc.candidate.v1`.
- **Privacy/size controls — DS-14 #3 (MYC-AUDIT-036).** Flag
  `--agent-payload-cap BYTES` (0 = default 16384; valid 1024..1048576,
  fail-fast exit 2) + `--no-persist` (mode tanpa jejak disk: ledger,
  cache SOL-18, ledger asumsi, profil TIDAK ditulis; verdict tidak
  berubah). Enforcement cap membuang enrichment bertahap di
  `myc_build_agent_result`; gagal jujur `-1` bila protokol inti pun tak
  muat (bukan truncate); agent JSON memuat `payload_cap`. Kontradiksi
  fail-fast `--no-persist` + `--profile`/`--write-repro`/
  `--require-assumptions-closed`; validasi API/MCP di
  `myc_request_validate`.
- **Project-local prompt/spec pack — DS-15 (`prompt.c/h`, item plan
  terakhir, MYC-AUDIT-037).** `myc prompt <file.c> [--pack-dir DIR]
  [--no-pack]`. Pack proyek version-controllable `myc.prompt.md` (teks
  bebas, cap 8 KiB, dipotong dengan penanda jujur) + `myc.spec.json`
  (spec terstruktur divalidasi `json_parse` ketat: `version:1` + `name`
  wajib; `rules`/`allow_headers`/`deny_functions` = array string);
  sha256 kedua file dilaporkan (deterministik); spec ADA tapi invalid =
  fail-fast exit 2.
- **Pack wiring: `--agent` + context SOL-22 — MYC-AUDIT-038.** Pack kini
  masuk agent JSON (myc.agent.v2) sebagai objek `pack` (`prompt_text`
  verbatim + sha256 + spec) — dibuang TERAKHIR saat enforcement cap
  (enrichment) — dan sebagai section `project pack` (prioritas terendah,
  dipotong pertama saat budget) pada paket context SOL-22; pack absen
  ditandai eksplisit.
- **Pack wiring: MCP — MYC-AUDIT-039.** Tool MCP `agent_check` menerima
  `pack_dir` (opsional; default cwd server) + `no_pack` (boolean);
  `structuredContent` memuat `pack_present`; spec invalid = error
  tool -32602 (fail-fast); `pinfo.prompt_text` di-free di semua jalur.

### Fixed

- `MYC_ERR_INVALID_AGENT_CAP` tidak ditangani di `myc_error_name`
  (report.c) — `-Werror=switch` menyala; case ditambahkan (036).
- Memory leak `prompt_text` pada path error `-1`/`-2` di `myc_pack_load`
  — cleanup mandiri (037).
- `agent_pack_build_json` mengabaikan return `json_serialize` (OOM bisa
  memberi pointer sampah) — kini `if (!json_serialize) out = NULL` (038).
- Double-free pada path error `myc_build_agent_result < 0` di
  `tool_agent_check` (agent.c sudah free internal sebelum return -1) +
  pola identik pre-existing di `context.c` SEC_ACTION (039).
- 2 bug dev `candidate.c`: `boundary_ok` base-pointer salah (baca di
  luar konteks, UB) dan `base_hash` tidak di-sort sebelum `line_delta`
  (churn menggelembung) (035).

### Changed

- `myc check <file> [--pack-dir DIR] [--no-pack]` — pack opsional untuk
  output `--agent`; `myc context <file> [--pack-dir DIR] [--no-pack]`.
- Benchmark baseline di-refresh tiap fitur additive; detection/clean
  tetap **100% (20/20)** — lihat `bench/reports/baseline-latest.txt`.

### Batas jujur (Fase 7, v1)

- EIG = lapisan PERENCANAAN rekomendasi; belum memilih/menjalankan gate
  otomatis di dalam `myc check` (follow-up).
- Dimensi candidate `churn`/`runtime`/`portability`/`readability` =
  proksi teks deterministik, bukan AST; perbedaan kecil antar kandidat
  jangan dianggap dominansi tunggal.
- Pack MCP di-resolve relatif cwd server (belum ada isolasi per-request);
  `tool_check` (myc.result.v1) tetap bebas pack.
- `--no-persist` berlaku untuk `check` (subcommand `calibrate mark` /
  `profile reset` punya intent eksplisit menulis).

## [v2026-08-05] — Fase 5/6 (sebelumnya)

Fase 5–6 dan sebelumnya: lihat [`docs/audit-history.md`](docs/audit-history.md)
(entry 1–32) dan commit history.
