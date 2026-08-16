# Changelog

Semua perubahan penting pada `myc` dicatat di sini. Format mengikuti
[Keep a Changelog](https://keepachangelog.com/id-ID/1.1.0/); versioning
semantik per tag rilis (`vX.Y.Z`).

Sejarah implementasi & audit terperinci (MYC-AUDIT-001..055, fase
pengembangan) ada di [`docs/audit-history.md`](docs/audit-history.md).

## [v2026-08-16] — qwen-review Fase 7 lengkap (T1..T6, MYC-AUDIT-053..064) - 2026-08-16

### Added

- **Roll-up ukuran sukses keseluruhan — MYC-AUDIT-058 (qwen-review §7/T6).**
  `bench/run_success_metrics.sh` mengukur 5 metrik §7 pada corpus nyata:
  M1 lokasi runtime benar 100% (≥90%, baseline 0%), M2 repair template
  patch terverifikasi 83% (≥50%), M3 regression replay 100%, M4
  `agent_check` konvergen ≤3 iterasi 87% (≥50%; diperkuat di
  MYC-AUDIT-059 jadi 7/8), M5 self-dogfood 56/56 (semua source
  kompiler; diperkuat di MYC-AUDIT-062). M2 repair template
  patch terverifikasi 85% (≥50%; diperkuat di MYC-AUDIT-060 jadi
  12/14). M1 lokasi runtime benar 100% (≥90%; corpus diperluas di
  MYC-AUDIT-061 jadi 9/9).
  Report ke `bench/reports/success-metrics-latest.txt`; wired di
  `_ci_linux.sh` (blok 7c) + `_regress_run.bat`.

- **Perkuat M4: corpus `agent_check` 8 kasus — MYC-AUDIT-059 (follow-up
  T6).** Fixture `test/agent_check_loop_input.jsonl` diperluas dengan 5
  buggy runtime template-able baru: `memset`-heap, `memset`-array,
  `strcat`, UAF lintas-fungsi (`noinline`, di-guard), dan `memcpy`-heap
  — semuanya konvergen ≤3 iterasi via template repair A/B/C. M4 naik
  dari 66% (2/3) ke **87% (7/8)**; UBSan tetap why jujur (anti-
  overclaim).

- **Perkuat M2: corpus repair template 14 kasus — MYC-AUDIT-060
  (follow-up T6).** `test/runtime_repair_test.c` diperluas T8–T15:
  `memcpy`-array-lokal, `memcpy`-heap, `strcpy` multi-baris, UAF nama
  lain, `strcpy`/`strcat` sumber global, overflow non-template
  (jujur-null), dan `memset`-heap 2-digit. M2 kini derivatif dari
  hasil test (`M2-TEMPLATE-PATCH: 12/14`, bukan hardcode 5/6) — naik
  dari 83% ke **85%**; T14 membuktikan anti-overclaim di luar
  vokabular template.

- **Perkuat M1: corpus lokasi runtime 9 fixture — MYC-AUDIT-061
  (follow-up T6).** Fixture baru `rt_double_free.c` (kind baru
  `attempting double-free` via `noinline` — lolos gate statis gcc),
  `rt_heap_memset12.c` (heap-buffer-overflow kapasitas malloc 2-digit),
  dan `rt_memcpy_ovf.c` (stack-buffer-overflow via `memcpy`). M1 tetap
  **100% (9/9)** dengan cakupan kind lebih luas; deterministik dua
  platform.

- **Perkuat M5: self-dogfood semua source kompiler — MYC-AUDIT-062
  (follow-up T6).** Blok M5 di `bench/run_success_metrics.sh` tidak
  lagi hardcode daftar nama parsial (~25, beberapa sudah tidak ada);
  kini iterasi deterministik `*.c dogfood/*.c` — **56/56 verdict OK**
  (termasuk sanloc.c, sha256.c, gate.c, persist.c, dst yang sebelumnya
  tak pernah di-check). Fixture `test/`/`tests/` yang sengaja buggy
  tetap di luar corpus self-dogfood.

- **Lint tidak melebar untuk ukuran literal — MYC-AUDIT-063 (Celah #3
  qwen-review §3.4).** Observasi "tanpa sizeof" kini di-skip bila
  argumen ukuran memcpy/memmove/memset adalah integer literal murni
  (`memset(p,'A',64)`, hex, suffix C) — ukuran eksplisit memang valid;
  observasi tetap untuk ukuran variabel/ekspresi. Mengurangi noise di
  payload agent tanpa mengubah verdict.

- **CI hijau: fix 3 bug blok 6f/6g/6i — MYC-AUDIT-064.** Push pertama
  Fase 7 mengekspos bug yang tak terlihat saat uji lokal (`.myc/`
  kosong): (1) source repair fdiv satu-baris → komentar `//@` menelan
  kode → COMPILE_ERROR → `regression_replay` hilang; (2) `grep -qF
  "a":"b"` di bash membuang kutip → pattern salah (Windows `findstr`
  tak terkena); (3) `cache_find_stale` mencocokkan file dengan entry
  cache path-kosong (source MCP) → baseline watch-diff salah. Semua
  blok 6f/6g/6i kini OK di `_ci_linux.sh` penuh (0 FAIL) + audit018
  SELESAI OK.

### Added (T1-T5: IDE-1/2/4/5/6, MYC-AUDIT-053..057)

- **`--watch-diff` delta assurance per-fungsi — MYC-AUDIT-057 (qwen-review IDE-6/T5).**
  Fast inner loop untuk agent yang mengedit per-fungsi: bandingkan source vs
  baseline cache (scenario sama) → delta TERSTRUKTUR per-fungsi `{name, line,
  status: berubah | identik | baru | dependent}` + counts + timing
  (`watch_diff_ms`, murni teks tanpa backend). Status `dependent` = fungsi
  identik yang memanggil fungsi berubah (perlu re-verify ikut). Output text
  `watch-diff:` + JSON `watch_diff` (`--json` / `--json-summary` / MCP check).
  Run pertama tanpa baseline → jujur "belum ada baseline" (bukan error);
  cache hit → delta kosong (konfirmasi golden). NON-blocking penuh: flag
  TIDAK masuk scenario hash, verdict/gates/receipt TIDAK berubah. Alias
  `--delta` — perintah `myc check <file.c> --delta` yang sudah disarankan
  `myc prompt` selama ini kini valid (sebelumnya unknown flag = fail-fast).

- **Repair template RUNTIME_VIOLATION — MYC-AUDIT-055 (qwen-review IDE-2/T3).**
  MCP `repair` menerima `run:1`: verdict `RUNTIME_VIOLATION` + `sanitizer_location`
  → patch template DETERMINISTIK (bukan AI): `strcpy/strcat` overflow → copy
  ber-batas + null-terminate, `memset/memcpy` overflow → clamp ke
  `sizeof`/kapasitas malloc, UAF → NULL-kan setelah free; UBSan/template
  tidak-yakin → jujur `patch=null` + `why` (anti-overclaim). Patch diterapkan
  in-memory, re-run `--no-cache` (fresh evidence), hasil `new_verdict_after_patch`
  = BUKTI (bukan klaim) + `regression_replay` (IDE-4). Verdict/gate semantics
  tidak berubah. Fix bug sanloc Linux: frame ASan `FILE:LINE:COL` (clang
  Linux) kini di-parse benar (line 11, bukan kolom 5).

- **Sanitizer Location Extractor — MYC-AUDIT-053 (qwen-review IDE-1/T1).**
  Modul `sanloc.c/h`: report ASan/UBSan (log_path non-spoofable) kini di-
  parse menjadi lokasi pelanggaran TERSTRUKTUR untuk repair loop agent:
  `violation_kind` presisi, `location {line, function}`, `allocation
  {line, function}` (blok freed/allocated by), `snippet` baris source;
  remap nomor baris saat kontrak requires di-inject; anti-overclaim
  (tanpa frame target → lokasi tidak ditebak). Field `sanitizer_location`
  di JSON (`--json-summary` + `--json`) dan `--agent`/`context` witness
  menampilkan `line:` — ADDITIVE, verdict/gate semantics tidak berubah.
  Baseline lokasi benar: 0% → ≥90% pada kasus runtime teruji.
- **Fix `--scenario auto` — MYC-AUDIT-054 (qwen-review IDE-5/T2).**
  Deteksi kelas parser: loop baca stdin (`fgets`/`fread`/`scanf`/
  `getchar`/`read(`) + panggilan parsing (`strtol`/`strtod`/`sscanf`/
  `isdigit`/`strchr`/`strtok`) → resep `parser` (fuzz+run), bukan lagi
  `cli-daily` (sebelumnya salah tebak). Prioritas D3: firmware > parser
  > library > cli-daily. NON-blocking; fixture `scen_input_parser.c`
  terverifikasi di CI (Linux + Windows + GitHub Actions).
- **Regression replay pasca-repair — MYC-AUDIT-054 (qwen-review IDE-4/T2).**
  MCP `repair` menerima `patched_source` opsional: bila verdict kode baru
  `OK`, myc me-replay corpus regression (`.myc/regression/`) terhadap kode
  itu in-process (`myc_regress_replay_mem`) dan melampirkan
  `regression_replay: K/N clean` di hasil — bila ada seed masih gagal,
  debt eksplisit "bug lama hidup kembali". Mencegah pola klasik LLM:
  memperbaiki bug A sambil menghidupkan kembali bug B. NON-blocking.

### Fixed

- **Sanloc hilang saat cache replay (kritis):** cache hit membuang
  `sanitizer_location` — repair loop agent jadi tebakan lagi di jalur
  replay (paling sering dilalui). `myc_cache_entry` kini menyimpan +
  me-replay field sanloc (arena dup), replay identik SOL-18.

---

## [v2026-08-14] — PR-018/PR-019 + hotfix MYC-AUDIT-052 - 2026-08-14

### Added

- **Resource ceilings (`limit.c/h`) — MYC-AUDIT-050 (PR-018/P7-T01).**
  Tabel `LIMITS[]` batas input/runtime deterministik (source/stdin/args/
  duration/driver-combos/output/gates), `myc limits` (29 entri, schema
  `myc.limits.v1`), audit `myc limits --require-complete`; kegagalan batas =
  INCONCLUSIVE + debt; NON-blocking penuh.

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

### Fixed

- **Stack-reuse bug stdin writer `proc.c` + `_POSIX_C_SOURCE` persist.c —
  MYC-AUDIT-052.** `warg` (`stdin_writer_arg`) dulu variabel STACK di dalam
  blok `if` di `proc_run_posix`; setelah blok selesai kompiler memakai ulang
  slot-nya untuk `struct timespec ts` di wait loop, thread writer membaca
  `fd=0` (EBADF) dan `data=0x989680` (= `ts.tv_nsec`) → stdin tak pernah
  ditulis/ditutup → `gcc -E` menunggu EOF selamanya → tiap `myc check`
  TIMEOUT di Linux (bug laten sejak PR-006, terpicu setelah PR-019 menggeser
  layout stack). Fix: `warg` di-heap-allocate di kedua platform. Plus
  `persist.c` butuh `#define _POSIX_C_SOURCE 200809L` untuk `fileno()` di
  glibc `-std=c11` (pola sama spt proc.c).

- **Build fixture di CI Linux (follow-up MYC-AUDIT-052).** Fix hang
  mengekspos bug build fixture pra-ada (tersembunyi selama hang; run CI
  hijau terakhir tidak punya section fixture tersebut): `_POSIX_C_SOURCE`
  hilang di 5 fixture (proc_deadlock_matrix/backend_fake/backend_abuse/
  parser_fuzz/receipt_vectors — kill/readlink/setenv/strdup),
  `myc_getpid` hanya di-define untuk `_WIN32` di backend_abuse.c, dan
  glibc 2.39 (ubuntu-24.04) menandai `chdir` `warn_unused_result` (4
  situs). `_audit018.sh` penuh kini SELESAI OK di kedua platform.

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
