# Production Invariants — kontrak trust myc

> Registry machine-readable: `docs/production-invariants.json`.
> Setiap invariant punya ID stabil. "Status" menunjukkan apakah invariant
> **ditegakkan implementasi saat ini**, **sebagian**, atau **target**
> (belum ditegakkan, gap terlihat — bukan kesunyian).
> Referensi modul: `gate.c`, `myc.c`, `proc.c`, `run.c`, `compile.c`,
> `cache.c`, `ledger.c`, `budget.c`, `assume.c`, `report.c`, `context.c`.

---

## INV-001 — No evidence → no clean claim

Gate yang diminta tetapi tidak mengeksekusi / crash / timeout / output
tidak ter-parse / kehilangan report / backend tak didukung / bukti tidak
lengkap **tidak boleh pernah** direpresentasikan sebagai `clean`. Harus
salah satu dari `unavailable`, `inconclusive`, `failed`, `timeout`,
`not_run` — dan assurance yang diminta harus menghasilkan debt.

**Status:** ditegakkan.

**Implementasi:** `gate.c` — `myc_reduce_verdict()`: gate requested dengan
status `MYC_GATE_UNAVAILABLE` / `MYC_GATE_INFRA_FAILED` /
`MYC_GATE_INCONCLUSIVE` → `has_incomplete` → verdict `MC_INCONCLUSIVE`
(bila verdict saat itu `MC_OK`/`MC_ERROR`). `myc_build_debt()` (gate.c)
menambah debt `MYC-INCOMPLETE-GATE-UNAVAILABLE` /
`-GATE-INFRA-FAILED` / `-GATE-INCONCLUSIVE`. `--require-complete`
(`enforce_require_complete` di myc.c) menaikkan `OK` → `INCONCLUSIVE`
(exit 1). Status skip jujur sejak MYC-AUDIT-004/010 (9.10).

PR-009 (2026-08-12) menutup gap di jalur POSIX native `myc_prove_gate`:
exit 0 + 0 alarm TIDAK lagi otomatis `COMPLETED_CLEAN` — output harus
memuat "ANALYSIS SUMMARY" (konsisten dengan jalur WSL). Output malformed
garbage + exit 0 → `NOT_APPLICABLE` + evidence skip, bukan clean palsu.

**Test:** `test/reducer_exhaustive.c` (PR-003, tiap status "no evidence"
pada tiap gate kritis → INCONCLUSIVE), `test/_regress_run.bat` (blok
driver_zero_cases / ok_filc --filc / debt), `test/_ci_linux.sh` (blok 4a),
`test/backend_abuse.c` (PR-009, parser-abuse corpus: truncation/dup-key/
deep-nest/huge-num/NUL/UTF-8-invalid/oversized/reordered/garbage/exit-0
pada GCC JSON+text, Fil-C, Frama-C Eva, sanitizer report — never crash,
never promote malformed ke clean), `test/_audit018.sh` blok 12.

---

## INV-002 — Bug evidence dominates incompleteness

Jika satu gate semantik membuktikan violation sementara gate lain
unavailable: `BUG + INCOMPLETE` harus tetap verdict bug, bukan menurun
ke `INCONCLUSIVE` generik.

**Status:** ditegakkan.

**Implementasi:** `gate.c` — reducer mengevaluasi `has_findings` lebih dulu
dari `has_incomplete`; ada gate `MYC_GATE_COMPLETED_FINDINGS` → verdict
`MC_VIOLATION` meski gate lain `UNAVAILABLE`/`INCONCLUSIVE`. Completeness
tetap `INCOMPLETE` + debt, sehingga laporan jujur "BUG + INCOMPLETE".

**Test:** `test/reducer_exhaustive.c` (PR-003, kasus FINDINGS + UNAVAILABLE).

---

## INV-003 — Heuristics cannot create hard safety verdicts

Scanner teks, negative-space, observasi portabilitas, heuristik
resource/state, dan lapisan sejenis tetap **observasi** kecuali dipromosikan
lewat backend semantik yang di-review.

**Status:** ditegakkan.

**Implementasi:** `myc.h` — `MYC_GATE_COMPLETED_OBSERVATIONS` benign di
reducer (`gate.c`: tidak menaikkan verdict, tidak menurunkan completeness,
tidak menambah debt). Modul observasi: `lint.c`, `negative.c`, `state.c`,
`resource.c`, `units.c`, `concur.c`, `perturb.c`, `stack.c`, `matrix.c`,
`taxonomy.c`, `candidate.c` (prinsip MYC-AUDIT-014).

**Test:** `test/reducer_exhaustive.c` (PR-003, COMPLETED_OBSERVATIONS →
OK/COMPLETE/CLEAN tanpa debt), `tests/spoof_marker_run.c`,
`test/_anti_false_ok.sh`.

---

## INV-004 — Identical verification identity → identical receipt identity

Input kanonik + scenario + konfigurasi gate + identitas/versi backend +
kontrak lingkungan yang relevan identik → identitas receipt identik.

**Status:** ditegakkan.

**Implementasi:** `gate.c` — `myc_build_receipt()`: sha256 deterministik dari
`verdict | completeness | gate:id:status* | debt* | fingerprint | source_sha`.
Fingerprint memuat tool path + cwd (mesin-spesifik → golden portabel =
determinisme dua-run, bukan nilai absolut).

**Test:** `test/_regress_run.bat` (blok receipt: REC1==REC2 untuk input sama;
MYC-AUDIT-023), `test/_ci_linux.sh`.

---

## INV-005 — Different semantic environment must not reuse stale evidence

Cache hit tidak valid bila ada dependensi yang memengaruhi bukti berubah.

**Status:** ditegakkan.

**Implementasi:** `cache.c` — key = sha256(source_sha256 + scenario_hash +
tool_key + cwd). `myc_ledger_build_scenario_hash` (ledger.c) memuat seluruh
flags gate + hash budget contract (`|budget=<sha>`) + ack asumsi. tool_key =
versi gcc + clang (`myc_tool_version`). Run stateful
(`--require-assumptions-closed`/`--assumption-ack`) tidak di-cache.

**Test:** `test/_regress_run.bat` (blok cache: hit identik; flags beda →
miss; kontrak beda → miss), `docs/audit-history.md` Fase 3 SOL-18.

---

## INV-006 — Child output cannot spoof semantic evidence

Program yang diuji mencetak teks mirip ASan/UBSan/diagnostic gcc/Frama-C/
marker Fil-C/marker internal MYC tidak boleh memproduksi hard evidence.

**Status:** ditegakkan.

**Implementasi:** MYC-AUDIT-017 — evidence utama sanitizer = file report
`log_path` yang ditulis runtime sanitizer sendiri (env deterministik
`ASAN_OPTIONS=log_path=...` / `UBSAN_OPTIONS=log_path=...` via `preq.env`
di proc.c); teks marker + exit != 0 hanya evidence sekunder; marker + exit 0
diabaikan + diagnostic. Fil-C: parser struktural kanonik (MYC-AUDIT-024).

PR-008 (2026-08-12) menutup saluran spoof tambahan: **file report PALSU**
— program yang diuji berjalan dengan cwd = tmp_dir myc dan bisa menulis
file `"<base>.<pid>"` (nama persis log_path) berisi teks spoof. Report
sekarang HANYA bukti bila exit code != 0 di 6 titik: gate run, metamorphic,
divergence (run.c) + driver, exhaustive, fuzz (driver.c). Karena env memakai
`abort_on_error=1`/`halt_on_error=1`, bug memori nyata SELALU berakhir
non-zero; report + exit 0 = file buatan program -> DITOLAK (konsisten
aturan marker). Prove (frama-c) aman struktural: backend mem-parse source,
program yang diuji tidak pernah dijalankan.

**Test:** `tests/evidence_spoof.c` (fixture korpus: semua marker di
stdout/stderr/argv/file report), `test/evidence_spoof.c` (unit test
T1-T6: marker+exit0, fake-report+exit0, filc panic kanonik, teks Eva di
source, komentar/nama-file, driver fake-report — semua TIDAK boleh jadi
violation), `tests/spoof_marker_run.c`, `tests/bad_driver_spoof.c`,
`test/_audit018.sh` blok 11, `test/_regress_run.bat` blok MYC-AUDIT-017.

---

## INV-007 — Source is never interpreted as a shell command

Aturan `program + argv[]` eksplisit dipertahankan di setiap backend/helper.

**Status:** ditegakkan.

**Implementasi:** `proc.c` — CreateProcess (Windows) / fork+execvp (POSIX)
tanpa shell; command line dibangun dari argv eksplisit; env deterministik
`build_env_block`.

**Test:** `test/argv_probe.c`, `test/audit_lampiran.c` T1 (exec-vs-127,
MYC-AUDIT-003).

---

## INV-008 — Timeout is terminal for that process tree

Setelah timeout/cancel: child mati, descendant mati (atau terbukti
detached by contract), semua pipe tertutup, reader thread berhenti,
file evidence sementara dibereskan, tidak ada stale evidence diterima.

**Status:** ditegakkan (POSIX + Windows).

**Implementasi:** `proc.c` — POSIX: `setpgid` child + `kill(-pid)` + eskalasi
TERM → bounded wait → KILL; Windows: Job Object. Drain thread di-join
setelah child berhenti + pipe tertutup (MYC-AUDIT-001); drain dibuat
sebelum menulis stdin (MYC-AUDIT-002). Report sanitizer dibersihkan
`myc_remove_sanitizer_reports`.

**Test:** `test/verify_descendants.c` (POSIX-only, group-kill mematikan
grandchild), `test/proc_flood.c` (deadlock/flood), `_audit018.sh`.

---

## INV-009 — Receipt binds evidence to source

Receipt tidak boleh di-replay terhadap hash source kanonik berbeda.

**Status:** ditegakkan.

**Implementasi:** receipt memuat `sha=<source_sha256>` (gate.c); cache
replay hanya terjadi bila seluruh komponen key (termasuk source sha)
cocok (cache.c).

**Test:** `test/_regress_run.bat` (receipt deterministik input sama;
ubah source → cache miss/delta).

---

## INV-010 — Schema version is explicit

Setiap hasil yang dikonsumsi mesin punya identifikasi schema/versi eksplisit.

**Status:** ditegakkan.

**Implementasi:** JSON result `schema: "myc.result.v1"` (report.c), MCP
`structuredContent` (mcp.c), receipt prefix `myc.receipt.v1|` (gate.c),
freeze di `docs/result-schema.md`.

**Test:** `test/_schema_golden.sh` (33 field wajib + enum beku + corpus
korup), `test/_mcp_smoke.bat`.

---

## INV-011 — Unknown enum/state fails closed

Parser yang menerima status hard-gate tak dikenal tidak boleh menafsirkan
ulang sebagai `clean`.

**Status:** ditegakkan (reducer, sejak fix PR-003 2026-08-12); **gap
terlihat** pada jalur cache replay (corrupt value verdict di luar rentang
→ field di-ignore → default `MC_OK`; ditangani penuh di P2/P3
cache-corruption policy — lihat `docs/verdict-state-inventory.md` §1d).

**Implementasi:** `gate.c` — `myc_reduce_verdict()` kini punya `default:`
(INV-011): status tak dikenal (di luar enum) → `has_incomplete`
→ `INCONCLUSIVE`, TIDAK pernah clean (sebelumnya jatuh diam-diam ke
`MC_OK` — bug ditemukan test PR-003). `myc_build_debt()` juga menambah
debt `GATE-INCONCLUSIVE` untuk status tak dikenal (fails closed
konsisten). `rc_gate_status()` default `"unknown"`. `cache.c` — clamp
`num <= MYC_GATE_COMPLETED_OBSERVATIONS` / `num <= MC_INCONCLUSIVE`:
nilai di luar rentang tidak di-set (gap verdict → default `MC_OK`).

PR-009 (2026-08-12): konsumen JSON menerapkan fail-closed yang sama —
`myc_budget_parse` (unknown gate/level, skema salah → -1, active=0),
`myc_calib_outcome_parse` (unknown enum → -1), `myc_scenario_apply`
(file profil korup → rc != 0, tidak pernah dipakai), `myc_cache_try_replay`
(file cache korup → miss, tidak pernah dipercaya).

**Test:** `test/reducer_exhaustive.c` (PR-003, status `(myc_gate_status)99`
→ INCONCLUSIVE + debt, tidak pernah OK), `test/backend_abuse.c` T2
(PR-009, konsumen JSON malformed/unknown fails closed).

---

## INV-012 — Partial write is never valid cache

Tulisan terputus ke `.myc/*` tidak boleh menghasilkan cache/ledger/receipt
valid.

**Status:** sebagian. Read side fail-closed (file rusak/truncated → parse
gagal → dianggap miss → recompute; tanpa crash). **Gap:** write side
belum atomik (`myc_cache_store` cache.c: `fopen "wb"` + fwrite + fclose,
tanpa temp+rename+fsync) → crash di tengah tulis menyisakan file truncated
yang aman (ditolak read), tetapi tidak ada quarantine/diagnostic. Target:
P3-T03 (atomic persistent state).

**Implementasi:** `cache.c` (`cache_read_all` tolak parse gagal,
`myc_cache_store` tulis langsung).

**Test:** `test/_regress_run.bat` blok cache; corpus korup
`test/_schema_golden.sh` (myc.result, bukan cache).

---

## INV-013 — Backend identity is evidence

Hasil clean dari satu versi compiler/backend tidak sama senyap dengan versi
lain kecuali policy mengizinkan.

**Status:** ditegakkan.

**Implementasi:** MYC-AUDIT-022 — baris pertama `<exe> --version` disimpan
(`gcc_version`/`clang_version` di myc_result, compile.c/run.c); cache
tool_key memakai versi; fingerprint memuat path tool.

**Test:** `test/_regress_run.bat` blok MYC-AUDIT-022 (`myc version`,
`gcc_version` di report/JSON).

---

## INV-014 — Reproduction command is semantically complete

Metadata reproduksi yang dipancarkan memuat informasi cukup untuk
merekonstruksi check, atau eksplisit mencantumkan dependensi lingkungan
yang hilang.

**Status:** ditegakkan.

**Implementasi:** `context.c` — blok `verify:` berisi perintah reproduksi
penuh (termasuk `--finding-id` bila dipakai); `myc_witness_write_repro`
(witness.c) menulis repro dir; capsule memuat source_sha/stdin_sha/backend/
flags.

**Test:** `test/_regress_run.bat` blok context SOL-22 (8 cek).

---

## INV-015 — Production mode never silently weakens requested assurance

Scenario/budget contract yang meminta bukti runtime/proof/checked tidak
boleh mengganti gate lebih lemah tanpa typed debt.

**Status:** ditegakkan untuk budget contract; `--production` mode itu
sendiri = target P12 (belum ada).

**Implementasi:** `budget.c` — `myc_budget_enforce()`: target `clean` yang
tidak tercapai (tidak diminta / UNAVAILABLE / FINDINGS / not_run) →
verdict `INCONCLUSIVE` (bila masih OK) + debt `MYC-INCOMPLETE-BUDGET-UNMET`
+ `budget_report` rinci dimensi yang dikorbankan.

**Test:** `test/_regress_run.bat` blok SOL-30 (6 cek: tercapai, recipe
lemah gagal, debt muncul, dimensi disebut, finding tetap, JSON invalid
ditolak).

---

## Ringkasan status

| Invariant | Status |
|---|---|
| INV-001 No evidence → no clean claim | ✅ ditegakkan |
| INV-002 Bug dominates incompleteness | ✅ ditegakkan |
| INV-003 Heuristics cannot hard-verdict | ✅ ditegakkan |
| INV-004 Deterministic receipt | ✅ ditegakkan |
| INV-005 No stale cache | ✅ ditegakkan |
| INV-006 No spoofed evidence | ✅ ditegakkan |
| INV-007 No shell interpretation | ✅ ditegakkan |
| INV-008 Timeout terminal | ✅ ditegakkan |
| INV-009 Receipt binds source | ✅ ditegakkan |
| INV-010 Schema version explicit | ✅ ditegakkan |
| INV-011 Unknown state fails closed | ✅ reducer (fix PR-003) / ⚠️ cache replay gap (P2/P3) |
| INV-012 Partial write invalid cache | ⚠️ read ✅ / write atomik gap (P3-T03) |
| INV-013 Backend identity is evidence | ✅ ditegakkan |
| INV-014 Reproduction command complete | ✅ ditegakkan |
| INV-015 No silent weaker assurance | ✅ budget contract / `--production` = P12 |
