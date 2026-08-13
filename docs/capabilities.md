# Capabilities & Limitations

myc checks C source in layers. Every gate produces **evidence**; the final
verdict is derived from typed gate status and reported as an **assurance
vector** `C S R B P D F` (Compile / Static / Runtime / Checked / Proof /
Driver / Filc; `0` = n/a, `1` = clean, `2` = findings, `3` = inconclusive).

> myc is a best-effort safety net, **not** a proof of correctness. The real
> evidence is the gate matrix, the per-finding `receipt_sha256`, and the source
> hash — not the label.

## Gate matrix

| Gate                | Flag       | Requires            | What it guarantees                                  | Notes / limits                                                              |
| ------------------- | ---------- | ------------------- | --------------------------------------------------- | --------------------------------------------------------------------------- |
| preprocess          | (always)   | gcc                 | source compiles under `gcc -E`                     | warnings non-blocking                                                        |
| lint                | (always)   | —                   | memory-safety *observations* (confidence-scored)    | **Non-blocking** (MYC-AUDIT-014); text heuristic, not proof                  |
| compile             | (always)   | gcc                 | `-Werror` clean under `-O2 -Wall -Wextra -pedantic` + memory tier (`-Warray-bounds`, `-Wstringop-overflow`, `-Wuse-after-free`, `-Wfree-nonheap-object`, `-Wformat-overflow`, …) | **hard gate**                                                       |
| include-marker-call | (always)   | —                   | whitelist / `# 1` depth-2 / denylist *warnings*    | **Non-blocking** (intended as extra signal, never a blocker)                |
| analyzer            | `--analyze`| gcc                 | `gcc -fanalyzer` clean                              | extra static analysis                                                        |
| checked             | `--checked`| gcc                 | `MYC_BUF` fat-pointer bounds ⇒ **L4 SPATIAL**       | covers **only `MYC_BUF` buffers**; plain arrays not covered — detected as `MYC-INCOMPLETE-RAW-BUFFERS` debt (MYC-AUDIT-040, non-blocking; `--require-complete` escalates) |
| runtime             | `--run`    | clang + ASan/UBSan  | clean run under sanitizers ⇒ **L3 RUNTIME**        | optional; non-blocking if clang absent                                       |
| metamorphic         | `--metamorphic` | clang + ASan  | `-O0` vs `-O2` discrepancy ⇒ UB / toolchain-sensitive | optional; non-blocking if clang absent; divergence ≠ proof of bug          |
| divergence          | `--divergence`  | gcc+clang+[tcc] × {-O0,-O2} | sanitizer divergence across toolchains ⇒ **hard RUNTIME_VIOLATION** (toolchain-sensitive); semantic/diagnostic divergence ⇒ observation | optional; non-blocking if toolchain absent; cells without ASan never claim sanitizer evidence |
| negative            | `--negative` | —                | "missing pattern" observations (e.g. unchecked alloc) | **Non-blocking** (MYC-AUDIT-014); confidence-scored                        |
| quorum              | `--quorum` | —                   | cross-backend agreement (clean / conflict / inconclusive) | optional; extra signal, never a blocker                                |
| require-complete    | `--require-complete` | —        | verification gap = CI failure (`MYC-INCOMPLETE-*`) | makes verdict INCONCLUSIVE when debt exists                                 |
| driver              | `--driver` | clang + ASan        | edge-case harness on contract-tagged functions     | optional; non-blocking if clang absent / no contracts                        |
| exhaustive          | `--exhaustive` | clang + ASan   | full enumeration of a **declared finite domain** ⇒ **P1 EXHAUSTIVE** (proof *within* that domain) | only for functions with `//@ requires n >= LO && n <= HI`; domain firewall rejects widths > 1024/dim or products > 1e6; **never** claims beyond the declared domain; DS-03 state detects SCOPE_LAUNDERING when the domain is narrowed across runs |
| compare             | `myc compare ref.c new.c [func...]` | clang + ASan | shared input battery run on **both versions**; identical ⇒ **behavior-preserving (P1 DIFF)**; any divergence ⇒ unexpected_change | functions must exist in both files with `//@` contracts; battery = union of both contracts' edge candidates + boundary portfolio + deterministic PRNG; DS-04 escrow compares ret + errno + output digest + exit + ABI signature + domain hash; non-pairable functions reported `unobserved` |
| stack               | `--stack [--stack-budget N]` | gcc `-fstack-usage` | worst-case static stack depth from root (`main`/`_start`) vs budget; recursion / alloca / VLA detected | **observation, non-blocking** (static worst-case ≠ dynamic; DS-10); budget default 4096 B; unknown calls (no `.su` frame) reported |
| fuzz                | `--fuzz [--fuzz-iters N] [--fuzz-seed S]` | clang + ASan/UBSan | **fuzz-lite**: deterministic PRNG + bounded loop on contract functions; contract `requires` constrains inputs (edge over blind fuzzers); crash ⇒ **hard DRIVER_VIOLATION** | zero-dependency fallback (no libFuzzer); seed fixed & reproducible (enters receipt); only pure contract functions |
| mutate              | `--mutate-audit [--mutate-max N]` | full pipeline | **verifier audits itself**: mutates code with LLM-error patterns (off-by-one, weakened guard, flipped comparison), re-runs requested gates; mutant that stays clean ⇒ **coverage gap** | **observation, non-blocking** (measures the verification setup, never the program's verdict); equivalent mutants skipped; budget N (default 8) bounds re-builds |
| freestanding        | `--freestanding` | gcc `-ffreestanding -fno-builtin` | C-without-OS mode (firmware): hosted libc APIs (`printf`, `malloc`, `fopen`, `exit`, …) reported as **trap observations**, not silent warnings | **observation, non-blocking**; compile failure in this mode is still a hard compile error; entry need not be `main` |
| baremetal           | `--freestanding` | lint (token heuristics) | **MMIO/volatile/alignment traps (DS-11)**: absolute-address deref without `volatile`, empty-body polling loop without `volatile`/accessor call, `packed` struct with multi-byte fields, `uint8_t*` → multi-byte cast, ISR function without `volatile`/`_Atomic` anywhere | **observation, non-blocking**, confidence-scored (`SUSPICIOUS`/`OBSERVATION`); active only in freestanding mode; catches code that looks correct on x86 but hangs/faults on bare metal |
| abi                  | `--abi` | gcc + helper program | **ABI/FFI Surface Certificate (SOL-14)**: snapshot exported symbols + struct size/align/offset + enum values + target triple + header digest via compiler-generated helper (`sizeof`/`offsetof`/`_Alignof`); `myc abi snapshot/diff`; ABI delta tak diminta = **hard transaction failure** | **observation, non-blocking** (butuh compiler gcc; helper gagal = `abi_ran=0` + laporan, verdict tetap); snapshot deterministik per compiler; delta mengabaikan HEADER sha |
| resource             | `myc resource <file>` | scanner teks (SOL-12) | **Resource Linearity Ledger**: profil acquire/release (default POSIX/Win32: fopen/fclose, open/close, popen/pclose, fdopen/fclose, mmap/munmap, CreateFile/CloseHandle + kustom `//@ resource ACQ -> REL;`) ditelusuri per fungsi ⇒ nasib tiap resource `acquired | released | leaked | double-released | transferred | unknown`; `myc resource <file>` mencetak report langsung; serapan juga muncul di output `check` biasa + `--json` / `--json-summary` (`"resource":{...}`) | **observation, non-blocking**, teks deterministik — verdict TIDAK pernah turun karenanya. Jujur parsial: tanpa interprosedural, resource yang dilewatkan sebagai argumen sembarang bukan klaim leak (`return var` = `transferred`); release pada variabel = parameter fungsi tidak dilaporkan (kepemilikan dari caller) |
| units | `myc units <file>` | scanner teks (SOL-11) | **Units / Shape / Provenance Contracts**: annotation ringan `//@ unit <id> <unit>` (bytes/elements, dst), `//@ shape <id> capacity=<id> length=<id>`, `//@ provenance <id> owned|borrowed|static`, `//@ endian <id> little|big`; myc melacak subset sederhana deterministik: unit mismatch pada assignment `a = b` (beda unit), shape-dim (capacity vs length beda unit), unbound annotation (identifier tak ada di source), dup annotation bertentangan; `myc units <file>` mencetak report langsung; serapan juga muncul di output `check` biasa + `--json` / `--json-summary` (`"units":{...}`) | **observation, non-blocking**, teks deterministik � verdict TIDAK pernah turun karenanya. Jujur parsial: hanya identifier yang eksplisit ter-annotasi; unit disebarkan via assignment intra-file; tidak ada dataflow penuh |
| regression         | `myc regression list \| run [file.c]` | corpus memory (Fase 6) | every counterexample found (fuzz crash with PRNG seed, exhaustive counterexample, driver violation) is auto-saved to `.myc/regression/<kind>_<sha8>.c` + index (idempotent) — fuzz seed PRNG is stored so the exact crashing input is reproducible; `myc regression list` shows the corpus; `myc regression run` replays all seeds (detection backstop); `myc regression run <file.c>` replays every seed-input on the CURRENT source: still violation = bug NOT fixed, OK = **RESOLVED** (a fix cannot silently regress) | NON-blocking both ways; fixtures `fuzz_div0.c` (buggy → STILL FAILING) and `fuzz_div0_fixed.c` (→ RESOLVED) verified in CI |
| thread-probe       | `--thread-probe` | concurrency probe (Fase 6) | **lock-order probe statis**: tracks mutex lock order per function (pthread_mutex_lock/mtx_lock/EnterCriticalSection), flags **LOCK-ORDER INVERSION** when two functions lock the same mutexes in opposite order (A→B vs B→A = potential deadlock); **TSan runtime probe** (best-effort): when the source uses threads and clang supports `-fsanitize=thread`, builds+runs and reports data races — platforms without TSan record "not tested" explicitly (never silence) | NON-blocking observation, verdict never changes; fixture `con_inv.c` must be flagged LOCK-ORDER INVERSION |
| perturb            | `--perturb` | env perturbation (Fase 6) | reruns the verified program with perturbed env (TZ=UTC+14, LC_ALL=tr_TR.UTF-8, PATH=nonexistent, HOME/TERM=nonexistent) and compares stdout-hash + exit code + sanitizer vs baseline — program whose behavior changes = **ENV-SENSITIVE** (verification results could differ on other machines); stable = DETERMINISTIC | NON-blocking observation, verdict never changes; tested with `test/fixtures/pert_tz.c` (localtime/TZ-sensitive) which must be flagged ENV-SENSITIVE |
| audit-tests        | `myc audit-tests` | corpus analysis (Fase 6) | **test-quality audit**: scans `test/`, `test/fixtures/`, `tests/` and maps coverage per hazard class (spatial/temporal/integer/runtime/proof/boundary/capability) and per backend (run/driver/exhaustive/fuzz/mutate/stack/prove/checked/filc/matrix); a hazard class or backend WITHOUT fixture = visible GAP (never silence) | NON-blocking; currently 7/7 hazard classes and 10/10 backends covered; report lists GAP lines explicitly |
| canary             | `myc canary list \| run [backend]` | self-check (Fase 6) | **canary swarm**: every backend that can claim memory-safety must PROVE it is alive via minimal sources that MUST be caught (positive) or MUST stay clean (negative) — compile, analyzer, run, driver, exhaustive, fuzz, mutate, stack, lint (11 canaries); a failed canary means the backend is **UNRELIABLE** (its clean claim cannot be trusted), closing the silent false-clean gap | fully self-contained (ingress MEMORY, no fixture files); non-blocking infrastructure audit — `myc canary run` = 11/11 PASS when all backends verified alive; text evidence per gate checked in `evidence[]` + per-gate reports |
| backends           | `myc backends [--canary]` | backend qualification registry (PR-017, P5-T01/P5-T02) | **backend policy registry**: 13 backend (compile/analyzer/run/driver/exhaustive/fuzz/mutate/stack/lint/checked/prove/filc/matrix) dengan tier kebijakan A (release-blocking) / B (supported non-blocking) / C (best-effort), executable utama, path resolv + versi EXACT (`<exe> --version`, INV-013: identitas backend = evidence), dan jumlah canary per backend; prove/filc jujur ditandai "via WSL" bila `wsl.exe` ada (backend di dalam WSL); `--canary` menjalankan canary per backend (kualifikasi hidup P5-T02: backend HARUS terbukti hidup sebelum klaim bersihnya dipercaya) | **NON-blocking** (registry = laporan, verdict target tidak pernah berubah); `myc backends` cepat (tanpa canary), `--canary` mahal (menjalankan canary per backend); kebijakan lengkap di `docs/backends.md`; flag tak dikenal = fail-fast exit 2 |
| scenario            | `--scenario NAME [--scenario-file PATH]` | JSON profile (strict-validated) | **resep verifikasi per domain** (C5): one command activates the right gate recipe — `cli-daily` (run+analyzer), `library` (driver+exhaustive), `parser` (fuzz+run), `firmware` (freestanding+stack+divergence); `myc scenario list` / `info`; user profiles via `scenarios.json` | `--scenario auto` (D3) infers the smallest sufficient recipe from source structure (main / `//@` contract / firmware patterns) and reports **why**; **DS-12 env contract** (`stack_budget`, `no_heap`, `no_recursion`, …) recorded in the report; never changes the verdict (all gates stay optional) |
| matrix              | `--matrix` | cross-gcc (`arm-none-eabi-gcc`, `riscv32/64-unknown-elf-gcc`) | **portability matrix** (C4): cross-compiles the same source per available target + macro dumps (`__CHAR_UNSIGNED__`, `__SIZEOF_POINTER__`, endianness) compared to host ⇒ shows which **portability bets change** (`char signed → unsigned` kills `c < 0`, pointer size, endianness) + per-target warning set | **observation, non-blocking**; cross-compiler absent = cells skipped with an honest “targets not tested (host-only)” note; never lowers the verdict |
| prove               | `--prove`  | Frama-C (Eva)       | abstract interpretation ⇒ **L2 EVA**               | optional; non-blocking if Frama-C absent (typically Linux)                   |
| profile             | `--profile ID` / `MYC_PROFILE_ID`; `myc profile list\|show <id>\|reset <id>` | store lokal `.myc/profiles/<id>.json` (Fase 7, SOL-20) | **Model/Harness Error Fingerprint**: agregat opt-in per model/harness — jumlah check (ok/findings/inconcl), per-gate status counts, per-class finding counts (gate/findings, verdict-findings, diagnostics, unverified-debt); **privacy-first: TIDAK menyimpan source**, hanya angka agregat | **observation, NON-blocking**; tanpa `--profile`/env TIDAK ada file dibuat; id charset `[A-Za-z0-9._-]` ≤ 63 (invalid = fail-fast exit 2); failure tulis = diabaikan; fix-success/regression/churn ditunda ke task Fase 7 #2 (Trust Calibration) |
| eig                  | `myc eig <file> [--profile <id>] [--budget-ms N] [--unchanged] [--json]` | derivasi murni: frontier + observasi + ledger `.myc/calibration.json` + profil `.myc/profiles/<id>.json` (Fase 7, #2029/DS-14) | **Expected-Information-Gain scheduler**: rekomendasi eksperimen terurut skor `expected_value = P(new_evidence) × severity × scope / (time_cost × token_cost)`; prior = tabel deterministik yang dikalibrasi dari Trust Calibration Ledger (rule `eig-<slug-hazard>`, accepted/confirmed_later naik, rejected/harmful_fix turun) + profil SOL-20 (kelas gate historis harness); `--budget-ms N` → flag `within_budget` per rekomendasi; `--unchanged` → prior dibagi dua (informasi baru kecil) | **observation, NON-blocking** (DS-14: versi pertama = tabel deterministik yang dikalibrasi dari ledger); verdict TIDAK pernah berubah; ledger/profil gagal baca = prior tabel murni; **batas jujur v1**: lapisan PERENCANAAN rekomendasi (`myc eig <file>`), belum memilih/menjalankan gate otomatis di dalam `myc check` (follow-up D3/SOL-30) |
| compare-candidates | `myc compare-candidates <base.c> <c1.c> [c2.c ...] [--json]` | menilai kandidat patch (baseline + hingga 7) pada dimensi terukur deterministik: pipeline myc per file (`myc_run`) + proksi teks (Fase 7, SOL-10) | **Candidate Tournament dengan Pareto Frontier**: dimensi `hard_gate`/`findings`/`obligations_lost`/`churn_lines`/`verification_cost`/`runtime_proxy`/`portability`/`readability` (`stack_impact` = UNMEASURED v1, gap terlihat); Pareto frontier = TIDAK didominasi pada dimensi yang terukur (anti-overclaim SOL-10: BUKAN "terbaik umum"; harness/user memilih final); baseline ikut sebagai opsi "pertahankan original"; report teks + JSON `myc.candidate.v1` | **observation, NON-blocking** (exit 0); baseline tak terbaca / flag tak dikenal / > 7 kandidat = fail-fast exit 2; deterministik; verifikasi_cost memakai tabel biaya DS-14 yang sama dengan eig (bukan salinan) |
| privacy            | `--agent-payload-cap BYTES`; `--no-persist` (Fase 7, DS-14 #3) | flag kontrol ukuran payload + mode tanpa jejak disk | **Privacy/size controls**: `--agent-payload-cap` override cap payload agent `--agent` (0 = default `MYC_AGENT_PAYLOAD_CAP` 16384; valid 1024..1048576; invalid = fail-fast exit 2 pola AUDIT-019/020) — enforcement di `myc_build_agent_result` buang enrichment bertahap (experiments/causal/next_best) sampai muat; agent JSON memuat `payload_cap`. `--no-persist` = mode privasi: ledger `.myc/ledger.json`, cache SOL-18, ledger asumsi, profil SOL-20 TIDAK ditulis (verdict/hasil TIDAK berubah, NON-blocking penuh); kontradiksi `--no-persist` + `--profile` = fail-fast (pola A1) | **NON-blocking penuh** (verdict/exit tetap); cap di luar rentang / non-angka = fail-fast exit 2; bila protokol inti agent melebihi cap, output agent gagal total (`-1`, jujur — bukan truncate diam-diam); tanpa `--no-persist` perilaku lama (ledger/cache default ON) |
| prompt              | `myc prompt <file.c> [--pack-dir DIR] [--no-pack]`; pack juga di-wire ke `myc check <file.c> --agent [--pack-dir DIR] [--no-pack]` dan `myc context <file.c> [--pack-dir DIR] [--no-pack]` (MYC-AUDIT-038) | D4/DS-15: fakta target gcc host + denylist fungsi + konvensi negative-space + idiom MYC_BUF (Fase 7: + project-local pack) | **System-Prompt Contract Generator**: snippet system-prompt ≤ 12 baris deterministik (bukan AI) untuk ditempel harness LLM SEBELUM menulis kode — pencegahan, bukan koreksi. **Project-local prompt/spec pack (item plan terakhir)**: `myc.prompt.md` (teks bebas proyek, cap 8 KiB, disisipkan verbatim) + `myc.spec.json` (spec terstruktur: `name`/`domain` wajib-opsional, `rules`/`allow_headers`/`deny_functions` = array string, batas jumlah/panjang di prompt.h) dicari di direktori proyek (default cwd; `--pack-dir DIR`); sha256 kedua file dilaporkan (deterministik, harness bisa verifikasi). **Wiring (MYC-AUDIT-038)**: pack masuk agent JSON sbg objek `pack` (prompt_text verbatim + spec + sha256) pada `--agent` — enrichment yang dibuang TERAKHIR saat enforcement `--agent-payload-cap`; dan sbg section `project pack` (prioritas terendah, dipotong pertama saat budget penuh) pada paket context SOL-22 | **observation, NON-blocking** (verdict TIDAK pernah berubah); `--no-pack` mematikan pack di ketiga jalur; spec.json ADA tapi invalid = fail-fast exit 2 (pola scenario -2); pack absen = output inti tetap normal (bukan error) |
| filc                | `--filc`   | Fil-C               | memory-safe execution ⇒ **L5 FILC**                | optional; non-blocking if Fil-C absent (Linux/x86_64)                       |

> Registry: daftar kanonik gate/flag/tool ada di `capabilities.json` (single
> source of truth). `test/_cap_sync.sh` memverifikasi doc ini sinkron dengan
> registry dan implementasi.

## Incremental Evidence Cache (SOL-18)

| Flag | Persistence | Behavior | Notes |
| --- | --- | --- | --- |
| (default ON) | `.myc/evidence_cache.json` | **Incremental evidence cache**: run dengan (source, scenario, tool, cwd, stdin, timeout, output cap, header dir, resep gate Fase 5/6) yang sama dengan run sebelumnya di-**REPLAY** tanpa menjalankan backend (verdict/gates/debt/diags/counts/receipt identik SOL-18); miss + source berubah → **delta report** (fungsi berubah + dependents) | **NON-blocking**: `.myc/` tak terbaca = miss, jalur normal; replay TIDAK pernah mengubah verdict; key v2 (spesifikasi per dimensi: `docs/cache-key.md`, PR-011) |
| `--no-cache` | — | matikan cache penuh (replay + store) | deterministik: selalu pipeline penuh |
| `--no-persist` | — | mode privasi: cache (dan ledger/profil/assumsi) TIDAK ditulis | verdict/hasil TIDAK berubah (NON-blocking penuh) |

**Key v2** = `sha256("v2|src|scen|tool|cwd|stdin|t|o|hdir|g2|")` — lihat
`docs/cache-key.md` untuk spesifikasi lengkap per dimensi dan gap v1→v2
yang diperbaiki (PR-011 / MYC-AUDIT-043: `--run-stdin`, `timeout_ms`,
`max_output_bytes`, `checked_header_dir`, flag gate Fase 5/6 kini wajib
memisahkan entry — sebelumnya berbagi key = replay stale/lossy).

## Atomic .myc state writes (PR-012 / P3-T03)

Semua state `.myc` (*.json) ditulis lewat helper bersama `persist.c`
(`myc_persist_atomic_write`) dengan protokol crash-consistent:

```text
tulis temp (<path>.tmp.<pid>, direktori sama) → flush →
fsync (POSIX) / FlushFileBuffers·_commit (Windows) →
rename/replace atomik (POSIX rename / Windows MoveFileExA
MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH) →
optional parent-dir fsync (POSIX)
```

Invariant P3-T03: pada crash di langkah mana pun, file state setelah
restart selalu **OLD valid ATAU NEW valid** — tidak pernah setengah
tertulis yang tampak valid. Temp stale dari crash dibersihkan pada write
berikutnya (termasuk milik PID lain). NON-blocking penuh: gagal tulis
diabaikan, verdict tidak pernah berubah.

File yang dimigrasi: `.myc/evidence_cache.json` (cache.c),
`.myc/ledger.json` (ledger.c), `.myc/assumptions.json` (assume.c),
`.myc/calibration.json` (calibrate.c), `.myc/exhaustive.json` (driver.c),
`.myc/profiles/<id>.json` (profile.c), seed `.myc/regression/*.c`
(regress.c). Teruji oleh `test/atomic_state.c` (PR-012 / MYC-AUDIT-044,
blok 15 di `_audit018.sh`): helper new/overwrite/failure-injection,
crash-simulasi temp stale, stress flip konten, E2E semua penulis +  scan akhir NOL leftover `*.tmp.*`.

## Cache corruption recovery (PR-013 / P3-T04)

File cache `.myc/evidence_cache.json` = input eksternal: TIDAK pernah
 dipercaya mentah-mentah.

- **Integritas byte file (L1)**: sidecar `.myc/evidence_cache.sha256`
  berisi `sha256` hex atas byte MENTAH evidence_cache.json. Hash atas byte
  mentah (bukan re-serialisasi JSON) stabil untuk konten apa pun — teks
  backend bisa berisi byte non-UTF8 yang tidak round-trip stabil.
  Sidecar hilang/stale/tampered = seluruh file di-ignore (fail-closed) →
  replay MISS → recompute.
- **Validasi semantik per entry (L2, setelah byte lolos L1)**: `key`/
  `source` wajib 64-hex, `verdict`/`err` wajib di range enum (verdict
  out-of-range TIDAK di-clamp ke OK — ditolak), enum lain + `duration_ms`
  valid bila ada, gate id/status di range, state mustahil (MC_ERROR tanpa
  err) ditolak.
- **Karantina + self-heal + recompute**: entry korup (L2) di-lewati,
  diagnostic `myc: cache: ...` ke stderr, file di-rewrite tanpa entry
  korup; file tidak ter-parse / byte tidak cocok (L1) di-ignore. Replay
  MISS → pipeline menghitung ulang. Entry duplikat (key sama) didedup
  (pertahankan yang pertama).
- L1 bersifat file-level: SATU byte korup di entry mana pun = seluruh file
  di-ignore → recompute penuh; store berikutnya menulis ulang dari nol
  (entry yang valid ikut dihitung ulang — aman, bukan hilang). L2
  (semantik) bekerja per-entry hanya bila byte file konsisten dengan
  sidecar.
- File cache dari versi lama (tanpa sidecar) ditolak fail-closed (sekali
  recompute; tidak pernah di-replay tanpa verifikasi).

Teruji oleh `test/cache_corrupt.c` (PR-013 / MYC-AUDIT-045, blok 16 di
`_audit018.sh`): truncated JSON, flipped bits, unknown schema, mismatched
hash, duplicate entries, stale backend version, malformed timestamp,
impossible gate state (hash sah pun ditolak), schema lama, non-object
entry, garbage — NEVER crash, NEVER replay korup.

## Receipt canonicalization (PR-014 / MYC-AUDIT-046)

Byte-string yang di-hash untuk `receipt_sha256` dibekukan oleh canonical
test vectors — spec di `docs/receipt-canonical.md`, test
`test/receipt_vectors.c` (blok 17 di `_audit018.sh`):

```text
myc.receipt.v1|verdict|completeness|<id>:<status>|...|debt=<nama>|...|fp=<fingerprint>|sha=<source_sha256>|
```

- `myc_receipt_canonical(res, buf, cap)` (gate.h) = satu-satunya sumber
  kebenaran format (OBSERVABLE); `myc_build_receipt` meng-hash
  keluarannya. Urutan gate/debt = urutan insert (bukan sorted).
- Golden vector V1-V4: string kanonik + sha256 hex dihitung INDEPENDEN
  (python3 hashlib), di-hardcode — mengubah format / enum mapping /
  urutan append mana pun = FAIL langsung.
- Empat lapis: golden hash, implementasi referensi independen di dalam
  test, konsistensi pipeline (`receipt_sha256` hasil reduce == golden),
  properti (determinisme, sensitivitas komponen, urutan, rebuild,
  truncation buffer cap-1 + NUL deterministik).

## Schema registry (PR-015 / MYC-AUDIT-047)

SEMUA skema JSON mesin dibekukan di `docs/schema-registry.md` dengan golden
file di `test/golden/` (8 file) dan test `test/schema_compat.c` (blok 18
`_audit018.sh`):

- `myc.result.v1` (`--json-summary`) — 38 field wajib; `assurance_vector`
  peta FLAT `{"C":"clean",...}` (catatan: serializer penuh `--json`
  `myc_result_to_json` memakai bentuk nested `{"status":...}` — dua skema
  berbeda, masing-masing beku).
- `myc.agent.v2` (`--agent`) — `schema`, `source_sha256`,
  `receipt_sha256`, `payload_cap`, `finding`, `verdict`,
  `assurance_vector`, `witness_text`, `allowed_edits`, `preserve`,
  `forbidden_changes`, `next_check`, `frontier` (+ kondisional
  `primary_finding`, `witness_repro`, `witness_slice`, `experiments`,
  `causal`, `next_best`, `delta_receipt_sha`, `pack`).
- `myc.calibration.v1` (`.myc/calibration.json`) — 6 counter outcome beku
  (`accepted`…`harmful_fix`, urutan `myc_calib_outcome`).
- Evidence cache (`.myc/evidence_cache.json`) — `key`/`source` hex64,
  enum dalam range, sidecar sha256 byte-mentah (PR-013 L1/L2).
- `myc.scenario.v1` (profil user + builtin) — `version:1`, `scenarios[]`.
- `myc.spec.v1` (`myc.spec.json` pack) — `version:1`, `name`, `domain`,
  `rules`, `allow_headers`, `deny_functions`.
- MCP JSON-RPC 2.0 envelope (request `{jsonrpc,id,method,params}` /
  response `{jsonrpc,id,result|error}` + `structuredContent`).

Aturan: additive-only (field asing TETAP diterima konsumen lama — diuji
T9), enum append-only, produsen wajib memancarkan semua field beku (T10),
fail-closed versi tak dikenal (INV-011, T8), perubahan skema = update
registry + golden + test hijau.

## MCP abuse & soak (PR-016 / P4-T04)

`mcp.exe` (server stdio JSON-RPC 2.0) diuji sebagai proses yang TIDAK
dipercaya oleh `test/mcp_abuse.c` (blok 19 `_audit018.sh`):

- **Protocol-clean stdout**: setiap baris yang dicetak mcp adalah respons
  JSON-RPC 2.0 sah (`jsonrpc:"2.0"`, id di-echo, tepat satu
  `result`/`error`) — tidak ada log/diagnostik bocor ke stdout
  (merusak framing klien MCP).
- **Korpus malformed deterministik** (39 kasus, tiap kasus + canary ping):
  json invalid/truncated, root non-objek, jsonrpc/method/id tipe salah,
  unknown method, `tools/call` params/name/arguments tipe salah, flags
  non-array / entry non-string / unknown flag, id null/string (sah),
  dup key, notifikasi valid → tanpa respons, notifikasi tanpa method →
  -32600.
- **Huge payload**: baris ~7,9 MiB (< cap) dan ~9 MiB (> cap 8 MiB
  `MCP_MAX_LINE`, read_line drain) → Parse error -32700 + canary tetap
  dijawab; tidak hang, tidak crash.
- **Duplicate id** → semua dijawab (server stateless). **Notification vs
  request** → notifikasi tanpa respons. **EOF/cancellation** → stdin
  kosong = exit 0 bersih tanpa baris. **Ordering** → respons urut sesuai
  request.
- **Soak 1.090 request** (1.000 ping + light tools + malformed) → tepat
  1.060 respons valid, semua id ping 1..1000 hadir, exit 0, stderr
  kosong.

**Hardening (mcp.c, MYC-AUDIT-048):** flags tool `check` wajib **array
string** — `"flags":"--run"` (string) atau entry non-string kini
ditolak `-32602` fail-fast (sebelumnya di-abaikan diam-diam = gate bisa
mati tanpa pesan).

**Bug proc.c ditemukan suite ini (MYC-AUDIT-048):** `drain_assemble`
untuk output kosong memaksa panjang 1 tapi tidak menulis byte pertama —
`stdout_shown=1` dengan 1 byte heap stale (uninitialized read) di stdout
DAN stderr. Kini output kosong → `shown=0` + string kosong.

## Honest limitations

- **No formal proof.** A clean run means "no evidence of this class of bug
  with the available toolchains", not "correct".
- **L1–L5 scalar labels are legacy/experimental.** Prefer the assurance
  vector.
- **`MYC_BUF` only.** The L4 SPATIAL guarantee applies *only* to buffers
  declared with `MYC_BUF(...)` and accessed via `MYC_AT(...)`. Plain C arrays
  (even correct ones) get L1/L3 only. Also, due to the anonymous-struct design
  of `myc_buf.h`, you **cannot** pass a `MYC_BUF` variable to another function
  or assign one `MYC_BUF` to another — keep the buffer in one scope and access
  it via `MYC_AT`. (See `docs/quickstart.md` for the idiomatic pattern.)
- **`--run` needs Clang + ASan.** On Windows the ASan runtime DLL must be
  resolvable at run time.
- **Denylist is a warning, not a blocker.** Calls to `system`, `exec*`,
  `popen`, file I/O, networking, etc. are reported but never reject the program.
- **Source is untrusted input.** It is never passed through a shell; the
  compiler is always launched with an explicit `program + argv[]`.

## What myc is NOT

- Not a replacement for cppcheck / clang-tidy breadth (no deep data-flow
  rules beyond what gcc/anitizer/Frama-C provide).
- Not a substitute for human review or testing.
- Not a sandbox: it analyzes and (optionally) runs the code; it does not
  confine the program beyond the sanitizer/OS job-object limits used for
  timeouts.

## Baseline benchmark (Fase -1, SOL-24)

`bash bench/run_bench.sh` — 20 task baseline terhadap fixture terverifikasi:

- **Hard detection (14)**: spatial (stack-oob, static-oob), temporal
  (use-after-free, witness-oob), integer overflow, checked (direct, oob,
  type), memory (malloc return), driver (oob), contract (pre), syntax,
  fuzz-lite, exhaustive, divergence.
- **Observasi NON-blocking (6)**: lint (intptr), negative-space, stack
  recursion, env perturb (ENV-SENSITIVE), thread-probe (LOCK-ORDER
  INVERSION) — verdict tetap OK, observasi harus muncul (`obs_pattern`).
- **Metrik**: detection rate, false-positive rate, binary size, default
  latency, full-suite latency, agent payload. Report deterministik di
  `bench/reports/baseline-latest.txt`.

## Result schema beku (Fase -1, SOL-24)

`myc.result.v1` (`--json-summary`) dan `myc.agent.v2` (`--agent`)
**dibekukan**: field tidak dihapus/diubah makna tanpa bump versi; verdict
enum hanya bertambah di akhir; determinisme dijamin modulo `duration_ms` /
`receipt_sha256`. Detail field + aturan perubahan: `docs/result-schema.md`.
