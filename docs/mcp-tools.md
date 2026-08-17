# MCP tools myc — panduan untuk coding agent

`mcp.exe` adalah MCP server (JSON-RPC 2.0 over stdio, newline-delimited —
satu pesan per baris). Agen yang mendukung MCP dapat menghubungkan `mcp.exe`
sebagai server dan memanggil pipeline verifikasi `myc` sebagai tool.

Agen lemah: pakai tool **`verify`** (`myc.lite.v1`). Agen frontier: `agent_check`.

## Koneksi

- Transport: stdio (server dijalankan sebagai subproses, `command: mcp.exe`).
- Protokol: MCP 2024-11-05. Negosiasi STRICT (MYC-AUDIT-016): `initialize`
  selalu mengumumkan versi server, tidak meng-echo permintaan klien.
- JSON-RPC 2.0 ketat: field `jsonrpc` wajib `"2.0"` (selain itu → error
  -32600); `id` hanya string/angka/null; pesan tanpa `id` = notification
  (diproses tanpa balasan).
- Server mengekspos capabilities `tools` (tanpa listChanged).
- Handshake: klien kirim `initialize` → server balas `serverInfo`
  (`{name:"myc", version}`) → klien kirim `notifications/initialized`.
- Server memanggil pipeline **in-process** (`myc_run`); source hanya lewat
  stdin. Tidak ada shell string.

## Tools

### 1. `check` — verifikasi source C (pipeline penuh)

- `source` (string, **wajib**): kode C yang akan diperiksa.
- `flags` (array string, opsional): `--run --prove --checked --filc
  --driver --analyze --strict --no-lint` (lihat
  [`docs/capabilities.md`](capabilities.md) untuk arti tiap flag).
  **Wajib array string** (PR-016 / MYC-AUDIT-048): `"flags":"--run"`
  (string) atau entry non-string → error -32602 fail-fast — tipe salah
  TIDAK pernah di-abaikan diam-diam (bisa mematikan gate tanpa pesan).
- `run_stdin` (string, opsional): stdin untuk program verification. Efektif
  bila `--run` (verification build clang) atau `--filc` (verification build
  Fil-C) diminta — konten ini dikirim ke stdin program yang dijalankan gate
  tersebut (pengganti `--run-stdin FILE` di CLI).
- `cwd` (string, opsional): direktori kerja gate (gcc/clang).
- **Hasil**: `content[0].text` memuat **JSON lengkap** `myc_result`
  (`verdict`, `assurance`, `error`, `exit_code`, `duration_ms`,
  `resolved_gcc`, `gcc_version`, `clang_version` (exact tool identity,
  MYC-AUDIT-022), `fingerprint`, `source_sha256`, `contract_requires`,
  `contract_ensures`, `truncated`, `stdout_bytes`, `stderr_bytes`, plus
  seksi gate yang berjalan (`run_*`, `checked_*`, `filc_*`, `driver_*`,
  `prove_*`) dan `diagnostics[]`). **Dan** objek `structuredContent`
  (schema `myc.result.v1` = hasil yang sama sebagai JSON terstruktur) —
  konsumen mesin TIDAK perlu parse JSON di dalam JSON (MYC-AUDIT-016).
- `isError` HANYA untuk kegagalan tool/protocol: verdict infrastruktur
  `ERROR` (input terlalu besar dll.), `TIMEOUT`, `CANCELLED` → `true`.
  Finding pada KODE (`PROVE_VIOLATION`, `DRIVER_VIOLATION`,
  runtime, compile) dikirim sebagai hasil biasa dengan `isError: false`
  (verdict membawa maknanya).
- **Verdict yang mungkin**: `OK`, `COMPILE_ERROR`,
  `RUNTIME_VIOLATION` (--run), `PROVE_VIOLATION` (--prove),
  `FILC_VIOLATION` (--filc), `DRIVER_VIOLATION` (--driver).
  (Lint tidak menghasilkan verdict — hanya observasi, MYC-AUDIT-014.)
- **Assurance ladder**: `L0 RAW` → `L1 SANE` (statis gcc) → `L2 EVA`
  (Frama-C Eva: 0 alarm RTE di bawah model, abstract interpretation) →
  `L3 RUNTIME` (ASan/UBSan) → `L4 SPATIAL` (MYC_BUF checked) →
  `L5 FILC` (eksekusi Fil-C bersih; label lama "FULL" dihapus — MYC-AUDIT-013).
  Level = yang tertinggi yang DIBUKTIKAN.

Contoh:

```json
{"name":"check","arguments":{
  "source":"#include <stdio.h>\nint main(void){char b[64];if(fgets(b,sizeof b,stdin))printf(\"got:%s\",b);return 0;}",
  "flags":["--run"],
  "run_stdin":"halo myc\n"}}
```

### 2. `version` — versi myc + ketersediaan backend

Tanpa argumen. Hasil teks:

```
myc 0.1.0
gcc: <path>
clang: <path> (TIDAK DITEMUKAN bila --run/--driver tidak tersedia)
```

### 3. `policy` — whitelist header default

Tanpa argumen. Hasil teks:

```
whitelist header (N):
  <stdio.h>
  ...
```

> Kebijakan (pivot 2026-08-01): whitelist hanyalah *default konservatif*,
> non-blocking (warning). Bukan daftar larangan mutlak.

### 4. `contracts` — scan kontrak-lite `//@ requires/ensures`

- `source` (string, **wajib**).
- **Hasil** teks:

```
contracts: requires=N ensures=M
  requires n <= 4;
  ensures  r >= 0;
```

Tidak menjalankan pipeline; hanya scan kontrak (API `myc_contract_list`).

### 5. `lint` — lint memory-safety myc (heuristik, NON-blocking)

- `source` (string, **wajib**).
- **Hasil** teks:

```
lint: N observasi (heuristik teks, NON-blocking -- MYC-AUDIT-014)
  [line:col] [confidence] pesan diagnostic...
```

MYC-AUDIT-014: heuristik teks TIDAK menghasilkan verdict — hanya observasi
ber-confidence (`observation`/`suspicious`). Hard violation ditangani bukti
semantik (gcc `-Wuse-after-free`, `-fanalyzer`, sanitizer, checked).
Pola yang di-observasi: cast pointer via `intptr_t`/`uintptr_t` (suspicious
bila operand jelas pointer, observation bila tidak), realloc ke variabel
lain (suspicious), memcpy/memmove/memset tanpa `sizeof` (observation),
ukuran alokasi perkalian tanpa `sizeof` (observation), akses langsung
`b[i]` pada variabel `MYC_BUF` (observation; hard = checked gate).

`lint` juga menyertakan **`why`** dan **`fix`** (template, bukan AI-generated)
di text output dan `structuredContent`: `why` = alasan pola berisiko, `fix` =
saran perbaikan berbasis template. Fungsi `myc_lint_why()` / `myc_lint_fix()`
di `lint.c`.

### 6. `repair` — patch minimal untuk finding (compile gcc ATAU runtime sanitizer)

- `source` (string, **wajib**): kode C yang akan diperbaiki.
- `finding_code` (string, opsional): salah satu dari `gcc-use-after-free`,
  `gcc-null-dereference`, `gcc-array-bounds`, `gcc-stringop-overflow`,
  `gcc-free-nonheap-object`. Bila kosong, repair memakai diagnostic pertama
  dari hasil `check` source yang sama.
- `run` (number, opsional, **IDE-2**, default 0): bila 1, repair menjalankan
  gate runtime (clang ASan/UBSan) sehingga `RUNTIME_VIOLATION` + lokasi
  `sanitizer_location` terisi. Repair lalu menghasilkan patch template
  deterministik berbasis lokasi dan **menerapkannya ke source** (hanya
  menyentuh baris pelanggaran, anti-churn):
  - `strcpy`/`strcat` overflow → copy ber-batas + null-terminate
    (`memcpy` + ukuran variabel — compile-clean tanpa `<stdio.h>` dan
    tanpa `-Wformat-truncation`);
  - `memset`/`memcpy` overflow → clamp `n` ke `sizeof` (array lokal) atau
    kapasitas alokasi `malloc` (baris alloc dari report);
  - `use-after-free` → NULL-kan pointer setelah `free()` (baris free dari
    blok `freed by`).
  Bila template tidak yakin (mis. UBSan undefined-behavior), `patch` bernilai
  `null` + `why` jujur — TIDAK pernah menebak. Karena cache replay (SOL-18)
  tidak menyimpan `sanloc_*`, `run=1` menonaktifkan cache otomatis agar bukti
  selalu fresh.
- `patched_source` (string, opsional, **IDE-4**): kode baru setelah patch
  diterapkan. Bila verdict kode baru = `OK`, myc me-replay corpus regression
  (`.myc/regression/`) terhadap kode baru secara in-process dan melampirkan
  `regression_replay` (mis. `1/1 clean`; bila ada seed yang masih gagal,
  debt eksplisit "N masih gagal (bug lama hidup kembali)"). Mencegah pola
  klasik LLM: memperbaiki bug A sambil menghidupkan kembali bug B.
- **Hasil** JSON: `finding`, `applied_verdict`, `confidence`, `patch`
  (diff siap-apply, `null` bila tidak tersedia), opsional
  `new_verdict_after_patch` (BUKTI re-run — dari patch runtime IDE-2 atau
  `patched_source` IDE-4, bukan klaim) + `regression_replay`, opsional `why`
  (alasan template tidak yakin), dan objek `structuredContent` (schema
  `myc.repair.v1`).
- **Batasan**: patch murni template deterministik (bukan AI-generated). Tidak
  semua finding punya template — bila tidak, `patch` bernilai `null` + alasan.

Contoh (compile):

```
{"name":"repair","arguments":{
  "source":"int f(void){char*p=malloc(4);return p[4];free(p);}",
  "finding_code":"gcc-stringop-overflow"}}
```

Contoh (runtime, IDE-2):

```
{"name":"repair","arguments":{
  "source":"#include <string.h>\nint f(void){char b[6]; strcpy(b, \"abcdefghij\"); return b[0];}\nint main(void){(void)f(); return 0;}",
  "run":1}}
```

### 7. `agent_check` — verifikasi source C dengan protokol agent (myc.agent.v2)

- `source` (string, **wajib**): kode C yang akan diperiksa.
- `flags` (array string, opsional): sama seperti tool `check`
  (`--run --prove --checked --filc --driver --analyze --strict --no-lint
  --quorum --metamorphic --negative --require-complete`). **Wajib array
  string** (PR-016 / MYC-AUDIT-048) — tipe salah = -32602 fail-fast.
  Meneruskan `--run` mengaktifkan deteksi runtime (RUNTIME_VIOLATION +
  `sanitizer_location`) sehingga loop repair bisa bekerja.
- `max_iter` (number, opsional, **IDE-3/T4**, default 3, dibatasi 1..8):
  **bounded repair loop** — satu panggilan `agent_check` menjalankan:
  1. `check(mode)` → verdict;
  2. bila findings: repair(template) → patch;
  3. apply patch **di memori** → check lagi → bandingkan verdict;
  4. ulangi maks `max_iter`; **setiap iterasi tercatat receipt chain di
     ledger** (`.myc/ledger.json`, NON-blocking — receipt_parent =
     receipt iterasi sebelumnya, delta dihitung vs iterasi sebelumnya);
  5. hasil: verdict akhir + array langkah `repair_loop.steps[]` +
     `preservation_obligations`.
  Tiap langkah memuat `iter`, `verdict`, `finding`, `source_sha256`,
  `receipt_sha256`, `parent_receipt`, `patch_applied`, `patch`
  (deskripsi template, `null` bila tidak ada), `confidence`,
  `verdict_after_patch` (BUKTI re-run, bukan klaim), dan opsional
  `regression_replay` (IDE-4: corpus di-replay terhadap kode baru bila
  convergen OK; bug lama hidup kembali = debt eksplisit).
  **Bounded & anti-overclaim**: template runtime deterministik (IDE-2)
  diterapkan per iterasi; bila template tidak yakin (mis. UBSan) atau
  verdict tanpa template → iterasi berhenti jujur dengan `why` — patch
  TIDAK pernah menebak, loop TIDAK pernah tak terbatas.
- `pack_dir` (string, opsional): direktori pack proyek lokal
  (`myc.prompt.md` + `myc.spec.json`); default = cwd server. Spec.json
  ADA tapi invalid = error tool -32602 (fail-fast, pola CLI exit 2).
- `no_pack` (boolean, opsional): `true` = nonaktifkan pack (perilaku =
  pack absen).
- **Hasil** JSON: `schema: "myc.agent.v2"`, `verdict`, `finding`,
  `primary_action`, `witness`, `next_check_command`, `payload_size`,
  objek `repair_loop` (`max_iter`/`iterations`/`converged`/`steps[]`),
  array `preservation_obligations` (anti-churn, konsisten context.c),
  plus objek `pack` (bila ada): `prompt_present`/`spec_present` +
  `prompt_text` verbatim + `prompt_sha256`/`spec_sha256` + spec
  (rules/allow_headers/deny_functions). `structuredContent` memuat
  `pack_present` (bool) + ringkasan `repair_loop_max_iter` /
  `repair_loop_iterations` / `repair_loop_converged`. Pack NON-blocking:
  verdict tidak berubah; dibuang terakhir saat enforcement cap
  (MYC-AUDIT-038/039).
- **Batasan**: mengikuti pipeline `check` standar (compile gate), output
  dalam format agent-ready. Loop repair aktif untuk verdict runtime
  dengan lokasi sanitizer (IDE-1/IDE-2); template compile = saran teks
  (tidak diterapkan otomatis — anti-churn).

Contoh (bounded repair loop, dua bug runtime beruntun → konvergen):

```
{"name":"agent_check","arguments":{
  "source":"#include <string.h>\nint f1(void){char a[6]; strcpy(a, \"abcdefghij\"); return a[0];}\nint f2(void){char b[6]; strcpy(b, \"klmnopqrst\"); return b[0];}\nint main(void){(void)f1(); (void)f2(); return 0;}\n",
  "flags":["--run"],
  "max_iter":3,
  "no_pack":true}}
```

### 8. `verify` — lite check untuk agen (myc.lite.v1)

- `source` (string, **wajib**): kode C.
- `flags` (array string, opsional). Kosong atau absen = `--scenario auto`
  (resep terkecil yang cukup dari bentuk source).
- **Hasil**: `content[0].text` + `structuredContent` schema `myc.lite.v1`:
  `verdict`, `claim`, `action`, `finding_id`, `line`, `function`, `why`,
  `fix_or_null`, `allowed_span`, `next_command`, `assurance_vector`,
  `receipt_sha256`, `source_sha256`, `source_anchor`.
- `action` enum: `STOP_COMPILE_CLEAN` | `FIX_ONE` | `ESCALATE_RUNTIME` |
  `ESCALATE_CONTRACT` | `GIVE_UP_NO_TEMPLATE`.
- `STOP_COMPILE_CLEAN` = compile bersih, **bukan** memory-safe.

Contoh:

```
{"name":"verify","arguments":{"source":"int add(int a,int b){return a+b;}\n"}}
```

### 9. `context` — paket konteks minimal (SOL-22)

- `source` (string, **wajib**).
- `flags` (array string, opsional).
- `finding_id` (string, opsional).
- `budget` (number, opsional, 4096..16384, default 4096).
- **Hasil**: teks paket context. NON-blocking; verdict tidak berubah.

### 10. `next` — rekomendasi EIG tanpa apply

- `source` (string, **wajib**).
- `flags` (array string, opsional).
- `budget_ms` (number, opsional, default 5000).
- **Hasil**: JSON rekomendasi EIG. Tidak menjalankan gate tambahan.
  Untuk mengeksekusi satu eksperimen: CLI `--eig-apply` / flag MCP `check`.

### 11. `compare_candidates` — Pareto frontier kandidat

- `baseline_path` (string, **wajib**): path file C baseline.
- `candidate_paths` (array string, **wajib**): 1..7 path kandidat.
- myc **tidak** memilih pemenang; harness yang memilih.

## Catatan untuk agent

- Selalu cek `verdict`/`assurance`/`error` di hasil `check`, bukan hanya
  status transport MCP.
- Gate `--run`/`--prove`/`--filc`/`--driver` bersifat **non-blocking**: bila
  backend hilang atau kode bukan executable, verdict tetap statis (L1) dengan
  diagnostic — jangan anggap skip sebagai kegagalan.
- Untuk program yang memakai `MYC_BUF`, gunakan `--checked` untuk L4 SPATIAL.
-Suite abuse & soak: `test/mcp_abuse.c` (blok 19 `_audit018.sh`,
PR-016/P4-T04) — 39 kasus protokol malformed + huge payload (> cap
8 MiB) + duplicate id + notification vs request + EOF + soak 1.090
request; invariant: stdout TETAP protocol-clean (tiap baris respons
JSON-RPC 2.0 sah), mcp tidak pernah crash/hang, stderr kosong.

Debug interop resmi: `test/_mcp_sdk_interop.py` (memakai SDK MCP Python
resmi, bukan client buatan sendiri). Cakupan: **25 cek** — handshake +
  `tools/list`, kelima tool, verdict OK + VIOLATION, isError transport
  (ERROR `1MiB+` / TIMEOUT, plus PROVE_VIOLATION/DRIVER_VIOLATION),
  dan seluruh gate opsional: `--run`
  (RUNTIME_VIOLATION OOB, contract-assert `bad_contract_pre.c`, `run_stdin`
  echo, TIMEOUT loop), `--prove` (L2 EVA / PROVE_VIOLATION),
  `--checked` (L4 SPATIAL / COMPILE_ERROR akses-langsung),
  `--run --checked` (RUNTIME_VIOLATION OOB + kombinasi max-level L4),
  `--driver` (L3 RUNTIME / DRIVER_VIOLATION), `--filc` (L5 FILC / skip),
  lint (observasi suspicious utk intptr_t + 0 observasi utk `ok_lint.c`,
  MYC-AUDIT-014 non-blocking),
  `structuredContent` (schema + verdict), isError yang benar (transport
  true; PROVE/DRIVER violation false), dan `cwd` (fingerprint berubah
  sesuai cwd).
  Semua gate non-blocking: bila backend hilang (clang/Frama-C/Fil-C/MYC_BUF),
  cek di-[SKIP] bukan [FAIL]. Jumlah cek: **26** (n_checks = 26 − skips).
