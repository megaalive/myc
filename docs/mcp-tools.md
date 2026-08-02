# MCP tools myc — panduan untuk coding agent

`mcp.exe` adalah MCP server (JSON-RPC 2.0 over stdio, newline-delimited —
satu pesan per baris). Agen yang mendukung MCP dapat menghubungkan `mcp.exe`
sebagai server dan memanggil pipeline verifikasi `myc` sebagai tool.

## Koneksi

- Transport: stdio (server dijalankan sebagai subproses, `command: mcp.exe`).
- Protokol: MCP 2024-11-05 (server menerima versi lain via `initialize`).
- Server mengekspos capabilities `tools` (tanpa listChanged).
- Handshake: klien kirim `initialize` → server balas `serverInfo`
  (`{name:"myc", version}`) → klien kirim `notifications/initialized`.
- Server memanggil pipeline **in-process** (`myc_run`); source hanya lewat
  stdin. Tidak ada shell string.

## Tools

### 1. `check` — verifikasi source C (pipeline penuh)

- `source` (string, **wajib**): kode C yang akan diperiksa.
- `flags` (array string, opsional): `--run --prove --checked --filc
  --driver --analyze --strict --no-lint` (lihat README untuk arti tiap flag).
- `run_stdin` (string, opsional): stdin untuk program verification. Efektif
  bila `--run` (verification build clang) atau `--filc` (verification build
  Fil-C) diminta — konten ini dikirim ke stdin program yang dijalankan gate
  tersebut (pengganti `--run-stdin FILE` di CLI).
- `cwd` (string, opsional): direktori kerja gate (gcc/clang).
- **Hasil**: satu string teks berisi **JSON lengkap** `myc_result`:
  `verdict`, `assurance`, `error`, `exit_code`, `duration_ms`,
  `resolved_gcc`, `fingerprint`, `source_sha256`, `contract_requires`,
  `contract_ensures`, `truncated`, `stdout_bytes`, `stderr_bytes`, plus
  seksi gate yang berjalan (`run_*`, `checked_*`, `filc_*`, `driver_*`,
  `prove_*`) dan `diagnostics[]`.
- `isError: true` untuk verdict infrastruktur
  (`ERROR`/`TIMEOUT`/`CANCELLED`) **dan pelanggaran hard gate**
  (`PROVE_VIOLATION` dari `--prove`, `DRIVER_VIOLATION` dari `--driver` —
  sejak 2026-08-02); VIOLATION lain (lint/runtime) dikirim sebagai hasil
  teks biasa.
- **Verdict yang mungkin**: `OK`, `VIOLATION` (lint), `COMPILE_ERROR`,
  `RUNTIME_VIOLATION` (--run), `PROVE_VIOLATION` (--prove),
  `FILC_VIOLATION` (--filc), `DRIVER_VIOLATION` (--driver).
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

### 5. `lint` — lint memory-safety myc (heuristik)

- `source` (string, **wajib**).
- **Hasil** teks:

```
lint verdict: OK|VIOLATION
  [line:col] pesan diagnostic...
```

Pola yang di-flag: cast pointer via `intptr_t`/`uintptr_t` (VIOLATION),
realloc ke variabel lain (VIOLATION), memcpy/memmove/memset tanpa `sizeof`
(warning), ukuran alokasi perkalian tanpa `sizeof` (warning).

## Catatan untuk agent

- Selalu cek `verdict`/`assurance`/`error` di hasil `check`, bukan hanya
  status transport MCP.
- Gate `--run`/`--prove`/`--filc`/`--driver` bersifat **non-blocking**: bila
  backend hilang atau kode bukan executable, verdict tetap statis (L1) dengan
  diagnostic — jangan anggap skip sebagai kegagalan.
- Untuk program yang memakai `MYC_BUF`, gunakan `--checked` untuk L4 SPATIAL.
- Debug interop resmi: `test/_mcp_sdk_interop.py` (memakai SDK MCP Python
  resmi, bukan client buatan sendiri). Cakupan: **25 cek** — handshake +
  `tools/list`, kelima tool, verdict OK + VIOLATION, isError transport
  (ERROR `1MiB+` / TIMEOUT, plus PROVE_VIOLATION/DRIVER_VIOLATION),
  dan seluruh gate opsional: `--run`
  (RUNTIME_VIOLATION OOB, contract-assert `bad_contract_pre.c`, `run_stdin`
  echo, TIMEOUT loop), `--prove` (L2 EVA / PROVE_VIOLATION),
  `--checked` (L4 SPATIAL / COMPILE_ERROR akses-langsung),
  `--run --checked` (RUNTIME_VIOLATION OOB + kombinasi max-level L4),
  `--driver` (L3 RUNTIME / DRIVER_VIOLATION), `--filc` (L5 FILC / skip),
  lint (VIOLATION intptr_t + tidak ada false-positive pada `ok_lint.c`),
  dan `cwd` (fingerprint berubah sesuai cwd).
  Semua gate non-blocking: bila backend hilang (clang/Frama-C/Fil-C/MYC_BUF),
  cek di-[SKIP] bukan [FAIL]. Jumlah cek: **25** (n_checks = 25 − skips).
