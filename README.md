# myc — Verifikator C aman untuk agent

`myc` mengecek kode C yang ditulis model (terutama model non-frontier) dengan
pipeline terstruktur. Kode C adalah **data tidak tepercaya** — tidak pernah
masuk ke shell string. Source hanya lewat stdin, gcc dipanggil dengan
`program + argv[]` langsung.

## Prinsip (dari rencana fpagnt)

- structured di model boundary
- canonical di dalam harness
- `program + argv[]` langsung di boundary proses
- policy **sebelum** launch gate
- stdin di-hash (SHA-256), tidak pernah di-log mentah

## Pipeline

```
scan include mentah (whitelist)   -> warning (non-blocking)
lint memory-safety (lint.c)       -> LINT_VIOLATION  (gate hard)
gcc -E (argv eksak, via stdin)    -> preprocessed output
scan penanda "# 1" (depth 2)      -> warning (non-blocking)
scan panggilan fungsi denylist    -> warning (non-blocking)
gcc -c -O2 -Wall -Wextra -Werror -pedantic
  + tier memori (Warray-bounds, stringop-overflow, use-after-free, ...)
                                    -> COMPILE_ERROR
gcc -c -O2 -fanalyzer -o <null_device> (--analyze, opsional)
                                    -> COMPILE_ERROR
gcc -c -O2 -DMYC_CHECKED (--checked, opsional)
   myc_buf.h fat-pointer; akses       -> L4 SPATIAL; COMPILE_ERROR bila
   langsung b[i] pada MYC_BUF gagal     disiplin fat-struct dilanggar
filc-clang build + run (--filc,      -> L5 FILC (opsional backend;
   opsional; native PATH / WSL)         FILC_VIOLATION bila panic Fil-C)
clang verification build + run      -> L3 RUNTIME (--run, opsional;
   (ASan+UBSan, -O0, eksekusi          RUNTIME_VIOLATION bila ada laporan
   terkendali via proc.c;              sanitizer; --checked juga aktif
   --checked: +MYC_CHECKED fat)        di verification build)
harness kasus tepi (--driver,       -> L3 RUNTIME (D2.2; DRIVER_VIOLATION
   D2.2): parse signature fungsi        bila sanitizer menangkap bug pada
   ber-kontrak, generate + run          kasus tepi di dalam domain kontrak)
OK (assurance: L1 SANE, L2 EVA, L3 RUNTIME, L4 SPATIAL, atau L5 FILC)
```

> **Assurance vector (MYC-AUDIT-006):** scalar L1–L5 dipertahankan sebagai
> legacy, tetapi ringkasan jujur kini per dimensi orthogonal —
> `assurance_vector: C1 S0 R1 B0 P0 D0 F0` (C=compile S=static R=runtime
> B=checked P=proof D=driver F=filc; 0=n/a 1=clean 2=findings
> 3=inconclusive 4=observations) — turunan murni dari typed gate status,
> tidak di-max-kan. Juga di JSON (`"assurance_vector":{"C":...}`).

> Catatan: gate memori memakai `-c -O2` karena `-Warray-bounds` dan
> `-Wstringop-overflow` hanya aktif saat kompilasi beroptimisasi.

## Penggunaan

```text
myc check <file.c> [--json] [--analyze] [--strict] [--no-lint] [--cwd DIR]
myc check <file.c> [--run [--run-stdin FILE]] [--prove] [--checked] [--filc] [--driver]
myc check -          [--json] [--analyze] [--strict] [--no-lint] (stdin)
myc policy                                 (tampilkan whitelist header)
myc probe                                  (self-test exact argv)
myc version
mcp.exe                                    (MCP server, lihat bawah)
```

Flag:
- `--strict` (alias `--level strict`) — tier ketat `-Wconversion
  -Wsign-conversion -Wint-conversion` (BISING, bukan default).
- `--no-lint` — matikan lint memory-safety.
- `--analyze` — tambah gate `-fanalyzer`.
- `--run` — verification build (clang ASan+UBSan, `-O0`) + eksekusi
  terkendali. Bersih (exit 0, tanpa laporan sanitizer) → assurance **L3
  RUNTIME**. `--run-stdin FILE` memberi stdin untuk program hasil build.
  Bukti sanitizer memakai **saluran non-spoofable** (MYC-AUDIT-017): env
  `ASAN_OPTIONS`/`UBSAN_OPTIONS` diarahkan ke `log_path` (report FILE di tmp
  dir, ditulis runtime sanitizer sendiri); marker teks stdout/stderr hanya
  bukti sekunder yang wajib exit code != 0 — teks mirip marker dengan exit 0
  diabaikan (program bisa mencetaknya sendiri).
- `--run` bersifat **opsional & non-blocking**: bila clang tidak tersedia atau
  kode bukan program executable (tanpa `main`), myc tetap memberi verdict
  statis (L1) plus diagnostic, tidak menahan.
- `--checked` (D1.2, P8) — bangun source dua kali: produksi normal (T* polos)
  + `-DMYC_CHECKED=1` sehingga `MYC_BUF` (dari `myc_buf.h`) menjadi
  **fat-struct** yang memaksa semua akses lewat `MYC_AT` (akses langsung
  `b[i]` = error kompilasi). Build checked lolos → assurance **L4 SPATIAL**
  untuk buffer MYC_BUF. Non-blocking: source tanpa pola MYC_BUF → skip +
  diagnostic. `--run --checked` memakai verification build fat-pointer di
  bawah ASan (pelanggaran batas → RUNTIME_VIOLATION).
- `--filc` (D4.1, P8) — verification build dengan **Fil-C** (memory-safe C,
  driver `filc-clang`, Linux/X86_64; di Windows otomatis lewat WSL). Run
  bersih tanpa marker panic → assurance **L5 FILC** (backend opsional;
  label lama "FULL" dihapus — MYC-AUDIT-013: run Fil-C membuktikan eksekusi
  terkendali bersih, bukan "full").
  Panic Fil-C (`filc safety error` dll) → **FILC_VIOLATION**. Non-blocking:
  bila filc-clang tidak tersedia (PATH/WSL), gate di-skip + diagnostic.
- `--driver` (D2.2) — **driver-generator**: scan fungsi ber-kontrak
  (`//@ requires`), parse signature, bangkitkan harness yang memanggil tiap
  fungsi dengan **kasus tepi di dalam domain kontrak** (batas dari requires,
  0, 1, 2, 3, ...) pada buffer calloc, lalu build + run dengan clang
  ASan+UBSan. Run bersih dengan ≥1 kasus tereksekusi → assurance **L3
  RUNTIME**; sanitizer menangkap bug → **DRIVER_VIOLATION**. Non-blocking:
  clang hilang / tidak ada fungsi ber-kontrak / build harness gagal → skip +
  diagnostic. Nilai negatif/SIZE_MAX tidak diuji tanpa kontrak yang
  membuka peluangnya (hindari false positive). Fixture: `ok_driver.c` → OK,
  `bad_driver_oob.c` (OOB via `a[n]` saat n=4 pada kontrak `n <= 4`) →
  DRIVER_VIOLATION.

## MCP server (P9)

`mcp.exe` mengekspos pipeline myc sebagai **MCP server** (JSON-RPC 2.0 over
stdio, newline-delimited — satu pesan per baris). Agen (harness yang
mendukung MCP) dapat memanggil `myc check` sebagai tool. Tool yang tersedia:

- `check` — verifikasi source C. Args: `source` (string, wajib), `flags`
  (array string opsional: `--run --prove --checked --filc --driver
  --analyze --strict --no-lint`), `run_stdin` (string opsional: stdin untuk
  program verification; efektif dengan `--run` atau `--filc`), `cwd`
  (opsional).
  Hasil: teks JSON lengkap (verdict, assurance L0–L5, error, diagnostics,
  output gate) di `content[0].text` **dan** objek `structuredContent`
  (schema `myc.result.v1`) — konsumen mesin tidak perlu parse JSON di
  dalam JSON. `isError` hanya untuk kegagalan tool/protocol
  (ERROR/TIMEOUT/CANCELLED); finding pada kode (PROVE_VIOLATION,
  DRIVER_VIOLATION, dll.) dikirim sebagai hasil biasa (isError=false).
  Unknown flag ditolak dengan error -32602 (tidak diabaikan).
- `version` — versi myc + ketersediaan gcc/clang.
- `policy` — whitelist header default.
- `contracts` — scan kontrak-lite `//@ requires/ensures` dan tampilkan
  semua ekspresi kontrak.
- `lint` — jalankan lint memory-safety myc pada source (verdict +
  diagnostic).

**Dokumentasi lengkap tiap tool untuk coding agent**: `docs/mcp-tools.md`
(argument, bentuk output, verdict/assurance, catatan penggunaan).

Client contoh tanpa dependensi: `python mcp_client.py` — handshake
`initialize`, `tools/list`, lalu memanggil tool `check`/`version`/
`contracts`/`lint` lewat stdio.

Uji interop dengan **SDK MCP Python resmi**: `test/_mcp_sdk_interop.py`
(`pip install mcp`; memakai `stdio_client` + `ClientSession` — bukan client
buatan sendiri). Cakupan: 26 cek — handshake/tools/list, semua tool
(check/version/policy/contracts/lint), verdict OK + VIOLATION,
`structuredContent` (schema myc.result.v1), isError transport
(ERROR/TIMEOUT=true; PROVE_VIOLATION/DRIVER_VIOLATION=false sejak
MYC-AUDIT-016), dan gate opsional `--run` (RUNTIME_VIOLATION,
contract-assert, `run_stdin` echo, TIMEOUT), `--prove` (L2 EVA /
PROVE_VIOLATION), `--checked` (L4 SPATIAL / COMPILE_ERROR),
`--run --checked` (RUNTIME_VIOLATION + kombinasi max-level L4),
`--driver` (L3 RUNTIME / DRIVER_VIOLATION), `--filc` (L5 FILC / skip),
lint (VIOLATION + tidak ada false-positive pada kode sah), dan `cwd`
(fingerprint berubah sesuai cwd). Skip non-blocking bila backend gate
tidak tersedia.

MCP server memanggil pipeline **in-process** (myc.c dibangun dengan
`-DMYC_NO_MAIN`); tidak ada shell string, source hanya lewat stdin.
Parser/serializer JSON sendiri (`json.c`, depth cap 64, tanpa dependensi
pustaka).

## Kebijakan (pivot 2026-08-01: memory-safety, bukan pembatasan library)

- **Header bebas**. Whitelist header hanyalah *default konservatif*; semua
  scan policy (include, markers, calls) bersifat **non-blocking** — hanya
  menambah warning, tidak pernah menolak program sah.
- **Denylist fungsi** (`system`, `exec*`, `spawn*`, `fork`, `popen`, file I/O,
  jaringan, `mmap`, env, utas) tetap dilaporkan sebagai warning (safety
  tambahan), bukan penghalang.
- **Gate hard = lint memory-safety** (intptr_t cast → VIOLATION, realloc
  invalidasi → VIOLATION) **+ gate gcc** (tier memori, `-Werror`).
- Fungsi tak dikenal ditangkap gcc via `-Werror=implicit-function-declaration`.

## Aturan untuk coding agent

Saat memanggil gcc atau proses lain dalam kode ini, gunakan process API
dengan `program + argv[]`. **Jangan pernah menyusun shell command string.**
Gunakan `shell` hanya bila sintaks shell memang dibutuhkan, dan jelaskan.

## Status

- P0–P7 selesai: `myc check` end-to-end, policy non-blocking, lint
  memory-safety (intptr_t/realloc), tier memori gcc + `-fanalyzer`,
  assurance L1 SANE, **verification run clang ASan+UBSan → L3 RUNTIME**
  (`--run`, eksekusi terkendali via proc.c, timeout kill pohon proses),
  contract-lite (D1.5) + **Frama-C Eva → L2 EVA** (`--prove`; 0 alarm
  RTE di bawah model Eva — abstract interpretation, bukan proof WP),
  self-dogfooding (11 source myc OK) + dogfooding lintas-program
  (`dogfood_ring.c` → L3, lalu L4 dengan `--checked`).
- **P8 D1.2 selesai**: checked-build makro (`myc_buf.h`, `--checked`) →
  assurance **L4 SPATIAL** untuk buffer MYC_BUF; fixture `ok_checked.c` →
  L4, `bad_checked.c` → COMPILE_ERROR, `bad_checked_oob.c` →
  RUNTIME_VIOLATION.
- **P8 D4.1 selesai**: gate **Fil-C** (`--filc`) → **L5 FILC** bila
  filc-clang tersedia (native PATH / WSL) dan run bersih; FILC_VIOLATION
  bila panic. Non-blocking: fixture `ok_filc.c`/`bad_filc_oob.c` di-skip
  bila Fil-C tidak terpasang.
- **P9 selesai**: **MCP server** (`mcp.exe` — JSON-RPC 2.0 over stdio,
  tool `check`/`version`/`policy`, in-process via `myc_run`; parser JSON
  sendiri `json.c`), **soak** (`test/_soak.bat`), dan **corpus abuse**
  (`test/_corpus_abuse.bat` + `test/corpus/*.c` — input ganas tidak boleh
  membuat myc crash/hang). Smoke test MCP: `test/_mcp_smoke.bat`.
- **MYC-AUDIT-018 selesai (2026-08-02)**: **test portabel lintas platform**
  `test/_audit018.sh` (bash — Windows git-bash & POSIX) menguji
  **concurrency** (`stress_threads.c` 8×200 `myc_run` paralel), **deadlock**
  (`proc_flood.c`: child tulis 1 MiB stdout → baca 1 MiB stdin → tulis
  1 MiB stderr; selesai tanpa timeout, total persis), **flood** (100 MiB
  stdout + stderr cap 64 KiB, prefix+tail ring dipertahankan, memori
  bounded), **env override**, dan **OOM** (`oom_guards.c` arena overflow
  guard; `oom_alloc.c` injeksi kegagalan malloc/calloc/realloc via
  `-Wl,--wrap` — 49 titik OOM tanpa crash). Di-wire ke
  `test/_regress_run.bat` via `where bash` (tanpa bash → [SKIP]).
- **D2.2 driver-generator selesai**: gate `--driver` (harness kasus tepi
  dari fungsi ber-kontrak, clang ASan+UBSan) → L3 RUNTIME bila bersih,
  DRIVER_VIOLATION bila sanitizer menangkap bug. Tool MCP tambahan:
  `contracts` + `lint`. Client MCP contoh: `mcp_client.py`. Self-dogfooding
  kini 15 source myc (termasuk `driver.c`) → OK.
- **Trust Core Stabilization — Fase 1 partial (2026-08-02)**:
  7 bug kritis dari audit `docs/myc-serious-review-and-roadmap.md`
  diperbaiki:
  - **MYC-AUDIT-005**: fingerprint OOB read (`compile.c`) — `snprintf`
    truncated dipakai sebagai panjang ke `sha256_hex`; kini hitung exact
    dengan `snprintf(NULL,0,...)` + alokasi dinamis.
  - **MYC-AUDIT-001**: drain thread POSIX tidak di-join (`proc.c`) —
    race/UAF pada buffer hasil; kini `pthread_join` sebelum transfer.
  - **MYC-AUDIT-002**: deadlock POSIX stdin/output (`proc.c`) — drain thread
    kini dibuat *sebelum* menulis stdin.
  - **MYC-AUDIT-011**: process group POSIX belum dibentuk (`proc.c`) —
    `setpgid(0,0)` di child agar `kill(-pgid)` efektif.
  - **MYC-AUDIT-003**: exec-error pipe (`proc.c`) — `execvp` gagal kini
    dibedakan dari exit 127 program via pipe `FD_CLOEXEC`.
  - **MYC-AUDIT-003**: temp path relatif POSIX (`run.c`) — fallback ke
    `/tmp`; canonicalize via `getcwd` bila base relatif.
  - **MYC-AUDIT-007**: `file_path` API null-deref (`myc.c`) — `myc_run()`
    kini load file ke memory sebelum masuk pipeline.
  - Dogfooding post-fix: 15/15 self + 3/3 dogfood/ OK;
    `_regress.bat` + `_regress_run.bat` semua pass.
- **Arah (2026-08-01)**: fokus = **memory-safety & minim bug**, bukan
  pembatasan library. Policy = warning non-blocking (lihat Kebijakan). Detail
  di `AGENTS.md` dan `docs/rencana-memory-safety.md`.

## Build

```bat
build.bat
```
Menghasilkan `myc.exe`, `mcp.exe`, dan `argv_probe.exe`.
