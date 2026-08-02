# AGENTS.md — Aturan proyek myc

## Arah & filosofi (keputusan 2026-08-01)

**Tujuan myc adalah memory-safety dan minimnya bug yang ditimbulkannya — BUKAN
membatasi library yang boleh dipakai user.**

Poin penting:

- User memakai **banyak agent harness yang berbeda**, dan **model yang berbeda**
  di dalam masing-masing harness.
- Permintaan user ke agent beragam: **hardware, game, web, dst.** Setiap domain
  butuh library yang berbeda (mis. untuk hardware butuh syscalls/register,
  untuk game butuh library grafis, dst).
- Karena itu **tidak boleh** membatasi dengan white/black list library/header.
  Header yang user butuhkan harus diizinkan.
- Yang diinginkan user dari myc: **memory-safety** dan **minimal bug** yang
  disebabkan masalah memori (buffer overflow, use-after-free, double-free,
  null deref, integer overflow, dst).

### Konsekuensi terhadap desain saat ini

- Model whitelist/denylist **header** saat ini (15 header) bertentangan dengan
  arah baru. Arah baru: whitelist header hanyalah *default konservatif*,
  bukan larangan mutlak — perlu mekanisme izin/override per proyek.
- Denylist **fungsi berbahaya** (system, exec*, fopen, ...) tetap berguna
  sebagai *safety* tambahan (mis. mencegah model memanggil system tanpa sadar),
  tapi **bukan fokus utama** dan tidak boleh menghalangi program yang sah.
- Focus utama berpindah ke **static analysis untuk memory-safety**:
  memaksimalkan `-fanalyzer`, menangkap jalur yang melewati batas buffer,
  dll.

### Status arah

- Arah baru **sudah diimplementasikan (Fase A, P4+P5, selesai 2026-08-01)**.
- Keputusan user: **policy = non-blocking warning**. Header & fungsi denylist
  tidak lagi menolak program sah. Satu-satunya gate hard = **lint
  memory-safety** (lint.c: intptr_t cast, realloc invalidasi) **+ gate gcc**
  (tier memori `-Werror`, `-fanalyzer`).
- **P6 selesai 2026-08-01**: gate verification run opsional (`--run`) dengan
  clang ASan+UBSan (`-O0`, source via stdin, DLL runtime disalin, eksekusi
  via proc.c) → assurance **L3 RUNTIME**. Non-blocking: bila clang hilang /
  kode bukan executable, assurance statis dipertahankan + diagnostic.
- **P7 (D1.5) contract-lite selesai 2026-08-01**: scan `//@ requires/ensures`
  (info di laporan: `contracts: requires=N ensures=M`) + inject
  `assert(requires)` ke verification build (`--run`) sebagai defense-in-depth.
  `bad_contract_pre.c` → RUNTIME_VIOLATION (assert menangkap pelanggaran pre).
- **D2.2 driver-generator selesai 2026-08-02**: gate `--driver` scan
  fungsi ber-kontrak (`//@ requires`), parse signature, bangkitkan harness
  kasus tepi DI DALAM domain kontrak (batas dari requires, 0/1/2/3), build +
  run clang ASan+UBSan (`-O0`, source via stdin). Run bersih ≥ 1 kasus →
  L3 RUNTIME; sanitizer menangkap bug → MC_DRIVER_VIOLATION (fixture
  `bad_driver_oob.c`: OOB via `a[n]` saat n=4 pada kontrak `n <= 4`).
  Non-blocking: clang hilang / tak ada fungsi ber-kontrak / build harness
  gagal → skip + diagnostic. Nilai negatif/SIZE_MAX TIDAK diuji tanpa
  kontrak yang membuka peluangnya (hindari false positive). Harness
  men-rename main asli via `#define main` lalu `#undef` — source dengan
  `main` tetap bisa di-drive.
- **Tool MCP `contracts` + `lint` selesai 2026-08-02**: `mcp.exe` kini
  mengekspos 5 tool (`check`, `version`, `policy`, `contracts`, `lint`).
  `contracts` = list ekspresi `//@ requires/ensures` (API baru
  `myc_contract_list` di contract.c). `lint` = jalankan lint memory-safety
  langsung (tanpa pipeline penuh). Smoke test diperbarui ke 10 pesan.
- **Client MCP contoh selesai 2026-08-02**: `mcp_client.py` (Python stdlib,
  tanpa dependensi) — handshake initialize, tools/list, panggil
  check/version/contracts/lint via stdio.
- **P7 (D3.1) Frama-C Eva selesai 2026-08-01**: gate `--prove` → L2 PROVEN.
  Frama-C 33.0 (Arsenic) diinstal via opam di WSL Ubuntu-24.04
  (`/home/megaalive/.opam/default/bin/frama-c`); myc mendeteksi via `wsl.exe`
  dan memanggil `frama-c -eva` dengan source via stdin (template bash tetap,
  tanpa shell string berisi source). Alarm Eva (`[eva:alarm]`, kelas RTE =
  bug pasti) → verdict PROVE_VIOLATION; 0 alarm + analisis sungguhan (cek
  "ANALYSIS SUMMARY") → L2. Non-blocking: wsl/frama-c hilang atau Eva tidak
  menganalisis → skip, assurance statis dipertahankan + diagnostic.
  Fixture: `ok_prove.c` → L2; `bad_prove.c` (OOB via argc opaque) →
  PROVE_VIOLATION.
- Self-dogfooding lolos penuh: 15 source myc dicek myc sendiri → OK.
  (Catatan lama "akan selalu VIOLATION karena windows.h" TIDAK berlaku lagi —
  policy non-blocking.)
- **Dogfooding lintas-program tiga tool (2026-08-02)**: `dogfood_ring.c`
  (ring buffer, MYC_BUF → L4), `dogfood_config.c` (parser config key=value,
  idiom realloc aman ke member `cfg->items = tmp` + copy_bounded), dan
  `dogfood_tilemap.c` (flood-fill BFS tile map 2D domain game,  stack eksplisit non-rekursif + indeks y*W+x berbatas). Ketiganya lolos `myc
  check` OK/L1 + `--run` OK/L3, gcc -Wall -Wextra -Werror diam; tilemap juga
  tervalidasi diam terhadap `-fanalyzer`. Terdaftar di
  `test/_regress_run.bat`.
- **P8 (D1.2) checked-build makro selesai 2026-08-01**: `myc_buf.h`
  dual-mode (produksi `MYC_BUF(T)` = `T*` polos; `-DMYC_CHECKED=1` =
  fat-struct + `MYC_AT` cek batas). Gate `--checked` membangun source 2×;
  akses langsung `b[i]` pada MYC_BUF = COMPILE_ERROR di checked build →
  semua akses dipaksa via MYC_AT → **L4 SPATIAL**. `--run --checked`
  memakai verification build fat-pointer di bawah ASan. Non-blocking:
  source tanpa pola MYC_BUF → skip + diagnostic. Fixture: `ok_checked.c` →
  L4; `bad_checked.c` → COMPILE_ERROR; `bad_checked_oob.c` →
  RUNTIME_VIOLATION. Dogfooding: `dogfood_ring.c` ditulis ulang memakai
  MYC_BUF → L4.
- **P8 (D4.1) gate Fil-C selesai 2026-08-01**: `--filc` → **L5 FULL**
  (backend opsional). Deteksi filc-clang di PATH (native Linux) atau via
  WSL (`command -v filc-clang` / `/opt/fil/bin/filc-clang`); verification
  build + eksekusi terkendali. Marker panic Fil-C (`filc safety error` dll,
  terkonfirmasi dari issue tracker) → verdict **FILC_VIOLATION**. Run
  bersih → L5. Non-blocking: filc-clang tidak tersedia → skip + diagnostic
  (assurance statis dipertahankan). Fixture: `ok_filc.c` → L5 bila ada,
  skip bila tidak; `bad_filc_oob.c` → FILC_VIOLATION bila ada, skip bila
  tidak. Di sistem ini Fil-C TIDAK terpasang → fixture diverifikasi lewat
  jalur skip (non-blocking berfungsi).
- Catatan bug yang ditemukan & diperbaiki saat P7 (dogfooding):
  - lint.c hanya mengenali idiom realloc aman `buf = tmp`, TIDAK mengenali
    akses member `b->data = nd` → false VIOLATION pd kode sah. Diperbaiki:
    `read_arg_ident`/`ident_before` kini membaca rantai member (`->`/`.`).
  - run.c: `myc_contract_inject` menulis `*out_len=0` pd return NULL sehingga
    `build_src_len` ter-clobber → clang menerima stdin kosong →
    `lld-link: subsystem must be defined` → semua fixture non-kontrak turun ke
    L1. Diperbaiki: panjang inject dipakai hanya bila non-NULL; contract.c
    tidak lagi menyentuh `*out_len` saat NULL.
- Perubahan perilaku: `bad_system.c`, `bad_fopen.c`, `bad_include.c`,
  `bad_macro.c` kini **OK** (hanya warning policy). `bad_intptr.c`,
  `bad_realloc.c` tetap VIOLATION (lint). Fixture P6: `ok_run.c` → L3;
  `bad_run_oob.c`/`bad_run_uaf.c`/`bad_run_intovf.c` → RUNTIME_VIOLATION.
- Fixture P8 (D1.2): `ok_checked.c` → L4 (SPATIAL); `bad_checked.c` →
  COMPILE_ERROR (akses langsung pada MYC_BUF); `bad_checked_oob.c` →
  RUNTIME_VIOLATION (`--run --checked`).
- Fixture P8 (D4.1): `ok_filc.c` / `bad_filc_oob.c` → L5 / FILC_VIOLATION
  bila Fil-C tersedia; di-skip (non-blocking) bila tidak.
- **Trust Core Stabilization — Fase 1 partial selesai 2026-08-02**
  (dari audit `docs/myc-serious-review-and-roadmap.md`):
  - **MYC-AUDIT-005 diperbaiki** (`compile.c`): fingerprint OOB read.
    `snprintf` truncated mengembalikan panjang *yang seharusnya* ditulis,
    bukan panjang aktual di buffer. Bug lama: `sha256_hex(buf, n, ...)` bisa
    membaca di luar `buf[512]` bila path gcc + cwd + metadata > 511 byte.
    Perbaikan: `snprintf(NULL, 0, ...)` dulu untuk menghitung panjang exact,
    alokasi dinamis, baru hash. Fingerprint version bump: `v7` → `v8`.
  - **MYC-AUDIT-001 diperbaiki** (`proc.c`): drain thread POSIX tidak
    di-join. `pthread_t` lama dibuang — thread masih menulis ke buffer
    sementara parent sudah transfer hasil (race/UAF). Perbaikan: simpan
    `pthread_t to/te`, periksa return `pthread_create`, `pthread_join`
    keduanya *setelah* child berhenti dan pipe ditutup, baru salin buffer.
  - **MYC-AUDIT-002 diperbaiki** (`proc.c`): deadlock POSIX stdin/output.
    Urutan lama: tulis stdin penuh → baru buat drain thread. Bila child
    mengisi pipe output sebelum selesai baca stdin → deadlock. Perbaikan:
    drain thread dibuat *sebelum* menulis stdin.
  - **MYC-AUDIT-011 diperbaiki** (`proc.c`): process group POSIX belum
    dibentuk sehingga `kill(-pid, SIGKILL)` tidak menjamin membunuh seluruh
    pohon child. Perbaikan: `setpgid(0, 0)` di child sebelum `execvp`;
    parent memakai `kill(-pid, ...)` ke group baru.
  - **MYC-AUDIT-003 partial** (`proc.c`): tidak bisa bedakan `execvp` gagal
    dari program yang memang exit 127. Perbaikan: exec-error pipe dengan
    `FD_CLOEXEC` — child write errno saat `execvp` gagal, parent baca untuk
    mengklasifikasikan `MYC_ERR_EXECUTE_FAILED` dengan tepat.
  - **MYC-AUDIT-003 partial** (`run.c`): fallback temp dir `"."` menghasilkan
    path relatif yang rusak saat child `chdir(tmp_dir)`. Perbaikan: fallback
    ke `/tmp` (POSIX) / `C:/Temp` (Windows), canonicalize via `getcwd` bila
    base masih relatif.
  - **MYC-AUDIT-007 diperbaiki** (`myc.c`): `file_path`-only request lolos
    validasi tapi pipeline null-deref (`req->source == NULL`). Perbaikan:
    `myc_run()` load file ke memory di ingress layer sebelum masuk pipeline;
    pipeline selalu menerima source in-memory.
  - Dogfooding: self-check 15/15 source myc OK + 3/3 dogfood/ OK; semua
    regression test + `_regress_run.bat` pass setelah perbaikan.

- **P9 (MCP server + soak + corpus abuse) selesai 2026-08-02**:
  - `mcp.exe` — MCP server JSON-RPC 2.0 over stdio (newline-delimited, satu
    pesan per baris). In-process memakai `myc_run` (myc.c dibangun dengan
    `-DMYC_NO_MAIN`; main CLI di-guard `#ifndef MYC_NO_MAIN`). Tool:
    `check` (source + flags + cwd → JSON verdict/assurance lengkap),
    `version`, `policy`. Parser/serializer JSON sendiri di `json.c`/`json.h`
    (depth cap 64, escape `\uXXXX` incl. surrogate pair, angka int64).
    `myc_result_to_json` (report.c) = serialisasi hasil reusable (tanpa batas
    buffer statis 4096). Smoke test: `test/_mcp_smoke.bat` +
    `test/mcp_smoke_input.jsonl`.
  - `test/_soak.bat` — stabilitas: 20× `myc check myc.c --analyze` (harus OK)
    + 10× `myc check ok_run.c --run` (harus ada verdict).
  - `test/_corpus_abuse.bat` + `test/corpus/*.c` — input ganas (empty,
    garbage, unclosed comment/string, deep nesting, huge line, macro ganas,
    rekursi dalam): myc harus tetap memberi verdict, tidak crash/hang.

- **Fase 3 typed-gate + evidence + unverified debt selesai 2026-08-02**:
  - Typed gate status (`myc_gate_status`), gate result per gate, dan
    verdict reducer PURE (`myc_reduce_verdict` di `gate.c`) mengganti
    logika boolean global. Verdict + assurance kini *diturunkan* dari status
    gate COMPLETED_CLEAN — bukan "level maksimum yang dipilih".
  - Evidence ledger append-only (`myc_result_add_evidence`).
  - Sumbu B completeness (`myc_completeness`: COMPLETE / INCOMPLETE) muncul
    di laporan teks + JSON.
  - **Unverified debt (gagasan pembeda 9.3, Fase 4 partial)**: laporan kini
    memuat `unverified_debt[]` (teks + JSON) hanya untuk scope yang diminta
    tapi TIDAK selesai: backend tidak tersedia (UNAVAILABLE), gagal infra
    (INFRA_FAILED), hasil tidak lengkap (INCONCLUSIVE), generated driver 0
    kasus, klausa `ensures` diparse tapi tidak dibuktikan, dan output
    backend terpotong. Debt dibangun murni dari typed gate status yang sudah
    ada — tanpa backend baru.
  - Regresi debt di `test/_regress_run.bat`: `bad_driver_oob --driver`
    memunculkan debt; `ok_run --run` bersih tanpa debt.
  - **Bug Fase 3 ditemukan & diperbaiki (2026-08-02)**: `report.c` serialisasi
    `evidence[]` tidak memakai `json_sb_escape` pada `message` sehingga semua
    pesan evidence kosong di JSON. Diperbaiki: escape diterapkan. (Ditemukan
    saat memverifikasi output canary.)
  - Semua regression + interop MCP 24 cek lolos.

- **Semantic Canary selesai 2026-08-02** (gagasan pembeda 9.9, Fase 7.2):
  Sebelum gate runtime menyatakan `COMPLETED_CLEAN` (L3 RUNTIME), myc
  mengkompilasi + menjalankan canary kecil yang PASTI membuat out-of-bounds
  (`myc_runtime_canary` di `run.c`). Bila canary TIDAK terdeteksi (gagal
  dibangun / clean), backend ASan dianggap tidak layak dipercaya -> gate
  di-turunkan ke INCONCLUSIVE (bukan COMPLETED_CLEAN) + diagnostic. Bila
  terdeteksi, evidence `semantic canary terdeteksi: backend ASan sehat`
  direkam di ledger. Non-blocking terhadap clang hilang (tetap UNAVAILABLE).
  Dogfooding: `ok_run --run`, `dogfood_ring --run`, `--run --checked` tetap
  L3/L4 (canary sehat). Regresi di `test/_regress_run.bat`.

- **Evidence Receipt selesai 2026-08-02** (gagasan pembeda 9.1): laporan teks +
  JSON kini memuat `receipt_sha256` — hash deterministik SHA-256 dari bukti
  terkumpul (`myc_build_receipt` di `gate.c`): version receipt, verdict,
  completeness, tiap gate id+status, debt, fingerprint, source_sha. Bukan
  klaim keamanan — melainkan sidik jari hasil agar CI/auditor dapat
  membandingkan dua receipt tanpa membaca prose. Deterministik (input sama →
  hash sama) dan berbeda antar verdict. Tidak menambah backend. Dogfooding &
  self-check tetap OK. Regresi di `test/_regress_run.bat`.

- **Fase 5 Reentrancy & Memory Ownership selesai 2026-08-02** (MYC-AUDIT-008):
  - Static message ring untuk diagnostic DIHAPUS di `compile.c`/`run.c`/
    `prove.c`/`filc.c`/`driver.c`/`contract.c`/`scanner.c`/`lint.c`. Diganti
    **arena bump milik hasil** (`myc_result_arena_dup` di `myc.c`, blok 64 KiB,
    dibebaskan utuh di `myc_result_free`). Global state `buf_vars` di `lint.c`
    menjadi `_Thread_local`. Akibat: `myc_run` reentrant — MCP in-process siap
    concurrency; result lama tak tertimpa (hasil tetap immutable). OOM di
    arena → NULL, diagnostic di-skip.
  - Regresi baru `test/stress_threads.c` (8 thread × 200 `myc_run`, cek tidak
    ada race/stale via kestabilan `source_sha256`) ditambahkan ke
    `test/_regress_run.bat`. Self-dogfooding 15 source tetap OK; receipt
    deterministik tetap (`ok_run --run` → `60b7db90eac4...`).

## Dogfooding (keputusan 2026-08-01)

Dogfooding myc dilakukan **dua cara**:

1. **Self-dogfooding**: source myc sendiri diperiksa myc (termasuk
   `json.c`/`mcp.c`/`driver.c`). Setelah pivot (policy non-blocking), seluruh
   15 source myc lulus OK — ini wajib dipertahankan di setiap perubahan:
   tiap source harus tetap OK.
2. **Dogfooding lintas-program**: buat tool/aplikasi lain (C murni) yang
   *realistis* untuk user, ditulis dan diperiksa dengan myc, untuk
   mematangkan jalur "lolos" (OK) myc pada kode yang sah.

Daftar tool dogfooding saat ini (semua di `dogfood/`, terdaftar di
`test/_regress_run.bat`):
- `dogfood_ring.c` — ring buffer kasir (domain aplikasi/game), memakai
  MYC_BUF → L4 SPATIAL saat `--checked`.
- `dogfood_config.c` — parser config key=value (domain web/server), melatih
  idiom realloc aman ke member struct + copy per-byte berbatas.
- `dogfood_tilemap.c` — flood-fill BFS tile map 2D (domain game), melatih
  indeks 2D berbatas + stack eksplisit non-rekursif + alokasi sizeof
  eksplisit.

Ciri tool dogfooding yang baik:
- Murni API yang sah (console, in-memory), sehingga melatih jalur OK.
- Sebaiknya relevan dengan domain user (hardware/game/web/dst) agar sekaligus
  mengekspos kebutuhan library baru → bahan revisi whitelist.
- Setiap fitur baru di tool tersebut = uji nyata untuk myc.
