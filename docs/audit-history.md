# Audit History — log kronologis pengembangan myc

> Dokumen ini berisi **sejarah implementasi dan audit** (MYC-AUDIT-001..030 dan
> catatan fase pengembangan). Aturan stabil dan panduan kerja ada di
> `AGENTS.md` di root. Jangan menaruh aturan baru yang mengikat di sini —
> tempatnya di `AGENTS.md` atau `docs/design-contract.md`.
>
> Prinsip lama yang masih berlaku (ringkas): heuristik teks = observasi
> ber-confidence dan non-blocking; satu-satunya gate hard = bukti semantik
> (gcc memory tier `-Werror`/`-fanalyzer`, sanitizer runtime, Eva, checked,
> Fil-C). Detail prinsip: `AGENTS.md`.

---

## Status arah (catatan 2026-08-01)

- Arah baru **sudah diimplementasikan (Fase A, P4+P5, selesai 2026-08-01)**.
- Keputusan user: **policy = non-blocking warning**. Header & fungsi denylist
  tidak lagi menolak program sah. Sejak **MYC-AUDIT-014** (2026-08-02),
  lint memory-safety juga TIDAK lagi hard (heuristik teks = observasi +
  confidence, non-blocking); satu-satunya gate hard = **gate gcc**
  (tier memori `-Werror`, `-fanalyzer` = bukti semantik) + gate runtime
  (sanitizer), proof (Eva), checked (L4), Fil-C.

---

## MYC-AUDIT-001..030 dan fase pengembangan (kronologis)

### P6 — Gate verification run (`--run`), 2026-08-01

Gate verification run opsional (`--run`) dengan clang ASan+UBSan (`-O0`,
source via stdin, DLL runtime disalin, eksekusi via proc.c) → assurance
**L3 RUNTIME**. Non-blocking: bila clang hilang / kode bukan executable,
assurance statis dipertahankan + diagnostic.

### P7 (D1.5) — contract-lite, 2026-08-01

Scan `//@ requires/ensures` (info di laporan: `contracts: requires=N
ensures=M`) + inject `assert(requires)` ke verification build (`--run`)
sebagai defense-in-depth. `bad_contract_pre.c` → RUNTIME_VIOLATION
(assert menangkap pelanggaran pre).

### D2.2 — driver-generator, 2026-08-02

Gate `--driver` scan fungsi ber-kontrak (`//@ requires`), parse signature,
bangkitkan harness kasus tepi DI DALAM domain kontrak (batas dari requires,
0/1/2/3), build + run clang ASan+UBSan (`-O0`, source via stdin). Run
bersih ≥ 1 kasus → L3 RUNTIME; sanitizer menangkap bug →
MC_DRIVER_VIOLATION (fixture `bad_driver_oob.c`: OOB via `a[n]` saat n=4
pada kontrak `n <= 4`). Non-blocking: clang hilang / tak ada fungsi
ber-kontrak / build harness gagal → skip + diagnostic. Nilai negatif/
SIZE_MAX TIDAK diuji tanpa kontrak yang membuka peluangnya (hindari false
positive). Harness men-rename main asli via `#define main` lalu `#undef` —
source dengan `main` tetap bisa di-drive.

### Tool MCP `contracts` + `lint`, 2026-08-02

`mcp.exe` mengekspos 5 tool (`check`, `version`, `policy`, `contracts`,
`lint`). `contracts` = list ekspresi `//@ requires/ensures` (API baru
`myc_contract_list` di contract.c). `lint` = jalankan lint memory-safety
langsung (tanpa pipeline penuh). Smoke test diperbarui ke 10 pesan.

### Client MCP contoh, 2026-08-02

`mcp_client.py` (Python stdlib, tanpa dependensi) — handshake initialize,
tools/list, panggil check/version/contracts/lint via stdio.

### P7 (D3.1) — Frama-C Eva (`--prove`), 2026-08-01

Gate `--prove` → L2 EVA (label lama "L2 PROVEN" dihapus MYC-AUDIT-013).
Frama-C 33.0 (Arsenic) diinstal via opam di WSL Ubuntu-24.04
(`/home/megaalive/.opam/default/bin/frama-c`); myc mendeteksi via `wsl.exe`
dan memanggil `frama-c -eva` dengan source via stdin (template bash tetap,
tanpa shell string berisi source). Alarm Eva (`[eva:alarm]`, kelas RTE =
bug pasti) → verdict PROVE_VIOLATION; 0 alarm + analisis sungguhan (cek
"ANALYSIS SUMMARY") → L2 EVA. Non-blocking: wsl/frama-c hilang atau Eva
tidak menganalisis → skip, assurance statis dipertahankan + diagnostic.
Fixture: `ok_prove.c` → L2 EVA; `bad_prove.c` (OOB via argc opaque) →
PROVE_VIOLATION.

### Self-dogfooding

Lolos penuh: 15 source myc dicek myc sendiri → OK. (Catatan lama "akan
selalu VIOLATION karena windows.h" TIDAK berlaku lagi — policy
non-blocking.)

### Counterexample Replay Capsule (#2), 2026-08-02

`myc_replay_capsule` struct di `myc.h` (source_sha256, stdin_sha256,
stdin_len, backend identity, flags, verdict, gate_status summary,
finding/completeness/claim). Disimpan di `myc_result.capsule`, dibangun di
`myc_run()` akhir pipeline, dibebaskan di `myc_result_free()`. Serialisasi
JSON + teks di `report.c`. OOM-safe: `goto fail` cleanup di
`myc_build_capsule()`. Self-dogfooding `myc.c` lolos `-fanalyzer` (tidak
ada lagi leak). Fixture: `ok_run --run --json` memuat `"capsule"` objek
dengan semua field; `ok_run --run` mencetak blok `capsule:` di teks.

### Differential Backend Quorum (#3), 2026-08-02

Flag `--quorum` (CLI + MCP tool `check`). Setelah pipeline selesai,
`myc_quorum_analysis()` (di `compile.c`, dipanggil dari `myc_run()` agar
selalu terpanggil walau pipeline early-return) membandingkan status semua
gate yang diminta: semua `completed_clean` → `MYC_QUORUM_CLEAN`; campuran
findings+clean → `CONFLICT` (backend tidak sepakat); ada gate
incomplete/unavailable → `INCONCLUSIVE`; **tidak ada hasil gate sama sekali**
(mis. lint memblokir pipeline sebelum gate berjalan) → `INCONCLUSIVE`
(jujur, bukan "agree clean"). Status + laporan teks di
`quorum_status`/`quorum_report` (teks + JSON + capsule).

Bug ditemukan saat menyelesaikan sesi: (1) `quorum_report` dialokasikan
dari arena tapi di-`free()` individual setelah arena dibebaskan → invalid
free/crash → dihapus (arena yang membebaskan); (2) quorum tidak dipanggil
di branch `file_path`-only `myc_run` → ditambahkan; (3) **bug lama**:
`myc_result_to_json` kehilangan `}` penutup level teratas sejak capsule #2
→ semua output `--json` invalid (MCP interop lolos karena hanya cek
substring) → diperbaiki, kini JSON valid ketat; (4) MCP belum mengekspos
`--quorum` → ditambahkan. Verifikasi: quorum clean pada
`ok_hello`/`ok_run --run`/`ok_driver --driver`, conflict pada
`bad_syntax`/`bad_run_oob --run`/`bad_driver_oob --driver`, inconclusive
pada lint-violation. Semua regression + self-dogfooding 16 source + MCP
smoke tetap hijau; receipt deterministik tetap (`ok_run --run` →
`272d7531...`).

### Metamorphic Verification (9.7), 2026-08-02

Gate `--metamorphic` (CLI + MCP tool `check`) → `myc_metamorphic_gate()` di
`run.c` memakai ulang mesin run gate (temp dir, ASan DLL, canary, marker).
Source SAMA dibangun 2× dengan clang ASan+UBSan (`-O0` dan `-O2`),
dijalankan dengan input sama, hasil dibandingkan: hanya satu build
menemukan sanitizer → `metamorphic_inconsistent` + verdict
`RUNTIME_VIOLATION` (kemungkinan UB / toolchain-sensitive — fixture
`bad_run_oob.c` membuktikan: OOB terdeteksi di `-O0`, hilang di `-O2`
karena optimizer); keduanya menemukan → violation konsisten; keduanya
bersih → `COMPLETED_CLEAN` (L3 RUNTIME); exit code berbeda tanpa sanitizer
→ hanya diagnostic informasional (bukan klaim bug). Non-blocking: clang
hilang / build gagal / canary mati → di-skip atau INCONCLUSIVE, assurance
statis dipertahankan. Fingerprint `v8`→`v9` (+dimensi `meta`). Berinteraksi
dengan `--quorum` (gate metamorphic ikut dibandingkan). Regresi di
`test/_regress_run.bat`.

### Negative-Space Analysis (9.8), 2026-08-02

Gate `--negative` (CLI + MCP tool `check`) → `myc_negative_space()` di
`negative.c` (baru, reentrant: tanpa global state — statistik per-fungsi di
array lokal berindeks ALLOC_FUNCS, nama = pointer statis, tanpa strdup).
Structural mining "pola yang hilang": keluarga pola pertama = konvensi
pemeriksaan hasil fungsi alokasi (`malloc/calloc/realloc/strdup/fopen`).
Untuk tiap callsite, tentukan apakah hasilnya DIPERIKSA (`== NULL` /
`!= NULL` / `!p`), langsung (`(p = malloc()) == NULL`) atau kemudian
(forward-scan sampai keluar blok, jendela 4096); LHS dikenali melewati cast
eksplisit (`p = (char *)malloc(...)` — bug awal: tanpa itu semua callsite
ber-cast terhitung salah). Bila mayoritas memeriksa tetapi ada yang tidak →
`project convention deviation` + confidence (0.55–0.98) di diagnostic.
**HANYA observasi**: status gate baru `MYC_GATE_COMPLETED_OBSERVATIONS`
(ditambahkan ke enum — gate selesai tapi hasilnya bukan finding
terkonfirmasi; benign terhadap reducer: tidak menaikkan verdict, tidak
menurunkan completeness, tidak menambah debt; quorum memperlakukannya
sebagai non-conflict). Verdict tetap OK walau ada deviation (prinsip
MYC-AUDIT-014: heuristik teks bukan bukti semantik). Non-blocking: 0
callsite → `NOT_APPLICABLE`, tanpa klaim. Laporan: teks
`negative (9.8): callsites=N deviations=M` + `scope:` + JSON
`ran_negative`/`negative_callsites`/`negative_deviations` + capsule.
Fingerprint `v9`→`v10` (+dimensi `neg`); karena `MYC_GATE_COUNT` bertambah,
receipt golden `ok_run --run` berubah → `272d7531...`
(`negative_ok --negative` → `6c364f7e...`, deterministik). Fixture:
`tests/negative_ok.c` (3 callsite, semua diperiksa → `completed_clean`),
`tests/negative_dev.c` (4/5 malloc diperiksa, `make_e()` tidak →
`completed_observations` + diagnostic callsite baris + konvensi `4/5 ...
confidence 0.81`, verdict tetap OK). Regresi di `test/_regress_run.bat`.

### Silence Is a Finding (9.10), 2026-08-02

Flag `--require-complete` (CLI + MCP tool `check`) → **verification gap =
kegagalan CI, bukan kesunyian**. Tiap gap verifikasi kini punya kode
finding `MYC-INCOMPLETE-XXX` (`myc_debt_code()` di `gate.c`:
GATE-UNAVAILABLE / GATE-INFRA-FAILED / GATE-INCONCLUSIVE / NONZERO-CASES /
ENSURES-UNPROVED / RAW-BUFFERS / OUTPUT-TRUNCATED) di laporan teks + JSON
(field `code` per item debt). Bila flag dipakai dan ada debt (gap) →
`enforce_require_complete()` di `myc_run()` menaikkan verdict `OK` →
`INCONCLUSIVE` (exit 1; finding/completeness diselaraskan). **Prasyarat
AUDIT-004/010 (sekaligus diperbaiki)**: gate DIMINTA yang backend-nya tidak
tersedia kini `UNAVAILABLE` + debt (bukan `NOT_APPLICABLE` yang diam-diam
lolos) — filc/prove/driver skip → `UNAVAILABLE` (driver tanpa fungsi
ber-kontrak tetap `NOT_APPLICABLE` = benar-benar tidak berlaku;
checked/negative tanpa pola tetap NA). Konsekuensi: `ok_filc --filc` di
sistem tanpa Fil-C kini `INCONCLUSIVE` + debt (dulu OK senyap); quorum ikut
lebih jujur (unavailable → inconclusive). Non-blocking tetap: assurance
statis dipertahankan (bukan diturunkan). Fingerprint `v10`→`v11`
(+dimensi `reqc`); receipt golden `ok_run --run` → `272d7531...`
(deterministik). Fixture tanpa flag: `ok_contract.c` → OK exit 0 (gap
ensures-unproved terlihat tapi tidak menggagalkan); dengan
`--require-complete` → INCONCLUSIVE exit 1. Regresi di
`test/_regress_run.bat` (+5 cek).

### MYC-AUDIT-012, 2026-08-02 (`myc_buf.h`)

Checked-buffer kini menjaga **element type + checked multiplication**.
Checked mode `MYC_BUF(T)` = struct anonim ber-*member typed* `T *data` +
`byte_capacity` (BYTE) + `elem_size` + `generation` + `cookie` (magic,
deteksi korupsi metadata). `MYC_AT` memverifikasi **ukuran elemen di
COMPILE TIME** via trik array negatif C11 murni
`sizeof(char[sizeof(T)==sizeof((b).data[0]) ? 1 : -1])` (tanpa ekstensi,
tetap LVALUE — cek diletakkan di argumen helper yang mengembalikan pointer,
bukan operator komma) **dan** membandingkan `elem_size` di runtime;
`MYC_NEW` menolak `n*sizeof(T) > SIZE_MAX` (trap `MYC_CHECKED: MYC_NEW
overflow` — sekaligus menangkap n negatif yang ter-cast ke size_t raksasa);
bounds `MYC_AT` memakai `i >= byte_capacity/elem` sehingga `i*elem`
dijamin tidak overflow (checked multiplication dalam satu pembandingan).
`MYC_FREE` memeriksa cookie (korupsi) dan men-null-kan data (use-after-free
terdeteksi). Mismatch tipe ber-ukuran sama (int vs unsigned) sengaja TIDAK
dianggap berbahaya (bounds/offset/alignment identik) — jujur di
dokumentasi. Batasan: MYC_AT harus lvalue (assignment) sehingga cek tidak
bisa dipisah jadi ekspresi komma; `MYC_NEW` pada buffer aktif (re-init)
tidak di-trap (baca memori indeterminate pada deklarasi segar). Fingerprint
`v11`→`v12` (+dimensi `buf` = revisi runtime checked-header); receipt
golden baru: `ok_run --run` → `272d7531...` (deterministik), `ok_hello` →
`17b404ab...`, `negative_ok --negative` → `6c364f7e...`. Fixture:
`tests/bad_checked_type.c` (MYC_AT tipe ber-ukuran salah pada MYC_BUF(int)
→ COMPILE_ERROR di checked build), `tests/bad_checked_new_overflow.c` (n
opaque via argc sehingga `n*4` overflow SIZE_MAX → `--run --checked` =
RUNTIME_VIOLATION dengan marker `MYC_NEW overflow`). Regresi di
`test/_regress_run.bat` (+3 cek); `ok_checked`/`dogfood_ring` tetap L4.

### MYC-AUDIT-013, 2026-08-02 (klaim Frama-C Eva / label assurance)

Label `L2 PROVEN` → **`L2 (EVA)`** dan `L5 FULL` → **`L5 (FILC)`** (enum
`MYC_ASSURANCE_L2_EVA`/`MYC_ASSURANCE_L5_FILC`; label lama menyiratkan
bukti lebih dari yang dikumpulkan). Eva adalah **abstract interpretation**:
L2 EVA = 0 alarm RTE di bawah model default (entry main), BUKAN proof
obligation WP, BUKAN "kontrak terbukti" — pesan diagnostic diubah ("prove:
Eva 0 alarm RTE (abstract interpretation, entry main; bukan proof
obligation WP)"). Laporan prove kini jujur dan berkonteks: `prove:` blok
memuat `mode` (`eva (abstract interpretation)`), `version` (diparse dari
`frama-c -version` via WSL detect — `33.0 (Arsenic)`), `entry` (main
default), `alarms`, dan catatan pembatasan — di teks + JSON
(`prove_mode`/`prove_version`). Pesan Fil-C juga dilemahkan ("run bersih -
eksekusi Fil-C bersih (L5 FILC); bukan klaim FULL"). Istilah FULL dihapus
dari README/docs. Receipt TIDAK berubah (label assurance tidak di-hash) —
`ok_run --run` tetap `272d7531...`. Verifikasi: `ok_prove --prove` → L2
(EVA) + version; `bad_prove` → PROVE_VIOLATION; self-dogfooding + regress
tetap hijau.

### MYC-AUDIT-016, 2026-08-02 (MCP schema & JSON-RPC ketat)

Tool `check` kini mengirim **`structuredContent`** — hasil `myc_result`
penuh sebagai objek JSON (`schema: "myc.result.v1"`) di samping
`content[0].text` (JSON string, tetap ada untuk backward compat) — konsumen
mesin TIDAK lagi perlu parse JSON di dalam JSON. **`isError` hanya untuk
kegagalan tool/protocol** (`ERROR` input/validasi, `TIMEOUT`, `CANCELLED`);
`PROVE_VIOLATION`/`DRIVER_VIOLATION` dll. adalah finding pada KODE →
isError=false (sebelumnya dicampur, tidak konsisten dengan verdict).
**JSON-RPC ketat**: field `jsonrpc` wajib `"2.0"` (selain itu → -32600),
`id` hanya string/angka/null (typed ID, nilai dipertahankan apa adanya),
pesan tanpa `id` = notification → diproses tanpa balasan (semantik JSON-RPC
2.0). **Negosiasi protokol strict**: `initialize` selalu mengumumkan versi
server (`2024-11-05`), tidak meng-echo permintaan klien. **Unknown flag
ditolak** (fail-fast -32602 dengan nama flag), tidak diabaikan. Tidak
menyentuh `myc_result` → fingerprint/receipt TIDAK berubah (`ok_run --run`
tetap `272d7531...`). Verifikasi: smoke MCP 13 respons (incl. -32600,
unknown flag, structuredContent+schema), interop SDK resmi 26 cek (incl.
isError=false untuk PROVE/DRIVER violation + structuredContent), semua
suite regress hijau.

### MYC-AUDIT-017, 2026-08-02 (saluran laporan sanitizer non-spoofable)

Marker teks pada stdout/stderr mudah dipalsukan program (fixture
`spoof_marker_run.c` / `bad_driver_spoof.c` mencetak teks mirip marker
sendiri, exit 0). Kini bukti UTAMA = FILE report yang ditulis runtime
sanitizer sendiri: env deterministik per gate (`preq.env` di proc.c —
`ASAN_OPTIONS=log_path=<base>:abort_on_error=1:halt_on_error=1`,
`UBSAN_OPTIONS=log_path=<base>:halt_on_error=1:print_stacktrace=1`,
`LC_ALL=C`) → runtime menulis `<base>.<pid>` di tmp_dir; myc membacanya via
`myc_read_sanitizer_report()` dan membersihkan via
`myc_remove_sanitizer_reports()` (glob `<base>.*`). Finding = report file
ADA **atau** (marker teks && exit code != 0). Teks mirip marker dengan exit
0 diabaikan + diagnostic (program bisa mencetaknya sendiri). Berlaku
konsisten di gate run (L3), canary, metamorphic, driver, dan filc (panic
Fil-C hanya finding bila exit != 0; marker tanpa exit = diagnostic).
`log_path` relatif (path absolut dengan `:` memecah parsing ASAN_OPTIONS di
Windows ASan; CWD child = tmp_dir unik). **Bug ditemukan & diperbaiki saat
uji**: env metamorphic dibuat di blok stack lokal yang keluar scope sebelum
`myc_proc_run` (use-after-scope → segfault; gdb backtrace: `strlen` di
`proc_run_win`); diperbaiki dengan buffer di scope fungsi
(`meta_env_asan/ubsan[2][160]`, `meta_env[2][4]`). **Bug review lanjutan**:
(1) `build_env_block` Windows hanya menambahkan override yang key-nya TIDAK
ada di induk → override yang menggantikan key induk (mis. `ASAN_OPTIONS`
bila user set) DROP total; diperbaiki: semua override ditambahkan (entri
induk ter-override sudah di-skip loop atas). (2) `child_env` POSIX bocor di
jalur sukses → di-free sebelum return. (3) filc `panics>0 && exit==0`:
jalur native vs WSL tidak konsisten (WSL set COMPLETED_CLEAN tapi ret=0 →
pipeline menimpa jadi UNAVAILABLE); kini kedua jalur treat sebagai run
bersih (`filc_panics` di-reset + ret=1 → L5 diklaim, teks diabaikan jadi
diagnostic). Verifikasi: `bad_run_oob --run` tetap RUNTIME_VIOLATION (via
report log_path), `spoof_marker_run --run` → OK + diagnostic,
`bad_run_oob --metamorphic` → inconsistency via report (-O0 finding vs -O2
clean), `ok_driver --driver` tetap OK, `ok_run --run` receipt tetap
`272d7531...`; regress 63 [OK] 0 [FAIL]; soak + MCP interop hijau.

### MYC-AUDIT-018, 2026-08-02 (test portabel: concurrency/deadlock/OOM)

Runner lintas-platform **`test/_audit018.sh`** (bash — jalan di Windows
git-bash DAN POSIX, di-wire ke `_regress_run.bat` via `where bash`; tanpa
bash → [SKIP]) membangun + menjalankan 4 unit test C baru: (1)
**`proc_flood.c`** — deadlock (child tulis 1 MiB stdout → baca 1 MiB stdin
→ tulis 1 MiB stderr; parent kirim 1 MiB stdin; tanpa timeout, total persis
— mengunci fix MYC-AUDIT-002), flood 100 MiB stdout + 100 MiB stderr cap 64
KiB (prefix+tail ring dipertahankan, truncated=1, memori bounded — mengunci
Fase 1.5), env override (key induk diganti, sisanya diwarisi — mengunci fix
AUDIT-017 build_env_block); (2) **`oom_guards.c`** — arena overflow guard +
input ekstrem (source >1MiB → INPUT_TOO_LARGE, NUL → NUL_IN_INPUT, request
kosong → INVALID_REQUEST); (3) **`oom_alloc.c`** — **allocator injection**
via `-Wl,--wrap=malloc,calloc,realloc` (GNU ld, MinGW & glibc): 49 titik
kegagalan alokasi pada myc_run tanpa crash/hang, verdict selalu valid,
kontrol OK; (4) **`stress_threads.c`** — concurrency 8×200 (kini juga di
POSIX). **Bug nyata ditemukan test ini**: `myc_result_arena_dup` dengan
`string_len` raksasa (SIZE_MAX-9) → `n+1` wrap ke 0 → `memcpy` OOB raksasa;
diperbaiki guard ganda (n==SIZE_MAX tolak + blok alokasi dicek `block >
SIZE_MAX - sizeof(arena)` → NULL). Regress naik ke **92 [OK] 0 [FAIL]**;
receipt golden tetap `272d7531...`.

### MYC-AUDIT-019, 2026-08-03 (CLI ingress fail-fast + portabilitas POSIX)

**CLI kini fail-fast pada unknown flag** (Fase-2 canonical ingress,
konsisten dengan reject unknown flag MCP AUDIT-016 -32602): `myc.exe check
ok.c --rnu` → pesan `myc: unknown option: --rnu` + exit 2 (sebelumnya
diam-diam diabaikan → hasil OK palsu saat user salah ketik flag);
`--run-stdin` / `--cwd` tanpa argumen nilai → pesan + exit 2 (sebelumnya
`--run-stdin` tanpa argumen menyebabkan OOB baca argv di luar batas saat
`argv[++i]` melewati akhir array). Parsing flag ditulis ulang ber-`known`
flag eksplisit, nilai flag dikonsumsi `i++` aman. **Bug segfault nyata di
stress_threads build POSIX**: `strdup` tidak dideklarasikan glibc tanpa
feature macro `_POSIX_C_SOURCE` → kompiler menganggapnya `int` → pointer
64-bit di-truncate ke 32-bit → segfault (ditemukan audit018 WSL); diganti
`myc_strdup()` (myc.h, impl. proc.c). **False-positive race di
stress_threads**: 8-thread berbaur di mount NTFS lambat → spawn gcc pertama
timeout transien (`MC_TIMEOUT`, err `MYC_ERR_TIMEOUT`) → `verdict_ok !=
NITER` melabeli thread "MISMATCH (race/stale)" padahal `source_sha256`
DETERMINISTIK stabil (dibuktikan debug per-iterasi); diperbaiki:
`MC_TIMEOUT` masuk set verdict yang dihitung, sinyal race tetap sha
determinisme. **Test infra**: `_regress_run.bat` memanggil `bash
test/_audit018.sh` (slash, bukan backslash — backslash pecah di WSL
git-bash), echo paren dihapus agar tak membobol blok `if errorlevel`;
`_audit018.sh` menambah deteksi `-pthread` (diperlukan pthread_create/join
di POSIX). Regresi: audit018 5/5 unit test lulus (proc_flood, oom_guards,
oom_alloc, stress_threads 8×200, verify_descendants), full
`_regress_run.bat` 0 [FAIL], receipt deterministik `ok_run --run` tetap
`8224c23a...` (tidak ada perubahan pipeline/hash).

### MYC-AUDIT-019 lanjutan, 2026-08-03 (Lampiran A roadmap + bug WIFSIGNALED POSIX)

**Bug nyata WSL ditemukan**: gate `--run` selalu INCONCLUSIVE di POSIX
karena `myc_runtime_canary` return -1 → diagnostic "canary ASan gagal
dibangun" padahal build canary sukses. Akar: program yang di-SIGABRT
sanitizer (OOB terdeteksi, exit 134 = 128+SIGABRT) diklasifikasi
`WIFSIGNALED` → `res->ok = 0` + `err = MYC_ERR_EXECUTE_FAILED` →
`myc_proc_run` return 0 → caller menganggapnya kegagalan infra. **Fix
proc.c**: `WIFSIGNALED` kini `ok = 1`, `err = MYC_ERR_NONE` (exit_code
128+sig hasil valid, konsisten dengan Windows yang selalu `ok=1` utk proses
berjalan; hanya exec/fork gagal yang `ok=0`). Akibat: run gate POSIX kini
benar-benar menangkap finding (bad_run_oob `--run` → RUNTIME_VIOLATION),
canary sehat (ok_run `--run` → completed_clean), metamorphic konsisten.
**Portabilitas `-Werror`** (self-dogfooding WSL awalnya 3 COMPILE_ERROR):
`(void)write()` tidak menekan `-Wunused-result` glibc → diganti tangkap
`ssize_t wr`; `copy_file`/`asan_dll_path` (run.c) & `drv_copy_file`/
`drv_asan_dll_path` (driver.c) hanya dipakai di `#ifdef _WIN32` → kini
di-guard `#ifdef _WIN32` (unused di POSIX). **Lampiran A roadmap ditutup**:
`test/audit_lampiran.c` baru (7 test portabel, di-wire ke `_audit018.sh`):
exec-vs-127, temp path absolut, multiple consecutive requires, long
contract expression REJECTED (bukan truncate — `read_contract_expr` kini
return 2 + diagnostic "terlalu panjang", contract.c), NUL tak pernah dibuat
di POSIX, 0 driver cases, result lama immutable. Lampiran A kini 24/27
`[x]` (sisa: fingerprint OOB test, file_path-only test, OOM JSON test,
Fil-C run_stdin, canary-failure fixture — fix ada, test eksplisit belum).
Regresi: audit018 6/6 unit (audit_lampiran 12/12 OK), self-dogfooding WSL
17/17 OK, Windows regress fixture utuh (ok_run L3, bad_run_oob
RUNTIME_VIOLATION, ok_checked L4).

### MYC-AUDIT-019 lanjutan #2, 2026-08-03 (Lampiran A di-ikat test penuh)

`test/audit_lampiran.c` bertambah menjadi 17 test: **T8** fingerprint cwd
3000-char tetap 64-hex + deterministik (AUDIT-005; `--fp-long` mode; varian
ASan di-ikat ke `_audit018.sh` section 6b — menangkap OOB read regresi
secara eksplisit, non-blocking bila toolchain tanpa ASan), **T9**
`file_path`-only request tanpa NULL deref + source di-load & di-hash
(AUDIT-007), **T11** canary failure invalidates backend (9.9): binary
di-hardlink sebagai `fake-clang` (`fake-clang.exe` di Windows,
`strstr(argv[0],"fake-clang")` dispatch) yang menolak build canary (`-o`
berisi "myc_canary" → exit 1, nama canary = `myc_canary.exe` di
`run.c:317`) tapi menerima verification build (compile program polos via
gcc) → `myc_runtime_canary` return -1 → gate runtime **INCONCLUSIVE**
(run.c:744-763). **OOM JSON** (AUDIT-009): fase
`json_new_obj/obj_set/arr_push/serialize` 49 fail point ditambahkan ke
`test/oom_alloc.c` (--wrap). **Bug nyata ditemukan di WSL**: parent myc mati
SIGPIPE (exit 141) saat menulis stdin ke child yang sudah mati lebih awal
(exec gagal / `chdir(cwd)` gagal — T8 memakai cwd 3000-char yang tak ada →
child _exit sebelum baca stdin) → `write()` tidak sempat return EPIPE karena
sinyal default membunuh parent. **Fix proc.c POSIX**: tahan `SIGPIPE`
(`SIG_IGN` via `sigaction`, simpan & pulihkan handler lama) selama loop
tulis stdin; `write()` kini return EPIPE → break seperti desain. Lampiran A
kini **27/28** `[x]` (sisa: Fil-C run_stdin WSL path — mekanisme ada tapi
stdin tidak diteruskan ke program child di WSL; fix terpisah). Fil-C kini
terpasang di WSL (pizfix 0.681, `~/bin/filc-clang` → `filc-clang` di PATH;
gate `--filc` berfungsi: ok_filc → L5 FILC, bad_filc_oob →
FILC_VIOLATION). Regresi: `_audit018.sh` WSL 6/6 + fp-long ASan OK +
verify_descendants OK (0 FAIL); Windows `_regress_run.bat` 0 [FAIL]
(self-dogfooding 16 OK, fixtures utuh, MCP interop 25 cek).

### MYC-AUDIT-020, 2026-08-03 (CLI `--timeout`/`--output-cap` + validasi request API)

Flag CLI baru `--timeout MS` (0–600000, 0 = default 30000) dan
`--output-cap BYTES` (0–104857600, 0 = default 1 MiB) memetakan ke field
`myc_request.timeout_ms`/`max_output_bytes` yang sudah dipakai semua gate
(proc/run/prove/filc/driver/metamorphic). **Validasi ingress di
`myc_request_validate`** (berlaku untuk CLI, API, dan MCP): timeout di luar
rentang → `MYC_ERR_INVALID_TIMEOUT`; output-cap di luar rentang →
`MYC_ERR_INVALID_OUTPUT_CAP`; `cwd` string kosong → `MYC_ERR_INVALID_CWD`
— verdict ERROR + diagnostic CONFIRMED (bukan silent). **Bug nyata yang
diperbaiki**: `--output-cap -5` sebelumnya LOLOS validasi (cek hanya `>
cap`) → di proc.c `req->max_output_bytes` (int -5) di-cast ke `size_t`
raksasa → alokasi drain buffer raksasa saat `--run`; kini nilai negatif
ditolak. **Fail-fast angka** (konsisten MYC-AUDIT-019): `atoi` diganti
helper `parse_int_arg` (strtol + cek `errno==ERANGE` + trailing garbage +
rentang int) — `--timeout abc`/`--timeout 5000x`/`--output-cap
99999999999` kini pesan + exit 2, bukan diam-diam jadi 0/default. Capsule
(`myc_replay_capsule`) sudah memuat timeout_ms/max_output_bytes (tidak
berubah). Receipt TIDAK berubah (validasi ingress tidak masuk hash) —
`ok_run --run` tetap `8224c23a...`. Regresi: section AUDIT-020 di
`test/_regress_run.bat` (+12 cek: valid, negatif, overflow, non-angka exit
2, aliran nilai ke capsule, cwd kosong).

### MYC-AUDIT-021, 2026-08-03 (Lampiran A 28/28: run_stdin ke Fil-C di WSL)

Gate `--filc --run-stdin` di WSL TIDAK meneruskan stdin ke program child —
env `MYC_FILC_STDIN` berisi path Windows (`D:\Temp\...`) yang tidak bisa
dibaca WSL, dan env Windows → WSL bash TIDAK diteruskan otomatis (debug
membuktikan: blok env benar berisi `MYC_FILC_STDIN`, tapi `echo` di WSL
tetap `UNSET`). **Fix**: pakai mekanisme resmi **`WSLENV`** — proc.c
`build_env_block` sekarang menambahkan override `WSLENV` (merges parent
bila sudah ada; `MYC_FILC_STDIN/p` = share + path translation otomatis ke
`/mnt/<drive>/...`), filc.c template WSL memakai `$MYC_FILC_STDIN`
langsung (fallback `wslpath` bila WSLENV tak sampai). **Bug lanjutan
ditemukan & diperbaiki**: entri env tanpa `=` → CreateProcess `ERROR 87`
(ERROR_INVALID_PARAMETER) — `wslenv_env` sempat tanpa prefix `WSLENV=`;
double-colon di WSLENV dihindari. **Leak**: file stdin temp Windows kini
di-`remove()` di semua jalur keluar (out_wsl + early-return). Fixture
permanen `test/fixtures/ok_filc_stdin.c` (baca stdin, cetak `got:...`) +
regresi AUDIT-021 (`ok_filc_stdin --filc --run-stdin` →
`got:halo-filc-stdin`; di sistem tanpa Fil-C = INFO, bukan FAIL). Lampiran
A kini **28/28** `[x]`. Receipt tidak berubah.

### MYC-AUDIT-022, 2026-08-03 (roadmap 7.1: machine-readable diagnostic + exact tool identity)

(1) **diagnostic JSON** — gate kompilasi (compile, analyzer, checked) dapat
mengekstrak diagnostik terstruktur jika GCC mendukung format JSON;
`ingest_gcc_diagnostics` di compile.c mem-parse array JSON (reuse parser
ketat json.c): `kind`/`message`/`locations[0].caret.line/column` →
`myc_diagnostic` terstruktur (kind `note` di-skip, konsisten parser teks
lama); bila parse JSON gagal (output terpotong bounded capture) atau stderr
format teks (gate preprocess `gcc -E` tanpa flag JSON) → fallback parser
baris lama. Verifikasi: `bad_realloc.c` → diag `[17:12] pointer 'buf' used
after 'realloc'` (dari JSON, confidence CONFIRMED); (2) **exact tool
identity** — helper baru `myc_tool_version()` di proc.c (jalankan `<exe>
--version`, ambil baris pertama stdout, buang trailing CR) → field baru
`myc_result.gcc_version`/`clang_version` (di-set pipeline setelah resolve
gcc/clang, guard NULL agar run+driver tidak double-free), ditampilkan di
teks (`gcc_version:`/`clang_version:`) + JSON (`"gcc_version"`/
`"clang_version"`, NULL → null); `myc version` CLI kini mencetak versi
persis backend (`gcc.exe (...) 15.2.0`, `clang version 22.1.6 (...)`) —
menutup roadmap "version belum memberi exact toolchain identity". Receipt
TIDAK berubah (flag/versi tidak masuk hash; status gate clean tetap clean)
— `ok_run --run` tetap `8224c23a...`. Regresi: section AUDIT-022 di
`test/_regress_run.bat` (+8 cek).

### MYC-AUDIT-023, 2026-08-03 (Fase 8: CI Windows + Linux / test engineering)

(1) **`build.sh`** — mirror POSIX `build.bat` (myc/mcp/argv_probe) untuk
Linux/CI. (2) **`test/_ci_linux.sh`** — trust-core runner POSIX: build +
self-dogfooding 16 source + fixture kunci (ok_hello OK, bad_syntax/
bad_realloc COMPILE_ERROR, diagnostic JSON, checked L4, run
L3/RUNTIME_VIOLATION, dogfood tool, json_abuse, audit018). Frama-C/Fil-C
TIDAK diinstall di CI → fixture terkait UNAVAILABLE (non-blocking 9.10).
(3) **`.github/workflows/ci.yml`** — job windows (build.bat +
`_regress_run.bat`; toolchain preinstalled image windows-2025: MSYS2
mingw64 gcc 15.2.0 di C:\msys64 + LLVM 20.1.8, keduanya ditambahkan ke
PATH) + job linux (build.sh + `_ci_linux.sh`; apt install clang). **Bug
portabilitas yang ditemukan & diperbaiki**: (a) assert receipt golden
`8224c23a...` di `_regress_run.bat` bersifat MESIN-SPESIFIK — receipt
memuat fingerprint berisi `gcc_path`+`cwd`, jadi nilai golden beda di CI →
diganti cek DETERMINISME lintas-run (dua run input sama → receipt sama);
(b) `_audit018.sh` section filc salah memakai `run_built` (cek EXIT code)
untuk fixture `bad_filc_oob --filc --run` — verdict FILC_VIOLATION memang
exit 1 → diganti grep output; (c) gcc 13 (Linux) memakai kutip Unicode `'`
sedangkan gcc 15 (MinGW) ASCII `'` pada pesan `pointer 'buf' used after
'realloc'` → pola regex cocok keduanya; (d) bug cmd: parens `(CI-
portabel)` di teks echo dalam blok `if (...)` memutus parsing (`)` tak
terduga) → bentuk `if defined ...` tanpa blok. **Perbaikan CI lanjutan
(2026-08-05)**: (e) `prove.c` -Werror gagal di Linux gcc 13 karena
`run_wsl()` + `wsl_path` unconditional di file yang juga dikompilasi di
POSIX → di-`#ifdef _WIN32`; (f) `fingerprint_cache_update` crash saat
`cwd == NULL` pada run kedua → guard `(!cwd || strcmp(...))`; (g)
`fp_cache` static global menyebabkan data race di `stress_threads` →
diubah jadi `_Thread_local`. Verifikasi: Linux (WSL) `_ci_linux.sh`
PASS=18 FAIL=0 (audit018 SELESAI OK incl. filc + verify_descendants);
Windows regress 153 [OK] 0 [FAIL]. Catatan: job CI windows memakai clang
MSVC-target LLVM (ASan DLL `clang_rt.asan_dynamic-x86_64`) — bila backend
run tak sehat, canary → INCONCLUSIVE dan assert L3 FAIL (jujur, bukan
false-clean).

### MYC-AUDIT-024, 2026-08-03 (roadmap 7.7: Fil-C version identity + robust report parser + per-case scope)

(1) **version identity** — field `filc_version` di `myc_result` (baris
pertama `filc-clang --version`, mis. `clang version 20.1.8 (Fil-C 0.681
...)`), diisi native via `myc_tool_version` dan WSL via query
`query_filc_version_wsl` (non-blocking: gagal = NULL, verdict tak berubah);
tampil di teks (blok `filc:` baris `version:`) + JSON (`filc_version`);
`myc version` kini juga mencetak status filc (jujur: `TIDAK DITEMUKAN` di
Windows karena filc-clang hanya Linux). (2) **robust report parser** —
`count_panics` (hitungan strstr marker yang rapuh/spoofable) diganti
`parse_filc_report` STRUKTURAL: panics = jumlah baris kanonik `[<pid>] filc
panic:` (tiap panic meng-abort SIGTRAP → tepat satu baris), fallback jumlah
blok `filc safety error:` (kompatibilitas format Fil-C lain); teks yang
HANYA memuat kata marker tanpa baris kanonik/blok safety error TIDAK
dihitung (konsisten MYC-AUDIT-017). (3) **per-case scope** —
`myc_filc_case[]` (maks 8, arena): tiap panic terekam message (teks setelah
`filc safety error:`) + lokasi origin dari frame pertama `semantic origin:`
(`file:line:col: func`); tampil di teks (`case #N:` + `origin:`) + JSON
(`filc_cases[]`); diagnostic violation kini memuat lokasi (`filc: 1 panic
-> bug memori terbukti (main @ /tmp/...:15:14: cannot write pointer ...)`
— terbukti fixture `bad_filc_oob`). Receipt TIDAK berubah (field baru
tidak masuk hash). Verifikasi: Windows regress 153 [OK] 0 [FAIL] (section
AUDIT-024 +6 cek), WSL `_ci_linux.sh` PASS=18 FAIL=0 (audit018 6c +
version identity + per-case scope), `myc version` cetak filc.

### MYC-AUDIT-025, 2026-08-03 (roadmap 7.4: Contract — pure expression validation + explicit clause status + stable function binding)

(1) **pure expression validation** — `contract_expr_purity()` (lexical,
skipping string/char literal): assignment (`=`, `+=`, `-=`, `*=`, `/=`,
`%=`, `<<=`, `>>=`, `&=`, `|=`, `^=` — `==`/`!=`/`<=`/`>=` pure), `++`/`--`,
operator comma level atas → **IMPURE**; pemanggilan fungsi (identifier
selain `sizeof` diikuti `(`) → **CALL** (purity tak terbukti). Klausa
impure/call **TIDAK pernah di-inject** sebagai assert (safety: ekspresi
ber-efek samping tidak boleh berjalan di verification build). (2)
**explicit clause status** — `myc_contract_clause[]` (maks 64, arena) per
klausa: expr, status (`ok`/`empty`/`too_long`/`impure`/`call`), kind,
line/col; tampil di teks (`contract clauses:` baris `[N] requires (func)
expr [status]`) + JSON (`contract_clauses[]` dengan function/expr/status/
line/col). (3) **stable function binding** — `find_func_binding()`: ikat
klausa ke NAMA fungsi dari pola `<ident>(...){` (keyword kontrol
if/for/while/switch/return/sizeof/case/do/else/goto ditolak; `;` sebelum
`{` = prototype/pernyataan → tak terikat); grup klausa berturut berbagi
satu binding; `myc_contract_inject` ditulis ulang: pending MULTIPLE
requires per fungsi + purity gate + whitespace antar token tidak memutus
ikatan (bug: spasi antara `)` dan `{` membuang pending). Bug purity
ditemukan saat uji: `a == b` salah ter-flag impure karena '=' pertama hanya
memeriksa karakter sebelumnya → kini cek depan+belakang. Fixture
`test/fixtures/contract_clauses.c`: pure (di-inject, run bersih), impure
`(x = 0) != 0` (TIDAK di-inject — bila di-inject pasti RUNTIME_VIOLATION),
call `helper(-5) > 0` (TIDAK di-inject), unbound sebelum deklarasi global.
Verifikasi: contract_clauses --run OK (bukti purity gate), bad_contract_pre
--run tetap RUNTIME_VIOLATION (requires pure di-inject), ok_contract --run
OK; regresi +8 cek AUDIT-025; receipt deterministik tetap `8224c23a...`
(field klausa tidak masuk hash).

### MYC-AUDIT-026, 2026-08-04 (roadmap 7.3: Checked buffer — coverage count + semantics parity tests)

(1) **coverage count** — scanner leksikal TUNGGAL `scan_checked_coverage()`
(compile.c) menggantikan `source_uses_checked_buf` (sumber kebenaran
tunggal, tanpa duplikasi logika skip komentar): menghitung deklarasi
`MYC_BUF(` + invokasi `MYC_NEW(`/`MYC_AT(`/`MYC_FREE(` di LUAR komentar /
string / char literal / baris preprocessor; batas identifier dijaga
(`MYC_BUF_COOKIE` tidak terhitung). Empat metrik `checked_buffers` /
`checked_allocations` / `checked_accesses` / `checked_frees` di laporan
teks (`checked:` blok `coverage: buffers=N allocations=M accesses=K
frees=F`) + JSON (`checked_buffers` dkk, hanya bila memakai MYC_BUF) +
capsule replay (`checked_coverage:` / `"checked_*"`). `accesses` = TITIK
akses di source yang tercakup disiplin MYC_AT (1 per invokasi tekstual,
BUKAN per eksekusi runtime — jujur: metrik statis seperti callsite
negative). Bila build `-DMYC_CHECKED` lolos, tiap buffer + tiap titik akses
terbukti tunduk cek batas → coverage = bukti cakupan L4. (2) **semantics
parity tests** — fixture `tests/semantics_parity.c` (digest deterministik
uint32; buffer `MYC_BUF(int)` + `MYC_BUF(point)` struct; coverage
2/2/6/2) dibangun DUA KALI oleh regresi: produksi (`gcc -O2`) vs checked
(`gcc -O2 -DMYC_CHECKED=1`); stdout + exit code harus IDENTIK
(`digest=176930656`, exit 0) → membuktikan transformasi fat-pointer TIDAK
mengubah perilaku kode sah (nol false positive). Terpasang di
`_regress_run.bat` (+8 cek AUDIT-026) dan `_ci_linux.sh` (section 4b,
Linux CI). Verifikasi: semantics_parity --checked → L4 + coverage
2/2/6/2, ok_checked → 1/1/2/1, dogfood_ring tetap L4, parity identik di
Windows; receipt tetap `8224c23a...` (coverage bukan bagian fingerprint —
source_sha sudah mencakup source).

### MYC-AUDIT-027, 2026-08-04 (roadmap 7.5: Driver — case record + replay capsule + boundary portfolio + combinatorial budget)

(1) **case record** — struct `myc_driver_case` di `myc.h` (case_id, func,
params, alloc_bytes, executed) + `driver_case_records[]` (maks
`MYC_MAX_DRIVER_RECORDS` 256) di `myc_result`; dibangun di
`myc_driver_gate` dari metadata harness (`drv_case_meta`: nama fungsi,
nama param, is_ptr, ukuran buffer, nilai kandidat per param, kombinasi) +
peta eksekusi per-case dari stdout. Record menampilkan parameter values +
allocation sizes + status run/skip — ditampilkan di teks (`case records
(input + status):` baris `#N func(a=16B, n=0) alloc=16B -> run`) + JSON
(`driver_case_records[]`) + capsule. (2) **harness flush jujur** — harness
kini `setvbuf(stdout, NULL, _IONBF, 0)` di awal main; tanpa ini, saat
sanitizer meng-abort proses di tengah run, stdout pipe yang fully-buffered
tidak ter-flush → SEMUA marker per-case hilang → record salah tampil 'skip'
dan klaim debt '0 kasus tereksekusi' muncul padahal kasus dieksekusi (bug
nyata ditemukan di bad_driver_oob: ASan abort di kasus n=4; sebelum fix
`cases: 0`, sesudah fix `cases: 2` + record #1/#2 run, #3-5 skip). Bila
summary `DRIVER run=N` tidak sempat tercetak (abort),
`driver_cases`/`driver_skipped` diturunkan dari jumlah marker per-case.
Akibat: bad_driver_oob TIDAK lagi memicu debt NONZERO-CASES (memang bukan
0 kasus); debt itu kini diuji lewat fixture baru
`test/fixtures/driver_zero_cases.c` (guard requires `g_flag == 1` selalu
salah → semua kasus di-skip, exit 3 → INCONCLUSIVE + debt GATE-UNAVAILABLE
+ NONZERO-CASES). (3) **combinatorial budget** — `build_combos()` di
driver.c: produk kartesian ≤ `DRV_MAX_CASES` 32 = strategi `full`; produk
> 32 = `coverage-first` (base + satu-per-nilai-ekstra + filler
leksikografis) dengan jaminan deterministik setiap nilai kandidat muncul
minimal sekali; dilaporkan jujur di teks+JSON (`combinatorial:
max_product=N budget=32 strategy=full|coverage-first`) + capsule
(`driver_max_product`/`driver_bounded`). (4) **harness identity** —
`driver_harness_sha256` (SHA-256 teks harness) di `myc_result` + capsule;
verifikasi fixture `ok_driver_bounded.c` (kontrak a/b/c ≤ 3 → max_product
64 > 32 → coverage-first, 32 kasus). Receipt TIDAK berubah (case
records/coverage bukan bagian hash) — `ok_driver --driver` tetap
`0e9be800...`. Terpasang di `_regress_run.bat` (section AUDIT-027, +10
cek) dan `_ci_linux.sh` (section 5c, +8 cek). Verifikasi: ok_driver OK L3 +
10 records + full; bad_driver_oob DRIVER_VIOLATION + records akurat;
driver_zero_cases INCONCLUSIVE + debt; mcp smoke 13 respons utuh; JSON +
capsule valid. (5) **bug portabilitas POSIX (kelas MYC-AUDIT-003)** ditemukan
saat menulis regresi Linux: `drv_make_temp_dir` memakai fallback `"."` di
POSIX (tanpa `/tmp` + canonicalisasi getcwd) → `exe_path` relatif rusak
setelah child `chdir(tmp_dir)` → gate driver di WSL SELALU "driver run exec
failed" (ok_driver jadi INCONCLUSIVE padahal build sukses; `funcs: 0`).
Diperbaiki mirror `make_temp_dir` run.c: `TEMP` → `TMPDIR` → `/tmp`,
canonicalize base relatif via `my_getcwd`; driver kini berfungsi penuh di
POSIX (ok_driver L3, harness sha IDENTIK lintas platform `6919dfb9...`,
bounded coverage-first 32 kasus). Verifikasi: `_ci_linux.sh` WSL PASS=30
FAIL=0 (sebelumnya PASS=21 FAIL=1).

### MYC-AUDIT-028, 2026-08-04 (Fase 2: size cap saat membaca)

`read_file`/`read_stdin` lama membaca PENUH tanpa batas (file 10 GB →
`malloc` 10 GB sebelum validasi menolak; `--run-stdin` tanpa cap sama
sekali; MCP `run_stdin` tak divalidasi). Kini
`read_file_capped(path, cap, ...)`/`read_stdin_capped(cap, ...)` (myc.c)
baca BERTAHAP chunk 64 KiB dan menolak SEGERA saat `len+1 > cap` — buffer
raksasa tidak pernah dialokasikan. Cap: source `MYC_MAX_CODE_BYTES` 1 MiB,
`--run-stdin` konstanta baru `MYC_MAX_STDIN_BYTES` 8 MiB (myc.h). CLI
fail-fast exit 2 + pesan (`myc: <file>: ukuran melebihi cap N byte`) untuk
source file, source stdin (`-`), dan `--run-stdin`. API/MCP: cap
`run_stdin_len` di `myc_request_validate` → error baru
`MYC_ERR_STDIN_TOO_LARGE` (mapping report.c `stdin_too_large`); MCP
`run_stdin` sudah ter-cover + perlindungan lapis kedua `MCP_MAX_LINE` 8 MiB
yang menolak baris JSON raksasa (parse error). Receipt TIDAK berubah (cap
validasi bukan bagian hash) — `ok_run --run` tetap `8224c23a...`.
Verifikasi: source 1.05 MiB → exit 2, run-stdin 9 MiB → exit 2, stdin
source 1.05 MiB → exit 2, MCP payload 9 MiB → parse error (MCP_MAX_LINE);
regress Windows 0 [FAIL] (flaky transient "inject requires pure rusak"
muncul sekali dari race run-gate berturut, hilang pada run ulang),
self-dogfooding myc.c/mcp.c OK, receipt deterministik. Terpasang di
`_regress_run.bat` (section AUDIT-028, +6 cek via `fsutil` big-file) dan
`_ci_linux.sh` (section 5d, via `dd`/`mktemp`).

### MYC-AUDIT-029, 2026-08-04 (Fase 2: canonical ingress — `myc_source_input` formal struct)

`myc_request` kini memakai `myc_source_input input` (enum `myc_source_kind`:
MYC_SOURCE_MEMORY / FILE / STDIN) menggantikan field
`source`/`source_len`/`file_path` yang tersebar. **Loader terpusat
`myc_source_load()`** (myc.h + myc.c): satu titik cap + NUL policy + error
typed untuk semua kind — MEMORY = pointer asli tanpa alokasi; FILE =
`read_file_capped`; STDIN = `read_stdin_capped` (keduanya dipindah keluar
blok CLI agar ikut ter-link ke mcp.exe). **Pipeline HANYA menerima
in-memory** (`MYC_SOURCE_MEMORY`): blok jalur file_path lama di `myc_run`
(fopen/fseek/ftell, baca penuh, hanya cap-check sebelum malloc) DIHAPUS —
sekarang semua lewat loader, jadi jalur file_path API/MCP mendapat cap saat
membaca juga (bukan hanya CLI). CLI dan MCP memakai loader yang sama dengan
API (satu sumber kebenaran, tidak ada duplikasi logika baca). Dampak
pemakai: `compile.c` membaca `req->input.data/len`; test API
(audit_lampiran/oom_alloc/oom_guards/stress_threads) di-update. Test baru
T12/T13 di audit_lampiran: `myc_source_load` MEMORY → pointer asli tanpa
alokasi, FILE >1MiB → INPUT_TOO_LARGE, FILE tak ada → INVALID_PATH. Receipt
TIDAK berubah (source_sha sudah di-hash di compile gate) — `ok_run --run`
tetap `8224c23a...`. Verifikasi: Windows regress 0 [FAIL] (audit_lampiran
OK, T9 file_path-only tetap hijau, run-stdin L3, MCP smoke utuh), WSL
`_ci_linux.sh` PASS=32 FAIL=0. Roadmap Fase 2: size cap (AUDIT-028) +
myc_source_input (029) selesai; sisa `File path canonicalization` +
`string public pointer+length`.

### MYC-AUDIT-030, 2026-08-04 (Fase 2: File path canonicalization)

Helper static `myc_absolutize()` di `myc.c` — canonicalization **lexical**
(absolutize path relatif terhadap `my_getcwd` buffer 4096, normalisasi
`\`→`/` di Windows, resolve `.`/`..` dengan pop yang tidak melewati
root/drive, prefix drive `X:` + root `/` dipertahankan; **tanpa menyentuh
filesystem** sehingga cwd boleh tidak ada). `myc_run()` kini canonicalisasi
`req->cwd` di ingress ke salinan efektif `reqc` (tanpa memutasi request
caller), dipakai pipeline/quorum/enforce/capsule; `free(canon_cwd)` di
semua jalur keluar termasuk error path. NON-blocking: `my_getcwd` gagal
atau OOM → pakai nilai cwd asli. Ejaan cwd-ekuivalen (`tests`,
`tests\..\tests`, `.\tests`, `tests/../tests`) → cwd capsule canonical +
fingerprint IDENTIK (`7252ee12...`); direktori berbeda → berbeda
(`166dc682...`). **Bug nyata yang diperbaiki saat verifikasi**: (1) array
segmen diresize memakai counter `j` (0 untuk path absolut) → heap corruption
exit `0xC0000374`; diganti ukuran `strlen(work)+1` tetap tanpa grow; (2)
`realloc`-grow yang men-trigger `-Wuse-after-free` false positive →
pre-alokasi tetap. T14 di audit_lampiran (fingerprint identik antar ejaan +
berbeda antar direktori, macro `myc_getcwd`). Regresi `_regress_run.bat`
seksi AUDIT-030 membandingkan baris capsule `cwd:` (bukan JSON penuh yang
memuat `duration_ms`). Receipt TIDAK berubah (cwd canonical setara untuk
input tanpa `--cwd`) — `ok_run --run` tetap `8224c23a...`. Roadmap Fase 2:
canonicalization selesai; sisa `string public pointer+length` (efektif
terpenuhi AUDIT-029: source → `input.data/len`, run_stdin →
`run_stdin_len`; cwd/file_path adalah path OS yang NUL tak valid).

### MYC-AUDIT-014, 2026-08-02 (lint heuristik TIDAK hard lagi)

Seluruh rule lint.c (intptr_t/uintptr_t cast, realloc ke variabel lain,
memcpy/memset tanpa sizeof, ukuran alokasi perkalian tanpa sizeof, akses
langsung `b[i]` pada MYC_BUF) kini menghasilkan **observasi ber-confidence**
(`myc_confidence`: OBSERVATION/SUSPICIOUS/LIKELY/CONFIRMED) dan
**NON-blocking** — `myc_lint_source` mengembalikan jumlah observasi,
`MYC_ERR_LINT_VIOLATION` tidak lagi dipicu, verdict tidak pernah turun
karena lint. Gate baru **`MYC_GATE_LINT`** (completed_clean /
completed_observations) masuk evidence matrix + assurance vector (dimensi
COMPILE; observations benign — C1 tetap selama gcc -c bersih) + quorum
(observations = non-conflict) + capsule. `myc_diagnostic.confidence`
diisi di semua setter: CONFIRMED untuk bukti semantik (gcc/sanitizer/Eva/
Fil-C/checked), OBSERVATION/SUSPICIOUS untuk heuristik teks (lint,
negative, scanner, contract). Laporan teks menampilkan `[confidence]` pada
diagnostic heuristik + ringkasan `lint (14): N observasi`; JSON memuat
`"confidence"` per diagnostic + `"lint_observations"`. Tool MCP `lint`
ikut non-blocking (`lint: N observasi`). Hard violation HANYA dari bukti
semantik: `bad_realloc.c` → COMPILE_ERROR via gcc `-Werror=use-after-free`
(AST/dataflow), `bad_intptr.c` → OK + 2 observasi (cast eksplisit tidak
ditangkap kompiler — jujur). Regresi: section AUDIT-014 di
`test/_regress_run.bat` (+7 cek, quorum bad_intptr diperbarui ke clean).
Receipt berubah (gate baru masuk hash) → `ok_run --run` → `8224c23a...`
(deterministik). Catatan: semua golden receipt yang disebut entri audit
LAMA (`272d7531...` dll) adalah nilai SAAT ITU — sejak AUDIT-014 receipt
bergeser karena `MYC_GATE_LINT` selalu masuk hash; nilai berlaku sekarang
= yang tertera di entri ini.

### MYC-AUDIT-015, 2026-08-02 (portability `NUL`)

Target `-o` pada gate compile-only kini memakai device null PORTABEL —
helper `myc_null_device()` di `compile.c` ("NUL" di Windows, "/dev/null" di
POSIX; literal "NUL" di POSIX adalah file biasa, artefak repo lama).
Literal "NUL" pada daftar flags statis (MEMORY_GATE/ANALYZER_EXTRA/
CHECKED_EXTRA) diganti runtime di `merge_args` — satu titik perubahan,
daftar tetap statis. Opsi temporary-object yang dikelola & dihapus TIDAK
diambil (lebih kompleks tanpa manfaat untuk compile-only). Fingerprint/
receipt TIDAK berubah (target -o tidak masuk hash) — `ok_run --run` tetap
`272d7531...`. Verifikasi: ok_hello L1, bad_syntax COMPILE_ERROR, ok_checked
L4 (gate compile + checked bekerja dengan device null); self-dogfooding +
regress hijau.

### Dogfooding lintas-program tiga tool, 2026-08-02

`dogfood_ring.c` (ring buffer, MYC_BUF → L4), `dogfood_config.c` (parser
config key=value, idiom realloc aman ke member `cfg->items = tmp` +
copy_bounded), dan `dogfood_tilemap.c` (flood-fill BFS tile map 2D domain
game, stack eksplisit non-rekursif + indeks y*W+x berbatas). Ketiganya
lolos `myc check` OK/L1 + `--run` OK/L3, gcc -Wall -Wextra -Werror diam;
tilemap juga tervalidasi diam terhadap `-fanalyzer`. Terdaftar di
`test/_regress_run.bat`.

### P8 (D1.2) — checked-build makro, 2026-08-01

`myc_buf.h` dual-mode (produksi `MYC_BUF(T)` = `T*` polos;
`-DMYC_CHECKED=1` = fat-struct + `MYC_AT` cek batas). Gate `--checked`
membangun source 2×; akses langsung `b[i]` pada MYC_BUF = COMPILE_ERROR di
checked build → semua akses dipaksa via MYC_AT → **L4 SPATIAL**.
`--run --checked` memakai verification build fat-pointer di bawah ASan.
Non-blocking: source tanpa pola MYC_BUF → skip + diagnostic. Fixture:
`ok_checked.c` → L4; `bad_checked.c` → COMPILE_ERROR; `bad_checked_oob.c`
→ RUNTIME_VIOLATION. Dogfooding: `dogfood_ring.c` ditulis ulang memakai
MYC_BUF → L4.

### P8 (D4.1) — gate Fil-C, 2026-08-01

`--filc` → **L5 FILC** (label lama "L5 FULL" dihapus MYC-AUDIT-013 — run
Fil-C membuktikan eksekusi terkendali bersih, bukan "full"; backend
opsional). Deteksi filc-clang di PATH (native Linux) atau via
WSL (`command -v filc-clang` / `/opt/fil/bin/filc-clang`); verification
build + eksekusi terkendali. Marker panic Fil-C (`filc safety error` dll,
terkonfirmasi dari issue tracker) → verdict **FILC_VIOLATION**. Run
bersih → L5 FILC. Non-blocking: filc-clang tidak tersedia → skip +
diagnostic (assurance statis dipertahankan). Fixture: `ok_filc.c` → L5
FILC bila ada; `bad_filc_oob.c` → FILC_VIOLATION bila ada. Di sistem ini
Fil-C TIDAK terpasang → fixture masuk jalur `UNAVAILABLE` (gap terlihat:
verdict INCONCLUSIVE + debt `MYC-INCOMPLETE-GATE-UNAVAILABLE`, bukan OK
senyap — perbaikan AUDIT-004/010 via 9.10).

### Catatan bug P7 (dogfooding)

- lint.c hanya mengenali idiom realloc aman `buf = tmp`, TIDAK mengenali
  akses member `b->data = nd` → false VIOLATION pd kode sah. Diperbaiki:
  `read_arg_ident`/`ident_before` kini membaca rantai member (`->`/`.`).
- run.c: `myc_contract_inject` menulis `*out_len=0` pd return NULL sehingga
  `build_src_len` ter-clobber → clang menerima stdin kosong →
  `lld-link: subsystem must be defined` → semua fixture non-kontrak turun ke
  L1. Diperbaiki: panjang inject dipakai hanya bila non-NULL; contract.c
  tidak lagi menyentuh `*out_len` saat NULL.

### Perubahan perilaku fixture

`bad_system.c`, `bad_fopen.c`, `bad_include.c`, `bad_macro.c` kini **OK**
(hanya warning policy). Sejak MYC-AUDIT-014: `bad_intptr.c` → OK + 2
observasi lint (cast eksplisit lolos gcc), `bad_realloc.c` →
**COMPILE_ERROR** via gcc `-Werror=use-after-free` (bukti semantik).
Fixture P6: `ok_run.c` → L3; `bad_run_oob.c`/`bad_run_uaf.c`/
`bad_run_intovf.c` → RUNTIME_VIOLATION.

Fixture P8 (D1.2): `ok_checked.c` → L4 (SPATIAL); `bad_checked.c` →
COMPILE_ERROR (akses langsung pada MYC_BUF); `bad_checked_oob.c` →
RUNTIME_VIOLATION (`--run --checked`).

Fixture P8 (D4.1): `ok_filc.c` / `bad_filc_oob.c` → L5 / FILC_VIOLATION
bila Fil-C tersedia; `UNAVAILABLE` + debt (gap terlihat) bila tidak
(perbaikan 9.10/AUDIT-004).

### Trust Core Stabilization — Fase 1 partial, 2026-08-02

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
  parent memakai `kill(-pid, ...)` ke group baru. **Lengkap 2026-08-02**:
  parent juga panggil race-safe `setpgid(pid, pid)` segera setelah fork
  (menutup window kill(-pid) sebelum setpgid child dieksekusi);
  **enabler portability** — `_strdup` (MSVC/MinGW-only, dipakai 6 file)
  diganti `myc_strdup()` (implementasi di `proc.c` agar ter-link unit
  test yang hanya men-link proc.c) + `#define _POSIX_C_SOURCE 200809L`
  di proc.c sebelum include sistem (clock_gettime/setpgid di -std=c11);
  **test nyata** `test/verify_descendants.c` (sebelumnya orphan, tak
  pernah jalan) ditulis ulang: child fork grandchild (pid + marker
  `desc.survived` setelah 5 s) lalu tidur 120 s; myc timeout 1500 ms →
  group-kill harus mematikan grandchild; harness cek marker TIDAK ada.
  POSIX-only → `_audit018.sh` guard uname (MINGW/MSYS/CYGWIN = SKIP).
  Verifikasi: WSL Ubuntu 4/4 OK; negatif kontrol (kill(-pid) mati) →
  test GAGAL (grandchild selamat & menulis marker). Windows regress 97
  [OK] 0 [FAIL]; receipt golden `272d7531...` utuh.
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
- **MYC-AUDIT-006 partial** (`proc.c`): bounded output capture hanya
  prefix — sanitizer report di akhir output terpotong bila output >
  cap. Perbaikan (Fase 1 Task 1.5): `drain_buf` kini menyimpan
  bounded prefix + bounded tail (ring buffer N byte terakhir),
  `drain_feed()` shared helper, `drain_assemble()` menghasilkan
  C-string head+tail kontigu. Flag `truncated` hanya menyala bila
  byte tengah benar-benar dibuang (total > head_cap+tail_cap).
  Regresi: `test/tail_unit.c` (8 kasus, ALL PASS).
- **Fase 4 claim compiler + legacy assurance + streaming evidence** (2026-08-02):
  `myc_validate_claim()` di `gate.c` memvalidasi assurance label
  terhadap bukti gate; `claim_status` (VALID/OVERSTATED/UNVERIFIED)
  di `myc_result`; tampil di teks `claim:` dan JSON `"claim"`.
  Assurance label lama ditandai `[legacy]` di teks; JSON menyertakan
  `"assurance_legacy":true`. Streaming evidence detector di `proc.c`
  (`stream_sanitizer_match()`) mendeteksi marker sanitizer (ASan/UBSan/
  LeakSanitizer) pada output streaming — `sanitizer_detected` +
  `sanitizer_marker` di `myc_proc_result` dan `myc_result`.
- Dogfooding: self-check 15/15 source myc OK + 3/3 dogfood/ OK; semua
  regression test + `_regress_run.bat` pass setelah perbaikan.

### P9 — MCP server + soak + corpus abuse, 2026-08-02

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

### Fase 3 — typed-gate + evidence + unverified debt, 2026-08-02

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

### Semantic Canary, 2026-08-02 (gagasan pembeda 9.9, Fase 7.2)

Sebelum gate runtime menyatakan `COMPLETED_CLEAN` (L3 RUNTIME), myc
mengkompilasi + menjalankan canary kecil yang PASTI membuat out-of-bounds
(`myc_runtime_canary` di `run.c`). Bila canary TIDAK terdeteksi (gagal
dibangun / clean), backend ASan dianggap tidak layak dipercaya -> gate
di-turunkan ke INCONCLUSIVE (bukan COMPLETED_CLEAN) + diagnostic. Bila
terdeteksi, evidence `semantic canary terdeteksi: backend ASan sehat`
direkam di ledger. Non-blocking terhadap clang hilang (tetap UNAVAILABLE).
Dogfooding: `ok_run --run`, `dogfood_ring --run`, `--run --checked` tetap
L3/L4 (canary sehat). Regresi di `test/_regress_run.bat`.

### Evidence Receipt, 2026-08-02 (gagasan pembeda 9.1)

Laporan teks + JSON kini memuat `receipt_sha256` — hash deterministik
SHA-256 dari bukti terkumpul (`myc_build_receipt` di `gate.c`): version
receipt, verdict, completeness, tiap gate id+status, debt, fingerprint,
source_sha. Bukan klaim keamanan — melainkan sidik jari hasil agar
CI/auditor dapat membandingkan dua receipt tanpa membaca prose.
Deterministik (input sama → hash sama) dan berbeda antar verdict. Tidak
menambah backend. Dogfooding & self-check tetap OK. Regresi di
`test/_regress_run.bat`.

### Fase 5 — Reentrancy & Memory Ownership, 2026-08-02 (MYC-AUDIT-008)

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
  deterministik tetap (`ok_run --run` → `272d7531...`).

### Fase 6 — JSON & MCP ketat, 2026-08-02 (MYC-AUDIT-009)

Parser `json.c` kini menolak — leading zero, fraction/exponent tanpa digit,
lone high/low surrogate, embedded NUL (`\u0000`), dan raw UTF-8 invalid
(overlong/continuation/terpotong). Kapasitas dilindungi overflow guard di
`sb_reserve`/`json_obj_set`/`json_arr_push`. Regress + soak + MCP interop
(24 cek) tetap hijau. Verdict JSON tidak terpengaruh (parser hanya dipakai
MCP transport).

### Fase 4 — evidence matrix + finding_verdict, 2026-08-02

Sumbu A kini eksplisit — `myc_result.finding` (`myc_finding`: CLEAN /
FINDINGS / INCONCLUSIVE), dihitung murni dari typed gate status di `gate.c`
(`myc_gate_status`): prioritas FINDINGS > INCONCLUSIVE > CLEAN; hanya gate
diminta yang berpengaruh. Dua sumbu (finding + completeness) dipisah dari
verdict legacy (MC_OK/MC_VIOLATION) agar konsumen tak menebak makna.
Laporan teks + JSON memuat `finding:` dan `gate_matrix[]` (daftar id +
status tiap gate = evidence matrix konkret per scope); teks juga menampilkan
blok `evidence:` ringkas. Receipt deterministik tetap sama untuk input yang
sama (`ok_run --run` → `272d7531...`) karena finding diturunkan dari
status gate yang sudah di-hash. Semua regress + soak + corpus + interop
tetap hijau.

### Fase 4 — scope certificate, 2026-08-02

Laporan teks + JSON kini memuat blok `scope:` / `"scope"` = daftar persis
apa yang diperiksa (counts kontrak requires/ensures/total + driver
funcs/cases) sesuai 9.11. Prinsip kejujuran dijaga: hanya metrik yang
BENAR-BENAR diukur yang dimunculkan; kolom function/buffer yang tidak
diproduksi penganalisis token tidak dimunculkan, tidak mengarang angka.
Receipt tetap deterministik (`ok_run --run` → `272d7531...`): scope tidak
masuk ke hash.

### MYC-AUDIT-006, 2026-08-02 (assurance vector / evidence lattice, roadmap 5.7)

Scalar L1–L5 yang menggabungkan bukti orthogonal (compile / static /
runtime / checked / proof / driver / filc) kini dilengkapi **assurance
vector per dimensi** — `myc_assurance_vector` di `myc.h` (7 dimensi
C/S/R/B/P/D/F), dihitung murni dari typed gate status di
`myc_reduce_verdict()` (`myc_build_assurance_vector` di `gate.c`, prioritas
findings > inconclusive > clean > observations > n/a; `MYC_DIM_COUNT`
di-cover `default` agar lolos `-Werror=switch`). Laporan teks memuat baris
kompak `assurance_vector: C1 S0 R1 B0 P0 D0 F0` (0=n/a 1=clean 2=findings
3=inconclusive 4=observations) + legend; JSON memuat
`"assurance_vector":{"C":{"status":"clean"},...}`. Scalar L1–L5 tetap
sebagai legacy, label `[legacy: gunakan assurance_vector + evidence
matrix + finding/completeness]`. Receipt TIDAK berubah (vector turunan
dari gate status yang sudah di-hash). Fixture: `ok_run --run` → `C1 R1`,
`bad_run_oob --run` → `R2`, `ok_checked --checked` → `B1`, plain check →
`C1`; regresi section AUDIT-006 di `test/_regress_run.bat`.

---

## Fitur baru (2026-08-05)

### --json-summary mode

- Flag `--json-summary` pada `myc check` menghasilkan JSON ringkas untuk agent LLM.
- Field: verdict, assurance_vector, receipt_sha256, finding, completeness,
  error, exit_code, duration_ms, lint_observations, ran_* flags, diagnostics,
  gate_matrix, unverified_debt, quorum_status.
- Field yang dihilangkan: stdout_text, stderr_text, fingerprint, gcc_version,
  clang_version, capsule, evidence, dll.
- Default `--json` tetap penuh (backward compatible).

### MCP repair tool

- Tool MCP baru: `repair` — kembalikan patch minimal untuk finding compile
  tertentu (gcc warning).
- Input: `source` (wajib), `finding_code` (opsional).
- Output: JSON dengan `finding`, `applied_verdict`, `confidence`, `patch`,
  `structuredContent` (schema `myc.repair.v1`).
- Template patch untuk: gcc-use-after-free, gcc-free-nonheap-object,
  gcc-null-dereference, gcc-array-bounds, gcc-stringop-overflow.

### Lint why+fix

- Tool MCP `lint` kini menyertakan `why` dan `fix` di text output dan
  `structuredContent`.
- `why`: penjelasan mengapa pola tersebut berisiko.
- `fix`: saran perbaikan berbasis template (bukan AI-generated).
- Fungsi `myc_lint_why()` dan `myc_lint_fix()` di `lint.c` untuk digunakan
  oleh MCP tool dan potensi penggunaan lain.

---

## Fase -1 — Truth Freeze (2026-08-05)

Dokumentasi, baseline, dan kompatibilitas sebelum fitur baru.

- **AGENTS.md split**: aturan stabil di root, sejarah di `docs/audit-history.md`.
- **README cleanup**: hapus fitur yang belum diimplementasi.
- **capabilities.json**: registry MCP tools + CLI flags dengan test sinkronisasi.
- **Baseline benchmark**: 20 task, catat latency, binary size, payload.

---

## Fase 0 — Agent Evidence Protocol (2026-08-05)

Memberi LLM satu paket aksi yang dapat dipercaya.

Commits: `a625fbf..35b65e3` (6 commits).

- **P0-1**: `agent.h` + `agent.c` — `myc_agent_result` struct, build agent result,
  JSON serialization, `select_primary`, witness integration, `next_check`.
- **P0-2**: `report.c` — `myc_report_agent()` untuk `--agent` CLI output.
- **P0-3**: `mcp.c` — MCP tool `agent_check` (structuredContent schema `myc.agent.v2`).
- **P0-4**: `myc.c` — `--agent` CLI flag + `myc_request.agent` field.
- **P0-5**: Fixtures — `agent_ok.c`, `agent_bad.c`.
- **P0-6**: CI wiring — `capabilities.json` updated, `_cap_sync.sh`, `docs/mcp-tools.md`.

---

## Fase 1 — Witness Pipeline (2026-08-06)

Setiap hard finding dapat dipahami dan direplay model.

### Stage 1: Witness struct + isi witness (`64a70d0`)

- **1.1**: `myc_witness` struct di `myc.h` — source, stdin, argv, slice, violation
  kind/msg/line/col, backend.
- **1.2**: Witness dari GCC diagnostics — `ingest_gcc_diagnostics()` di `compile.c`
  mengisi witness via `repair_find_code()`.
- **1.3**: Witness dari sanitizer — `run.c` memetakan ASan/UBSan markers ke
  violation kinds.
- **1.4**: Witness dari Eva/Fil-C/driver — `prove.c`, `filc.c`, `driver.c`.
- `myc_witness_init/free` di `myc.c`; `myc_result_free` diupdate untuk free witness.

### Stage 2: Repro + Minimizer + Slice (`9aeb287`)

- **1.5**: `witness.c` — `myc_witness_write_repro()` menulis `.myc-witness/<kind>/`
  (source.c, stdin.bin, witness.json, replay.sh, replay.bat).
- **1.6**: `myc_witness_minimize_input()` — line-by-line removal skeleton.
- **1.7**: `myc_witness_build_slice()` + `myc_witness_extract_function()`.
- `witness.c` ditambahkan ke PIPELINE di build.sh/build.bat.

### Stage 3: Serialization + Downgrade + Agent wiring (`6bbec72`)

- **1.8**: `gate.c` — `myc_reduce_verdict()` downgrades hard→observation
  bila `!res->witness` (MYC-AUDIT-014: tanpa bukti replayable, finding
  tidak dianggap keras).
- **1.9**: `agent.c` — witness diintegrasikan ke agent output; bila
  `res->witness` ada, gunakan itu; fallback ke capsule.
- **1.10**: Fixtures — `witness_uaf.c`, `witness_oob.c`, `witness_clean.c`.
- **report.c**: serialisasi witness ke JSON (violation, backend, slice, argv).

### Sisa Fase 1

- [ ] `pre-state → operation → violation` — tambah field `pre_state` dan
  `operation` ke witness struct agar LLM memahami kronologi pelanggaran.
- [ ] Replay test lintas Windows/Linux — verifikasi `.myc-witness/` replay
  konsisten.

---

> Terakhir diperbarui: 2026-08-06 (Fase 1 Stage 3 selesai). Isi kronologis
> di atas tidak diubah/dihilangkan — dipindahkan verbatim dari AGENTS.md lama.
