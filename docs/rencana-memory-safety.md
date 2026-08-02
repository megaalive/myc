# Rencana: myc sebagai Penjamin Memory-Safety C

Status: **disetujui 2026-08-01** (arah & fase pertama). Ini dokumen hidup; update
bila keputusan berubah. **Fase A (P4+P5) SELESAI 2026-08-01. P6 SELESAI 2026-08-01.
P7 SELESAI 2026-08-01 (D1.5 contract-lite + D3.1 Frama-C Eva → L2 EVA).
P8 SELESAI 2026-08-01 (D1.2 checked-build makro → L4 SPATIAL + D4.1
gate Fil-C → L5 FILC opsional). P9 SELESAI 2026-08-02 (MCP server +
soak + corpus abuse → integrasi agent). D2.2 driver-generator SELESAI
2026-08-02 (gate --driver → L3 RUNTIME / DRIVER_VIOLATION) + tool MCP
contracts & lint + client MCP contoh (mcp_client.py).**

## Keputusan arah (2026-08-01)

- Tujuan myc: **memory-safety & minim bug** — BUKAN pembatasan library.
- User memakai banyak harness/model; domain beragam (hardware, game, web) →
  whitelist header hanyalah *default konservatif*, bukan larangan mutlak.
- **Overhead produksi = 0.** Fil-C / CheriABI (yang membebani runtime produksi)
  **di luar scope utama**. Fokus: static analysis + verification-run sanitizer.
- Fase pertama: **A — perluas statis gcc (P4 + P5)** — selesai.
- **Keputusan tambahan saat implementasi Fase A**: policy (header & denylist
  fungsi) dijadikan **non-blocking warning** (bukan VIOLATION). Gate hard hanya
  lint memory-safety + gate gcc.

## Bagian A — Landasan

### A.1 Taksonomi bug memori di C (target yang harus ditutup)

| Kelas | Contoh |
|---|---|
| Spasial | buffer overflow/underflow, intra-object overrun |
| Temporal | use-after-free, double-free, dangling stack pointer |
| Uninitialized | baca memori belum diinisialisasi |
| Leak / lifetime | memory leak, pointer melampaui scope |
| Integer | overflow/underflow → indeks array tak terduga |
| Aliasing / provenance | pointer palsu via intptr_t/cast, realloc invalidasi |
| Concurrency | race pada pointer non-atomic |

### A.2 Prinsip desain

1. Defense in depth — stack beberapa lapis, bukan satu solusi.
2. Verdict jujur (assurance level), bukan hitam-putih PASS/FAIL.
3. Verification build ≠ production build — instrumentasi hanya di verifikasi.
4. Domain-agnostic, library-agnostic.
5. Cocok untuk kode yang ditulis model (boleh menuntut pola/konvensi).

## Bagian B — Peta solusi yang ada (hasil riset 2026-08-01)

| Pendekatan | Perwakilan | Overhead | Kekuatan | Kelemahan utk kita |
|---|---|---|---|---|
| Sanitizer runtime | ASan, MSan, UBSan | 1.5–3× (verification run) | Cepat, nyata, matang | Butuh eksekusi; hanya jalur dieksekusi |
| Fat/metadata pointer | SoftBound, CCured, Cyclone | 22–67% | Sound spasial+temporal | ABI berubah; false positive dgn intptr_t |
| Shadow bounds | Low-Fat, Baggy Bounds | 20–60% mem | Cepat | Lemah utk pointer luar region |
| Arch capability | CHERI/CheriABI, MPX | 0–20% HW | Jaminan HW, provenance asli | Butuh hardware/OS khusus |
| Anotasi tipe | Checked C | rendah | Incremental, kompatibel | Fork clang; model harus belajar anotasi |
| Bahasa baru | Zig, ATS, Rust | — | Jaminan di type system | Bukan C; user tetap mau C |
| Implementasi C aman | Fil-C (InvisiCaps+GC) | "beberapa ×" | Menutup SEMUA kelas | Overhead produksi; ABI beda — di luar scope |
| Formal verification | Frama-C (Eva sound RTE; WP correctness) | 0 runtime (static) | Sound | Lambat saat analisis; butuh anotasi |
| GC C | Boehm, Fil-C FUGC | ~ | Temporal via GC | Kurang deterministik |

Insight: tidak ada yang menutup semua kelas tanpa trade-off. Myc menggabungkan
dan memberi label jaminan yang jujur.

## Bagian C — Assurance Ladder

Setiap berkas mendapat level jaminan (0–5). Verdict = level tertinggi yang
DIBUKTIKAN, bukan asumsi.

```
L0 RAW       hanya compile check
L1 SANE      gcc -Wall -Wextra -Werror -pedantic + implicit-decl + -fanalyzer
L2 EVA       Frama-C Eva: 0 alarm RTE di bawah model (abstract interpretation,
             BUKAN proof obligation WP; label lama "PROVEN" dihapus MYC-AUDIT-013)
L3 RUNTIME   verification build + eksekusi dgn ASan+UBSan+MSan+Leak
L4 SPATIAL   transformasi fat-pointer/SoftBound-style (tanpa eksekusi semua jalur)
L5 FILC      (opsional) eksekusi Fil-C bersih (label lama "FULL" dihapus)
```

Verdict output: `assurance: L2 (EVA)` + daftar sisa risiko yang tak dibuktikan.

## Bagian D — Paket teknik

### D1. Statis & struktural (tanpa eksekusi)
- D1.1 `-fanalyzer` maksimal + warning set memori (semua `-Werror`).
- D1.2 Macro-typing "checked build": typedef/makro (MYC_BUF) → fat-struct di
  verifikasi, T* di produksi. Source sama dibangun 2×. Tanpa fork bahasa.
- D1.3 Bounds provenance lint: scanner AST/level-token yang melacak asal pointer;
  menolak intptr_t roundtrip, cast lintas alokasi, realloc invalidasi.
- D1.4 Integer data-flow: melacak variabel indeks vs ukuran malloc/sizeof.
- D1.5 Contract-lite auto (ACSL minimal): `//@ requires/ensures` 1-baris →
  anotasi Frama-C + assert() runtime.
- D1.6 Region/arena transform: tulis ulang malloc/free → arena scoped (anti-UAF
  & anti-leak struktural). Siklus → Boehm per-region.

### D2. Dinamis (verification build + eksekusi terkendali)
- D2.1 Sanitizer suite: -fsanitize=address,undefined,leak (+ MSan bila ada).
- D2.2 Test-driver generator: dari signature + contract-lite, generate harness
  pemanggil dgn input acak/edge, jalan di bawah sanitizer.
- D2.3 Fuzz-instrumented (opsional): libFuzzer/AFL++ utk fungsi @fuzz.

### D3. Formal (sound, tanpa eksekusi)
- D3.1 Frama-C Eva on demand (`@prove`); alarm = bug pasti (kelas RTE).
- D3.2 Frama-C WP (opsional lanjut): correctness fungsional.
- D3.3 E-ACSL RAC: cek anotasi runtime di build verifikasi.

### D4. Toolchain (jaminan tertinggi, opsional per platform)
- D4.1 Deteksi & integrasi Fil-C bila tersedia (laporan panic sebagai diagnosa).
- D4.2 CHERI/CheriABI bila hardware/emulasi tersedia.
- (Catatan: keduanya di luar scope utama karena overhead produksi; integrasi
  hanya sebagai backend opsional.)

## Bagian E — Arsitektur yang dituju

```
myc check foo.c --level L3 --prove bar baz --fuzz qux
├─ L1 policy scan (whitelist "default", override per proyek)
│      + bounds provenance lint (D1.3) + integer data-flow (D1.4)
├─ gcc -E
├─ gcc -Wall -Wextra -Werror ... -fanalyzer            → L1
├─ frama-c -eva (hanya @prove)                         → L2 EVA (0 alarm RTE)
├─ build verifikasi + sanitizer + driver (D2)          → L3
├─ (opsional) fat-pointer transform                    → L4
├─ (opsional) filc-clang / cheriabi                    → L5
└─ laporan: assurance level, sisa risiko, alarm
```

Konfigurasi per proyek (`myc.toml`): domain, library, @prove set, ambang
assurance wajib, backend L5 tersedia.

## Bagian F — Roadmap bertahap

| Fase | Isi | Keluar |
|---|---|---|
| **P4** | Perluas gcc flags memori (Werror set + -fanalyzer), pisahkan --level | L1 SANE penuh |
| **P5** | D1.3 bounds provenance lint + D1.4 integer data-flow | alarm presisi spasial/int |
| **P6** | D2.1 sanitizer build + eksekusi terkendali (run) | L3 RUNTIME — **D2.2 driver generator SELESAI 2026-08-02** |
| **P7** | D1.5 contract-lite + D3.1 Frama-C Eva integrasi | L2 EVA (0 alarm RTE) — **SELESAI 2026-08-01** |
| **P8** | D1.2 checked-build makro + D4.1 gate Fil-C — **SELESAI 2026-08-01** | L4 SPATIAL, L5 FILC (ops) |
| **P9** | MCP server + soak + corpus abuse — **SELESAI 2026-08-02** | integrasi agent |

Setiap fase = dogfooding (aturan AGENTS.md): alat ditulis C murni & diperiksa
myc; fitur baru diekspos lewat tool lain yang realistis.

---

# Rencana Eksekusi — Fase A (P4 + P5) [SELESAI 2026-08-01]

## P4 — Perluas verifikasi statis gcc + perkenalkan --level [DONE]

### 4.1 Flags gcc baru (di compile.c)
Tier dasar (default, nol false-positive pd kode sah):
```
-Warray-bounds -Wstringop-overflow -Wuse-after-free -Wfree-nonheap-object
-Wformat-overflow -Wformat-truncation
```
Semua `-Werror`.

> **Catatan implementasi**: gate memori memakai `-c -O2` (bukan
> `-fsyntax-only`) karena `-Warray-bounds`/`-Wstringop-overflow` hanya aktif
> saat kompilasi beroptimisasi (GIMPLE pass).

Tier ketat (`--strict`, opsional, BISING — bukan default):
```
-Wconversion -Wsign-conversion -Wint-conversion
```
Keputusan: tidak default agar tidak memblokir program sah (filosofi: jaminan,
bukan pembatas).

### 4.2 Label jaminan di verdict [DONE]
- myc.h: enum `myc_assurance { NONE, L0_RAW, L1_SANE, L2_EVA, L3_RUNTIME,
  L4_SPATIAL, L5_FILC }` di myc_result.
- report.c: output teks + JSON tampilkan `assurance` (OK → `L1 (SANE)`).
- `--strict` / `--level strict` menyalakan tier ketat.

### 4.3 Refactor kecil [DONE]
- Pindahkan string flags gcc dari hardcode compile.c ke tabel terpusat
  (MEMORY_WARNINGS, STRICT_WARNINGS, SYNTAX_BASE, ANALYZER_EXTRA + merge_args).
- Fixture baru: `ok_bounds.c` (loop index aman → OK) dan `bad_oob.c`
  (index overflow statis → COMPILE_ERROR) — bukti tier dasar tidak bising.

Keluar P4: myc melaporkan assurance L1, warning memori fatal, fixture lolos.

## P5 — Bounds provenance lint + integer data-flow (terbatas) [DONE]

### 5.1 Bounds provenance lint (scanner.c + file baru lint.c) [DONE]
Deteksi pola berisiko tingkat token (feasible tanpa AST):
- intptr_t/uintptr_t roundtrip, cast (intptr_t)/(uintptr_t) → VIOLATION lint.
- realloc hasil disimpan ke variabel yg masih memakai pointer lama → VIOLATION.
  (Idiom aman `tmp = realloc(buf,...); ...; buf = tmp;` dikenali via
  reassign_after → tidak di-flag.)
- memcpy/memmove/memset tanpa ukuran tetap/eksplisit dari sizeof → warning.

### 5.2 Integer data-flow (terbatas) [DONE]
- Scanner catat malloc(n)/calloc(n) dengan perkalian tanpa sizeof →
  warning potensi integer overflow. (Data-flow loop index penuh dipertahankan
  ke fase berikut; gate gcc -O2 menangkap sebagian besar.)

### 5.3 Batas jujur [DONE]
Tanpa AST/CFG ini heuristik, BUKAN sound. Diposisikan sebagai early warning
(bukan penalti penuh) agar tidak memblokir program sah. Versi sound = Frama-C Eva
di fase berikutnya (P7).

### 5.4 Fixture dogfooding [DONE]
- ok_lint.c (clean) → OK.
- bad_intptr.c (cast intptr_t→*) → VIOLATION lint.
- bad_realloc.c → VIOLATION lint.
- Ini dogfooding lintas-program sesuai AGENTS.md.

### 5.5 Dogfooding (hasil nyata, 2026-08-01)
- Self-dogfooding: 9 source myc dicek myc → **semua OK**.
- Bug nyata DITEMUKAN dogfooding: out-of-bounds read di compile.c — `prelen`
  memakai `total_stdout_bytes` (output gcc penuh, bisa >1MB) padahal buffer
  hanya `shown_stdout_bytes`. Diperbaiki.
- Tool lintas-program: `dogfood/dogfood_ring.c` (ring buffer in-memory) → OK
  + OK dengan `--analyze`.

Keluar P5: myc menangkap pola UAF/provenance/int obvious di luar gcc, false
positive terkontrol.

# Rencana Eksekusi — P8 D4.1 (gate Fil-C → L5 FILC, opsional backend) [DONE 2026-08-01]

## 9.1 Deteksi & integrasi [DONE]

- `--filc`: cari driver `filc-clang` di PATH (native Linux) atau di dalam
  WSL (`command -v filc-clang` / `/opt/fil/bin/filc-clang`). Fil-C hanya
  Linux/X86_64 (konfirmasi README resmi). Di Windows → WSL (pola prove.c).
- Verification build `filc-clang -O0 -g` (source via stdin, template WSL
  tetap) + eksekusi terkendali via proc.c.

## 9.2 Verdict & assurance [DONE]

- Marker panic Fil-C (`filc safety error` — terkonfirmasi dari issue
  tracker; plus `Fatal runtime error`, `panicked`, `double free`) pada
  stdout/stderr → **MC_FILC_VIOLATION** (bug memori terbukti).
- Run bersih (exit 0, tanpa marker) → caller naikkan ke **L5 FILC**.
- Non-blocking (arah): filc-clang tidak tersedia (PATH/WSL) → skip,
  assurance statis dipertahankan + diagnostic. Build/run gagal tanpa
  marker panic → skip (bukan bukti bug).

## 9.3 Fixture [DONE]

- `ok_filc.c` → L5 (bila Fil-C tersedia); skip bila tidak.
- `bad_filc_oob.c` (OOB via argc opaque) → FILC_VIOLATION bila ada;
  skip bila tidak. Di sistem ini Fil-C tidak terpasang → jalur skip
  diverifikasi (non-blocking bekerja).

# Rencana Eksekusi — P8 D1.2 (checked-build makro → L4 SPATIAL) [DONE 2026-08-01]

## 8.1 myc_buf.h dual-mode [DONE]

- Header `myc_buf.h` di root proyek (dikirim bersama myc.exe).
- Mode produksi (tanpa `-DMYC_CHECKED`): `MYC_BUF(T)` = `T*` polos,
  `MYC_NEW` = calloc, `MYC_AT` = index biasa, `MYC_FREE` = free. Overhead 0.
- Mode checked (`-DMYC_CHECKED=1`): `MYC_BUF(T)` = fat-struct `myc_fat`
  (`void *data; size_t cap`); `MYC_AT` memanggil `myc_buf_at` yang abort
  (dengan marker `MYC_CHECKED:`) saat indeks ≥ cap atau data NULL.

## 8.2 Gate --checked (compile.c) [DONE]

- `myc check <file> --checked`: setelah gate gcc statis, source dibangun
  ulang dengan `-DMYC_CHECKED=1 -include myc_buf.h` (+ `-I<dir myc.exe>`).
- Akses langsung `b[i]` pada variabel MYC_BUF → fat-struct tak bisa
  di-index → COMPILE_ERROR. Inilah mekanisme L4: disiplin dipaksakan oleh
  tipe, bukan heuristik.
- Build checked lolos → verdict OK + assurance **L4 SPATIAL** untuk buffer
  MYC_BUF (jujur: buffer di luar MYC_BUF tetap L1/ASan).
- Non-blocking: source tanpa pola MYC_BUF → skip + diagnostic (assurance
  statis dipertahankan).

## 8.3 Integrasi --run [DONE]

- `--run --checked`: verification build clang diberi `-DMYC_CHECKED=1 -I`
  → runtime fat-pointer ikut di-sanitize (ASan+UBSan). Marker `MYC_CHECKED:`
  ditambahkan ke deteksi sanitizer → pelanggaran batas = RUNTIME_VIOLATION.
- L4 > L3: bila checked build lolos dan run bersih, assurance tetap L4.

## 8.4 Fixture & dogfooding [DONE]

- `ok_checked.c` → L4; `bad_checked.c` → COMPILE_ERROR; `bad_checked_oob.c`
  → RUNTIME_VIOLATION.
- `dogfood/dogfood_ring.c` ditulis ulang memakai MYC_BUF → L4 + L4-runtime.
- Lint D1.2: lint.c mencatat variabel MYC_BUF dan memberi warning saat
  diakses langsung `b[i]` (non-blocking, diagnosis lebih awal).

# Rencana Eksekusi — P6 (D2.1 sanitizer build + eksekusi terkendali) [DONE 2026-08-01]

## 6.1 Backend sanitizer (clang ASan+UBSan) [DONE]

- clang 22.1.6 di `D:\LLVM\bin\clang.exe` (target x86_64-pc-windows-msvc)
  mendukung `-fsanitize=address,undefined`. gcc MinGW 15.2 TIDAK punya
  libasan/libubsan.
- `-fsanitize=leak` dan `-fsanitize=memory` TIDAK didukung target Windows
  clang → L3 di Windows = ASan+UBSan (tanpa LSan/MSan).
- **`-O0` WAJIB**: di `-O1`/`-O2` clang mengeliminasi dead-store sehingga ASan
  luput dari OOB yang tidak dibaca (dead-store elimination). Resep final:
  `clang -x c - -std=c11 -O0 -g -fsanitize=address,undefined
  -fno-sanitize-recover=all -o <exe>` (source via stdin).
- Runtime DLL Windows: `clang -print-file-name=clang_rt.asan_dynamic-x86_64.dll`
  → disalin ke samping exe hasil build; tanpa itu exe gagal run 0xC0000135.

## 6.2 Gate verification run (run.c) [DONE]

- `myc check <file> --run [--run-stdin FILE]`:
  1. Cari clang (PATH / req->clang_program).
  2. Buat direktori temp unik (`%TEMP%/myc_run_<pid>_<n>`).
  3. Verification build (source via stdin, tidak pernah jadi argumen).
  4. Windows: salin ASan DLL ke samping exe.
  5. Eksekusi via `myc_proc_run` (Job Object + timeout; kill pohon proses).
  6. Deteksi marker sanitizer (ASan/UBSan) pada stdout+stderr.
- Verdict: run bersih (exit 0, tanpa marker) → `MC_OK` + **assurance L3
  (RUNTIME)**. Marker sanitizer → `MC_RUNTIME_VIOLATION` + err
  `runtime_violation`. Timeout → `MC_TIMEOUT`. Build verifikasi gagal (mis.
  tanpa `main`) / clang hilang → gate di-skip, assurance statis dipertahankan
  (non-blocking, sesuai arah).
- run.c/beserta 9 source myc lain lolos self-dogfooding (OK).

## 6.3 Fixture P6 [DONE]

- `ok_run.c` (hello heap) → OK + L3 RUNTIME.
- `bad_run_oob.c` (heap-buffer-overflow, `memset` 16 ke malloc 8) → RUNTIME_VIOLATION.
- `bad_run_uaf.c` (use-after-free lintas fungsi `noinline` — lolos gate statis
  gcc, hanya tertangkap ASan) → RUNTIME_VIOLATION.
- `bad_run_intovf.c` (signed integer overflow) → RUNTIME_VIOLATION (UBSan).
- `dogfood_ring.c` → OK + L3 RUNTIME.
- Catatan: `bad_run_uaf` varian non-noinline tertangkap gate statis gcc
  (`-Werror=use-after-free`) — defense-in-depth bekerja seperti seharusnya.

Keluar P6: assurance L3 RUNTIME tercapai; sanitizer menangkap OOB/UAF/int-overflow
yang lolos statis; timeout membunuh pohon proses tanpa sisa.

## Catatan keputusan yang disetujui
1. Tier -Wconversion tidak default (agar tidak memblokir kode sah).
2. Hasil P5 = heuristik, di-flag warning/lint (bukan VIOLATION) bila perlu.
3. Test lint pakai fixture C murni di tests/.
4. **Policy (header & denylist fungsi) = non-blocking warning** (keputusan saat
   implementasi Fase A): header bebas, denylist hanya warning.
5. **--run = opsional, non-blocking** (keputusan P6): bila clang tidak tersedia
   atau build verifikasi gagal (mis. kode bukan program executable tanpa main),
   myc tetap memberi verdict statis (L1) dan menulis diagnostic; tidak menahan.
6. **L3 di Windows = ASan+UBSan** (LSan/MSan tidak didukung target MSVC).
