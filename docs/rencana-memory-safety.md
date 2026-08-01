# Rencana: myc sebagai Penjamin Memory-Safety C

Status: **disetujui 2026-08-01** (arah & fase pertama). Ini dokumen hidup; update
bila keputusan berubah. **Fase A (P4+P5) SELESAI 2026-08-01. P6 SELESAI 2026-08-01.**

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
L2 PROVEN    Frama-C Eva (sound utk RTE) pd fungsi @prove
L3 RUNTIME   verification build + eksekusi dgn ASan+UBSan+MSan+Leak
L4 SPATIAL   transformasi fat-pointer/SoftBound-style (tanpa eksekusi semua jalur)
L5 FULL      (opsional, bila platform tersedia) Fil-C / CheriABI
```

Verdict output: `assurance: L2 (PROVEN)` + daftar sisa risiko yang tak dibuktikan.

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
├─ frama-c -eva (hanya @prove)                         → L2 (sound)
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
| **P6** | D2.1 sanitizer build + D2.2 driver generator + eksekusi terkendali (run) | L3 RUNTIME |
| **P7** | D1.5 contract-lite + D3.1 Frama-C Eva integrasi | L2 PROVEN sound |
| **P8** | D1.2 checked-build makro + D4.1 deteksi Fil-C | L4 SPATIAL, L5 FULL (ops) |
| **P9** | MCP server + soak + corpus abuse | integrasi agent |

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
- myc.h: enum `myc_assurance { NONE, L0_RAW, L1_SANE, L2_PROVEN, L3_RUNTIME,
  L4_SPATIAL, L5_FULL }` di myc_result.
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
