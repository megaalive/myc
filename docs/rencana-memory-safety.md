# Rencana: myc sebagai Penjamin Memory-Safety C

Status: **disetujui 2026-08-01** (arah & fase pertama). Ini dokumen hidup; update
bila keputusan berubah.

## Keputusan arah (2026-08-01)

- Tujuan myc: **memory-safety & minim bug** — BUKAN pembatasan library.
- User memakai banyak harness/model; domain beragam (hardware, game, web) →
  whitelist header hanyalah *default konservatif*, bukan larangan mutlak.
- **Overhead produksi = 0.** Fil-C / CheriABI (yang membebani runtime produksi)
  **di luar scope utama**. Fokus: static analysis + verification-run sanitizer.
- Fase pertama: **A — perluas statis gcc (P4 + P5)**.

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

# Rencana Eksekusi — Fase A (P4 + P5) [DISETUJUI]

## P4 — Perluas verifikasi statis gcc + perkenalkan --level

### 4.1 Flags gcc baru (di compile.c)
Tier dasar (default, nol false-positive pd kode sah):
```
-Warray-bounds -Wstringop-overflow -Wuse-after-free -Wfree-nonheap-object
-Wformat-overflow -Wformat-truncation
```
Semua `-Werror`.

Tier ketat (`--strict`, opsional, BISING — bukan default):
```
-Wconversion -Wsign-conversion -Wint-conversion
```
Keputusan: tidak default agar tidak memblokir program sah (filosofi: jaminan,
bukan pembatas).

### 4.2 Label jaminan di verdict
- myc.h: enum `myc_assurance { NONE, L1_SANE, ... }` di myc_result.
- report.c: output teks + JSON tampilkan `assurance: L1 SANE` + sisa risiko.
- --level default L1; --level strict menyalakan tier ketat.

### 4.3 Refactor kecil
- Pindahkan string flags gcc dari hardcode compile.c ke tabel terpusat.
- Fixture baru: `ok_bounds.c` (loop index aman → OK) dan `bad_oob.c`
  (index overflow statis → COMPILE_ERROR) — bukti tier dasar tidak bising.

Keluar P4: myc melaporkan assurance L1, warning memori fatal, fixture lolos.

## P5 — Bounds provenance lint + integer data-flow (terbatas)

### 5.1 Bounds provenance lint (scanner.c + file baru lint.c)
Deteksi pola berisiko tingkat token (feasible tanpa AST):
- intptr_t/uintptr_t roundtrip, cast (intptr_t)/(uintptr_t) → VIOLATION lint.
- realloc hasil disimpan ke variabel yg masih memakai pointer lama → VIOLATION.
- memcpy/memmove/memset tanpa ukuran tetap/eksplisit dari sizeof → warning.

### 5.2 Integer data-flow (terbatas)
- Scanner catat malloc(n)/calloc(n) → kapasitas.
- Loop for(i=0; i<K; ...) dgn a[i] — bila K bisa melebihi kapasitas diketahui
  dan gcc tak menjangkaunya → diagnostic.

### 5.3 Batas jujur
Tanpa AST/CFG ini heuristik, BUKAN sound. Diposisikan sebagai early warning
(bukan penalti penuh) agar tidak memblokir program sah. Versi sound = Frama-C Eva
di fase berikutnya (P7).

### 5.4 Fixture dogfooding
- ok_lint.c (clean) → OK.
- bad_intptr.c (cast intptr_t→*) → VIOLATION lint.
- bad_realloc.c → VIOLATION lint.
- Ini dogfooding lintas-program sesuai AGENTS.md.

Keluar P5: myc menangkap pola UAF/provenance/int obvious di luar gcc, false
positive terkontrol.

## Catatan keputusan yang disetujui
1. Tier -Wconversion tidak default (agar tidak memblokir kode sah).
2. Hasil P5 = heuristik, di-flag warning/lint (bukan VIOLATION) bila perlu.
3. Test lint pakai fixture C murni di tests/.
