# Backend qualification policy (P5-T01 / PR-017)

Kebijakan resmi dukungan backend myc. Registry hidup (path + versi exact
per mesin) tersedia via `myc backends`; kualifikasi canary per backend via
`myc backends --canary` (dan `myc canary run` untuk seluruh swarm).

Kebijakan ini menentukan kapan ketiadaan/kerusakan backend menjadi
**release-blocking** (Tier A), **debt non-blocking** (Tier B), atau
**observasi best-effort** (Tier C). Ini adalah batas dukungan yang
DIDEKLARASIKAN — keberadaan biner di PATH tidak menjadikan backend
"didukung" bila di luar tabel di bawah.

## Tier

| Tier | Makna | Kegagalan backend |
|---|---|---|
| **A** | Release-blocking. Diuji CI Windows + Linux. Harus tersedia agar klaim assurance penuh. | Unavailability / kerusakan = INCONCLUSIVE + debt (dengan `--require-complete` = CI gagal) |
| **B** | Supported non-blocking. Kehadiran meningkatkan assurance; ketiadaan = debt jujur, bukan FAIL. | Unavailability = UNAVAILABLE + debt; verdict TIDAK turun |
| **C** | Best-effort / eksperimental. Observasi saja; tidak pernah menjadi hard evidence. | Selalu observasi; tidak pernah mempengaruhi verdict |

## Registry backend

| Backend | Executable | Tier | OS | Versi minimum | Evidence yang diekstrak | Failure semantics |
|---|---|---|---|---|---|---|
| `compile` | `gcc` | A | Windows, Linux | gcc 9+ | Diagnostic GCC JSON ter-struktur (`-Werror` + memory tier) | compile error = COMPILE_ERROR; gcc hilang = INCONCLUSIVE + debt |
| `analyzer` | `gcc` | A | Windows, Linux | gcc 10+ (`-fanalyzer`) | Finding `-fanalyzer` interprocedural | finding = COMPILE_ERROR; gcc tanpa fanalyzer = di-skip + debt |
| `run` | `clang` | A | Windows, Linux | clang 11+ (ASan/UBSan) | Report sanitizer non-spoofable (`log_path`) | sanitizer finding = RUNTIME_VIOLATION; clang hilang = UNAVAILABLE + debt |
| `driver` | `gcc` | A | Windows, Linux | — | Harness kasus tepi dari kontrak (case records) | edge violation = DRIVER_VIOLATION |
| `exhaustive` | `gcc` | A | Windows, Linux | — | Counterexample / proof P1 EXHAUSTIVE per domain deklarasi | counterexample = DRIVER_VIOLATION |
| `fuzz` | `gcc` | A | Windows, Linux | — | Crash reproduksibel dalam domain kontrak | crash = DRIVER_VIOLATION |
| `mutate` | `gcc` | B | Windows, Linux | — | Mutation coverage gap (audit verifier) | gap = observasi NON-blocking |
| `stack` | `gcc` | B | Windows, Linux | — | Stack budget + call graph worst-path | cycle/rekursi = observasi NON-blocking |
| `lint` | *(internal)* | A | — | — | Heuristik memory-safety ber-confidence | SELALU observasi, verdict tidak pernah berubah |
| `checked` | *(internal)* | B | — | — | MYC_BUF fat-pointer (L4 SPATIAL) | gap disiplin = debt jujur (RAW-BUFFERS) |
| `prove` | `frama-c` | B | Linux (native), Windows (via WSL) | frama-c 28+ | Alarm Eva RTE (L2 EVA) | alarm = PROVE_VIOLATION; frama-c hilang = UNAVAILABLE + debt |
| `filc` | `filc-clang` | B | Linux (native), Windows (via WSL) | — | Fil-C panics (L5) | panic = FILC_VIOLATION; filc-clang hilang = UNAVAILABLE + debt |
| `matrix` | `arm-none-eabi-gcc`, `riscv64-unknown-elf-gcc` | B | Windows, Linux (cross-compile host) | — | Macro dump + warning set per target | target hilang = sel di-skip jujur ("targets not tested") |

## Aturan kebijakan

1. **Tier A = tidak boleh senyap.** Bila gate Tier A diminta dan backend
   tidak tersedia/rusak, hasil = INCONCLUSIVE + debt (INV-001), bukan OK.
   Dengan `--require-complete`, CI gagal (MYC-INCOMPLETE-*).
2. **Tier B = ketiadaan jujur.** Gate Tier B yang diminta tanpa backend
   menampilkan UNAVAILABLE + debt; verdict TIDAK turun dari apa yang
   backend lain buktikan (INV-002: bug mendominasi incompleteness).
3. **Tier C = observasi.** Tidak pernah menjadi hard evidence (INV-003).
4. **Identitas backend adalah evidence (INV-013).** Hasil bersih dari satu
   versi compiler tidak setara versi lain. `myc backends` menampilkan path
   + versi exact per backend; receipt/cache mengikat identitas ini.
5. **Canary = bukti hidup (P5-T02).** Setiap backend yang bisa memberi
   klaim memory-safety diuji canary positif (bug harus TERDETEKSI) dan
   negatif (source aman harus bersih). Canary gagal → backend
   **UNRELIABLE** — klaim bersihnya tidak dipercaya sampai canary hijau.
   `myc backends --canary` / `myc canary run` menjalankan kualifikasi ini.
6. **Tidak menjanjikan dukungan universal.** Biner yang ditemukan di PATH
   belum tentu "didukung". Catatan kebijakan: versi di bawah minimum atau
   known-bad (jika ada) HARUSNYA diperlakukan sebagai unavailable + debt,
   bukan clean — namun ENFORCEMENT versi minimum belum diimplementasikan
   di pemilih tool (tabel `min_version` di registry bersifat informatif
   sampai PR-027 `--production` + P5-T03 version-drift lane; gate saat ini
   menjalankan tool yang tersedia dengan perilaku lama).

## Host vs target

Tabel di atas adalah **host support** (myc berjalan dan memanggil backend
di mesin itu). `matrix` adalah cross-compile **target support** — host
myc di Windows/Linux x86-64 dapat menargetkan ARM/RISC-V; itu TIDAK
berarti myc host runtime didukung production di ARM/RISC-V (lihat
P6-T01 support contract).
