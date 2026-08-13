# Receipt Canonicalization — `receipt_sha256` (PR-014 / MYC-AUDIT-046)

Dokumen ini adalah **spesifikasi kanonik** byte-string yang di-hash untuk
`receipt_sha256` (gagasan pembeda 9.1, `myc_build_receipt` di `gate.c`).
Dibekukan oleh canonical test vectors di `test/receipt_vectors.c` (blok 17
di `test/_audit018.sh`).

## Tujuan

`receipt_sha256` adalah sidik jari deterministik atas bukti yang terkumpul
(verdict, completeness, setiap gate id+status, debt, fingerprint,
source_sha) — bukan klaim keamanan. CI/auditor membandingkan dua receipt
tanpa membaca prosa. Agar perbandingan bermakna, **format byte-string yang
di-hash harus stabil**: mengubah format, urutan append, atau mapping enum
secara tak sengaja = semua receipt berubah = test vector langsung gagal.

## Definisi

Byte-string kanonik adalah konkatenasi:

```
"myc.receipt.v1|"
+ verdict + "|"
+ completeness + "|"
+ (untuk tiap gate, URUTAN INSERT): "<id>:<status>|"
+ "debt=" + (untuk tiap debt, urutan insert): "<nama>|"
+ "fp=" + fingerprint
+ "|sha=" + source_sha256
+ "|"
```

Contoh (V4, golden):

```
myc.receipt.v1|INCONCLUSIVE|incomplete|1:completed_clean|4:unavailable|debt=unavailable|fp=fp-1234|sha=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef|
```

### Aturan

1. **Urutan = urutan insert, BUKAN sorted.** Dua run dengan gate yang sama
   tapi urutan set berbeda → receipt berbeda (T6 s5).
2. **Mapping nama enum** (huruf kecil, snake_case) — mengubah nama =
   semua receipt berubah (tertangkap golden vector):

   | Verdict | Completeness | Gate status | Debt |
   |---|---|---|---|
   | `OK` | `unknown` | `not_requested` | `none` |
   | `VIOLATION` | `complete` | `not_applicable` | `unavailable` |
   | `COMPILE_ERROR` | `incomplete` | `unavailable` | `infra_failed` |
   | `ERROR` | | `infra_failed` | `inconclusive` |
   | `TIMEOUT` | | `inconclusive` | `nonzero_cases` |
   | `CANCELLED` | | `completed_clean` | `ensures_unproved` |
   | `RUNTIME_VIOLATION` | | `completed_findings` | `raw_buffers` |
   | `PROVE_VIOLATION` | | `completed_observations` | `output_truncated` |
   | `FILC_VIOLATION` | | (di luar enum = `unknown`, fails closed) | `budget_unmet` |
   | `DRIVER_VIOLATION` | | | `assumption_open` |
   | `INCONCLUSIVE` | | | `count` |
   | (di luar enum = `UNKNOWN`) | | | (di luar enum = `unknown`) |

3. **Gate segment** memakai `<id>:<status>` — id NUMERIK enum
   `myc_gate_id` (PREPROCESS=0, COMPILE=1, ANALYZER=2, RUNTIME=3, PROVE=4,
   CHECKED=5, FILC=6, DRIVER=7, METAMORPHIC=8, NEGATIVE=9, LINT=10,
   DIVERGENCE=11, EXHAUSTIVE=12, COMPARE=13, STACK=14, FUZZ=15, MUTATE=16,
   FREESTANDING=17, MATRIX=18, CONCUR=19). Menambah gate di akhir enum
   AMAN (id lama tidak berubah); menyisipkan/merombak enum = receipt
   berubah untuk semua entry (harus bump versi receipt).
4. **Field kosong** = string kosong (`fp=` dan `sha=` tanpa isi bila NULL).
   Verdict dan completeness TIDAK pernah kosong.
5. **Buffer & truncation**: string penuh bisa melebihi 4095 byte (mis.
   fingerprint panjang). Hash SELALU atas **cap-1 byte pertama** (4095)
   + NUL — deterministic, bukan error, identik antara `myc_receipt_canonical`
   dan hash yang dihitung `myc_build_receipt` (T7). Truncation setara
   dengan memotong string penuh di 4095 byte.
6. **Kosong vs tak ada**: `res->gate_count == 0` dan `debt_count == 0` →
   segmen tidak muncul (V1: `...|complete|debt=fp=|sha=|`).

## Golden vector (dihitung INDEPENDEN — python3 hashlib)

Perubahan format/enum mapping/urutan append mana pun → salah satu dari
empat vector ini gagal.

| V | Deskripsi | Canonical string | sha256 |
|---|---|---|---|
| V1 | empty result (tanpa gate) | `myc.receipt.v1\|OK\|complete\|debt=fp=\|sha=\|` (41 B) | `d5c6ba36e3af0bc27b9b473d7b8279fdd9eb44582d52dc9e73dd128ce8d540af` |
| V2 | satu gate clean (COMPILE=1) | `myc.receipt.v1\|OK\|complete\|1:completed_clean\|debt=fp=\|sha=\|` (59 B) | `90f951f64bed6cc4725508db8da95629b7f680937a5b1fa28caaebff926dcfd7` |
| V3 | COMPILE clean + RUNTIME(3) unavailable → debt | `myc.receipt.v1\|INCONCLUSIVE\|incomplete\|1:completed_clean\|3:unavailable\|debt=unavailable\|fp=\|sha=\|` (97 B) | `79db943e82fdbd4bd6b6295b016fc85aeb843a71289e5ff5f8202b9632796eb0` |
| V4 | full: fingerprint + source_sha + debt | `myc.receipt.v1\|INCONCLUSIVE\|incomplete\|1:completed_clean\|4:unavailable\|debt=unavailable\|fp=fp-1234\|sha=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\|` (168 B) | `3972bd39e3bb976351dd6b7a72c5738292a1b6d3438c5ea2d651e298c4111b8d` |

## API yang di-lock

- `size_t myc_receipt_canonical(const myc_result *res, char *buf, size_t cap)`
  (`gate.h`): menulis byte-string kanonik (cap-1 + NUL), return panjang.
  Satu-satunya sumber kebenaran format; `myc_build_receipt` meng-hash
  keluarannya.
- `void myc_rebuild_receipt(myc_result *res)`: re-hash SETELAH state
  diubah manual (enforcement require-complete) — TIDAK menjalankan
  reducer ulang.

## Invariants yang diuji (`test/receipt_vectors.c`)

- **Golden**: canonical == string hardcode, sha256(canonical) == hash
  hardcode (independen), `res.receipt_sha256` == hash (pipeline).
- **Referensi**: implementasi independen di dalam test (dari dokumen ini,
  bukan salinan gate.c) menghasilkan byte-string sama.
- **Determinisme**: build sama 2× → canonical + hash identik.
- **Sensitivitas**: fingerprint / source_sha / gate status / gate id /
  urutan insert gate / jumlah gate / verdict manual → hash BERUBAH.
- **Fail-closed enum (INV-011)**: status gate / verdict di luar enum
  di-render `unknown` / `UNKNOWN` (bukan crash, bukan clamp) dan referensi
  setuju.
- **Rebuild**: `myc_rebuild_receipt` setelah mutasi → hash berubah dan
  tetap == sha256(canonical baru).
- **Truncation**: fingerprint 5000 B → canonical 4095 B + NUL, hash atas
  string terpotong, cap kecil (1/5/8) → cap-1 byte + NUL.

## Batas jujur

- Receipt mengunci **bentuk** bukti (status gate, debt, fingerprint,
  source_sha) — bukan isi output backend. Dua run dengan gate status sama
  tapi output diagnostik berbeda bisa punya receipt sama; pembeda isi
  ada di fingerprint/source_sha dan laporan penuh.
- Perubahan `myc_gate_id` enum (penyisipan) atau mapping nama = format
  break → bump versi `myc.receipt.v1` → v2 (semua receipt berubah, test
  golden wajib diperbarui dengan vector baru).
