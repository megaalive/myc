# Incident procedure (P15)

Apa yang dilakukan bila myc memberi hasil yang salah, crash, atau
artefak rilis tidak cocok checksum. Ini prosedur operasional — **bukan**
klaim bahwa `OK` berarti program aman.

## Klasifikasi

| Kelas | Contoh | Prioritas |
|---|---|---|
| False OK | gate semantik yang diminta CLEAN padahal ada pelanggaran yang harusnya terdeteksi | P0 — tarik klaim, rollback tag bila sudah rilis |
| False FAIL / noise | source sah jadi COMPILE_ERROR / RUNTIME_VIOLATION | P1 — perbaikan + regresi |
| Crash / hang / leak myc | verifier sendiri tidak selesai atau korup | P0 bila merusak evidence; selain itu P1 |
| Checksum mismatch | unduhan ≠ `SHA256SUMS` | Jangan pakai biner; unduh ulang atau pakai tag sebelumnya |
| Backend UNRELIABLE | canary gagal | Jangan percaya CLEAN dari backend itu sampai canary hijau |

## Jangan

- Mengklaim `OK` = "aman" / "semua bug memori mustahil".
- Menurunkan verdict dari heuristik (lint, negative-space, scanner).
- Menghapus receipt / ledger / laporan sanitizer sebelum insiden ditutup.

## Laporan (GitHub issue)

Sertakan:

1. `myc version` (baris `git:`, `gcc version:`, `clang version:`)
2. Perintah lengkap (`myc check …` termasuk flag)
3. `receipt_sha256` dan `source_sha256` dari laporan
4. Verdict + gate matrix (atau `--json-summary`)
5. OS + arch host (Windows/Linux x86-64)
6. Bila `--run`: cuplikan report ASan/UBSan (bukan seluruh binary)

Source boleh dipotong sampai repro; jangan kirim rahasia.

## Rollback rilis

1. Jangan hapus tag yang sudah diunduh orang — tandai rilis GitHub
   sebagai prerelease / draft bila perlu, dan tunjuk tag sebelumnya.
2. Artefak tag lama tetap provenance (`SHA256SUMS` + `git:`).
3. Perbaikan masuk commit baru di `master`; tag baru hanya setelah CI
   hijau (`docs/release.md`).

## Jejak yang disimpan

- `.myc/ledger.json` (rantai receipt)
- `.myc/evidence_cache.json` + sidecar sha256 (bila relevan)
- Output `--json` / capsule / `--write-repro`
- Log CI untuk SHA yang sama

## Setelah perbaikan

Tambah regresi yang menggagalkan kasus insiden. Jangan tutup sebagai
"sudah aman" tanpa tes yang akan merah jika bug kembali.
