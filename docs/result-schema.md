# myc.result.v1 — Skema hasil terbekukan

> Status: **BEKU (frozen)** sejak Fase -1 (SOL-24). Semua field di bawah
> adalah kontrak stabil `myc check` → konsumen (CLI, MCP, agent harness).
> Perubahan apa pun pada skema ini WAJIB bump versi schema dan mencatat
> kompatibilitas di seksi "Riwayat kompatibilitas".

## Tujuan

Konsumen myc (LLM harness, MCP client, CI) harus dapat mem-parse output
JSON tanpa berubah-ubah. "Beku" berarti:

1. **Field yang sudah ada tidak dihapus/diganti makna** tanpa bump versi.
2. **Field baru** boleh ditambah (additive), asalkan tidak mengubah makna
   field lama dan didokumentasikan di bawah.
3. **Verdict enum tidak berubah urutan/nilai** untuk nilai yang sudah
   diklaim. Nilai baru hanya boleh ditambah di akhir.
4. **Determinisme**: input + tool + scenario sama → JSON sama (modulo
   `duration_ms` dan `receipt_sha256` yang memang bergantung run).

## Skema `--json-summary` (myc.result.v1)

Output `myc check <file> [flags] --json-summary` adalah satu objek JSON:

| Field | Tipe | Makna |
|---|---|---|
| `verdict` | string enum | `OK`, `COMPILE_ERROR`, `RUNTIME_VIOLATION`, `DRIVER_VIOLATION`, `INCONCLUSIVE`, `UNAVAILABLE` |
| `finding` | string | ringkasan finding (mis. `clean`, `out-of-bounds`, `use-after-free`) |
| `assurance_vector` | string | `C<S> R<..> B<..> P<..> D<..> F<..>` per dimensi gate |
| `diagnostics` | list | diagnosa compiler/sanitizer terstruktur (witness) |
| `exit_code` | int | exit code run (bila `--run`) |
| `duration_ms` | int | durasi run (tidak deterministik) |
| `receipt_sha256` | string | receipt bukti (chain parent) |
| `unverified_debt` | list | debt verifikasi (gap yang terlihat, bukan kesunyian) |
| `ran_runtime` | bool | `--run` tereksekusi |
| `ran_checked` | bool | `--checked` tereksekusi |
| `ran_prove` | bool | `--prove` tereksekusi |
| `ran_filc` | bool | `--filc` tereksekusi |
| `ran_driver` | bool | `--driver` tereksekusi |
| `ran_exhaustive` | bool | `--exhaustive` tereksekusi |
| `ran_stack` | bool | `--stack` tereksekusi |
| `ran_fuzz` | bool | `--fuzz` tereksekusi |
| `ran_mutate` | bool | `--mutate-audit` tereksekusi |
| `ran_metamorphic` | bool | `--metamorphic` tereksekusi |
| `ran_divergence` | bool | `--divergence` tereksekusi |
| `ran_compare` | bool | quorum/compare tereksekusi |
| `ran_negative` | bool | `--negative` tereksekusi |
| `ran_freestanding` | bool | `--freestanding` tereksekusi |
| `gate_matrix` | list | matriks gate × status (evidence) |
| `quorum_status` | string/null | hasil quorum lintas backend |
| `coaching` | list | saran satu-aksi (B3) bila ada |
| `harvest` | list | hasil harvest kontrak (B4) bila ada |
| `relational` | obj | klasifikasi klausa kontrak relasional (Fase 5): `analyzed`/`unary`/`relations`/`unbound` — observasi NON-blocking, verdict tidak pernah turun karenanya |
| `state_machine` | obj | ghost state machine (Fase 5, SOL-13): `states`/`events`/`transitions`/`findings` — observasi NON-blocking dari `//@ sm` |
| `abi` | obj | ABI/FFI Surface Certificate (Fase 5, SOL-14): `ran`/`structs`/`enums`/`symbols`/`changed`/`delta`/`target`/`header_sha`/`snapshot`/`delta_text` — observasi NON-blocking (hanya saat `--abi`); `snapshot` = teks "# myc abi v1", `delta` = jumlah baris ABI berubah vs referensi (HEADER sha diabaikan) |
| `lint_observations` | list | observasi lint ber-confidence NON-blocking |
| `lint_embedded_hits` | list | hit pola lint ter-embed |
| `assumptions` | list | ledger asumsi (A1) |
| `budget_met` | bool/null | budget kontrak (SOL-30) terpenuhi |
| `budget_report` | string/null | detail budget |
| `completeness` | string/null | status `--require-complete` |
| `error` | string/null | error pipeline bila gagal internal |

### Verdict enum (urutan beku)

```
OK  COMPILE_ERROR  RUNTIME_VIOLATION  DRIVER_VIOLATION  INCONCLUSIVE  UNAVAILABLE
```

- Nilai baru hanya boleh **ditambahkan di akhir**.
- Verdict adalah hasil gate HARD (compile/run/driver/proof/checked/filc);
  observasi heuristik (lint/negative/scanner/contract) **tidak pernah**
  menurunkan verdict.

## Skema `--agent` (myc.agent.v2)

Output `myc check <file> [flags] --agent`:

| Field | Tipe | Makna |
|---|---|---|
| `schema` | string | selalu `myc.agent.v2` |
| `verdict` | int | 0=OK, >0 tingkat keparahan (ordinal) |
| `finding` | int | indeks primary finding |
| `assurance_vector` | obj | vector per dimensi |
| `allowed_edits` | list | region yang boleh diubah (untuk repair) |
| `preserve` | list | simbol yang wajib dipertahankan |
| `forbidden_changes` | list | perubahan yang dilarang (preservation) |
| `frontier` | list | verification frontier per hazard class |
| `next_best` | obj | rekomendasi eksperimen termurah (SOL-03) |
| `next_check` | obj | satu aksi utama berikutnya |
| `receipt_sha256` | string | receipt |
| `source_sha256` | string | hash source |
| `witness_text` | string | witness terformat (replay) |

### Kontrak konsumen

- **Satu aksi utama**: `next_check` berisi SATU tindakan; `primary_finding`
  memilih SATU finding. Tidak ada parsing prose yang ambigu.
- **Payload cap**: `MYC_AGENT_PAYLOAD_CAP` — field enrichment
  (experiments/causal/next-best) dibuang bila melebihi cap, bukan
  ditruncate diam-diam.
- **Stable finding_id**: `f-%08x` dari line hex; ID bertahan terhadap
  pergeseran baris (semantic anchor via `source_anchor`).

## Riwayat kompatibilitas

| Tanggal | Versi | Perubahan |
|---|---|---|
| 2026-08-08 | `myc.result.v1` / `myc.agent.v2` | **Beku** (Fase -1, SOL-24). Dokumentasi awal skema stabil. |
| 2026-08-08 | `myc.result.v1` | Field `relational` ditambah (additive, Fase 5 Relational contracts) — objek observasi NON-blocking; tidak mengubah makna field lama. |
| 2026-08-08 | `myc.result.v1` | Field `state_machine` ditambah (additive, Fase 5 SOL-13 State-Machine Ghosting) — objek observasi NON-blocking; tidak mengubah makna field lama. |
| 2026-08-08 | `myc.result.v1` | Field `abi` ditambah (additive, Fase 5 SOL-14 ABI Certificate) — objek observasi NON-blocking; tidak mengubah makna field lama. |

## Aturan perubahan (untuk pengembang)

1. Field lama: TIDAK dihapus atau diubah makna.
2. Field baru: additive; tambahkan baris di tabel atas + catat di Riwayat.
3. Verdict enum: nilai baru hanya di akhir; jangan reorder.
4. Setiap perubahan skema → bump `schema_version` di `bench/manifest.json`
   + jalankan ulang `bench/run_bench.sh` (baseline) + update golden.
