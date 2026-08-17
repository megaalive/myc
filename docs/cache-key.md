# Cache Key Specification — Incremental Evidence Cache (SOL-18)

Dokumen ini adalah **spesifikasi kanonik key** untuk Incremental Evidence
Cache (`cache.c/.h`, SOL-18): apa saja yang membentuk key, dimensi apa yang
wajib memisahkan entry, dimensi apa yang sengaja tidak masuk key, dan
riwayat perubahan format (v1 → v2).

Test yang mengunci perilaku ini: `test/cache_key_matrix.c` (PR-011,
MYC-AUDIT-043), di-wire sebagai blok 14 di `test/_audit018.sh`.

## Prinsip

1. **Key adalah fungsi deterministik dari (source, scenario, tool, cwd,
   eksekusi, resep gate Fase 5/6).** Input + request yang sama → key sama.
2. **Bila hasil verifikasi bisa berbeda, key HARUS berbeda.** Replay
   (SOL-18) mengembalikan hasil yang sudah dihitung valid — tidak pernah
   boleh mengembalikan hasil *stale* untuk konfigurasi yang berbeda.
3. **NON-blocking:** cache rusak / tidak terbaca / tidak tertulis = miss,
   jalur pipeline normal; verdict tidak pernah berubah karena cache.

## Key kanonik v2

```
key = sha256(
    "v2|"
    "src:"  + sha256(source bytes)                 // 64 hex
  + "|scen:" + scenario_hash                       // 16 hex (lihat bawah)
  + "|tool:" + tool_key                            // gcc/clang version identity
  + "|cwd:" + req->cwd                             // workspace root
  + "|stdin:" + stdin_hash                         // 16 hex | "-"
  + "|t:" + req->timeout_ms
  + "|o:" + req->max_output_bytes
  + "|hdir:" + req->checked_header_dir
  + "|g2:" + gates2_hash                           // 16 hex (lihat bawah)
  + "|"
)
```

### Dimensi key per bagian

| Bagian | Isi | Mengapa wajib |
|---|---|---|
| `src` | sha256 byte source (1 MiB, boleh ber-NUL) | Hasil verifikasi seluruhnya turunan source |
| `scen` | `myc_ledger_build_scenario_hash(req, NULL)` dipotong 16 hex | Encodes flags gate inti: `strict`, `run_analyzer`, `run`, `prove`, `checked`, `filc`, `driver`, `metamorphic`, `divergence`, `negative`, `quorum`, `require_complete`, `require_assumptions_closed`, `no_assumptions`, `assumption_acks` (hash), dan budget contract (`active`, level per gate, `max_time_ms`, `max_output_bytes`) |
| `tool` | `gcc:<version>\|clang:<version>` dari `myc_tool_version` (`--version`); gagal = `?` | Toolchain berbeda → hasil gate berbeda. clang hanya diprobes bila `run`/`driver`/`metamorphic`/`divergence` diminta |
| `cwd` | `req->cwd` | Resolusi `#include` relatif + `.myc/` lokasi bergantung cwd |
| `stdin` | sha256(`req->run_stdin`) 16 hex, `-` bila kosong | `--run-stdin` mengubah **perilaku program verifikasi** → hasil gate run berbeda. **Gap v1, fix PR-011** |
| `t` | `req->timeout_ms` | Timeout gate berbeda → hasil berbeda (timeout vs selesai). **Gap v1, fix PR-011** |
| `o` | `req->max_output_bytes` | Output cap mengubah truncation/teks yang disimpan; marker sanitizer di luar cap bisa hilang. **Gap v1, fix PR-011** |
| `hdir` | `req->checked_header_dir` | Versi `myc_buf.h` berbeda → hasil L4 SPATIAL berbeda. **Gap v1, fix PR-011** |
| `g2` | hash flags gate Fase 5/6 + G4: `run_lint`, `exhaustive`, `stack` (+`stack_budget`), `fuzz` (+`fuzz_iters`, `fuzz_seed`), `mutate_audit` (+`mutate_max`), `freestanding`, `matrix`, `abi`, `perturb`, `thread_probe`, `eig_apply`, `eig_budget_ms` | Resep gate berbeda → hasil/observasi berbeda. `--eig-apply` mengubah gate yang dijalankan setelah L1, jadi wajib di key. |

### Dimensi yang sengaja TIDAK di key (dan alasannya aman)

| Dimensi | Alasan |
|---|---|
| `no_cache` | Hanya mengontrol apakah cache dipakai; bila 1, replay/store mati total |
| `no_persist` | Hanya mengontrol penulisan disk; hasil tidak berubah |
| `as_json` / `json_summary` / `agent` / `agent_payload_cap` | Hanya format/render output; hasil verifikasi sama, output dibangun ulang saat report |
| `pack_dir` / `no_pack` | Pack (prompt/spec proyek) dibaca ulang saat report `--agent`/`context`; NON-blocking (verdict tidak pernah berubah) |
| `input.kind` (FILE vs MEMORY vs STDIN) | Konten sudah di-canonical ke bytes di `src`; path disimpan sebagai metadata entry (`path`), bukan bagian key |
| `write_repro` / `tx_*` | Tidak mengubah hasil verifikasi (hanya artifact/report); subcommand yang memakainya (`myc eig`, `myc compare`, `compare-candidates`) sudah `no_cache=1` |
| `scenario` / `scenario_file` | Aman selama resepnya terpetakan penuh ke field request yang sudah di-key (gate flag di `scen`/`g2`). Catatan: env-contract DS-12 (mis. `stack_budget`) kini ikut di-key via `g2` |

## Riwayat format

### v1 (Fase 3, SOL-18 — asli)

`v1|src|scen|tool|cwd|` — hanya source, scenario (flags inti + asumsi +
budget), tool, cwd.

**Gap yang ditemukan audit PR-011 (MYC-AUDIT-043):**

1. **`--run-stdin` tidak di key.** Dua run dgn stdin berbeda berbagi entry →
   replay hasil gate run dengan stdin yang salah (**replay stale**, risiko
   bukti salah).
2. **`timeout_ms` / `max_output_bytes` tidak di key.** Timeout/output cap
   berbeda → hasil berbeda (timeout vs selesai; truncation, marker di luar
   cap) tapi key sama.
3. **Flag gate Fase 5/6 tidak di key.** `--stack`/`--fuzz`/`--matrix`/
   `--mutate-audit`/`--freestanding`/`--abi`/`--perturb`/`--thread-probe`/
   `--no-lint` bisa HIT entry dari run polos → output gate **hilang
   diam-diam**; `--exhaustive` bisa replay `ex_*` stale (0) padahal run
   asli menjalankan gate.
4. **`checked_header_dir` tidak di key.** Versi `myc_buf.h` berbeda →
   hasil L4 berbeda tapi key sama.

### v2 (PR-011, MYC-AUDIT-043 — aktif)

Menambahkan `stdin`, `t`, `o`, `hdir`, `g2`. Entry v1 lama otomatis MISS
(key v1 ≠ key v2) → upgrade mulus, replay stale tidak pernah terjadi.

## Invariants yang diuji (`test/cache_key_matrix.c`)

- **Determinisme + dedup:** store 2× dengan request identik = 1 entry
  (last-write-wins), replay HIT identik (marker hasil di-replay).
- **Per dimensi:** nilai A → HIT; nilai B → MISS. Dimensi: source, 13 flag
  inti, 14 flag Fase 5/6 (incl. `stack_budget`), budget
  (active/level/max_time/max_output), cwd, tool identity, eksekusi
  (stdin/timeout/output cap/header dir).
- **Tidak di-store:** run stateful (`--assumption-ack`,
  `--require-assumptions-closed`), hasil error (`MC_ERROR`), `--no-cache`.

## Batas jujur (replay lossy untuk detail gate tertentu)

Status gate di-REPLAY lengkap (array `gates` di entry, incl. gate Fase 5/6),
tetapi untuk gate yang field detailnya TIDAK disimpan di entry (stack report,
fuzz/matrix/mutate/thread-probe/freestanding/perturb detail; juga
harvest/rel/units/rsrc/sm/abi report — pola "replay hanya punya counts"
yang sudah terdokumentasi), replay run ber-flag sama = status gate + counts
tanpa teks report. `g2` memastikan run ber-flag TIDAK pernah memakai entry
run polos (gap v1 ditutup); replay antar run ber-flag yang identik tetap
mengembalikan status + counts (bukan report penuh) — perilaku sadar,
bukan kehilangan verdict.
