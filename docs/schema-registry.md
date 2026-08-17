# Schema registry — machine API schemas myc (BEKU)

> Status: **BEKU (frozen)** sejak Batch PR-015 (MYC-AUDIT-047). Dokumen ini
> adalah satu-satunya registry resmi untuk **semua** skema JSON yang
> dipertukarkan antara komponen myc dan konsumen mesin (CLI, MCP client,
> agent harness, CI, `.myc/` state). Setiap skema punya versi bernama,
> produsen, konsumen, tabel field wajib, dan **golden file** di
> `test/golden/` yang mengunci bentuk kanoniknya.
>
> Aturan perubahan (sama dengan docs/result-schema.md):
> 1. Field lama: TIDAK dihapus / diubah makna tanpa bump versi.
> 2. Field baru: additive — konsumen lama wajib tetap mem-parse dokumen
>    yang memuat field asing (diuji, lihat aturan 4).
> 3. Enum: nilai baru hanya di akhir; jangan reorder.
> 4. Setiap perubahan skema → update golden file + `test/schema_compat.c`
>    HARUS hijau (golden tetap ter-parse; konsumen tetap menerima golden;
>    produsen tetap memancarkan semua field beku; fail-closed pada versi
>    tak dikenal).

## Ringkasan registry

| Skema | Versi | Produsen | Konsumen | Golden file |
|---|---|---|---|---|
| `myc.result.v1` | `--json-summary` | `report.c` `myc_report_json_summary` | CLI/MCP/harness | `test/golden/myc.result.v1.json` |
| `myc.agent.v2` | `--agent` | `agent.c` `myc_agent_result_json` | agent harness, MCP `agent_check` | `test/golden/myc.agent.v2.json` |
| `myc.lite.v1` | `--lite` / MCP `verify` | `agent.c` `myc_lite_result_json` | agen lemah, MCP `verify` | `test/golden/myc.lite.v1.json` |
| `myc.calibration.v1` | `.myc/calibration.json` | `calibrate.c` `calib_save` | `calibrate.c` `calib_load` (EIG/annotasi) | `test/golden/myc.calibration.v1.json` |
| evidence cache | `.myc/evidence_cache.json` | `cache.c` `cache_write_all` | `cache.c` `cache_read_all` (replay) | `test/golden/myc.evidence_cache.v1.json` |
| scenario profile | file profil user / `--scenario` | user / `scenario.c` builtin | `scenario.c` `parse_profiles` | `test/golden/myc.scenario.v1.json` |
| pack spec | `myc.spec.json` | user (project-local) | `prompt.c` `pack_parse_spec` | `test/golden/myc.spec.v1.json` |
| MCP JSON-RPC | envelope request/response | `mcp.c` | `mcp.c` dispatcher / SDK client | `test/golden/mcp.request.tools-call.v1.json`, `test/golden/mcp.response.tools-call.v1.json` |
| receipt canonical | `myc.receipt.v1` byte-string | `gate.c` `myc_receipt_canonical` | ledger/CI | `docs/receipt-canonical.md` (PR-014) |

Dua skema teratas (`myc.result.v1`, `myc.agent.v2`) sudah dibekukan sejak
Fase -1 (SOL-24) di `docs/result-schema.md`; tabel field di bawah adalah
salinan ringkas + penunjuk. Skema sisanya baru dibekukan di sini.

---

## 1. `myc.result.v1` — ringkasan hasil (`--json-summary`)

Referensi lengkap: `docs/result-schema.md` (Fase -1, SOL-24).

**Field wajib** (38; semua selalu ada di output valid): `verdict`,
`finding`, `completeness`, `error`, `exit_code`, `duration_ms`,
`receipt_sha256`, `unverified_debt`, `gate_matrix`, `diagnostics`,
`assurance_vector` (objek `C/S/R/B/P/D/F` → **string status** — peta
flat, mis. `"C": "clean"`; catatan: serializer penuh `--json`
`myc_result_to_json` memakai bentuk nested `{"status": ...}` — dua
bentuk ini adalah DUA skema berbeda dan masing-masing beku), semua `ran_*`
(`ran_runtime`, `ran_checked`, `ran_prove`, `ran_filc`, `ran_driver`,
`ran_exhaustive`, `ran_stack`, `ran_fuzz`, `ran_mutate`, `ran_metamorphic`,
`ran_divergence`, `ran_compare`, `ran_negative`, `ran_freestanding`),
`quorum_status`, `coaching`, `harvest`, `lint_observations`,
`lint_embedded_hits`, `assumptions`, `budget_met`, `budget_report`,
`abi`, `relational`, `state_machine`, `resource`, `units`.

**Verdict enum (urutan beku):** `OK  COMPILE_ERROR  RUNTIME_VIOLATION
DRIVER_VIOLATION  INCONCLUSIVE  UNAVAILABLE`. Nilai baru hanya di akhir.

**Kontrak:** output `--json-summary` SELALU JSON valid (termasuk input
korup); field wajib di atas selalu ada. Diuji oleh `test/_schema_golden.sh`
(33 field inti) + `test/schema_compat.c` (38 field penuh, tipe, enum).

---

## 2. `myc.agent.v2` — protokol agent (`--agent`)

Referensi lengkap: `docs/result-schema.md` (Fase -1, SOL-24).

**Field wajib:** `schema` (selalu `"myc.agent.v2"`), `verdict` (int ordinal),
`finding` (int), `payload_cap` (int), `assurance_vector` (objek
`C/S/R/B/P/D/F` → int), `allowed_edits` (array), `preserve` (array),
`forbidden_changes` (array), `frontier` (array), `next_check` (objek
`{finding_id, command}`), `receipt_sha256`, `source_sha256`,
`witness_text` (string). Field string opsional (`intent_hash`,
`scenario_hash`, `source_sha256`, `receipt_sha256`, `witness_text`,
`experiments`, `causal`, `next_best`) di-emit HANYA bila terisi
(`agent_add_str` melewatkan key saat NULL), jadi golden = himpunan key
untuk hasil representatif; T10 membuktikan serializer masih memancarkan
semua key golden.

**Field kondisional (bila ada data):** `intent_hash`, `scenario_hash`,
`primary_finding` (objek `{finding_id, anchor, diagnostic_class, message,
confidence, repro, witness_hash}`), `witness_repro`, `witness_slice`,
`experiments`, `causal`, `next_best`, `delta_receipt_sha`, `feedback`
(NEMO-6: string system-prompt deterministik), `payload_dropped` (NEMO-5:
array string nama enrichment yang dibuang karena cap), `pack` (objek
JSON ter-parse dari `pack_json`).

**Kontrak konsumen:** SATU aksi utama (`next_check`); payload cap
`MYC_AGENT_PAYLOAD_CAP` (16384 default) — enrichment dibuang, bukan
ditruncate; `finding_id` stabil (`f-%08x` dari line). Diuji oleh
`test/_schema_golden.sh` + `test/schema_compat.c`.

---

## 3. `myc.calibration.v1` — ledger kalibrasi

File: `.myc/calibration.json` (ditulis atomik, PR-012).

```json
{ "schema": "myc.calibration.v1",
  "entries": [ { "rule": "lint-oob",
                 "accepted": 12, "rejected": 3, "confirmed_later": 2,
                 "missed": 1, "useful_fix": 5, "harmful_fix": 0,
                 "match": "out of bounds" } ] }
```

**Field:** `schema` (string, selalu `myc.calibration.v1`), `entries` (array
objek). Tiap entry: `rule` (string wajib), enam counter outcome (`accepted`,
`rejected`, `confirmed_later`, `missed`, `useful_fix`, `harmful_fix` —
angka, urutan beku `myc_calib_outcome`), `match` (string opsional).

**Konsumen fail-closed:** `calib_load` meng-ignore file yang tidak
ter-parse / tanpa `entries` array (return 0 entry, tanpa crash) —
diuji `test/schema_compat.c` T4 (konsumen menerima golden) dan T8b
(korup di-ignore).

---

## 4. Evidence cache — `.myc/evidence_cache.json`

File state internal (SOL-18), diperlakukan sebagai **input eksternal yang
TIDAK dipercaya** (PR-013). Dua lapis pertahanan: L1 sidecar
`.myc/evidence_cache.sha256` (sha256 byte mentah file) + L2 validasi
semantik per entry.

**Root:** objek dengan `entries` (array). **Entry:** `key`/`source`
(wajib sha256 hex 64), `scenario`, `tool`, `cwd`, `path`, `receipt`,
`fingerprint` (string), `verdict`/`err` (wajib dalam range enum),
`assurance`/`finding`/`completeness`/`claim` (dalam range bila ada),
`duration_ms` (>= 0), `gates` (array `{id, requested, status, findings}`,
id/status dalam range), `debt`/`debt_text`, `diags`, `funcs`, `av`
(array 7), `div_cells`, `drv_records`, `filc_cases`, `clauses`,
`evidence`, plus snapshot numerik `exit_code`, `truncated`,
`run_timed_out`, `ran_*`, `checked_*`, `asm_*` (host facts), `div_*`,
`rel_*`, `sm_*`, `abi_*`, `rsrc_*`, `unt_*`, `ex_*`, dst.

**Fail-closed:** sidecar hilang/stale/tampered = seluruh file di-ignore
(recompute); entry dengan enum out-of-range / key bukan hex64 / state
mustahil (MC_ERROR tanpa err) dikarantina + file di-heal. Diuji:
`test/cache_corrupt.c` (PR-013) + `test/schema_compat.c` (golden).

---

## 5. Scenario profile — `myc.scenario.v1`

File profil (builtin `scenario.c` + file user; `--scenario`, `--pack-dir`).

```json
{ "version": 1,
  "scenarios": [ { "name": "cli-daily", "desc": "...",
                   "flags": ["run", "analyzer"], "env": {} } ] }
```

**Field:** root `version` (wajib angka == 1), `scenarios` (wajib array
non-kosong). Tiap scenario: `name` + `desc` (string wajib), `flags`
(array string opsional), `env` (objek opsional). Flag tak dikenal
di-ignore (data profil, non-blocking).

**Fail-closed:** `version != 1`, `scenarios` hilang/kosong, entry tanpa
`name`/`desc`, atau tipe salah → profil USER di-ignore dan fallback ke
profil bawaan (`effective_root` tidak pernah NULL): gates user TIDAK
pernah di-apply, scenario user tak terlihat (return -1), tanpa crash
(INV-011). Diuji `test/schema_compat.c` T6 (konformansi + konsumen +
fail-closed versi) dan T9 (additive: scenario user-only di-merge).

---

## 6. Pack spec — `myc.spec.json`

File project-local opsional (version-controllable, BUKAN `.myc/`),
dibaca `myc_pack_load` (Fase 7, DS-15).

```json
{ "version": 1, "name": "pack-fixture", "domain": "embedded",
  "rules": ["..."], "allow_headers": ["stdint.h"],
  "deny_functions": ["system"] }
```

**Field:** `version` (wajib angka == 1), `name` (wajib string non-kosong,
<= 63), `domain` (opsional), `rules` (array string, max 8), `allow_headers`
(array string, max 8), `deny_functions` (array string, max 8).

**Fail-closed:** spec ADA tapi invalid = fail-fast (`myc_pack_load` -1,
pola scenario); `--no-pack` menonaktifkan. Diuji `test/schema_compat.c`
T7 (konsumen + fail-fast) dan T9 (additive: field asing tetap valid).

---

## 7. MCP JSON-RPC 2.0 — envelope

Server `mcp` (mcp.c) memakai JSON-RPC 2.0 KETAT (MYC-AUDIT-016).

**Request:** `{ "jsonrpc": "2.0", "id": <string|number|null>, "method":
<string>, "params": <objek|array> }`. `jsonrpc` wajib `"2.0"`; `id` hanya
string/angka/null; pesan tanpa `id` = notification (diproses tanpa balasan).

**Response:** `{ "jsonrpc": "2.0", "id": <sama dengan request>, "result":
{...} }` atau `{ "jsonrpc": "2.0", "id": ..., "error": { "code": <int>,
"message": <string> } }`.

**Structured content (tools/call):** `content` (array `{type:"text",
text}`) SELALU ada (backward compatible); `structuredContent` objek
dengan `schema` (`myc.result.v1` / `myc.agent.v2` / `myc.repair.v1`) —
konsumen mesin tidak perlu parse JSON di dalam JSON. `isError` HANYA untuk
kegagalan tool/protocol (ERROR/TIMEOUT/CANCELLED), bukan finding pada kode.
Diuji `test/schema_compat.c` T8 (envelope request/response) +
`test/_mcp_smoke.bat`.

---

## Aturan golden file (`test/golden/`)

1. Setiap golden file = **instance kanonik** dari skemanya: field wajib
   lengkap, tipe benar, enum dalam himpunan beku. File TIDAK boleh
   diubah tanpa alasan skema.
2. `test/schema_compat.c` (blok 18 `_audit018.sh`) membuktikan:
   - T1: setiap golden ter-parse oleh `json.c` (golden tidak busuk).
   - T2–T7: golden sesuai tabel field/tipe beku di atas.
   - T8: konsumen fail-closed pada versi tak dikenal (scenario v2, spec
     v99, cache verdict out-of-range, calib korup) — INV-011.
   - T9: evolution additive — field asing pada golden TETAP diterima
     konsumen lama (tidak pernah ditolak).
   - T10: produsen (`myc_result_to_json`, `myc_agent_result_json`) masih
     memancarkan SEMUA field beku (backward compat).
3. Perubahan skema = update doc ini + golden + test, semuanya hijau.
